# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Windows confinement for a local Model Context Protocol server process.

A configured server is somebody else's program running with the operator's own account. Consent decides whether it runs at all; this module
decides what it can reach once it does.

A sandboxed server is spawned by this module rather than by the SDK, because confinement has to be in place before the server executes its
first instruction. The process is created suspended with a restricted token, placed in a job object, and only then resumed, so the server
and every process it ever starts run inside the job from creation; nothing has to be found and adopted after the fact.

What is enforced:

* **Environment.** The child receives exactly :data:`ENVIRONMENT_ALLOWLIST` from Intellicrack's own environment, the variables the
  operator named in ``inheritEnv``, the locations of its own sandbox home, and the server's own configured entries. Nothing is merged in
  from anywhere else, so the API keys and tokens Intellicrack's environment carries do not travel.
* **Home.** Each server gets a home of its own under Intellicrack's state directory -- temporary files, a profile, local and roaming
  application data, and the caches and tool directories of npm, uv, pip and pipx -- and the child's environment points every launcher
  there. The operator's own profile is not writable at Low integrity, so without it ``npx``, ``uvx`` and their kind fail to create their
  caches. The home is writable to the server for as long as it runs, like an ``allowWrite`` directory with ``writeExisting``.
* **Token.** Every privilege except change-notify is removed, the Administrators group is deny-only, and the integrity level is lowered to
  Low.
* **Writes.** A Low integrity process cannot write to anything labelled above Low, which by default is everything the operator owns. For
  as long as the server runs, each directory in ``allowWrite`` carries an inheritable Low mandatory label, so the server can create files
  and folders there; what was already inside keeps its own label unless the operator opted into ``writeExisting``. When the server stops,
  every directory's original label is put back and the Low label is withdrawn from everything that inherited it, so nothing stays
  writable to other Low integrity processes afterwards. A grant still in force when Intellicrack last exited is reverted at the next
  start. Labelling runs on a worker thread, never on the event loop. Locations Windows itself labels Low, such as
  ``%USERPROFILE%\AppData\LocalLow``, remain writable to any Low integrity process, this one included. Reads are not restricted.
* **Job.** An active-process cap, per-process and per-job committed-memory caps, UI restrictions, and kill-on-close, so a server that
  spawns children cannot outlive its connection.
* **Console.** The child runs with no console window.

What is not enforced: network access. ``allowedDomains`` is recorded and logged, but a sandboxed server can still connect to any host.

Everything Win32 here is gated on the platform. On anything else a sandboxed launch is refused outright, never quietly downgraded to an
unconfined one: a configuration that says ``"sandbox": {"enabled": true}`` and silently runs without one is worse than no sandbox at all,
because the operator believes they have protection they do not have.
"""

from __future__ import annotations

import codecs
import ctypes
import functools
import os
import re
import sys
import threading
from collections import deque
from contextlib import asynccontextmanager, suppress
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING, Any, BinaryIO, ClassVar, Final, Self

import anyio
import anyio.lowlevel
import mcp_types
from anyio.streams.file import FileReadStream, FileWriteStream
from mcp.shared.message import SessionMessage

from intellicrack.core.config import get_config_file
from intellicrack.core.handle_inheritance import INHERITANCE_LOCK
from intellicrack.core.json_payload import JsonObject, is_json_object
from intellicrack.core.locked_json import JsonDocumentError, LockedJsonFile
from intellicrack.core.logging import get_logger
from intellicrack.core.untrusted_text import clean_untrusted_label
from intellicrack.mcp.config import launcher_notes, sandbox_limitations
from intellicrack.mcp.errors import McpConfigError, McpConnectionError


if sys.platform == "win32":
    import msvcrt

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping, Sequence
    from typing import TextIO

    from intellicrack.mcp.config import McpSandboxSpec, StdioServerSpec


_logger = get_logger(__name__)


IS_WIN32: Final[bool] = sys.platform == "win32"
"""Whether the confinement in this module is available at all."""

CREATE_SUSPENDED: Final[int] = 0x00000004
CREATE_UNICODE_ENVIRONMENT: Final[int] = 0x00000400
EXTENDED_STARTUPINFO_PRESENT: Final[int] = 0x00080000
CREATE_NO_WINDOW: Final[int] = 0x08000000

_STD_INPUT_HANDLE: Final[int] = 0xFFFFFFF6
_STD_OUTPUT_HANDLE: Final[int] = 0xFFFFFFF5
_STD_ERROR_HANDLE: Final[int] = 0xFFFFFFF4
_STD_HANDLES: Final[tuple[int, int, int]] = (_STD_INPUT_HANDLE, _STD_OUTPUT_HANDLE, _STD_ERROR_HANDLE)
_SW_HIDE: Final[int] = 0

SANDBOX_CREATION_FLAGS: Final[int] = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT
"""Creation flags of every confined launch.

``CREATE_SUSPENDED`` is what keeps the job airtight: the process is placed in its job before its first thread runs, so neither the server
nor anything it starts ever executes outside the job. No breakaway flag is set, and the job does not permit breakaway.

No console-creation flag is set, so the server inherits the launcher's console rather than allocating its own. A console-subsystem child
with no console to inherit -- which ``CREATE_NO_WINDOW`` forces, since it allocates a fresh one -- stands that console up under the
restricted Low integrity token, and that allocation fails during loader initialization with ``STATUS_DLL_INIT_FAILED`` on a hosted runner,
killing the server before it runs. It fails the same way for any console-subsystem grandchild a shim or launcher starts, which a flag on the
direct child cannot prevent. :func:`ensure_inheritable_console` gives the launcher a console under its own unrestricted token for the whole
confined tree to inherit, so nothing in it ever allocates one.
"""

DEFAULT_ACTIVE_PROCESS_LIMIT: Final[int] = 16
"""How many processes one server and its descendants may run at once."""

DEFAULT_PROCESS_MEMORY_BYTES: Final[int] = 2 * 1024 * 1024 * 1024
"""Committed-memory ceiling for any single process in the job."""

DEFAULT_JOB_MEMORY_BYTES: Final[int] = 4 * 1024 * 1024 * 1024
"""Committed-memory ceiling for the whole job."""

ENVIRONMENT_ALLOWLIST: Final[frozenset[str]] = frozenset({
    "COMSPEC",
    "NUMBER_OF_PROCESSORS",
    "OS",
    "PATH",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "WINDIR",
})
"""Inherited variables a confined child keeps.

Enough for a program to find its interpreter and its DLLs, and nothing that carries a credential. ``TEMP`` and ``TMP`` are not inherited:
the operator's temporary directory is not writable at Low integrity, so they are pointed at :data:`SANDBOX_TEMP_DIRNAME` inside the first
writable directory instead. Everything else the server needs it must be given explicitly in its own configuration.
"""

SANDBOX_HOMES_DIRNAME: Final[str] = "mcp-sandbox"
"""Directory under Intellicrack's configuration directory holding one sandbox home per server."""

SANDBOX_TEMP_DIRNAME: Final[str] = "tmp"
"""Directory inside a server's sandbox home that its ``TEMP`` and ``TMP`` name."""

SANDBOX_HOME_LAYOUT: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    (SANDBOX_TEMP_DIRNAME, ("TEMP", "TMP")),
    ("profile", ("USERPROFILE", "HOME")),
    ("profile/.docker", ("DOCKER_CONFIG",)),
    ("local", ("LOCALAPPDATA",)),
    ("roaming", ("APPDATA",)),
    ("cache", ("XDG_CACHE_HOME",)),
    ("cache/npm", ("npm_config_cache",)),
    ("cache/uv", ("UV_CACHE_DIR",)),
    ("cache/pip", ("PIP_CACHE_DIR",)),
    ("local/uv/tools", ("UV_TOOL_DIR",)),
    ("local/uv/bin", ("UV_TOOL_BIN_DIR", "UV_PYTHON_BIN_DIR")),
    ("local/uv/python", ("UV_PYTHON_INSTALL_DIR",)),
    ("local/pipx", ("PIPX_HOME",)),
    ("local/pipx/bin", ("PIPX_BIN_DIR",)),
)
"""Each directory of a sandbox home, relative to its root, and the variables that name it.

The profile and application-data variables cover whatever reads them, npm included. uv and pipx find their directories through the Windows
known-folder API rather than the environment, so they are pointed at the home by their own variables; without them ``uv`` and ``uvx``
fail with "Failed to initialize cache ... Access is denied".
"""

BATCH_SUFFIXES: Final[frozenset[str]] = frozenset({".cmd", ".bat"})
"""Script suffixes that run through the command interpreter rather than directly."""

DEFAULT_PATHEXT: Final[str] = ".COM;.EXE;.BAT;.CMD"
"""Executable suffixes tried when the child's environment carries no ``PATHEXT``."""

BATCH_UNSAFE_CHARACTERS: Final[tuple[str, ...]] = ('"', "%", "\r", "\n", "\0")
"""Characters ``cmd.exe`` interprets even inside a quoted argument.

A batch script's arguments are re-parsed by the command interpreter, where ``%`` expands a variable and a stray ``"`` ends quoting early.
An argument carrying one cannot be passed through a ``.cmd`` or ``.bat`` shim without the interpreter rewriting it, so it is refused.
"""

PROCESS_TERMINATION_GRACE_S: Final[float] = 2.0
"""How long a confined server may take to exit by itself after its stdin closes."""

KILL_REAP_TIMEOUT_S: Final[float] = 2.0
"""How long to wait for the job's processes to die after the job is terminated."""

STDERR_TAIL_LINES: Final[int] = 20
"""How many of a confined server's last standard error lines are kept to explain why it exited."""

STDERR_TAIL_LINE_CHARS: Final[int] = 400
"""Longest standard error line kept whole in that tail; longer lines are cut."""

STDERR_DRAIN_TIMEOUT_S: Final[float] = 2.0
"""How long to wait for a confined server's standard error to be read to its end once the server has stopped."""

_STDOUT_READ_BYTES: Final[int] = 65536
_STDERR_READ_BYTES: Final[int] = 4096
_NTSTATUS_ERROR_SEVERITY: Final[int] = 0xC0000000

NTSTATUS_EXIT_CODES: Final[Mapping[int, tuple[str, str]]] = {
    0xC0000005: ("STATUS_ACCESS_VIOLATION", "the program read or wrote memory it does not own"),
    0xC0000017: ("STATUS_NO_MEMORY", "a memory allocation failed, which the job's memory ceilings can cause"),
    0xC000001D: ("STATUS_ILLEGAL_INSTRUCTION", "the program ran an instruction this processor does not support"),
    0xC0000022: ("STATUS_ACCESS_DENIED", "Windows refused the program access it needed while starting"),
    0xC0000044: ("STATUS_QUOTA_EXCEEDED", "a quota was exceeded, which the job's limits can cause"),
    0xC000007B: ("STATUS_INVALID_IMAGE_FORMAT", "the program or a DLL it loads is not a valid image for this machine"),
    0xC00000FD: ("STATUS_STACK_OVERFLOW", "the program overflowed its stack"),
    0xC000012D: ("STATUS_COMMITMENT_LIMIT", "the system or the job ran out of committable memory"),
    0xC0000135: ("STATUS_DLL_NOT_FOUND", "a DLL the program needs could not be found or could not be opened with the sandbox's token"),
    0xC0000139: ("STATUS_ENTRYPOINT_NOT_FOUND", "a DLL the program loaded lacks a function it imports"),
    0xC000013A: ("STATUS_CONTROL_C_EXIT", "the program was ended by a console interrupt"),
    0xC0000142: (
        "STATUS_DLL_INIT_FAILED",
        "a DLL failed to initialize, which happens when the program cannot open its window station, its desktop or its console",
    ),
    0xC0000374: ("STATUS_HEAP_CORRUPTION", "the program corrupted its heap"),
    0xC0000409: ("STATUS_STACK_BUFFER_OVERRUN", "the program ended itself through a fail-fast check or an abort"),
    0xC0000417: ("STATUS_INVALID_CRUNTIME_PARAMETER", "the C runtime ended the program on an invalid parameter"),
}
"""Exit codes that are Windows status values, each with its name and what it means for a server that has just started."""

_JOB_OBJECT_LIMIT_ACTIVE_PROCESS: Final[int] = 0x00000008
_JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: Final[int] = 0x00000400
_JOB_OBJECT_LIMIT_JOB_MEMORY: Final[int] = 0x00000200
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final[int] = 0x00002000
_JOB_OBJECT_LIMIT_PROCESS_MEMORY: Final[int] = 0x00000100

_JOB_OBJECT_UILIMIT_DESKTOP: Final[int] = 0x00000040
_JOB_OBJECT_UILIMIT_DISPLAYSETTINGS: Final[int] = 0x00000010
_JOB_OBJECT_UILIMIT_EXITWINDOWS: Final[int] = 0x00000080
_JOB_OBJECT_UILIMIT_GLOBALATOMS: Final[int] = 0x00000020
_JOB_OBJECT_UILIMIT_HANDLES: Final[int] = 0x00000001
_JOB_OBJECT_UILIMIT_READCLIPBOARD: Final[int] = 0x00000002
_JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: Final[int] = 0x00000100
_JOB_OBJECT_UILIMIT_WRITECLIPBOARD: Final[int] = 0x00000004

_UI_RESTRICTIONS: Final[int] = (
    _JOB_OBJECT_UILIMIT_DESKTOP
    | _JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | _JOB_OBJECT_UILIMIT_EXITWINDOWS
    | _JOB_OBJECT_UILIMIT_GLOBALATOMS
    | _JOB_OBJECT_UILIMIT_HANDLES
    | _JOB_OBJECT_UILIMIT_READCLIPBOARD
    | _JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | _JOB_OBJECT_UILIMIT_WRITECLIPBOARD
)
"""Every UI capability a headless server has no business using.

``HANDLES`` is the load-bearing one: without it the child can reach the window handles of processes outside the job, which is a path
straight back out of the confinement.
"""

_JOB_OBJECT_BASIC_UI_RESTRICTIONS: Final[int] = 4
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: Final[int] = 9

_DO_NOT_INHERIT_HANDLE: Final[int] = 0
"""``bInheritHandle`` for a handle the child must not receive."""

_INHERIT_LISTED_HANDLES: Final[int] = 1
"""``bInheritHandles`` for a spawn whose inheritance is narrowed by a handle list."""

_PROCESS_SET_QUOTA: Final[int] = 0x0100
_PROCESS_TERMINATE: Final[int] = 0x0001

_TOKEN_ASSIGN_PRIMARY: Final[int] = 0x0001
_TOKEN_DUPLICATE: Final[int] = 0x0002
_TOKEN_QUERY: Final[int] = 0x0008
_TOKEN_ADJUST_DEFAULT: Final[int] = 0x0080
_TOKEN_ACCESS: Final[int] = _TOKEN_ASSIGN_PRIMARY | _TOKEN_DUPLICATE | _TOKEN_QUERY | _TOKEN_ADJUST_DEFAULT

_DISABLE_MAX_PRIVILEGE: Final[int] = 0x1
_TOKEN_INTEGRITY_LEVEL_CLASS: Final[int] = 25
_SE_GROUP_INTEGRITY: Final[int] = 0x00000020
_WIN_BUILTIN_ADMINISTRATORS_SID: Final[int] = 26
_WIN_LOW_LABEL_SID: Final[int] = 66
_SECURITY_MAX_SID_SIZE: Final[int] = 68

_LOW_LABEL_SDDL: Final[str] = "S:(ML;OICI;NW;;;LW)"
"""A SACL granting Low integrity write access, inherited by files and subdirectories."""

_NO_LABEL_SDDL: Final[str] = "S:"
"""A SACL with no entries: an object carrying it has no explicit mandatory label."""

_MANDATORY_LABEL_MARKER: Final[str] = "(ML;"
"""How a mandatory-label ACE opens in SDDL.

Its absence means the object carries no integrity label, whatever else the SACL holds: a NULL SACL renders as ``NO_ACCESS_CONTROL`` and an
auto-inherited one carries the ``AI`` control flag, so ``"S:"``, ``"S:NO_ACCESS_CONTROL"`` and ``"S:AINO_ACCESS_CONTROL"`` all mean the same
absence and must read back the same.
"""

_SDDL_REVISION_1: Final[int] = 1
_SE_FILE_OBJECT: Final[int] = 1
_LABEL_SECURITY_INFORMATION: Final[int] = 0x00000010

GRANTS_FILENAME: Final[str] = "mcp_sandbox_grants.json"
"""File recording every Low integrity write grant in force, so one left behind by a crash is reverted at the next start."""

_STARTF_USESTDHANDLES: Final[int] = 0x00000100
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST: Final[int] = 0x00020002
_RESUME_FAILED: Final[int] = 0xFFFFFFFF
_HANDLE_FLAG_INHERIT: Final[int] = 0x00000001
_WAIT_OBJECT_0: Final[int] = 0x00000000
_ERROR_INSUFFICIENT_BUFFER: Final[int] = 122

_ERR_UNSUPPORTED_PLATFORM = (
    "MCP server sandboxing is implemented with Windows job objects, restricted tokens and integrity levels, and is not available on "
    "this platform. Turn the sandbox off for this server to run it unconfined, which is a decision that should be made deliberately "
    "rather than by default."
)


class _IoCounters(ctypes.Structure):
    """Win32 ``IO_COUNTERS``, present only to size the structure that embeds it."""

    _fields_: ClassVar = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JobBasicLimitInformation(ctypes.Structure):
    """Win32 ``JOBOBJECT_BASIC_LIMIT_INFORMATION``."""

    _fields_: ClassVar = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JobExtendedLimitInformation(ctypes.Structure):
    """Win32 ``JOBOBJECT_EXTENDED_LIMIT_INFORMATION``."""

    _fields_: ClassVar = [
        ("BasicLimitInformation", _JobBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _JobBasicUiRestrictions(ctypes.Structure):
    """Win32 ``JOBOBJECT_BASIC_UI_RESTRICTIONS``."""

    _fields_: ClassVar = [("UIRestrictionsClass", wintypes.DWORD)]


class _SidAndAttributes(ctypes.Structure):
    """Win32 ``SID_AND_ATTRIBUTES``."""

    _fields_: ClassVar = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TokenMandatoryLabel(ctypes.Structure):
    """Win32 ``TOKEN_MANDATORY_LABEL``."""

    _fields_: ClassVar = [("Label", _SidAndAttributes)]


class _StartupInfoW(ctypes.Structure):
    """Win32 ``STARTUPINFOW``."""

    _fields_: ClassVar = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _StartupInfoExW(ctypes.Structure):
    """Win32 ``STARTUPINFOEXW``."""

    _fields_: ClassVar = [("StartupInfo", _StartupInfoW), ("lpAttributeList", ctypes.c_void_p)]


class _ProcessInformation(ctypes.Structure):
    """Win32 ``PROCESS_INFORMATION``."""

    _fields_: ClassVar = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


@dataclass(frozen=True, slots=True)
class JobLimits:
    """The ceilings a sandboxed server's job object enforces.

    Attributes:
        active_process_limit: Processes the job may run at once, the server
            and every descendant included.
        process_memory_bytes: Committed-memory ceiling per process.
        job_memory_bytes: Committed-memory ceiling for the whole job.
    """

    active_process_limit: int = DEFAULT_ACTIVE_PROCESS_LIMIT
    process_memory_bytes: int = DEFAULT_PROCESS_MEMORY_BYTES
    job_memory_bytes: int = DEFAULT_JOB_MEMORY_BYTES


@dataclass(frozen=True, slots=True)
class SandboxedLaunch:
    """A confined launch, ready to be spawned.

    Attributes:
        command: The resolved program the operator configured, as a full
            path. For a ``.cmd`` or ``.bat`` shim this is the script.
        args: Its arguments, in order.
        application: The image actually executed: ``command`` itself, or
            the command interpreter when ``command`` is a batch script.
        env: The complete environment the child receives. This replaces the
            inherited environment; it is not merged over it.
        cwd: The confined working directory.
        writable: The directories the child may write to, resolved.
        temp_dir: The directory ``TEMP`` and ``TMP`` point at, inside
            ``home``.
        creation_flags: Win32 process creation flags.
        limits: The ceilings to apply to the job the child runs in.
        write_existing: Whether content already in the writable directories
            may be changed too.
        home: The server's own sandbox home.
    """

    command: str
    args: tuple[str, ...]
    application: str
    env: Mapping[str, str]
    cwd: str
    writable: tuple[str, ...]
    temp_dir: str
    creation_flags: int = SANDBOX_CREATION_FLAGS
    limits: JobLimits = field(default_factory=JobLimits)
    write_existing: bool = False
    home: SandboxHome | None = None

    @property
    def is_batch_script(self) -> bool:
        """Whether the configured program is a ``.cmd`` or ``.bat`` shim.

        Returns:
            bool: ``True`` when it runs through the command interpreter.
        """
        return PureWindowsPath(self.command).suffix.lower() in BATCH_SUFFIXES

    @property
    def command_line(self) -> str:
        """The command line handed to ``CreateProcessAsUserW``.

        Returns:
            str: The rendered command line.
        """
        return render_command_line(self.application, self.command, self.args)


@dataclass(frozen=True, slots=True)
class SandboxHome:
    """The directories one sandboxed server keeps its own state in.

    Attributes:
        root: The home's root directory.
    """

    root: str

    @property
    def temp(self) -> str:
        """The directory ``TEMP`` and ``TMP`` name.

        Returns:
            str: The temporary directory.
        """
        return str(Path(self.root, SANDBOX_TEMP_DIRNAME))

    def directories(self) -> tuple[str, ...]:
        """List every directory of the home, root first.

        Returns:
            tuple[str, ...]: The directories, each after its parent.
        """
        return (self.root, *(str(Path(self.root, relative)) for relative, _ in SANDBOX_HOME_LAYOUT))

    def environment(self) -> dict[str, str]:
        """Build the variables that point a launcher at this home.

        Returns:
            dict[str, str]: Each variable of :data:`SANDBOX_HOME_LAYOUT` and the directory it names.
        """
        return {name: str(Path(self.root, relative)) for relative, names in SANDBOX_HOME_LAYOUT for name in names}

    def create(self) -> None:
        """Create every directory of the home that does not exist yet."""
        for directory in self.directories():
            Path(directory).mkdir(parents=True, exist_ok=True)


def sandbox_home(server_id: str) -> SandboxHome:
    """Locate one server's sandbox home under Intellicrack's configuration directory.

    Args:
        server_id: The server id, which :data:`~intellicrack.mcp.config.SERVER_ID_PATTERN` keeps to a single safe path component.

    Returns:
        SandboxHome: The home. Nothing is created.
    """
    return SandboxHome(str(get_config_file(SANDBOX_HOMES_DIRNAME) / server_id))


_ACCESS_DENIED: Final[re.Pattern[str]] = re.compile(
    r"access is denied|access denied|\beacces\b|\beperm\b|permissionerror|operation not permitted|os error 5\b",
    re.IGNORECASE,
)
"""How the common runtimes report a write the sandbox refused."""

_QUOTED_WINDOWS_PATH: Final[re.Pattern[str]] = re.compile(r"""['"`]((?:[A-Za-z]:\\|\\\\)[^'"`]+)['"`]""")
"""A Windows path in quotes or backticks, as Python, Node and uv print the path they were refused."""


def sandbox_access_guidance(stderr_lines: Sequence[str]) -> str | None:
    """Tell the operator what to change when a sandboxed server failed on a refused access.

    The refused path is looked for on the line reporting the refusal and on the line before it, where uv names the cache it could not
    create.

    Args:
        stderr_lines: What the server wrote to its standard error, oldest first.

    Returns:
        str | None: The guidance, naming the refused path when the server's message carried one, or ``None`` when nothing the server
        wrote reads as a refused access.
    """
    refused = [index for index, line in enumerate(stderr_lines) if _ACCESS_DENIED.search(line)]
    if not refused:
        return None
    nearby = [stderr_lines[line] for index in reversed(refused) for line in (index, index - 1) if line >= 0]
    path = next((_unrepr_path(match.group(1)) for line in nearby if (match := _QUOTED_WINDOWS_PATH.search(line))), None)
    where = f" to {path}" if path is not None else ""
    return (
        f"The sandbox refused the server access{where}. If the server has to write there, add the folder under Writable folders "
        f"(sandbox.allowWrite), and turn on writeExisting if it changes files already in it. If it needs a variable from your own "
        f"environment, add the variable's name under Extra inherited variables (sandbox.inheritEnv)."
    )


def _unrepr_path(path: str) -> str:
    r"""Undo the doubled backslashes of a path Python printed with :func:`repr`.

    Python reports ``PermissionError: [WinError 5] Access is denied: 'C:\\x'``; Node and uv print the path as it is.

    Args:
        path: The path as the message carried it.

    Returns:
        str: The path with single separators.
    """
    doubled = path[2:4] == "\\\\" if path[1:2] == ":" else path.startswith("\\\\" * 2)
    return path.replace("\\\\", "\\") if doubled else path


def sandbox_supported() -> bool:
    """Report whether sandboxed launches are available on this platform.

    Returns:
        bool: ``True`` only on Windows.
    """
    return IS_WIN32


def build_environment_allowlist(
    env: Mapping[str, str],
    inherited: Mapping[str, str],
    home: SandboxHome,
    inherit: Sequence[str] = (),
) -> dict[str, str]:
    """Build the complete environment a confined child receives.

    Four layers, each overriding the one before: the inherited environment
    filtered to :data:`ENVIRONMENT_ALLOWLIST`; the variables pointing every
    launcher at the server's sandbox home; the inherited variables the
    operator named in ``inheritEnv``; and the server's own configured
    entries. Nothing else crosses: a credential sitting in Intellicrack's
    environment for one provider has no business reaching a third-party
    server. Names are compared without regard to case, as Windows compares
    them, so a later layer replaces an earlier entry rather than sitting
    beside it. The mapping is the child's whole environment; the spawn adds
    nothing to it.

    Args:
        env: The server's own resolved environment entries.
        inherited: The environment Intellicrack itself is running with.
        home: The server's sandbox home.
        inherit: Further variable names to pass through from ``inherited``.

    Returns:
        dict[str, str]: The environment to hand to the child.
    """
    wanted = {name.upper() for name in inherit}
    allowed: dict[str, str] = {}
    _merge_environment(allowed, {name: value for name, value in inherited.items() if name.upper() in ENVIRONMENT_ALLOWLIST})
    _merge_environment(allowed, home.environment())
    _merge_environment(allowed, {name: value for name, value in inherited.items() if name.upper() in wanted})
    _merge_environment(allowed, env)
    return allowed


def _merge_environment(target: dict[str, str], layer: Mapping[str, str]) -> None:
    """Lay one set of variables over another, comparing names as Windows does.

    Args:
        target: The environment being built, changed in place.
        layer: The variables that win over what ``target`` holds.
    """
    for name, value in layer.items():
        for existing in [key for key in target if key.upper() == name.upper()]:
            del target[existing]
        target[name] = value


def _lookup(env: Mapping[str, str], name: str) -> str | None:
    """Read an environment entry case-insensitively, as Windows does.

    Args:
        env: The environment to search.
        name: The variable name.

    Returns:
        str | None: The value, or ``None`` when absent.
    """
    wanted = name.upper()
    return next((value for key, value in env.items() if key.upper() == wanted), None)


def resolve_executable(command: str, env: Mapping[str, str]) -> str:
    """Resolve a configured command to the file a confined child runs.

    The search mirrors the Windows shell: a command with a directory part is
    taken as a path, anything else is looked up along the child's own
    ``PATH``, and a name without a suffix is tried with each ``PATHEXT``
    suffix in turn. The child's environment is used rather than
    Intellicrack's, because that is the environment the program will run in.

    Args:
        command: The configured launch command.
        env: The child's complete environment.

    Returns:
        str: The full path of the program to run.

    Raises:
        McpConfigError: If no matching file exists.
    """
    suffixes = [""] if PureWindowsPath(command).suffix else []
    pathext = _lookup(env, "PATHEXT") or DEFAULT_PATHEXT
    suffixes += [suffix.lower() for suffix in pathext.split(";") if suffix]
    candidate = PureWindowsPath(command)
    if candidate.anchor or len(candidate.parts) > 1:
        directories = [""]
    else:
        directories = [entry.strip('"') for entry in (_lookup(env, "PATH") or "").split(";") if entry.strip('"')]
    for directory in directories:
        for suffix in suffixes:
            path = Path(directory, f"{command}{suffix}") if directory else Path(f"{command}{suffix}")
            if path.is_file():
                return str(path.resolve())
    message = f"cannot find {command!r} for the sandboxed server on the PATH it will run with"
    raise McpConfigError(message)


def render_command_line(application: str, command: str, args: Sequence[str]) -> str:
    """Render the command line a confined child is created with.

    A native program gets the standard MSVC quoting of ``command`` and its
    arguments. A batch script cannot be executed directly; it runs as
    ``cmd.exe /d /v:off /s /c "..."`` with every token double-quoted, which
    keeps ``&``, ``|``, ``<``, ``>``, ``^`` and parentheses literal, and
    with the backslashes before each closing quote doubled for the program
    the script hands its arguments to. The characters in
    :data:`BATCH_UNSAFE_CHARACTERS` cannot be made literal for the
    interpreter and are refused.

    Args:
        application: The image executed.
        command: The configured program, resolved.
        args: The program's arguments.

    Returns:
        str: The command line.

    Raises:
        McpConfigError: If a batch script would receive an argument the
            command interpreter cannot pass through unchanged.
    """
    if PureWindowsPath(command).suffix.lower() not in BATCH_SUFFIXES:
        return " ".join(quote_windows_argument(token) for token in [command, *args])
    for index, token in enumerate([command, *args]):
        if found := [character for character in BATCH_UNSAFE_CHARACTERS if character in token]:
            rendered = " ".join(repr(character) for character in found)
            message = (
                f"argument {index} of batch script {command!r} contains {rendered}, which the command interpreter would rewrite; "
                f"launch the script's underlying program directly instead"
            )
            raise McpConfigError(message)
    quoted = " ".join(_quote_batch_token(token) for token in [command, *args])
    return f'"{application}" /d /v:off /s /c "{quoted}"'


def _quote_batch_token(token: str) -> str:
    r"""Double-quote one token of a batch script's command line.

    The script hands its arguments on, ``%*`` and all, to a program that
    parses them with the MSVC rules, where backslashes before a closing
    quote escape it. Those backslashes are doubled, so an argument ending in
    one, such as ``C:\proj\``, still ends where it should instead of
    swallowing every argument after it. The token holds no double quote:
    :func:`render_command_line` refuses those first.

    Args:
        token: The argument.

    Returns:
        str: The quoted token.
    """
    doubled = "\\" * (len(token) - len(token.rstrip("\\")))
    return f'"{token}{doubled}"'


def quote_windows_argument(argument: str) -> str:
    """Quote one argument the way the Microsoft C runtime parses it back.

    Backslashes are literal except before a double quote, where they are
    doubled and the quote is escaped. An argument containing a space or a
    tab, or an empty one, is wrapped in double quotes, with any backslashes
    before the closing quote doubled.

    Args:
        argument: The argument to quote.

    Returns:
        str: The argument as it must appear on a command line.
    """
    wrap = not argument or any(character in argument for character in " \t")
    parts: list[str] = ['"'] if wrap else []
    backslashes = 0
    for character in argument:
        if character == "\\":
            backslashes += 1
            continue
        if character == '"':
            parts.append("\\" * (backslashes * 2 + 1))
        else:
            parts.append("\\" * backslashes)
        backslashes = 0
        parts.append(character)
    if wrap:
        parts.extend(("\\" * (backslashes * 2), '"'))
    else:
        parts.append("\\" * backslashes)
    return "".join(parts)


def command_interpreter(inherited: Mapping[str, str]) -> str:
    """Locate the system command interpreter a batch script runs under.

    ``COMSPEC`` is deliberately not trusted: it is an ordinary variable
    anyone can point at another program. The interpreter is taken from the
    system directory instead.

    Args:
        inherited: The environment Intellicrack is running with.

    Returns:
        str: The full path of ``cmd.exe``.
    """
    root = _lookup(inherited, "SYSTEMROOT") or "C:\\Windows"
    return str(PureWindowsPath(root, "System32", "cmd.exe"))


def confine_working_directory(spec: StdioServerSpec, sandbox: McpSandboxSpec) -> str:
    """Resolve the working directory a confined child is restricted to.

    Args:
        spec: The server's launch description.
        sandbox: The server's sandbox settings.

    Returns:
        str: The resolved working directory.

    Raises:
        McpConfigError: If no writable location was nominated, the nominated
            directory does not exist, or the configured working directory
            lies outside every writable location.
    """
    writable = [Path(entry) for entry in sandbox.allow_write]
    if not writable:
        message = (
            "a sandboxed server needs at least one writable directory: set sandbox.allowWrite so the "
            "server has somewhere to work that you chose deliberately."
        )
        raise McpConfigError(message)

    for directory in writable:
        if not directory.is_dir():
            message = f"sandbox write path {directory} does not exist"
            raise McpConfigError(message)

    if spec.cwd is None:
        return str(writable[0].resolve())

    requested = Path(spec.cwd)
    if not requested.is_dir():
        message = f"working directory {spec.cwd!r} does not exist"
        raise McpConfigError(message)
    resolved = requested.resolve()
    if not any(_is_within(resolved, directory.resolve()) for directory in writable):
        allowed = ", ".join(str(directory) for directory in writable)
        message = f"working directory {spec.cwd!r} is outside every sandbox write path ({allowed})"
        raise McpConfigError(message)
    return str(resolved)


def _is_within(candidate: Path, root: Path) -> bool:
    """Report whether one path lies inside another.

    Args:
        candidate: The path to test.
        root: The directory it must be inside.

    Returns:
        bool: ``True`` when ``candidate`` is ``root`` or below it.
    """
    return candidate == root or root in candidate.parents


def plan_sandboxed_launch(
    spec: StdioServerSpec,
    sandbox: McpSandboxSpec,
    env: Mapping[str, str],
    inherited: Mapping[str, str],
    *,
    home: SandboxHome,
) -> SandboxedLaunch:
    """Work out every detail of a confined launch without touching the system.

    This is the platform-independent half of :func:`build_sandboxed_startup`:
    it resolves the program, the command line, the environment and the
    directories, and it performs no Win32 call.

    Args:
        spec: The server's launch description.
        sandbox: The server's sandbox settings.
        env: The server's own resolved environment entries.
        inherited: The environment to filter.
        home: The server's sandbox home.

    Returns:
        SandboxedLaunch: Everything needed to spawn the child confined.

    Raises:
        McpConfigError: If the sandbox is not enabled for this server, the
            command is empty or cannot be found, a batch script would
            receive an argument it cannot be passed safely, or the working
            directory cannot be confined.
    """
    if not sandbox.enabled:
        message = "sandboxing is not enabled for this server"
        raise McpConfigError(message)
    command = spec.command.strip()
    if not command:
        message = "a sandboxed server needs a launch command"
        raise McpConfigError(message)

    cwd = confine_working_directory(spec, sandbox)
    writable = tuple(str(Path(entry).resolve()) for entry in sandbox.allow_write)
    environment = build_environment_allowlist(env, inherited, home, sandbox.inherit_env)
    program = resolve_executable(command, environment)
    batch = PureWindowsPath(program).suffix.lower() in BATCH_SUFFIXES
    launch = SandboxedLaunch(
        command=program,
        args=tuple(spec.args),
        application=command_interpreter(inherited) if batch else program,
        env=environment,
        cwd=cwd,
        writable=writable,
        temp_dir=home.temp,
        write_existing=sandbox.write_existing,
        home=home,
    )
    _ = launch.command_line
    return launch


def build_sandboxed_startup(
    spec: StdioServerSpec,
    sandbox: McpSandboxSpec,
    env: Mapping[str, str],
    inherited: Mapping[str, str] | None = None,
    *,
    server_id: str,
) -> SandboxedLaunch:
    """Build the confined launch for one local server.

    A launch that cannot be planned propagates :class:`McpConfigError` from
    :func:`plan_sandboxed_launch`.

    Args:
        spec: The server's launch description.
        sandbox: The server's sandbox settings.
        env: The server's own resolved environment entries.
        inherited: The environment to filter, defaulting to the running
            process's own.
        server_id: The server, whose sandbox home the launch uses.

    Returns:
        SandboxedLaunch: Everything needed to spawn the child confined.

    Raises:
        McpConfigError: If the platform has no sandbox.
    """
    if not sandbox_supported():
        raise McpConfigError(_ERR_UNSUPPORTED_PLATFORM)
    launch = plan_sandboxed_launch(spec, sandbox, env, inherited if inherited is not None else os.environ, home=sandbox_home(server_id))
    _logger.info(
        "mcp_sandbox_launch_built",
        command=launch.command,
        application=launch.application,
        argument_count=len(launch.args),
        env_count=len(launch.env),
        cwd=launch.cwd,
        writable=list(launch.writable),
    )
    for limitation in sandbox_limitations(sandbox):
        _logger.warning("mcp_sandbox_limitation", limitation=limitation)
    for note in launcher_notes(spec.command):
        _logger.info("mcp_sandbox_launcher_note", server_id=server_id, note=note)
    return launch


@functools.cache
def _kernel32() -> ctypes.WinDLL:
    """Resolve the Win32 kernel API.

    Returns:
        ctypes.WinDLL: The ``kernel32`` library.

    Raises:
        McpConfigError: If called on a platform that has no Win32 API.
    """
    if not IS_WIN32:
        raise McpConfigError(_ERR_UNSUPPORTED_PLATFORM)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    kernel32.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel32.DeleteProcThreadAttributeList.restype = None
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
    kernel32.SetHandleInformation.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.AllocConsole.argtypes = []
    kernel32.AllocConsole.restype = wintypes.BOOL
    kernel32.GetConsoleWindow.argtypes = []
    kernel32.GetConsoleWindow.restype = wintypes.HWND
    kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
    kernel32.GetStdHandle.restype = wintypes.HANDLE
    kernel32.SetStdHandle.argtypes = [wintypes.DWORD, wintypes.HANDLE]
    kernel32.SetStdHandle.restype = wintypes.BOOL
    return kernel32


@functools.cache
def _user32() -> ctypes.WinDLL:
    """Resolve the Win32 window-management API.

    Returns:
        ctypes.WinDLL: The ``user32`` library.

    Raises:
        McpConfigError: If called on a platform that has no Win32 API.
    """
    if not IS_WIN32:
        raise McpConfigError(_ERR_UNSUPPORTED_PLATFORM)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wintypes.BOOL
    return user32


@functools.cache
def ensure_inheritable_console() -> None:
    """Give the launcher a console the confined tree can inherit, once per process.

    A console-subsystem child with no console to inherit allocates its own, and
    that allocation fails under the confined restricted token on a hosted
    runner, so every process in the tree must inherit one instead. When the
    launcher already has a console -- the usual case under a terminal --
    ``AllocConsole`` fails with ``ERROR_ACCESS_DENIED`` and the tree inherits
    that one. When it has none -- a windowed application -- a console is
    allocated here, under the launcher's own unrestricted token where the
    allocation succeeds, and its window is hidden so nothing flashes on screen.
    The launcher's own standard handles are saved across the call and restored,
    since ``AllocConsole`` repoints them at the new console and the launcher's
    own input and output must stay where they were.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`.
    """
    kernel32 = _kernel32()
    saved = [kernel32.GetStdHandle(std) for std in _STD_HANDLES]
    if not kernel32.AllocConsole():
        return
    window = kernel32.GetConsoleWindow()
    if window:
        _ = _user32().ShowWindow(window, _SW_HIDE)
    for std, handle in zip(_STD_HANDLES, saved, strict=True):
        _ = kernel32.SetStdHandle(std, handle)
    _logger.debug("mcp_sandbox_console_allocated")


@functools.cache
def _advapi32() -> ctypes.WinDLL:
    """Resolve the Win32 security API.

    Returns:
        ctypes.WinDLL: The ``advapi32`` library.

    Raises:
        McpConfigError: If called on a platform that has no Win32 API.
    """
    if not IS_WIN32:
        raise McpConfigError(_ERR_UNSUPPORTED_PLATFORM)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.CreateRestrictedToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.CreateRestrictedToken.restype = wintypes.BOOL
    advapi32.CreateWellKnownSid.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    advapi32.CreateWellKnownSid.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    advapi32.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    advapi32.SetTokenInformation.restype = wintypes.BOOL
    advapi32.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.POINTER(_ProcessInformation),
    ]
    advapi32.CreateProcessAsUserW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorSacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorSacl.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetFileSecurityW.restype = wintypes.BOOL
    advapi32.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    advapi32.SetFileSecurityW.restype = wintypes.BOOL
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.ULONG),
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
    return advapi32


def create_job_object() -> int:
    """Create the job object a sandboxed server runs inside.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`.

    Returns:
        int: The job handle. The caller owns it and must pass it to
        :func:`close_job_object`, which is also what terminates everything
        inside it.

    Raises:
        ctypes.WinError: If the job object could not be created.
    """
    kernel32 = _kernel32()
    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    _logger.debug("mcp_sandbox_job_created")
    return int(handle)


def apply_job_limits(handle: int, sandbox: McpSandboxSpec, limits: JobLimits | None = None) -> None:
    """Apply the confinement ceilings to a job object.

    ``KILL_ON_JOB_CLOSE`` is what makes teardown total: closing the handle
    terminates every process in the job, so a server that spawned children
    of its own cannot survive its connection being dropped. Breakaway is not
    permitted, so no process in the job can start a child outside it.

    Args:
        handle: The job handle from :func:`create_job_object`.
        sandbox: The server's sandbox settings, checked so a disabled
            sandbox cannot be applied by mistake.
        limits: The ceilings to enforce, defaulting to :class:`JobLimits`.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`.

    Raises:
        McpConfigError: If the sandbox is not enabled for this server.
        ctypes.WinError: If a limit could not be set.
    """
    if not sandbox.enabled:
        message = "sandboxing is not enabled for this server"
        raise McpConfigError(message)
    kernel32 = _kernel32()
    ceilings = limits if limits is not None else JobLimits()

    extended = _JobExtendedLimitInformation()
    extended.BasicLimitInformation.LimitFlags = (
        _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | _JOB_OBJECT_LIMIT_JOB_MEMORY
        | _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    extended.BasicLimitInformation.ActiveProcessLimit = ceilings.active_process_limit
    extended.ProcessMemoryLimit = ceilings.process_memory_bytes
    extended.JobMemoryLimit = ceilings.job_memory_bytes
    if not kernel32.SetInformationJobObject(
        wintypes.HANDLE(handle),
        _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(extended),
        ctypes.sizeof(extended),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    restrictions = _JobBasicUiRestrictions(UIRestrictionsClass=_UI_RESTRICTIONS)
    if not kernel32.SetInformationJobObject(
        wintypes.HANDLE(handle),
        _JOB_OBJECT_BASIC_UI_RESTRICTIONS,
        ctypes.byref(restrictions),
        ctypes.sizeof(restrictions),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    _logger.info(
        "mcp_sandbox_limits_applied",
        active_process_limit=ceilings.active_process_limit,
        process_memory_bytes=ceilings.process_memory_bytes,
        job_memory_bytes=ceilings.job_memory_bytes,
        allowed_domains=list(sandbox.allowed_domains),
        allowed_domains_enforced=False,
    )


def assign_process_to_job(handle: int, pid: int) -> None:
    """Place a running process, and everything it later spawns, into a job.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`.

    Args:
        handle: The job handle.
        pid: The process to place in it.

    Raises:
        ctypes.WinError: If the process could not be opened or assigned.
    """
    kernel32 = _kernel32()
    process = kernel32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, _DO_NOT_INHERIT_HANDLE, pid)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not kernel32.AssignProcessToJobObject(wintypes.HANDLE(handle), process):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        _ = kernel32.CloseHandle(process)
    _logger.info("mcp_sandbox_process_assigned", pid=pid)


def terminate_job(handle: int, exit_code: int = 1) -> None:
    """Terminate every process in a job.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`.

    Args:
        handle: The job handle.
        exit_code: Exit code reported for the terminated processes.
    """
    kernel32 = _kernel32()
    if not kernel32.TerminateJobObject(wintypes.HANDLE(handle), exit_code):
        _logger.warning("mcp_sandbox_job_terminate_failed", error=ctypes.get_last_error())


def close_job_object(handle: int) -> None:
    """Close a job handle, terminating everything still inside it.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`.

    Args:
        handle: The job handle.
    """
    kernel32 = _kernel32()
    if not kernel32.CloseHandle(wintypes.HANDLE(handle)):
        _logger.warning("mcp_sandbox_job_close_failed", error=ctypes.get_last_error())
    else:
        _logger.debug("mcp_sandbox_job_closed")


def _well_known_sid(advapi32: ctypes.WinDLL, sid_type: int) -> ctypes.Array[ctypes.c_char]:
    """Build one well-known security identifier.

    Args:
        advapi32: The security API.
        sid_type: The ``WELL_KNOWN_SID_TYPE`` value.

    Returns:
        ctypes.Array[ctypes.c_char]: A buffer holding the SID.

    Raises:
        ctypes.WinError: If the SID could not be built.
    """
    buffer = ctypes.create_string_buffer(_SECURITY_MAX_SID_SIZE)
    size = wintypes.DWORD(_SECURITY_MAX_SID_SIZE)
    if not advapi32.CreateWellKnownSid(sid_type, None, buffer, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer


def _restricted_copy(own: wintypes.HANDLE, administrators: ctypes.Array[ctypes.c_char]) -> wintypes.HANDLE:
    """Copy a token with its privileges stripped and Administrators deny-only.

    Args:
        own: The token to copy.
        administrators: The Administrators group SID.

    Returns:
        wintypes.HANDLE: The restricted copy. The caller owns it.

    Raises:
        ctypes.WinError: If the copy could not be made.
    """
    restricted = wintypes.HANDLE()
    disabled = _SidAndAttributes(Sid=ctypes.cast(administrators, ctypes.c_void_p), Attributes=0)
    if not _advapi32().CreateRestrictedToken(
        own,
        _DISABLE_MAX_PRIVILEGE,
        1,
        ctypes.byref(disabled),
        0,
        None,
        0,
        None,
        ctypes.byref(restricted),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return restricted


def _lower_integrity(token: wintypes.HANDLE, label_sid: ctypes.Array[ctypes.c_char]) -> int:
    """Set a token's integrity level.

    Args:
        token: The token to lower.
        label_sid: The mandatory label SID to give it.

    Returns:
        int: Zero on success, else the Win32 error code.
    """
    advapi32 = _advapi32()
    label = _TokenMandatoryLabel()
    label.Label.Sid = ctypes.cast(label_sid, ctypes.c_void_p)
    label.Label.Attributes = _SE_GROUP_INTEGRITY
    size = ctypes.sizeof(label) + advapi32.GetLengthSid(label_sid)
    if advapi32.SetTokenInformation(token, _TOKEN_INTEGRITY_LEVEL_CLASS, ctypes.byref(label), size):
        return 0
    return ctypes.get_last_error()


def create_restricted_token() -> int:
    """Derive the primary token a confined server runs with.

    The token is a restricted copy of Intellicrack's own: every privilege
    except change-notify is removed, the Administrators group is made
    deny-only so an elevated operator's rights do not reach the server, and
    the integrity level is lowered to Low. Being derived from the caller's
    own token is what lets it be assigned to a new process without the
    ``SeAssignPrimaryTokenPrivilege`` a foreign token would need.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`, and a token that cannot be copied propagates
    ``ctypes.WinError`` from :func:`_restricted_copy`.

    Returns:
        int: The token handle. The caller owns it and must close it.

    Raises:
        ctypes.WinError: If the process token could not be opened or the copy
            could not be lowered to Low integrity.
    """
    kernel32 = _kernel32()
    advapi32 = _advapi32()
    administrators = _well_known_sid(advapi32, _WIN_BUILTIN_ADMINISTRATORS_SID)
    low = _well_known_sid(advapi32, _WIN_LOW_LABEL_SID)
    own = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_ACCESS, ctypes.byref(own)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        restricted = _restricted_copy(own, administrators)
    finally:
        _ = kernel32.CloseHandle(own)
    if error := _lower_integrity(restricted, low):
        _ = kernel32.CloseHandle(restricted)
        raise ctypes.WinError(error)
    _logger.debug("mcp_sandbox_token_restricted")
    return int(restricted.value or 0)


@dataclass(frozen=True, slots=True)
class WriteGrant:
    """One directory made writable to Low integrity processes, and how to undo it.

    Attributes:
        directory: The directory, resolved.
        original_label: The directory's mandatory label before the grant, in
            SDDL; ``"S:"`` when it carried none.
        existing: Whether content already in the directory was relabelled
            too, rather than only the directory itself.
    """

    directory: str
    original_label: str
    existing: bool


def _security_descriptor_from_sddl(sddl: str) -> ctypes.c_void_p:
    """Build a self-relative security descriptor from SDDL.

    Args:
        sddl: The descriptor's SDDL.

    Returns:
        ctypes.c_void_p: The descriptor. The caller frees it with ``LocalFree``.

    Raises:
        ctypes.WinError: If the SDDL could not be converted.
    """
    descriptor = ctypes.c_void_p()
    if not _advapi32().ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return descriptor


def read_mandatory_label(path: str) -> str:
    """Read a file or directory's mandatory label as SDDL.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`.

    Args:
        path: The file or directory.

    Returns:
        str: The label's SDDL, such as ``"S:(ML;OICI;NW;;;LW)"``, or
        ``"S:"`` when the object carries no explicit label.

    Raises:
        ctypes.WinError: If the label could not be read.
    """
    kernel32 = _kernel32()
    advapi32 = _advapi32()
    needed = wintypes.DWORD(0)
    _ = advapi32.GetFileSecurityW(path, _LABEL_SECURITY_INFORMATION, None, 0, ctypes.byref(needed))
    if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER or not needed.value:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_string_buffer(needed.value)
    if not advapi32.GetFileSecurityW(path, _LABEL_SECURITY_INFORMATION, buffer, needed, ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    text = wintypes.LPWSTR()
    length = wintypes.ULONG(0)
    if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        buffer,
        _SDDL_REVISION_1,
        _LABEL_SECURITY_INFORMATION,
        ctypes.byref(text),
        ctypes.byref(length),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        rendered = text.value or ""
    finally:
        _ = kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    return rendered if _MANDATORY_LABEL_MARKER in rendered else _NO_LABEL_SDDL


def set_mandatory_label(path: str, sddl: str, *, propagate: bool) -> None:
    """Set a file or directory's mandatory label.

    Without ``propagate`` only the object itself changes: its children keep
    their labels, and an inheritable label reaches only what is created in it
    afterwards. With ``propagate`` the change is carried to every descendant,
    which adds an inheritable label to all of them or withdraws one they
    inherited.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`.

    Args:
        path: The file or directory.
        sddl: The label's SDDL; ``"S:"`` removes any explicit label.
        propagate: Whether descendants follow the change.

    Raises:
        ctypes.WinError: If the label could not be built or applied.
    """
    kernel32 = _kernel32()
    advapi32 = _advapi32()
    descriptor = _security_descriptor_from_sddl(sddl)
    try:
        if not propagate:
            if not advapi32.SetFileSecurityW(path, _LABEL_SECURITY_INFORMATION, descriptor):
                raise ctypes.WinError(ctypes.get_last_error())
            return
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        sacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorSacl(descriptor, ctypes.byref(present), ctypes.byref(sacl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_unicode_buffer(path)
        status = advapi32.SetNamedSecurityInfoW(buffer, _SE_FILE_OBJECT, _LABEL_SECURITY_INFORMATION, None, None, None, sacl)
        if status:
            raise ctypes.WinError(status)
    finally:
        _ = kernel32.LocalFree(descriptor)


def label_directory_low_integrity(directory: str, *, existing: bool = False) -> None:
    """Let Low integrity processes create files inside one directory.

    The directory receives a Low mandatory label that whatever is created in
    it inherits. Its access control list is untouched, so it grants nobody
    anything it did not already grant. Content already inside keeps its own
    label unless ``existing`` is set, in which case the label is carried to
    every descendant too.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`, and a label that cannot be built or applied
    propagates ``ctypes.WinError`` from :func:`set_mandatory_label`.

    Args:
        directory: The directory the confined server may write to.
        existing: Whether content already inside becomes writable too.
    """
    set_mandatory_label(directory, _LOW_LABEL_SDDL, propagate=existing)
    _logger.info("mcp_sandbox_write_path_labelled", directory=directory, existing=existing)


class WriteGrantLedger:
    """Every Low integrity write grant this process holds, counted and recorded on disk.

    Two servers may nominate the same directory. The first grant records the directory's original label; later ones only count, and the
    label is put back when the last of them is revoked. Each grant in force is also written to :data:`GRANTS_FILENAME`, so a grant a crash
    left behind can be reverted at the next start.
    """

    def __init__(self, path: Path | None = None) -> None:
        """Start with no grants.

        Args:
            path: The file grants are recorded in, defaulting to
                :data:`GRANTS_FILENAME` in Intellicrack's configuration
                directory, resolved when first needed.
        """
        self._path = path
        self._lock = threading.Lock()
        self._held: dict[str, tuple[int, WriteGrant]] = {}

    def _record(self) -> LockedJsonFile:
        """Open the file grants are recorded in.

        Returns:
            LockedJsonFile: The ledger file.
        """
        return LockedJsonFile(self._path if self._path is not None else get_config_file(GRANTS_FILENAME))

    def held(self) -> tuple[WriteGrant, ...]:
        """List the grants this ledger holds.

        Returns:
            tuple[WriteGrant, ...]: One per directory, in no particular order.
        """
        with self._lock:
            return tuple(grant for _, grant in self._held.values())

    def acquire(self, directory: str, *, existing: bool) -> WriteGrant:
        """Make one directory writable at Low integrity, or count another holder of it.

        Args:
            directory: The directory, resolved.
            existing: Whether content already inside is made writable too.

        Returns:
            WriteGrant: The grant in force.

        Raises:
            McpConfigError: If the directory's label could not be read,
                recorded or changed. Nothing is left changed.
        """
        key = os.path.normcase(directory)
        with self._lock:
            held = self._held.get(key)
            if held is not None:
                count, grant = held
                if existing and not grant.existing:
                    self._apply(grant.directory, existing=True)
                    grant = WriteGrant(grant.directory, grant.original_label, existing=True)
                self._held[key] = (count + 1, grant)
                return grant
            try:
                original = read_mandatory_label(directory)
            except OSError as exc:
                message = f"cannot read the integrity label of sandbox write path {directory}: {exc}"
                raise McpConfigError(message) from exc
            grant = WriteGrant(directory, original, existing=existing)
            self._remember(key, grant)
            try:
                self._apply(directory, existing=existing)
            except McpConfigError:
                self._forget(key)
                raise
            self._held[key] = (1, grant)
            _logger.info("mcp_sandbox_write_granted", directory=directory, existing=existing, original_label=original)
            return grant

    def release(self, grant: WriteGrant) -> None:
        """Give up one holder of a grant, reverting the directory when it was the last.

        Args:
            grant: The grant being given up.
        """
        key = os.path.normcase(grant.directory)
        with self._lock:
            held = self._held.get(key)
            if held is None:
                return
            count, current = held
            if count > 1:
                self._held[key] = (count - 1, current)
                return
            del self._held[key]
            if revert_write_grant(current):
                self._forget(key)

    @staticmethod
    def _apply(directory: str, *, existing: bool) -> None:
        """Put the Low label on a directory.

        Args:
            directory: The directory.
            existing: Whether content already inside is relabelled too.

        Raises:
            McpConfigError: If the label could not be applied.
        """
        try:
            label_directory_low_integrity(directory, existing=existing)
        except OSError as exc:
            message = f"cannot make sandbox write path {directory} writable at low integrity: {exc}"
            raise McpConfigError(message) from exc

    def _remember(self, key: str, grant: WriteGrant) -> None:
        """Record a grant on disk before it takes effect.

        Args:
            key: The directory's normalized key.
            grant: The grant.

        Raises:
            McpConfigError: If the record could not be written, in which case
                no label is changed.
        """

        def _add(data: JsonObject) -> bool:
            """Add the grant.

            Args:
                data: The decoded ledger.

            Returns:
                bool: Always ``True``.
            """
            data[key] = {"directory": grant.directory, "originalLabel": grant.original_label, "existing": grant.existing}
            return True

        try:
            _ = self._record().update(_add)
        except JsonDocumentError as exc:
            message = f"cannot record the sandbox write grant for {grant.directory}: {exc}"
            raise McpConfigError(message) from exc

    def _forget(self, key: str) -> None:
        """Drop a grant's record once it has been reverted.

        Args:
            key: The directory's normalized key.
        """

        def _drop(data: JsonObject) -> bool:
            """Drop the grant.

            Args:
                data: The decoded ledger.

            Returns:
                bool: Whether it was recorded.
            """
            return data.pop(key, None) is not None

        try:
            _ = self._record().update(_drop)
        except JsonDocumentError as exc:
            _logger.warning("mcp_sandbox_grant_record_unremoved", key=key, error=str(exc))

    def revert_stale(self) -> int:
        """Revert every recorded grant this process does not hold.

        Returns:
            int: How many grants were reverted.
        """
        try:
            recorded = self._record().read()
        except JsonDocumentError as exc:
            _logger.warning("mcp_sandbox_grant_ledger_unreadable", error=str(exc))
            return 0
        reverted = 0
        for key, entry in recorded.items():
            with self._lock:
                if key in self._held:
                    continue
            if not is_json_object(entry):
                self._forget(key)
                continue
            directory = entry.get("directory")
            original = entry.get("originalLabel")
            if not isinstance(directory, str) or not isinstance(original, str):
                self._forget(key)
                continue
            if revert_write_grant(WriteGrant(directory, original, existing=entry.get("existing") is True)):
                self._forget(key)
                reverted += 1
        return reverted


def revert_write_grant(grant: WriteGrant) -> bool:
    """Put a directory's original label back and withdraw the Low label from its content.

    The original label is restored with propagation, so every file and
    folder that inherited the Low label while the grant was in force -- all
    of the directory's content when ``existing`` was chosen, otherwise only
    what the server created -- loses it again.

    Args:
        grant: The grant to revert.

    Returns:
        bool: ``True`` when the directory is back as it was, ``False`` when it
        no longer exists or could not be changed, which is logged.
    """
    if not Path(grant.directory).exists():
        _logger.info("mcp_sandbox_write_grant_target_gone", directory=grant.directory)
        return True
    try:
        set_mandatory_label(grant.directory, grant.original_label, propagate=True)
    except OSError as exc:
        _logger.warning("mcp_sandbox_write_grant_unreverted", directory=grant.directory, error=str(exc))
        return False
    _logger.info("mcp_sandbox_write_revoked", directory=grant.directory)
    return True


_GRANTS = WriteGrantLedger()


def revert_stale_write_grants() -> int:
    """Revert every write grant a previous run left in force.

    Returns:
        int: How many grants were reverted; ``0`` on a platform with no
        sandbox.
    """
    if not sandbox_supported():
        return 0
    return _GRANTS.revert_stale()


def apply_write_confinement(launch: SandboxedLaunch) -> tuple[WriteGrant, ...]:
    """Make exactly the nominated directories writable to the confined child.

    Every ``allowWrite`` directory receives an inheritable Low mandatory
    label, on the directory alone unless ``writeExisting`` was chosen. The
    server's sandbox home is created and made writable throughout, since
    everything in it is the server's own from an earlier run. Blocking: run
    it on a worker thread.

    Args:
        launch: The planned launch.

    Returns:
        tuple[WriteGrant, ...]: The grants now in force, to be handed to
        :func:`release_write_confinement` once the server has stopped.

    Raises:
        McpConfigError: If a directory could not be labelled or the
            sandbox home could not be created. Every grant already made is
            reverted first.
    """
    grants: list[WriteGrant] = []
    try:
        grants.extend(_prepare_home(launch))
        grants.extend(_GRANTS.acquire(directory, existing=launch.write_existing) for directory in launch.writable)
    except OSError as exc:
        release_write_confinement(tuple(grants))
        message = f"cannot create the sandbox home {launch.home.root if launch.home is not None else launch.temp_dir}: {exc}"
        raise McpConfigError(message) from exc
    except McpConfigError:
        release_write_confinement(tuple(grants))
        raise
    return tuple(grants)


def _prepare_home(launch: SandboxedLaunch) -> tuple[WriteGrant, ...]:
    """Create a launch's sandbox home and make it writable to the child throughout.

    A launch built without a home gets its temporary directory created and nothing granted, since it lies inside a directory that is.
    A directory that cannot be created propagates :class:`OSError`, and one that cannot be labelled :class:`McpConfigError` from
    :meth:`WriteGrantLedger.acquire`.

    Args:
        launch: The planned launch.

    Returns:
        tuple[WriteGrant, ...]: The grant on the home, or nothing.
    """
    home = launch.home
    if home is None:
        Path(launch.temp_dir).mkdir(parents=True, exist_ok=True)
        return ()
    home.create()
    return (_GRANTS.acquire(str(Path(home.root).resolve()), existing=True),)


def release_write_confinement(grants: Sequence[WriteGrant]) -> None:
    """Give up the grants one confined launch held. Blocking: run it on a worker thread.

    Args:
        grants: The grants :func:`apply_write_confinement` returned.
    """
    for grant in reversed(grants):
        _GRANTS.release(grant)


def environment_block(env: Mapping[str, str]) -> str:
    """Render an environment as a Win32 Unicode environment block.

    Entries are sorted case-insensitively by name, as ``CreateProcess``
    requires, each is terminated by a NUL, and the block ends with a second
    NUL.

    Args:
        env: The complete environment.

    Returns:
        str: The block, including its terminating NULs.

    Raises:
        McpConfigError: If a name is empty or contains ``=``, or an entry
            contains a NUL.
    """
    entries: list[str] = []
    for name in sorted(env, key=str.upper):
        value = env[name]
        if not name or "=" in name or "\0" in name or "\0" in value:
            message = f"environment entry {name!r} cannot be passed to a Windows process"
            raise McpConfigError(message)
        entries.append(f"{name}={value}\0")
    return "".join(entries) + "\0"


def describe_exit_code(code: int) -> str:
    """Render a process exit code so the operator can tell a crash from an ordinary exit.

    A code with the Windows error severity bits set is a status value the
    system or the loader ended the process with rather than one the program
    chose, so it is shown in hexadecimal and, when it is one a confined
    server commonly dies with, by name and meaning.

    Args:
        code: The exit code, as ``GetExitCodeProcess`` reports it.

    Returns:
        str: The description, such as ``exit code 3`` or
        ``exit code 0xc0000135 (STATUS_DLL_NOT_FOUND: ...)``.
    """
    unsigned = code & 0xFFFFFFFF
    if unsigned & _NTSTATUS_ERROR_SEVERITY != _NTSTATUS_ERROR_SEVERITY:
        return f"exit code {unsigned}"
    known = NTSTATUS_EXIT_CODES.get(unsigned)
    if known is None:
        return f"exit code {unsigned:#010x}"
    name, meaning = known
    return f"exit code {unsigned:#010x} ({name}: {meaning})"


class SandboxedServerExitedError(McpConnectionError):
    """A confined server's process ended while its session still needed it.

    Without this the session reports only that the connection closed, which
    says nothing about why: a server that could not load a DLL, open its
    script, or reach a directory with the sandbox's token dies before it
    writes a byte to standard output.

    Attributes:
        pid: The server's process id.
        exit_code: What the process exited with, or ``None`` when it was
            ended by the sandbox rather than by itself or its code could not
            be read.
        stderr_tail: The last lines the server wrote to standard error,
            oldest first.
    """

    pid: int
    exit_code: int | None
    stderr_tail: tuple[str, ...]

    def __init__(self, pid: int, exit_code: int | None, stderr_tail: Sequence[str]) -> None:
        """Describe the exit.

        Args:
            pid: The server's process id.
            exit_code: What the process exited with, or ``None`` when unknown.
            stderr_tail: The last lines it wrote to standard error.
        """
        self.pid = pid
        self.exit_code = exit_code
        self.stderr_tail = tuple(clean_untrusted_label(line, limit=STDERR_TAIL_LINE_CHARS) for line in stderr_tail)
        how = f"exited with {describe_exit_code(exit_code)}" if exit_code is not None else "stopped without an exit code of its own"
        said = (
            f"its last standard error output was: {' | '.join(self.stderr_tail)}"
            if self.stderr_tail
            else "it wrote nothing to standard error"
        )
        super().__init__(f"the sandboxed server process {pid} {how} before its session ended; {said}")


class StderrTee:
    """Carries a confined server's standard error to its log while keeping the last lines.

    The child writes to a pipe of the tee's own; a reader thread forwards
    every byte, unchanged and as it arrives, to the log the caller supplied,
    and keeps the most recent lines so the reason a server died can be put
    in the error that reports it. The thread ends when every process holding
    the write end has closed it, which for a confined server is when its job
    has ended.
    """

    def __init__(self, errlog: TextIO, read_fd: int, write_fd: int) -> None:
        """Wrap an open pipe; use :meth:`open` to create one.

        Args:
            errlog: Where the server's standard error is forwarded.
            read_fd: Read end, owned by the tee.
            write_fd: Write end, owned by the tee until :meth:`close_writer`.
        """
        self._errlog_fd = errlog.fileno()
        self._read_fd: int | None = read_fd
        self._writer: TextIO | None = os.fdopen(write_fd, "w", encoding="utf-8")
        self._lines: deque[str] = deque(maxlen=STDERR_TAIL_LINES)
        self._partial = ""
        self._lock = threading.Lock()
        self._forwarding = True
        self._thread = threading.Thread(target=self._drain, args=(read_fd,), name="mcp-sandbox-stderr", daemon=True)

    @classmethod
    def open(cls, errlog: TextIO) -> Self:
        """Create the pipe and start reading it.

        Args:
            errlog: Where the server's standard error is forwarded.

        Returns:
            Self: The running tee.
        """
        errlog.flush()
        read_fd, write_fd = os.pipe()
        tee = cls(errlog, read_fd, write_fd)
        tee._thread.start()
        return tee

    @property
    def writer(self) -> TextIO:
        """The write end to bind the child's standard error to.

        Returns:
            TextIO: The write end.

        Raises:
            McpConfigError: If :meth:`close_writer` already closed it.
        """
        if self._writer is None:
            message = "the stderr capture's write end is already closed"
            raise McpConfigError(message)
        return self._writer

    def close_writer(self) -> None:
        """Close the tee's own copy of the write end, once the child holds its own."""
        writer = self._writer
        self._writer = None
        if writer is not None:
            with suppress(OSError, ValueError):
                writer.close()

    def tail(self) -> list[str]:
        """Return the last lines read, the unterminated final one included.

        Returns:
            list[str]: Up to :data:`STDERR_TAIL_LINES` lines, oldest first.
        """
        with self._lock:
            lines = [*self._lines, self._partial.rstrip("\r")] if self._partial else list(self._lines)
        return lines[-STDERR_TAIL_LINES:]

    def finish(self, timeout_s: float = STDERR_DRAIN_TIMEOUT_S) -> None:
        """Wait for the server's standard error to end, then release the pipe.

        A reader still running when the wait runs out stops forwarding, so it
        never writes to a log its owner is about to close.

        Args:
            timeout_s: Longest wait for the reader to reach the end.
        """
        self.close_writer()
        if self._thread.is_alive():
            self._thread.join(timeout=timeout_s)
        if self._thread.is_alive():
            self._forwarding = False
            _logger.warning("mcp_sandbox_stderr_still_open", timeout_s=timeout_s)
            return
        read_fd = self._read_fd
        self._read_fd = None
        if read_fd is not None:
            with suppress(OSError):
                os.close(read_fd)

    def _drain(self, read_fd: int) -> None:
        """Forward and record the pipe's contents until it ends.

        Args:
            read_fd: The read end.
        """
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while True:
            try:
                chunk = os.read(read_fd, _STDERR_READ_BYTES)
            except OSError:
                _logger.debug("mcp_sandbox_stderr_reader_closed")
                break
            if not chunk:
                break
            self._forward(chunk)
            self._record(decoder.decode(chunk))
        self._record(decoder.decode(b"", final=True))

    def _forward(self, chunk: bytes) -> None:
        """Write one chunk to the caller's log, stopping for good once the log is gone.

        Args:
            chunk: Bytes the server wrote.
        """
        if not self._forwarding:
            return
        view = memoryview(chunk)
        try:
            while view:
                view = view[os.write(self._errlog_fd, view) :]
        except OSError:
            self._forwarding = False
            _logger.debug("mcp_sandbox_stderr_log_closed")

    def _record(self, text: str) -> None:
        """Split decoded text into lines and keep the most recent ones, each cut to :data:`STDERR_TAIL_LINE_CHARS`.

        Args:
            text: The newly decoded text.
        """
        if not text:
            return
        with self._lock:
            for index, piece in enumerate(text.split("\n")):
                if index:
                    self._lines.append(self._partial.rstrip("\r"))
                    self._partial = ""
                room = STDERR_TAIL_LINE_CHARS - len(self._partial)
                if room > 0:
                    self._partial += piece[:room]


@dataclass(slots=True)
class ConfinedProcess:
    """A server process created inside its job.

    Attributes:
        pid: The process id.
        handle: The process handle, owned by this object until closed.
        stdin: Writable end of the child's standard input.
        stdout: Readable end of the child's standard output.
    """

    pid: int
    handle: int
    stdin: BinaryIO
    stdout: BinaryIO

    def has_exited(self) -> bool:
        """Report whether the process has exited.

        Returns:
            bool: ``True`` once it has.
        """
        return self._wait_blocking(0)

    def exit_code(self) -> int | None:
        """Read the code the process exited with.

        Returns:
            int | None: The exit code, or ``None`` while the process is still
            running or once its handle is closed.
        """
        if not self.handle or not self.has_exited():
            return None
        code = wintypes.DWORD()
        if not _kernel32().GetExitCodeProcess(wintypes.HANDLE(self.handle), ctypes.byref(code)):
            _logger.warning("mcp_sandbox_exit_code_unreadable", pid=self.pid, error=ctypes.get_last_error())
            return None
        return int(code.value)

    def _wait_blocking(self, timeout_ms: int) -> bool:
        """Block the calling thread until the process exits or time runs out.

        Args:
            timeout_ms: Longest wait in milliseconds.

        Returns:
            bool: ``True`` when the process has exited.
        """
        return _kernel32().WaitForSingleObject(wintypes.HANDLE(self.handle), timeout_ms) == _WAIT_OBJECT_0

    async def wait(self, timeout_s: float) -> bool:
        """Wait, off the event loop, for the process to exit.

        The wait runs on a worker thread and is bounded by ``timeout_s``, so
        it cannot hold up the loop and cannot outlive its bound.

        Args:
            timeout_s: Longest wait in seconds.

        Returns:
            bool: ``True`` when the process has exited.
        """
        return await anyio.to_thread.run_sync(self._wait_blocking, max(0, int(timeout_s * 1000)))

    def close(self) -> None:
        """Close the process handle and the parent's ends of the pipes."""
        for stream in (self.stdin, self.stdout):
            with suppress(OSError, ValueError):
                stream.close()
        if self.handle:
            _ = _kernel32().CloseHandle(wintypes.HANDLE(self.handle))
            self.handle = 0


def _inheritable_handle(fd: int) -> int:
    """Mark a descriptor's OS handle inheritable and return it.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`.

    Args:
        fd: A descriptor the parent owns and will close after the spawn.

    Returns:
        int: The OS handle.

    Raises:
        ctypes.WinError: If the handle's inheritance could not be changed.
    """
    handle = msvcrt.get_osfhandle(fd)
    if not _kernel32().SetHandleInformation(wintypes.HANDLE(handle), _HANDLE_FLAG_INHERIT, _HANDLE_FLAG_INHERIT):
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


@dataclass(slots=True)
class _ChildPipes:
    """The descriptors behind one confined child's standard streams.

    Attributes:
        child_stdin: Read end the child's standard input is bound to.
        parent_stdin: Write end the parent keeps.
        child_stdout: Write end the child's standard output is bound to.
        parent_stdout: Read end the parent keeps.
        child_stderr: A duplicate of the stderr capture's write end.
    """

    child_stdin: int
    parent_stdin: int
    child_stdout: int
    parent_stdout: int
    child_stderr: int

    @classmethod
    def open(cls, errlog: TextIO) -> Self:
        """Create the pipes and duplicate the stderr capture.

        Args:
            errlog: Where the child's standard error is written.

        Returns:
            Self: The descriptors, every one owned by the caller.
        """
        child_stdin, parent_stdin = os.pipe()
        parent_stdout, child_stdout = os.pipe()
        return cls(
            child_stdin=child_stdin,
            parent_stdin=parent_stdin,
            child_stdout=child_stdout,
            parent_stdout=parent_stdout,
            child_stderr=os.dup(errlog.fileno()),
        )

    def close_child_ends(self) -> None:
        """Close the ends the child inherited, which the parent must not keep."""
        for fd in (self.child_stdin, self.child_stdout, self.child_stderr):
            with suppress(OSError):
                os.close(fd)

    def close_parent_ends(self) -> None:
        """Close the ends the parent kept, after a spawn that failed."""
        for fd in (self.parent_stdin, self.parent_stdout):
            with suppress(OSError):
                os.close(fd)


def _handle_list_attributes(handles: ctypes.Array[wintypes.HANDLE]) -> ctypes.Array[ctypes.c_char]:
    """Build a thread attribute list naming the only handles a child inherits.

    The caller must pass the result to ``DeleteProcThreadAttributeList``
    once the process is created, and must keep ``handles`` alive until then.

    Args:
        handles: The inheritable handles the child receives.

    Returns:
        ctypes.Array[ctypes.c_char]: The initialized attribute list.

    Raises:
        ctypes.WinError: If the list could not be sized, initialized or
            updated.
    """
    kernel32 = _kernel32()
    size = ctypes.c_size_t(0)
    _ = kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = ctypes.create_string_buffer(size.value)
    if not kernel32.InitializeProcThreadAttributeList(attributes, 1, 0, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel32.UpdateProcThreadAttribute(
        attributes,
        0,
        _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        handles,
        ctypes.sizeof(handles),
        None,
        None,
    ):
        error = ctypes.get_last_error()
        kernel32.DeleteProcThreadAttributeList(attributes)
        raise ctypes.WinError(error)
    return attributes


def _create_suspended_process(launch: SandboxedLaunch, token: int, pipes: _ChildPipes) -> _ProcessInformation:
    """Create a confined child with its first thread suspended.

    Args:
        launch: The planned launch.
        token: The restricted primary token.
        pipes: The child's standard stream descriptors.

    Returns:
        _ProcessInformation: The new process and its suspended thread.

    Raises:
        ctypes.WinError: If the process could not be created.
    """
    kernel32 = _kernel32()
    handles = (wintypes.HANDLE * 3)(
        _inheritable_handle(pipes.child_stdin),
        _inheritable_handle(pipes.child_stdout),
        _inheritable_handle(pipes.child_stderr),
    )
    attributes = _handle_list_attributes(handles)
    startup = _StartupInfoExW()
    startup.StartupInfo.cb = ctypes.sizeof(startup)
    startup.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
    startup.StartupInfo.hStdInput = handles[0]
    startup.StartupInfo.hStdOutput = handles[1]
    startup.StartupInfo.hStdError = handles[2]
    startup.lpAttributeList = ctypes.cast(attributes, ctypes.c_void_p)
    information = _ProcessInformation()
    command_line = ctypes.create_unicode_buffer(launch.command_line)
    environment = ctypes.create_unicode_buffer(environment_block(launch.env))
    created = _advapi32().CreateProcessAsUserW(
        wintypes.HANDLE(token),
        launch.application,
        command_line,
        None,
        None,
        _INHERIT_LISTED_HANDLES,
        launch.creation_flags,
        environment,
        launch.cwd,
        ctypes.byref(startup),
        ctypes.byref(information),
    )
    error = ctypes.get_last_error()
    kernel32.DeleteProcThreadAttributeList(attributes)
    if not created:
        raise ctypes.WinError(error)
    return information


class SandboxConfinementError(OSError):
    """A step of confining a newly created server process failed.

    Attributes:
        step: The Win32 call that failed, such as ``ResumeThread``.
        error: The last error read after it failed, zero when Windows gave none.
    """

    step: str
    error: int

    def __init__(self, step: str, error: int) -> None:
        """Describe the failed step.

        Args:
            step: The Win32 call that failed.
            error: The last error read after it failed, possibly zero.
        """
        if error:
            super().__init__(0, f"{step} failed with Windows error {error}", None, error)
        else:
            super().__init__(f"{step} failed without reporting a reason")
        self.step = step
        self.error = error


def check_resumed(previous_suspend_count: int, error: int) -> None:
    """Confirm that ``ResumeThread`` let a suspended server run.

    The failure is decided by the call's own result, never by the error
    code: Windows does not promise a non-zero last error for every failure,
    and a failed resume taken for success would leave the server suspended
    forever while its connection waited on it.

    Args:
        previous_suspend_count: What ``ResumeThread`` returned.
        error: The last error read straight after the call.

    Raises:
        SandboxConfinementError: If the call failed, whatever ``error`` reads.
    """
    if previous_suspend_count == _RESUME_FAILED:
        step = "ResumeThread"
        raise SandboxConfinementError(step, error)


def _confine_and_resume(information: _ProcessInformation, job: SandboxedJob) -> None:
    """Place a suspended process in its job, then let it run.

    A process that cannot be confined is terminated before it ever runs.

    Args:
        information: The suspended process and its thread.
        job: The open job.

    Raises:
        OSError: If the process could not be placed in the job, or its
            thread could not be resumed, whatever the last error read; the
            latter arrives as :class:`SandboxConfinementError` from
            :func:`check_resumed`.
        McpConfigError: If the job was not open.
    """
    kernel32 = _kernel32()
    try:
        job.adopt(int(information.dwProcessId))
        previous = kernel32.ResumeThread(information.hThread)
        check_resumed(previous, ctypes.get_last_error())
    except (OSError, McpConfigError):
        _ = kernel32.TerminateProcess(information.hProcess, 1)
        raise
    finally:
        _ = kernel32.CloseHandle(information.hThread)


def spawn_confined_process(launch: SandboxedLaunch, job: SandboxedJob, token: int, errlog: TextIO) -> ConfinedProcess:
    """Create a server process suspended, place it in its job, and resume it.

    The process is created with the restricted token, a handle list that
    lets it inherit exactly its three standard handles, and the launch's
    complete environment. It is assigned to the job before its first thread
    is resumed, so it can never run outside the job and neither can any
    process it starts.

    The child's pipe ends are inheritable only while
    :data:`~intellicrack.core.handle_inheritance.INHERITANCE_LOCK` is held,
    from before they are marked until after they are closed, so no other
    spawn in the process can hand them to a child of its own.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`. A failure to create the process propagates
    ``ctypes.WinError`` from :func:`_create_suspended_process`, and a failure
    to confine it propagates the same from :func:`_confine_and_resume`, after
    the process has been terminated.

    Args:
        launch: The planned launch.
        job: The open job.
        token: The restricted primary token.
        errlog: Where the child's standard error is written.

    Returns:
        ConfinedProcess: The running, confined process.

    Raises:
        OSError: If the process could not be created or confined. The
            parent's pipe ends are closed before it is raised.
        McpConfigError: If the job was not open. The process has been
            terminated and its pipe ends closed.
    """
    ensure_inheritable_console()
    pipes = _ChildPipes.open(errlog)
    with INHERITANCE_LOCK:
        try:
            information = _create_suspended_process(launch, token, pipes)
        except OSError:
            pipes.close_parent_ends()
            raise
        finally:
            pipes.close_child_ends()
    process = ConfinedProcess(
        pid=int(information.dwProcessId),
        handle=int(information.hProcess or 0),
        stdin=os.fdopen(pipes.parent_stdin, "wb", buffering=0),
        stdout=os.fdopen(pipes.parent_stdout, "rb", buffering=0),
    )
    try:
        _confine_and_resume(information, job)
    except (OSError, McpConfigError):
        process.close()
        raise
    _logger.info("mcp_sandbox_process_started", pid=process.pid, application=launch.application)
    return process


class SandboxedJob:
    """Owns one sandboxed server's job object for the life of its connection.

    Entering creates the job and applies the ceilings; a process is created inside it; leaving closes the handle, which terminates the
    server and every descendant it started.
    """

    def __init__(self, sandbox: McpSandboxSpec, limits: JobLimits | None = None) -> None:
        """Initialize the job wrapper.

        Args:
            sandbox: The server's sandbox settings.
            limits: The ceilings to enforce, defaulting to :class:`JobLimits`.
        """
        self._sandbox = sandbox
        self._limits = limits
        self._handle: int | None = None

    @property
    def handle(self) -> int | None:
        """The job handle while the job is open.

        Returns:
            int | None: The handle, or ``None`` before entry and after exit.
        """
        return self._handle

    def __enter__(self) -> Self:
        """Create the job and apply its ceilings.

        Returns:
            Self: This wrapper, with its job open.

        Raises:
            McpConfigError: If the platform has no sandbox, or it is not
                enabled for this server.
            OSError: If the job could not be created or limited. ``WinError``
                is the concrete type Win32 failures arrive as.
        """
        handle = create_job_object()
        try:
            apply_job_limits(handle, self._sandbox, self._limits)
        except (McpConfigError, OSError):
            close_job_object(handle)
            raise
        self._handle = handle
        return self

    def __exit__(self, *exc: object) -> None:
        """Close the job, terminating everything inside it.

        Args:
            *exc: Exception type, value and traceback, when the body raised.
        """
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        terminate_job(handle)
        close_job_object(handle)

    def adopt(self, pid: int) -> None:
        """Place a running process into this job.

        A process that could not be opened or assigned propagates
        :class:`OSError` from :func:`assign_process_to_job`.

        Args:
            pid: The process to confine.

        Raises:
            McpConfigError: If the job is not open.
        """
        handle = self._handle
        if handle is None:
            message = "the sandbox job is not open"
            raise McpConfigError(message)
        assign_process_to_job(handle, pid)


def parse_server_line(line: str) -> SessionMessage | Exception:
    """Parse one line a server wrote to its standard output.

    Args:
        line: One newline-delimited JSON-RPC message.

    Returns:
        SessionMessage | Exception: The message, or the parse error as a
        value so the session can surface it without the transport failing.
    """
    try:
        message = mcp_types.jsonrpc_message_adapter.validate_json(line, by_name=False)
    except ValueError as exc:
        _logger.warning("mcp_sandbox_unparseable_line", error=str(exc))
        return exc
    return SessionMessage(message)


@asynccontextmanager
async def pipe_session_streams(
    stdout: FileReadStream,
    stdin: FileWriteStream,
    shutdown: Callable[[], Awaitable[None]],
    on_output_end: Callable[[], None] | None = None,
) -> AsyncGenerator[tuple[Any, Any]]:
    """Bridge a server's standard pipes to the session's message streams.

    Standard output is split into lines and parsed; messages written to the
    session's write stream are serialized one per line onto standard input.
    When the server's output ends the read stream ends too, which is how the
    session learns the server has gone, and ``on_output_end`` is told so
    that the caller can tell a server that left from one it stopped.

    On exit the transport is wound down in order: traffic stops, standard
    input closes, and ``shutdown`` runs shielded so the server is stopped
    even under cancellation. ``shutdown`` must end the process, which is
    what unblocks the reads still waiting in worker threads.

    Args:
        stdout: The server's standard output.
        stdin: The server's standard input.
        shutdown: Stops the server process once its input has closed.
        on_output_end: Called when the server's standard output reaches its
            end while the session is still open, before the read stream is
            closed; an end reached during teardown is not reported.

    Yields:
        tuple[Any, Any]: The read stream and the write stream.
    """
    read_stream_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    stopping = False
    write_stream, write_stream_reader = anyio.create_memory_object_stream[SessionMessage](0)

    async def pump() -> None:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        buffer = ""
        while True:
            chunk = await stdout.receive(_STDOUT_READ_BYTES)
            lines = (buffer + decoder.decode(chunk)).split("\n")
            buffer = lines.pop()
            for line in lines:
                if line.strip():
                    await read_stream_writer.send(parse_server_line(line))

    async def read_output() -> None:
        async with read_stream_writer:
            with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
                try:
                    await pump()
                except anyio.EndOfStream:
                    if on_output_end is not None and not stopping:
                        on_output_end()

    async def write_input() -> None:
        async with write_stream_reader:
            with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
                async for session_message in write_stream_reader:
                    payload = session_message.message.model_dump_json(by_alias=True, exclude_unset=True)
                    await stdin.send(f"{payload}\n".encode())
        await read_stream_writer.aclose()

    async with anyio.create_task_group() as group:
        group.start_soon(read_output)
        group.start_soon(write_input)
        try:
            yield read_stream, write_stream
        finally:
            stopping = True
            with anyio.CancelScope(shield=True):
                write_stream.close()
                read_stream.close()
                with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
                    await stdin.aclose()
                await shutdown()
            group.cancel_scope.cancel()
    await anyio.lowlevel.cancel_shielded_checkpoint()


async def _stop_confined_process(process: ConfinedProcess, job: int) -> bool:
    """Give a confined server its grace period, then end its whole job.

    Args:
        process: The server process, whose standard input has closed.
        job: The job it runs in.

    Returns:
        bool: ``True`` when the server exited by itself within its grace
        period, ``False`` when it had to be terminated with its job.
    """
    exited = await process.wait(PROCESS_TERMINATION_GRACE_S)
    if not exited:
        _logger.info("mcp_sandbox_process_grace_expired", pid=process.pid)
    terminate_job(job)
    if not await process.wait(KILL_REAP_TIMEOUT_S):
        _logger.warning("mcp_sandbox_process_survived_termination", pid=process.pid)
    return exited


@dataclass(slots=True)
class _ServerEnd:
    """How a confined server's session came to an end.

    Attributes:
        output_ended: Whether the server's standard output reached its end
            while the client still held its session, which is how a server
            that left first is told from one that was stopped.
        exited_by_itself: Whether the process exited within its grace period
            rather than being terminated with its job.
    """

    output_ended: bool = False
    exited_by_itself: bool = False

    def mark_output_ended(self) -> None:
        """Record that the server's standard output reached its end."""
        self.output_ended = True

    def own_exit_code(self, process: ConfinedProcess) -> int | None:
        """Read the exit code the server chose or died with, never the one the sandbox gave it.

        Args:
            process: The server process.

        Returns:
            int | None: The exit code, or ``None`` when the process was
            terminated with its job or its code could not be read.
        """
        return process.exit_code() if self.exited_by_itself else None


def _log_server_end(process: ConfinedProcess, end: _ServerEnd) -> None:
    """Log how a confined server's process ended.

    Args:
        process: The server process, stopped.
        end: How its session ended.
    """
    code = end.own_exit_code(process)
    log = _logger.warning if end.output_ended else _logger.info
    log(
        "mcp_sandbox_process_exited",
        pid=process.pid,
        exit=describe_exit_code(code) if code is not None else None,
        left_before_client=end.output_ended,
        exited_by_itself=end.exited_by_itself,
    )


@asynccontextmanager
async def _confined_session(process: ConfinedProcess, job: int, stderr: StderrTee) -> AsyncGenerator[tuple[Any, Any]]:
    """Bridge a running confined server to its session, and say why when the server goes first.

    Args:
        process: The running server.
        job: The job it runs in.
        stderr: The capture its standard error passes through.

    Yields:
        tuple[Any, Any]: The read stream and the write stream.

    Raises:
        ExceptionGroup: The session's own failure, unchanged, when the
            server was still there as it failed.
        SandboxedServerExitedError: If the server's process ended before
            the client let go of a session that then failed.
    """
    end = _ServerEnd()

    async def shutdown() -> None:
        end.exited_by_itself = await _stop_confined_process(process, job)

    session = pipe_session_streams(FileReadStream(process.stdout), FileWriteStream(process.stdin), shutdown, end.mark_output_ended)
    try:
        async with session as streams:
            yield streams
    except ExceptionGroup as failure:
        if not end.output_ended:
            raise
        with anyio.CancelScope(shield=True):
            await anyio.to_thread.run_sync(stderr.finish)
        raise SandboxedServerExitedError(process.pid, end.own_exit_code(process), stderr.tail()) from failure
    finally:
        _log_server_end(process, end)


@asynccontextmanager
async def confined_stdio_client(
    launch: SandboxedLaunch,
    sandbox: McpSandboxSpec,
    errlog: TextIO,
) -> AsyncGenerator[tuple[Any, Any]]:
    """Run a local server fully confined and talk to it over its stdio.

    Order matters and is fixed: the job exists and carries its limits, the
    write paths carry their labels and the restricted token exists before
    the process is created, and the process is in the job before it runs.
    Teardown closes standard input, waits out the grace period, and then
    terminates the job, which takes every descendant with it; only then are
    the write paths' labels reverted, so nothing in the job can write to
    them while they change back. Labelling, reverting and the spawn itself
    run on a worker thread, so neither a large tree nor a spawn waiting on
    :data:`~intellicrack.core.handle_inheritance.INHERITANCE_LOCK` stalls the
    event loop.

    The child's standard error passes through a :class:`StderrTee` on its
    way to ``errlog``. When the server goes before the client has let go of
    its session and the session fails for it, the failure is reported as a
    :class:`SandboxedServerExitedError` naming the server's exit code and
    its last standard error lines, chained to what the session saw and
    propagated from :func:`_confined_session`, because a dropped connection
    alone does not say why a server died.

    A job, token or process that cannot be created propagates
    :class:`OSError` from :class:`SandboxedJob`,
    :func:`create_restricted_token` or :func:`spawn_confined_process`, and a
    write path that cannot be prepared propagates :class:`McpConfigError`
    from :func:`apply_write_confinement`.

    Args:
        launch: The planned launch.
        sandbox: The server's sandbox settings.
        errlog: Where the child's standard error is written.

    Yields:
        tuple[Any, Any]: The read stream and the write stream.

    Raises:
        McpConfigError: If the platform has no sandbox, or the job was not
            open once entered.
    """
    if not sandbox_supported():
        raise McpConfigError(_ERR_UNSUPPORTED_PLATFORM)
    with SandboxedJob(sandbox, launch.limits) as job:
        job_handle = job.handle
        if job_handle is None:
            message = "the sandbox job is not open"
            raise McpConfigError(message)
        stderr = StderrTee.open(errlog)
        try:
            grants = await anyio.to_thread.run_sync(apply_write_confinement, launch)
            try:
                token = create_restricted_token()
                try:
                    process = await anyio.to_thread.run_sync(spawn_confined_process, launch, job, token, stderr.writer)
                finally:
                    _ = _kernel32().CloseHandle(wintypes.HANDLE(token))
                    stderr.close_writer()
                try:
                    async with _confined_session(process, job_handle, stderr) as streams:
                        yield streams
                finally:
                    process.close()
            finally:
                with anyio.CancelScope(shield=True):
                    terminate_job(job_handle)
                    await anyio.to_thread.run_sync(release_write_confinement, grants)
        finally:
            with anyio.CancelScope(shield=True):
                await anyio.to_thread.run_sync(stderr.finish)
