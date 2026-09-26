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

* **Environment.** The child receives exactly :data:`ENVIRONMENT_ALLOWLIST` from Intellicrack's own environment plus the server's own
  configured entries. Nothing is merged in from anywhere else, so the API keys and tokens Intellicrack's environment carries do not travel.
* **Token.** Every privilege except change-notify is removed, the Administrators group is deny-only, and the integrity level is lowered to
  Low.
* **Writes.** A Low integrity process cannot write to anything labelled above Low, which by default is everything the operator owns. The
  directories in ``allowWrite`` are given a Low mandatory label (inherited by their contents) so the server can write there. Locations
  Windows itself labels Low, such as ``%USERPROFILE%\AppData\LocalLow``, remain writable to any Low integrity process, this one
  included. Reads are not restricted.
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
import sys
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

from intellicrack.core.logging import get_logger
from intellicrack.mcp.errors import McpConfigError


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

SANDBOX_CREATION_FLAGS: Final[int] = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW
"""Creation flags of every confined launch.

``CREATE_SUSPENDED`` is what keeps the job airtight: the process is placed in its job before its first thread runs, so neither the server
nor anything it starts ever executes outside the job. No breakaway flag is set, and the job does not permit breakaway.
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

SANDBOX_TEMP_DIRNAME: Final[str] = ".mcp-sandbox-tmp"
"""Directory created inside the first ``allowWrite`` entry for the child's ``TEMP`` and ``TMP``."""

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

_STDOUT_READ_BYTES: Final[int] = 65536

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

_SDDL_REVISION_1: Final[int] = 1
_SE_FILE_OBJECT: Final[int] = 1
_LABEL_SECURITY_INFORMATION: Final[int] = 0x00000010

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
        temp_dir: The directory ``TEMP`` and ``TMP`` point at.
        creation_flags: Win32 process creation flags.
        limits: The ceilings to apply to the job the child runs in.
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


def sandbox_supported() -> bool:
    """Report whether sandboxed launches are available on this platform.

    Returns:
        bool: ``True`` only on Windows.
    """
    return IS_WIN32


def sandbox_limitations(sandbox: McpSandboxSpec) -> tuple[str, ...]:
    """State plainly what a server's sandbox does not protect against.

    Args:
        sandbox: The server's sandbox settings.

    Returns:
        tuple[str, ...]: One sentence per limitation, empty when the sandbox
        is disabled and so claims nothing.
    """
    if not sandbox.enabled:
        return ()
    network = "Network access is not restricted: the server can connect to any host."
    if sandbox.allowed_domains:
        listed = ", ".join(sandbox.allowed_domains)
        network = f"Network access is not restricted: allowedDomains ({listed}) is recorded only and is not enforced."
    return (
        network,
        "Reads are not restricted: the server can read any file your account can read.",
        "Locations Windows labels low-integrity, such as AppData\\LocalLow, stay writable to the server.",
    )


def build_environment_allowlist(env: Mapping[str, str], inherited: Mapping[str, str], temp_dir: str) -> dict[str, str]:
    """Build the complete environment a confined child receives.

    The inherited environment is filtered to :data:`ENVIRONMENT_ALLOWLIST`,
    ``TEMP`` and ``TMP`` are pointed at the confined temporary directory, and
    the server's own configured entries are merged over the result. Nothing
    else crosses: a credential sitting in Intellicrack's environment for one
    provider has no business reaching a third-party server. The mapping is
    the child's whole environment; the spawn adds nothing to it.

    Args:
        env: The server's own resolved environment entries.
        inherited: The environment Intellicrack itself is running with.
        temp_dir: The directory the child's ``TEMP`` and ``TMP`` name.

    Returns:
        dict[str, str]: The environment to hand to the child.
    """
    allowed = {name: value for name, value in inherited.items() if name.upper() in ENVIRONMENT_ALLOWLIST}
    allowed |= {"TEMP": temp_dir, "TMP": temp_dir}
    allowed |= env
    return allowed


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
    keeps ``&``, ``|``, ``<``, ``>``, ``^`` and parentheses literal. The
    characters in :data:`BATCH_UNSAFE_CHARACTERS` cannot be made literal for
    the interpreter and are refused.

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
    quoted = " ".join(f'"{token}"' for token in [command, *args])
    return f'"{application}" /d /v:off /s /c "{quoted}"'


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
    temp_dir = str(Path(writable[0], SANDBOX_TEMP_DIRNAME))
    environment = build_environment_allowlist(env, inherited, temp_dir)
    program = resolve_executable(command, environment)
    batch = PureWindowsPath(program).suffix.lower() in BATCH_SUFFIXES
    launch = SandboxedLaunch(
        command=program,
        args=tuple(spec.args),
        application=command_interpreter(inherited) if batch else program,
        env=environment,
        cwd=cwd,
        writable=writable,
        temp_dir=temp_dir,
    )
    _ = launch.command_line
    return launch


def build_sandboxed_startup(
    spec: StdioServerSpec,
    sandbox: McpSandboxSpec,
    env: Mapping[str, str],
    inherited: Mapping[str, str] | None = None,
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

    Returns:
        SandboxedLaunch: Everything needed to spawn the child confined.

    Raises:
        McpConfigError: If the platform has no sandbox.
    """
    if not sandbox_supported():
        raise McpConfigError(_ERR_UNSUPPORTED_PLATFORM)
    launch = plan_sandboxed_launch(spec, sandbox, env, inherited if inherited is not None else os.environ)
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
    return kernel32


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


def label_directory_low_integrity(directory: str) -> None:
    """Let Low integrity processes write inside one directory.

    The directory receives a Low mandatory label that its files and
    subdirectories inherit. That is the only change: its access control list
    is untouched, so it grants nobody anything it did not already grant.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`.

    Args:
        directory: The directory the confined server may write to.

    Raises:
        ctypes.WinError: If the label could not be built or applied.
    """
    kernel32 = _kernel32()
    advapi32 = _advapi32()
    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        _LOW_LABEL_SDDL,
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        sacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorSacl(descriptor, ctypes.byref(present), ctypes.byref(sacl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        path = ctypes.create_unicode_buffer(directory)
        status = advapi32.SetNamedSecurityInfoW(path, _SE_FILE_OBJECT, _LABEL_SECURITY_INFORMATION, None, None, None, sacl)
        if status:
            raise ctypes.WinError(status)
    finally:
        _ = kernel32.LocalFree(descriptor)
    _logger.info("mcp_sandbox_write_path_labelled", directory=directory)


def apply_write_confinement(launch: SandboxedLaunch) -> None:
    """Make exactly the nominated directories writable to the confined child.

    Every ``allowWrite`` directory receives a Low mandatory label, and the
    child's temporary directory is created inside the first of them so it
    inherits that label.

    Args:
        launch: The planned launch.

    Raises:
        McpConfigError: If a directory could not be labelled or the
            temporary directory could not be created.
    """
    for directory in launch.writable:
        try:
            label_directory_low_integrity(directory)
        except OSError as exc:
            message = f"cannot make sandbox write path {directory} writable at low integrity: {exc}"
            raise McpConfigError(message) from exc
    try:
        Path(launch.temp_dir).mkdir(exist_ok=True)
    except OSError as exc:
        message = f"cannot create the sandbox temporary directory {launch.temp_dir}: {exc}"
        raise McpConfigError(message) from exc


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


def _confine_and_resume(information: _ProcessInformation, job: int) -> None:
    """Place a suspended process in its job, then let it run.

    A process that cannot be confined is terminated before it ever runs.

    Args:
        information: The suspended process and its thread.
        job: The open job handle.

    Raises:
        ctypes.WinError: If the assignment or the resume failed.
    """
    kernel32 = _kernel32()
    error = 0
    if (
        not kernel32.AssignProcessToJobObject(wintypes.HANDLE(job), information.hProcess)
        or kernel32.ResumeThread(information.hThread) == _RESUME_FAILED
    ):
        error = ctypes.get_last_error()
    _ = kernel32.CloseHandle(information.hThread)
    if error:
        _ = kernel32.TerminateProcess(information.hProcess, 1)
        raise ctypes.WinError(error)


def spawn_confined_process(launch: SandboxedLaunch, job: int, token: int, errlog: TextIO) -> ConfinedProcess:
    """Create a server process suspended, place it in its job, and resume it.

    The process is created with the restricted token, a handle list that
    lets it inherit exactly its three standard handles, and the launch's
    complete environment. It is assigned to the job before its first thread
    is resumed, so it can never run outside the job and neither can any
    process it starts.

    A platform with no sandbox propagates :class:`McpConfigError` from
    :func:`_kernel32`. A failure to create the process propagates
    ``ctypes.WinError`` from :func:`_create_suspended_process`, and a failure
    to confine it propagates the same from :func:`_confine_and_resume`, after
    the process has been terminated.

    Args:
        launch: The planned launch.
        job: The open job handle.
        token: The restricted primary token.
        errlog: Where the child's standard error is written.

    Returns:
        ConfinedProcess: The running, confined process.

    Raises:
        OSError: If the process could not be created or confined. The
            parent's pipe ends are closed before it is raised.
    """
    pipes = _ChildPipes.open(errlog)
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
    except OSError:
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
) -> AsyncGenerator[tuple[Any, Any]]:
    """Bridge a server's standard pipes to the session's message streams.

    Standard output is split into lines and parsed; messages written to the
    session's write stream are serialized one per line onto standard input.
    When the server's output ends the read stream ends too, which is how the
    session learns the server has gone.

    On exit the transport is wound down in order: traffic stops, standard
    input closes, and ``shutdown`` runs shielded so the server is stopped
    even under cancellation. ``shutdown`` must end the process, which is
    what unblocks the reads still waiting in worker threads.

    Args:
        stdout: The server's standard output.
        stdin: The server's standard input.
        shutdown: Stops the server process once its input has closed.

    Yields:
        tuple[Any, Any]: The read stream and the write stream.
    """
    read_stream_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    write_stream, write_stream_reader = anyio.create_memory_object_stream[SessionMessage](0)

    async def read_output() -> None:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        buffer = ""
        async with read_stream_writer:
            with suppress(anyio.EndOfStream, anyio.ClosedResourceError, anyio.BrokenResourceError):
                while True:
                    chunk = await stdout.receive(_STDOUT_READ_BYTES)
                    lines = (buffer + decoder.decode(chunk)).split("\n")
                    buffer = lines.pop()
                    for line in lines:
                        if line.strip():
                            await read_stream_writer.send(parse_server_line(line))

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
            with anyio.CancelScope(shield=True):
                write_stream.close()
                read_stream.close()
                with suppress(anyio.ClosedResourceError, anyio.BrokenResourceError):
                    await stdin.aclose()
                await shutdown()
            group.cancel_scope.cancel()
    await anyio.lowlevel.cancel_shielded_checkpoint()


async def _stop_confined_process(process: ConfinedProcess, job: int) -> None:
    """Give a confined server its grace period, then end its whole job.

    Args:
        process: The server process, whose standard input has closed.
        job: The job it runs in.
    """
    if not await process.wait(PROCESS_TERMINATION_GRACE_S):
        _logger.info("mcp_sandbox_process_grace_expired", pid=process.pid)
    terminate_job(job)
    if not await process.wait(KILL_REAP_TIMEOUT_S):
        _logger.warning("mcp_sandbox_process_survived_termination", pid=process.pid)


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
    terminates the job, which takes every descendant with it.

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
        apply_write_confinement(launch)
        token = create_restricted_token()
        try:
            process = spawn_confined_process(launch, job_handle, token, errlog)
        finally:
            _ = _kernel32().CloseHandle(wintypes.HANDLE(token))
        try:

            async def shutdown() -> None:
                await _stop_confined_process(process, job_handle)

            async with pipe_session_streams(FileReadStream(process.stdout), FileWriteStream(process.stdin), shutdown) as streams:
                yield streams
        finally:
            process.close()
