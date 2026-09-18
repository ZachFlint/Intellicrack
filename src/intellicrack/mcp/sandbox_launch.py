# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Windows confinement for a local Model Context Protocol server process.

A configured server is somebody else's program running with the operator's own account. Consent decides whether it runs at all; this module
decides what it can reach once it does.

Four things are constrained. The child receives an explicit environment allowlist rather than an inherited copy, so the API keys, tokens and
paths Intellicrack's own environment carries do not travel into it. Its working directory is confined to a location the operator nominated.
It is placed in a job object carrying an active-process cap, a per-process and per-job memory cap, and UI restrictions, and that job kills
everything inside it when it closes, so a server that spawns children of its own cannot outlive its connection. And it runs with no console
window.

Everything Win32 here is gated on the platform. On anything else a sandboxed launch is refused outright, never quietly downgraded to an
unconfined one: a configuration that says ``"sandbox": {"enabled": true}`` and silently runs without one is worse than no sandbox at all,
because the operator believes they have protection they do not have.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, Self

from intellicrack.core.logging import get_logger
from intellicrack.mcp.errors import McpConfigError


if TYPE_CHECKING:
    from collections.abc import Mapping

    from intellicrack.mcp.config import McpSandboxSpec, StdioServerSpec


_logger = get_logger(__name__)


IS_WIN32: Final[bool] = sys.platform == "win32"
"""Whether the confinement in this module is available at all."""

CREATE_NO_WINDOW: Final[int] = 0x08000000
CREATE_UNICODE_ENVIRONMENT: Final[int] = 0x00000400
CREATE_BREAKAWAY_FROM_JOB: Final[int] = 0x01000000

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
    "TEMP",
    "TMP",
    "WINDIR",
})
"""Inherited variables a confined child keeps.

Enough for a program to find its interpreter, its DLLs and a scratch directory, and nothing that carries a credential. Everything else the
server needs it must be given explicitly in its own configuration.
"""

_JOB_OBJECT_LIMIT_ACTIVE_PROCESS: Final[int] = 0x00000008
_JOB_OBJECT_LIMIT_BREAKAWAY_OK: Final[int] = 0x00000800
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

_PROCESS_SET_QUOTA: Final[int] = 0x0100
_PROCESS_TERMINATE: Final[int] = 0x0001

_ERR_UNSUPPORTED_PLATFORM = (
    "MCP server sandboxing is implemented with Windows job objects and is not available on this platform. "
    "Turn the sandbox off for this server to run it unconfined, which is a decision that should be made "
    "deliberately rather than by default."
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
        command: The executable to run.
        args: Its arguments, in order.
        env: The complete environment the child receives. This replaces the
            inherited environment; it is not merged over it.
        cwd: The confined working directory.
        creation_flags: Win32 process creation flags.
        limits: The ceilings to apply to the job the child runs in.
    """

    command: str
    args: tuple[str, ...]
    env: Mapping[str, str]
    cwd: str
    creation_flags: int
    limits: JobLimits


def sandbox_supported() -> bool:
    """Report whether sandboxed launches are available on this platform.

    Returns:
        bool: ``True`` only on Windows.
    """
    return IS_WIN32


def build_environment_allowlist(env: Mapping[str, str], inherited: Mapping[str, str]) -> dict[str, str]:
    """Build the complete environment a confined child receives.

    The inherited environment is filtered to :data:`ENVIRONMENT_ALLOWLIST` and
    the server's own configured entries are merged over it. Nothing else
    crosses: a credential sitting in Intellicrack's environment for one
    provider has no business reaching a third-party server.

    Args:
        env: The server's own resolved environment entries.
        inherited: The environment Intellicrack itself is running with.

    Returns:
        dict[str, str]: The environment to hand to the child.
    """
    allowed = {name: value for name, value in inherited.items() if name.upper() in ENVIRONMENT_ALLOWLIST}
    allowed.update(env)
    return allowed


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
        return str(writable[0])

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


def build_sandboxed_startup(
    spec: StdioServerSpec,
    sandbox: McpSandboxSpec,
    env: Mapping[str, str],
    inherited: Mapping[str, str] | None = None,
) -> SandboxedLaunch:
    """Build the confined launch for one local server.

    Args:
        spec: The server's launch description.
        sandbox: The server's sandbox settings.
        env: The server's own resolved environment entries.
        inherited: The environment to filter, defaulting to the running
            process's own.

    Returns:
        SandboxedLaunch: Everything needed to spawn the child confined.

    Raises:
        McpConfigError: If the platform has no sandbox, the sandbox is not
            enabled for this server, the command is empty, or the working
            directory cannot be confined.
    """
    if not sandbox.enabled:
        message = "sandboxing is not enabled for this server"
        raise McpConfigError(message)
    if not sandbox_supported():
        raise McpConfigError(_ERR_UNSUPPORTED_PLATFORM)
    command = spec.command.strip()
    if not command:
        message = "a sandboxed server needs a launch command"
        raise McpConfigError(message)

    environment = build_environment_allowlist(env, inherited if inherited is not None else os.environ)
    launch = SandboxedLaunch(
        command=command,
        args=tuple(spec.args),
        env=environment,
        cwd=confine_working_directory(spec, sandbox),
        creation_flags=CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_BREAKAWAY_FROM_JOB,
        limits=JobLimits(),
    )
    _logger.info(
        "mcp_sandbox_launch_built",
        command=launch.command,
        argument_count=len(launch.args),
        env_count=len(launch.env),
        cwd=launch.cwd,
    )
    return launch


def _kernel32() -> ctypes.WinDLL:
    """Resolve the Win32 kernel API.

    Returns:
        ctypes.WinDLL: The ``kernel32`` library.

    Raises:
        McpConfigError: If called on a platform that has no Win32 API.
    """
    if not IS_WIN32:
        raise McpConfigError(_ERR_UNSUPPORTED_PLATFORM)
    return ctypes.WinDLL("kernel32", use_last_error=True)


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
        error = ctypes.get_last_error()
        raise ctypes.WinError(error)
    _logger.debug("mcp_sandbox_job_created")
    return int(handle)


def apply_job_limits(handle: int, sandbox: McpSandboxSpec) -> None:
    """Apply the confinement ceilings to a job object.

    ``KILL_ON_JOB_CLOSE`` is what makes teardown total: closing the handle
    terminates every process in the job, so a server that spawned children
    of its own cannot survive its connection being dropped.

    Args:
        handle: The job handle from :func:`create_job_object`.
        sandbox: The server's sandbox settings, checked so a disabled
            sandbox cannot be applied by mistake.

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
    limits = JobLimits()

    extended = _JobExtendedLimitInformation()
    extended.BasicLimitInformation.LimitFlags = (
        _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | _JOB_OBJECT_LIMIT_JOB_MEMORY
        | _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    extended.BasicLimitInformation.ActiveProcessLimit = limits.active_process_limit
    extended.ProcessMemoryLimit = limits.process_memory_bytes
    extended.JobMemoryLimit = limits.job_memory_bytes
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
        active_process_limit=limits.active_process_limit,
        process_memory_bytes=limits.process_memory_bytes,
        job_memory_bytes=limits.job_memory_bytes,
        allowed_domains=list(sandbox.allowed_domains),
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
    process = kernel32.OpenProcess(
        wintypes.DWORD(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE),
        wintypes.BOOL(_DO_NOT_INHERIT_HANDLE),
        wintypes.DWORD(pid),
    )
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
    if not kernel32.TerminateJobObject(wintypes.HANDLE(handle), wintypes.UINT(exit_code)):
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


class SandboxedJob:
    """Owns one sandboxed server's job object for the life of its connection.

    Entering creates the job and applies the ceilings; a process is placed in it once it exists; leaving closes the handle, which terminates
    the server and every descendant it started.
    """

    def __init__(self, sandbox: McpSandboxSpec) -> None:
        """Initialize the job wrapper.

        Args:
            sandbox: The server's sandbox settings.
        """
        self._sandbox = sandbox
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
            apply_job_limits(handle, self._sandbox)
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
        :class:`ctypes.WinError` from :func:`assign_process_to_job`.

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
