# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Serialize the Docker Windows engine against Host Compute Service VMs.

Windows containers, WHPX virtual machines and Windows Sandbox sessions all run
on the Host Compute Service. Starting a WHPX virtual machine while the Docker
Windows engine is live wedges the engine -- recovery needs Docker Desktop
relaunched elevated -- and has bugchecked this host outright.

:mod:`scripts.sandbox.docker_sandbox` already covers one direction: it refuses
to start a container while a virtual machine holds the host. This module covers
the other, which was only ever half-built. The WHPX boot gates asked ``docker
ps`` whether a *container* was running, but the collision is with the *engine*:
Docker Desktop keeps its Windows engine and its utility VM on the Host Compute
Service for as long as it runs, with or without a container. ``just test`` runs
the container leg and then the host-native leg, so by the time the WHPX gates
look, the container has exited while the engine is still up -- the container
check passes and a virtual machine boots straight into the live engine.

The interlock here detects the engine itself and quiesces it before any WHPX
virtual machine starts. Quiescing is a graceful Docker Desktop shutdown, which
needs no elevation. When that does not clear the engine, only an elevated token
can stop the engine service; this module uses one when the caller already holds
it and never asks for one, because a test run must never raise a UAC prompt. An
engine that will not clear leaves the host in :attr:`DockerEngineState.BLOCKED`
and the WHPX gates skip, which is the safe outcome: no virtual machine is
started beside a live engine.
"""

from __future__ import annotations

import enum
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

import psutil

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable


_LOGGER = get_logger("sandbox.hcs_interlock")

# Docker Desktop publishes one named pipe per container engine. This one exists
# exactly while the Windows engine -- the engine that shares the Host Compute
# Service with WHPX -- is up, which is the signal the container check missed.
DOCKER_WINDOWS_ENGINE_PIPE: Final[str] = "dockerDesktopWindowsEngine"

# Named pipes are enumerable as a directory on Windows, so the pipe can be
# observed without opening it: opening the engine pipe is itself an engine
# operation, and a wedged engine would hang the probe rather than answer it.
_NAMED_PIPE_ROOT: Final[str] = "\\\\.\\pipe\\"

# Processes that keep Docker's engine and its utility VM on the Host Compute
# Service. The Docker Desktop GUI is deliberately absent: it can outlive the
# engine it launched, and treating the window as the engine would strand the
# WHPX gates behind a host that is in fact clear.
_DOCKER_ENGINE_PROCESS_NAMES: Final[frozenset[str]] = frozenset(
    {
        "dockerd",
        "com.docker.backend",
        "com.docker.service",
        "vmmemdockerdesktop",
    },
)

_DOCKER_CLI_PATHS: Final[tuple[Path, ...]] = (
    Path(r"C:\Program Files\Docker\Docker\DockerCli.exe"),
    Path(r"C:\Program Files\Docker\DockerCli.exe"),
)

# Docker Desktop's own quit path. It runs as the invoking user -- this is what
# the tray's "Quit Docker Desktop" does -- so it raises no UAC prompt.
_DOCKER_CLI_SHUTDOWN_FLAG: Final[str] = "-Shutdown"
_DOCKER_CLI_TIMEOUT_SECONDS: Final[float] = 120.0

# Stopping the engine service requires an elevated token. It is only ever run
# when the caller already holds one; nothing here requests elevation.
_DOCKER_ENGINE_SERVICE: Final[str] = "com.docker.service"
_STOP_SERVICE_COMMAND: Final[str] = f"Stop-Service -Name '{_DOCKER_ENGINE_SERVICE}' -Force -ErrorAction Stop"
_STOP_SERVICE_TIMEOUT_SECONDS: Final[float] = 120.0

_DOCKER_PS_TIMEOUT_SECONDS: Final[float] = 30.0

DOCKER_QUIESCE_TIMEOUT_SECONDS: Final[float] = 180.0
"""Total budget for the engine to leave the Host Compute Service."""

DOCKER_CONTAINER_WAIT_TIMEOUT_SECONDS: Final[float] = 900.0
"""Budget for a sibling session's containers to finish before Docker is touched.

Generous on purpose: a sandbox run is minutes of work, and outwaiting one costs
this run nothing but the virtual machine gates, while cutting it short destroys
somebody else's run outright.
"""

DOCKER_QUIESCE_POLL_INTERVAL_SECONDS: Final[float] = 2.0
"""Interval between engine-liveness polls while waiting for it to clear."""


class DockerEngineState(enum.Enum):
    """Outcome of an attempt to clear the Docker engine off the Host Compute Service."""

    STOPPED = "stopped"
    """No Docker engine was running; the host was already clear."""

    QUIESCED = "quiesced"
    """An engine was running and this call shut it down; the host is now clear."""

    BLOCKED = "blocked"
    """An engine is still running and could not be cleared without elevation."""

    @property
    def host_is_clear(self) -> bool:
        """Report whether a WHPX virtual machine may be started.

        Returns:
            bool: ``True`` only when no Docker engine holds the Host Compute
            Service, so a virtual machine can start without colliding with it.
        """
        return self is not DockerEngineState.BLOCKED


def named_pipe_names() -> tuple[str, ...]:
    """List the named pipes published on this host.

    Returns:
        tuple[str, ...]: Every pipe name under the Windows named-pipe root,
        empty on a platform without named pipes or when the root cannot be read.
    """
    try:
        return tuple(os.listdir(_NAMED_PIPE_ROOT))
    except OSError:
        return ()


def running_docker_engine_processes() -> tuple[tuple[int, str], ...]:
    """Return every live process holding the Docker engine on the Host Compute Service.

    Enumeration tolerates processes that exit mid-walk and those this account
    cannot open: a process that cannot be inspected is not evidence of an
    engine, and treating it as one would strand every WHPX gate on this host.

    Returns:
        tuple[tuple[int, str], ...]: ``(pid, name)`` for each running Docker
        engine process, empty when none are running.
    """
    found: list[tuple[int, str]] = []
    for process in psutil.process_iter():
        try:
            name = process.name()
            pid = process.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if name.lower().removesuffix(".exe") in _DOCKER_ENGINE_PROCESS_NAMES:
            found.append((pid, name))
    return tuple(found)


def docker_windows_engine_running(
    *,
    pipe_names: Callable[[], tuple[str, ...]] = named_pipe_names,
    engine_processes: Callable[[], tuple[tuple[int, str], ...]] = running_docker_engine_processes,
) -> bool:
    """Report whether the Docker Windows engine holds the Host Compute Service.

    Two independent signals are consulted because either alone has a blind
    spot. The engine's named pipe is the precise marker of a serving Windows
    engine but is absent while the engine is still starting or already tearing
    down, and the backend processes cover exactly that window -- the utility VM
    sits on the Host Compute Service for the whole of it. A virtual machine is
    unsafe to start while *either* reports the engine present.

    Args:
        pipe_names: Enumerates the host's named pipes; injectable for testing.
        engine_processes: Enumerates live Docker engine processes; injectable
            for testing.

    Returns:
        bool: ``True`` when a Docker engine is on the Host Compute Service.
    """
    if DOCKER_WINDOWS_ENGINE_PIPE in pipe_names():
        return True
    return bool(engine_processes())


def docker_cli_binary() -> Path | None:
    """Locate ``DockerCli.exe``, Docker Desktop's own shutdown entry point.

    Returns:
        Path | None: Path to the executable, or ``None`` when Docker Desktop is
        not installed at a known location.
    """
    for candidate in _DOCKER_CLI_PATHS:
        if candidate.exists():
            return candidate
    return None


def shutdown_docker_desktop() -> bool:
    """Ask Docker Desktop to quit, taking its engine and utility VM with it.

    This is the unelevated quit path Docker Desktop offers its own tray menu,
    so it raises no UAC prompt. The call returning ``True`` means the request
    was accepted, not that the engine is already gone; the caller waits for the
    engine to actually leave the Host Compute Service.

    Returns:
        bool: ``True`` when the shutdown request was delivered and accepted.
    """
    cli = docker_cli_binary()
    if cli is None:
        _LOGGER.warning("docker_cli_missing", searched=[str(path) for path in _DOCKER_CLI_PATHS])
        return False
    _LOGGER.info("docker_graceful_shutdown_requested", cli=str(cli))
    try:
        completed = subprocess.run(
            [str(cli), _DOCKER_CLI_SHUTDOWN_FLAG],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_DOCKER_CLI_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _LOGGER.warning("docker_graceful_shutdown_failed", error=str(exc))
        return False
    if completed.returncode != 0:
        _LOGGER.warning(
            "docker_graceful_shutdown_nonzero",
            returncode=completed.returncode,
            detail=(completed.stderr.strip() or completed.stdout.strip()),
        )
        return False
    return True


def stop_docker_engine_service() -> bool:
    """Stop the Docker engine service outright, for an already-elevated caller.

    Only reached when a graceful shutdown left the engine on the Host Compute
    Service. Stopping the service needs an elevated token, which is why a
    wedged engine has previously needed Docker Desktop relaunched as
    administrator to recover. Nothing here requests elevation: the caller
    decides whether it already holds a token, and a run that does not simply
    leaves the engine up and skips the virtual machine gates.

    Returns:
        bool: ``True`` when the service stop command completed successfully.
    """
    powershell = shutil.which("pwsh")
    if powershell is None:
        _LOGGER.warning("pwsh_missing_for_service_stop", service=_DOCKER_ENGINE_SERVICE)
        return False
    _LOGGER.info("docker_service_stop_requested", service=_DOCKER_ENGINE_SERVICE)
    try:
        completed = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _STOP_SERVICE_COMMAND],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_STOP_SERVICE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _LOGGER.warning("docker_service_stop_failed", error=str(exc))
        return False
    if completed.returncode != 0:
        _LOGGER.warning(
            "docker_service_stop_nonzero",
            returncode=completed.returncode,
            detail=(completed.stderr.strip() or completed.stdout.strip()),
        )
        return False
    return True


def running_container_ids(
    *,
    timeout: float = _DOCKER_PS_TIMEOUT_SECONDS,
) -> tuple[str, ...]:
    """Return the ids of the containers the engine is currently running.

    A missing or unreachable Docker CLI reports no containers: the engine
    detector, not this, decides whether an engine is present, and a CLI that
    cannot answer is no reason to believe a sibling's run is in flight.

    Args:
        timeout: Seconds to allow the Docker CLI to answer.

    Returns:
        tuple[str, ...]: Ids of running containers, empty when there are none
        or when Docker cannot be queried.
    """
    docker = shutil.which("docker")
    if docker is None:
        return ()
    try:
        completed = subprocess.run(
            [docker, "ps", "--quiet"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ()
    if completed.returncode != 0:
        return ()
    return tuple(line.strip() for line in completed.stdout.splitlines() if line.strip())


def _wait_until(
    predicate: Callable[[], bool],
    *,
    deadline: float,
    poll_interval: float,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
) -> bool:
    """Poll until a condition holds or the deadline passes.

    Args:
        predicate: The condition being waited on.
        deadline: Monotonic timestamp after which to give up.
        poll_interval: Seconds between polls.
        sleep: Blocking sleep; injectable for testing.
        monotonic: Monotonic clock; injectable for testing.

    Returns:
        bool: ``True`` when the condition held before the deadline expired.
    """
    while monotonic() < deadline:
        sleep(poll_interval)
        if predicate():
            return True
    return predicate()


def quiesce_docker_engine(
    *,
    engine_running: Callable[[], bool],
    running_containers: Callable[[], tuple[str, ...]],
    graceful_shutdown: Callable[[], bool],
    stop_engine_service: Callable[[], bool],
    elevated: bool,
    timeout: float = DOCKER_QUIESCE_TIMEOUT_SECONDS,
    container_timeout: float = DOCKER_CONTAINER_WAIT_TIMEOUT_SECONDS,
    poll_interval: float = DOCKER_QUIESCE_POLL_INTERVAL_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> DockerEngineState:
    """Clear the Docker engine off the Host Compute Service before a VM starts.

    A running container is waited out, never shut down. Sibling agent sessions
    share this host and queue their runs through
    :class:`scripts.sandbox.admission.SlotGate`, so an engine that is busy is
    doing somebody's work; taking it down would destroy their run to make room
    for these gates. The wait is bounded, and a container that outlasts it
    leaves the host :attr:`~DockerEngineState.BLOCKED` -- the virtual machine
    gates skip, which costs this run some coverage and costs the sibling
    nothing.

    Escalation is likewise bounded by the token the caller already holds. The
    graceful shutdown runs unelevated and settles the ordinary case. Only when
    that fails to clear the engine is the service stop considered, and only for
    a caller that is already elevated -- an unelevated run reports ``BLOCKED``
    rather than raising a UAC prompt, because a test run must never put an
    elevation dialog in front of the operator. Every ``BLOCKED`` path is safe:
    it stops the virtual machine gates from starting a machine beside a live
    engine, which is the collision being prevented.

    Args:
        engine_running: Reports whether a Docker engine holds the host.
        running_containers: Lists the containers the engine is running, so a
            sibling session's run is waited out instead of killed.
        graceful_shutdown: Requests Docker Desktop's own unelevated quit.
        stop_engine_service: Stops the engine service; only invoked when
            ``elevated`` is ``True``.
        elevated: Whether the caller already holds an elevated token. Never
            used to request one.
        timeout: Seconds allowed for the engine to leave the host.
        container_timeout: Seconds allowed for running containers to finish
            before the engine is touched at all.
        poll_interval: Seconds between polls.
        sleep: Blocking sleep; injectable for testing.
        monotonic: Monotonic clock; injectable for testing.

    Returns:
        DockerEngineState: :attr:`~DockerEngineState.STOPPED` when no engine was
        running, :attr:`~DockerEngineState.QUIESCED` when one was shut down, or
        :attr:`~DockerEngineState.BLOCKED` when one is still holding the host.
    """
    if not engine_running():
        _LOGGER.info("docker_engine_already_stopped")
        return DockerEngineState.STOPPED

    _LOGGER.info("docker_engine_quiesce_started", elevated=elevated, timeout=timeout)
    busy = running_containers()
    if busy:
        _LOGGER.info("docker_engine_busy_waiting", containers=list(busy), timeout=container_timeout)
        if not _wait_until(
            lambda: not running_containers(),
            deadline=monotonic() + container_timeout,
            poll_interval=poll_interval,
            sleep=sleep,
            monotonic=monotonic,
        ):
            _LOGGER.warning(
                "docker_engine_quiesce_blocked",
                reason="containers still running; a sibling session's run must not be shut down",
                containers=list(running_containers()),
            )
            return DockerEngineState.BLOCKED

    _ = graceful_shutdown()
    if _wait_until(
        lambda: not engine_running(),
        deadline=monotonic() + timeout,
        poll_interval=poll_interval,
        sleep=sleep,
        monotonic=monotonic,
    ):
        _LOGGER.info("docker_engine_quiesced", method="graceful")
        return DockerEngineState.QUIESCED

    if not elevated:
        _LOGGER.warning("docker_engine_quiesce_blocked", reason="not elevated; refusing to raise a UAC prompt")
        return DockerEngineState.BLOCKED

    _ = stop_engine_service()
    if _wait_until(
        lambda: not engine_running(),
        deadline=monotonic() + timeout,
        poll_interval=poll_interval,
        sleep=sleep,
        monotonic=monotonic,
    ):
        _LOGGER.info("docker_engine_quiesced", method="service_stop")
        return DockerEngineState.QUIESCED

    _LOGGER.warning("docker_engine_quiesce_blocked", reason="engine survived an elevated service stop")
    return DockerEngineState.BLOCKED


def ensure_docker_engine_quiesced(
    *,
    elevated: bool,
    timeout: float = DOCKER_QUIESCE_TIMEOUT_SECONDS,
) -> DockerEngineState:
    """Quiesce the real Docker engine on this host ahead of the VM gates.

    Args:
        elevated: Whether the calling process already holds an elevated token.
        timeout: Total seconds allowed for the engine to leave the host.

    Returns:
        DockerEngineState: The resulting state of the Host Compute Service.
    """
    return quiesce_docker_engine(
        engine_running=docker_windows_engine_running,
        running_containers=running_container_ids,
        graceful_shutdown=shutdown_docker_desktop,
        stop_engine_service=stop_docker_engine_service,
        elevated=elevated,
        timeout=timeout,
    )


def quiesce_notice(state: DockerEngineState) -> str:
    """Build the console line explaining what the interlock did to Docker.

    Args:
        state: Outcome reported by :func:`quiesce_docker_engine`.

    Returns:
        str: A single-line, human-readable notice for the console.
    """
    if state is DockerEngineState.STOPPED:
        return "[host-native] Docker engine not running; the Host Compute Service is clear for the VM gates."
    if state is DockerEngineState.QUIESCED:
        return (
            "[host-native] Docker engine shut down so the WHPX gates cannot collide with it on the "
            "Host Compute Service. Docker stays down; the next container test run starts it again."
        )
    return (
        "[host-native] Docker engine is still running -- it is busy with a container, or it could not be "
        "stopped without elevation. The WHPX/VM gates will SKIP rather than risk the host. Quit Docker "
        "Desktop once its containers have finished, or re-run from an already-elevated shell, to include them."
    )
