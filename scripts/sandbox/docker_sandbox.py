# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Host-side driver for Intellicrack's Docker-based test sandbox.

This module launches a Windows process-isolated Docker container that runs
Intellicrack's pytest suite. It ensures Docker Desktop is running, builds
or pulls the sandbox image when necessary, starts a container with the
project mounted read-only and ``reports/tests/`` mounted read-write, streams
stdout/stderr in real time, forwards ``Ctrl+C`` to the container, and on
exit harvests artifacts into a normalized summary.

Every run owns a distinct identity token (see
:func:`scripts.sandbox.test_types.run_token`) from which the container name,
the serialized spec file, the exit-code file, and every report filename are
derived. Two runs can therefore execute concurrently without overwriting each
other's pytest argv, removing each other's container, or clobbering each
other's artifacts.

Invoke via ``pixi run python -m scripts.sandbox.docker_sandbox --help``.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import psutil

from intellicrack.core.logging import IntellicrackLogger, get_logger

from .admission import (
    CapacityPlan,
    SlotGate,
    plan_capacity,
)
from .reporting import (
    SummaryRecord,
    harvest_reports,
    merge_run_log_into_shared,
    print_host_summary,
    run_log_path,
    write_summary_json,
)
from .test_types import (
    TestRunSpec,
    TestType,
    build_pytest_args,
    run_token,
    spec_to_dict,
)


if TYPE_CHECKING:
    from collections.abc import Iterable
    from types import FrameType


_LOGGER = get_logger("sandbox.docker")

_PROJECT_ROOT = Path("D:/Intellicrack")
_REPORTS_ROOT = _PROJECT_ROOT / "reports" / "tests"
_DRIVER_LOG_DIR = _PROJECT_ROOT / "logs" / "sandbox"
_DOCKERFILE = _PROJECT_ROOT / "docker" / "Dockerfile.windows"
_ENTRYPOINT_HOST = _PROJECT_ROOT / "docker" / "entrypoint.ps1"
_PIXI_LOCK = _PROJECT_ROOT / "pixi.lock"
_IMAGE_NAME = "intellicrack-sandbox"
_IMAGE_LABEL = "intellicrack-sandbox"
_CONTAINER_WORKSPACE = "C:\\app"
_CONTAINER_REPORTS = f"{_CONTAINER_WORKSPACE}\\reports"
_CONTAINER_REPORTS_TESTS = f"{_CONTAINER_REPORTS}\\tests"
_CONTAINER_NAME_PREFIX = "intellicrack-sandbox"
_QUOTE_PAIR_LEN = 2
_ORPHAN_STATUSES: tuple[str, ...] = ("exited", "dead")
_SPEC_FILE_PREFIX = "_run_spec_"
_SPEC_FILE_SUFFIX = ".json"
_EXIT_CODE_FILE_PREFIX = "_last_exitcode_"
# A control file is only reaped once it is far older than any plausible run,
# because a run writes its spec before ``docker run`` has created the container
# that would mark it live. Nothing consumes these files after their own run, so
# a generous window costs nothing and removes every chance of racing a sibling.
_CONTROL_FILE_RETENTION_SECONDS = 86400.0

_DOCKER_DESKTOP_PATHS: tuple[Path, ...] = (
    Path(r"C:\Program Files\Docker\Docker\Docker Desktop.exe"),
    Path(r"C:\Program Files\Docker\Docker Desktop.exe"),
)
_DOCKER_DAEMON_TIMEOUT_SECONDS = 180
_DOCKER_DAEMON_POLL_INTERVAL = 3.0
_DOCKER_PROBE_TIMEOUT_SECONDS = 20.0
_NETWORK_QUERY_TIMEOUT_SECONDS = 20.0

# The built-in connected network carries a different name per engine: the
# Windows container engine creates "nat", the Linux engine creates "bridge".
# Ordered most-specific-first for this host, which runs Windows containers.
_CONNECTED_NETWORK_CANDIDATES: tuple[str, ...] = ("nat", "bridge")

# Windows containers, WHPX virtual machines and Windows Sandbox sessions all run
# on the Host Compute Service, and interleaving them bugchecked this host on
# 2026-08-02. The WHPX boot gates already refuse to start a VM while a container
# is running; without the mirror image of that check the interlock is only
# one-directional, and a container started here while a VM is live is the same
# collision from the other side.
_HCS_VM_PROCESS_PREFIXES: tuple[str, ...] = (
    "qemu-system",
    "windowssandboxremotesession",
    "windowssandboxserver",
)
_HCS_VM_WAIT_TIMEOUT_SECONDS = 900.0
_HCS_VM_POLL_INTERVAL = 5.0

# Directory under the shared reports root holding one reservation file per
# in-flight run. The admission gate counts these to bound how many containers
# run at once across every driver process on the host.
_SLOTS_DIRNAME = ".sandbox_slots"

_TIMESTAMP_FORMAT = "%m-%d-%Y_%H-%M"

_PIXI_VERSION_MIN_PARTS = 2


def container_name_for(spec: TestRunSpec) -> str:
    """Return the Docker container name reserved for one run.

    The name carries the run's identity token, so two runs of the same test
    type launched at the same time never claim the same ``--name`` and never
    force-remove each other. The token uses only characters Docker accepts in
    a container name and stays readable in ``docker ps`` output.

    Args:
        spec: The run specification.

    Returns:
        str: Container name, for example
            ``intellicrack-sandbox-module_08-06-2026_14-22_p20164-9fa3c1``.
    """
    return f"{_CONTAINER_NAME_PREFIX}-{run_token(spec)}"


def host_spec_path(spec: TestRunSpec) -> Path:
    """Return the host path of a run's serialized specification.

    Args:
        spec: The run specification.

    Returns:
        Path: Absolute host path under ``reports/tests/``.
    """
    return _REPORTS_ROOT / f"_run_spec_{run_token(spec)}.json"


def container_spec_path(spec: TestRunSpec) -> str:
    """Return the in-container path of a run's serialized specification.

    The value is forwarded through the ``SANDBOX_SPEC_PATH`` environment
    variable, which the container entrypoint already honours.

    Args:
        spec: The run specification.

    Returns:
        str: Windows path visible inside the container.
    """
    return f"{_CONTAINER_REPORTS_TESTS}\\_run_spec_{run_token(spec)}.json"


def host_exit_code_path(spec: TestRunSpec) -> Path:
    """Return the host path of a run's recorded exit code.

    Args:
        spec: The run specification.

    Returns:
        Path: Absolute host path under ``reports/tests/``.
    """
    return _REPORTS_ROOT / f"_last_exitcode_{run_token(spec)}"


def container_exit_code_path(spec: TestRunSpec) -> str:
    """Return the in-container path a run writes its exit code to.

    Args:
        spec: The run specification.

    Returns:
        str: Windows path visible inside the container.
    """
    return f"{_CONTAINER_REPORTS_TESTS}\\_last_exitcode_{run_token(spec)}"


class SandboxError(RuntimeError):
    """Raised when the sandbox driver cannot proceed.

    Used to distinguish operator-facing sandbox lifecycle failures (Docker not
    installed, image build failed, container start failed) from unexpected
    programming errors.
    """


def _docker_binary() -> str:
    """Locate the ``docker`` CLI executable on the host.

    Returns:
        str: Absolute path to the Docker executable.

    Raises:
        SandboxError: If Docker is not installed or not on ``PATH``.
    """
    resolved = shutil.which("docker")
    if resolved:
        return resolved
    default = Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe")
    if default.exists():
        return str(default)
    message = "docker CLI not found on PATH or at default Docker Desktop location"
    raise SandboxError(message)


def _env_file_docker_args(env_file: Path) -> list[str]:
    """Forward a host ``.env`` file as ``docker run --env`` arguments.

    Windows containers cannot bind-mount a single file, so real provider
    credentials are passed as individual environment variables instead. Each
    ``KEY=VALUE`` line is parsed with surrounding single/double quotes stripped
    so dotenv-quoted secrets reach the container unquoted; blank lines, ``#``
    comments, ``export`` prefixes, and lines without a valid identifier key are
    skipped. A missing file yields no arguments.

    Args:
        env_file: Path to the host ``.env`` file.

    Returns:
        list[str]: Flat ``["--env", "KEY=VALUE", ...]`` argument list, empty
        when the file is absent.
    """
    if not env_file.is_file():
        return []
    args: list[str] = []
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.removeprefix("export ").strip()
        if not key.isidentifier():
            continue
        value = value.strip()
        if len(value) >= _QUOTE_PAIR_LEN and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        args.extend(["--env", f"{key}={value}"])
    return args


def _pixi_version() -> str:
    """Return the host's pixi version string (e.g. ``0.68.0``).

    The build pipeline forwards this value as a ``--build-arg`` so the
    container always installs the same pixi version that wrote ``pixi.lock``,
    preventing lockfile-format mismatches between host and container.

    Returns:
        str: The version number reported by ``pixi --version``.

    Raises:
        SandboxError: When pixi is not on ``PATH`` or its version output
            cannot be parsed.
    """
    pixi = shutil.which("pixi")
    if not pixi:
        message = "pixi CLI not found on PATH; install pixi or add it to PATH"
        raise SandboxError(message)
    proc = subprocess.run(
        [pixi, "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        message = f"pixi --version failed (exit {proc.returncode}): {detail}"
        raise SandboxError(message)
    parts = proc.stdout.strip().split()
    if len(parts) < _PIXI_VERSION_MIN_PARTS:
        message = f"unable to parse pixi version from output: {proc.stdout!r}"
        raise SandboxError(message)
    return parts[1]


def _docker_desktop_binary() -> Path | None:
    """Locate the Docker Desktop launcher.

    Returns:
        Path | None: Path to ``Docker Desktop.exe``, or ``None`` if the
            launcher cannot be found.
    """
    for candidate in _DOCKER_DESKTOP_PATHS:
        if candidate.exists():
            return candidate
    return None


def _run_docker(
    args: list[str],
    *,
    check: bool = True,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Invoke ``docker`` with a captured text result.

    Args:
        args: Argument list passed after the docker executable.
        check: When ``True`` raise :class:`SandboxError` on non-zero exit.
        timeout: Optional wall-clock limit in seconds. When the CLI does not
            return within this window the child is killed and the call is
            treated as a failure. ``None`` waits indefinitely, which is
            appropriate for long-running operations such as image builds.

    Returns:
        subprocess.CompletedProcess[str]: The completed process object. On
            timeout a synthetic result with return code ``124`` and a
            descriptive ``stderr`` is returned (when ``check`` is false).

    Raises:
        SandboxError: When the process fails and ``check`` is true, including
            the timeout case.
    """
    docker = _docker_binary()
    _LOGGER.debug("docker_cli_invoke", argv=args, timeout=timeout)
    try:
        proc = subprocess.run(
            [docker, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        # subprocess.run already terminated the child before re-raising; we
        # surface the timeout as a non-zero result so probes can retry instead
        # of the caller blocking forever on a wedged daemon connection.
        _LOGGER.warning("docker_cli_timeout", argv=args, timeout=timeout)
        message = f"docker {' '.join(args)} timed out after {timeout:g}s"
        if check:
            raise SandboxError(message) from exc
        captured = exc.stderr or exc.stdout or ""
        stderr_text = captured.decode("utf-8", "replace") if isinstance(captured, bytes) else captured
        return subprocess.CompletedProcess(
            args=[docker, *args],
            returncode=124,
            stdout="",
            stderr=stderr_text or message,
        )
    if check and proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        message = f"docker {' '.join(args)} failed (exit {proc.returncode}): {detail}"
        raise SandboxError(message)
    return proc


def _daemon_ready() -> bool:
    """Report whether the Docker daemon is responsive.

    Returns:
        bool: ``True`` when ``docker version`` exits 0, ``False`` otherwise.
    """
    try:
        proc = _run_docker(
            ["version", "--format", "{{.Server.Version}}"],
            check=False,
            timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
        )
    except SandboxError:
        return False
    return proc.returncode == 0 and bool(proc.stdout.strip())


def _engine_ready() -> bool:
    """Report whether the container engine can service container operations.

    ``docker version`` answers as soon as the API server is up, but on Windows
    the container runtime needs additional time before it can create and attach
    containers -- an immediate ``docker run`` in that window fails with
    ``unable to upgrade to tcp, received 500``. ``docker ps`` exercises the
    container backend, so a clean exit is a reliable signal that ``docker run``
    will succeed.

    Returns:
        bool: ``True`` when ``docker ps`` exits 0, ``False`` otherwise.
    """
    try:
        proc = _run_docker(
            ["ps", "--quiet"],
            check=False,
            timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
        )
    except SandboxError:
        return False
    return proc.returncode == 0


def ensure_docker_running() -> None:
    """Verify Docker is ready to run containers; start Docker Desktop if not.

    Readiness requires both the daemon (``docker version``) *and* the container
    engine (``docker ps``): the daemon answers first, but running a container
    before the engine has warmed up fails with ``unable to upgrade to tcp,
    received 500``. When the daemon is down the function launches ``Docker
    Desktop.exe``; when the daemon is already up but the engine is still warming
    up (Docker Desktop mid-start) it waits without relaunching. Either way it
    polls until both are ready or :data:`_DOCKER_DAEMON_TIMEOUT_SECONDS` elapses.

    Raises:
        SandboxError: If the Docker Desktop launcher cannot be found or Docker
            never becomes ready to run containers.
    """
    if _daemon_ready() and _engine_ready():
        _LOGGER.info("docker_ready")
        return

    # Only launch Docker Desktop when the daemon itself is down. If the daemon
    # already answers, Docker is mid-start and relaunching is pointless -- just
    # wait for the engine to finish warming up.
    if not _daemon_ready():
        launcher = _docker_desktop_binary()
        if launcher is None:
            message = "Docker daemon is not running and Docker Desktop launcher was not found; install Docker Desktop or start it manually"
            raise SandboxError(message)
        _LOGGER.info("docker_desktop_starting", launcher=str(launcher))
        print(f"[sandbox] Docker daemon not responding; launching {launcher.name} ...", file=sys.stderr)
        subprocess.Popen(
            [str(launcher)],
            cwd=str(launcher.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    else:
        _LOGGER.info("docker_engine_warming_up")
        print("[sandbox] Docker daemon up; waiting for the container engine to warm up ...", file=sys.stderr)

    deadline = time.monotonic() + _DOCKER_DAEMON_TIMEOUT_SECONDS
    elapsed = 0.0
    while time.monotonic() < deadline:
        if _daemon_ready() and _engine_ready():
            _LOGGER.info("docker_ready_after_wait", waited_seconds=round(elapsed, 1))
            print(
                f"[sandbox] Docker ready to run containers after {elapsed:.1f}s.",
                file=sys.stderr,
            )
            return
        time.sleep(_DOCKER_DAEMON_POLL_INTERVAL)
        elapsed += _DOCKER_DAEMON_POLL_INTERVAL
        _LOGGER.debug("docker_ready_wait", elapsed_seconds=round(elapsed, 1))
    message = f"Docker did not become ready to run containers within {_DOCKER_DAEMON_TIMEOUT_SECONDS}s"
    raise SandboxError(message)


def running_hcs_vm_processes() -> tuple[tuple[int, str], ...]:
    """Return every live process that shares the Host Compute Service with containers.

    Enumeration tolerates processes that exit mid-walk and those this account
    cannot open: a process that cannot be inspected is not evidence of a VM,
    and treating it as one would wedge every run on this host.

    Returns:
        tuple[tuple[int, str], ...]: ``(pid, name)`` for each running QEMU or
        Windows Sandbox process, empty when none are running.
    """
    found: list[tuple[int, str]] = []
    for process in psutil.process_iter():
        try:
            name = process.name()
            pid = process.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if name.lower().removesuffix(".exe").startswith(_HCS_VM_PROCESS_PREFIXES):
            found.append((pid, name))
    return tuple(found)


def _alive_pids() -> frozenset[int]:
    """Return the process ids currently alive on the host.

    Fed to the admission gate so a reservation whose launching driver has died
    is recognised as stale and its slot reclaimed.

    Returns:
        frozenset[int]: Every process id psutil currently reports.
    """
    return frozenset(psutil.pids())


def _refuse_rebuild_with_live_siblings(*, rebuild: bool, running_containers: frozenset[str]) -> None:
    """Reject a forced image rebuild while sibling containers are running.

    The image tag ``intellicrack-sandbox:latest`` is global. A rebuild drops and
    replaces that tag out from under every container already running against it,
    which turns a sibling agent's cached-image run into a competing full Windows
    image build. A rebuild is therefore only safe when no sandbox container is
    live; the operator is told to retry once the host is clear rather than
    silently corrupting a concurrent run.

    Args:
        rebuild: Whether a forced rebuild was requested.
        running_containers: Names of sandbox-labeled containers Docker reports as
            running.

    Raises:
        SandboxError: If a rebuild was requested while any sandbox container is
            running.
    """
    if not rebuild or not running_containers:
        return
    detail = ", ".join(sorted(running_containers))
    message = (
        "--rebuild replaces the shared intellicrack-sandbox:latest image, which would break the "
        f"{len(running_containers)} sandbox container(s) already running against it: {detail}. "
        "Rebuild when no sandbox run is active."
    )
    raise SandboxError(message)


def ensure_no_hcs_vm_running(*, timeout: float = _HCS_VM_WAIT_TIMEOUT_SECONDS) -> None:
    """Block until no Host Compute Service virtual machine is running.

    Waits rather than refusing outright, because the collision is transient by
    nature: the sibling session's VM gates finish and the container run can then
    proceed. The wait is bounded so a VM that never exits surfaces as a failure
    naming the processes holding the host, instead of a run that hangs forever.

    Args:
        timeout: Seconds to wait for the host to clear before giving up.

    Raises:
        SandboxError: If a VM process is still running when the budget expires.
    """
    running = running_hcs_vm_processes()
    if not running:
        return
    print(
        f"[sandbox] {len(running)} Host Compute Service VM process(es) running; "
        f"waiting up to {timeout:.0f}s before starting a container ...",
        file=sys.stderr,
    )
    _LOGGER.info("hcs_vm_wait_started", processes=[f"{pid}:{name}" for pid, name in running])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(_HCS_VM_POLL_INTERVAL)
        running = running_hcs_vm_processes()
        if not running:
            _LOGGER.info("hcs_vm_wait_cleared")
            print("[sandbox] Host clear; starting container.", file=sys.stderr)
            return
    detail = ", ".join(f"{name} (pid {pid})" for pid, name in running)
    message = (
        f"a Host Compute Service virtual machine is still running after {timeout:.0f}s, and Windows "
        f"containers cannot be started alongside one without risking a host bugcheck: {detail}"
    )
    raise SandboxError(message)


def _ensure_windows_engine() -> None:
    """Confirm Docker is running the Windows container engine.

    Raises:
        SandboxError: When Docker is running the Linux engine; the sandbox
            image cannot run under the Linux engine.
    """
    proc = _run_docker(
        ["version", "--format", "{{.Server.Os}}"],
        check=False,
        timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
    )
    os_value = proc.stdout.strip().lower()
    if proc.returncode != 0:
        detail = proc.stderr.strip()
        message = f"unable to query Docker server OS (exit {proc.returncode}): {detail}"
        raise SandboxError(message)
    if os_value != "windows":
        message = (
            f"Docker is running the {os_value!r} engine; switch to Windows containers "
            "(Docker Desktop -> 'Switch to Windows containers') and retry"
        )
        raise SandboxError(message)
    _LOGGER.debug("docker_engine_verified", os=os_value)


def _compute_image_tag() -> str:
    """Return the canonical image tag.

    Docker's layer cache handles invalidation automatically when ``pixi.lock``
    or the Dockerfile changes, so we don't need a content-addressed tag.

    Returns:
        str: ``intellicrack-sandbox:latest``.
    """
    return f"{_IMAGE_NAME}:latest"


def _image_exists(tag: str) -> bool:
    """Report whether a locally cached image exists for ``tag``.

    Args:
        tag: Image reference to probe.

    Returns:
        bool: ``True`` when ``docker image inspect`` exits 0.
    """
    proc = _run_docker(
        ["image", "inspect", tag],
        check=False,
        timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
    )
    return proc.returncode == 0


def build_image(tag: str, *, rebuild: bool = False) -> str:
    """Ensure the sandbox image is present locally, building it when missing.

    Args:
        tag: Target image tag.
        rebuild: When ``True`` force a rebuild even when the tag exists.

    Returns:
        str: The image tag that was built or already present.

    Raises:
        SandboxError: When the Dockerfile is missing or ``docker build`` fails.
    """
    if not _DOCKERFILE.exists():
        message = f"Dockerfile not found: {_DOCKERFILE}"
        raise SandboxError(message)

    if _image_exists(tag) and not rebuild:
        _LOGGER.info("sandbox_image_cached", tag=tag)
        return tag

    docker = _docker_binary()
    pixi_version = _pixi_version()
    argv = [
        docker,
        "build",
        "--file",
        str(_DOCKERFILE),
        "--tag",
        tag,
        "--label",
        f"{_IMAGE_LABEL}=1",
        "--build-arg",
        f"PIXI_VERSION={pixi_version}",
        "--isolation",
        "process",
        "--force-rm",
        str(_PROJECT_ROOT),
    ]
    _LOGGER.info("sandbox_image_building", tag=tag, dockerfile=str(_DOCKERFILE), pixi_version=pixi_version)
    print(f"[sandbox] Building image {tag} (this may take 10-15 minutes on first run)...", file=sys.stderr)
    build_env = os.environ.copy()
    build_env["DOCKER_BUILDKIT"] = "0"
    start = time.monotonic()
    proc = subprocess.run(argv, check=False, env=build_env)
    duration = time.monotonic() - start
    if proc.returncode != 0:
        _LOGGER.error("sandbox_image_build_failed", tag=tag, exit_code=proc.returncode, duration_seconds=round(duration, 1))
        message = f"docker build failed with exit code {proc.returncode}"
        raise SandboxError(message)
    _LOGGER.info("sandbox_image_built", tag=tag, duration_seconds=round(duration, 1))
    print(f"[sandbox] Image ready: {tag} (built in {duration:.1f}s)", file=sys.stderr)
    return tag


def _build_docker_run_argv(
    spec: TestRunSpec,
    tag: str,
    *,
    memory: str,
    cpus: str,
    network: str,
    writable_workspace: bool,
    interactive: bool,
) -> list[str]:
    """Construct the argument list passed to ``docker run``.

    Args:
        spec: The run specification; serialized into the container at a
            run-specific path so the entrypoint reproduces this run's exact
            pytest argv and never a concurrent run's.
        tag: Image tag to launch.
        memory: Memory reservation (``docker run --memory``).
        cpus: CPU quota (``docker run --cpus``).
        network: Docker network name, typically ``none`` for offline runs or
            the engine's connected network (``nat`` on Windows containers,
            ``bridge`` on Linux) for integration/e2e runs.
        writable_workspace: When ``True`` the workspace mount is writable.
        interactive: When ``True`` allocate an interactive TTY and keep stdin
            open for shell sessions.

    Returns:
        list[str]: Argument vector beginning with the ``docker`` executable.
    """
    docker = _docker_binary()
    reports_mount = f"{_REPORTS_ROOT.parent}:{_CONTAINER_REPORTS}"
    tests_mount = f"{_PROJECT_ROOT / 'tests'}:{_CONTAINER_WORKSPACE}\\tests:ro"
    docker_mount = f"{_PROJECT_ROOT / 'docker'}:{_CONTAINER_WORKSPACE}\\docker:ro"
    src_mount = f"{_PROJECT_ROOT / 'src'}:{_CONTAINER_WORKSPACE}\\src:ro"
    scripts_mount = f"{_PROJECT_ROOT / 'scripts'}:{_CONTAINER_WORKSPACE}\\scripts:ro"
    _ = writable_workspace

    container_name = container_name_for(spec)
    argv: list[str] = [
        docker,
        "run",
        "--rm",
        "--name",
        container_name,
        "--isolation",
        "process",
        "--init",
        "--memory",
        memory,
        "--cpus",
        cpus,
        "--network",
        network,
        "--volume",
        reports_mount,
        "--volume",
        tests_mount,
        "--volume",
        docker_mount,
        "--volume",
        src_mount,
        "--volume",
        scripts_mount,
    ]
    # Mount the committed vendor corpus when present so real-data tests that
    # drive the shipped ``.hexpat`` pattern files (and other vendored fixtures)
    # exercise genuine inputs instead of skipping. Mounting conditionally keeps
    # sparse checkouts that omit the submodules working.
    vendor_dir = _PROJECT_ROOT / "vendor"
    if vendor_dir.is_dir():
        argv.extend(["--volume", f"{vendor_dir}:{_CONTAINER_WORKSPACE}\\vendor:ro"])
    # Mount the installer packaging tree when present so tests under
    # ``tests/packaging`` can target the live ``packaging`` sources (the Inno
    # Setup script and the ML-split helper) instead of a copy baked into the
    # image at build time.
    packaging_dir = _PROJECT_ROOT / "packaging"
    if packaging_dir.is_dir():
        argv.extend(["--volume", f"{packaging_dir}:{_CONTAINER_WORKSPACE}\\packaging:ro"])
    argv.extend([
        "--workdir",
        _CONTAINER_WORKSPACE,
        "--env",
        "INTELLICRACK_SANDBOXED=1",
        "--env",
        "INTELLICRACK_LOCAL_TESTS=1",
        "--env",
        "CI=1",
        "--env",
        "PYTHONUNBUFFERED=1",
        "--env",
        "QT_QPA_PLATFORM=offscreen",
        "--env",
        f"TEST_TYPE={spec.test_type.value}",
        "--env",
        f"TEST_TIMESTAMP={spec.timestamp}",
        "--env",
        f"SANDBOX_RUN_ID={spec.run_id}",
        "--env",
        f"SANDBOX_SPEC_PATH={container_spec_path(spec)}",
        "--env",
        f"SANDBOX_EXITCODE_PATH={container_exit_code_path(spec)}",
        "--label",
        f"{_IMAGE_LABEL}=1",
    ])
    # Inject real provider API keys from the host ``.env`` into the container
    # environment (Windows cannot bind-mount a single file). ``CredentialLoader``
    # falls back to ``os.environ`` after the ``.env`` file, so live cloud-provider
    # tests resolve real credentials. The file stays on the host and is never
    # baked into the image; runs without an ``.env`` simply forward nothing and
    # the key-gated tests skip themselves.
    argv.extend(_env_file_docker_args(_PROJECT_ROOT / ".env"))
    # Forward isolated-coverage tuning knobs when the operator has set them on
    # the host. ``COVERAGE_TESTS_ROOT`` scopes the per-directory run to a subset
    # (used for smoke-testing the mechanism); ``COVERAGE_GROUP_TIMEOUT`` bounds
    # each per-directory pytest process before the watchdog kills it;
    # ``COVERAGE_JOBS`` overrides how many groups run concurrently.
    for cov_var in ("COVERAGE_TESTS_ROOT", "COVERAGE_GROUP_TIMEOUT", "COVERAGE_JOBS"):
        cov_val = os.environ.get(cov_var)
        if cov_val:
            argv.extend(["--env", f"{cov_var}={cov_val}"])
    if spec.module:
        argv.extend(["--env", f"TEST_MODULE={spec.module}"])
    if interactive:
        argv.extend(["-it"])
    else:
        argv.extend(["-t"])
    # Pass the test type as the explicit container command so it overrides the
    # image's ``CMD ["unit"]`` default. Without this the default positional arg
    # binds the entrypoint's ``$TestType`` to ``unit`` regardless of the
    # ``TEST_TYPE`` environment variable, causing the entrypoint's host-spec
    # branch (which requires ``$TestType -eq $Spec.test_type``) to be skipped
    # and the full unit suite to run instead of the requested selection.
    argv.extend((tag, spec.test_type.value))
    return argv


def _container_names_by_status(status: str) -> frozenset[str]:
    """List sandbox-labeled container names Docker reports in a given status.

    Args:
        status: Docker status filter value (``running``, ``exited``, ``dead``).

    Returns:
        frozenset[str]: Container names carrying the sandbox label in that
            status; empty when the query fails.
    """
    proc = _run_docker(
        [
            "ps",
            "-a",
            "--filter",
            f"label={_IMAGE_LABEL}=1",
            "--filter",
            f"status={status}",
            "--format",
            "{{.Names}}",
        ],
        check=False,
        timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
    )
    if proc.returncode != 0:
        return frozenset()
    return frozenset(line.strip() for line in proc.stdout.splitlines() if line.strip())


def _container_exists(name: str) -> bool:
    """Report whether a container with exactly this name exists.

    The name filter Docker applies is a substring regex, so the comparison is
    finished host-side to avoid matching a sibling whose name merely contains
    this one.

    Args:
        name: Container name to probe.

    Returns:
        bool: ``True`` when a container with exactly ``name`` exists.
    """
    proc = _run_docker(
        ["ps", "-a", "--filter", f"name={name}", "--format", "{{.Names}}"],
        check=False,
        timeout=_DOCKER_PROBE_TIMEOUT_SECONDS,
    )
    if proc.returncode != 0:
        return False
    return any(line.strip() == name for line in proc.stdout.splitlines())


def _select_removable_containers(
    orphaned: frozenset[str],
    running: frozenset[str],
    *,
    own_name: str,
    own_exists: bool,
) -> tuple[str, ...]:
    """Decide which containers this run is allowed to force-remove.

    A run may reap only containers that cannot belong to a live sibling: the
    sandbox-labeled containers Docker reports as exited or dead, which ``--rm``
    should already have removed and which therefore survive only when a driver
    was killed abruptly. A container Docker reports as running -- or one still
    being created, which no status here matches -- is never removed unless the
    name is this run's own, which is unique to it by construction.

    Args:
        orphaned: Labeled container names in an exited or dead status.
        running: Labeled container names Docker reports as running.
        own_name: This run's own unique container name.
        own_exists: Whether a container already exists under ``own_name``.

    Returns:
        tuple[str, ...]: Sorted container names safe to force-remove.
    """
    targets = {name for name in orphaned if name not in running and name != own_name}
    if own_exists:
        targets.add(own_name)
    return tuple(sorted(targets))


def _remove_stale_container(name: str) -> None:
    """Reap orphaned sandbox containers without disturbing live siblings.

    A prior run killed abruptly (``kill -9``, power cut) leaves a container
    behind that ``--rm`` never removed; left in place it wastes disk and, when
    the name matches, blocks the next ``docker run --name``. Because container
    names are now unique per run, cleanup can no longer key on the name alone:
    it reaps sandbox-labeled containers in an exited or dead status plus this
    run's own name, and leaves every running container of a concurrent run
    untouched.

    Args:
        name: This run's own container name.
    """
    orphaned: set[str] = set()
    for status in _ORPHAN_STATUSES:
        orphaned |= _container_names_by_status(status)
    running = _container_names_by_status("running")
    targets = _select_removable_containers(
        frozenset(orphaned),
        running,
        own_name=name,
        own_exists=_container_exists(name),
    )
    for target in targets:
        _LOGGER.info("sandbox_stale_container_removed", container=target, own_name=name)
        _run_docker(["rm", "-f", target], check=False, timeout=_DOCKER_PROBE_TIMEOUT_SECONDS)


def _write_spec_file(spec: TestRunSpec) -> Path:
    """Persist the serialized spec where the container entrypoint expects it.

    The destination carries the run's identity token, so a second driver
    running at the same time cannot overwrite this run's pytest argv.

    Args:
        spec: The run specification to serialize.

    Returns:
        Path: The host path the specification was written to.
    """
    destination = host_spec_path(spec)
    destination.parent.mkdir(parents=True, exist_ok=True)
    pytest_args: list[str] = []
    if spec.test_type not in {TestType.INTERACTIVE, TestType.INTERACTIVE_RW}:
        pytest_args = build_pytest_args(spec)
    payload = {**spec_to_dict(spec), "pytest_args": pytest_args}
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _LOGGER.debug("sandbox_spec_written", path=str(destination), argc=len(pytest_args))
    return destination


def _write_exit_code(spec: TestRunSpec, exit_code: int) -> Path:
    """Persist this run's container exit code for CI integration.

    Args:
        spec: The run specification whose identity names the file.
        exit_code: Exit code reported by the container entrypoint.

    Returns:
        Path: The host path the exit code was written to.
    """
    destination = host_exit_code_path(spec)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(str(exit_code), encoding="utf-8")
    return destination


def _should_retain_control_files(exit_code: int) -> bool:
    """Decide whether a finished run's control files still carry diagnostic value.

    The spec file and the exit-code file are ephemeral control-plane state, not
    artifacts: on a clean run both are fully redundant with kept output -- the
    exit code is recorded in ``summary_<token>.json`` and the pytest argv is
    echoed into the ``test-log_<token>.txt`` banner -- so they are discarded.
    A run that ended badly may have died before its entrypoint wrote that
    banner, leaving the spec file as the only record of the argv the container
    was handed, so its control files are kept for the operator to inspect and
    are removed later by the age-based reaper instead.

    Args:
        exit_code: Exit code reported for the finished run.

    Returns:
        bool: ``True`` when the files must be kept for diagnosis.
    """
    return exit_code != 0


def _delete_control_file(path: Path) -> bool:
    """Delete one control file, tolerating a file that is already gone.

    Args:
        path: Control file to remove.

    Returns:
        bool: ``True`` when the file no longer exists afterwards, ``False``
            when it could not be removed (for example while another process
            holds it open).
    """
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        _LOGGER.warning("sandbox_control_file_not_removed", path=str(path), error=str(exc))
        return False
    return True


def _discard_control_files(spec: TestRunSpec) -> tuple[Path, ...]:
    """Remove a finished run's own spec and exit-code files.

    Safe under concurrency by construction: both names are derived from this
    run's unique identity token, so no sibling's files can be addressed.

    Args:
        spec: The run whose control files are being discarded.

    Returns:
        tuple[Path, ...]: The control files that no longer exist afterwards.
    """
    removed = [path for path in (host_spec_path(spec), host_exit_code_path(spec)) if _delete_control_file(path)]
    if removed:
        _LOGGER.debug("sandbox_control_files_discarded", run_id=spec.run_id, count=len(removed))
    return tuple(removed)


def _control_file_token(path: Path) -> str | None:
    """Extract the run token encoded in a control file's name.

    Args:
        path: Candidate file inside the reports directory.

    Returns:
        str | None: The run token, or ``None`` when the file is not a control
            file (report artifacts and logs yield ``None`` and are never
            considered for reaping).
    """
    name = path.name
    if name.startswith(_SPEC_FILE_PREFIX) and name.endswith(_SPEC_FILE_SUFFIX):
        return name[len(_SPEC_FILE_PREFIX) : -len(_SPEC_FILE_SUFFIX)] or None
    if name.startswith(_EXIT_CODE_FILE_PREFIX):
        return name.removeprefix(_EXIT_CODE_FILE_PREFIX) or None
    return None


def _live_run_tokens() -> frozenset[str]:
    """Return the identity tokens of runs whose container is currently running.

    Returns:
        frozenset[str]: Tokens recovered from the names of running sandbox
            containers; empty when Docker reports none.
    """
    prefix = f"{_CONTAINER_NAME_PREFIX}-"
    return frozenset(name.removeprefix(prefix) for name in _container_names_by_status("running") if name.startswith(prefix))


def _select_reapable_control_files(
    candidates: Iterable[Path],
    live_tokens: frozenset[str],
    *,
    own_token: str,
    now: float,
    retention_seconds: float,
) -> tuple[Path, ...]:
    """Decide which leftover control files are safe to delete.

    A file qualifies only when all three hold: it is a control file (report
    artifacts are never touched), it belongs to neither this run nor a run
    whose container Docker reports as running, and it is older than the
    retention window. The age test is what makes the sequence safe, because a
    run writes its spec file before ``docker run`` has created the container
    that would mark its token live.

    Args:
        candidates: Files found in the reports directory.
        live_tokens: Tokens of runs with a currently running container.
        own_token: This run's own identity token.
        now: Current wall-clock time as a POSIX timestamp.
        retention_seconds: Minimum age before a leftover may be removed.

    Returns:
        tuple[Path, ...]: Sorted control files safe to delete.
    """
    targets: list[Path] = []
    for candidate in candidates:
        token = _control_file_token(candidate)
        if token is None or token == own_token or token in live_tokens:
            continue
        try:
            age = now - candidate.stat().st_mtime
        except OSError:
            continue
        if age > retention_seconds:
            targets.append(candidate)
    return tuple(sorted(targets))


def _reap_orphaned_control_files(*, own_token: str) -> tuple[Path, ...]:
    """Delete control files left behind by drivers that died before cleaning up.

    A driver killed abruptly never reaches its own cleanup, so its spec and
    exit-code files would otherwise accumulate in ``reports/tests/`` forever.
    This runs at startup alongside the stale-container reaping and never
    touches a file belonging to a live sibling.

    Args:
        own_token: This run's own identity token, always spared.

    Returns:
        tuple[Path, ...]: Control files removed by this call.
    """
    if not _REPORTS_ROOT.is_dir():
        return ()
    targets = _select_reapable_control_files(
        _REPORTS_ROOT.iterdir(),
        _live_run_tokens(),
        own_token=own_token,
        now=time.time(),
        retention_seconds=_CONTROL_FILE_RETENTION_SECONDS,
    )
    removed = tuple(target for target in targets if _delete_control_file(target))
    if removed:
        _LOGGER.info("sandbox_orphaned_control_files_reaped", count=len(removed))
    return removed


class DockerSandbox:
    """Coordinate image build, container launch, and report harvesting.

    Attributes:
        memory: Memory quota string, for example ``"32g"``.
        cpus: CPU quota string, for example ``"16"``.
        network: Docker network attached to the container.
        rebuild: When ``True`` force an image rebuild.
        writable_workspace: When ``True`` mount the host workspace read-write.
        slot_budget: Maximum number of containers permitted to run concurrently.
    """

    memory: str
    cpus: str
    network: str
    rebuild: bool
    writable_workspace: bool
    slot_budget: int

    def __init__(
        self,
        *,
        memory: str = "32g",
        cpus: str = "16",
        network: str = "none",
        rebuild: bool = False,
        writable_workspace: bool = False,
        slot_budget: int = 1,
    ) -> None:
        """Initialize the sandbox driver with resource and build options.

        Args:
            memory: Memory quota passed to ``docker run --memory``.
            cpus: CPU quota passed to ``docker run --cpus``.
            network: Docker network name (``none`` for offline runs).
            rebuild: Force an image rebuild even when a cached tag exists.
            writable_workspace: Mount the host workspace read-write.
            slot_budget: Maximum number of sandbox containers permitted to run
                concurrently across every driver process on this host.
        """
        self.memory = memory
        self.cpus = cpus
        self.network = network
        self.rebuild = rebuild
        self.writable_workspace = writable_workspace
        self.slot_budget = slot_budget

    def ensure_image(self) -> str:
        """Ensure Docker is running and the sandbox image is available.

        Returns:
            str: Tag of the ready image.
        """
        # Before Docker is even woken up: Docker Desktop starts its own utility
        # VM, so launching it is already a Host Compute Service operation.
        ensure_no_hcs_vm_running()
        ensure_docker_running()
        _ensure_windows_engine()
        # A forced rebuild replaces the shared image tag, so it may not proceed
        # while another run is still using it.
        _refuse_rebuild_with_live_siblings(rebuild=self.rebuild, running_containers=_container_names_by_status("running"))
        tag = _compute_image_tag()
        return build_image(tag, rebuild=self.rebuild)

    def _slot_gate(self) -> SlotGate:
        """Construct the admission gate that bounds concurrent container runs.

        Returns:
            SlotGate: A gate over the shared reservations directory wired to this
                host's Docker and process-liveness state.
        """
        return SlotGate(
            _REPORTS_ROOT / _SLOTS_DIRNAME,
            self.slot_budget,
            live_tokens=_live_run_tokens,
            alive_pids=_alive_pids,
        )

    def run(self, spec: TestRunSpec, *, interactive: bool = False) -> SummaryRecord:
        """Execute a run specification inside the sandbox container.

        Args:
            spec: Run specification whose pytest argv will execute inside the
                container.
            interactive: When ``True`` allocate an interactive TTY, used for
                :attr:`TestType.INTERACTIVE` / :attr:`TestType.INTERACTIVE_RW`.

        Returns:
            SummaryRecord: Normalized summary for the completed run.
        """
        tag = self.ensure_image()
        container_name = container_name_for(spec)
        _remove_stale_container(container_name)
        _reap_orphaned_control_files(own_token=run_token(spec))
        _write_spec_file(spec)
        argv = _build_docker_run_argv(
            spec,
            tag,
            memory=self.memory,
            cpus=self.cpus,
            network=self.network,
            writable_workspace=self.writable_workspace,
            interactive=interactive,
        )
        _LOGGER.info(
            "sandbox_container_starting",
            test_type=spec.test_type.value,
            timestamp=spec.timestamp,
            run_id=spec.run_id,
            container=container_name,
            network=self.network,
            memory=self.memory,
            cpus=self.cpus,
            writable_workspace=self.writable_workspace,
            module=spec.module,
            extra_args=list(spec.extra_args),
        )
        print(
            f"[sandbox] Running {spec.test_type.value} (ts={spec.timestamp}, run={spec.run_id}, "
            f"net={self.network}, mem={self.memory}, cpus={self.cpus}, slots={self.slot_budget})",
            file=sys.stderr,
        )
        # Hold a concurrency slot for the lifetime of the container only. The
        # gate blocks here until fewer than ``slot_budget`` runs are in flight,
        # so several drivers can queue safely instead of oversubscribing the
        # Host Compute Service.
        slot = self._slot_gate().acquire(run_token(spec))
        start = time.monotonic()
        try:
            exit_code = _run_streamed(
                argv,
                timeout_seconds=spec.timeout_seconds,
                container_name=container_name,
            )
        finally:
            slot.release()
        duration = time.monotonic() - start
        _LOGGER.info(
            "sandbox_container_finished",
            test_type=spec.test_type.value,
            timestamp=spec.timestamp,
            run_id=spec.run_id,
            exit_code=exit_code,
            duration_seconds=round(duration, 2),
        )
        _write_exit_code(spec, exit_code)
        try:
            # The container has exited, so it no longer holds its own log open
            # and the aggregate append-only history can be extended without two
            # containers contending for one handle across the bind mount.
            merged = merge_run_log_into_shared(
                run_log_path(spec.test_type.value, spec.timestamp, spec.run_id),
            )
            if not merged:
                _LOGGER.warning(
                    "sandbox_shared_log_not_updated",
                    test_type=spec.test_type.value,
                    run_id=spec.run_id,
                )
            record = harvest_reports(
                spec.test_type,
                spec.timestamp,
                exit_code,
                run_id=spec.run_id,
                module=spec.module,
                extra_args=spec.extra_args,
            )
            if record.paths.summary is None:
                summary_path = _REPORTS_ROOT / f"summary_{run_token(spec)}.json"
                write_summary_json(record, summary_path)
                record = harvest_reports(
                    spec.test_type,
                    spec.timestamp,
                    exit_code,
                    run_id=spec.run_id,
                    module=spec.module,
                    extra_args=spec.extra_args,
                )
            return record
        finally:
            # The exit code has been read and folded into the summary, so this
            # run's ephemeral control files have served their purpose. A run
            # that ended badly keeps them for diagnosis instead.
            if not _should_retain_control_files(exit_code):
                _discard_control_files(spec)


def _force_stop_container(container_name: str) -> None:
    """Stop a detached container by name, killing every process inside it.

    Terminating the host-side ``docker run`` client does **not** stop the
    container it launched: the container runs detached in the Docker engine and
    keeps executing (this is why an earlier hung run continued for hours after
    the host timeout fired). ``docker kill`` sends the stop to the engine, which
    terminates the container and, via ``--rm``, removes it.

    Args:
        container_name: Name of the container to stop.
    """
    _LOGGER.warning("sandbox_container_force_stop", name=container_name)
    result = _run_docker(["kill", container_name], check=False, timeout=30)
    if result.returncode != 0:
        # The container may already be gone; ensure no stale record remains so
        # the next run's ``--name`` does not conflict.
        _run_docker(["rm", "-f", container_name], check=False, timeout=30)


def _run_streamed(
    argv: list[str],
    *,
    timeout_seconds: int,
    container_name: str,
) -> int:
    """Run a subprocess with live output streaming and SIGINT forwarding.

    Args:
        argv: Argument vector beginning with the executable path.
        timeout_seconds: Hard timeout applied to the subprocess.
        container_name: Name of the launched container, used to force-stop it
            in the engine when the host timeout or an interrupt fires (killing
            the ``docker run`` client alone leaves the detached container
            running).

    Returns:
        int: The subprocess exit code. ``130`` is returned on ``KeyboardInterrupt``
            and ``124`` on timeout, matching standard POSIX conventions.
    """
    proc = subprocess.Popen(
        argv,
        stdout=None,
        stderr=None,
        stdin=None,
        bufsize=1,
        text=True,
    )
    previous_handler = signal.getsignal(signal.SIGINT)

    def _forward_sigint(_signum: int, _frame: FrameType | None) -> None:
        """Forward Ctrl+C to the running container.

        Args:
            _signum: Signal number (unused).
            _frame: Current stack frame (unused).
        """
        _LOGGER.warning("sandbox_interrupt_forwarded")
        try:
            proc.send_signal(signal.SIGINT)
        except OSError:
            proc.terminate()

    signal.signal(signal.SIGINT, _forward_sigint)
    try:
        return proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        _LOGGER.exception("sandbox_timeout", timeout_seconds=timeout_seconds)
        _force_stop_container(container_name)
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
        return 124
    except KeyboardInterrupt:
        _force_stop_container(container_name)
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
        return 130
    finally:
        signal.signal(signal.SIGINT, previous_handler)


def _timestamp_now() -> str:
    """Return a UTC timestamp suitable for artifact filenames.

    Returns:
        str: Timestamp formatted as ``yyyyMMdd_HHmmss``.
    """
    return datetime.now(UTC).strftime(_TIMESTAMP_FORMAT)


def _parse_extra_args(raw: str | None) -> tuple[str, ...]:
    """Tokenize an operator-supplied ``--extra-args`` string.

    Args:
        raw: Raw string passed on the CLI; may be ``None``.

    Returns:
        tuple[str, ...]: Tokenized argument list, empty when ``raw`` is ``None``.
    """
    if not raw:
        return ()
    return tuple(shlex.split(raw, posix=False))


def _build_parser() -> argparse.ArgumentParser:
    """Construct the CLI parser.

    Returns:
        argparse.ArgumentParser: Configured parser.
    """
    parser = argparse.ArgumentParser(
        prog="docker-sandbox",
        description=(
            "Run Intellicrack's pytest suite inside a Windows process-isolated "
            "Docker container. Replaces the prior Windows Sandbox harness."
        ),
    )
    parser.add_argument(
        "test_type",
        nargs="?",
        default=None,
        choices=[t.value for t in TestType],
        help="Test execution mode. Defaults to 'unit'. Ignored with --shell / --build-only.",
    )
    parser.add_argument(
        "--module",
        "-m",
        default=None,
        help="Module name or tests/... path for module / module-cov runs.",
    )
    parser.add_argument(
        "--extra-args",
        "-a",
        default=None,
        help="Additional pytest arguments forwarded to the container verbatim.",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Force an image rebuild before running.",
    )
    parser.add_argument(
        "--shell",
        action="store_true",
        help="Open an interactive shell instead of running pytest.",
    )
    parser.add_argument(
        "--rw",
        action="store_true",
        help="Mount the workspace read-write (for --shell and interactive-rw).",
    )
    parser.add_argument(
        "--memory",
        default=None,
        help="Memory quota for docker run. Default: auto-sized from host RAM so several runs fit concurrently.",
    )
    parser.add_argument(
        "--cpus",
        default=None,
        help="CPU quota for docker run. Default: auto-sized from host CPU count so several runs fit concurrently.",
    )
    parser.add_argument(
        "--network",
        default=None,
        help="Docker network (default: the engine's connected network for integration/e2e, none otherwise).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=7200,
        help="Hard timeout in seconds for the container process (default: 7200).",
    )
    parser.add_argument(
        "--build-only",
        action="store_true",
        help="Only build the image and exit; do not run a container.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Driver log level (default: INFO).",
    )
    return parser


def _existing_networks() -> frozenset[str]:
    """List the Docker networks the active engine currently defines.

    Returns:
        frozenset[str]: Network names reported by ``docker network ls``, empty
            when the CLI call fails so the caller reports the shortfall with
            run context instead of this shim surfacing a bare CLI error.
    """
    proc = _run_docker(
        ["network", "ls", "--format", "{{.Name}}"],
        check=False,
        timeout=_NETWORK_QUERY_TIMEOUT_SECONDS,
    )
    if proc.returncode != 0:
        _LOGGER.warning("docker_network_list_failed", detail=proc.stderr.strip())
        return frozenset()
    return frozenset(line.strip() for line in proc.stdout.splitlines() if line.strip())


def select_connected_network(available: frozenset[str], label: str) -> str:
    """Pick the connected network to attach from the engine's own network list.

    The built-in connected network carries a different name per engine: the
    Windows container engine creates ``nat`` while the Linux engine creates
    ``bridge``. Naming one that the engine does not define makes ``docker run``
    fail with ``network ... not found`` before a single test is collected, so
    the candidates are matched against what the engine reports.

    Args:
        available: Network names the engine currently defines.
        label: Run-mode name used in the failure message.

    Returns:
        str: The first candidate network the engine actually defines.

    Raises:
        SandboxError: When the engine defines none of the known connected
            networks.
    """
    for candidate in _CONNECTED_NETWORK_CANDIDATES:
        if candidate in available:
            return candidate

    found = ", ".join(sorted(available)) or "nothing"
    message = (
        f"{label} needs a connected network but the engine defines none of "
        f"{', '.join(_CONNECTED_NETWORK_CANDIDATES)} (found: {found}); "
        "pass --network explicitly"
    )
    raise SandboxError(message)


def _default_network(test_type: TestType | None) -> str:
    """Select a default Docker network for the given test type.

    Args:
        test_type: Active test type or ``None`` when running a shell.

    Returns:
        str: The engine's connected-network name for network-requiring modes,
            or ``"none"`` for isolated modes.
    """
    if test_type is None:
        return "none"
    if test_type not in {TestType.INTEGRATION, TestType.E2E}:
        return "none"

    return select_connected_network(_existing_networks(), test_type.value)


def _resolve_capacity_plan(*, requested_memory: str | None, requested_cpus: str | None) -> CapacityPlan:
    """Derive the concurrency budget and per-run resource share for this host.

    Reads the host's total memory and logical CPU count and delegates the policy
    to :func:`scripts.sandbox.admission.plan_capacity`. Operator-pinned
    ``--memory`` / ``--cpus`` values are forwarded so an explicit request is
    honoured and the budget shrinks to whatever number of such runs fits.

    Args:
        requested_memory: Operator-pinned ``--memory`` value, or ``None``.
        requested_cpus: Operator-pinned ``--cpus`` value, or ``None``.

    Returns:
        CapacityPlan: The resolved slot budget and per-run memory/CPU share.
    """
    total_memory = psutil.virtual_memory().total
    cpu_count = psutil.cpu_count(logical=True) or 1
    return plan_capacity(
        total_memory,
        cpu_count,
        requested_memory=requested_memory,
        requested_cpus=requested_cpus,
    )


def _resolve_test_type(args: argparse.Namespace) -> TestType:
    """Pick the :class:`TestType` for the requested CLI invocation.

    Args:
        args: Parsed CLI arguments.

    Returns:
        TestType: Test type that satisfies the CLI flag combination.
    """
    if args.shell:
        return TestType.INTERACTIVE_RW if args.rw else TestType.INTERACTIVE
    if not args.test_type:
        return TestType.UNIT
    return TestType(args.test_type)


def _configure_driver_logging(level: str) -> None:
    """Configure structlog output for the driver's own logger.

    Initializes the shared Intellicrack logger so that driver events are
    written both to the console and to ``logs/sandbox/sandbox.log`` in
    JSON form. The dedicated filename prevents collision with the main
    application's ``logs/intellicrack.log``. Call once per process at
    startup.

    Args:
        level: Log level name (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).
    """
    _DRIVER_LOG_DIR.mkdir(parents=True, exist_ok=True)
    IntellicrackLogger.configure(
        level=level.upper(),
        log_dir=_DRIVER_LOG_DIR,
        file_enabled=True,
        console_enabled=True,
        max_file_size_mb=10,
        backup_count=5,
        retention_days=14,
        json_file=True,
        filename="sandbox.log",
    )


def main(raw_args: list[str] | None = None) -> int:
    """Entry point invoked by the justfile.

    Args:
        raw_args: CLI arguments to parse. When ``None`` :mod:`sys.argv` is used.

    Returns:
        int: Exit code to propagate to the shell.
    """
    parser = _build_parser()
    args = parser.parse_args(raw_args)
    _configure_driver_logging(args.log_level)

    test_type = _resolve_test_type(args)
    timestamp = _timestamp_now()
    spec = TestRunSpec(
        test_type=test_type,
        timestamp=timestamp,
        module=args.module,
        extra_args=_parse_extra_args(args.extra_args),
        timeout_seconds=args.timeout,
    )
    network = args.network or _default_network(test_type)
    writable = args.rw or test_type is TestType.INTERACTIVE_RW
    plan = _resolve_capacity_plan(requested_memory=args.memory, requested_cpus=args.cpus)

    _LOGGER.info(
        "sandbox_invocation",
        test_type=test_type.value,
        timestamp=timestamp,
        run_id=spec.run_id,
        network=network,
        writable_workspace=writable,
        rebuild=args.rebuild,
        shell=args.shell,
        build_only=args.build_only,
        module=args.module,
        extra_args=list(spec.extra_args),
        slot_budget=plan.slots,
        memory=plan.memory,
        cpus=plan.cpus,
    )
    print(
        f"[sandbox] Host capacity: up to {plan.slots} concurrent run(s), "
        f"{plan.memory} / {plan.cpus} CPU(s) each.",
        file=sys.stderr,
    )

    sandbox = DockerSandbox(
        memory=plan.memory,
        cpus=plan.cpus,
        network=network,
        rebuild=args.rebuild,
        writable_workspace=writable,
        slot_budget=plan.slots,
    )

    try:
        if args.build_only:
            tag = sandbox.ensure_image()
            print(f"image ready: {tag}")
            return 0
        record = sandbox.run(spec, interactive=args.shell)
    except SandboxError as exc:
        print(f"sandbox error: {exc}", file=sys.stderr)
        _LOGGER.exception("sandbox_error", error=str(exc))
        return 3
    except KeyboardInterrupt:
        _LOGGER.warning("sandbox_keyboard_interrupt")
        return 130

    if test_type not in {TestType.INTERACTIVE, TestType.INTERACTIVE_RW}:
        print_host_summary(record)
    return record.exit_code


if __name__ == "__main__":
    sys.exit(main())
