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

Invoke via ``pixi run python -m scripts.sandbox.docker_sandbox --help``.
"""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from intellicrack.core.logging import IntellicrackLogger, get_logger

from .reporting import (
    SummaryRecord,
    harvest_reports,
    print_host_summary,
    write_summary_json,
)
from .test_types import (
    TestRunSpec,
    TestType,
    build_pytest_args,
    spec_to_dict,
)


if TYPE_CHECKING:
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
_CONTAINER_SPEC_PATH = f"{_CONTAINER_REPORTS}\\tests\\_run_spec.json"
_HOST_SPEC_PATH = _REPORTS_ROOT / "_run_spec.json"
_EXIT_CODE_FILE = _REPORTS_ROOT / "_last_exitcode"

_DOCKER_DESKTOP_PATHS: tuple[Path, ...] = (
    Path(r"C:\Program Files\Docker\Docker\Docker Desktop.exe"),
    Path(r"C:\Program Files\Docker\Docker Desktop.exe"),
)
_DOCKER_DAEMON_TIMEOUT_SECONDS = 180
_DOCKER_DAEMON_POLL_INTERVAL = 3.0

_TIMESTAMP_FORMAT = "%m-%d-%Y_%H-%M"


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


def _run_docker(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Invoke ``docker`` with a captured text result.

    Args:
        args: Argument list passed after the docker executable.
        check: When ``True`` raise :class:`SandboxError` on non-zero exit.

    Returns:
        subprocess.CompletedProcess[str]: The completed process object.

    Raises:
        SandboxError: When ``check`` is true and the process fails.
    """
    docker = _docker_binary()
    _LOGGER.debug("docker_cli_invoke", argv=args)
    proc = subprocess.run(
        [docker, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
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
        proc = _run_docker(["version", "--format", "{{.Server.Version}}"], check=False)
    except SandboxError:
        return False
    return proc.returncode == 0 and bool(proc.stdout.strip())


def ensure_docker_running() -> None:
    """Verify the Docker daemon is running; start Docker Desktop if not.

    When the daemon is unresponsive the function launches ``Docker Desktop.exe``
    in the background and polls ``docker version`` until the daemon responds
    or :data:`_DOCKER_DAEMON_TIMEOUT_SECONDS` elapses.

    Raises:
        SandboxError: If the Docker Desktop launcher cannot be found or the
            daemon never becomes ready.
    """
    if _daemon_ready():
        _LOGGER.info("docker_daemon_ready")
        return

    launcher = _docker_desktop_binary()
    if launcher is None:
        message = (
            "Docker daemon is not running and Docker Desktop launcher was not found; "
            "install Docker Desktop or start it manually"
        )
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

    deadline = time.monotonic() + _DOCKER_DAEMON_TIMEOUT_SECONDS
    elapsed = 0.0
    while time.monotonic() < deadline:
        if _daemon_ready():
            _LOGGER.info("docker_daemon_ready_after_launch", waited_seconds=round(elapsed, 1))
            print(
                f"[sandbox] Docker daemon ready after {elapsed:.1f}s.",
                file=sys.stderr,
            )
            return
        time.sleep(_DOCKER_DAEMON_POLL_INTERVAL)
        elapsed += _DOCKER_DAEMON_POLL_INTERVAL
        _LOGGER.debug("docker_daemon_wait", elapsed_seconds=round(elapsed, 1))
    message = f"Docker daemon did not become ready within {_DOCKER_DAEMON_TIMEOUT_SECONDS}s"
    raise SandboxError(message)


def _ensure_windows_engine() -> None:
    """Confirm Docker is running the Windows container engine.

    Raises:
        SandboxError: When Docker is running the Linux engine; the sandbox
            image cannot run under the Linux engine.
    """
    proc = _run_docker(["version", "--format", "{{.Server.Os}}"], check=False)
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
    proc = _run_docker(["image", "inspect", tag], check=False)
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
    argv = [
        docker,
        "build",
        "--file",
        str(_DOCKERFILE),
        "--tag",
        tag,
        "--label",
        f"{_IMAGE_LABEL}=1",
        "--isolation",
        "process",
        str(_PROJECT_ROOT),
    ]
    _LOGGER.info("sandbox_image_building", tag=tag, dockerfile=str(_DOCKERFILE))
    print(f"[sandbox] Building image {tag} (this may take 10-15 minutes on first run)...", file=sys.stderr)
    start = time.monotonic()
    proc = subprocess.run(argv, check=False)
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
        spec: The run specification; serialized into the container at a known
            path so the entrypoint can reproduce the exact pytest argv.
        tag: Image tag to launch.
        memory: Memory reservation (``docker run --memory``).
        cpus: CPU quota (``docker run --cpus``).
        network: Docker network name, typically ``none`` for offline runs or
            ``bridge`` for integration/e2e runs.
        writable_workspace: When ``True`` the workspace mount is writable.
        interactive: When ``True`` allocate an interactive TTY and keep stdin
            open for shell sessions.

    Returns:
        list[str]: Argument vector beginning with the ``docker`` executable.
    """
    docker = _docker_binary()
    reports_mount = f"{_REPORTS_ROOT.parent}:{_CONTAINER_REPORTS}"
    _ = writable_workspace

    container_name = f"intellicrack-sandbox-{spec.test_type.value}"
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
        f"SANDBOX_SPEC_PATH={_CONTAINER_SPEC_PATH}",
        "--label",
        f"{_IMAGE_LABEL}=1",
    ]
    if spec.module:
        argv.extend(["--env", f"TEST_MODULE={spec.module}"])
    if interactive:
        argv.extend(["-it"])
    else:
        argv.extend(["-t"])
    argv.append(tag)
    return argv


def _remove_stale_container(name: str) -> None:
    """Remove a leftover container with the given name, if it exists.

    Handles the case where a prior run was killed abruptly (``kill -9``, power
    cut) before ``--rm`` could remove the container. Without this, the next
    ``docker run --name`` with the same name would fail with a conflict.

    Args:
        name: Container name to probe and remove.
    """
    proc = _run_docker(["ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"], check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        return
    _LOGGER.info("sandbox_stale_container_removed", name=name)
    _run_docker(["rm", "-f", name], check=False)


def _write_spec_file(spec: TestRunSpec) -> None:
    """Persist the serialized spec where the container entrypoint expects it.

    Args:
        spec: The run specification to serialize.
    """
    _HOST_SPEC_PATH.parent.mkdir(parents=True, exist_ok=True)
    pytest_args: list[str] = []
    if spec.test_type not in {TestType.INTERACTIVE, TestType.INTERACTIVE_RW}:
        pytest_args = build_pytest_args(spec)
    payload = {**spec_to_dict(spec), "pytest_args": pytest_args}
    _HOST_SPEC_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _LOGGER.debug("sandbox_spec_written", path=str(_HOST_SPEC_PATH), argc=len(pytest_args))


def _write_exit_code(exit_code: int) -> None:
    """Persist the last container exit code for CI integration.

    Args:
        exit_code: Exit code reported by the container entrypoint.
    """
    _EXIT_CODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _EXIT_CODE_FILE.write_text(str(exit_code), encoding="utf-8")


class DockerSandbox:
    """Coordinate image build, container launch, and report harvesting.

    Attributes:
        memory: Memory quota string, for example ``"8g"``.
        cpus: CPU quota string, for example ``"4"``.
        network: Docker network attached to the container.
        rebuild: When ``True`` force an image rebuild.
        writable_workspace: When ``True`` mount the host workspace read-write.
    """

    memory: str
    cpus: str
    network: str
    rebuild: bool
    writable_workspace: bool

    def __init__(
        self,
        *,
        memory: str = "8g",
        cpus: str = "4",
        network: str = "none",
        rebuild: bool = False,
        writable_workspace: bool = False,
    ) -> None:
        """Initialize the sandbox driver with resource and build options.

        Args:
            memory: Memory quota passed to ``docker run --memory``.
            cpus: CPU quota passed to ``docker run --cpus``.
            network: Docker network name (``none`` for offline runs).
            rebuild: Force an image rebuild even when a cached tag exists.
            writable_workspace: Mount the host workspace read-write.
        """
        self.memory = memory
        self.cpus = cpus
        self.network = network
        self.rebuild = rebuild
        self.writable_workspace = writable_workspace

    def ensure_image(self) -> str:
        """Ensure Docker is running and the sandbox image is available.

        Returns:
            str: Tag of the ready image.
        """
        ensure_docker_running()
        _ensure_windows_engine()
        tag = _compute_image_tag()
        return build_image(tag, rebuild=self.rebuild)

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
        _remove_stale_container(f"intellicrack-sandbox-{spec.test_type.value}")
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
            network=self.network,
            memory=self.memory,
            cpus=self.cpus,
            writable_workspace=self.writable_workspace,
            module=spec.module,
            extra_args=list(spec.extra_args),
        )
        print(
            f"[sandbox] Running {spec.test_type.value} (ts={spec.timestamp}, "
            f"net={self.network}, mem={self.memory}, cpus={self.cpus})",
            file=sys.stderr,
        )
        start = time.monotonic()
        exit_code = _run_streamed(argv, timeout_seconds=spec.timeout_seconds)
        duration = time.monotonic() - start
        _LOGGER.info(
            "sandbox_container_finished",
            test_type=spec.test_type.value,
            timestamp=spec.timestamp,
            exit_code=exit_code,
            duration_seconds=round(duration, 2),
        )
        _write_exit_code(exit_code)
        record = harvest_reports(
            spec.test_type,
            spec.timestamp,
            exit_code,
            module=spec.module,
            extra_args=spec.extra_args,
        )
        if record.paths.summary is None:
            summary_path = (
                _REPORTS_ROOT / f"summary_{record.test_type}_{record.timestamp}.json"
            )
            write_summary_json(record, summary_path)
            record = harvest_reports(
                spec.test_type,
                spec.timestamp,
                exit_code,
                module=spec.module,
                extra_args=spec.extra_args,
            )
        return record


def _run_streamed(argv: list[str], *, timeout_seconds: int) -> int:
    """Run a subprocess with live output streaming and SIGINT forwarding.

    Args:
        argv: Argument vector beginning with the executable path.
        timeout_seconds: Hard timeout applied to the subprocess.

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
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
        return 124
    except KeyboardInterrupt:
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
        default="8g",
        help="Memory quota for docker run (default: 8g).",
    )
    parser.add_argument(
        "--cpus",
        default="4",
        help="CPU quota for docker run (default: 4).",
    )
    parser.add_argument(
        "--network",
        default=None,
        help="Docker network (default: bridge for integration/e2e, none otherwise).",
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


def _default_network(test_type: TestType | None) -> str:
    """Select a default Docker network for the given test type.

    Args:
        test_type: Active test type or ``None`` when running a shell.

    Returns:
        str: ``"bridge"`` for network-requiring modes, ``"none"`` otherwise.
    """
    if test_type in {TestType.INTEGRATION, TestType.E2E}:
        return "bridge"
    return "none"


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
    written both to the console and to ``logs/sandbox/driver.log`` in JSON
    form. Call once per process at startup.

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

    _LOGGER.info(
        "sandbox_invocation",
        test_type=test_type.value,
        timestamp=timestamp,
        network=network,
        writable_workspace=writable,
        rebuild=args.rebuild,
        shell=args.shell,
        build_only=args.build_only,
        module=args.module,
        extra_args=list(spec.extra_args),
    )

    sandbox = DockerSandbox(
        memory=args.memory,
        cpus=args.cpus,
        network=network,
        rebuild=args.rebuild,
        writable_workspace=writable,
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
