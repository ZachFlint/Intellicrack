# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""A WHPX virtual machine must never start beside a live Docker Windows engine.

The container-side half of this interlock is gated by
:mod:`tests.sandbox.test_docker_sandbox_hcs_interlock`: a container will not
start while a virtual machine holds the Host Compute Service. This module gates
the other half, which was only ever partly built.

The WHPX boot gates asked ``docker ps`` whether a *container* was running. The
collision is with the *engine*: Docker Desktop keeps its Windows engine and
utility VM on the Host Compute Service for as long as it runs, container or no
container. ``just test`` runs the container leg and then the host-native pass,
so by the time the WHPX gates looked, the container had exited and the engine
was still up -- zero containers, engine live, gate open, virtual machine booted
straight into it. That is the state that wedges Docker until Docker Desktop is
relaunched as administrator, and it is what
:func:`test_the_gate_refuses_an_idle_engine_with_no_container_running` pins.

Nothing here is asserted against a mock. The probes are injected because they
describe the *host* -- whether an engine is up, whether a shutdown worked --
and the logic deciding what to do about it is the real production code under
test. Where a real host signal can be produced instead, it is: the process
enumerator is gated against a genuine running process carrying an engine's
name, exactly as the container-side interlock gates its own.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import os
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from scripts.sandbox.hcs_interlock import (
    DOCKER_WINDOWS_ENGINE_PIPE,
    DockerEngineState,
    docker_windows_engine_running,
    quiesce_docker_engine,
    running_docker_engine_processes,
)
from tests.sandbox.qemu.windows_boot_probe import (
    docker_engine_refusal_reason,
    resolve_whpx_qemu_path,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


_HOST_NATIVE_MODULE: Final[str] = "scripts.host_native_tests"
_HOST_NATIVE_ENTRY: Final[str] = "run"
_QUIESCE_CALL: Final[str] = "_quiesce_docker_for_vm_gates"

_ENGINE_PROCESS_NAME: Final[str] = "dockerd.exe"
_PROCESS_KILL_GRACE_SEC: Final[float] = 5.0

# The orchestration is driven by an injected clock, so the waits it really
# performs are exercised without spending the real budget on them.
_TEST_TIMEOUT_SEC: Final[float] = 30.0
_TEST_CONTAINER_TIMEOUT_SEC: Final[float] = 20.0
_TEST_POLL_SEC: Final[float] = 1.0
_SIBLING_CONTAINERS: Final[tuple[str, ...]] = ("9f2c1a", "77bd04")

_WINDOWS_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="the Docker engine process enumerator inspects Windows process names",
)


def _module_source(module_name: str) -> str:
    """Read a module's source text without importing it.

    Importing ``scripts.host_native_tests`` merely to parse it would pull in
    torch and an HTTP client, and the container this runs in has no hardware
    for torch to find. This gate only reads text, so ``find_spec`` locates the
    file through the same import machinery pytest uses, executing none of it.

    Args:
        module_name: Dotted name of the module to read.

    Returns:
        str: The module's source text.
    """
    spec = importlib.util.find_spec(module_name)
    assert spec is not None, f"{module_name} is not importable from the test environment"
    origin = spec.origin
    assert origin is not None, f"{module_name} resolves to no file on disk"
    return Path(origin).read_text(encoding="utf-8")


def _ordered_calls_in(source: str, function_name: str) -> list[str]:
    """List, in source order, the names one function in ``source`` calls.

    Args:
        source: Source text of the module holding the function.
        function_name: Name of the function to read.

    Returns:
        list[str]: Called names in source order; empty when the function is not
        defined exactly once in the module.
    """
    defined = [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef) and node.name == function_name]
    if len(defined) != 1:
        return []
    calls = [node for node in ast.walk(defined[0]) if isinstance(node, ast.Call)]
    return [
        node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        for node in sorted(calls, key=lambda node: (node.lineno, node.col_offset))
        if isinstance(node.func, ast.Name | ast.Attribute)
    ]


def _no_containers() -> tuple[str, ...]:
    """Describe a host running no containers.

    Returns:
        tuple[str, ...]: Always empty.
    """
    return ()


def _no_pipes() -> tuple[str, ...]:
    """Describe a host publishing no named pipes.

    Returns:
        tuple[str, ...]: Always empty.
    """
    return ()


def _no_engine_processes() -> tuple[tuple[int, str], ...]:
    """Describe a host running no Docker engine processes.

    Returns:
        tuple[tuple[int, str], ...]: Always empty.
    """
    return ()


class _ContainerQuery:
    """A container listing that records whether the gate bothered to ask."""

    def __init__(self) -> None:
        """Start with no queries recorded."""
        self.calls: int = 0

    def __call__(self) -> tuple[str, ...]:
        """Answer the gate's container question and count the query.

        Returns:
            tuple[str, ...]: Always empty; no container is running.
        """
        self.calls += 1
        return ()


class _FakeClock:
    """A monotonic clock that only advances when the code under test sleeps."""

    def __init__(self) -> None:
        """Start the clock at zero."""
        self.now: float = 0.0

    def monotonic(self) -> float:
        """Return the current fake time.

        Returns:
            float: Seconds since this clock was created.
        """
        return self.now

    def sleep(self, seconds: float) -> None:
        """Advance the clock instead of blocking.

        Args:
            seconds: How far to move the clock forward.
        """
        self.now += seconds


class _EngineProbe:
    """A host whose Docker engine is up until a named effect brings it down."""

    def __init__(
        self,
        *,
        running: bool,
        cleared_by: str | None,
        containers: tuple[str, ...] = (),
        container_polls_until_idle: int = 0,
    ) -> None:
        """Configure the host this probe describes.

        Args:
            running: Whether an engine is on the Host Compute Service to begin
                with.
            cleared_by: Which effect stops the engine -- ``"shutdown"``,
                ``"service"``, or ``None`` for an engine nothing clears.
            containers: Container ids the engine is running to begin with.
            container_polls_until_idle: How many container polls pass before
                those containers finish; ``0`` leaves them running forever.
        """
        self.running: bool = running
        self.cleared_by: str | None = cleared_by
        self.containers: tuple[str, ...] = containers
        self.container_polls_until_idle: int = container_polls_until_idle
        self.container_polls: int = 0
        self.shutdown_calls: int = 0
        self.service_calls: int = 0

    def engine_running(self) -> bool:
        """Report whether the engine still holds the host.

        Returns:
            bool: ``True`` while the engine is up.
        """
        return self.running

    def running_containers(self) -> tuple[str, ...]:
        """Report the containers still running, retiring them once polled enough.

        Returns:
            tuple[str, ...]: Ids still running, empty once they have finished.
        """
        self.container_polls += 1
        if self.container_polls_until_idle and self.container_polls >= self.container_polls_until_idle:
            self.containers = ()
        return self.containers

    def graceful_shutdown(self) -> bool:
        """Record an unelevated Docker Desktop quit and apply its effect.

        Returns:
            bool: ``True``; the shutdown request was accepted.
        """
        self.shutdown_calls += 1
        if self.cleared_by == "shutdown":
            self.running = False
        return True

    def stop_engine_service(self) -> bool:
        """Record an elevated service stop and apply its effect.

        Returns:
            bool: ``True``; the stop command completed.
        """
        self.service_calls += 1
        if self.cleared_by == "service":
            self.running = False
        return True


def _quiesce(probe: _EngineProbe, *, elevated: bool) -> DockerEngineState:
    """Run the production orchestration against a described host.

    Args:
        probe: The host state and effects the orchestration acts on.
        elevated: Whether the caller already holds an elevated token.

    Returns:
        DockerEngineState: What the interlock decided about the host.
    """
    clock = _FakeClock()
    return quiesce_docker_engine(
        engine_running=probe.engine_running,
        running_containers=probe.running_containers,
        graceful_shutdown=probe.graceful_shutdown,
        stop_engine_service=probe.stop_engine_service,
        elevated=elevated,
        timeout=_TEST_TIMEOUT_SEC,
        container_timeout=_TEST_CONTAINER_TIMEOUT_SEC,
        poll_interval=_TEST_POLL_SEC,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
    )


def test_the_gate_refuses_an_idle_engine_with_no_container_running() -> None:
    """The exact state that wedged Docker must be refused, not waved through.

    A host whose container leg has finished has zero running containers and a
    live Docker Windows engine. The container-only check this replaced returned
    "no reason to refuse" here, and a WHPX virtual machine started beside the
    engine. Anything that reverts the gate to counting containers fails this.
    """
    reason = docker_engine_refusal_reason(engine_running=lambda: True, containers=_no_containers)

    assert reason, "the gate allowed a WHPX virtual machine to start while the Docker Windows engine held the Host Compute Service"
    assert "Host Compute Service" in reason, f"the refusal must say what is being protected; reason={reason!r}"
    assert "no container running" in reason, (
        f"the refusal must show it refused an engine with no container, the state a container check missed; reason={reason!r}"
    )


def test_the_gate_allows_a_host_with_no_engine() -> None:
    """A clear host must not be refused, or the gates could never run.

    The control for the refusal above: an implementation that always refused
    would satisfy that test and fail this one. A clear host must also not be
    made to wait on a ``docker ps`` that cannot change the outcome, which is
    the query a wedged engine would leave hanging.
    """
    containers = _ContainerQuery()

    assert docker_engine_refusal_reason(engine_running=lambda: False, containers=containers) == ""
    assert containers.calls == 0, "a host with no engine running was still made to query Docker for its containers"


def test_the_gate_reports_the_containers_a_busy_engine_is_running() -> None:
    """A refusal on a busy engine must tell the operator what is holding it."""
    reason = docker_engine_refusal_reason(engine_running=lambda: True, containers=lambda: ("abc123", "def456"))

    assert "2 container(s) running" in reason, f"the refusal must name what the engine is doing; reason={reason!r}"


def test_the_engine_pipe_alone_proves_the_engine_is_up() -> None:
    """The Windows engine's named pipe must be read as a live engine.

    This is the signal a container count cannot see: the pipe exists exactly
    while the engine that shares the Host Compute Service with WHPX is serving.
    """
    assert docker_windows_engine_running(
        pipe_names=lambda: ("SomeOtherPipe", DOCKER_WINDOWS_ENGINE_PIPE),
        engine_processes=_no_engine_processes,
    ), "an engine publishing its Windows engine pipe was not detected"


def test_an_engine_process_alone_proves_the_engine_is_up() -> None:
    """A backend process must be read as a live engine even with no pipe yet.

    The pipe is absent while the engine is still starting or already tearing
    down, and the utility VM is on the Host Compute Service for all of it.
    """
    assert docker_windows_engine_running(
        pipe_names=_no_pipes,
        engine_processes=lambda: ((4321, "com.docker.backend.exe"),),
    ), "a running Docker backend process was not detected as a live engine"


def test_a_host_with_neither_signal_is_reported_clear() -> None:
    """With no pipe and no engine process the host must be reported clear.

    The control for the two detection tests: an implementation hard-wired to
    report an engine would pass both and fail here, stranding every VM gate.
    """
    assert not docker_windows_engine_running(pipe_names=_no_pipes, engine_processes=_no_engine_processes)


def test_an_unrelated_pipe_is_not_mistaken_for_the_engine() -> None:
    """Only the Docker Windows engine pipe may count as a live engine."""
    assert not docker_windows_engine_running(
        pipe_names=lambda: ("dockerDesktopLinuxEngine", "chrome.sync", "PIPE_EventLog"),
        engine_processes=_no_engine_processes,
    ), "a pipe that is not the Windows engine's was read as a live Windows engine"


def test_a_clear_host_is_not_shut_down() -> None:
    """With no engine running nothing may be shut down.

    An interlock that quit Docker unconditionally would pass the quiesce tests
    below and fail here, taking down an engine no virtual machine needed gone.
    """
    probe = _EngineProbe(running=False, cleared_by=None)

    state = _quiesce(probe, elevated=False)

    assert state is DockerEngineState.STOPPED, f"a clear host was not reported STOPPED; state={state}"
    assert probe.shutdown_calls == 0, "a host with no engine running was sent a shutdown anyway"
    assert probe.service_calls == 0, "a host with no engine running had its engine service stopped"


def test_a_running_engine_is_quiesced_by_the_unelevated_shutdown() -> None:
    """The ordinary case must clear the host without touching the service.

    Docker Desktop's own quit path needs no elevation, so the common case must
    never reach the elevated branch at all.
    """
    probe = _EngineProbe(running=True, cleared_by="shutdown")

    state = _quiesce(probe, elevated=False)

    assert state is DockerEngineState.QUIESCED, f"a running engine was not cleared by a graceful shutdown; state={state}"
    assert probe.shutdown_calls == 1, f"expected exactly one graceful shutdown; calls={probe.shutdown_calls}"
    assert probe.service_calls == 0, "the engine service was stopped even though the graceful shutdown had already cleared the host"


def test_an_unelevated_run_never_reaches_the_service_stop() -> None:
    """No test run may raise a UAC prompt, so it must give up instead.

    Stopping the engine service needs an elevated token. An unelevated run that
    tried anyway would put an elevation dialog in front of the operator in the
    middle of a test run, which is forbidden outright: it reports BLOCKED and
    the WHPX gates skip.
    """
    probe = _EngineProbe(running=True, cleared_by="service")

    state = _quiesce(probe, elevated=False)

    assert state is DockerEngineState.BLOCKED, f"an engine that survived the graceful shutdown was not reported BLOCKED; state={state}"
    assert probe.service_calls == 0, (
        "an unelevated run invoked the elevated service stop, the path that raises a UAC prompt during a test run"
    )
    assert probe.engine_running(), "the engine is not actually up, so this no longer describes a blocked host"


def test_an_already_elevated_run_stops_the_service_the_shutdown_could_not() -> None:
    """A caller already holding a token may clear a wedged engine outright.

    This is why recovery has needed Docker Desktop relaunched as administrator:
    an engine the graceful quit cannot shift only leaves the Host Compute
    Service when its service is stopped, and that needs elevation.
    """
    probe = _EngineProbe(running=True, cleared_by="service")

    state = _quiesce(probe, elevated=True)

    assert state is DockerEngineState.QUIESCED, f"an elevated run failed to clear an engine its service stop could remove; state={state}"
    assert probe.shutdown_calls == 1, "the elevated run skipped the graceful shutdown it should always try first"
    assert probe.service_calls == 1, f"expected exactly one service stop; calls={probe.service_calls}"


def test_an_engine_nothing_can_clear_blocks_rather_than_reporting_success() -> None:
    """An engine that survives everything must never be reported clear.

    Reporting success here is precisely what would start a virtual machine
    beside a live engine, so the interlock must fail closed.
    """
    probe = _EngineProbe(running=True, cleared_by=None)

    state = _quiesce(probe, elevated=True)

    assert state is DockerEngineState.BLOCKED, f"an engine that survived both remedies was not reported BLOCKED; state={state}"
    assert probe.shutdown_calls == 1, "the graceful shutdown was not attempted"
    assert probe.service_calls == 1, "the elevated service stop was not attempted by a caller that held a token"


def test_a_sibling_sessions_running_container_is_never_shut_down() -> None:
    """A busy engine must be left alone, not quit out from under its container.

    Sibling agent sessions share this host and queue their runs through the
    admission gate, so a container running here is somebody else's work. An
    interlock that quit Docker to clear the host for its own virtual machines
    would destroy that run. It must wait, and when the container outlasts the
    wait it must give up its own gates rather than the sibling's container.
    """
    probe = _EngineProbe(running=True, cleared_by="shutdown", containers=_SIBLING_CONTAINERS)

    state = _quiesce(probe, elevated=True)

    assert state is DockerEngineState.BLOCKED, f"a host busy with a sibling's container was not reported BLOCKED; state={state}"
    assert probe.shutdown_calls == 0, (
        "Docker was shut down while a sibling session's container was still running, destroying their test run"
    )
    assert probe.service_calls == 0, "the engine service was stopped while a sibling session's container was still running"
    assert probe.container_polls > 1, f"the interlock never waited for the container to finish; polls={probe.container_polls}"


def test_a_container_that_finishes_in_time_lets_the_quiesce_proceed() -> None:
    """Waiting must end as soon as the sibling's run is done, not always block.

    The control for the guard above: an implementation that refused whenever it
    ever saw a container would pass that test and fail this one, permanently
    stranding the VM gates on any host that had just run the container leg.
    """
    probe = _EngineProbe(
        running=True,
        cleared_by="shutdown",
        containers=_SIBLING_CONTAINERS,
        container_polls_until_idle=3,
    )

    state = _quiesce(probe, elevated=False)

    assert state is DockerEngineState.QUIESCED, f"the engine was not quiesced once its containers had finished; state={state}"
    assert probe.shutdown_calls == 1, "the engine was never shut down even though the host had gone idle"


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (DockerEngineState.STOPPED, True),
        (DockerEngineState.QUIESCED, True),
        (DockerEngineState.BLOCKED, False),
    ],
)
def test_only_a_cleared_host_is_reported_safe_for_a_virtual_machine(state: DockerEngineState, *, expected: bool) -> None:
    """Only STOPPED and QUIESCED may permit a virtual machine to start.

    Args:
        state: The interlock outcome under test.
        expected: Whether a virtual machine may start in that state.
    """
    assert state.host_is_clear is expected, f"{state} reported host_is_clear={state.host_is_clear}, expected {expected}"


def test_the_whpx_resolver_consults_the_engine_refusal_before_handing_back_qemu() -> None:
    """``resolve_whpx_qemu_path`` must ask the interlock, not just the accelerator.

    The tests above prove the refusal is correct; this proves the WHPX launch
    path actually uses it, which no runtime test can reach from inside the
    container -- resolving a WHPX QEMU needs a hypervisor the container has
    none of. The call is read out of the function's own syntax tree, so
    reformatting cannot fake a pass and deleting the call cannot hide behind a
    comment that still mentions it.
    """
    source = inspect.getsource(resolve_whpx_qemu_path)
    called = [node.func.id for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]

    assert docker_engine_refusal_reason.__name__ in called, (
        f"resolve_whpx_qemu_path never calls {docker_engine_refusal_reason.__name__}, so a WHPX virtual "
        f"machine can still be started while the Docker Windows engine holds the host; calls={called!r}"
    )


def test_the_refusal_is_decided_by_the_engine_and_not_by_a_container_count() -> None:
    """The gate's default probe must be the engine one, not ``docker ps``.

    A revert that pointed the gate back at running containers would still call
    a refusal helper and satisfy the wiring test above; this pins which
    question that helper asks by default.
    """
    default = inspect.signature(docker_engine_refusal_reason).parameters["engine_running"].default

    assert default is docker_windows_engine_running, (
        f"the WHPX gate defaults to {default!r} rather than the Docker engine probe, so an idle engine "
        "would be waved through exactly as the container-only check waved it through"
    )


def test_the_host_native_pass_quiesces_docker_before_it_runs_pytest() -> None:
    """The host-native runner must clear the engine before any test can boot a VM.

    ``just test`` runs the container leg and then this pass, so the engine is
    live when the pass starts. Quiescing after pytest had already begun would
    leave the WHPX gates to race it, so ordering is asserted as well as
    presence, read from the runner's own syntax tree.
    """
    ordered = _ordered_calls_in(_module_source(_HOST_NATIVE_MODULE), _HOST_NATIVE_ENTRY)

    assert ordered, f"{_HOST_NATIVE_MODULE}.{_HOST_NATIVE_ENTRY} could not be read, so its wiring is unproven"
    assert _QUIESCE_CALL in ordered, (
        f"the host-native pass never calls {_QUIESCE_CALL}, so it starts WHPX virtual machines while the "
        f"Docker Windows engine still holds the Host Compute Service; calls={ordered!r}"
    )
    assert "run" in ordered, f"the host-native pass no longer launches pytest through subprocess.run; calls={ordered!r}"
    assert ordered.index(_QUIESCE_CALL) < ordered.index("run"), (
        f"{_QUIESCE_CALL} must run before pytest is launched, or the WHPX gates race the engine shutdown; order={ordered!r}"
    )


@pytest.fixture
def engine_named_process(tmp_path: Path) -> Iterator[Popen[bytes]]:
    """Yield a live process carrying the Docker engine daemon's name.

    ``cmd.exe`` is copied because it is self-contained: a lone copy of the
    Python interpreter cannot start away from its own DLLs, so it would exit
    before the enumerator could ever see it. The enumerator matches on the
    process name and nothing else, so this is the same evidence it takes from a
    real ``dockerd.exe``.

    Args:
        tmp_path: Pytest-provided temp directory holding the executable.

    Yields:
        Popen[bytes]: The running stand-in process.
    """
    source = Path(os.environ["SYSTEMROOT"]) / "System32" / "cmd.exe"
    assert source.is_file(), f"cmd.exe not found at {source}"
    target = tmp_path / _ENGINE_PROCESS_NAME
    shutil.copy2(source, target)
    process = Popen([str(target)], stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL)
    try:
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=_PROCESS_KILL_GRACE_SEC)


@_WINDOWS_ONLY
def test_a_running_engine_process_is_enumerated(engine_named_process: Popen[bytes]) -> None:
    """The enumerator must report a live engine-named process by pid.

    Args:
        engine_named_process: A live process named ``dockerd.exe``.
    """
    found = running_docker_engine_processes()
    pids = {pid for pid, _ in found}

    assert engine_named_process.pid in pids, (
        f"the interlock cannot see a running {_ENGINE_PROCESS_NAME} (pid {engine_named_process.pid}); found={found!r}"
    )


@_WINDOWS_ONLY
def test_the_detector_reports_the_engine_up_from_that_process_alone(engine_named_process: Popen[bytes]) -> None:
    """A real engine-named process must make the detector report an engine.

    Args:
        engine_named_process: A live process named ``dockerd.exe``.
    """
    assert docker_windows_engine_running(pipe_names=_no_pipes), (
        f"a real running {_ENGINE_PROCESS_NAME} (pid {engine_named_process.pid}) did not make the detector report a live engine"
    )
