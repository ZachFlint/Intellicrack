# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the Ghidra bridge response-timeout and polled analyze path.

These tests pin the two invariants that keep ``Analyze`` / ``get_functions``
from silently timing out into an empty view:

  1. :meth:`GhidraBridge.initialize` must construct the underlying
     ``ghidra_bridge.GhidraBridge`` RPC client with an explicit
     ``response_timeout`` well above the 2-second jfx_bridge default, so the
     derived ``remote_exec``/``remote_eval`` ceilings are large enough for
     real Ghidra workloads. Dropping the kwarg fails
     ``test_initialize_constructs_bridge_with_large_response_timeout``.

  2. :meth:`GhidraBridge.analyze` must launch ``analyzeAll`` on a background
     Jython thread and poll a completion flag in short RPCs, never blocking a
     single RPC on ``waitForAnalysis``. A fake RPC backend models a
     long-running analysis with real wall-clock; the polled path completes
     past the old 2-second ceiling, times out only against the bounded
     deadline, and surfaces a worker-side failure. Re-blocking the analyze
     path (single ``waitForAnalysis`` RPC) or deleting the deadline/poll loop
     breaks these gates.

The end-to-end analyze is host-gated on a real Ghidra 12.1.2 headless install;
these gates cover the timeout plumbing and poll logic that runs on the client.
"""

from __future__ import annotations

import inspect
import socket
import time

import pytest

import intellicrack.bridges.ghidra as ghidra_mod
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


_ANALYSIS_DONE_EXPR = "_ic_analysis_done"
_ANALYSIS_ERROR_EXPR = "_ic_analysis_error"


class _AnalysisFake:
    """In-process double for the ghidra_bridge RPC client used by ``analyze``.

    Records every ``remote_exec``/``remote_eval`` payload. Models a
    long-running background analysis using a real monotonic clock: the
    completion flag ``_ic_analysis_done`` reports ``True`` only once
    ``done_after`` seconds have elapsed since the kick-off exec (or never,
    when ``done_after`` is ``None``). The worker error flag
    ``_ic_analysis_error`` returns ``analysis_error`` verbatim.
    """

    def __init__(self, done_after: float | None, analysis_error: str | None = None) -> None:
        """Initialise the recording double.

        Args:
            done_after: Seconds after the kick-off exec at which the analysis
                completion flag flips to ``True``; ``None`` to never complete.
            analysis_error: Value returned for the worker error flag, or
                ``None`` when the analysis succeeded.
        """
        self.done_after: float | None = done_after
        self.analysis_error: str | None = analysis_error
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self._exec_time: float | None = None

    def _is_done(self) -> bool:
        """Report whether the modelled background analysis has finished.

        Returns:
            bool: ``True`` once ``done_after`` seconds have elapsed since the
            kick-off exec, ``False`` while still running or never-completing.
        """
        if self.done_after is None or self._exec_time is None:
            return False
        return (time.monotonic() - self._exec_time) >= self.done_after

    def remote_exec(self, code: str) -> None:
        """Record the kick-off script and start the modelled analysis clock.

        Args:
            code: Jython source forwarded from the bridge.
        """
        self.exec_calls.append(code)
        if self._exec_time is None:
            self._exec_time = time.monotonic()

    def remote_eval(self, expression: str, **_kwargs: object) -> object:
        """Serve poll reads for the completion flag, error flag, and sentinel.

        Args:
            expression: Expression forwarded from the bridge (a completion or
                error flag, or a ``prepare_remote_script`` sentinel readback).
            **_kwargs: Ignored keyword arguments matching the real client.

        Returns:
            object: The completion boolean, the worker error value, or
            ``None`` for the kick-off sentinel readback.
        """
        self.eval_calls.append(expression)
        if expression == _ANALYSIS_DONE_EXPR:
            return self._is_done()
        if expression == _ANALYSIS_ERROR_EXPR:
            return self.analysis_error
        return None


def _connected_bridge(fake: _AnalysisFake) -> GhidraBridge:
    """Wire a GhidraBridge to the analysis fake and mark it connected.

    Args:
        fake: The recording double to attach as the RPC backend.

    Returns:
        GhidraBridge: Bridge whose ``_bridge`` attribute is the fake.
    """
    bridge = GhidraBridge()
    setattr(bridge, "_bridge", fake)
    bridge.state.connected = True
    bridge.state.tool_running = True
    return bridge


@pytest.mark.asyncio
async def test_initialize_constructs_bridge_with_large_response_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Initialize must pass an explicit response_timeout far above the 2s jfx default.

    Patches the ``GhidraBridge`` symbol the bridge imports with a capturing
    callable that records constructor kwargs. The gate fails if
    ``response_timeout`` is dropped or reduced to the tiny default that makes
    long analyses time out.

    Args:
        monkeypatch: Pytest fixture used to patch the imported RPC client.
    """
    ghidra_bridge = pytest.importorskip("ghidra_bridge")

    captured: list[dict[str, object]] = []

    class _CapturingClient:
        """Capturing stand-in that records the RPC client construction kwargs."""

        def __init__(self, **kwargs: object) -> None:
            """Record the constructor keyword arguments.

            Args:
                **kwargs: Keyword arguments the bridge passes to the client.
            """
            captured.append(dict(kwargs))

    monkeypatch.setattr(ghidra_bridge, "GhidraBridge", _CapturingClient)

    def _reachable(_host: str, _port: int, _timeout_seconds: float = 3.0) -> bool:
        """Report the bridge port reachable so initialize reaches client construction.

        Args:
            _host: Ignored probe host.
            _port: Ignored probe port.
            _timeout_seconds: Ignored probe timeout.

        Returns:
            bool: Always True.
        """
        return True

    monkeypatch.setattr(GhidraBridge, "_probe_bridge_port", staticmethod(_reachable))

    bridge = GhidraBridge()
    await bridge.initialize()

    assert len(captured) == 1
    kwargs = captured[0]
    assert "response_timeout" in kwargs

    response_timeout = kwargs["response_timeout"]
    assert isinstance(response_timeout, int)
    assert response_timeout > 2
    assert response_timeout >= 60


@pytest.mark.asyncio
async def test_analyze_polls_completion_past_old_two_second_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Analyze must poll a threaded analysis to completion, surviving past the old 2s ceiling.

    Models an analysis that finishes only after 2.5 s of wall-clock. A single
    blocking RPC would trip the old 2 s default, but the polled path completes.
    The gate fails if analyze re-blocks on a single ``waitForAnalysis`` RPC
    (the kick-off script assertions break) or drops the poll loop.

    Args:
        monkeypatch: Pytest fixture used to shrink the poll interval.
    """
    monkeypatch.setattr(ghidra_mod, "_GHIDRA_ANALYZE_POLL_INTERVAL_SECONDS", 0.05)

    fake = _AnalysisFake(done_after=2.5)
    bridge = _connected_bridge(fake)

    start = time.monotonic()
    await bridge.analyze()
    elapsed = time.monotonic() - start

    assert elapsed > 2.0

    assert len(fake.exec_calls) == 1
    kickoff = fake.exec_calls[0]
    assert "analyzeAll(currentProgram)" in kickoff
    assert "_ic_analysis_thread" in kickoff
    assert "waitForAnalysis" not in kickoff

    done_polls = [call for call in fake.eval_calls if call == _ANALYSIS_DONE_EXPR]
    assert len(done_polls) >= 2


@pytest.mark.asyncio
async def test_analyze_times_out_against_bounded_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Analyze must give up with a ToolError once the bounded deadline elapses.

    Models an analysis that never completes. With a short deadline and poll
    interval the polled loop must raise rather than hang forever. The gate
    fails if the deadline check is removed (the loop never terminates) or the
    kick-off is skipped.

    Args:
        monkeypatch: Pytest fixture used to shrink the deadline and interval.
    """
    monkeypatch.setattr(ghidra_mod, "_GHIDRA_ANALYZE_POLL_INTERVAL_SECONDS", 0.02)
    monkeypatch.setattr(ghidra_mod, "_GHIDRA_ANALYZE_DEADLINE_SECONDS", 0.15)

    fake = _AnalysisFake(done_after=None)
    bridge = _connected_bridge(fake)

    with pytest.raises(ToolError) as exc_info:
        await bridge.analyze()

    assert "did not complete" in str(exc_info.value)
    assert len(fake.exec_calls) == 1
    assert any(call == _ANALYSIS_DONE_EXPR for call in fake.eval_calls)


@pytest.mark.asyncio
async def test_analyze_surfaces_worker_side_failure() -> None:
    """Analyze must re-raise a background analyzer failure captured on the server.

    The worker completes immediately but reports an error string; analyze must
    surface it as a ToolError instead of returning success. The gate fails if
    the worker-error readback is dropped.
    """
    fake = _AnalysisFake(done_after=0.0, analysis_error="analyzer exploded on region 0x1000")
    bridge = _connected_bridge(fake)

    with pytest.raises(ToolError) as exc_info:
        await bridge.analyze()

    assert "analyzer exploded on region 0x1000" in str(exc_info.value)


@pytest.mark.asyncio
async def test_wait_for_bridge_port_raises_after_polling_closed_port() -> None:
    """``_wait_for_bridge_port`` polls a closed port, then raises on timeout.

    Binds and immediately releases an ephemeral port so nothing listens on it,
    points the bridge at that dead port with no live child process, and drives
    the real poll loop with a short timeout. The gate proves the method
    genuinely polls the port (it does not return early against a dead port) and
    raises ``ToolError`` once the bounded deadline passes, rather than hanging
    or reporting the bridge ready. A regression that dropped the timeout raise
    or returned success would fail here.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    bridge = GhidraBridge()
    setattr(bridge, "_port", closed_port)
    setattr(bridge, "_process", None)
    wait_for_port = getattr(bridge, "_wait_for_bridge_port")

    start = time.monotonic()
    with pytest.raises(ToolError, match="not ready"):
        await wait_for_port(timeout_seconds=0.3, poll_interval=0.1)
    elapsed = time.monotonic() - start

    assert elapsed >= 0.3, "must poll until the timeout, not fail instantly"
    assert elapsed < 10.0, "must not hang past the bounded deadline"


def test_wait_for_bridge_port_default_timeout_covers_cold_jvm_boot() -> None:
    """The default port-wait budget must tolerate a cold Windows JVM boot (F-1).

    A cold first boot of the JVM plus Ghidra, PyGhidra and the ``jfx_bridge``
    import on Windows (with antivirus scanning the freshly written classes) can
    exceed a minute before the bridge socket binds. The default
    ``timeout_seconds`` must therefore stay generous so ``start_headless`` does
    not spuriously fail before the port is ready. Reverting the hardened default
    back to 60 s fails this gate.
    """
    signature = inspect.signature(getattr(GhidraBridge, "_wait_for_bridge_port"))
    default_timeout = signature.parameters["timeout_seconds"].default
    assert default_timeout >= 120
