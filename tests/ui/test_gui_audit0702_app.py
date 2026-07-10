# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for GUI audit findings C1, H1, M1, and M38 in ``ui.app``.

C1 -- ``_open_process_memory`` (the tail of ``_on_process_attached`` reached
after the user picks a memory region) scheduled ``HexBridge.open_process_memory``
with a bare ``asyncio.ensure_future(coro_result)``. That call resolves against
``asyncio.get_event_loop()`` on the GUI thread; nothing ever drives that loop
during normal operation (``main.py`` blocks synchronously inside
``app.exec()``), so the scheduled task never actually advances -- the feature
silently does nothing. The fix dispatches through
``run_bridge_coroutine_logged``, which runs the coroutine on the persistent
background bridge loop (a real ``asyncio`` loop that is actively
``run_forever()``-ing on its own thread) and delivers the result back via a
queued Qt signal.

H1 -- ``_apply_sandbox_settings`` called the **blocking**
``run_bridge_coroutine(self.sandbox_manager.destroy_all())`` directly on the
GUI thread, freezing the whole UI for as long as live sandbox instances took
to tear down. The fix dispatches teardown through
``run_bridge_coroutine_logged`` and defers the manager rebuild plus the
``status_update`` signal to ``_finish_sandbox_settings_apply``, invoked only
once the queued success/error signal fires.

M1 -- ``_on_process_attached`` called the synchronous native FFI
``_hexcore.HexDocument.list_process_memory_regions(pid)`` directly inline on
the GUI thread, blocking the Qt event loop for the duration of the native
enumeration. The fix dispatches the call through a background
``GenericCallableWorker`` and resolves the region-picker (or the failure
warning) via its queued ``call_finished``/``call_error`` signals.

M38 -- ``_apply_smart_window_size`` floored the window width at a fixed 800px
even though ``_setup_ui`` gives the chat panel a 400px minimum and the tool
panel a 500px minimum inside a ``childrenCollapsible(False)`` splitter (a
900px effective floor). On a screen whose available width lands between 800
and 900px, the pre-fix floor produced a window narrower than its own
splitter panes can honour. The fix raises the floor to the panels' combined
minimum width.

Every test below drives the real ``MainWindow`` handlers (extracted, testable
seams: ``_open_process_memory``, ``_apply_sandbox_settings``,
``_on_process_attached``, ``_apply_smart_window_size``) against real
collaborators -- a real (subclassed) ``HexEditorBridge``, a real (subclassed)
``SandboxManager``, and a real ``GenericCallableWorker`` / background bridge
loop -- injecting an artificial delay so the non-blocking dispatch contract
can be measured directly: the handler must return before the delayed
operation completes, and every observable side effect must remain unset
until the Qt event loop is pumped and the queued result signal fires.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.sandbox import SandboxManager
from intellicrack.ui.app import MainWindow

from .conftest import CallRecorder, NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


_DELAY_S: float = 0.4
"""Artificial delay injected into fake background operations, in seconds."""

_RETURN_BUDGET_S: float = _DELAY_S / 2
"""Maximum wall-clock time a non-blocking dispatch may take to return."""


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float) -> bool:
    """Pump the Qt event loop until ``predicate()`` is true or the timeout elapses.

    Results delivered from a background thread (``GenericCallableWorker`` /
    ``BridgeCallWorker`` queued signals) only reach their Qt slots while the
    main-thread event loop is processing events, so tests must pump the loop
    while waiting for a handler's delayed side effect.

    Args:
        qapp: The active QApplication whose event loop is pumped.
        predicate: Zero-argument callable polled after each pump.
        timeout_s: Maximum number of seconds to wait.

    Returns:
        bool: ``True`` if ``predicate()`` became true before the timeout.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(0.02)
    return predicate()


@pytest.fixture
def patched_window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Create a real, unshown ``MainWindow`` with ``SandboxManager`` construction stubbed out.

    ``SandboxManager()`` itself performs no I/O, but stubbing its
    construction keeps ``MainWindow.__init__`` fast and isolates window
    construction from sandbox back-end availability; individual tests that
    need a real ``SandboxManager`` install one directly on
    ``window.sandbox_manager`` afterwards.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real Config instance.
        real_orchestrator: Real Orchestrator instance.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        MainWindow: A constructed, unshown MainWindow instance.
    """
    _ = qapp
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    window = MainWindow(real_config, real_orchestrator)
    yield window
    window.close()


# ---------------------------------------------------------------------------
# C1 -- process-memory open must dispatch through the background bridge loop,
# never through a bare asyncio.ensure_future() on the (undriven) GUI loop.
# ---------------------------------------------------------------------------


class _DelayedHexEditorBridge(HexEditorBridge):
    """``HexEditorBridge`` whose ``open_process_memory`` imposes an artificial delay.

    Lets a test distinguish "the coroutine actually ran to completion on a
    real, driven event loop" from "the coroutine was scheduled but nothing
    ever advances it" -- exactly the C1 failure mode, where
    ``asyncio.ensure_future`` scheduled a task against a loop nobody drives.

    Attributes:
        open_calls: Every ``(pid, address, size)`` tuple the coroutine body
            actually ran to completion for, in call order. Stays empty until
            the coroutine is genuinely awaited to completion by a real,
            running event loop.
    """

    open_calls: list[tuple[int, int, int]]

    def __init__(self, delay_s: float) -> None:
        """Initialise the bridge with the configured artificial delay.

        Args:
            delay_s: Number of seconds ``open_process_memory`` sleeps for
                before recording its call and returning.
        """
        super().__init__()
        self._delay_s: float = delay_s
        self.open_calls = []

    async def open_process_memory(self, pid: int, address: int, size: int) -> dict[str, object]:
        """Sleep, then record the call and return a deterministic result.

        Args:
            pid: Process ID to read from.
            address: Base address of the memory region.
            size: Number of bytes to read.

        Returns:
            dict[str, object]: Fixed payload mirroring the real bridge's shape.
        """
        await asyncio.sleep(self._delay_s)
        self.open_calls.append((pid, address, size))
        return {"pid": pid, "address": address, "size": size, "document_length": size}


def test_c1_open_process_memory_resolves_via_background_loop_not_a_dormant_task(
    qapp: QApplication,
    patched_window: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dispatched coroutine must actually run to completion once pumped.

    Pre-fix, ``asyncio.ensure_future(coro_result)`` schedules the task
    against ``asyncio.get_event_loop()`` on the GUI thread. During real
    operation nothing ever drives that loop (``main.py`` is blocked inside
    a synchronous ``app.exec()`` for the app's entire usable lifetime), so
    the task never executes any of its steps -- ``open_calls`` would never
    become non-empty no matter how long the test waits. Post-fix, dispatch
    goes through ``run_bridge_coroutine_logged``, which runs the coroutine
    on the persistent background bridge loop -- a real ``asyncio`` loop
    that is actively ``run_forever()``-ing on its own dedicated thread --
    so the coroutine genuinely completes and the result is delivered back
    via a queued signal once the Qt event loop is pumped.

    Args:
        qapp: The shared offscreen QApplication fixture.
        patched_window: A constructed MainWindow with SandboxManager stubbed.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = patched_window
    bridge = _DelayedHexEditorBridge(_DELAY_S)
    monkeypatch.setattr(
        window._orchestrator,
        "get_typed_bridge",
        lambda tool_name: bridge if tool_name == "hex_editor" else None,
    )

    pid, base_addr, region_size = 4242, 0x7FF600000000, 0x1000
    window._open_process_memory(pid, base_addr, region_size)

    assert bridge.open_calls == [], "open_process_memory's body ran synchronously before the Qt event loop was ever pumped"

    completed = _pump_until(qapp, lambda: bool(bridge.open_calls), timeout_s=_DELAY_S + 5.0)
    assert completed, (
        "open_process_memory's coroutine never resolved after its delay elapsed; the dispatched "
        "task is dormant instead of running on a real, driven event loop"
    )
    assert bridge.open_calls == [(pid, base_addr, region_size)]


def test_c1_open_process_memory_never_uses_bare_asyncio_ensure_future(
    patched_window: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_open_process_memory`` must never schedule its coroutine via ``asyncio.ensure_future``.

    Direct regression guard for the exact offending call site: pre-fix,
    ``_open_process_memory`` called ``asyncio.ensure_future(coro_result)``
    unconditionally once a coroutine was obtained. This poisons
    ``asyncio.ensure_future`` so any reintroduction of that call raises
    immediately instead of silently scheduling a dormant task.

    Args:
        patched_window: A constructed MainWindow with SandboxManager stubbed.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = patched_window
    bridge = _DelayedHexEditorBridge(0.01)
    monkeypatch.setattr(
        window._orchestrator,
        "get_typed_bridge",
        lambda tool_name: bridge if tool_name == "hex_editor" else None,
    )

    def _poison_ensure_future(*_args: object, **_kwargs: object) -> None:
        msg = "asyncio.ensure_future must not be used to schedule the bridge coroutine"
        raise AssertionError(msg)

    monkeypatch.setattr(asyncio, "ensure_future", _poison_ensure_future)

    window._open_process_memory(4243, 0x1000, 0x1000)


# ---------------------------------------------------------------------------
# H1 -- applying sandbox settings must not block the GUI thread on teardown.
# ---------------------------------------------------------------------------


class _DelayedSandboxManager(SandboxManager):
    """``SandboxManager`` whose ``destroy_all`` imposes an artificial teardown delay.

    Attributes:
        destroy_all_calls: Number of times ``destroy_all`` has been invoked.
    """

    destroy_all_calls: int

    def __init__(self, delay_s: float) -> None:
        """Initialise the manager with the configured artificial teardown delay.

        Args:
            delay_s: Number of seconds ``destroy_all`` sleeps for before
                returning, standing in for a slow Windows Sandbox/QEMU stop.
        """
        super().__init__()
        self._delay_s: float = delay_s
        self.destroy_all_calls = 0

    async def destroy_all(self) -> None:
        """Record the call, then sleep to simulate a slow instance teardown."""
        self.destroy_all_calls += 1
        await asyncio.sleep(self._delay_s)


def test_h1_apply_sandbox_settings_returns_before_teardown_completes(
    qapp: QApplication,
    patched_window: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_apply_sandbox_settings`` must return before ``destroy_all`` finishes.

    Pre-fix, ``_apply_sandbox_settings`` called the blocking
    ``run_bridge_coroutine(self.sandbox_manager.destroy_all())``, which
    invokes ``future.result()`` on the calling (GUI) thread -- the whole
    method, including the manager rebuild and the ``status_update`` emit
    that followed it inline, would not complete until the full artificial
    teardown delay had elapsed. Post-fix, teardown is dispatched via
    ``run_bridge_coroutine_logged`` and the rebuild/status-update only
    happen in ``_finish_sandbox_settings_apply``, invoked once the queued
    result signal fires.

    Args:
        qapp: The shared offscreen QApplication fixture.
        patched_window: A constructed MainWindow with SandboxManager stubbed.
        monkeypatch: Pytest monkeypatch fixture used to restore the real
            ``SandboxManager`` so the post-teardown rebuild constructs a
            genuine instance rather than the construction-time stub.
    """
    window = patched_window
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", SandboxManager)
    delayed_manager = _DelayedSandboxManager(_DELAY_S)
    window.sandbox_manager = delayed_manager

    status_updates: list[str] = []
    _ = window.status_update.connect(status_updates.append)

    settings: dict[str, object] = {
        "timeout_seconds": 321,
        "memory_limit_mb": 2048,
        "network_enabled": True,
    }

    start = time.monotonic()
    window._apply_sandbox_settings(settings)
    elapsed = time.monotonic() - start

    assert elapsed < _RETURN_BUDGET_S, (
        f"_apply_sandbox_settings blocked the calling thread for {elapsed:.3f}s waiting on a "
        f"{_DELAY_S}s destroy_all() teardown instead of dispatching it to a background worker"
    )
    assert window.sandbox_manager is delayed_manager, (
        "sandbox_manager was already rebuilt before _apply_sandbox_settings returned; the "
        "rebuild is running synchronously instead of waiting for teardown to complete"
    )
    assert status_updates == [], (
        "status_update fired before _apply_sandbox_settings returned; the GUI-thread method did "
        "not wait for the queued teardown-completion signal"
    )

    completed = _pump_until(qapp, lambda: bool(status_updates), timeout_s=_DELAY_S + 5.0)
    assert completed, "status_update was never emitted after the delayed teardown resolved"

    assert delayed_manager.destroy_all_calls == 1
    assert window.sandbox_manager is not delayed_manager
    assert isinstance(window.sandbox_manager, SandboxManager)
    assert window.sandbox_manager._default_config.timeout_seconds == 321
    assert status_updates == ["Sandbox settings applied"]


def test_h1_apply_sandbox_settings_never_calls_blocking_run_bridge_coroutine(
    patched_window: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_apply_sandbox_settings`` must never call the blocking ``run_bridge_coroutine``.

    Direct regression guard for the exact offending call site: pre-fix,
    ``_apply_sandbox_settings`` called
    ``run_bridge_coroutine(self.sandbox_manager.destroy_all())``
    synchronously. This poisons the module-level ``run_bridge_coroutine``
    import so any reintroduction of that blocking call raises immediately
    instead of silently freezing the GUI thread.

    Args:
        patched_window: A constructed MainWindow with SandboxManager stubbed.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = patched_window
    window.sandbox_manager = SandboxManager()

    def _poison_blocking_call(*_args: object, **_kwargs: object) -> None:
        msg = "_apply_sandbox_settings must not call the blocking run_bridge_coroutine"
        raise AssertionError(msg)

    monkeypatch.setattr("intellicrack.ui.app.run_bridge_coroutine", _poison_blocking_call)

    window._apply_sandbox_settings(
        {"timeout_seconds": 10, "memory_limit_mb": 128, "network_enabled": False},
    )


# ---------------------------------------------------------------------------
# M1 -- process-attach memory-region listing must run off the GUI thread.
# ---------------------------------------------------------------------------


def _make_fake_hexcore(
    delay_s: float,
    regions: list[tuple[int, int, int, int]] | None = None,
    error: Exception | None = None,
) -> tuple[object, list[int]]:
    """Build a stand-in ``intellicrack_hexcore`` module for ``_on_process_attached``.

    Args:
        delay_s: Number of seconds ``list_process_memory_regions`` sleeps
            for before recording its call, standing in for a native FFI
            walk of a large virtual address space.
        regions: Regions to return on success. Defaults to an empty list.
        error: When provided, raised (after the delay) instead of returning
            ``regions``.

    Returns:
        tuple[object, list[int]]: The fake ``_hexcore``-shaped module object,
        and the list of ``pid`` values it will append to as calls occur.
    """
    calls: list[int] = []
    resolved_regions = regions or []

    class _FakeHexDocument:
        """Stand-in for ``intellicrack_hexcore.HexDocument``."""

        @staticmethod
        def list_process_memory_regions(pid: int) -> list[tuple[int, int, int, int]]:
            """Sleep, record the call, then return regions or raise.

            Args:
                pid: Process ID requested by the caller.

            Returns:
                list[tuple[int, int, int, int]]: The configured regions.

            Raises:
                error: The configured exception, when one was provided,
                    re-raised as-is after the artificial delay.
            """
            time.sleep(delay_s)
            calls.append(pid)
            if error is not None:
                raise error
            return list(resolved_regions)

    class _FakeHexcoreModule:
        """Stand-in for the top-level ``intellicrack_hexcore`` module."""

        HexDocument = _FakeHexDocument

    return _FakeHexcoreModule(), calls


def test_m1_on_process_attached_lists_regions_off_gui_thread(
    qapp: QApplication,
    patched_window: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_process_attached`` must return before native enumeration completes.

    Pre-fix, ``_on_process_attached`` called
    ``_hexcore.HexDocument.list_process_memory_regions(pid)`` directly
    inline, blocking the whole method (and the Qt event loop) for the full
    duration of the native call. Post-fix, the call is dispatched to a
    background ``GenericCallableWorker`` and the result is delivered to
    ``_on_process_regions_listed`` via a queued signal.

    Args:
        qapp: The shared offscreen QApplication fixture.
        patched_window: A constructed MainWindow with SandboxManager stubbed.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = patched_window
    regions = [(0x0000000140000000, 0x1000, 0x20, 0x1000)]
    fake_hexcore, calls = _make_fake_hexcore(_DELAY_S, regions=regions)
    monkeypatch.setattr("intellicrack.ui.app._hexcore", fake_hexcore)

    listed_recorder = CallRecorder()
    monkeypatch.setattr(window, "_on_process_regions_listed", listed_recorder)

    pid = 9999
    start = time.monotonic()
    window._on_process_attached(pid)
    elapsed = time.monotonic() - start

    assert elapsed < _RETURN_BUDGET_S, (
        f"_on_process_attached blocked the calling thread for {elapsed:.3f}s waiting on a "
        f"{_DELAY_S}s native enumeration call instead of dispatching it to a background worker"
    )
    assert calls == [], (
        "the native enumeration call already ran before _on_process_attached returned; it is "
        "still executing synchronously on the GUI thread"
    )

    completed = _pump_until(qapp, lambda: listed_recorder.times_called > 0, timeout_s=_DELAY_S + 5.0)
    assert completed, "region listing never resolved after the delayed native call completed"
    assert calls == [pid]
    args, kwargs = listed_recorder.calls[0]
    assert args == (pid, regions)
    assert kwargs == {}


def test_m1_on_process_attached_native_error_surfaced_asynchronously(
    qapp: QApplication,
    patched_window: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failing native enumeration must warn only after the delayed call actually fails.

    Pre-fix, the inline ``try/except`` around the blocking native call meant
    ``QMessageBox.warning`` was already invoked, on the calling thread, by
    the time ``_on_process_attached`` returned -- after blocking for the
    full artificial delay. Post-fix, ``GenericCallableWorker`` delivers the
    exception via the queued ``call_error`` signal to
    ``_on_process_regions_failed``, so the handler returns immediately and
    no failure has been recorded until the Qt event loop is pumped and the
    background call has had time to fail.

    Args:
        qapp: The shared offscreen QApplication fixture.
        patched_window: A constructed MainWindow with SandboxManager stubbed.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = patched_window
    boom = RuntimeError("region enumeration failed")
    fake_hexcore, calls = _make_fake_hexcore(_DELAY_S, error=boom)
    monkeypatch.setattr("intellicrack.ui.app._hexcore", fake_hexcore)

    failed_recorder = CallRecorder()
    monkeypatch.setattr(window, "_on_process_regions_failed", failed_recorder)

    pid = 8888
    start = time.monotonic()
    window._on_process_attached(pid)
    elapsed = time.monotonic() - start

    assert elapsed < _RETURN_BUDGET_S, (
        f"_on_process_attached blocked the calling thread for {elapsed:.3f}s waiting on a "
        f"{_DELAY_S}s failing native call instead of dispatching it to a background worker"
    )
    assert failed_recorder.times_called == 0, (
        "the failure handler already ran before _on_process_attached returned; the exception is "
        "being surfaced synchronously on the calling thread"
    )

    completed = _pump_until(qapp, lambda: failed_recorder.times_called > 0, timeout_s=_DELAY_S + 5.0)
    assert completed, "the failure handler was never invoked after the delayed native call failed"
    assert calls == [pid]
    args, kwargs = failed_recorder.calls[0]
    assert args[0] == pid
    assert isinstance(args[1], RuntimeError)
    assert str(args[1]) == "region enumeration failed"
    assert kwargs == {}


# ---------------------------------------------------------------------------
# M38 -- the window's minimum floor must cover the splitter panes' minimums.
# ---------------------------------------------------------------------------


def test_m38_narrow_screen_window_not_narrower_than_splitter_minimum(
    patched_window: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On a screen between 800px and the panes' true minimum, the window must not shrink below it.

    Pre-fix, ``min_w`` was a fixed 800px even though the chat panel
    (``setMinimumWidth(400)``) and tool panel (``setMinimumWidth(500)``)
    inside a ``childrenCollapsible(False)`` splitter give the central layout
    an effective 900px minimum. On an available width of 850px, pre-fix
    ``target_w = max(800, min(1400, 850-6)) = 844``, narrower than the
    panes can honour. Post-fix the floor equals the panes' combined
    minimum, so ``target_w`` never lands below it.

    Args:
        patched_window: A constructed MainWindow with SandboxManager stubbed.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = patched_window
    combined_pane_minimum = window._chat_panel.minimumWidth() + window.tool_panel.minimumWidth()
    assert combined_pane_minimum == 900, "test premise: chat(400) + tool(500) panel minimums"

    narrow_avail_w = combined_pane_minimum - 50
    monkeypatch.setattr(
        MainWindow,
        "_resolve_screen_geometry",
        staticmethod(lambda: (0, 0, narrow_avail_w, 700)),
    )

    window._apply_smart_window_size()

    assert window.width() >= combined_pane_minimum, (
        f"window width {window.width()}px is narrower than the splitter panes' combined "
        f"minimum width ({combined_pane_minimum}px); the chat/tool panels cannot both honour "
        "their setMinimumWidth() constraints inside a childrenCollapsible(False) splitter"
    )


@pytest.mark.parametrize("narrow_avail_w", [810, 850, 899])
def test_m38_every_width_in_the_pre_fix_gap_still_floors_correctly(
    patched_window: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
    narrow_avail_w: int,
) -> None:
    """Every available width in the old 800-900px gap must still floor at the panes' minimum.

    Pre-fix, any available width between the old 800px floor and the panes'
    real 900px minimum passed straight through
    ``max(800, min(1400, avail_w - 6))`` unmodified, producing a window
    narrower than its own splitter contents require. This sweeps the whole
    previously-broken range.

    Args:
        patched_window: A constructed MainWindow with SandboxManager stubbed.
        monkeypatch: Pytest monkeypatch fixture.
        narrow_avail_w: Available screen width, in pixels, under test.
    """
    window = patched_window
    combined_pane_minimum = window._chat_panel.minimumWidth() + window.tool_panel.minimumWidth()
    monkeypatch.setattr(
        MainWindow,
        "_resolve_screen_geometry",
        staticmethod(lambda: (0, 0, narrow_avail_w, 700)),
    )

    window._apply_smart_window_size()

    assert window.width() >= combined_pane_minimum, (
        f"avail_w={narrow_avail_w}: window width {window.width()}px is narrower than the "
        f"splitter panes' combined minimum width ({combined_pane_minimum}px)"
    )


def test_m38_wide_screen_still_caps_at_the_documented_maximum(
    patched_window: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Raising the floor must not disturb the documented 1400x900 cap on large screens.

    Args:
        patched_window: A constructed MainWindow with SandboxManager stubbed.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = patched_window
    monkeypatch.setattr(
        MainWindow,
        "_resolve_screen_geometry",
        staticmethod(lambda: (0, 0, 2000, 1200)),
    )

    window._apply_smart_window_size()

    assert window.width() == 1400
    assert window.height() == 900
