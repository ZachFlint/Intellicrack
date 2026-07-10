# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""GUI audit regression gates for ``intellicrack.ui.panels.hex_editor.transforms``.

Covers the 2026-07-02 audit finding for ``transforms.py``:

* H8 -- ``TransformsMixin._on_apply_arithmetic`` previously dispatched both
  bridge calls (``select_range`` and ``apply_arithmetic_to_selection``)
  through the *blocking* ``run_bridge_coroutine()``, which calls
  ``future.result(timeout=None)`` on the calling (Qt main) thread and
  therefore freezes the GUI event loop for the duration of the native
  hexcore transform. The fix wraps both bridge calls in a single coroutine
  that awaits them in sequence and dispatches that coroutine exactly once
  through the non-blocking ``run_bridge_coroutine_logged``, refreshing the
  widget from the coroutine's success callback and warning the user from
  its error callback.

Three independent gates prove the fix, all driving the *real*
``run_bridge_coroutine_logged``/``BridgeCallWorker`` machinery (no mocking of
the dispatcher itself) with a bridge stand-in whose coroutines sleep for a
measurable duration:

1. :class:`TestH8NonBlockingDispatch` proves the calling thread returns
   almost immediately and that the two bridge calls execute strictly in
   sequence (the second only starts once the first coroutine step
   completes), then confirms the widget is refreshed once the background
   chain finishes.
2. :class:`TestH8ErrorSurfacesWarning` proves a failure at either step
   returns control to the caller almost immediately (rather than blocking
   for the failing coroutine's full latency) and only surfaces its warning
   dialog later, from the callback chain, without a partial or duplicate
   widget refresh.
3. :class:`TestH8SingleDispatchWiring` patches only the dispatcher entry
   point to record the exact call-site wiring (call count, event name, and
   structured context) without executing the coroutine, proving the call
   site issues exactly one non-blocking dispatch instead of two blocking
   calls.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QComboBox, QLineEdit, QMessageBox, QSpinBox

from intellicrack.ui.panels.hex_editor import transforms as transforms_module
from intellicrack.ui.panels.hex_editor.transforms import TransformsMixin


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    import structlog
    from PyQt6.QtWidgets import QApplication, QWidget


_SELECT_START: int = 4
_SELECT_END: int = 19
_ARITH_KEY_HEX: str = "AA"
_ARITH_COUNT: int = 3
_MAX_WAIT_S: float = 5.0
_POLL_INTERVAL_S: float = 0.01
_NON_BLOCKING_RETURN_CEILING_S: float = 0.2
_BRIDGE_STEP_DELAY_S: float = 0.35


class _StubHexWidget:
    """Minimal hex-widget stand-in that counts viewport refreshes via ``update_count``."""

    def __init__(self) -> None:
        """Initialise the stub with zero observed viewport updates."""
        self.update_count: int = 0

    def _update_viewport(self) -> None:
        """Record a viewport refresh request."""
        self.update_count += 1


class _SlowArithmeticBridge:
    """Real async bridge stand-in whose coroutines sleep for a fixed delay.

    Both methods are genuine coroutine functions (not mocks) so they must be
    driven through an actual event loop -- either by blocking
    ``future.result()`` on the caller's thread (pre-fix behaviour) or by the
    persistent background loop thread used by ``run_bridge_coroutine_logged``
    (post-fix behaviour). Calls are recorded on ``select_calls`` and
    ``apply_calls`` respectively.
    """

    def __init__(self, step_delay_s: float, *, fail_at: str | None = None) -> None:
        """Initialise the bridge with a per-call sleep duration.

        Args:
            step_delay_s: Seconds each coroutine sleeps before returning,
                simulating the native hexcore transform's real latency.
            fail_at: Method name (``"select_range"`` or
                ``"apply_arithmetic_to_selection"``) that should raise after
                its delay, or ``None`` for an always-successful bridge.
        """
        self._step_delay_s: float = step_delay_s
        self._fail_at: str | None = fail_at
        self.select_calls: list[tuple[int, int]] = []
        self.apply_calls: list[tuple[str, str, int]] = []

    async def select_range(self, start: int, end: int) -> None:
        """Record the selection range and sleep to simulate bridge latency.

        Args:
            start: Selection start offset.
            end: Selection end offset (inclusive).

        Raises:
            RuntimeError: If constructed with ``fail_at="select_range"``.
        """
        self.select_calls.append((start, end))
        await asyncio.sleep(self._step_delay_s)
        if self._fail_at == "select_range":
            msg = "bridge selection failed"
            raise RuntimeError(msg)

    async def apply_arithmetic_to_selection(self, op: str, *, key_hex: str, count: int) -> dict[str, Any]:
        """Record the arithmetic call, sleep, and return a stub result.

        Args:
            op: Short arithmetic operation code (e.g. ``"xor"``).
            key_hex: Hex-encoded key or mask.
            count: Shift/rotate count.

        Returns:
            dict[str, Any]: A stub success payload.

        Raises:
            RuntimeError: If constructed with ``fail_at="apply_arithmetic_to_selection"``.
        """
        self.apply_calls.append((op, key_hex, count))
        await asyncio.sleep(self._step_delay_s)
        if self._fail_at == "apply_arithmetic_to_selection":
            msg = "native transform failed"
            raise RuntimeError(msg)
        return {"op": op}


class _ArithmeticHarness(TransformsMixin):
    """Concrete, non-Qt-widget host for :class:`TransformsMixin` arithmetic dispatch.

    Provides exactly the attributes ``_on_apply_arithmetic`` and
    ``_refresh_widget`` read, without constructing the full
    ``HexEditorPanel`` (which pulls in dozens of unrelated mixins).
    ``_hex_widget`` is a :class:`_StubHexWidget` used to observe post-apply
    viewport refreshes, and ``_on_data_changed`` is overridden locally to
    count invocations instead of touching panel-only widgets.
    """

    def __init__(
        self,
        bridge: object,
        *,
        sel_start: int = _SELECT_START,
        sel_end: int = _SELECT_END,
        op_label: str = "XOR",
        key_hex: str = _ARITH_KEY_HEX,
        count: int = _ARITH_COUNT,
    ) -> None:
        """Construct the harness wired to the given bridge stand-in.

        Args:
            bridge: Object exposing async ``select_range`` and
                ``apply_arithmetic_to_selection`` methods.
            sel_start: Selection start offset to publish on the harness.
            sel_end: Selection end offset to publish on the harness.
            op_label: Human-readable label selected in the operation combo.
            key_hex: Hex key/mask text placed in the key field.
            count: Shift/rotate count placed in the count spinbox.
        """
        self.document: Any = object()
        self._hex_widget: _StubHexWidget = _StubHexWidget()
        self._bridge: Any = bridge
        self._selection_start: int = sel_start
        self._selection_end: int = sel_end
        self.data_changed_count: int = 0

        self._arith_op_combo: QComboBox = QComboBox()
        self._arith_op_combo.addItem(op_label)
        self._arith_key_edit: QLineEdit = QLineEdit()
        self._arith_key_edit.setText(key_hex)
        self._arith_count_spin: QSpinBox = QSpinBox()
        self._arith_count_spin.setRange(1, 64)
        self._arith_count_spin.setValue(count)

    def _on_data_changed(self) -> None:
        """Record that ``_refresh_widget`` reached its data-changed hook."""
        self.data_changed_count += 1


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], *, timeout_s: float = _MAX_WAIT_S) -> bool:
    """Pump the Qt event loop until ``predicate()`` is true or the timeout elapses.

    Args:
        qapp: The shared offscreen ``QApplication``.
        predicate: Zero-argument callable polled after each event-loop pump.
        timeout_s: Maximum number of seconds to wait.

    Returns:
        bool: ``True`` if ``predicate()`` became true before the timeout,
            ``False`` otherwise.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(_POLL_INTERVAL_S)
    return bool(predicate())


@pytest.mark.usefixtures("qapp")
class TestH8NonBlockingDispatch:
    """H8: arithmetic dispatch must not block the calling thread on the bridge."""

    @staticmethod
    def test_apply_arithmetic_returns_before_slow_bridge_completes(qapp: QApplication) -> None:
        """``_on_apply_arithmetic`` must return long before the bridge chain finishes.

        Regression: pre-fix, ``_on_apply_arithmetic`` called the blocking
        ``run_bridge_coroutine()`` twice in sequence on the calling thread,
        so the call would not return until both
        ``2 * _BRIDGE_STEP_DELAY_S`` seconds of native-transform latency had
        elapsed. Post-fix, the single chained coroutine is dispatched
        through ``run_bridge_coroutine_logged``, which starts a background
        ``BridgeCallWorker`` QThread and returns immediately; the method
        call itself must complete in a small fraction of the bridge's
        simulated latency, and the effects only appear once the event loop
        is pumped.

        Args:
            qapp: The shared offscreen ``QApplication`` fixture.
        """
        bridge = _SlowArithmeticBridge(step_delay_s=_BRIDGE_STEP_DELAY_S)
        harness = _ArithmeticHarness(bridge)

        started = time.monotonic()
        harness._on_apply_arithmetic()
        elapsed = time.monotonic() - started

        assert elapsed < _NON_BLOCKING_RETURN_CEILING_S, (
            f"_on_apply_arithmetic blocked the calling thread for {elapsed:.3f}s "
            f"(ceiling {_NON_BLOCKING_RETURN_CEILING_S}s); it must dispatch via the "
            "non-blocking run_bridge_coroutine_logged rather than await the blocking future in-thread"
        )
        assert harness._hex_widget.update_count == 0, "widget must not be refreshed before the bridge chain completes"

        completed = _pump_until(qapp, lambda: harness._hex_widget.update_count == 1)
        assert completed, "the arithmetic chain never completed on the background loop"
        assert harness.data_changed_count == 1
        assert bridge.select_calls == [(_SELECT_START, _SELECT_END - 1)]
        assert bridge.apply_calls == [("xor", _ARITH_KEY_HEX, _ARITH_COUNT)]

    @staticmethod
    def test_select_range_completes_before_apply_arithmetic_starts(qapp: QApplication) -> None:
        """``apply_arithmetic_to_selection`` must not start until ``select_range`` finishes.

        Both bridge calls are awaited in sequence inside one coroutine
        (``await bridge.select_range(...)`` then
        ``await bridge.apply_arithmetic_to_selection(...)``). This proves
        that ordering: while ``select_range`` is still asleep,
        ``apply_calls`` must be empty.

        Args:
            qapp: The shared offscreen ``QApplication`` fixture.
        """
        bridge = _SlowArithmeticBridge(step_delay_s=_BRIDGE_STEP_DELAY_S)
        harness = _ArithmeticHarness(bridge)

        harness._on_apply_arithmetic()

        select_started = _pump_until(qapp, lambda: len(bridge.select_calls) == 1, timeout_s=1.0)
        assert select_started, "select_range was never dispatched"
        assert not bridge.apply_calls, "apply_arithmetic_to_selection must not start before select_range's await completes"

        apply_started = _pump_until(qapp, lambda: len(bridge.apply_calls) == 1)
        assert apply_started, "apply_arithmetic_to_selection was never dispatched after select_range completed"
        assert bridge.apply_calls == [("xor", _ARITH_KEY_HEX, _ARITH_COUNT)]

        completed = _pump_until(qapp, lambda: harness._hex_widget.update_count == 1)
        assert completed, "the arithmetic chain never refreshed the widget"
        assert harness.data_changed_count == 1


@pytest.mark.usefixtures("qapp")
class TestH8ErrorSurfacesWarning:
    """H8: a bridge failure at either chain step must warn without a partial refresh."""

    @staticmethod
    def test_select_range_failure_warns_without_dispatching_apply(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """A ``select_range`` failure must warn the user via the async callback, not inline.

        Regression: pre-fix, both bridge calls ran through the blocking
        ``run_bridge_coroutine()`` on the calling thread, so
        ``_on_apply_arithmetic`` would not return until the failing
        ``select_range`` coroutine's full ``_BRIDGE_STEP_DELAY_S`` sleep had
        elapsed *and* the ``except`` block had synchronously invoked
        ``QMessageBox.warning`` -- all before the call returned control to the
        caller. Post-fix, the coroutine is dispatched via the non-blocking
        ``run_bridge_coroutine_logged`` and the warning is only raised later
        from the background chain's error callback once the event loop is
        pumped, so the call itself returns almost immediately with no warning
        recorded yet. Asserting both the near-instant return *and* that no
        warning exists synchronously distinguishes the two implementations;
        the pre-fix code fails the elapsed-time ceiling and would already have
        one warning recorded by the time the method returns.

        Args:
            qapp: The shared offscreen ``QApplication`` fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        warnings: list[tuple[object, str, str]] = []

        def _record_warning(parent: object, title: str, text: str, *_args: object, **_kwargs: object) -> None:
            warnings.append((parent, title, text))

        monkeypatch.setattr(QMessageBox, "warning", _record_warning)
        bridge = _SlowArithmeticBridge(step_delay_s=_BRIDGE_STEP_DELAY_S, fail_at="select_range")
        harness = _ArithmeticHarness(bridge)

        started = time.monotonic()
        harness._on_apply_arithmetic()
        elapsed = time.monotonic() - started

        assert elapsed < _NON_BLOCKING_RETURN_CEILING_S, (
            f"_on_apply_arithmetic blocked the calling thread for {elapsed:.3f}s while select_range "
            f"failed (ceiling {_NON_BLOCKING_RETURN_CEILING_S}s); the failing coroutine must run on the "
            "background loop, not be awaited synchronously via the blocking run_bridge_coroutine"
        )
        assert not warnings, "the warning must be raised later by the async error callback, not synchronously inline"

        warned = _pump_until(qapp, lambda: bool(warnings))
        assert warned, "select_range failure never surfaced a warning dialog"
        assert "bridge selection failed" in warnings[0][2]
        assert not bridge.apply_calls, "apply_arithmetic_to_selection must not be dispatched after select_range failed"
        assert harness._hex_widget.update_count == 0, "a failed select_range must not refresh the widget"
        assert harness.data_changed_count == 0

    @staticmethod
    def test_apply_arithmetic_failure_warns_and_skips_refresh(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """An ``apply_arithmetic_to_selection`` failure must warn via the async callback, not inline.

        Regression: pre-fix, ``select_range`` would complete (blocking for
        ``_BRIDGE_STEP_DELAY_S``) and then ``apply_arithmetic_to_selection``
        would also block for a further ``_BRIDGE_STEP_DELAY_S`` before raising,
        all synchronously on the calling thread, with ``QMessageBox.warning``
        invoked before ``_on_apply_arithmetic`` returned. Post-fix, the whole
        chained coroutine runs on the background loop and the warning is only
        raised from the error callback once the event loop is pumped, so the
        call returns almost immediately with no warning recorded yet. This
        combination of a sub-ceiling elapsed time *and* an empty ``warnings``
        list immediately after the call fails against the pre-fix blocking
        implementation, which would already have recorded the warning and
        consumed roughly ``2 * _BRIDGE_STEP_DELAY_S`` seconds by that point.

        Args:
            qapp: The shared offscreen ``QApplication`` fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        warnings: list[tuple[object, str, str]] = []

        def _record_warning(parent: object, title: str, text: str, *_args: object, **_kwargs: object) -> None:
            warnings.append((parent, title, text))

        monkeypatch.setattr(QMessageBox, "warning", _record_warning)
        bridge = _SlowArithmeticBridge(step_delay_s=_BRIDGE_STEP_DELAY_S, fail_at="apply_arithmetic_to_selection")
        harness = _ArithmeticHarness(bridge)

        started = time.monotonic()
        harness._on_apply_arithmetic()
        elapsed = time.monotonic() - started

        assert elapsed < _NON_BLOCKING_RETURN_CEILING_S, (
            f"_on_apply_arithmetic blocked the calling thread for {elapsed:.3f}s while apply_arithmetic_to_selection "
            f"failed (ceiling {_NON_BLOCKING_RETURN_CEILING_S}s); the chained coroutine must run on the "
            "background loop, not be awaited synchronously via two blocking run_bridge_coroutine calls"
        )
        assert not warnings, "the warning must be raised later by the async error callback, not synchronously inline"

        warned = _pump_until(qapp, lambda: bool(warnings))
        assert warned, "apply_arithmetic_to_selection failure never surfaced a warning dialog"
        assert "native transform failed" in warnings[0][2]
        assert bridge.select_calls == [(_SELECT_START, _SELECT_END - 1)]
        assert bridge.apply_calls == [("xor", _ARITH_KEY_HEX, _ARITH_COUNT)]
        assert harness._hex_widget.update_count == 0, "a failed apply must not refresh the widget"
        assert harness.data_changed_count == 0


class _DispatchCall:
    """One captured invocation of ``run_bridge_coroutine_logged``."""

    def __init__(
        self,
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None,
        on_error: Callable[[object], None] | None,
        event: str,
        context: dict[str, object],
    ) -> None:
        """Store one captured dispatcher invocation.

        Args:
            coro: The coroutine object the call site handed the dispatcher.
            on_success: Success callback the call site registered.
            on_error: Error callback the call site registered.
            event: Structured-log event name for this dispatch.
            context: Remaining structured-log keyword context.
        """
        self.coro: Coroutine[object, object, object] = coro
        self.on_success: Callable[[object], None] | None = on_success
        self.on_error: Callable[[object], None] | None = on_error
        self.event: str = event
        self.context: dict[str, object] = context


@pytest.fixture
def dispatch_spy(monkeypatch: pytest.MonkeyPatch) -> list[_DispatchCall]:
    """Replace ``run_bridge_coroutine_logged`` with a recording, non-executing spy.

    The spy never awaits the coroutine it is handed (mirroring the real
    dispatcher's non-blocking contract at the call boundary) and closes it
    immediately to avoid an "unawaited coroutine" warning. Because the
    pre-fix call site imports ``run_bridge_coroutine`` (not
    ``run_bridge_coroutine_logged``), patching this name on the module does
    not even exist pre-fix, so this fixture itself fails against the
    pre-fix source.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        list[_DispatchCall]: Mutable list appended with one entry per
            ``run_bridge_coroutine_logged`` invocation, in call order.
    """
    calls: list[_DispatchCall] = []

    def _spy(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: QWidget | None = None,
        *,
        event: str,
        logger: structlog.stdlib.BoundLogger | None = None,
        level: str = "debug",
        **context: object,
    ) -> None:
        del parent, logger, level
        calls.append(_DispatchCall(coro, on_success, on_error, event, context))
        coro.close()

    monkeypatch.setattr(transforms_module, "run_bridge_coroutine_logged", _spy)
    return calls


class TestH8SingleDispatchWiring:
    """H8: the call site must issue exactly one non-blocking dispatch."""

    @staticmethod
    def test_exactly_one_dispatch_with_expected_event_and_context(dispatch_spy: list[_DispatchCall]) -> None:
        """The handler must issue exactly one ``run_bridge_coroutine_logged`` call.

        Pre-fix, the handler called the blocking ``run_bridge_coroutine()``
        twice and never referenced ``run_bridge_coroutine_logged`` at all, so
        this dispatch would never fire and ``dispatch_spy`` would stay empty
        (the fixture itself errors first, since the attribute does not exist
        on the pre-fix module). Post-fix, exactly one dispatch carries both
        chained bridge calls.

        Args:
            dispatch_spy: Fixture capturing every ``run_bridge_coroutine_logged`` call.
        """
        bridge = _SlowArithmeticBridge(step_delay_s=0.0)
        harness = _ArithmeticHarness(bridge)

        harness._on_apply_arithmetic()

        assert len(dispatch_spy) == 1, "the handler must issue exactly one non-blocking dispatch, not per-call blocking calls"
        call = dispatch_spy[0]
        assert call.event == "hex_editor_apply_arithmetic"
        assert call.context.get("operation") == "xor"
        assert call.context.get("selection_start") == _SELECT_START
        assert call.context.get("selection_end") == _SELECT_END - 1
        assert call.on_success is not None
        assert call.on_error is not None
        assert harness._hex_widget.update_count == 0, "the widget must not refresh before the dispatched coroutine runs"
        assert bridge.select_calls == [], "the coroutine must not run synchronously at dispatch time"
        assert bridge.apply_calls == []
