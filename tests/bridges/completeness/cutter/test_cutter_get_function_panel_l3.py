# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness gate tests for finding T2-8c (Cutter ``get_function`` GUI reachability).

``CutterBridge.get_function`` (single-function detail: real parameter,
local-variable, and calling-convention extraction via rizin's ``afij``/
``afvj``) was fully implemented and registered as ``cutter.get_function``,
but no control anywhere in ``cutter_panel.py``/``cutter_tabs.py``/
``cutter_static_extra_tab.py`` ever invoked it. The fix adds
``FunctionDetailsTab`` (``cutter_static_extra_tab.py``) -- an address-driven
sub-tab of ``StaticAnalysisExtrasTab`` that calls ``get_function`` directly,
and is also reached automatically through ``StaticAnalysisExtrasTab.show_function``
(the same hook the pre-existing ``BasicBlocksTab``/``FunctionDisasmTab`` use),
which ``CutterPanel._on_function_clicked`` already calls for every function
selected in the functions sidebar.

Every test drives a real ``CutterBridge`` (backed by a recording r2pipe
double, the genuine external boundary a live rizin child process would
occupy) and a real Qt ``FunctionDetailsTab``/``StaticAnalysisExtrasTab``, so
the production bridge parsing and GUI handler code both run for real.
"""

from __future__ import annotations

import asyncio
import sys
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Final, cast

from PyQt6 import sip
from PyQt6.QtWidgets import QLabel, QLineEdit, QTreeWidget

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.ui.panels.async_bridge import drain_bridge_workers
from intellicrack.ui.panels.cutter_static_extra_tab import FunctionDetailsTab, StaticAnalysisExtrasTab
from tests.bridges.completeness.cutter.conftest import CommandRecorder, as_r2pipe, priv


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


_MAX_WAIT_S: Final[float] = 5.0
_POLL_INTERVAL_S: Final[float] = 0.02
_CALLBACK_SETTLE_S: Final[float] = 0.5

_AFIJ_MAIN: Final[str] = '[{"name":"main","offset":4198400,"size":64,"cc":"amd64","type":"int","bits":64}]'
_AFVJ_MAIN: Final[str] = (
    '[{"sp":[],'
    '"bp":[{"name":"local_8h","kind":"var","type":"int64_t","ref":{"base":"rbp","offset":-8}}],'
    '"reg":[{"name":"argc","kind":"arg","type":"int32_t","ref":{"base":"rdi","offset":0}}]}]'
)


def _pump_until(app: QApplication, predicate: object, *, timeout_s: float = _MAX_WAIT_S) -> bool:
    """Pump the Qt event loop until ``predicate()`` is truthy or the timeout elapses.

    Args:
        app: The live ``QApplication`` instance used to process pending events.
        predicate: Zero-argument callable checked after each pump iteration.
        timeout_s: Maximum time in seconds to keep pumping.

    Returns:
        bool: ``True`` if ``predicate()`` became truthy before the timeout,
        ``False`` otherwise.
    """
    assert callable(predicate)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(_POLL_INTERVAL_S)
    return bool(predicate())


def _pump_capturing_exceptions(app: QApplication, duration_s: float = _CALLBACK_SETTLE_S) -> list[BaseException]:
    """Pump the Qt event loop for a fixed duration, capturing anything routed to ``sys.excepthook``.

    A ``run_bridge_coroutine_logged`` success/error callback is delivered by
    Qt as a queued cross-thread signal; PyQt6 routes an exception raised
    while dispatching one to ``sys.excepthook`` rather than back to
    whichever caller pumped the loop, so a crashing late callback would
    otherwise vanish silently instead of failing the test that provoked it.

    Args:
        app: The live ``QApplication`` instance used to process pending events.
        duration_s: How long, in seconds, to keep pumping.

    Returns:
        list[BaseException]: Every exception ``sys.excepthook`` observed
        while the loop was pumped, in the order received.
    """
    captured: list[BaseException] = []
    original_hook = sys.excepthook

    def _capture(exc_type: type[BaseException], exc_value: BaseException, exc_tb: object) -> None:
        """Record an exception routed to ``sys.excepthook`` during the pump.

        Args:
            exc_type: The exception's type (unused; ``exc_value`` carries the same information).
            exc_value: The exception instance raised while dispatching a queued slot.
            exc_tb: The exception's traceback (unused).
        """
        del exc_type, exc_tb
        captured.append(exc_value)

    sys.excepthook = _capture
    try:
        deadline = time.monotonic() + duration_s
        while time.monotonic() < deadline:
            app.processEvents()
            time.sleep(_POLL_INTERVAL_S)
    finally:
        sys.excepthook = original_hook
    return captured


def _mark_analyzed(bridge: CutterBridge, recorder: CommandRecorder) -> None:
    """Run the real ``analyze()`` coroutine so ``get_function``'s analysis guard passes.

    Uses the bridge's own public ``analyze()`` method (rather than poking a
    private field) so the bridge reaches the analyzed state exactly as
    production code does. The resulting ``aaa`` command is discarded from
    ``recorder.commands`` afterward so later assertions about ``afij``/
    ``afvj`` are not confused by it.

    Args:
        bridge: The bridge to mark analyzed.
        recorder: The command recorder backing ``bridge.r2``, cleared after
            the analysis command completes.
    """
    asyncio.run(bridge.analyze())
    recorder.commands.clear()


class TestFunctionDetailsTabL3:
    """L3 gate: ``FunctionDetailsTab`` must invoke the real ``get_function`` bridge method."""

    @staticmethod
    def test_fetch_button_calls_afij_afvj_and_renders_params_locals(qapp: QApplication) -> None:
        """Clicking "Get Function Info" must issue ``afij``/``afvj`` and render the real params/locals/calling-convention.

        Falsifiable: if ``FunctionDetailsTab._on_fetch`` never called
        ``self._bridge.get_function(address)``, 'afij' and 'afvj' would
        never appear in the recorder and the summary label/tree would stay
        empty. Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.get_function(address), ...)``
        call in ``FunctionDetailsTab._on_fetch`` (``cutter_static_extra_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop while
                the real background bridge-call worker thread runs.
        """
        recorder = CommandRecorder({"afij": _AFIJ_MAIN, "afvj": _AFVJ_MAIN})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)
        _mark_analyzed(bridge, recorder)

        tab = FunctionDetailsTab()
        tab.refresh(bridge)
        addr_input = priv(tab, "_addr_input", QLineEdit)
        summary_label = priv(tab, "_summary_label", QLabel)
        tree = priv(tab, "_tree", QTreeWidget)
        addr_input.setText("0x401000")

        on_fetch = cast(Callable[[], None], getattr(tab, "_on_fetch"))
        on_fetch()

        assert _pump_until(qapp, lambda: tree.topLevelItemCount() > 0)
        assert "afij" in recorder.commands
        assert "afvj" in recorder.commands

        summary_text = summary_label.text()
        assert "main" in summary_text
        assert "0x401000" in summary_text
        assert "size=64" in summary_text
        assert "amd64" in summary_text
        assert "returns=int" in summary_text

        assert tree.topLevelItemCount() == 2
        params_node = tree.topLevelItem(0)
        locals_node = tree.topLevelItem(1)
        assert params_node is not None
        assert locals_node is not None
        assert params_node.text(0) == "Parameters (1)"
        assert locals_node.text(0) == "Local Variables (1)"

        param_row = params_node.child(0)
        assert param_row is not None
        assert param_row.text(0) == "argc"
        assert param_row.text(1) == "int32_t"
        assert param_row.text(2) == "4"
        assert param_row.text(3) == "rdi", "register-resident argument must show its register name as the location"

        local_row = locals_node.child(0)
        assert local_row is not None
        assert local_row.text(0) == "local_8h"
        assert local_row.text(1) == "int64_t"
        assert local_row.text(2) == "8"
        assert local_row.text(3) == "-0x8", "a negative rizin ref offset must render as a signed hex string, not '0x-8'"

    @staticmethod
    def test_no_function_at_address_shows_message_without_crashing(qapp: QApplication) -> None:
        """An address with no analyzed function must show a message and clear the tree, not raise.

        Falsifiable: if the ``FunctionInfo`` isinstance guard were removed
        from ``_apply_data``, an empty ``afij`` result (``get_function``
        returning ``None``) would raise ``AttributeError`` while trying to
        read ``result.name`` instead of showing the "not found" message.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"afij": "[]"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)
        _mark_analyzed(bridge, recorder)

        tab = FunctionDetailsTab()
        tab.refresh(bridge)
        addr_input = priv(tab, "_addr_input", QLineEdit)
        summary_label = priv(tab, "_summary_label", QLabel)
        addr_input.setText("0x999000")

        on_fetch = cast(Callable[[], None], getattr(tab, "_on_fetch"))
        on_fetch()

        assert _pump_until(qapp, lambda: "no function" in summary_label.text().lower())
        assert "no function" in summary_label.text().lower()

    @staticmethod
    def test_invalid_address_input_does_not_dispatch(qapp: QApplication) -> None:
        """An unparseable address must not reach the bridge and must report the input error.

        Args:
            qapp: Qt application fixture (unused directly but required so a
                QWidget can be constructed).
        """
        del qapp
        recorder = CommandRecorder({"afij": _AFIJ_MAIN, "afvj": _AFVJ_MAIN})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = FunctionDetailsTab()
        tab.refresh(bridge)
        addr_input = priv(tab, "_addr_input", QLineEdit)
        summary_label = priv(tab, "_summary_label", QLabel)
        addr_input.setText("not-an-address")

        on_fetch = cast(Callable[[], None], getattr(tab, "_on_fetch"))
        on_fetch()

        assert recorder.commands == [], "an invalid address must never reach the bridge"
        assert summary_label.text() == "Invalid address"


class TestFunctionDetailsReachableFromFunctionSelectionL3:
    """L3 gate: selecting a function must reach ``get_function`` through ``StaticAnalysisExtrasTab.show_function``.

    This is the exact reachability path ``CutterPanel._on_function_clicked``
    drives for every function clicked in the functions sidebar (it already
    calls ``self._static_extras_tab.show_function(address)`` for
    ``BasicBlocksTab``/``FunctionDisasmTab``); this gate proves
    ``get_function`` is now included in that same fan-out.
    """

    @staticmethod
    def test_construction_wires_function_details_tab(qapp: QApplication) -> None:
        """``StaticAnalysisExtrasTab`` must construct a real ``FunctionDetailsTab`` sub-tab.

        Falsifiable: if the ``self._function_details_tab = FunctionDetailsTab()``
        construction (or its ``addTab`` call) were removed from
        ``StaticAnalysisExtrasTab.__init__``, this attribute access would
        raise ``AttributeError``.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        del qapp
        composite = StaticAnalysisExtrasTab()
        details_tab = priv(composite, "_function_details_tab", FunctionDetailsTab)
        assert isinstance(details_tab, FunctionDetailsTab)

    @staticmethod
    def test_show_function_forwards_address_to_function_details_tab(qapp: QApplication) -> None:
        """``show_function`` must populate the details tab's address input and issue a real ``get_function`` query.

        Falsifiable: if ``show_function`` did not call
        ``self._function_details_tab.set_address(address)``, the address
        input would stay blank and 'afij' would never be recorded. Broken
        production line: the ``self._function_details_tab.set_address(address)``
        call in ``StaticAnalysisExtrasTab.show_function`` (``cutter_static_extra_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"afij": _AFIJ_MAIN, "afvj": _AFVJ_MAIN})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)
        _mark_analyzed(bridge, recorder)

        composite = StaticAnalysisExtrasTab()
        composite.refresh(bridge)

        composite.show_function(0x401000)

        details_tab = priv(composite, "_function_details_tab", FunctionDetailsTab)
        addr_input = priv(details_tab, "_addr_input", QLineEdit)
        assert addr_input.text() == "0x401000"

        assert _pump_until(qapp, lambda: "afij" in recorder.commands)
        assert "afij" in recorder.commands
        assert "afvj" in recorder.commands


class TestLateCallbackSurvivesDestroyedTab:
    """Regression gate: a bridge callback firing after its tab is destroyed must not crash the Qt event loop.

    ``FunctionDetailsTab._apply_data``/``_on_fetch_error`` run as the
    ``on_success``/``on_error`` callbacks of a ``run_bridge_coroutine_logged``
    dispatch. Destroying the tab's underlying C++ object while that call is
    still in flight reproduces the crash observed when ``StaticAnalysisExtrasTab``
    went out of scope with several sub-tab bridge calls still pending: a late
    callback touched a deleted ``QPushButton``/``QTreeWidget``/``QTableWidget``
    and raised ``RuntimeError: wrapped C/C++ object ... has been deleted``
    into the Qt event loop (surfacing as "CALL ERROR: Exceptions caught in
    Qt event loop") instead of returning harmlessly.

    Each gate drains the dispatched worker thread to a genuine stop with
    ``drain_bridge_workers`` *before* forcing the tab's underlying object to
    be deleted with ``PyQt6.sip.delete``. That ordering matters:
    ``run_bridge_coroutine_logged`` starts its worker with ``parent=self``,
    so the worker thread is a Qt child of the tab; destroying the tab while
    that thread were still genuinely running would abort the whole process
    with ``QThread: Destroyed while thread is still running`` instead of
    reproducing the callback race under test. Once the worker has already
    finished, its queued result/exception is waiting to be dispatched but
    has not been yet -- exactly the window in which the tab was destroyed
    in production.
    """

    @staticmethod
    def test_apply_data_survives_tab_destroyed_before_callback(qapp: QApplication) -> None:
        """A ``get_function`` result arriving after its tab is destroyed must not raise.

        Falsifiable: removing the ``_widget_is_alive`` guard from
        ``FunctionDetailsTab._apply_data`` (``cutter_static_extra_tab.py``)
        makes this callback run ``self._fetch_btn.setEnabled(True)`` against
        the deleted tab, raising ``RuntimeError: wrapped C/C++ object of
        type QPushButton has been deleted`` into the Qt event loop and
        failing the final assertion.

        Args:
            qapp: Qt application fixture used to pump the event loop and
                deliver the queued callback after the tab is destroyed.
        """
        recorder = CommandRecorder({"afij": _AFIJ_MAIN, "afvj": _AFVJ_MAIN})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)
        _mark_analyzed(bridge, recorder)

        tab = FunctionDetailsTab()
        tab.refresh(bridge)
        addr_input = priv(tab, "_addr_input", QLineEdit)
        addr_input.setText("0x401000")

        on_fetch = cast(Callable[[], None], getattr(tab, "_on_fetch"))
        on_fetch()
        _ = drain_bridge_workers()
        sip.delete(tab)

        captured = _pump_capturing_exceptions(qapp)

        assert "afij" in recorder.commands, "the bridge call never completed; the test premise was not established"
        assert "afvj" in recorder.commands, "the bridge call never completed; the test premise was not established"
        assert not captured, f"a late get_function result crashed the Qt event loop after its tab was destroyed: {captured!r}"

    @staticmethod
    def test_fetch_error_survives_tab_destroyed_before_callback(qapp: QApplication) -> None:
        """A ``get_function`` failure arriving after its tab is destroyed must not raise.

        Uses an unparseable ``afij`` response so the bridge call fails and
        resolves through ``on_error`` instead of ``on_success``.

        Falsifiable: removing the ``_widget_is_alive`` guard from
        ``FunctionDetailsTab._on_fetch_error`` (``cutter_static_extra_tab.py``)
        makes this callback run ``self._fetch_btn.setEnabled(True)`` against
        the deleted tab, raising ``RuntimeError: wrapped C/C++ object of
        type QPushButton has been deleted`` into the Qt event loop and
        failing the final assertion.

        Args:
            qapp: Qt application fixture used to pump the event loop and
                deliver the queued callback after the tab is destroyed.
        """
        recorder = CommandRecorder({"afij": "not valid json output"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)
        _mark_analyzed(bridge, recorder)

        tab = FunctionDetailsTab()
        tab.refresh(bridge)
        addr_input = priv(tab, "_addr_input", QLineEdit)
        addr_input.setText("0x401000")

        on_fetch = cast(Callable[[], None], getattr(tab, "_on_fetch"))
        on_fetch()
        _ = drain_bridge_workers()
        sip.delete(tab)

        captured = _pump_capturing_exceptions(qapp)

        assert "afij" in recorder.commands, "the bridge call never completed; the test premise was not established"
        assert not captured, f"a late get_function failure crashed the Qt event loop after its tab was destroyed: {captured!r}"
