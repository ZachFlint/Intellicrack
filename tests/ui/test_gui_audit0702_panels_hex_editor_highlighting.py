# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for GUI audit findings H6 and M6 in ``hex_editor/highlighting.py``.

H6 -- ``HighlightingMixin.refresh_pattern_highlights`` previously ran a
synchronous, whole-document ``search_hex`` scan on the Qt GUI thread for
every active pattern-type highlight rule, and it did so on *every single*
``HexEditorWidget.data_changed`` emission -- i.e. on every byte edit made in
the hex view (wired via ``HexEditorPanel._on_data_changed``). The fix moves
the scan onto a background ``GenericCallableWorker`` thread and coalesces any
refresh requested while one is already in flight into a single follow-up
pass, so rapid successive edits never block the event loop and never queue
an unbounded number of background scans.

M6 -- ``HighlightingMixin._resolve_pattern_rule`` (the pattern-rule
resolution path reached from the "Add Rule" button, prior to any bridge
dispatch) previously called the same blocking ``search_hex`` synchronously
on the GUI thread. The fix splits this into
``_on_add_pattern_highlight_rule``, which resolves the pattern's offsets on
a background ``GenericCallableWorker`` thread and only dispatches the
``add_highlight_rule`` bridge RPC once those offsets are available.

Every test below drives the real ``HighlightingMixin`` handlers on a real
``HexEditorPanel`` bound to a real ``intellicrack_hexcore.HexDocument``
wrapped so that ``search_hex`` is measurably slow and records which thread
invoked it -- letting each test tell a non-blocking, worker-thread dispatch
apart from the pre-fix synchronous, GUI-thread scan by both elapsed wall-clock
time and the recorded caller thread.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QComboBox, QLineEdit, QMessageBox

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget, HighlightRule


if TYPE_CHECKING:
    from collections.abc import Callable


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real hex documents",
)


pytestmark = pytest.mark.integration


_DELAY_S: float = 0.35
"""Artificial delay injected into the wrapped document's ``search_hex``, in seconds."""

_RETURN_BUDGET_S: float = _DELAY_S / 2
"""Maximum wall-clock time a non-blocking dispatch may take to return."""

_WAIT_TIMEOUT_S: float = _DELAY_S + 5.0
"""Ceiling for pumping the Qt event loop while waiting for a background worker."""

_PATTERN_HEX: str = "AA BB CC DD"
"""Hex pattern typed into the highlight rule / search UI for every test below."""

_PATTERN_BYTES: bytes = bytes.fromhex(_PATTERN_HEX.replace(" ", ""))
"""Raw bytes corresponding to :data:`_PATTERN_HEX`."""


def priv[T](obj: object, name: str, typ: type[T]) -> T:
    """Read a private attribute with a runtime-checked, statically narrowed type.

    Args:
        obj: The object whose private attribute is being read.
        name: The attribute name to look up.
        typ: The expected runtime type of the attribute.

    Returns:
        T: The attribute value, narrowed to ``typ``.

    Raises:
        TypeError: If the attribute's runtime type does not match ``typ``.
    """
    value = getattr(obj, name)
    if not isinstance(value, typ):
        msg = f"{obj!r}.{name} is {type(value).__name__}, expected {typ.__name__}"
        raise TypeError(msg)
    return value


def priv_method(obj: object, name: str) -> Callable[..., object]:
    """Read a private bound method off an object.

    Args:
        obj: The object whose private method is being looked up.
        name: The method name to look up.

    Returns:
        Callable[..., object]: The bound method.

    Raises:
        TypeError: If the attribute's runtime value is not callable.
    """
    value = getattr(obj, name)
    if not callable(value):
        msg = f"{obj!r}.{name} is not callable"
        raise TypeError(msg)
    return value


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float = _WAIT_TIMEOUT_S) -> bool:
    """Pump the Qt event loop until ``predicate()`` is true or the timeout elapses.

    Cross-thread results delivered via ``GenericCallableWorker`` /
    ``BridgeCallWorker`` signals from a background thread only reach their Qt
    slots while the main-thread event loop is processing events, so tests
    must pump the loop while waiting for a worker's delayed side effect.

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


@pytest.fixture(autouse=True)
def _non_blocking_warning_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep modal warning dialogs from freezing the offscreen event loop.

    These tests pump the Qt event loop while a live ``HexEditorPanel`` is
    present. A debounced follow-cursor disassembly can fire mid-pump and, when
    it fails on the synthetic document, call ``QMessageBox.warning`` -- a modal
    dialog whose nested event loop never returns under the offscreen platform
    (there is no user to dismiss it), hanging the test indefinitely. Replacing
    it with a non-blocking stand-in keeps the loop responsive. Tests that
    assert on a specific warning install their own recorder afterwards, which
    overrides this default.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """

    def _stub_warning(parent: object, title: str, text: str, *_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        del parent, title, text
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "warning", _stub_warning)


def _type_byte(widget: HexEditorWidget, offset: int, hexstr: str) -> None:
    """Type a full byte via two hex-nibble key handlers at ``offset``.

    Mirrors a real user edit in the hex view: positions the cursor and feeds
    both nibbles through ``_handle_hex_input``, which performs the
    ``write_bytes`` call and emits ``data_changed`` exactly like a live
    keystroke would.

    Args:
        widget: The hex widget under test.
        offset: Byte offset to place the cursor before typing.
        hexstr: Two-character hex string, e.g. ``"AA"``.
    """
    widget._cursor_offset = offset
    widget._nibble_index = 0
    widget._handle_hex_input(hexstr[0])
    widget._handle_hex_input(hexstr[1])


class _DelayedSearchDocument:
    """Wraps a real hexcore document, delaying and recording every ``search_hex`` call.

    Every other attribute access (``read``, ``write_bytes``, ``length``,
    ``is_modified``, etc.) is delegated straight through to the wrapped
    document so the panel and hex widget can use it exactly like a real
    ``intellicrack_hexcore.HexDocument`` for anything other than searching.
    Recording the calling thread's name for every ``search_hex`` invocation
    lets a test prove the scan ran off the Qt GUI thread rather than merely
    inferring it from timing.
    """

    def __init__(self, document: object, delay_s: float) -> None:
        """Initialise the wrapper around a real document.

        Args:
            document: Real ``intellicrack_hexcore.HexDocument`` to delegate to.
            delay_s: Number of seconds each ``search_hex`` call sleeps for
                before delegating to the wrapped document's real ``search_hex``.
        """
        self._document = document
        self._delay_s = delay_s
        self.search_calls: list[tuple[str, int]] = []
        self.search_threads: list[str] = []

    def search_hex(self, pattern: str, max_matches: int) -> object:
        """Record the call and calling thread, sleep, then delegate to the real search.

        Args:
            pattern: Hex pattern string to search for.
            max_matches: Maximum number of matches to return.

        Returns:
            object: The raw match list from the wrapped document's ``search_hex``.
        """
        self.search_calls.append((pattern, max_matches))
        self.search_threads.append(threading.current_thread().name)
        time.sleep(self._delay_s)
        return self._document.search_hex(pattern, max_matches)

    def __getattr__(self, name: str) -> object:
        """Delegate any other attribute access to the wrapped document.

        Args:
            name: Attribute name being looked up.

        Returns:
            object: The corresponding attribute on the wrapped document.
        """
        return getattr(self._document, name)


class _FailingSearchDocument:
    """Wraps a real hexcore document whose ``search_hex`` raises after an artificial delay.

    Used to prove that a pattern-rule search failure is surfaced through the
    background worker's ``call_error`` signal rather than by raising inline
    on the calling (GUI) thread.
    """

    def __init__(self, document: object, delay_s: float) -> None:
        """Initialise the wrapper around a real document.

        Args:
            document: Real ``intellicrack_hexcore.HexDocument`` to delegate to.
            delay_s: Number of seconds ``search_hex`` sleeps for before raising.
        """
        self._document = document
        self._delay_s = delay_s
        self.search_calls: list[tuple[str, int]] = []

    def search_hex(self, pattern: str, max_matches: int) -> object:
        """Record the call, sleep, then raise a simulated native-search failure.

        Args:
            pattern: Hex pattern string to search for.
            max_matches: Maximum number of matches to return.

        Returns:
            object: Never returns; always raises.

        Raises:
            RuntimeError: Always, after the artificial delay.
        """
        self.search_calls.append((pattern, max_matches))
        time.sleep(self._delay_s)
        msg = "simulated search_hex failure"
        raise RuntimeError(msg)

    def __getattr__(self, name: str) -> object:
        """Delegate any other attribute access to the wrapped document.

        Args:
            name: Attribute name being looked up.

        Returns:
            object: The corresponding attribute on the wrapped document.
        """
        return getattr(self._document, name)


def _make_document_bytes(length: int, offsets: list[int]) -> bytes:
    """Build a zero-filled buffer with :data:`_PATTERN_BYTES` embedded at ``offsets``.

    Args:
        length: Total length of the buffer in bytes.
        offsets: Byte offsets at which to embed the pattern.

    Returns:
        bytes: The assembled buffer.
    """
    buf = bytearray(length)
    for off in offsets:
        buf[off : off + len(_PATTERN_BYTES)] = _PATTERN_BYTES
    return bytes(buf)


def _make_panel(document: object, bridge: HexEditorBridge | None = None) -> HexEditorPanel:
    """Build a real ``HexEditorPanel`` bound to ``document`` (and optionally ``bridge``).

    Attaches ``document`` both as ``panel.document`` and as the embedded hex
    widget's own document, mirroring how ``HexEditorPanel._load_file_impl``
    wires a freshly opened file to both in production.

    Args:
        document: Document object to attach.
        bridge: Optional hex editor bridge to attach via ``set_bridge``.

    Returns:
        HexEditorPanel: A panel ready to drive highlighting handlers.
    """
    panel = HexEditorPanel()
    if bridge is not None:
        panel.set_bridge(bridge)
    panel.document = document
    widget = priv(panel, "_hex_widget", HexEditorWidget)
    widget.set_document(document)
    return panel


class TestH6RefreshPatternHighlightsAsyncDispatch:
    """H6: pattern-highlight refresh runs off the GUI thread and coalesces bursts of edits."""

    def test_h6_byte_edit_triggers_refresh_without_blocking_gui_thread(self, qapp: QApplication) -> None:
        """A single byte edit dispatches the pattern rescan without blocking the caller.

        Pre-fix, ``refresh_pattern_highlights`` (invoked synchronously from
        ``_on_data_changed`` on every ``data_changed`` emission) called
        ``search_hex`` directly on the GUI thread, so typing a single hex
        digit would not return control to the caller until the whole-document
        scan (here, ``_DELAY_S``) had completed, and the rule's offsets would
        already be updated by the time the call returned. Post-fix, the scan
        runs on a background ``GenericCallableWorker`` thread, so the edit
        handler returns in a small fraction of the delay and the rule's
        offsets remain the stale pre-refresh value until the Qt event loop is
        pumped and the worker's result signal is delivered.

        Args:
            qapp: The shared QApplication fixture.
        """
        offsets = [10, 100, 200]
        real_doc = hexcore.HexDocument.open_bytes(_make_document_bytes(300, offsets))
        wrapped = _DelayedSearchDocument(real_doc, _DELAY_S)
        panel = _make_panel(wrapped)
        try:
            widget = priv(panel, "_hex_widget", HexEditorWidget)
            params: dict[str, object] = {"pattern": _PATTERN_HEX, "offsets": []}
            widget.add_highlight_rule(
                HighlightRule(rule_id="r1", condition_type="pattern", condition_params=params, color="#FFFF00"),
            )

            start = time.monotonic()
            _type_byte(widget, 290, "11")
            elapsed = time.monotonic() - start

            assert elapsed < _RETURN_BUDGET_S, (
                f"typing a byte blocked the calling thread for {elapsed:.3f}s waiting on a "
                f"{_DELAY_S}s search_hex rescan instead of dispatching it to a background worker"
            )
            assert params["offsets"] == [], (
                "the rule's offsets were already rewritten before the edit handler returned; the "
                "pattern rescan is running synchronously on the GUI thread"
            )

            completed = _pump_until(qapp, lambda: params["offsets"] == {10, 100, 200})
            assert completed, "the pattern rescan never completed after pumping the Qt event loop"

            assert wrapped.search_calls == [(_PATTERN_HEX, 10000)]
            assert wrapped.search_threads[-1] != threading.main_thread().name, (
                "search_hex ran on the Qt main thread instead of a background GenericCallableWorker thread"
            )
        finally:
            panel.deleteLater()

    def test_h6_rapid_edits_coalesce_into_bounded_search_calls(self, qapp: QApplication) -> None:
        """Three edits made while a rescan is in flight collapse into exactly one follow-up scan.

        Pre-fix, each of the three edits synchronously ran its own
        whole-document ``search_hex`` call inline (three scans total, each
        blocking the caller for ``_DELAY_S``). Post-fix, the first edit starts
        a background worker; because ``QThread.isRunning()`` is already true
        the instant ``start()`` returns, the second and third edits -- made
        well within the worker's artificial delay -- observe it still running
        and only set a pending-refresh flag instead of starting their own
        scans. Once the in-flight worker finishes, exactly one coalesced
        follow-up scan runs. The wrapped document therefore records exactly
        two ``search_hex`` calls for three edits, never three.

        Args:
            qapp: The shared QApplication fixture.
        """
        offsets = [10, 100, 200]
        real_doc = hexcore.HexDocument.open_bytes(_make_document_bytes(300, offsets))
        wrapped = _DelayedSearchDocument(real_doc, _DELAY_S)
        panel = _make_panel(wrapped)
        try:
            widget = priv(panel, "_hex_widget", HexEditorWidget)
            params: dict[str, object] = {"pattern": _PATTERN_HEX, "offsets": []}
            widget.add_highlight_rule(
                HighlightRule(rule_id="r1", condition_type="pattern", condition_params=params, color="#FFFF00"),
            )

            start = time.monotonic()
            _type_byte(widget, 210, "11")
            _type_byte(widget, 211, "22")
            _type_byte(widget, 212, "33")
            elapsed = time.monotonic() - start

            assert elapsed < _RETURN_BUDGET_S, (
                f"three rapid edits blocked the calling thread for {elapsed:.3f}s instead of "
                "dispatching their pattern rescans to a background worker"
            )

            completed = _pump_until(qapp, lambda: params["offsets"] == {10, 100, 200}, timeout_s=2 * _DELAY_S + 8.0)
            assert completed, "the coalesced pattern rescan never completed after pumping the Qt event loop"

            assert len(wrapped.search_calls) == 2, (
                f"expected exactly 2 search_hex calls (1 in-flight + 1 coalesced follow-up) for 3 rapid "
                f"edits, got {len(wrapped.search_calls)}: rapid successive edits are not being coalesced "
                "into a single follow-up rescan"
            )
        finally:
            panel.deleteLater()


class TestM6AddPatternHighlightRuleAsyncDispatch:
    """M6: resolving a pattern highlight rule's offsets runs off the GUI thread."""

    def test_m6_add_pattern_rule_returns_before_search_completes_and_dispatches_resolved_offsets(
        self,
        qapp: QApplication,
    ) -> None:
        """Clicking 'Add Rule' for a Pattern condition returns immediately and later persists real offsets.

        Pre-fix, ``_resolve_pattern_rule`` called ``search_hex`` directly on
        the GUI thread from ``_on_add_highlight_rule`` before any bridge
        dispatch, so the click handler would not return -- and the
        ``add_highlight_rule`` bridge RPC would not even be sent -- until the
        whole-document scan (here, ``_DELAY_S``) had completed. Post-fix, the
        scan runs on a background ``GenericCallableWorker`` thread and the
        bridge RPC is only dispatched once real offsets are resolved, so the
        handler returns almost immediately, the bridge has recorded no rule
        yet, and only after the Qt event loop is pumped does the bridge
        receive an ``add_highlight_rule`` call carrying the real, sorted match
        offsets.

        Args:
            qapp: The shared QApplication fixture.
        """
        offsets = [10, 50, 90]
        real_doc = hexcore.HexDocument.open_bytes(_make_document_bytes(150, offsets))
        wrapped = _DelayedSearchDocument(real_doc, _DELAY_S)
        bridge = HexEditorBridge()
        panel = _make_panel(wrapped, bridge)
        try:
            priv(panel, "_highlight_condition_combo", QComboBox).setCurrentIndex(2)
            priv(panel, "_highlight_pattern_edit", QLineEdit).setText(_PATTERN_HEX)
            priv(panel, "_highlight_color_edit", QLineEdit).setText("#00FF00")

            start = time.monotonic()
            priv_method(panel, "_on_add_highlight_rule")()
            elapsed = time.monotonic() - start

            assert elapsed < _RETURN_BUDGET_S, (
                f"_on_add_highlight_rule blocked the calling thread for {elapsed:.3f}s waiting on a "
                f"{_DELAY_S}s search_hex call instead of dispatching it to a background worker"
            )
            assert not bridge._highlight_rules, (
                "add_highlight_rule was already dispatched to the bridge before the pattern search "
                "completed; the offset resolution is running synchronously on the GUI thread"
            )

            completed = _pump_until(qapp, lambda: bool(bridge._highlight_rules))
            assert completed, "the pattern highlight rule was never dispatched to the bridge"

            rule = next(iter(bridge._highlight_rules.values()))
            assert rule["condition_type"] == "pattern"
            assert rule["condition_params"]["pattern"] == _PATTERN_HEX
            assert sorted(rule["condition_params"]["offsets"]) == offsets, (
                "the dispatched rule's offsets do not match the real search_hex matches; the pattern "
                "was not actually resolved against the document"
            )
            assert rule["color"] == "#00FF00"

            assert wrapped.search_calls == [(_PATTERN_HEX, 10000)]
            assert wrapped.search_threads[-1] != threading.main_thread().name, (
                "search_hex ran on the Qt main thread instead of a background GenericCallableWorker thread"
            )
        finally:
            panel.deleteLater()

    def test_m6_add_pattern_rule_search_failure_surfaces_asynchronously_without_dispatch(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failing pattern search warns the user asynchronously and never reaches the bridge.

        Pre-fix, a ``search_hex`` failure inside ``_resolve_pattern_rule``
        raised synchronously on the GUI thread and ``QMessageBox.warning`` was
        already invoked, on the calling thread, by the time
        ``_on_add_highlight_rule`` returned -- after blocking for the full
        ``_DELAY_S``. Post-fix, the failure is delivered via the background
        worker's ``call_error`` signal to ``_on_pattern_rule_search_error``,
        so the handler returns almost immediately, no warning has been
        recorded yet, and the bridge never receives an ``add_highlight_rule``
        call for the failed pattern.

        Args:
            qapp: The shared QApplication fixture.
            monkeypatch: Pytest fixture used to intercept ``QMessageBox.warning``
                so no real modal dialog is spawned.
        """
        warnings: list[tuple[object, str, str]] = []

        def _record_warning(parent: object, title: str, text: str, *_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warnings.append((parent, title, text))
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "warning", _record_warning)

        real_doc = hexcore.HexDocument.open_bytes(_make_document_bytes(64, [10]))
        wrapped = _FailingSearchDocument(real_doc, _DELAY_S)
        bridge = HexEditorBridge()
        panel = _make_panel(wrapped, bridge)
        try:
            priv(panel, "_highlight_condition_combo", QComboBox).setCurrentIndex(2)
            priv(panel, "_highlight_pattern_edit", QLineEdit).setText(_PATTERN_HEX)

            start = time.monotonic()
            priv_method(panel, "_on_add_highlight_rule")()
            elapsed = time.monotonic() - start

            assert elapsed < _RETURN_BUDGET_S, (
                f"_on_add_highlight_rule blocked the calling thread for {elapsed:.3f}s waiting for the "
                f"{_DELAY_S}s failing search_hex call instead of dispatching it asynchronously"
            )
            assert not warnings, (
                "QMessageBox.warning was already invoked before _on_add_highlight_rule returned; the "
                "search failure is being handled synchronously on the calling thread"
            )

            warned = _pump_until(qapp, lambda: bool(warnings))
            assert warned, "the pattern search failure was never surfaced to the user"
            assert warnings[0][1] == "Highlight"
            assert "Pattern search failed" in warnings[0][2]
            assert not bridge._highlight_rules, (
                "add_highlight_rule must not be dispatched to the bridge when the background pattern search fails"
            )
        finally:
            panel.deleteLater()
