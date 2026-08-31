# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for GUI audit finding H7 in ``hex_editor/search.py``.

H7 -- Replace All / Replace previously blocked the Qt GUI thread by calling
the **blocking** ``run_bridge_coroutine`` variant directly from a
synchronous button-click slot (``SearchMixin._on_replace_all`` /
``_on_replace`` / ``_replace_all_regex_matches``), freezing the whole
application for the duration of the ``HexEditorBridge.replace_bytes`` /
``encode_text`` RPC. The fix routes every one of those dispatch sites
through the non-blocking ``run_bridge_coroutine_logged`` (built on
``BridgeCallWorker`` / ``run_bridge_coroutine_async``), which runs the
coroutine on the persistent background event-loop thread and delivers the
result back to the GUI thread via a queued Qt signal.

Every test below drives the real ``SearchMixin`` handlers on a real
``HexEditorPanel`` against a real ``HexEditorBridge`` bound to a real
``intellicrack_hexcore.HexDocument``. A thin ``HexEditorBridge`` subclass
injects an artificial ``asyncio.sleep`` delay into ``replace_bytes`` /
``encode_text`` so the non-blocking dispatch contract can be measured
directly: the handler must return to its caller in a small fraction of the
delay (proving it did not wait on ``future.result()`` inline) and the
document must remain unmodified until the delayed coroutine actually
completes on the background thread and the Qt event loop is pumped.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QComboBox, QLabel, QLineEdit, QMessageBox, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor import search as search_module
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from collections.abc import Callable


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real hex documents",
)


pytestmark = pytest.mark.integration


_DELAY_S: float = 0.4
"""Artificial async delay injected into the fake bridge RPCs, in seconds."""

_RETURN_BUDGET_S: float = _DELAY_S / 2
"""Maximum wall-clock time a non-blocking dispatch may take to return."""


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


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float) -> bool:
    """Pump the Qt event loop until ``predicate()`` is true or the timeout elapses.

    Cross-thread results delivered via ``run_bridge_coroutine_logged`` /
    ``BridgeCallWorker`` signals from the background asyncio thread only
    reach their Qt slots while the main-thread event loop is processing
    events, so tests must pump the loop while waiting for a handler's
    delayed side effect.

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


class _DelayedReplaceBridge(HexEditorBridge):
    """``HexEditorBridge`` whose ``replace_bytes``/``encode_text`` impose an artificial delay.

    Lets a test distinguish a non-blocking dispatch (the caller returns well
    before the coroutine finishes) from a blocking one (the caller only
    returns once the coroutine, including the delay, has completed).
    """

    def __init__(self, delay_s: float) -> None:
        """Initialise the bridge with the configured artificial delay.

        Args:
            delay_s: Number of seconds ``replace_bytes``/``encode_text``
                sleep for before performing the real operation.
        """
        super().__init__()
        self._delay_s: float = delay_s

    async def replace_bytes(self, pattern_hex: str, replacement_hex: str) -> int:
        """Sleep, then perform the real byte-pattern replace.

        Args:
            pattern_hex: Hex string pattern to find.
            replacement_hex: Hex string replacement.

        Returns:
            int: Number of replacements made.
        """
        await asyncio.sleep(self._delay_s)
        return await super().replace_bytes(pattern_hex, replacement_hex)

    async def encode_text(self, text: str, encoding: str = "utf-8") -> str:
        """Sleep, then perform the real text-to-hex encoding.

        Args:
            text: Text string to encode.
            encoding: Python codec name.

        Returns:
            str: Hex string of the encoded bytes.
        """
        await asyncio.sleep(self._delay_s)
        return await super().encode_text(text, encoding)


class _FailingReplaceBridge(HexEditorBridge):
    """``HexEditorBridge`` whose ``replace_bytes`` raises after an artificial delay.

    Used to prove that a failed RPC is surfaced through the async
    ``on_error`` callback path rather than by blocking the caller until the
    failure occurs and raising/handling it inline.
    """

    def __init__(self, delay_s: float) -> None:
        """Initialise the bridge with the configured artificial delay.

        Args:
            delay_s: Number of seconds ``replace_bytes`` sleeps for before
                raising.
        """
        super().__init__()
        self._delay_s: float = delay_s

    async def replace_bytes(self, pattern_hex: str, replacement_hex: str) -> int:
        """Sleep, then raise a simulated RPC failure.

        Args:
            pattern_hex: Hex string pattern to find (unused; failure is
                unconditional).
            replacement_hex: Hex string replacement (unused; failure is
                unconditional).

        Returns:
            int: Never returns; always raises.

        Raises:
            RuntimeError: Always, after the artificial delay.
        """
        del pattern_hex, replacement_hex
        await asyncio.sleep(self._delay_s)
        msg = "simulated replace_bytes failure"
        raise RuntimeError(msg)


class _WarningRecorder:
    """Records ``show_warning`` invocations and the thread each was made from."""

    def __init__(self) -> None:
        """Initialise empty call and thread-name ledgers."""
        self.calls: list[tuple[str, str]] = []
        self.thread_names: list[str] = []

    def __call__(
        self,
        parent: QWidget | None,
        title: str,
        message: str,
        *,
        exc: BaseException | None = None,
    ) -> QMessageBox.StandardButton:
        """Record the call's title, message, and calling thread name.

        Args:
            parent: Parent widget for the warning dialog (unused; not shown).
            title: Dialog title.
            message: Dialog message body.
            exc: Optional exception associated with the warning (unused).

        Returns:
            QMessageBox.StandardButton: A fixed ``Ok`` response, mirroring
                the dismissal a real dialog would eventually return.
        """
        del parent, exc
        self.calls.append((title, message))
        self.thread_names.append(threading.current_thread().name)
        return QMessageBox.StandardButton.Ok


def _make_panel(bridge: HexEditorBridge, document: object) -> HexEditorPanel:
    """Build a real ``HexEditorPanel`` bound to ``bridge`` and ``document``.

    Args:
        bridge: Hex editor bridge to attach via ``set_bridge``.
        document: Real ``intellicrack_hexcore`` document to attach.

    Returns:
        HexEditorPanel: A panel ready to drive search/replace handlers.
    """
    panel = HexEditorPanel()
    panel.set_bridge(bridge)
    panel.document = document
    return panel


class TestH7ReplaceAllHexModeNonBlockingDispatch:
    """H7: Hex-mode Replace All dispatches ``replace_bytes`` without blocking the GUI thread."""

    def test_h7_on_replace_all_returns_before_delayed_replace_completes(self, qapp: QApplication) -> None:
        """``_on_replace_all`` returns almost immediately, well before the delayed RPC finishes.

        Pre-fix, ``_on_replace_all`` called the blocking
        ``run_bridge_coroutine(bridge.replace_bytes(...))``, which invokes
        ``future.result(timeout_s=None)`` on the calling (GUI) thread and
        therefore would not return until the full ``_DELAY_S`` artificial
        delay -- plus the real replace -- had elapsed, and the document
        would already be mutated by the time the call returned. Post-fix,
        the RPC is dispatched via ``run_bridge_coroutine_logged`` onto a
        background ``BridgeCallWorker`` thread, so the handler returns in a
        small fraction of the delay and the document is untouched until the
        Qt event loop is later pumped and the queued result signal fires.

        Args:
            qapp: The shared QApplication fixture.
        """
        original = b"\x90\x90\xcc\x90\x90\xcc\x11\x22"
        document = hexcore.HexDocument.open_bytes(original)
        bridge = _DelayedReplaceBridge(_DELAY_S)
        bridge.document = document
        panel = _make_panel(bridge, document)
        try:
            priv(panel, "_search_mode_combo", QComboBox).setCurrentText("Hex")
            priv(panel, "_search_input", QLineEdit).setText("90 90")
            priv(panel, "_replace_input", QLineEdit).setText("AA BB")

            start = time.monotonic()
            priv_method(panel, "_on_replace_all")()
            elapsed = time.monotonic() - start

            assert elapsed < _RETURN_BUDGET_S, (
                f"_on_replace_all blocked the calling thread for {elapsed:.3f}s waiting on a "
                f"{_DELAY_S}s replace_bytes RPC instead of dispatching it to a background worker"
            )

            unmutated = bytes(document.read(0, len(original)))
            assert unmutated == original, (
                "document was already mutated before _on_replace_all returned; the dispatch is "
                "blocking (awaiting the coroutine synchronously) instead of asynchronous"
            )

            completed = _pump_until(
                qapp,
                lambda: "Replaced" in priv(panel, "_search_status_label", QLabel).text(),
                timeout_s=_DELAY_S + 5.0,
            )
            assert completed, "Replace All never completed after pumping the Qt event loop"

            after = bytes(document.read(0, len(original)))
            expected = original.replace(b"\x90\x90", b"\xaa\xbb")
            assert after == expected
            assert priv(panel, "_search_status_label", QLabel).text() == "Replaced 2 occurrence(s)"
        finally:
            panel.deleteLater()


class TestH7ReplaceAllTextModeNonBlockingDispatch:
    """H7: Text-mode Replace All folds two ``encode_text`` round trips and a replace into one non-blocking dispatch."""

    def test_h7_on_replace_all_text_mode_returns_before_encode_and_replace_complete(self, qapp: QApplication) -> None:
        """``_on_replace_all`` in Text mode returns before any of the three delayed RPCs finish.

        Pre-fix, ``_resolve_hex_replace_pair`` issued two sequential
        blocking ``run_bridge_coroutine(bridge.encode_text(...))`` calls
        directly on the GUI thread before ``_on_replace_all`` issued a
        third blocking ``replace_bytes`` call, so the handler would not
        return until all three delayed RPCs (``3 * _DELAY_S`` at minimum)
        had completed synchronously. Post-fix, all three round trips are
        folded into the single ``_replace_all_text_bytes`` coroutine
        dispatched via ``run_bridge_coroutine_logged``, so the handler
        returns in a small fraction of even one delay.

        Args:
            qapp: The shared QApplication fixture.
        """
        original = b"AAAABBBBAAAA"
        document = hexcore.HexDocument.open_bytes(original)
        bridge = _DelayedReplaceBridge(_DELAY_S)
        bridge.document = document
        panel = _make_panel(bridge, document)
        try:
            priv(panel, "_search_mode_combo", QComboBox).setCurrentText("Text")
            priv(panel, "_search_input", QLineEdit).setText("AAAA")
            priv(panel, "_replace_input", QLineEdit).setText("ZZZZ")

            start = time.monotonic()
            priv_method(panel, "_on_replace_all")()
            elapsed = time.monotonic() - start

            assert elapsed < _RETURN_BUDGET_S, (
                f"_on_replace_all (Text mode) blocked the calling thread for {elapsed:.3f}s across "
                "the encode/encode/replace round trips instead of dispatching them asynchronously"
            )

            unmutated = bytes(document.read(0, len(original)))
            assert unmutated == original, (
                "document was already mutated before _on_replace_all (Text mode) returned; the "
                "encode_text/replace_bytes round trips are running synchronously on the GUI thread"
            )

            completed = _pump_until(
                qapp,
                lambda: "Replaced" in priv(panel, "_search_status_label", QLabel).text(),
                timeout_s=3 * _DELAY_S + 8.0,
            )
            assert completed, "Text-mode Replace All never completed after pumping the Qt event loop"
            assert bytes(document.read(0, len(original))) == b"ZZZZBBBBZZZZ"
        finally:
            panel.deleteLater()


class TestH7SingleReplaceTextModeNonBlockingDispatch:
    """H7: single Replace in Text mode dispatches ``encode_text`` without blocking the GUI thread."""

    def test_h7_on_replace_text_mode_returns_before_encode_completes(self, qapp: QApplication) -> None:
        """``_on_replace`` in Text mode returns before the delayed ``encode_text`` RPC finishes.

        Pre-fix, ``_resolve_single_replacement_bytes`` issued a blocking
        ``run_bridge_coroutine(bridge.encode_text(...))`` directly from
        ``_on_replace``, so the single-match write would not happen (and
        the handler would not return) until the delayed RPC completed.
        Post-fix, Text/Regex modes dispatch ``encode_text`` via
        ``run_bridge_coroutine_logged`` and the write is completed later in
        ``_apply_encoded_single_replacement`` once the queued result
        signal fires.

        Args:
            qapp: The shared QApplication fixture.
        """
        original = b"AAAABBBBAAAA"
        document = hexcore.HexDocument.open_bytes(original)
        bridge = _DelayedReplaceBridge(_DELAY_S)
        bridge.document = document
        panel = _make_panel(bridge, document)
        try:
            priv(panel, "_search_mode_combo", QComboBox).setCurrentText("Text")
            priv(panel, "_search_input", QLineEdit).setText("AAAA")
            priv(panel, "_replace_input", QLineEdit).setText("ZZZZ")
            panel._search_results = [(0, 4)]
            panel._search_index = 0

            start = time.monotonic()
            priv_method(panel, "_on_replace")()
            elapsed = time.monotonic() - start

            assert elapsed < _RETURN_BUDGET_S, (
                f"_on_replace (Text mode) blocked the calling thread for {elapsed:.3f}s waiting on a "
                f"{_DELAY_S}s encode_text RPC instead of dispatching it to a background worker"
            )

            unmutated = bytes(document.read(0, 4))
            assert unmutated == b"AAAA", (
                "the match was already overwritten before _on_replace returned; the encode_text "
                "round trip is running synchronously on the GUI thread"
            )

            completed = _pump_until(
                qapp,
                lambda: bytes(document.read(0, 4)) == b"ZZZZ",
                timeout_s=_DELAY_S + 5.0,
            )
            assert completed, "Single Replace never completed after pumping the Qt event loop"
        finally:
            panel.deleteLater()


class TestH7ReplaceAllFailureSurfacedAsynchronously:
    """H7: a failed Replace All RPC is surfaced via the async error callback, not a blocking wait."""

    def test_h7_on_replace_all_failure_reported_only_after_event_pump(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failing ``replace_bytes`` warns the user only once the delayed coroutine actually fails.

        Pre-fix, the blocking dispatch's ``try/except`` around
        ``run_bridge_coroutine(...)`` meant ``show_warning`` was already
        invoked, on the calling thread, by the time ``_on_replace_all``
        returned -- after blocking for the full ``_DELAY_S``. Post-fix,
        ``run_bridge_coroutine_logged`` delivers the exception via the
        queued ``call_error`` signal to ``_on_replace_all_failed``, so the
        handler returns immediately and no warning has been recorded until
        the Qt event loop is pumped and the background coroutine has had
        time to fail.

        Args:
            qapp: The shared QApplication fixture.
            monkeypatch: Pytest fixture used to intercept the module-level
                ``show_warning`` so no real modal dialog is spawned.
        """
        original = b"\x90\x90\xcc\x90\x90\xcc"
        document = hexcore.HexDocument.open_bytes(original)
        bridge = _FailingReplaceBridge(_DELAY_S)
        bridge.document = document
        panel = _make_panel(bridge, document)
        recorder = _WarningRecorder()
        monkeypatch.setattr(search_module, "show_warning", recorder)
        try:
            priv(panel, "_search_mode_combo", QComboBox).setCurrentText("Hex")
            priv(panel, "_search_input", QLineEdit).setText("90 90")
            priv(panel, "_replace_input", QLineEdit).setText("AA BB")

            start = time.monotonic()
            priv_method(panel, "_on_replace_all")()
            elapsed = time.monotonic() - start

            assert elapsed < _RETURN_BUDGET_S, (
                f"_on_replace_all blocked the calling thread for {elapsed:.3f}s waiting for the "
                f"{_DELAY_S}s failing replace_bytes RPC instead of dispatching it asynchronously"
            )
            assert not recorder.calls, (
                "show_warning was already invoked before _on_replace_all returned; the failure is "
                "being handled synchronously on the calling thread instead of via the async callback"
            )

            completed = _pump_until(qapp, lambda: bool(recorder.calls), timeout_s=_DELAY_S + 5.0)
            assert completed, "the replace failure was never surfaced to the user"

            title, message = recorder.calls[0]
            assert title == "Replace All"
            assert "Replace failed" in message
            assert recorder.thread_names[-1] == threading.main_thread().name, (
                "the failure callback must be delivered on the GUI thread via the queued call_error "
                "signal, not invoked directly from the background bridge event-loop thread"
            )

            unmutated = bytes(document.read(0, len(original)))
            assert unmutated == original
        finally:
            panel.deleteLater()
