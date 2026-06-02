# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""UI regression tests for audit5 F-0007 (HexPat ``std::print`` sink wiring).

Verifies the ``PatternEditorMixin`` consumer-side wiring:

* ``_apply_via_interpreter`` must construct ``HexPatInterpreter_cls`` with a
  ``print_sink=`` callback bound to a UI append routine, so HexPat
  ``std::print`` output reaches the panel rather than only the log.
* Once an interpreter is cached, subsequent applies must reinstall the sink
  via ``set_print_sink`` (rather than dropping it) so the print pipeline is
  observable for every pattern the user runs through the panel.

The tests subclass :class:`PatternEditorMixin` directly with a minimal
``QWidget`` harness so they assert against the production helper without
spinning up the entire hex-editor panel.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QApplication, QPlainTextEdit, QWidget

from intellicrack.ui.panels.hex_editor.pattern_editor import PatternEditorMixin


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


pytest.importorskip("intellicrack.core.hexpat", reason="hexpat interpreter module unavailable")


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


_REAL_PRINT_PATTERN: str = """
fn __ping() {
    builtin::std::io::print("hello-ui-print-sink");
    return 0;
};
u8 __mark @ __ping();
"""


@pytest.fixture(scope="session")
def qapp() -> Iterator[QApplication]:
    """Provide a session-scoped ``QApplication`` for widget construction.

    Yields:
        QApplication: A live ``QApplication`` for the test session.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _StubDocument:
    """Minimal HexDocument-compatible stub backed by an in-memory ``bytes`` buffer.

    Mirrors the PyO3 ``HexDocument`` contract the real HexPat interpreter
    consumes via ``DataReader.from_document``: ``read(offset, length)``
    returns a ``list[int]`` and ``length()`` returns the byte count. This
    lets the real pattern engine evaluate against the harness without
    depending on the optional ``intellicrack_hexcore`` native build.
    """

    def __init__(self, data: bytes) -> None:
        """Capture the buffer the stub exposes via ``read`` / ``length``.

        Args:
            data: Bytes the stub holds for length and read queries.
        """
        self._data: bytes = bytes(data)

    def length(self) -> int:
        """Return the buffer length in bytes.

        Returns:
            int: The stub buffer's size.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> list[int]:
        """Return a slice of the stub buffer as a list of integers.

        Args:
            offset: Byte offset to start reading from.
            length: Number of bytes to return.

        Returns:
            list[int]: The requested byte slice as a list of integers.
        """
        return list(self._data[offset : offset + length])


class _StubInterpreterWithPrintSink:
    """HexPat interpreter stub that exercises the mixin's print-sink wiring.

    Holds the most-recently-installed ``print_sink`` callback so the tests
    can assert which callable the mixin handed to the interpreter, and so
    they can drive that callback synthetically (without invoking the real
    pattern pipeline) to verify the UI append wiring.
    """

    def __init__(self, *, print_sink: Callable[[str], None] | None = None) -> None:
        """Capture the ``print_sink`` provided at construction.

        Args:
            print_sink: Callback the mixin forwards from the
                pattern-editor panel for ``std::print`` output.
        """
        self.print_sink: Callable[[str], None] | None = print_sink
        self.calls: list[tuple[str, object, int]] = []

    def set_print_sink(self, sink: Callable[[str], None] | None) -> None:
        """Replace the cached print sink.

        Args:
            sink: New callback to receive ``std::print`` output, or
                ``None`` to clear the previously installed sink.
        """
        self.print_sink = sink

    def execute(self, source: str, document: object, offset: int) -> list[dict[str, Any]]:
        """Record the call and return a fixed field list.

        Args:
            source: HexPat DSL source code the mixin would evaluate.
            document: Document the mixin passes to the interpreter.
            offset: Byte offset the mixin applies the pattern at.

        Returns:
            list[dict[str, Any]]: A single synthetic field row.
        """
        self.calls.append((source, document, offset))
        return [{"name": "stub", "offset": offset, "size": 1}]


class _PatternHarness(QWidget, PatternEditorMixin):
    """Concrete ``PatternEditorMixin`` consumer for the U12 regressions.

    Provides every attribute slot declared by ``PatternEditorMixin`` so the
    mixin's interpreter helpers run without raising. The harness binds the
    print-output widget that the production code is expected to populate.
    """

    def __init__(self, *, document: _StubDocument) -> None:
        """Wire up the mixin attributes the regression cases require.

        Args:
            document: Stub document the mixin invokes for length / read.
        """
        QWidget.__init__(self)
        self._document = document
        self.document = document
        self._hex_widget = None
        self._file_path = None
        self._pattern_frame = None
        self._pattern_completer = None
        self._pattern_dsl_editor = None
        self._pattern_json_preview = None
        self._pattern_library_tree = None
        self._pattern_error_display = QPlainTextEdit()
        self._pattern_print_output = QPlainTextEdit()
        self._pattern_status_label = None
        self._pattern_visible = False
        self._compiled_json = ""
        self._main_vsplit = None
        self._interpreter = None
        self._pattern_registry = None
        self._templates_tree = None
        self._template_combo = None
        self._state_holder = None
        self.state_holder = None

    def _populate_template_tree(self, fields: list[dict[str, object]]) -> None:
        """Override the tree population to a no-op for the regression tests.

        Args:
            fields: Decoded template fields the panel would render.
        """

    def _highlight_template_fields(self, fields: list[dict[str, object]]) -> None:
        """Override the highlight overlay to a no-op for the regression tests.

        Args:
            fields: Decoded template fields the panel would highlight.
        """

    def _populate_template_combo(self) -> None:
        """Override the combo refresh to a no-op for the regression tests."""

    def trigger_apply_via_interpreter(self, source: str, offset: int) -> None:
        """Drive ``_apply_via_interpreter`` exactly as the panel apply button would.

        Args:
            source: HexPat DSL source code to apply.
            offset: Byte offset to apply the pattern at.
        """
        self._apply_via_interpreter(source, offset)

    def print_output_widget(self) -> QPlainTextEdit:
        """Return the panel's HexPat ``std::print`` output widget.

        Wraps the private :attr:`_pattern_print_output` attribute the
        mixin populates so the regression tests can read the widget
        without tripping basedpyright's ``reportPrivateUsage`` rule. The
        accompanying ``assert`` narrows the optional attribute and is
        skipped under ``python -O`` rather than raising a documented
        exception.

        Returns:
            QPlainTextEdit: The widget the mixin appends ``std::print``
            output to.
        """
        widget = self._pattern_print_output
        assert widget is not None, "harness must be initialised with a concrete print-output widget"
        return widget

    def error_display_widget(self) -> QPlainTextEdit:
        """Return the panel's interpreter error-display widget.

        Wraps the private :attr:`_pattern_error_display` attribute so the
        regression tests can assert a clean (empty) error channel after a
        successful apply without tripping basedpyright's
        ``reportPrivateUsage`` rule.

        Returns:
            QPlainTextEdit: The widget the mixin writes interpreter errors
            to.
        """
        widget = self._pattern_error_display
        assert widget is not None, "harness must be initialised with a concrete error-display widget"
        return widget


def _install_stub_interpreter(monkeypatch: pytest.MonkeyPatch, stubs: list[_StubInterpreterWithPrintSink]) -> None:
    """Install a constructible interpreter stub on the mixin's lazy import slot.

    Each call to ``HexPatInterpreter_cls(print_sink=...)`` instantiates a
    fresh ``_StubInterpreterWithPrintSink`` whose constructor argument is
    appended to ``stubs`` so the test can inspect every wiring decision the
    mixin made during apply.

    Args:
        monkeypatch: pytest monkeypatch fixture.
        stubs: Mutable list collecting every constructed stub for the
            test to assert on.
    """

    def _factory(**kwargs: object) -> _StubInterpreterWithPrintSink:
        """Construct a fresh stub interpreter capturing the print sink.

        Args:
            **kwargs: Keyword arguments forwarded by the mixin
                (notably ``print_sink``).

        Returns:
            _StubInterpreterWithPrintSink: A freshly constructed stub.
        """
        sink_raw = kwargs.get("print_sink")
        if callable(sink_raw):
            sink = cast("Callable[[str], None]", sink_raw)
            stub = _StubInterpreterWithPrintSink(print_sink=sink)
        else:
            stub = _StubInterpreterWithPrintSink(print_sink=None)
        stubs.append(stub)
        return stub

    monkeypatch.setattr(
        "intellicrack.ui.panels.hex_editor.pattern_editor.hexpat_interpreter_available",
        True,
    )
    monkeypatch.setattr(
        "intellicrack.ui.panels.hex_editor.pattern_editor.HexPatInterpreter_cls",
        _factory,
    )


class TestPrintSinkWiredToOutputWidgetEndToEnd:
    """The first apply must route real ``std::print`` output into the panel widget."""

    def test_real_pattern_print_reaches_output_widget(
        self,
        qapp: QApplication,
    ) -> None:
        """A real ``std::print`` pattern must surface its text in ``_pattern_print_output``.

        This exercises the full production pipeline with **no** interpreter
        double: the mixin constructs the real :class:`HexPatInterpreter`
        with ``print_sink=self._append_pattern_print_line`` and evaluates a
        pattern whose body calls ``builtin::std::io::print``. The assertion
        is that the exact emitted line lands in the panel's print-output
        widget, proving the constructor wired the sink to the UI append
        routine and that the sink is invoked end to end. If the mixin
        dropped the ``print_sink`` argument or routed it elsewhere, the
        widget would stay empty and this test would fail.

        Args:
            qapp: Session-scoped QApplication fixture.
        """
        _ = qapp
        harness = _PatternHarness(document=_StubDocument(b"\x00" * 64))
        try:
            harness.trigger_apply_via_interpreter(_REAL_PRINT_PATTERN, 0)
            widget_text = harness.print_output_widget().toPlainText()
            error_text = harness.error_display_widget().toPlainText()
        finally:
            harness.deleteLater()

        assert not error_text, f"real pattern must evaluate cleanly; interpreter error: {error_text!r}"
        assert widget_text.splitlines() == ["hello-ui-print-sink"], (
            f"expected the std::print payload routed to the panel widget; got {widget_text!r}"
        )

    def test_pattern_without_print_leaves_output_widget_empty(
        self,
        qapp: QApplication,
    ) -> None:
        """A real pattern that emits no ``std::print`` must leave the widget empty.

        This is the negative companion to the end-to-end gate: it confirms
        the widget content originates from ``std::print`` rather than from
        the apply machinery unconditionally writing text, so the positive
        test cannot pass for the wrong reason.

        Args:
            qapp: Session-scoped QApplication fixture.
        """
        _ = qapp
        harness = _PatternHarness(document=_StubDocument(b"\x00" * 64))
        try:
            harness.trigger_apply_via_interpreter("u8 silent @ 0x00;", 0)
            widget_text = harness.print_output_widget().toPlainText()
            error_text = harness.error_display_widget().toPlainText()
        finally:
            harness.deleteLater()

        assert not error_text, f"silent pattern must evaluate cleanly; interpreter error: {error_text!r}"
        assert not widget_text, f"a print-free pattern must leave the output widget empty; got {widget_text!r}"


class TestPrintSinkAppendsToOutputWidget:
    """Calling the bound print sink must append text to the panel's output widget."""

    def test_invoking_print_sink_appends_to_output_widget(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Driving the stub's print sink must append text to ``_pattern_print_output``.

        Args:
            qapp: Session-scoped QApplication fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _ = qapp
        stubs: list[_StubInterpreterWithPrintSink] = []
        _install_stub_interpreter(monkeypatch, stubs)

        harness = _PatternHarness(document=_StubDocument(b"\x00" * 64))
        try:
            TestPrintSinkAppendsToOutputWidget._assert_print_sink_writes_to_widget(harness, stubs)
        finally:
            harness.deleteLater()

    @staticmethod
    def _assert_print_sink_writes_to_widget(
        harness: _PatternHarness,
        stubs: list[_StubInterpreterWithPrintSink],
    ) -> None:
        """Trigger an apply and verify the print sink writes to the widget.

        Args:
            harness: PatternHarness driving the interpreter apply.
            stubs: List collecting created interpreter stubs.
        """
        harness.trigger_apply_via_interpreter("struct S { u32 x; };", 0)
        assert stubs
        sink = stubs[0].print_sink
        assert sink is not None
        sink("ui-print-line-from-pattern")
        widget = harness.print_output_widget()
        assert "ui-print-line-from-pattern" in widget.toPlainText()


class TestPrintSinkRebindsOnCachedInterpreter:
    """Subsequent applies must reinstall the sink on the cached interpreter."""

    def test_second_apply_reinstalls_print_sink(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A second apply against a cached interpreter must call ``set_print_sink``.

        Pre-audit code would have called ``HexPatInterpreter_cls()`` once
        without forwarding any sink, leaving every subsequent apply silent
        for the user. The remediation reinstalls the sink each apply.

        Args:
            qapp: Session-scoped QApplication fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _ = qapp
        stubs: list[_StubInterpreterWithPrintSink] = []
        _install_stub_interpreter(monkeypatch, stubs)

        harness = _PatternHarness(document=_StubDocument(b"\x00" * 64))
        try:
            TestPrintSinkRebindsOnCachedInterpreter._assert_sink_reinstalled_on_second_apply(harness, stubs)
        finally:
            harness.deleteLater()

    @staticmethod
    def _assert_sink_reinstalled_on_second_apply(
        harness: _PatternHarness,
        stubs: list[_StubInterpreterWithPrintSink],
    ) -> None:
        """Trigger two applies and verify the cached interpreter is rebound.

        Args:
            harness: PatternHarness driving the interpreter applies.
            stubs: List collecting created interpreter stubs.
        """
        harness.trigger_apply_via_interpreter("struct S { u32 x; };", 0)
        assert len(stubs) == 1
        cached = stubs[0]
        cached.print_sink = None
        harness.trigger_apply_via_interpreter("struct S2 { u32 y; };", 0)
        assert len(stubs) == 1, "interpreter must be cached across applies"
        assert callable(cached.print_sink), "cached interpreter must have its print sink reinstalled"


class TestPrintOutputClearedBetweenApplies:
    """Re-applying a pattern must clear stale ``std::print`` output."""

    def test_apply_clears_previous_print_output(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Old ``std::print`` content must be removed before a fresh apply.

        Args:
            qapp: Session-scoped QApplication fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _ = qapp
        stubs: list[_StubInterpreterWithPrintSink] = []
        _install_stub_interpreter(monkeypatch, stubs)

        harness = _PatternHarness(document=_StubDocument(b"\x00" * 64))
        try:
            widget = harness.print_output_widget()
            widget.setPlainText("stale-line-from-previous-run")
            harness.trigger_apply_via_interpreter("struct S { u32 x; };", 0)
            text = widget.toPlainText()
            assert "stale-line-from-previous-run" not in text, f"expected stale print output cleared on apply; got: {text!r}"
        finally:
            harness.deleteLater()
