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

from intellicrack.ui.panels.hex_editor._pattern_editor import PatternEditorMixin


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


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
    """Minimal document stub satisfying ``PatternEditorMixin._apply_via_interpreter``.

    The interpreter stub used in this test never actually reads from the
    document, so the stub only exposes the attribute slots the mixin checks
    on the document handle.
    """

    def __init__(self, data: bytes) -> None:
        """Capture the buffer the stub would return for reads.

        Args:
            data: Bytes the stub holds for length-related queries.
        """
        self._data: bytes = bytes(data)

    def length(self) -> int:
        """Return the buffer length in bytes.

        Returns:
            int: The stub buffer's size.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        """Return a slice of the stub buffer.

        Args:
            offset: Byte offset to start reading from.
            length: Number of bytes to return.

        Returns:
            bytes: Slice of the stub buffer.
        """
        return self._data[offset : offset + length]


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
        "intellicrack.ui.panels.hex_editor._pattern_editor.hexpat_interpreter_available",
        True,
    )
    monkeypatch.setattr(
        "intellicrack.ui.panels.hex_editor._pattern_editor.HexPatInterpreter_cls",
        _factory,
    )


class TestPrintSinkWiredAtConstruction:
    """The first apply must construct the interpreter with a callable print sink."""

    def test_constructor_receives_callable_print_sink(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``HexPatInterpreter_cls`` must be called with a callable ``print_sink``.

        Args:
            qapp: Session-scoped QApplication fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        _ = qapp
        stubs: list[_StubInterpreterWithPrintSink] = []
        _install_stub_interpreter(monkeypatch, stubs)

        harness = _PatternHarness(document=_StubDocument(b"\x00" * 64))
        try:
            harness.trigger_apply_via_interpreter("struct S { u32 x; };", 0)
        finally:
            harness.deleteLater()

        assert len(stubs) == 1, f"expected exactly one interpreter construction; got {len(stubs)}"
        assert callable(stubs[0].print_sink), "interpreter must be constructed with a callable print_sink"


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
            harness.trigger_apply_via_interpreter("struct S { u32 x; };", 0)
            assert stubs
            sink = stubs[0].print_sink
            assert sink is not None
            sink("ui-print-line-from-pattern")
            widget = harness.print_output_widget()
            assert "ui-print-line-from-pattern" in widget.toPlainText()
        finally:
            harness.deleteLater()


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
            harness.trigger_apply_via_interpreter("struct S { u32 x; };", 0)
            assert len(stubs) == 1
            cached = stubs[0]
            cached.print_sink = None
            harness.trigger_apply_via_interpreter("struct S2 { u32 y; };", 0)
            assert len(stubs) == 1, "interpreter must be cached across applies"
            assert callable(cached.print_sink), "cached interpreter must have its print sink reinstalled"
        finally:
            harness.deleteLater()


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
