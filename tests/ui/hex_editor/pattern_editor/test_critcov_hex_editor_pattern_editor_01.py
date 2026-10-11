# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the HexPat pattern editor mixin of the hex editor panel.

Every test drives the production mixin through a small concrete widget host that combines ``PatternEditorMixin`` with the real
``TemplatesMixin`` and a real ``HexEditorWidget``. The panes are the real Qt widgets built by ``_build_pattern_editor``, the document is a
genuine ``intellicrack_hexcore.HexDocument`` holding known bytes, the compiler and interpreter are the production HexPat pipeline, and the
asynchronous apply worker is the real ``GenericCallableWorker``. Expected values come from byte arithmetic, the Python standard library,
the documented HexPat syntax, or the hexcore template engine's own answer for the same input.
"""

from __future__ import annotations

import json
import struct
import threading
from typing import TYPE_CHECKING, Any

import intellicrack_hexcore
import pytest
from PyQt6.QtCore import QStringListModel, Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QLabel,
    QPlainTextEdit,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.core.hexpat import HexPatInterpreter, PatternRegistry
from intellicrack.core.hexpat.errors import HexPatError
from intellicrack.ui.panels.async_bridge import (
    GenericCallableWorker,
    drain_bridge_workers,
    drain_bridge_workers_for,
    run_callable_async,
)
from intellicrack.ui.panels.hex_editor import pattern_editor as pattern_editor_module
from intellicrack.ui.panels.hex_editor.pattern_editor import PatternEditorMixin
from intellicrack.ui.panels.hex_editor.templates import TemplatesMixin
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget
from intellicrack.ui.resources.theme_manager import ThemeManager


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

    from pytestqt.qtbot import QtBot

    from intellicrack.ui.panels.hex_editor.pattern_code_editor import PatternCodeEditor


pytestmark = pytest.mark.usefixtures("qapp")


_DATA: bytes = b"\x00\x00" + struct.pack("<HI", 0x5A4D, 0xDEADBEEF) + bytes(18)
_HEADER_DSL: str = "struct DSL_HDR {\n    le u16 magic;\n    le u32 size;\n};\n"
_PRINT_PATTERN: str = 'fn __ping() {\n    builtin::std::io::print("hello-from-print-sink");\n    return 0;\n};\nu8 __mark @ __ping();\n'
_ODD_MAGIC_SOURCE: str = '#pragma magic [0x0, "4D5"]\nu8 first @ 0x00;\n'
_NEW_SKELETON: str = "struct MY_HEADER {\n    le u16 magic;\n    le u32 size;\n};\n"
_WAIT_MS: int = 20_000
_FAIL_WAIT_MS: int = 3_000


class _PatternHost(PatternEditorMixin, TemplatesMixin, QWidget):
    """Concrete widget host that exposes the pattern editor mixin's slots to the tests."""

    def __init__(
        self,
        document: intellicrack_hexcore.HexDocument | None = None,
        hex_widget: object | None = None,
    ) -> None:
        """Create a host with none of the pattern editor panes built yet.

        Args:
            document: Real hexcore document the mixin operates on, or ``None``.
            hex_widget: Widget the mixin reads the cursor from and highlights through, or ``None``.
        """
        super().__init__()
        self._document = document
        self.document = document
        self._hex_widget = hex_widget
        self._file_path = None
        self._pattern_frame = None
        self._pattern_dsl_editor = None
        self._pattern_completer = None
        self._pattern_json_preview = None
        self._pattern_library_tree = None
        self._pattern_error_display = None
        self._pattern_print_output = None
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
        self._pattern_apply_worker = None
        self._pattern_print_buffer = None
        self._user_notifier = None
        self._bridge = None

    def build_editor(self) -> None:
        """Build the real pattern editor panes and place them inside the host."""
        frame = self._build_pattern_editor()
        self._pattern_frame = frame
        QVBoxLayout(self).addWidget(frame)

    def build_side_widgets(self) -> None:
        """Create the template tree and template combo box the apply paths fill."""
        self._templates_tree = QTreeWidget(self)
        self._template_combo = QComboBox(self)

    def drop_widget(self, attribute: str) -> None:
        """Forget one pane so the slots see it as not yet created.

        Args:
            attribute: Name of the mixin attribute to reset to ``None``.
        """
        setattr(self, attribute, None)

    def use_document(self, document: object | None) -> None:
        """Replace the document the mixin operates on.

        Args:
            document: The new document, or any other object, or ``None``.
        """
        self._document = document
        self.document = document

    def use_state(self, holder: object | None) -> None:
        """Install the state holder the apply paths notify.

        Args:
            holder: A state holder, or any other object, or ``None``.
        """
        self.state_holder = holder

    def use_registry(self, registry: object | None) -> None:
        """Install the community pattern registry.

        Args:
            registry: A pattern registry, or any other object, or ``None``.
        """
        self._pattern_registry = registry

    def use_interpreter(self, interpreter: object | None) -> None:
        """Install the cached interpreter.

        Args:
            interpreter: An interpreter, or any other object, or ``None``.
        """
        self._interpreter = interpreter

    def use_worker(self, worker: GenericCallableWorker | None) -> None:
        """Record a worker as the host's current apply worker.

        Args:
            worker: The worker to record, or ``None``.
        """
        self._pattern_apply_worker = worker

    def use_vsplit(self, splitter: QSplitter | None) -> None:
        """Install the vertical splitter the toggle slot resizes.

        Args:
            splitter: The splitter, or ``None``.
        """
        self._main_vsplit = splitter

    def set_compiled_json(self, text: str) -> None:
        """Seed the compiled JSON the apply and save slots work from.

        Args:
            text: JSON text to hold as the compiled template.
        """
        self._compiled_json = text

    def set_print_buffer(self, buffer: list[str] | None) -> None:
        """Seed the worker-thread print buffer.

        Args:
            buffer: The buffer list, or ``None`` for no buffering.
        """
        self._pattern_print_buffer = buffer

    @property
    def compiled_json(self) -> str:
        """The JSON text the mixin currently holds as compiled.

        Returns:
            str: The compiled template JSON, empty when nothing is compiled.
        """
        return self._compiled_json

    @property
    def print_buffer(self) -> list[str] | None:
        """The worker-thread print buffer.

        Returns:
            list[str] | None: Buffered lines, or ``None`` when no buffer is active.
        """
        return self._pattern_print_buffer

    @property
    def pattern_visible(self) -> bool:
        """Whether the mixin considers the pattern editor shown.

        Returns:
            bool: The visibility flag toggled by the toolbar button.
        """
        return self._pattern_visible

    @property
    def interpreter(self) -> object | None:
        """The cached interpreter.

        Returns:
            object | None: The interpreter the apply slot created, or ``None``.
        """
        return self._interpreter

    @property
    def worker(self) -> GenericCallableWorker | None:
        """The worker the apply slot started most recently.

        Returns:
            GenericCallableWorker | None: The worker, or ``None`` when nothing has run.
        """
        return self._pattern_apply_worker

    @property
    def frame(self) -> QFrame:
        """The pattern editor frame built by the mixin.

        Returns:
            QFrame: The frame widget.
        """
        frame = self._pattern_frame
        assert frame is not None
        return frame

    @property
    def dsl(self) -> PatternCodeEditor:
        """The DSL editor created by the mixin.

        Returns:
            PatternCodeEditor: The editor widget.
        """
        editor = self._pattern_dsl_editor
        assert editor is not None
        return editor

    @property
    def json_preview(self) -> QPlainTextEdit:
        """The JSON preview pane created by the mixin.

        Returns:
            QPlainTextEdit: The preview widget.
        """
        preview = self._pattern_json_preview
        assert preview is not None
        return preview

    @property
    def error_display(self) -> QPlainTextEdit:
        """The error pane created by the mixin.

        Returns:
            QPlainTextEdit: The error widget.
        """
        display = self._pattern_error_display
        assert display is not None
        return display

    @property
    def print_output(self) -> QPlainTextEdit:
        """The ``std::print`` pane created by the mixin.

        Returns:
            QPlainTextEdit: The print output widget.
        """
        output = self._pattern_print_output
        assert output is not None
        return output

    @property
    def status_label(self) -> QLabel:
        """The status label created by the mixin.

        Returns:
            QLabel: The status label.
        """
        label = self._pattern_status_label
        assert label is not None
        return label

    @property
    def library_tree(self) -> QTreeWidget:
        """The pattern library tree created by the mixin.

        Returns:
            QTreeWidget: The library tree.
        """
        tree = self._pattern_library_tree
        assert tree is not None
        return tree

    @property
    def templates_tree(self) -> QTreeWidget:
        """The template preview tree created by ``build_side_widgets``.

        Returns:
            QTreeWidget: The template tree.
        """
        tree = self._templates_tree
        assert tree is not None
        return tree

    @property
    def template_combo(self) -> QComboBox:
        """The template combo box created by ``build_side_widgets``.

        Returns:
            QComboBox: The combo box.
        """
        combo = self._template_combo
        assert combo is not None
        return combo

    def populate_template_tree(self, fields: list[dict[str, object]]) -> None:
        """Invoke the template tree population.

        Args:
            fields: Field entries to render.
        """
        self._populate_template_tree(fields)

    def highlight(self, fields: list[dict[str, object]]) -> None:
        """Invoke the hex view highlighting.

        Args:
            fields: Field entries to highlight.
        """
        self._highlight_template_fields(fields)

    def toggle(self) -> None:
        """Invoke the slot the Pattern Editor toolbar button triggers."""
        self._toggle_pattern_editor()

    def do_compile(self) -> None:
        """Invoke the slot the Compile button triggers."""
        self._on_pattern_compile()

    def do_apply(self) -> None:
        """Invoke the slot the Apply at Cursor button triggers."""
        self._on_pattern_apply()

    def do_save(self) -> None:
        """Invoke the slot the Save button triggers."""
        self._on_pattern_save()

    def do_open(self) -> None:
        """Invoke the slot the Open button triggers."""
        self._on_pattern_open()

    def do_new(self) -> None:
        """Invoke the slot the New button triggers."""
        self._on_pattern_new()

    def refresh_completer(self) -> None:
        """Invoke the completer refresh."""
        self._refresh_pattern_completer()

    def append_print_line(self, line: str) -> None:
        """Invoke the print output append.

        Args:
            line: Line to append.
        """
        self._append_pattern_print_line(line)

    def pattern_print_sink(self, line: str) -> None:
        """Invoke the interpreter print sink.

        Args:
            line: Line the interpreter would print.
        """
        self._pattern_print_sink(line)

    def apply_via_interpreter(self, source: str, offset: int) -> None:
        """Invoke the interpreter apply path.

        Args:
            source: HexPat source to execute.
            offset: Byte offset to apply at.
        """
        self._apply_via_interpreter(source, offset)

    def flush_print_buffer(self) -> None:
        """Invoke the print buffer flush."""
        self._flush_pattern_print_buffer()

    def interpreter_error(self, exc: object) -> None:
        """Deliver an exception to the interpreter error handler.

        Args:
            exc: Exception object a worker emitted.
        """
        self._on_interpreter_apply_error(exc)

    def library_clicked(self, item: QTreeWidgetItem) -> None:
        """Invoke the library click slot on a tree item.

        Args:
            item: The clicked tree item.
        """
        self._on_pattern_library_clicked(item, 0)

    def load_library(self, file_path: str, name: str) -> None:
        """Invoke the community pattern loader.

        Args:
            file_path: Path of the ``.hexpat`` file.
            name: Display name of the pattern.
        """
        self._load_hexpat_from_library(file_path, name)

    def populate_library(self) -> None:
        """Invoke the library tree population."""
        self._populate_pattern_library()

    def populate_hexpat_entries(self) -> None:
        """Invoke the community pattern population."""
        self._populate_hexpat_library_entries()

    def refresh_combo(self) -> None:
        """Invoke the template combo refresh."""
        self._refresh_template_combo()


def _header_template_json(name: str) -> str:
    """Build a two-field struct template in the hexcore JSON schema.

    Args:
        name: Template name.

    Returns:
        str: JSON text declaring a coloured ``u16`` and an uncoloured ``u32``, both little endian.
    """
    return json.dumps({
        "name": name,
        "description": "two field header",
        "default_endianness": "little",
        "fields": [
            {"name": "magic", "field_type": {"type": "UInt16"}, "description": "", "color": "#112233"},
            {"name": "size", "field_type": {"type": "UInt32"}, "description": ""},
        ],
    })


def _rows(tree: QTreeWidget) -> list[list[str]]:
    """Read the Field, Offset and Size columns of every top-level tree row.

    Args:
        tree: Tree to read.

    Returns:
        list[list[str]]: One list of three column texts per top-level row.
    """
    rows: list[list[str]] = []
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        assert item is not None
        rows.append([item.text(column) for column in range(3)])
    return rows


def _top_level_names(tree: QTreeWidget) -> list[str]:
    """Read the first column of every top-level tree row.

    Args:
        tree: Tree to read.

    Returns:
        list[str]: Column zero text of each top-level item, in order.
    """
    names: list[str] = []
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        assert item is not None
        names.append(item.text(0))
    return names


def _event_log(state: HexDocumentState) -> list[tuple[HexDocumentEvent, dict[str, Any]]]:
    """Subscribe an observer to a state holder and return the list it fills.

    Args:
        state: Real state holder the host notifies.

    Returns:
        list[tuple[HexDocumentEvent, dict[str, Any]]]: Live list of every ``(event, payload)`` delivered after this call.
    """
    events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

    def _collect(event: HexDocumentEvent, data: dict[str, Any]) -> None:
        """Record one delivered notification.

        Args:
            event: Event type delivered by the state holder.
            data: Payload delivered with the event.
        """
        events.append((event, dict(data)))

    state.register_callback(_collect, source_id="critcov-observer")
    return events


def _payloads(events: list[tuple[HexDocumentEvent, dict[str, Any]]], wanted: HexDocumentEvent) -> list[dict[str, Any]]:
    """Select the payloads recorded for one event type.

    Args:
        events: Recorded notifications.
        wanted: Event type to select.

    Returns:
        list[dict[str, Any]]: Payloads of that event type, in delivery order.
    """
    return [data for event, data in events if event is wanted]


def _file_picker(path: str) -> Callable[..., tuple[str, str]]:
    """Build a file-dialog replacement that picks a fixed path.

    Args:
        path: Path the picker reports as chosen.

    Returns:
        Callable[..., tuple[str, str]]: Function with the static dialog's result shape.
    """

    def _pick(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Report the fixed path as the user's choice.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, str]: The path and an empty filter.
        """
        return (path, "")

    return _pick


def _odd_hex_message() -> str:
    """Compute the standard library's error text for an odd-length hex string.

    Returns:
        str: The message of the ``ValueError`` raised by ``bytes.fromhex("4D5")``.
    """
    with pytest.raises(ValueError, match="fromhex") as caught:
        bytes.fromhex("4D5")
    return str(caught.value)


def _run_in_thread(target: Callable[[str], None], argument: str) -> None:
    """Run a callable once on a foreign thread and join that thread.

    Args:
        target: Callable to run.
        argument: The single argument passed to it.
    """
    thread = threading.Thread(target=target, args=(argument,))
    thread.start()
    thread.join()


def _wait_for_status(qtbot: QtBot, host: _PatternHost, text: str) -> None:
    """Wait until the host's status label shows a given text.

    Args:
        qtbot: pytest-qt fixture used to spin the event loop.
        host: Host whose worker was started.
        text: Status text to wait for.
    """
    qtbot.waitUntil(lambda: host.status_label.text() == text, timeout=_WAIT_MS)


def _library_child(host: _PatternHost, text: str) -> QTreeWidgetItem:
    """Add a leaf item below a new top-level item of the library tree.

    Args:
        host: Host whose library tree receives the items.
        text: Caption of the leaf item.

    Returns:
        QTreeWidgetItem: The leaf item, whose parent is the new top-level item.
    """
    root = QTreeWidgetItem(["Root"])
    host.library_tree.addTopLevelItem(root)
    child = QTreeWidgetItem([text])
    root.addChild(child)
    return child


@pytest.fixture
def interpreter_unavailable() -> Generator[None]:
    """Mark the HexPat interpreter as unavailable for the duration of a test.

    Yields:
        None: Control passes to the test; the original flag is restored afterwards.
    """
    original: object = getattr(pattern_editor_module, "hexpat_interpreter_available")
    setattr(pattern_editor_module, "hexpat_interpreter_available", False)
    try:
        yield
    finally:
        setattr(pattern_editor_module, "hexpat_interpreter_available", original)


@pytest.fixture
def compiler_unavailable() -> Generator[None]:
    """Mark the HexPat compiler as unavailable for the duration of a test.

    Yields:
        None: Control passes to the test; the original flag is restored afterwards.
    """
    original: object = getattr(pattern_editor_module, "hexpat_available")
    setattr(pattern_editor_module, "hexpat_available", False)
    try:
        yield
    finally:
        setattr(pattern_editor_module, "hexpat_available", original)


@pytest.fixture
def document() -> intellicrack_hexcore.HexDocument:
    """Open a real document over the sample bytes.

    Returns:
        intellicrack_hexcore.HexDocument: Document holding ``_DATA``.
    """
    return intellicrack_hexcore.HexDocument.open_bytes(_DATA)


@pytest.fixture
def hex_widget(qtbot: QtBot, document: intellicrack_hexcore.HexDocument) -> HexEditorWidget:
    """Create a real hex editor widget showing the sample document.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
        document: Document to display.

    Returns:
        HexEditorWidget: Widget with the document attached.
    """
    widget = HexEditorWidget()
    qtbot.addWidget(widget)
    widget.set_document(document)
    return widget


@pytest.fixture
def host(
    qtbot: QtBot,
    document: intellicrack_hexcore.HexDocument,
    hex_widget: HexEditorWidget,
) -> Generator[_PatternHost]:
    """Create a host with every pane built and whose workers are joined on teardown.

    Args:
        qtbot: pytest-qt fixture that owns the host.
        document: Document the mixin operates on.
        hex_widget: Widget the mixin reads the cursor from.

    Yields:
        _PatternHost: Host with the pattern editor panes and the template widgets built.
    """
    instance = _PatternHost(document, hex_widget)
    qtbot.addWidget(instance)
    instance.build_editor()
    instance.build_side_widgets()
    try:
        yield instance
    finally:
        drain_bridge_workers_for(instance)
        drain_bridge_workers()


@pytest.fixture
def bare(qtbot: QtBot, document: intellicrack_hexcore.HexDocument) -> Generator[_PatternHost]:
    """Create a host with a document but none of the panes and no hex widget.

    Args:
        qtbot: pytest-qt fixture that owns the host.
        document: Document the mixin operates on.

    Yields:
        _PatternHost: Host with every optional pane absent.
    """
    instance = _PatternHost(document)
    qtbot.addWidget(instance)
    try:
        yield instance
    finally:
        drain_bridge_workers_for(instance)
        drain_bridge_workers()


def test_populate_template_tree_without_a_tree_is_a_noop(bare: _PatternHost) -> None:
    """Rendering template fields with no tree built leaves the host without any tree.

    Args:
        bare: Host with no panes.
    """
    bare.populate_template_tree([{"name": "magic", "offset": 2, "size": 2, "type": "u16"}])
    assert bare.findChildren(QTreeWidget) == []


def test_highlight_template_fields_ignores_missing_or_incapable_widgets(
    qtbot: QtBot,
    document: intellicrack_hexcore.HexDocument,
    hex_widget: HexEditorWidget,
) -> None:
    """A host without a hex widget, or with one lacking ``highlight_offsets``, highlights nothing and does not raise.

    A host holding a real widget, given the same fields, does reach it.

    Args:
        qtbot: pytest-qt fixture that owns the hosts.
        document: Real document the hosts hold.
        hex_widget: Real widget that does support highlighting.
    """
    fields: list[dict[str, object]] = [{"offset": 1, "size": 2, "color": "#112233"}]
    for widget in (None, object()):
        instance = _PatternHost(document, widget)
        qtbot.addWidget(instance)
        instance.highlight(fields)
    capable = _PatternHost(document, hex_widget)
    qtbot.addWidget(capable)
    capable.highlight(fields)
    sources: dict[str, list[tuple[int, int, str]]] = getattr(hex_widget, "_highlight_sources")
    assert sources["pattern"] == [(1, 2, "#112233")]


def test_highlight_template_fields_uses_field_color_then_the_theme_default(
    host: _PatternHost,
    hex_widget: HexEditorWidget,
) -> None:
    """Only fields with integer offset and size are highlighted; a missing or non-text colour takes the theme's pattern colour.

    Args:
        host: Host with the hex widget attached.
        hex_widget: Real widget the host highlights through.
    """
    host.highlight([
        {"offset": 2, "size": 2, "color": "#112233"},
        {"offset": 4, "size": 4},
        {"offset": "0x10", "size": 4, "color": "#445566"},
        {"offset": 9, "size": "wide", "color": "#778899"},
        {"offset": 10, "size": 1, "color": 7},
    ])
    default_color = ThemeManager.get_instance().get_hex_mark_colors()["pattern_field"]
    sources: dict[str, list[tuple[int, int, str]]] = getattr(hex_widget, "_highlight_sources")
    assert sources["pattern"] == [(2, 2, "#112233"), (4, 4, default_color), (10, 1, default_color)]


def test_highlight_template_fields_skips_the_widget_when_no_field_qualifies(
    host: _PatternHost,
    hex_widget: HexEditorWidget,
) -> None:
    """Fields without integer geometry never reach the widget, so no highlight source is created.

    Args:
        host: Host with the hex widget attached.
        hex_widget: Real widget the host highlights through.
    """
    host.highlight([{"offset": "0x10", "size": 4}, {"name": "no geometry"}])
    sources: dict[str, list[tuple[int, int, str]]] = getattr(hex_widget, "_highlight_sources")
    assert "pattern" not in sources


def test_toggle_pattern_editor_without_frame_or_splitter(bare: _PatternHost) -> None:
    """The visibility flag flips on every toggle even when no frame or splitter exists.

    Args:
        bare: Host with no panes.
    """
    bare.toggle()
    assert bare.pattern_visible is True
    bare.toggle()
    assert bare.pattern_visible is False


def test_toggle_pattern_editor_shows_frame_without_a_splitter(host: _PatternHost) -> None:
    """With a frame but no splitter, toggling shows and hides the frame and does not touch the library.

    Args:
        host: Host with the pattern editor frame built.
    """
    host.frame.setVisible(False)
    host.toggle()
    assert not host.frame.isHidden()
    assert host.library_tree.topLevelItemCount() == 0
    host.toggle()
    assert host.frame.isHidden()


def test_toggle_pattern_editor_shows_then_hides_frame_and_loads_library_once(qtbot: QtBot, host: _PatternHost) -> None:
    """Showing the editor loads the library; hiding it hides the frame and leaves the library as it was.

    Args:
        qtbot: pytest-qt fixture that owns the splitter.
        host: Host with the pattern editor frame built.
    """
    splitter = QSplitter(Qt.Orientation.Vertical)
    qtbot.addWidget(splitter)
    splitter.addWidget(QWidget())
    splitter.addWidget(host.frame)
    splitter.addWidget(QWidget())
    host.frame.setVisible(False)
    host.use_vsplit(splitter)

    host.toggle()
    assert host.pattern_visible is True
    assert not host.frame.isHidden()
    assert _top_level_names(host.library_tree)[:2] == ["Built-in", "User"]

    host.library_tree.addTopLevelItem(QTreeWidgetItem(["sentinel"]))
    host.toggle()
    assert host.pattern_visible is False
    assert host.frame.isHidden()
    assert "sentinel" in _top_level_names(host.library_tree)


def test_pattern_compile_ignores_missing_editor_and_blank_source(host: _PatternHost) -> None:
    """Compile does nothing without an editor or with only whitespace in it, and leaves the panes alone.

    Args:
        host: Host with every pane built.
    """
    host.status_label.setText("untouched")
    host.json_preview.setPlainText("keep")
    host.dsl.setPlainText("  \n\t ")
    host.do_compile()
    assert not host.compiled_json
    assert host.status_label.text() == "untouched"
    assert host.json_preview.toPlainText() == "keep"

    host.drop_widget("_pattern_dsl_editor")
    host.do_compile()
    assert not host.compiled_json
    assert host.status_label.text() == "untouched"


def test_pattern_compile_shows_json_and_clears_errors(host: _PatternHost) -> None:
    """A valid struct compiles to a JSON template shown in the preview, with the error pane cleared.

    Args:
        host: Host with every pane built.
    """
    host.error_display.setPlainText("stale error")
    host.dsl.setPlainText(_HEADER_DSL)
    host.do_compile()
    compiled = host.compiled_json
    template = json.loads(compiled)
    assert template["name"] == "DSL_HDR"
    assert [field["name"] for field in template["fields"]] == ["magic", "size"]
    assert [field["field_type"]["type"] for field in template["fields"]] == ["UInt16", "UInt32"]
    assert host.json_preview.toPlainText() == compiled
    assert not host.error_display.toPlainText()
    assert host.status_label.text() == "Compiled successfully"


def test_pattern_compile_succeeds_without_output_panes(host: _PatternHost) -> None:
    """Compiling still stores the JSON when the preview, error and status panes do not exist.

    Args:
        host: Host with every pane built.
    """
    for attribute in ("_pattern_json_preview", "_pattern_error_display", "_pattern_status_label"):
        host.drop_widget(attribute)
    host.dsl.setPlainText(_HEADER_DSL)
    host.do_compile()
    assert json.loads(host.compiled_json)["name"] == "DSL_HDR"


def test_pattern_compile_reports_an_unavailable_compiler(host: _PatternHost, compiler_unavailable: None) -> None:
    """With no compiler the error pane says so, nothing is compiled, and a missing error pane is tolerated.

    Args:
        host: Host with every pane built.
        compiler_unavailable: Fixture that flags the compiler as missing.
    """
    del compiler_unavailable
    host.dsl.setPlainText(_HEADER_DSL)
    host.do_compile()
    assert host.error_display.toPlainText() == "HexPat compiler not available"
    assert not host.compiled_json
    assert not host.json_preview.toPlainText()

    host.drop_widget("_pattern_error_display")
    host.do_compile()
    assert not host.compiled_json


def test_pattern_compile_reports_value_errors_and_discards_stale_json(host: _PatternHost) -> None:
    """A source the preprocessor rejects with ``ValueError`` shows that error, flags failure and drops older JSON.

    An odd-length ``#pragma magic`` byte string makes ``bytes.fromhex`` raise inside the preprocessor.

    Args:
        host: Host with every pane built.
    """
    host.set_compiled_json("stale-json")
    host.json_preview.setPlainText("stale preview")
    host.dsl.setPlainText(_ODD_MAGIC_SOURCE)
    host.do_compile()
    assert not host.compiled_json
    assert host.error_display.toPlainText() == _odd_hex_message()
    assert host.status_label.text() == "Compilation failed"
    assert host.json_preview.toPlainText() == "stale preview"


def test_pattern_compile_failure_tolerates_missing_output_panes(host: _PatternHost) -> None:
    """A failing compile still discards the stored JSON when the error and status panes do not exist.

    Args:
        host: Host with every pane built.
    """
    host.drop_widget("_pattern_error_display")
    host.drop_widget("_pattern_status_label")
    host.set_compiled_json("stale-json")
    host.dsl.setPlainText(_ODD_MAGIC_SOURCE)
    host.do_compile()
    assert not host.compiled_json


def test_pattern_compile_reports_hexpat_errors_with_line_and_column(host: _PatternHost) -> None:
    """A source the HexPat compiler itself rejects is reported in the error pane as ``Line N, Col M: message``.

    A comment-only source has no struct declaration, so the compiler raises ``HexPatError("no struct declaration found")`` with line
    and column zero. The panel must catch it instead of letting it escape the Compile button's slot.

    Args:
        host: Host with every pane built.
    """
    host.set_compiled_json("stale-json")
    host.dsl.setPlainText("// nothing but a comment\n")
    host.do_compile()
    assert not host.compiled_json
    assert host.error_display.toPlainText() == "Line 0, Col 0: no struct declaration found"
    assert host.status_label.text() == "Compilation failed"


def test_pattern_apply_does_nothing_without_a_document(host: _PatternHost, document: intellicrack_hexcore.HexDocument) -> None:
    """Without a document the Apply slot registers nothing and reports no error.

    Args:
        host: Host with every pane built.
        document: Real document that must stay untouched.
    """
    templates_before = document.list_templates()
    host.drop_widget("_pattern_dsl_editor")
    host.set_compiled_json(_header_template_json("NODOC_HDR"))
    host.use_document(None)
    host.do_apply()
    assert document.list_templates() == templates_before
    assert not host.error_display.toPlainText()
    assert not host.status_label.text()


def test_pattern_apply_with_nothing_to_apply_registers_nothing(host: _PatternHost, document: intellicrack_hexcore.HexDocument) -> None:
    """With no compiled JSON and no compilable source, Apply returns quietly instead of registering an empty template.

    Args:
        host: Host with every pane built.
        document: Real document that must stay untouched.
    """
    templates_before = document.list_templates()
    host.dsl.setPlainText("   ")
    host.do_apply()
    host.drop_widget("_pattern_dsl_editor")
    host.do_apply()
    assert document.list_templates() == templates_before
    assert not host.error_display.toPlainText()
    assert not host.status_label.text()


def test_pattern_apply_registers_template_and_fills_every_pane(
    host: _PatternHost,
    hex_widget: HexEditorWidget,
    document: intellicrack_hexcore.HexDocument,
) -> None:
    """Apply registers the compiled template, decodes it at the cursor and updates tree, highlights, combo, status and observers.

    The cursor sits at offset 2, where the sample bytes hold the little-endian ``u16`` 0x5A4D followed by a ``u32``.

    Args:
        host: Host with every pane built.
        hex_widget: Real widget holding the cursor.
        document: Real document the template is registered on.
    """
    state = HexDocumentState()
    events = _event_log(state)
    host.use_state(state)
    host.drop_widget("_pattern_dsl_editor")
    host.set_compiled_json(_header_template_json("APPLY_HDR"))
    hex_widget.goto_offset(2)
    assert getattr(hex_widget, "_cursor_offset") == 2

    host.do_apply()

    assert "APPLY_HDR" in [name for name, _description in document.list_templates()]
    assert _rows(host.templates_tree) == [["magic", "0x00000002", "2"], ["size", "0x00000004", "4"]]
    default_color = ThemeManager.get_instance().get_hex_mark_colors()["pattern_field"]
    sources: dict[str, list[tuple[int, int, str]]] = getattr(hex_widget, "_highlight_sources")
    assert sources["pattern"] == [(2, 2, "#112233"), (4, 4, default_color)]
    combo_items = [host.template_combo.itemText(index) for index in range(host.template_combo.count())]
    assert combo_items == [name for name, _description in document.list_templates()]
    assert host.status_label.text() == "Applied 'APPLY_HDR' at offset 2"
    assert _payloads(events, HexDocumentEvent.TEMPLATE_REGISTERED) == [{"template_name": "APPLY_HDR"}]
    assert _payloads(events, HexDocumentEvent.PATTERN_EXECUTED) == [{"pattern_name": "APPLY_HDR", "field_count": 2}]


def test_pattern_apply_fills_the_value_column_with_the_decoded_value(
    host: _PatternHost,
    hex_widget: HexEditorWidget,
    document: intellicrack_hexcore.HexDocument,
) -> None:
    """The ``Value`` column of the template tree shows each field's decoded value as the template engine reports it.

    Args:
        host: Host with every pane built.
        hex_widget: Real widget holding the cursor.
        document: Real document the template is registered on.
    """
    host.drop_widget("_pattern_dsl_editor")
    host.set_compiled_json(_header_template_json("VALUE_HDR"))
    hex_widget.goto_offset(2)
    host.do_apply()
    expected = [str(field["display_value"]) for field in document.apply_template("VALUE_HDR", 2)]
    tree = host.templates_tree
    shown: list[str] = []
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        assert item is not None
        shown.append(item.text(3))
    assert all(expected)
    assert shown == expected


def test_pattern_apply_compiles_the_editor_source_when_the_interpreter_is_unavailable(
    host: _PatternHost,
    hex_widget: HexEditorWidget,
    document: intellicrack_hexcore.HexDocument,
    interpreter_unavailable: None,
) -> None:
    """Without the interpreter, Apply compiles the editor's DSL itself, registers the result and decodes it at the cursor.

    Args:
        host: Host with every pane built.
        hex_widget: Real widget holding the cursor.
        document: Real document the template is registered on.
        interpreter_unavailable: Fixture that flags the interpreter as missing.
    """
    del interpreter_unavailable
    state = HexDocumentState()
    events = _event_log(state)
    host.use_state(state)
    host.dsl.setPlainText(_HEADER_DSL)
    hex_widget.goto_offset(2)

    host.do_apply()

    assert json.loads(host.compiled_json)["name"] == "DSL_HDR"
    assert "DSL_HDR" in [name for name, _description in document.list_templates()]
    assert _rows(host.templates_tree) == [["magic", "0x00000002", "2"], ["size", "0x00000004", "4"]]
    assert host.status_label.text() == "Applied 'DSL_HDR' at offset 2"
    assert _payloads(events, HexDocumentEvent.PATTERN_EXECUTED) == [{"pattern_name": "DSL_HDR", "field_count": 2}]


def test_pattern_apply_tolerates_missing_widgets_and_unwired_state_holders(
    bare: _PatternHost,
    document: intellicrack_hexcore.HexDocument,
) -> None:
    """Apply registers the template with no panes, and ignores a state holder that has no notification hooks.

    Args:
        bare: Host with no panes.
        document: Real document the template is registered on.
    """
    bare.set_compiled_json(_header_template_json("BARE_HDR"))
    bare.do_apply()
    assert "BARE_HDR" in [name for name, _description in document.list_templates()]

    bare.use_state(object())
    bare.do_apply()
    assert "BARE_HDR" in [name for name, _description in document.list_templates()]


def test_pattern_apply_reports_registration_failures(host: _PatternHost, document: intellicrack_hexcore.HexDocument) -> None:
    """JSON the engine rejects shows ``Apply failed`` with the engine's message and registers nothing.

    Args:
        host: Host with every pane built.
        document: Real document that must stay untouched.
    """
    templates_before = document.list_templates()
    host.drop_widget("_pattern_dsl_editor")
    host.set_compiled_json('{"name": "BROKEN", not valid json')
    host.do_apply()
    message = host.error_display.toPlainText()
    assert message.startswith("Apply failed: ")
    assert len(message) > len("Apply failed: ")
    assert host.status_label.text() == "Apply failed"
    assert host.templates_tree.topLevelItemCount() == 0
    assert document.list_templates() == templates_before


def test_pattern_apply_failure_tolerates_missing_error_and_status_panes(
    bare: _PatternHost,
    document: intellicrack_hexcore.HexDocument,
) -> None:
    """A rejected template with no error or status pane still registers nothing and does not raise.

    Args:
        bare: Host with no panes.
        document: Real document that must stay untouched.
    """
    templates_before = document.list_templates()
    bare.set_compiled_json("{not json")
    bare.do_apply()
    assert document.list_templates() == templates_before


def test_apply_via_interpreter_does_nothing_without_a_document(host: _PatternHost) -> None:
    """With no document the interpreter path neither builds an interpreter nor starts a worker.

    Args:
        host: Host with every pane built.
    """
    host.use_document(None)
    host.apply_via_interpreter("u8 first @ 0x00;", 0)
    assert host.interpreter is None
    assert host.worker is None
    assert not host.status_label.text()


def test_apply_via_interpreter_is_skipped_while_a_previous_worker_runs(host: _PatternHost) -> None:
    """While an apply worker is still running a second apply changes nothing.

    Args:
        host: Host with every pane built.
    """
    release = threading.Event()
    blocker = run_callable_async(release.wait, 30.0)
    try:
        host.use_worker(blocker)
        host.print_output.setPlainText("kept")
        host.apply_via_interpreter("u8 first @ 0x00;", 0)
        assert host.interpreter is None
        assert host.worker is blocker
        assert host.print_output.toPlainText() == "kept"
        assert not host.status_label.text()
    finally:
        release.set()
        drain_bridge_workers()


def test_interpreter_apply_routes_worker_thread_prints_to_the_print_pane(
    qtbot: QtBot,
    host: _PatternHost,
    hex_widget: HexEditorWidget,
) -> None:
    """A pattern's ``std::print`` runs on the worker thread, is buffered there, and reaches the print pane once the worker finishes.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host with every pane built.
        hex_widget: Real widget that receives the field highlights.
    """
    state = HexDocumentState()
    events = _event_log(state)
    host.use_state(state)
    host.print_output.setPlainText("stale")

    host.apply_via_interpreter(_PRINT_PATTERN, 0)
    _wait_for_status(qtbot, host, "Executed at offset 0 (1 fields)")

    assert host.print_output.toPlainText() == "hello-from-print-sink"
    assert host.print_buffer is None
    assert _rows(host.templates_tree) == [["__mark", "0x00000000", "1"]]
    assert not host.error_display.toPlainText()
    sources: dict[str, list[tuple[int, int, str]]] = getattr(hex_widget, "_highlight_sources")
    assert [(offset, size) for offset, size, _color in sources["pattern"]] == [(0, 1)]
    assert _payloads(events, HexDocumentEvent.TEMPLATE_REGISTERED) == [{"template_name": "<inline>"}]
    assert _payloads(events, HexDocumentEvent.PATTERN_EXECUTED) == [{"pattern_name": "<inline>", "field_count": 1}]


def test_interpreter_apply_ignores_a_state_holder_without_notification_hooks(qtbot: QtBot, host: _PatternHost) -> None:
    """A state holder lacking the notification hooks does not stop the decoded fields from being shown.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host with every pane built.
    """
    host.use_state(object())
    host.apply_via_interpreter("u8 first @ 0x00;\n", 0)
    _wait_for_status(qtbot, host, "Executed at offset 0 (1 fields)")
    assert _rows(host.templates_tree) == [["first", "0x00000000", "1"]]


def test_interpreter_apply_reports_value_errors_from_the_worker(qtbot: QtBot, host: _PatternHost) -> None:
    """A ``ValueError`` raised while executing is delivered to the error pane and the status label.

    The odd-length ``#pragma magic`` byte string makes the preprocessor raise ``ValueError`` inside the worker thread.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host with every pane built.
    """
    host.error_display.setPlainText("stale error")
    host.apply_via_interpreter(_ODD_MAGIC_SOURCE, 0)
    _wait_for_status(qtbot, host, "Execution failed")
    assert host.error_display.toPlainText() == _odd_hex_message()
    assert host.templates_tree.topLevelItemCount() == 0


def test_interpreter_apply_reports_pattern_syntax_errors_from_the_worker(qtbot: QtBot, host: _PatternHost) -> None:
    """A syntax error in the pattern is reported as ``Execution failed`` with its message instead of leaving ``Executing...`` forever.

    ``0x`` without digits is an invalid hexadecimal literal, which the HexPat lexer reports as a ``HexPatError``.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host with every pane built.
    """
    host.apply_via_interpreter("u8 first @ 0x;\n", 0)
    qtbot.waitUntil(lambda: host.status_label.text() == "Execution failed", timeout=_FAIL_WAIT_MS)
    assert "Invalid hexadecimal literal" in host.error_display.toPlainText()


def test_interpreter_error_handler_formats_location_and_flushes_buffered_prints(host: _PatternHost) -> None:
    """An error carrying a line and column is shown with that location, after any buffered print output is flushed.

    Args:
        host: Host with every pane built.
    """
    host.set_print_buffer(["queued one", "queued two"])
    host.interpreter_error(HexPatError("bad token", 3, 7))
    shown = host.error_display.toPlainText()
    assert shown.startswith("Line 3, Col 7: ")
    assert shown.endswith("bad token")
    assert host.status_label.text() == "Execution failed"
    assert host.print_output.toPlainText() == "queued one\nqueued two"
    assert host.print_buffer is None

    host.interpreter_error(ValueError("plain failure"))
    assert host.error_display.toPlainText() == "plain failure"


def test_interpreter_error_handler_tolerates_missing_panes(bare: _PatternHost) -> None:
    """The error handler runs with no error, status or print pane and still clears the print buffer.

    Args:
        bare: Host with no panes.
    """
    bare.set_print_buffer(["queued"])
    bare.interpreter_error(ValueError("boom"))
    assert bare.print_buffer is None


def test_print_sink_buffers_lines_arriving_from_foreign_threads(host: _PatternHost) -> None:
    """A line printed from a non-GUI thread is buffered instead of touching the print pane.

    Args:
        host: Host with every pane built.
    """
    host.set_print_buffer([])
    _run_in_thread(host.pattern_print_sink, "from worker")
    assert host.print_buffer == ["from worker"]
    assert not host.print_output.toPlainText()


def test_print_sink_drops_foreign_thread_lines_when_no_buffer_is_active(host: _PatternHost) -> None:
    """With no buffer active a foreign-thread line is dropped rather than raising or reaching the pane.

    Args:
        host: Host with every pane built.
    """
    host.set_print_buffer(None)
    _run_in_thread(host.pattern_print_sink, "lost line")
    assert host.print_buffer is None
    assert not host.print_output.toPlainText()


def test_append_print_line_appends_to_the_pane_and_tolerates_its_absence(host: _PatternHost, bare: _PatternHost) -> None:
    """Printed lines are appended one per line to the pane, and a host without the pane ignores them.

    Args:
        host: Host with every pane built.
        bare: Host with no panes.
    """
    host.append_print_line("alpha")
    host.append_print_line("beta")
    assert host.print_output.toPlainText() == "alpha\nbeta"
    bare.append_print_line("ignored")


def test_flush_print_buffer_moves_buffered_lines_into_the_pane(host: _PatternHost) -> None:
    """Flushing appends the buffered lines in order and discards the buffer; flushing again changes nothing.

    Args:
        host: Host with every pane built.
    """
    host.set_print_buffer(["first", "second"])
    host.flush_print_buffer()
    assert host.print_output.toPlainText() == "first\nsecond"
    assert host.print_buffer is None
    host.flush_print_buffer()
    assert host.print_output.toPlainText() == "first\nsecond"


def test_refresh_pattern_completer_keeps_names_until_a_run_has_succeeded(host: _PatternHost) -> None:
    """An interpreter that has not executed anything has no type registry, so the editor's completion names stay as they were.

    Args:
        host: Host with every pane built.
    """
    host.use_interpreter(HexPatInterpreter())
    host.dsl.update_type_names(["zz_sentinel"])
    host.refresh_completer()
    model: QStringListModel = getattr(host.dsl, "_model")
    assert model.stringList() == ["zz_sentinel"]


def test_save_compiles_first_and_writes_the_editor_text_as_hexpat(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    host: _PatternHost,
) -> None:
    """Saving a ``.hexpat`` file compiles the editor source first and writes the editor text itself.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory receiving the file.
        host: Host with every pane built.
    """
    target = tmp_path / "out.hexpat"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_picker(str(target)))
    host.dsl.setPlainText(_HEADER_DSL)
    host.do_save()
    assert target.read_text(encoding="utf-8") == _HEADER_DSL
    assert json.loads(host.compiled_json)["name"] == "DSL_HDR"
    assert host.status_label.text() == "Saved to out.hexpat"


def test_save_json_writes_the_compiled_template(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: _PatternHost) -> None:
    """Saving a ``.json`` file writes the compiled template instead of the DSL text.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory receiving the file.
        host: Host with every pane built.
    """
    target = tmp_path / "out.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_picker(str(target)))
    host.dsl.setPlainText(_HEADER_DSL)
    host.do_save()
    written = json.loads(target.read_text(encoding="utf-8"))
    assert written["name"] == "DSL_HDR"
    assert [field["name"] for field in written["fields"]] == ["magic", "size"]
    assert host.status_label.text() == "Saved to out.json"


def test_save_does_nothing_when_the_dialog_is_cancelled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: _PatternHost) -> None:
    """A cancelled save dialog writes nothing and leaves the status alone, even with a blank editor.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory that must stay empty.
        host: Host with every pane built.
    """
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_picker(""))
    host.dsl.setPlainText("  ")
    host.status_label.setText("untouched")
    host.do_save()
    assert host.status_label.text() == "untouched"
    assert not host.compiled_json
    assert list(tmp_path.iterdir()) == []


def test_save_writes_nothing_without_a_payload(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bare: _PatternHost) -> None:
    """With neither compiled JSON nor an editor there is nothing to save, so no file is created.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory that must stay empty.
        bare: Host with no panes.
    """
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_picker(str(tmp_path / "out.hexpat")))
    bare.do_save()
    assert list(tmp_path.iterdir()) == []


def test_save_reports_a_failed_write_in_the_status(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: _PatternHost) -> None:
    """A target in a directory that does not exist reports ``Save failed`` and creates nothing.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory; the chosen parent directory is absent.
        host: Host with every pane built.
    """
    target = tmp_path / "absent-dir" / "out.hexpat"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_picker(str(target)))
    host.dsl.setPlainText(_HEADER_DSL)
    host.do_save()
    assert host.status_label.text() == "Save failed"
    assert not target.parent.exists()


def test_save_without_a_status_label_still_writes_or_fails_quietly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    host: _PatternHost,
) -> None:
    """Saving works, and a failing save does not raise, when the status label does not exist.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory receiving the file.
        host: Host with every pane built.
    """
    host.drop_widget("_pattern_status_label")
    host.dsl.setPlainText(_HEADER_DSL)
    good = tmp_path / "good.hexpat"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_picker(str(good)))
    host.do_save()
    assert good.read_text(encoding="utf-8") == _HEADER_DSL

    bad = tmp_path / "absent-dir" / "bad.hexpat"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _file_picker(str(bad)))
    host.do_save()
    assert not bad.parent.exists()


def test_open_hexpat_replaces_the_editor_text(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: _PatternHost) -> None:
    """Opening a ``.hexpat`` file loads it into the DSL editor and leaves the compiled JSON alone.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory holding the file.
        host: Host with every pane built.
    """
    source = tmp_path / "opened.hexpat"
    source.write_text("struct OPENED { u8 b; };\n", encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(source)))
    host.set_compiled_json("keep-json")
    host.do_open()
    assert host.dsl.toPlainText() == "struct OPENED { u8 b; };\n"
    assert host.status_label.text() == "Loaded: opened.hexpat"
    assert host.compiled_json == "keep-json"


def test_open_json_loads_the_preview_and_compiled_template(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: _PatternHost) -> None:
    """Opening a ``.json`` file stores it as the compiled template and shows it in the JSON preview, not the DSL editor.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory holding the file.
        host: Host with every pane built.
    """
    text = _header_template_json("OPENED_HDR")
    source = tmp_path / "opened.json"
    source.write_text(text, encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(source)))
    host.dsl.setPlainText("untouched")
    host.do_open()
    assert host.compiled_json == text
    assert host.json_preview.toPlainText() == text
    assert host.dsl.toPlainText() == "untouched"
    assert host.status_label.text() == "Loaded JSON: opened.json"


def test_open_does_nothing_when_the_dialog_is_cancelled(monkeypatch: pytest.MonkeyPatch, host: _PatternHost) -> None:
    """A cancelled open dialog changes no pane.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        host: Host with every pane built.
    """
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(""))
    host.dsl.setPlainText("untouched")
    host.status_label.setText("untouched")
    host.do_open()
    assert host.dsl.toPlainText() == "untouched"
    assert host.status_label.text() == "untouched"


def test_open_reports_a_file_that_cannot_be_read(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: _PatternHost) -> None:
    """A path that does not exist reports ``Open failed`` and leaves the editor unchanged.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory; the chosen file does not exist in it.
        host: Host with every pane built.
    """
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(tmp_path / "missing.hexpat")))
    host.dsl.setPlainText("untouched")
    host.do_open()
    assert host.status_label.text() == "Open failed"
    assert host.dsl.toPlainText() == "untouched"


def test_open_works_without_any_panes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, bare: _PatternHost) -> None:
    """Opening a JSON file stores it as compiled, and opening a DSL file does not raise, when no pane exists.

    Args:
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory holding the files.
        bare: Host with no panes.
    """
    json_file = tmp_path / "bare.json"
    json_file.write_text('{"name": "BARE"}', encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(json_file)))
    bare.do_open()
    assert bare.compiled_json == '{"name": "BARE"}'

    dsl_file = tmp_path / "bare.hexpat"
    dsl_file.write_text("u8 value @ 0x00;\n", encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(dsl_file)))
    bare.do_open()
    assert bare.compiled_json == '{"name": "BARE"}'


def test_new_pattern_resets_every_pane_to_the_starter_skeleton(host: _PatternHost) -> None:
    """New puts the starter struct in the editor and empties the preview, error and print panes and the compiled JSON.

    Args:
        host: Host with every pane built.
    """
    host.dsl.setPlainText("old source")
    host.json_preview.setPlainText("old json")
    host.error_display.setPlainText("old error")
    host.print_output.setPlainText("old print")
    host.set_compiled_json("old compiled")
    host.do_new()
    assert host.dsl.toPlainText() == _NEW_SKELETON
    assert not host.json_preview.toPlainText()
    assert not host.error_display.toPlainText()
    assert not host.print_output.toPlainText()
    assert not host.compiled_json
    assert host.status_label.text() == "New pattern"


def test_new_pattern_without_panes_still_clears_the_compiled_json(bare: _PatternHost) -> None:
    """With no pane to reset, New still discards the compiled JSON.

    Args:
        bare: Host with no panes.
    """
    bare.set_compiled_json("old compiled")
    bare.do_new()
    assert not bare.compiled_json


def test_library_click_does_nothing_without_a_document(tmp_path: Path, host: _PatternHost) -> None:
    """Clicking a community pattern with no document open loads nothing.

    Args:
        tmp_path: Per-test temporary directory holding the pattern file.
        host: Host with every pane built.
    """
    pattern = tmp_path / "community.hexpat"
    pattern.write_text("struct COMMUNITY { u8 b; };\n", encoding="utf-8")
    item = _library_child(host, "community")
    item.setData(0, Qt.ItemDataRole.UserRole, str(pattern))
    host.use_document(None)
    host.dsl.setPlainText("untouched")
    host.library_clicked(item)
    assert host.dsl.toPlainText() == "untouched"


def test_library_click_ignores_a_top_level_leaf(tmp_path: Path, host: _PatternHost) -> None:
    """A childless top-level item is a section header, not a pattern, so clicking it loads nothing.

    Args:
        tmp_path: Per-test temporary directory holding the pattern file.
        host: Host with every pane built.
    """
    pattern = tmp_path / "community.hexpat"
    pattern.write_text("struct COMMUNITY { u8 b; };\n", encoding="utf-8")
    item = QTreeWidgetItem(["Lonely"])
    item.setData(0, Qt.ItemDataRole.UserRole, str(pattern))
    host.library_tree.addTopLevelItem(item)
    host.dsl.setPlainText("untouched")
    host.library_clicked(item)
    assert host.dsl.toPlainText() == "untouched"


def test_library_click_loads_a_community_pattern_file(tmp_path: Path, host: _PatternHost) -> None:
    """A leaf carrying a ``.hexpat`` path loads that file into the DSL editor and reports it in the status.

    Args:
        tmp_path: Per-test temporary directory holding the pattern file.
        host: Host with every pane built.
    """
    pattern = tmp_path / "community.hexpat"
    pattern.write_text("struct COMMUNITY { u8 b; };\n", encoding="utf-8")
    item = _library_child(host, "Community Pattern")
    item.setData(0, Qt.ItemDataRole.UserRole, str(pattern))
    host.set_compiled_json("stale-json")
    host.library_clicked(item)
    assert host.dsl.toPlainText() == "struct COMMUNITY { u8 b; };\n"
    assert not host.compiled_json
    assert host.status_label.text() == "Loaded: Community Pattern"


def test_library_click_on_an_unknown_template_changes_nothing(host: _PatternHost) -> None:
    """A leaf naming a template the document does not know is logged and leaves the panes untouched.

    Args:
        host: Host with every pane built.
    """
    item = _library_child(host, "NOT_A_TEMPLATE")
    host.set_compiled_json("stale-json")
    host.status_label.setText("untouched")
    host.library_clicked(item)
    assert host.compiled_json == "stale-json"
    assert host.status_label.text() == "untouched"


def test_library_click_loads_a_registered_template_as_json(host: _PatternHost, document: intellicrack_hexcore.HexDocument) -> None:
    """A leaf naming a registered template shows that template's exported JSON and reports it in the status.

    Args:
        host: Host with every pane built.
        document: Real document the template is registered on.
    """
    document.register_json_template(_header_template_json("LIB_HDR"))
    host.library_clicked(_library_child(host, "LIB_HDR"))
    exported = json.loads(host.compiled_json)
    assert exported["name"] == "LIB_HDR"
    assert [field["name"] for field in exported["fields"]] == ["magic", "size"]
    assert host.json_preview.toPlainText() == host.compiled_json
    assert host.status_label.text() == "Loaded: LIB_HDR"


def test_library_click_loads_a_registered_template_without_panes(bare: _PatternHost, document: intellicrack_hexcore.HexDocument) -> None:
    """Loading a registered template works with no preview or status pane.

    Args:
        bare: Host with no panes.
        document: Real document the template is registered on.
    """
    document.register_json_template(_header_template_json("BARE_LIB_HDR"))
    root = QTreeWidgetItem(["Root"])
    child = QTreeWidgetItem(["BARE_LIB_HDR"])
    root.addChild(child)
    bare.library_clicked(child)
    assert json.loads(bare.compiled_json)["name"] == "BARE_LIB_HDR"


def test_load_hexpat_from_library_replaces_the_editor_and_clears_the_other_panes(tmp_path: Path, host: _PatternHost) -> None:
    """Loading a community pattern decodes the file with replacement characters and resets every dependent pane.

    Args:
        tmp_path: Per-test temporary directory holding the pattern file.
        host: Host with every pane built.
    """
    raw = b"struct COMMUNITY { u8 b; }; // caf\xff\n"
    pattern = tmp_path / "community.hexpat"
    pattern.write_bytes(raw)
    host.set_compiled_json("stale-json")
    host.json_preview.setPlainText("stale preview")
    host.error_display.setPlainText("stale error")
    host.print_output.setPlainText("stale print")
    host.load_library(str(pattern), "Community")
    assert host.dsl.toPlainText() == raw.decode("utf-8", errors="replace")
    assert not host.compiled_json
    assert not host.json_preview.toPlainText()
    assert not host.error_display.toPlainText()
    assert not host.print_output.toPlainText()
    assert host.status_label.text() == "Loaded: Community"


def test_load_hexpat_from_library_keeps_the_editor_when_the_file_is_missing(tmp_path: Path, host: _PatternHost) -> None:
    """A pattern file that cannot be read leaves the editor and the compiled JSON as they were.

    Args:
        tmp_path: Per-test temporary directory; the chosen file does not exist in it.
        host: Host with every pane built.
    """
    host.dsl.setPlainText("untouched")
    host.set_compiled_json("keep-json")
    host.load_library(str(tmp_path / "missing.hexpat"), "Missing")
    assert host.dsl.toPlainText() == "untouched"
    assert host.compiled_json == "keep-json"
    assert not host.status_label.text()


def test_load_hexpat_from_library_without_panes_clears_the_compiled_json(tmp_path: Path, bare: _PatternHost) -> None:
    """Loading a community pattern with no panes still discards the compiled JSON.

    Args:
        tmp_path: Per-test temporary directory holding the pattern file.
        bare: Host with no panes.
    """
    pattern = tmp_path / "community.hexpat"
    pattern.write_text("u8 value @ 0x00;\n", encoding="utf-8")
    bare.set_compiled_json("stale-json")
    bare.load_library(str(pattern), "Community")
    assert not bare.compiled_json


def test_populate_pattern_library_survives_a_document_without_the_template_api(host: _PatternHost) -> None:
    """A document that cannot list templates leaves the library tree empty instead of raising.

    Args:
        host: Host with every pane built.
    """
    host.library_tree.addTopLevelItem(QTreeWidgetItem(["stale"]))
    host.use_document(object())
    host.populate_library()
    assert host.library_tree.topLevelItemCount() == 0


def test_hexpat_entries_need_a_library_tree(tmp_path: Path, bare: _PatternHost) -> None:
    """Without a library tree the community patterns are not listed and nothing raises.

    Args:
        tmp_path: Per-test temporary directory holding a pattern.
        bare: Host with no panes.
    """
    category = tmp_path / "formats"
    category.mkdir()
    (category / "one.hexpat").write_text("struct ONE { u8 b; };\n", encoding="utf-8")
    bare.use_registry(PatternRegistry([tmp_path]))
    bare.populate_hexpat_entries()
    assert bare.findChildren(QTreeWidget) == []


def test_hexpat_entries_survive_a_registry_that_cannot_list_by_category(host: _PatternHost) -> None:
    """A registry object lacking the listing API leaves the library tree without a community section.

    Args:
        host: Host with every pane built.
    """
    host.use_registry(object())
    host.populate_hexpat_entries()
    assert host.library_tree.topLevelItemCount() == 0


def test_hexpat_entries_skip_an_empty_registry(tmp_path: Path, host: _PatternHost) -> None:
    """A registry that finds no patterns adds no community section to the library tree.

    Args:
        tmp_path: Per-test temporary directory scanned by the registry; it holds no pattern.
        host: Host with every pane built.
    """
    host.use_registry(PatternRegistry([tmp_path]))
    host.populate_hexpat_entries()
    assert host.library_tree.topLevelItemCount() == 0


def test_refresh_template_combo_lists_the_documents_templates(host: _PatternHost, document: intellicrack_hexcore.HexDocument) -> None:
    """Refreshing fills the combo box with the names of every template the document knows, including a newly registered one.

    Args:
        host: Host with every pane built.
        document: Real document the template is registered on.
    """
    document.register_json_template(_header_template_json("COMBO_HDR"))
    host.refresh_combo()
    items = [host.template_combo.itemText(index) for index in range(host.template_combo.count())]
    assert "COMBO_HDR" in items
    assert items == [name for name, _description in document.list_templates()]
