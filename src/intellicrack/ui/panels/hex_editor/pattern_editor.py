# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Pattern editor mixin for the hex editor panel."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.hexpat.completer import HexPatCompleter
from intellicrack.core.logging import get_logger
from intellicrack.ui.highlighter import HexPatSyntaxHighlighter
from intellicrack.ui.panels.hex_editor.base import (
    SPLITTER_MAIN_RATIO,
    SPLITTER_PATTERN_RATIO,
    HexPatInterpreter_cls,
    PatternRegistryCls,
    hexpat_available,
    hexpat_interpreter_available,
    hexpat_mod,
)
from intellicrack.ui.panels.hex_editor.pattern_code_editor import PatternCodeEditor
from intellicrack.ui.resources.font_manager import FontManager
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger(__name__)


_PATTERN_FIELD_DARK: Final[str] = "#FFD080"
_PATTERN_FIELD_LIGHT: Final[str] = "#E65100"


def _get_default_pattern_field_color() -> str:
    """Return a theme-appropriate highlight color for pattern editor fields.

    Returns:
        str: Hex color string suitable for the active theme.
    """
    if ThemeManager.get_instance().is_dark_theme():
        return _PATTERN_FIELD_DARK
    return _PATTERN_FIELD_LIGHT


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.bridges.hex_state import HexDocumentState


class PatternEditorMixin:
    """Mixin providing the HexPat DSL pattern editor for the hex editor panel."""

    document: Any | None
    state_holder: Any | None
    _document: Any | None
    _hex_widget: Any | None
    _file_path: Path | None
    _pattern_frame: QFrame | None
    _pattern_dsl_editor: PatternCodeEditor | None
    _pattern_completer: HexPatCompleter | None
    _pattern_json_preview: QPlainTextEdit | None
    _pattern_library_tree: QTreeWidget | None
    _pattern_error_display: QPlainTextEdit | None
    _pattern_print_output: QPlainTextEdit | None
    _pattern_status_label: QLabel | None
    _pattern_visible: bool
    _compiled_json: str
    _main_vsplit: QSplitter | None
    _interpreter: Any | None
    _pattern_registry: Any | None
    _templates_tree: QTreeWidget | None
    _template_combo: QComboBox | None
    _state_holder: HexDocumentState | None
    _populate_template_combo: Callable[[], None]

    def _populate_template_tree(self, fields: list[dict[str, object]]) -> None:
        """Populate the template preview tree from decoded structure fields.

        Args:
            fields: Interpreted template field entries with metadata.
        """
        if self._templates_tree is None:
            return
        for field in fields:
            name_val = str(field.get("name", ""))
            offset_raw = field.get("offset")
            size_raw = field.get("size")
            type_val = str(field.get("type", ""))
            offset_int = offset_raw if isinstance(offset_raw, int) else 0
            size_int = size_raw if isinstance(size_raw, int) else 0
            item = QTreeWidgetItem([
                name_val,
                f"0x{offset_int:08X}",
                f"{size_int}",
                type_val,
            ])
            self._templates_tree.addTopLevelItem(item)

    def _highlight_template_fields(self, fields: list[dict[str, object]]) -> None:
        """Apply region highlights in the hex view for template fields.

        Args:
            fields: Interpreted template field entries with offsets and sizes.
        """
        if self._hex_widget is None:
            return
        highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
        if not callable(highlight_fn):
            return
        highlights: list[tuple[int, int, str]] = []
        for field in fields:
            offset_raw = field.get("offset")
            size_raw = field.get("size")
            if isinstance(offset_raw, int) and isinstance(size_raw, int):
                color_raw = field.get("color")
                color = color_raw if isinstance(color_raw, str) else _get_default_pattern_field_color()
                highlights.append((offset_raw, size_raw, color))
        if highlights:
            highlight_fn(highlights, "pattern")

    def _build_pattern_editor(self) -> QFrame:
        """Build the collapsible pattern editor panel.

        Returns:
            QFrame: Frame containing the pattern editor UI.
        """
        frame = QFrame()
        frame_layout = QHBoxLayout(frame)
        frame_layout.setContentsMargins(2, 2, 2, 2)

        editor_splitter = QSplitter(Qt.Orientation.Horizontal)

        self._pattern_library_tree = QTreeWidget()
        self._pattern_library_tree.setHeaderLabels(["Templates"])
        self._pattern_library_tree.setMaximumWidth(200)
        self._pattern_library_tree.itemClicked.connect(self._on_pattern_library_clicked)
        editor_splitter.addWidget(self._pattern_library_tree)

        right_area = QWidget()
        right_layout = QVBoxLayout(right_area)
        right_layout.setContentsMargins(0, 0, 0, 0)

        editor_tabs = QTabWidget()

        self._pattern_dsl_editor = PatternCodeEditor()
        self._pattern_dsl_editor.setPlainText("struct MY_HEADER {\n    le u16 magic [[validate(0x5A4D)]];\n    le u32 size;\n};\n")
        font = FontManager.get_instance().get_code_font(10)
        self._pattern_dsl_editor.setFont(font)
        HexPatSyntaxHighlighter(self._pattern_dsl_editor.document())
        self._pattern_completer = HexPatCompleter()
        self._pattern_dsl_editor.update_type_names(self._pattern_completer.all_type_names())
        editor_tabs.addTab(self._pattern_dsl_editor, "DSL")

        self._pattern_json_preview = QPlainTextEdit()
        self._pattern_json_preview.setReadOnly(True)
        self._pattern_json_preview.setFont(font)
        editor_tabs.addTab(self._pattern_json_preview, "JSON")

        right_layout.addWidget(editor_tabs, stretch=3)

        action_bar = QHBoxLayout()
        compile_btn = QPushButton("Compile")
        compile_btn.clicked.connect(self._on_pattern_compile)
        action_bar.addWidget(compile_btn)

        apply_btn = QPushButton("Apply at Cursor")
        apply_btn.clicked.connect(self._on_pattern_apply)
        action_bar.addWidget(apply_btn)

        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self._on_pattern_save)
        action_bar.addWidget(save_btn)

        open_btn = QPushButton("Open")
        open_btn.clicked.connect(self._on_pattern_open)
        action_bar.addWidget(open_btn)

        new_btn = QPushButton("New")
        new_btn.clicked.connect(self._on_pattern_new)
        action_bar.addWidget(new_btn)

        self._pattern_status_label = QLabel("")
        action_bar.addWidget(self._pattern_status_label)
        action_bar.addStretch()

        right_layout.addLayout(action_bar)

        self._pattern_error_display = QPlainTextEdit()
        self._pattern_error_display.setReadOnly(True)
        self._pattern_error_display.setMaximumHeight(60)
        right_layout.addWidget(self._pattern_error_display)

        print_label = QLabel("std::print output")
        right_layout.addWidget(print_label)

        self._pattern_print_output = QPlainTextEdit()
        self._pattern_print_output.setReadOnly(True)
        self._pattern_print_output.setMaximumHeight(100)
        self._pattern_print_output.setFont(font)
        right_layout.addWidget(self._pattern_print_output)

        editor_splitter.addWidget(right_area)
        editor_splitter.setStretchFactor(0, 1)
        editor_splitter.setStretchFactor(1, 4)

        frame_layout.addWidget(editor_splitter)
        return frame

    def _toggle_pattern_editor(self) -> None:
        """Toggle the pattern editor panel visibility."""
        self._pattern_visible = not self._pattern_visible
        if self._pattern_frame is not None:
            self._pattern_frame.setVisible(self._pattern_visible)
        if self._pattern_visible and self._main_vsplit is not None:
            total = self._main_vsplit.height()
            n = self._main_vsplit.count()
            numeric_panel_idx = 2
            numeric_size = self._main_vsplit.sizes()[numeric_panel_idx] if n > numeric_panel_idx else 0
            remaining = total - numeric_size
            tail = [numeric_size] if n > numeric_panel_idx else []
            sizes = [
                int(remaining * SPLITTER_MAIN_RATIO),
                int(remaining * SPLITTER_PATTERN_RATIO),
                *tail,
            ]
            self._main_vsplit.setSizes(sizes)
            self._populate_pattern_library()

    def _on_pattern_compile(self) -> None:
        """Compile the DSL source to JSON and show in preview."""
        if self._pattern_dsl_editor is None:
            return

        source = self._pattern_dsl_editor.toPlainText()
        if not source.strip():
            return

        if not hexpat_available or hexpat_mod is None:
            if self._pattern_error_display is not None:
                self._pattern_error_display.setPlainText("HexPat compiler not available")
            return

        compiler_cls: type[Any] | None = getattr(hexpat_mod, "HexPatCompiler", None)
        error_cls: type[Any] | None = getattr(hexpat_mod, "HexPatError", None)
        if compiler_cls is None:
            return

        try:
            compiler_inst: Any = compiler_cls()
            compiled: str = compiler_inst.compile(source)
        except (ValueError, TypeError, AttributeError) as exc:
            is_hexpat_error = error_cls is not None and isinstance(exc, error_cls)
            self._compiled_json = ""
            if is_hexpat_error:
                line_num = getattr(exc, "line", 0)
                col_num = getattr(exc, "column", 0)
                msg = getattr(exc, "message", str(exc))
                if self._pattern_error_display is not None:
                    self._pattern_error_display.setPlainText(f"Line {line_num}, Col {col_num}: {msg}")
            elif self._pattern_error_display is not None:
                self._pattern_error_display.setPlainText(str(exc))
            if self._pattern_status_label is not None:
                self._pattern_status_label.setText("Compilation failed")
            _logger.exception("pattern_compile_failed")
        else:
            self._compiled_json = compiled

            if self._pattern_json_preview is not None:
                self._pattern_json_preview.setPlainText(compiled)

            if self._pattern_error_display is not None:
                self._pattern_error_display.clear()

            if self._pattern_status_label is not None:
                self._pattern_status_label.setText("Compiled successfully")

            _logger.info("pattern_compiled")

    def _on_pattern_apply(self) -> None:
        """Apply the pattern at the current cursor offset.

        Tries the HexPat interpreter first for direct execution, then falls back to compile-register-apply via the Rust backend.
        """
        if self.document is None:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        source = ""
        if self._pattern_dsl_editor is not None:
            source = self._pattern_dsl_editor.toPlainText().strip()

        if source and hexpat_interpreter_available and HexPatInterpreter_cls is not None:
            self._apply_via_interpreter(source, cursor_offset)
            return

        if not self._compiled_json:
            self._on_pattern_compile()
        if not self._compiled_json:
            return

        try:
            name: str = self.document.register_json_template(self._compiled_json)
            result = self.document.apply_template(name, cursor_offset)
        except (AttributeError, ValueError, TypeError) as exc:
            if self._pattern_error_display is not None:
                self._pattern_error_display.setPlainText(f"Apply failed: {exc}")
            if self._pattern_status_label is not None:
                self._pattern_status_label.setText("Apply failed")
            _logger.exception("pattern_apply_failed")
        else:
            field_count = 0
            if isinstance(result, list):
                typed_fields = cast("list[dict[str, object]]", result)
                field_count = len(typed_fields)
                if self._templates_tree is not None:
                    self._templates_tree.clear()
                    self._populate_template_tree(typed_fields)
                    self._highlight_template_fields(typed_fields)
            elif self._templates_tree is not None:
                self._templates_tree.clear()

            self._populate_template_combo()

            if self._pattern_status_label is not None:
                self._pattern_status_label.setText(f"Applied '{name}' at offset {cursor_offset}")

            if self.state_holder is not None:
                register_fn = getattr(self.state_holder, "notify_template_registered", None)
                if callable(register_fn):
                    register_fn(name, source="hex-editor.pattern_editor.apply.register")
                pattern_executed = getattr(self.state_holder, "notify_pattern_executed", None)
                if callable(pattern_executed):
                    pattern_executed(
                        name,
                        field_count,
                        source="hex-editor.pattern_editor.apply.execute",
                    )

            _logger.info("pattern_applied", template_name=name, offset=cursor_offset)

    def _refresh_pattern_completer(self) -> None:
        """Refresh the DSL editor's type-name completer from the interpreter.

        Reads the :class:`TypeRegistry` produced by the most recent successful interpreter execution (exposed through
        :attr:`HexPatInterpreter.last_type_registry`) and rebuilds the editor's completion model so the popup offers built-in primitives
        plus all user-declared identifiers from the last run.
        """
        if self._interpreter is None or self._pattern_completer is None or self._pattern_dsl_editor is None:
            return
        registry: Any | None = getattr(self._interpreter, "last_type_registry", None)
        if registry is None:
            return
        self._pattern_completer.update_from_registry(registry)
        self._pattern_dsl_editor.update_type_names(self._pattern_completer.all_type_names())

    def _append_pattern_print_line(self, line: str) -> None:
        """Append a single ``std::print`` line to the pattern editor's print output.

        The interpreter installs this method as its ``print_sink`` so output
        produced by ``std::print`` inside a pattern surfaces in the UI panel
        rather than only landing in the structured log.

        Args:
            line: Formatted message emitted by ``std::print``.
        """
        if self._pattern_print_output is None:
            return
        self._pattern_print_output.appendPlainText(line)

    def _apply_via_interpreter(self, source: str, offset: int) -> None:
        """Execute HexPat source directly via the interpreter.

        Args:
            source: HexPat DSL source code.
            offset: Byte offset to apply at.
        """
        if self.document is None or HexPatInterpreter_cls is None:
            return

        if self._pattern_print_output is not None:
            self._pattern_print_output.clear()

        if self._interpreter is None:
            self._interpreter = HexPatInterpreter_cls(print_sink=self._append_pattern_print_line)
        else:
            set_sink = getattr(self._interpreter, "set_print_sink", None)
            if callable(set_sink):
                set_sink(self._append_pattern_print_line)
        interpreter = self._interpreter
        if interpreter is None:
            return

        try:
            fields: list[dict[str, Any]] = interpreter.execute(source, self.document, offset)
        except (ValueError, TypeError, AttributeError) as exc:
            if self._pattern_error_display is not None:
                err_msg = str(exc)
                line_num = getattr(exc, "line", None)
                col_num = getattr(exc, "column", None)
                if line_num is not None and col_num is not None:
                    err_msg = f"Line {line_num}, Col {col_num}: {err_msg}"
                self._pattern_error_display.setPlainText(err_msg)
            if self._pattern_status_label is not None:
                self._pattern_status_label.setText("Execution failed")
            _logger.exception("pattern_interpreter_failed")
        else:
            self._refresh_pattern_completer()
            if self._pattern_error_display is not None:
                self._pattern_error_display.clear()

            if self._templates_tree is not None:
                self._templates_tree.clear()
                typed_fields = cast("list[dict[str, object]]", fields)
                self._populate_template_tree(typed_fields)
                self._highlight_template_fields(typed_fields)

            if self._pattern_status_label is not None:
                self._pattern_status_label.setText(f"Executed at offset {offset} ({len(fields)} fields)")

            if self.state_holder is not None:
                register_fn = getattr(self.state_holder, "notify_template_registered", None)
                if callable(register_fn):
                    register_fn(
                        "<inline>",
                        source="hex-editor.pattern_editor.apply.interpreter.register",
                    )
                pattern_executed = getattr(self.state_holder, "notify_pattern_executed", None)
                if callable(pattern_executed):
                    pattern_executed(
                        "<inline>",
                        len(fields),
                        source="hex-editor.pattern_editor.apply.interpreter",
                    )

            _logger.info("pattern_executed_via_interpreter", field_count=len(fields))

    def _on_pattern_save(self) -> None:
        """Save the current pattern to a file."""
        if not self._compiled_json and self._pattern_dsl_editor is not None:
            source = self._pattern_dsl_editor.toPlainText()
            if source.strip():
                self._on_pattern_compile()

        parent = self if isinstance(self, QWidget) else None
        result = QFileDialog.getSaveFileName(
            parent,
            "Save Pattern",
            "",
            "HexPat Files (*.hexpat);;JSON Templates (*.json);;All Files (*)",
        )
        save_path = result[0] if result else ""
        if not save_path:
            return

        path = Path(save_path)
        if path.suffix == ".json" and self._compiled_json:
            payload = self._compiled_json
            payload_format = "json"
        elif self._pattern_dsl_editor is not None:
            payload = self._pattern_dsl_editor.toPlainText()
            payload_format = "hexpat"
        else:
            _logger.debug("pattern_save_skipped", reason="no payload available")
            return

        _logger.info(
            "pattern_save_begin",
            path=str(path),
            format=payload_format,
            size=len(payload),
        )

        try:
            path.write_text(payload, encoding="utf-8")
        except OSError:
            if self._pattern_status_label is not None:
                self._pattern_status_label.setText("Save failed")
            _logger.exception("pattern_save_failed", path=save_path)
        else:
            if self._pattern_status_label is not None:
                self._pattern_status_label.setText(f"Saved to {path.name}")
            _logger.info("pattern_saved", path=str(path))

    def _on_pattern_open(self) -> None:
        """Open a pattern file from disk."""
        parent = self if isinstance(self, QWidget) else None
        result = QFileDialog.getOpenFileName(
            parent,
            "Open Pattern",
            "",
            "Pattern Files (*.hexpat *.json);;All Files (*)",
        )
        file_path_str = result[0] if result else ""
        if not file_path_str:
            return

        _logger.info("pattern_open_begin", path=file_path_str)
        try:
            path = Path(file_path_str)
            _logger.info("pattern_open_begin", path=str(path))
            content = path.read_text(encoding="utf-8")
        except OSError:
            if self._pattern_status_label is not None:
                self._pattern_status_label.setText("Open failed")
            _logger.exception("pattern_open_failed", path=file_path_str)
        else:
            if path.suffix == ".json":
                self._compiled_json = content
                if self._pattern_json_preview is not None:
                    self._pattern_json_preview.setPlainText(content)
                if self._pattern_status_label is not None:
                    self._pattern_status_label.setText(f"Loaded JSON: {path.name}")
            else:
                if self._pattern_dsl_editor is not None:
                    self._pattern_dsl_editor.setPlainText(content)
                if self._pattern_status_label is not None:
                    self._pattern_status_label.setText(f"Loaded: {path.name}")

            _logger.info("pattern_opened", path=str(path))

    def _on_pattern_new(self) -> None:
        """Clear the pattern editor with a starter skeleton."""
        if self._pattern_dsl_editor is not None:
            self._pattern_dsl_editor.setPlainText("struct MY_HEADER {\n    le u16 magic;\n    le u32 size;\n};\n")
        if self._pattern_json_preview is not None:
            self._pattern_json_preview.clear()
        if self._pattern_error_display is not None:
            self._pattern_error_display.clear()
        if self._pattern_print_output is not None:
            self._pattern_print_output.clear()
        self._compiled_json = ""
        if self._pattern_status_label is not None:
            self._pattern_status_label.setText("New pattern")

    def _on_pattern_library_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Load the selected template from the library into the editors.

        Handles both built-in JSON templates and .hexpat pattern files.

        Args:
            item: The clicked tree widget item.
            column: The clicked column index.
        """
        _ = column
        if self.document is None:
            return

        parent_item = item.parent()
        if parent_item is None:
            return

        hexpat_path = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(hexpat_path, str) and hexpat_path:
            self._load_hexpat_from_library(hexpat_path, item.text(0))
            return

        template_name = item.text(0)
        try:
            json_str_val: str = self.document.export_template_json(template_name)
        except (AttributeError, ValueError):
            _logger.exception("pattern_library_load_failed")
        else:
            self._compiled_json = json_str_val

            if self._pattern_json_preview is not None:
                self._pattern_json_preview.setPlainText(json_str_val)

            if self._pattern_status_label is not None:
                self._pattern_status_label.setText(f"Loaded: {template_name}")

            _logger.info("pattern_library_loaded", template_name=template_name)

    def _load_hexpat_from_library(self, file_path: str, name: str) -> None:
        """Load a .hexpat pattern file into the DSL editor.

        Args:
            file_path: Absolute path to the .hexpat file.
            name: Display name of the pattern.
        """
        try:
            _logger.info("hexpat_library_load_begin", path=file_path, pattern_name=name)
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            _logger.exception("hexpat_library_load_failed", path=file_path, pattern_name=name)
            return

        if self._pattern_dsl_editor is not None:
            self._pattern_dsl_editor.setPlainText(source)
        self._compiled_json = ""
        if self._pattern_json_preview is not None:
            self._pattern_json_preview.clear()
        if self._pattern_error_display is not None:
            self._pattern_error_display.clear()
        if self._pattern_print_output is not None:
            self._pattern_print_output.clear()
        if self._pattern_status_label is not None:
            self._pattern_status_label.setText(f"Loaded: {name}")

    def _populate_pattern_library(self) -> None:
        """Populate the pattern library tree with available templates."""
        if self._pattern_library_tree is None or self.document is None:
            return

        self._pattern_library_tree.clear()

        try:
            templates = self.document.list_templates()
        except (AttributeError, ValueError):
            _logger.exception("pattern_library_populate_failed")
            return

        categories: dict[str, QTreeWidgetItem] = {}

        builtin_root = QTreeWidgetItem(["Built-in"])
        self._pattern_library_tree.addTopLevelItem(builtin_root)

        user_root = QTreeWidgetItem(["User"])
        self._pattern_library_tree.addTopLevelItem(user_root)

        for tpl_entry in templates:
            name_val = str(tpl_entry[0])
            desc_val = str(tpl_entry[1])
            name_upper = name_val.upper()
            if any(name_upper.startswith(p) for p in ("ELF", "ELF32", "ELF64")):
                category = "ELF"
            elif any(name_upper.startswith(p) for p in ("MACH", "LOAD_COMMAND", "SEGMENT")):
                category = "Mach-O"
            elif name_upper.startswith("ZIP"):
                category = "ZIP"
            elif name_upper in {"GUID", "FILETIME"}:
                category = "Common"
            elif name_upper.startswith(("IMAGE", "PE", "DOS")):
                category = "PE"
            else:
                category = "Other"

            if category not in categories:
                cat_item = QTreeWidgetItem([category])
                builtin_root.addChild(cat_item)
                categories[category] = cat_item

            template_item = QTreeWidgetItem([name_val])
            template_item.setToolTip(0, desc_val)
            categories[category].addChild(template_item)

        builtin_root.setExpanded(True)

        self._populate_hexpat_library_entries()

    def _populate_hexpat_library_entries(self) -> None:
        """Add .hexpat community patterns to the pattern library tree."""
        if self._pattern_library_tree is None or not hexpat_interpreter_available or PatternRegistryCls is None:
            return

        if self._pattern_registry is None:
            project_root = Path(__file__).resolve().parents[4]
            patterns_dir = project_root / "vendor" / "community-patterns" / "patterns"
            if not patterns_dir.exists():
                return
            self._pattern_registry = PatternRegistryCls([patterns_dir])

        registry = self._pattern_registry
        if registry is None:
            return

        try:
            by_cat: dict[str, list[Any]] = registry.list_by_category()
        except (AttributeError, ValueError):
            _logger.exception("hexpat_library_populate_failed")
            return

        if not by_cat:
            return

        hexpat_root = QTreeWidgetItem(["HexPat Patterns"])
        self._pattern_library_tree.addTopLevelItem(hexpat_root)

        for category, patterns in by_cat.items():
            cat_item = QTreeWidgetItem([category])
            hexpat_root.addChild(cat_item)
            for pattern in patterns:
                p_item = QTreeWidgetItem([pattern.name])
                tooltip = pattern.description or ""
                p_item.setToolTip(0, tooltip)
                p_item.setData(0, Qt.ItemDataRole.UserRole, str(pattern.file_path))
                cat_item.addChild(p_item)

        hexpat_root.setExpanded(True)

    def _refresh_template_combo(self) -> None:
        """Refresh the template combo box after registration changes."""
        self._populate_template_combo()
