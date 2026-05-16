# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Script manager panel for creating and managing analysis scripts.

Provides a comprehensive UI for script editing, validation, and execution with support for Frida, Ghidra, Cutter, x64dbg, and Python
scripts.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, cast, override

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.core.script_gen import Script, ScriptLanguage, ScriptType
from intellicrack.ui.highlighter import get_highlighter_for_language
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtGui import QSyntaxHighlighter

    from intellicrack.core.script_gen import ScriptManager, ScriptValidator

    ScriptExecutor = Callable[[str, str, str], str | None]

_logger = get_logger(__name__)

_PANEL_MARGIN: Final[int] = 8
_PANEL_MARGIN_INNER: Final[int] = 4
_PANEL_SPACING: Final[int] = 8
_LEFT_PANEL_MAX_WIDTH: Final[int] = 250
_SPLITTER_LEFT_SIZE: Final[int] = 200
_SPLITTER_RIGHT_SIZE: Final[int] = 600
_RESULT_PANE_MIN_HEIGHT: Final[int] = 80
_EXECUTION_TIMEOUT_MS: Final[int] = 30000
_STATUS_RESET_MS: Final[int] = 3000


def _restyle(widget: QWidget) -> None:
    """Force a QSS re-evaluation after a dynamic property change.

    Args:
        widget: The widget whose style should be refreshed.
    """
    s = widget.style()
    if s is not None:
        s.unpolish(widget)
        s.polish(widget)


class ScriptTypeInfo:
    """Information about a script type including templates and extensions.

    Attributes:
        TYPES: Mapping of script type identifiers to their configuration dicts.
    """

    TYPES: ClassVar[dict[str, dict[str, str]]] = {
        "frida": {
            "display": "Frida",
            "extension": ".js",
            "language": "javascript",
            "template": """/**
 * Frida script for license validation hook
 * Target: {target}
 */

Interceptor.attach(ptr("{address}"), {
    onEnter: function(args) {
        console.log("[+] Function called");
        // Log arguments
        for (var i = 0; i < 4; i++) {
            console.log("  arg" + i + ": " + args[i]);
        }
    },
    onLeave: function(retval) {
        console.log("[+] Return value: " + retval);
        // Modify return value to bypass check
        // retval.replace(ptr("1"));
    }
});
""",
        },
        "ghidra": {
            "display": "Ghidra",
            "extension": ".java",
            "language": "java",
            "template": """/**
 * Ghidra script for license analysis
 * @category Intellicrack
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class LicenseAnalyzer extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("Starting license analysis...");

        // Get current address
        var addr = currentAddress;
        println("Analyzing at: " + addr);

        // Find function at address
        Function func = getFunctionContaining(addr);
        if (func != null) {
            println("Function: " + func.getName());
            // Analyze function for license checks
        }
    }
}
""",
        },
        "cutter": {
            "display": "Cutter",
            "extension": ".r2",
            "language": "r2cmd",
            "template": """# Cutter/Rizin script for license analysis # Target: {target}

                        # Analyze all
                        aaa

                        # Find license-related strings
                        iz~licen
                        iz~serial
                        iz~regist

                        # Find crypto function references
                        axt sym.imp.CryptAcquireContextW

                        # Seek to main
                        s main

                        # Print disassembly
                        pdf

                        # Find comparison operations
                        /c cmp
                        """,
        },
        "x64dbg": {
            "display": "x64dbg",
            "extension": ".txt",
            "language": "x64dbg",
            "template": """// x64dbg script for license bypass
// Target: {target}

// Set an unconditional breakpoint at the validation function entry
bp {address}

// Log a line each time the breakpoint is hit
SetBreakpointLog {address}, "License check hit at {address}"

// On hit: force the function's return register to 1 and resume.
// This runs AFTER the breakpoint fires, so eax has a defined value.
SetBreakpointCommand {address}, "eax=1; run"

// Begin execution; the breakpoint command above performs the bypass on hit
run
""",
        },
        "python": {
            "display": "Python",
            "extension": ".py",
            "language": "python",
            "template": '''"""
Python analysis script for license examination.
Target: {target}
"""

import struct
from pathlib import Path


def analyze_binary(file_path: str) -> dict[str, list[str]]:
    """Analyze binary for license protection patterns.

    Args:
        file_path: Path to binary file.

    Returns:
        Analysis results dictionary.
    """
    results = {
        "license_strings": [],
        "crypto_imports": [],
        "validation_patterns": [],
    }

    data = Path(file_path).read_bytes()

    # Search for common license strings
    patterns = [b"license", b"serial", b"registration", b"activate"]
    for pattern in patterns:
        offset = 0
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            results["license_strings"].append((hex(idx), pattern.decode()))
            offset = idx + 1

    return results


if __name__ == "__main__":
    # Replace with target binary path
    target = r"{target}"
    if Path(target).exists():
        analysis = analyze_binary(target)
        print(f"Found {{len(analysis['license_strings'])}} license strings")
''',
        },
    }

    @classmethod
    def get_types(cls) -> list[str]:
        """Get list of available script types.

        Returns:
            list[str]: List of script type identifiers.
        """
        return list(cls.TYPES.keys())

    @classmethod
    def get_display_name(cls, script_type: str) -> str:
        """Get display name for a script type.

        Args:
            script_type: Script type identifier.

        Returns:
            str: Human-readable display name.
        """
        info = cls.TYPES.get(script_type, {})
        return info.get("display", script_type)

    @classmethod
    def get_extension(cls, script_type: str) -> str:
        """Get file extension for a script type.

        Args:
            script_type: Script type identifier.

        Returns:
            str: File extension including dot.
        """
        info = cls.TYPES.get(script_type, {})
        return info.get("extension", ".txt")

    @classmethod
    def get_language(cls, script_type: str) -> str:
        """Get syntax highlighting language for a script type.

        Args:
            script_type: Script type identifier.

        Returns:
            str: Language identifier for syntax highlighting.
        """
        info = cls.TYPES.get(script_type, {})
        return info.get("language", "text")

    @classmethod
    def get_template(cls, script_type: str, target: str = "", address: str = "0x0") -> str:
        """Get a template script for a type.

        Args:
            script_type: Script type identifier.
            target: Target binary name for template.
            address: Target address for template.

        Returns:
            str: Template script content.
        """
        info = cls.TYPES.get(script_type, {})
        template = info.get("template", "")
        return template.format(target=target, address=address)


class ScriptListWidget(QListWidget):
    """List widget for displaying and filtering scripts.

    Attributes:
        script_selected: Qt signal for script selected.
    """

    script_selected = pyqtSignal(str)

    @override
    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ScriptListWidget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._scripts: dict[str, dict[str, str]] = {}
        self._current_filter: str | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the list widget UI."""
        self.setObjectName("script_list_widget")
        self.itemClicked.connect(self._on_item_clicked)

    def _on_item_clicked(self, item: QListWidgetItem) -> None:
        """Handle item click.

        Args:
            item: Clicked list item.
        """
        if script_id := item.data(Qt.ItemDataRole.UserRole):
            self.script_selected.emit(script_id)

    def add_script(self, script_id: str, name: str, script_type: str) -> None:
        """Add a script to the list.

        Args:
            script_id: Unique script identifier.
            name: Script display name.
            script_type: Script type identifier.
        """
        self._scripts[script_id] = {"name": name, "type": script_type}
        self._refresh_list()

    def remove_script(self, script_id: str) -> None:
        """Remove a script from the list.

        Args:
            script_id: Script identifier to remove.
        """
        if script_id in self._scripts:
            del self._scripts[script_id]
            self._refresh_list()

    def set_filter(self, script_type: str | None) -> None:
        """Set the type filter for the list.

        Args:
            script_type: Script type to filter by, or None for all.
        """
        self._current_filter = script_type
        self._refresh_list()

    def _refresh_list(self) -> None:
        """Refresh the list based on current filter."""
        self.clear()

        for script_id, info in self._scripts.items():
            if self._current_filter and info["type"] != self._current_filter:
                continue

            type_prefix = ScriptTypeInfo.get_display_name(info["type"])
            item = QListWidgetItem(f"[{type_prefix}] {info['name']}")
            item.setData(Qt.ItemDataRole.UserRole, script_id)
            self.addItem(item)

    def get_selected_id(self) -> str | None:
        """Get the currently selected script ID.

        Returns:
            str | None: Selected script ID or None.
        """
        if current := self.currentItem():
            return current.data(Qt.ItemDataRole.UserRole)
        return None


class ScriptEditor(QPlainTextEdit):
    """Code editor widget for script editing with basic styling.

    Attributes:
        content_changed: Qt signal for content changed.
    """

    content_changed = pyqtSignal()

    @override
    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ScriptEditor.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent=parent)
        self._highlighter: QSyntaxHighlighter | None = None
        self._current_language: str = ""
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the editor UI."""
        self.setObjectName("script_editor_widget")
        self.setFont(FontManager.get_instance().get_code_font(10))
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setTabStopDistance(40)

        self.textChanged.connect(self.content_changed.emit)

    def set_language(self, language: str) -> None:
        """Set the syntax highlighting language.

        Tears down any previously attached highlighter and instantiates a new
        one attached to this editor's document for the requested language.
        A no-op when the language is unchanged.

        Args:
            language: Language identifier (e.g. ``"python"``, ``"javascript"``, ``"c"``).
        """
        if language == self._current_language and self._highlighter is not None:
            return

        if self._highlighter is not None:
            self._highlighter.setDocument(None)
            self._highlighter.setParent(None)
            self._highlighter.deleteLater()
            self._highlighter = None

        self._current_language = language
        document = self.document()
        if document is None:
            _logger.debug("script_editor_no_document", language=language)
            return

        highlighter = get_highlighter_for_language(language, document)
        if highlighter is None:
            _logger.debug("script_editor_no_highlighter", language=language)
            return

        self._highlighter = highlighter
        highlighter.rehighlight()
        _logger.debug("script_editor_highlighter_attached", language=language)

    def get_content(self) -> str:
        """Get the current editor content.

        Returns:
            str: Script content string.
        """
        return self.toPlainText()

    def set_content(self, content: str) -> None:
        """Set the editor content.

        Args:
            content: Script content to display.
        """
        self.setPlainText(content)


class ScriptManagerPanel(QWidget):
    """Main script manager panel for creating, editing, and executing scripts.

    Provides a split view with script list and editor, plus controls
    for script management and execution.

    Attributes:
        script_execute: Qt signal emitted with ``(name, script_type, content)`` when Execute is pressed.
        script_execution_completed: Qt signal emitted with ``(name, result)`` after acknowledge_execution.
    """

    script_execute = pyqtSignal(str, str, str)
    script_execution_completed = pyqtSignal(str, str)

    @override
    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ScriptManagerPanel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._backend: ScriptManager | None = None
        self._validator: ScriptValidator | None = None
        self._executor: ScriptExecutor | None = None
        self._current_script_id: str | None = None
        self._modified = False
        self._execution_in_progress: bool = False
        self._execution_timer: QTimer = QTimer(self)
        self._execution_timer.setSingleShot(True)
        self._execution_timer.setInterval(_EXECUTION_TIMEOUT_MS)
        self._execution_timer.timeout.connect(self._on_execution_timeout)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QFrame()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN_INNER, _PANEL_MARGIN)
        left_layout.setSpacing(_PANEL_SPACING)

        filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter:")
        self._filter_combo = QComboBox()
        self._filter_combo.addItem("All Types", None)
        for script_type in ScriptTypeInfo.get_types():
            display = ScriptTypeInfo.get_display_name(script_type)
            self._filter_combo.addItem(display, script_type)
        self._filter_combo.currentIndexChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self._filter_combo, 1)
        left_layout.addLayout(filter_layout)

        self._script_list = ScriptListWidget()
        self._script_list.script_selected.connect(self._on_script_selected)
        left_layout.addWidget(self._script_list)

        left_panel.setMaximumWidth(_LEFT_PANEL_MAX_WIDTH)
        splitter.addWidget(left_panel)

        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(_PANEL_MARGIN_INNER, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        right_layout.setSpacing(_PANEL_SPACING)

        header_layout = QHBoxLayout()
        header_layout.setSpacing(_PANEL_SPACING)

        self._name_edit = QLineEdit()
        self._name_edit.setToolTip("Enter script name")
        self._name_edit.setClearButtonEnabled(True)
        header_layout.addWidget(self._name_edit, 1)

        self._type_combo = QComboBox()
        for script_type in ScriptTypeInfo.get_types():
            display = ScriptTypeInfo.get_display_name(script_type)
            self._type_combo.addItem(display, script_type)
        self._type_combo.currentIndexChanged.connect(self._on_type_changed)
        header_layout.addWidget(self._type_combo)

        right_layout.addLayout(header_layout)

        self._editor = ScriptEditor()
        self._editor.content_changed.connect(self._on_content_changed)
        right_layout.addWidget(self._editor, 1)

        self._result_pane = QPlainTextEdit()
        self._result_pane.setObjectName("script_result_pane")
        self._result_pane.setReadOnly(True)
        self._result_pane.setMinimumHeight(_RESULT_PANE_MIN_HEIGHT)
        self._result_pane.setFont(FontManager.get_instance().get_code_font(10))
        self._result_pane.setPlaceholderText("Script execution results will appear here.")
        right_layout.addWidget(self._result_pane)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(_PANEL_SPACING)

        self._new_btn = QPushButton("New")
        self._new_btn.clicked.connect(self._on_new)
        button_layout.addWidget(self._new_btn)

        self._save_btn = QPushButton("Save")
        self._save_btn.clicked.connect(self._on_save)
        button_layout.addWidget(self._save_btn)

        self._delete_btn = QPushButton("Delete")
        self._delete_btn.clicked.connect(self._on_delete)
        button_layout.addWidget(self._delete_btn)

        self._load_file_btn = QPushButton("Load File")
        self._load_file_btn.clicked.connect(self._on_load_file)
        button_layout.addWidget(self._load_file_btn)

        button_layout.addStretch()

        self._validate_btn = QPushButton("Validate")
        self._validate_btn.clicked.connect(self._on_validate)
        button_layout.addWidget(self._validate_btn)

        self._execute_btn = QPushButton("Execute")
        self._execute_btn.setObjectName("execute_button")
        self._execute_btn.clicked.connect(self._on_execute)
        button_layout.addWidget(self._execute_btn)

        right_layout.addLayout(button_layout)

        splitter.addWidget(right_panel)
        splitter.setSizes([_SPLITTER_LEFT_SIZE, _SPLITTER_RIGHT_SIZE])

        layout.addWidget(splitter)

        self._status_bar = QStatusBar()
        self._status_bar.setProperty("status", "info")
        _restyle(self._status_bar)
        self._status_bar.showMessage("Ready")
        layout.addWidget(self._status_bar)

        initial_type = str(self._type_combo.currentData() or "frida")
        self._editor.set_language(ScriptTypeInfo.get_language(initial_type))

    def _on_filter_changed(self, _index: int) -> None:
        """Handle filter combo change.

        Args:
            _index: Selected index (unused, data retrieved from combo).
        """
        script_type_data = self._filter_combo.currentData()
        self._script_list.set_filter(str(script_type_data) if script_type_data else None)

    def _on_type_changed(self, _index: int) -> None:
        """Handle type combo change.

        Args:
            _index: Selected index (unused, data retrieved from combo).
        """
        if script_type_raw := self._type_combo.currentData():
            language = ScriptTypeInfo.get_language(str(script_type_raw))
            self._editor.set_language(language)

    @staticmethod
    def _build_script(name: str, script_type: str, content: str) -> Script:
        """Build a Script object from panel data.

        Args:
            name: Script name.
            script_type: Script type identifier.
            content: Script content.

        Returns:
            Script: Script object ready for use with ScriptManager.
        """
        language_map = {
            "frida": ScriptLanguage.JAVASCRIPT,
            "ghidra": ScriptLanguage.JAVA,
            "cutter": ScriptLanguage.R2_COMMANDS,
            "x64dbg": ScriptLanguage.X64DBG_SCRIPT,
            "python": ScriptLanguage.PYTHON,
        }
        language = language_map.get(script_type, ScriptLanguage.JAVASCRIPT)

        valid_type = cast("ScriptType", script_type) if script_type in language_map else cast("ScriptType", "frida")

        return Script(
            name=name,
            script_type=valid_type,
            language=language,
            content=content,
            description=f"Script: {name}",
        )

    def _on_script_selected(self, script_id: str) -> None:
        """Handle script selection.

        Args:
            script_id: Selected script ID.
        """
        if self._modified:
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "Save current script before switching?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._on_save()
            elif reply == QMessageBox.StandardButton.Cancel:
                return

        self._load_script(script_id)

    def _load_script(self, script_id: str) -> None:
        """Load a script into the editor.

        Refreshes the script from disk before loading to pick up
        any external modifications.

        Args:
            script_id: Script ID to load.
        """
        if not self._backend:
            return

        reload_fn = getattr(self._backend, "reload_script", None)
        if callable(reload_fn):
            reload_fn(script_id)

        script = self._backend.get_script(script_id)
        if not script:
            return

        self._current_script_id = script_id
        self._name_edit.setText(script.name)

        type_index = self._type_combo.findData(script.script_type)
        if type_index >= 0:
            self._type_combo.setCurrentIndex(type_index)

        self._editor.set_content(script.content)
        self._modified = False
        self._status_bar.showMessage(f"Loaded: {script.name}")
        _logger.debug("script_loaded", script_id=script_id, script_name=script.name)

    def _on_content_changed(self) -> None:
        """Handle editor content change."""
        self._modified = True

    def _on_new(self) -> None:
        """Handle new script button."""
        if self._modified:
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "Save current script before creating new?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._on_save()
            elif reply == QMessageBox.StandardButton.Cancel:
                return

        self._current_script_id = None
        self._name_edit.clear()

        script_type = str(self._type_combo.currentData() or "frida")
        template = ScriptTypeInfo.get_template(script_type)
        self._editor.set_content(template)
        self._modified = False
        self._status_bar.showMessage("New script created")
        _logger.debug("script_new_created", script_type=script_type)

    def _on_save(self) -> None:
        """Handle save button.

        On successful backend add, detects rename (``current_script_id`` differs from the entered name) and removes the old backend entry
        and list item so the same script does not appear twice under two identities.
        """
        name = self._name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Error", "Please enter a script name.")
            return

        script_type = str(self._type_combo.currentData() or "frida")
        content = self._editor.get_content()
        previous_id = self._current_script_id

        if self._backend:
            script = self._build_script(name, script_type, content)
            if not self._backend.add_script(script, validate=False):
                self._status_bar.showMessage("Failed to save script")
                return

            if previous_id and previous_id != name:
                self._backend.delete_script(previous_id)
                self._script_list.remove_script(previous_id)
                self._script_list.add_script(name, name, script_type)
                _logger.info(
                    "script_renamed",
                    old_script_id=previous_id,
                    new_script_id=name,
                    script_type=script_type,
                )
            elif not previous_id:
                self._script_list.add_script(name, name, script_type)

            self._current_script_id = name

        self._modified = False

        ensure_saved = getattr(self._backend, "ensure_script_saved", None)
        if callable(ensure_saved):
            ensure_saved(name)

        self._status_bar.showMessage(f"Saved: {name}")
        _logger.info("script_saved", script_name=name, script_type=script_type)

    def _on_delete(self) -> None:
        """Handle delete button."""
        if not self._current_script_id:
            return

        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            "Are you sure you want to delete this script?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            deleted_id = self._current_script_id
            if self._backend:
                self._backend.delete_script(self._current_script_id)
            self._script_list.remove_script(self._current_script_id)

            self._current_script_id = None
            self._name_edit.clear()
            self._editor.set_content("")
            self._modified = False
            self._status_bar.showMessage("Script deleted")
            _logger.info("script_deleted", script_id=deleted_id)

    def _on_load_file(self) -> None:
        """Handle load file button."""
        script_type = str(self._type_combo.currentData() or "frida")
        extension = ScriptTypeInfo.get_extension(script_type)

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Script",
            "",
            f"Script files (*{extension});;All files (*.*)",
        )

        if file_path:
            content: str | None = None
            try:
                content = Path(file_path).read_text(encoding="utf-8")
            except OSError:
                _logger.exception("script_file_load_failed", path=file_path)
                QMessageBox.critical(self, "Error", "Failed to load file. Check logs for details.")
            if content is not None:
                self._editor.set_content(content)
                name = Path(file_path).stem
                self._name_edit.setText(name)
                self._modified = True
                self._status_bar.showMessage(f"Loaded from: {file_path}")

    def _set_status_style(self, status: str) -> None:
        """Set the status bar QSS property and refresh its style.

        Args:
            status: One of ``"info"``, ``"error"``, ``"success"``, or ``"idle"``.
        """
        self._status_bar.setProperty("status", status)
        _restyle(self._status_bar)

    def _on_validate(self) -> None:
        """Handle validate button."""
        if not self._validator:
            self._status_bar.showMessage("Validator not configured")
            return

        name = self._name_edit.text().strip() or "Unnamed"
        script_type = str(self._type_combo.currentData() or "frida")
        content = self._editor.get_content()

        script = self._build_script(name, script_type, content)

        validation_completed = False
        is_valid = False
        error_msg: str | None = None
        try:
            is_valid, error_msg = self._validator.validate(script)
            validation_completed = True
        except (RuntimeError, ValueError):
            _logger.exception("script_validation_failed", script_name=name)
            self._status_bar.showMessage("Validation error. Check logs for details.")
            self._set_status_style("error")
        if validation_completed:
            if is_valid:
                self._status_bar.showMessage("Validation passed")
                self._set_status_style("success")
            else:
                error_text = error_msg or "Unknown error"
                self._status_bar.showMessage(f"Validation failed: {error_text}")
                self._set_status_style("error")

        def reset_status() -> None:
            self._set_status_style("info")

        QTimer.singleShot(_STATUS_RESET_MS, reset_status)

    def _on_execute(self) -> None:
        """Handle execute button.

        Dispatches execution through the injected executor when available (preferred path), otherwise emits the ``script_execute`` signal
        for an external owner to handle. In both cases the panel enters an "executing" state: the Execute button is disabled, a persistent
        spinner message is shown on the status bar, and a timeout timer is armed. The state is cleared by ``acknowledge_execution`` or by
        timeout, never implicitly.
        """
        if self._execution_in_progress:
            _logger.debug("script_execute_ignored_busy")
            return

        name = self._name_edit.text().strip() or "Unnamed"
        script_type = str(self._type_combo.currentData() or "frida")
        content = self._editor.get_content()

        if not content.strip():
            QMessageBox.warning(self, "Error", "Cannot execute empty script.")
            return

        _logger.info("script_execute_requested", script_name=name, script_type=script_type)
        self._begin_execution(name)
        self._result_pane.setPlainText(f"Executing {name} ({script_type})...")

        if self._executor is not None:
            try:
                result = self._executor(name, script_type, content)
            except (RuntimeError, OSError, ValueError, TypeError) as exc:
                _logger.exception("script_execute_failed", script_name=name, script_type=script_type)
                self.acknowledge_execution(name, f"Execution error: {exc}")
                return
            if result is not None:
                self.acknowledge_execution(name, result)
            return

        self.script_execute.emit(name, script_type, content)

    def _begin_execution(self, name: str) -> None:
        """Enter the "executing" UI state.

        Args:
            name: Script name currently being executed.
        """
        self._execution_in_progress = True
        self._execute_btn.setEnabled(False)
        self._status_bar.showMessage(f"Executing: {name}...")
        self._set_status_style("info")
        self._execution_timer.start()

    def _end_execution(self) -> None:
        """Leave the "executing" UI state."""
        self._execution_in_progress = False
        self._execute_btn.setEnabled(True)
        self._execution_timer.stop()

    def _on_execution_timeout(self) -> None:
        """Handle execution timeout by clearing the busy state with a warning."""
        if not self._execution_in_progress:
            return
        _logger.warning("script_execute_timeout", timeout_ms=_EXECUTION_TIMEOUT_MS)
        self._end_execution()
        self._status_bar.showMessage("Execution timed out (no acknowledgement received)")
        self._set_status_style("error")
        self._result_pane.appendPlainText("\n[timeout] No acknowledgement received from executor.")

    def acknowledge_execution(self, name: str, result: str) -> None:
        """Clear the executing state and display a script's execution result.

        Owners that wire the ``script_execute`` signal must call this method
        once the external execution completes so the persistent spinner is
        turned off and the result pane is updated.

        Args:
            name: Script name that was executed.
            result: Textual result or error message to display.
        """
        self._end_execution()
        self._result_pane.setPlainText(result)
        self._status_bar.showMessage(f"Executed: {name}")
        self._set_status_style("success")
        _logger.info("script_execute_acknowledged", script_name=name, result_length=len(result))

        def reset_status() -> None:
            self._set_status_style("info")

        QTimer.singleShot(_STATUS_RESET_MS, reset_status)
        self.script_execution_completed.emit(name, result)

    def set_backend(
        self,
        manager: ScriptManager,
        validator: ScriptValidator | None = None,
        executor: ScriptExecutor | None = None,
    ) -> None:
        """Set the script manager backend and optional executor.

        Args:
            manager: The ScriptManager instance.
            validator: Optional ScriptValidator instance.
            executor: Optional callable ``(name, script_type, content) -> str | None``
                that dispatches script execution to the appropriate bridge for
                the given ``script_type``. When provided, execution is routed
                through this callable instead of only emitting the
                ``script_execute`` signal. A non-``None`` return value
                acknowledges execution synchronously; returning ``None``
                indicates the executor will call ``acknowledge_execution``
                later.
        """
        self._backend = manager
        self._validator = validator
        self._executor = executor

        for script_id in manager.list_scripts():
            if script := manager.get_script(script_id):
                self._script_list.add_script(script_id, script.name, script.script_type)

        _logger.info(
            "script_manager_backend_attached",
            script_count=len(manager.list_scripts()),
            executor_attached=executor is not None,
        )

    def get_current_script(self) -> tuple[str, str, str] | None:
        """Get the current script data.

        Returns:
            tuple[str, str, str] | None: Tuple of (name, type, content) or None.
        """
        name = self._name_edit.text().strip()
        script_type_raw = self._type_combo.currentData()
        content = self._editor.get_content()

        if not name or not script_type_raw or not content:
            return None

        return (name, str(script_type_raw), content)
