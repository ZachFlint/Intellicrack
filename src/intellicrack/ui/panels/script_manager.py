"""Script manager panel for creating and managing analysis scripts.

Provides a comprehensive UI for script editing, validation, and execution
with support for Frida, Ghidra, radare2, x64dbg, and Python scripts.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast, override

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
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

from intellicrack.core.script_gen import Script, ScriptLanguage, ScriptType


if TYPE_CHECKING:
    from intellicrack.core.script_gen import ScriptManager, ScriptValidator

_logger = logging.getLogger(__name__)


class ScriptTypeInfo:
    """Information about a script type including templates and extensions."""

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
        "radare2": {
            "display": "radare2",
            "extension": ".r2",
            "language": "r2cmd",
            "template": """# radare2 script for license analysis
# Target: {target}

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

// Set breakpoint at validation function
bp {address}

// When hit, modify return value
bpcnd {address}, "eax=1"

// Log when breakpoint is hit
log "License check bypassed at {address}"

// Continue execution
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

    with open(file_path, "rb") as f:
        data = f.read()

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
            List of script type identifiers.
        """
        return list(cls.TYPES.keys())

    @classmethod
    def get_display_name(cls, script_type: str) -> str:
        """Get display name for a script type.

        Args:
            script_type: Script type identifier.

        Returns:
            Human-readable display name.
        """
        info = cls.TYPES.get(script_type, {})
        return info.get("display", script_type)

    @classmethod
    def get_extension(cls, script_type: str) -> str:
        """Get file extension for a script type.

        Args:
            script_type: Script type identifier.

        Returns:
            File extension including dot.
        """
        info = cls.TYPES.get(script_type, {})
        return info.get("extension", ".txt")

    @classmethod
    def get_language(cls, script_type: str) -> str:
        """Get syntax highlighting language for a script type.

        Args:
            script_type: Script type identifier.

        Returns:
            Language identifier for syntax highlighting.
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
            Template script content.
        """
        info = cls.TYPES.get(script_type, {})
        template = info.get("template", "")
        return template.format(target=target, address=address)


class ScriptListWidget(QListWidget):
    """List widget for displaying and filtering scripts."""

    script_selected = pyqtSignal(str)

    @override
    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the script list widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._scripts: dict[str, dict[str, str]] = {}
        self._current_filter: str | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the list widget UI."""
        self.setStyleSheet("""
            QListWidget {
                background-color: #252526;
                border: none;
                outline: none;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #3e3e42;
            }
            QListWidget::item:selected {
                background-color: #094771;
            }
            QListWidget::item:hover {
                background-color: #2a2d2e;
            }
        """)

        self.itemClicked.connect(self._on_item_clicked)

    def _on_item_clicked(self, item: QListWidgetItem) -> None:
        """Handle item click.

        Args:
            item: Clicked list item.
        """
        script_id = item.data(Qt.ItemDataRole.UserRole)
        if script_id:
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
            Selected script ID or None.
        """
        current = self.currentItem()
        if current:
            return current.data(Qt.ItemDataRole.UserRole)
        return None


class ScriptEditor(QPlainTextEdit):
    """Code editor widget for script editing with basic styling."""

    content_changed = pyqtSignal()

    @override
    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the script editor.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent=parent)
        self._current_language = "text"
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the editor UI."""
        self.setFont(QFont("JetBrains Mono", 10))
        self.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: none;
                selection-background-color: #264f78;
            }
        """)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setTabStopDistance(40)

        self.textChanged.connect(self.content_changed.emit)

    def set_language(self, language: str) -> None:
        """Set the syntax highlighting language.

        Args:
            language: Language identifier.
        """
        self._current_language = language

    def get_content(self) -> str:
        """Get the current editor content.

        Returns:
            Script content string.
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
    """

    script_execute = pyqtSignal(str, str, str)

    @override
    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the script manager panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._backend: ScriptManager | None = None
        self._validator: ScriptValidator | None = None
        self._current_script_id: str | None = None
        self._modified = False
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QFrame()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(8, 8, 4, 8)
        left_layout.setSpacing(8)

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

        left_panel.setMaximumWidth(250)
        splitter.addWidget(left_panel)

        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(4, 8, 8, 8)
        right_layout.setSpacing(8)

        header_layout = QHBoxLayout()
        header_layout.setSpacing(8)

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
        right_layout.addWidget(self._editor)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(8)

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
        self._execute_btn.setStyleSheet("""
            QPushButton {
                background-color: #0e639c;
                padding: 6px 16px;
            }
            QPushButton:hover {
                background-color: #1177bb;
            }
        """)
        self._execute_btn.clicked.connect(self._on_execute)
        button_layout.addWidget(self._execute_btn)

        right_layout.addLayout(button_layout)

        splitter.addWidget(right_panel)
        splitter.setSizes([200, 600])

        layout.addWidget(splitter)

        self._status_bar = QStatusBar()
        self._status_bar.setStyleSheet("background-color: #007acc; color: white;")
        self._status_bar.showMessage("Ready")
        layout.addWidget(self._status_bar)

    def _on_filter_changed(self, _index: int) -> None:
        """Handle filter combo change.

        Args:
            _index: Selected index (unused, data retrieved from combo).
        """
        script_type = self._filter_combo.currentData()
        self._script_list.set_filter(script_type)

    def _on_type_changed(self, _index: int) -> None:
        """Handle type combo change.

        Args:
            _index: Selected index (unused, data retrieved from combo).
        """
        script_type = self._type_combo.currentData()
        if script_type:
            language = ScriptTypeInfo.get_language(script_type)
            self._editor.set_language(language)

    def _build_script(self, name: str, script_type: str, content: str) -> Script:
        """Build a Script object from panel data.

        Args:
            name: Script name.
            script_type: Script type identifier.
            content: Script content.

        Returns:
            Script object ready for use with ScriptManager.
        """
        language_map = {
            "frida": ScriptLanguage.JAVASCRIPT,
            "ghidra": ScriptLanguage.JAVA,
            "radare2": ScriptLanguage.R2_COMMANDS,
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

        Args:
            script_id: Script ID to load.
        """
        if not self._backend:
            return

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

        script_type = self._type_combo.currentData()
        template = ScriptTypeInfo.get_template(script_type or "frida")
        self._editor.set_content(template)
        self._modified = False
        self._status_bar.showMessage("New script created")

    def _on_save(self) -> None:
        """Handle save button."""
        name = self._name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Error", "Please enter a script name.")
            return

        script_type = self._type_combo.currentData() or "frida"
        content = self._editor.get_content()

        if self._backend:
            script = self._build_script(name, script_type, content)
            success = self._backend.add_script(script, validate=False)
            if success:
                if not self._current_script_id:
                    self._current_script_id = name
                    self._script_list.add_script(name, name, script_type)
            else:
                self._status_bar.showMessage("Failed to save script")
                return

        self._modified = False
        self._status_bar.showMessage(f"Saved: {name}")

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
            if self._backend:
                self._backend.delete_script(self._current_script_id)
            self._script_list.remove_script(self._current_script_id)

            self._current_script_id = None
            self._name_edit.clear()
            self._editor.set_content("")
            self._modified = False
            self._status_bar.showMessage("Script deleted")

    def _on_load_file(self) -> None:
        """Handle load file button."""
        script_type = self._type_combo.currentData() or "frida"
        extension = ScriptTypeInfo.get_extension(script_type)

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Script",
            "",
            f"Script files (*{extension});;All files (*.*)",
        )

        if file_path:
            try:
                content = Path(file_path).read_text(encoding="utf-8")
            except Exception:
                _logger.exception("script_file_load_failed", extra={"path": file_path})
                QMessageBox.critical(self, "Error", "Failed to load file. Check logs for details.")
            else:
                self._editor.set_content(content)
                name = Path(file_path).stem
                self._name_edit.setText(name)
                self._modified = True
                self._status_bar.showMessage(f"Loaded from: {file_path}")

    def _on_validate(self) -> None:
        """Handle validate button."""
        if not self._validator:
            self._status_bar.showMessage("Validator not configured")
            return

        name = self._name_edit.text().strip() or "Unnamed"
        script_type = self._type_combo.currentData() or "frida"
        content = self._editor.get_content()

        script = self._build_script(name, script_type, content)

        try:
            is_valid, error_msg = self._validator.validate(script)
        except Exception:
            _logger.exception("script_validation_failed")
            self._status_bar.showMessage("Validation error. Check logs for details.")
            self._status_bar.setStyleSheet("background-color: #f14c4c; color: white;")
        else:
            if is_valid:
                self._status_bar.showMessage("Validation passed")
                self._status_bar.setStyleSheet("background-color: #4ec9b0; color: black;")
            else:
                error_text = error_msg if error_msg else "Unknown error"
                self._status_bar.showMessage(f"Validation failed: {error_text}")
                self._status_bar.setStyleSheet("background-color: #f14c4c; color: white;")

        def reset_status() -> None:
            self._status_bar.setStyleSheet("background-color: #007acc; color: white;")

        QTimer.singleShot(3000, reset_status)

    def _on_execute(self) -> None:
        """Handle execute button."""
        name = self._name_edit.text().strip() or "Unnamed"
        script_type = self._type_combo.currentData() or "frida"
        content = self._editor.get_content()

        if not content.strip():
            QMessageBox.warning(self, "Error", "Cannot execute empty script.")
            return

        self._status_bar.showMessage(f"Executing: {name}...")
        self.script_execute.emit(name, script_type, content)

    def set_backend(self, manager: ScriptManager, validator: ScriptValidator | None = None) -> None:
        """Set the script manager backend.

        Args:
            manager: The ScriptManager instance.
            validator: Optional ScriptValidator instance.
        """
        self._backend = manager
        self._validator = validator

        for script_id in manager.list_scripts():
            script = manager.get_script(script_id)
            if script:
                self._script_list.add_script(script_id, script.name, script.script_type)

        _logger.info("Script manager backend attached")

    def get_current_script(self) -> tuple[str, str, str] | None:
        """Get the current script data.

        Returns:
            Tuple of (name, type, content) or None.
        """
        name = self._name_edit.text().strip()
        script_type = self._type_combo.currentData()
        content = self._editor.get_content()

        if not name or not script_type or not content:
            return None

        return (name, script_type, content)
