"""Tool configuration dialog for Intellicrack.

This module provides the UI for configuring reverse engineering tool
bridges, including path settings, installation, and connection options.
"""

from __future__ import annotations

import ctypes
import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import httpx
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ..core.logging import get_logger
from ..core.process_manager import ProcessManager
from .resources import IconManager


_winreg_module: ModuleType | None
try:
    import winreg as _winreg_module
except ImportError:
    _winreg_module = None


if TYPE_CHECKING:
    from types import ModuleType

    from intellicrack.core.tools import ToolRegistry


HTTP_OK = 200
EXPECTED_TOOL_COUNT = 6
_RETURNCODE_SUCCESS = 0

_logger = get_logger("ui.tool_config")
_hwnd_broadcast = 0xFFFF
_wm_settingchange = 0x1A
_smto_abortifhung = 0x2


class ToolInstallWorker(QThread):
    """Worker thread for installing tools.

    Downloads and installs tools in a separate thread to avoid blocking UI.

    Attributes:
        progress: Signal emitted with progress percentage (0-100).
        install_finished: Signal emitted when installation completes with (success, message).
    """

    progress: pyqtSignal = pyqtSignal(int)
    install_finished: pyqtSignal = pyqtSignal(bool, str)

    DOWNLOAD_URLS: ClassVar[dict[str, dict[str, str]]] = {
        "ghidra": {
            "url": "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip",
            "name": "Ghidra 11.2.1",
        },
        "x64dbg": {
            "url": "https://github.com/x64dbg/x64dbg/releases/download/snapshot/snapshot_2024-01-01_00-00.zip",
            "name": "x64dbg Snapshot",
        },
        "radare2": {
            "url": "https://github.com/radareorg/radare2/releases/download/5.9.6/radare2-5.9.6-w64.zip",
            "name": "radare2 5.9.6",
        },
    }

    def __init__(
        self,
        tool_id: str,
        install_path: Path,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the tool install worker.

        Args:
            tool_id: The tool identifier.
            install_path: Directory to install the tool.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._tool_id = tool_id
        self._install_path = install_path

    def run(self) -> None:
        """Run the installation in a separate thread."""
        try:
            self._install_tool()
        except Exception as e:
            _logger.exception("tool_install_failed", extra={"error": str(e)})
            self.install_finished.emit(False, f"Installation failed: {e}")

    def _install_tool(self) -> None:
        """Download and install the tool."""
        if self._tool_id not in self.DOWNLOAD_URLS:
            self.install_finished.emit(False, f"No download URL for {self._tool_id}")
            return

        tool_info = self.DOWNLOAD_URLS[self._tool_id]
        url = tool_info["url"]
        name = tool_info["name"]

        self.progress.emit(5)

        self._install_path.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            zip_path = temp_path / f"{self._tool_id}.zip"

            self.progress.emit(10)

            try:
                with (
                    httpx.Client(timeout=httpx.Timeout(300.0, connect=30.0)) as client,
                    client.stream("GET", url, follow_redirects=True) as response,
                ):
                    if response.status_code != HTTP_OK:
                        self.install_finished.emit(
                            False,
                            f"Download failed: HTTP {response.status_code}",
                        )
                        return

                    total = int(response.headers.get("content-length", 0))
                    downloaded = 0

                    with open(zip_path, "wb") as f:
                        for chunk in response.iter_bytes(chunk_size=8192):
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total > 0:
                                pct = int(10 + (downloaded / total) * 70)
                                self.progress.emit(pct)

            except httpx.TimeoutException as exc:
                _logger.exception("tool_download_timeout", extra={"tool_id": self._tool_id, "error": str(exc)})
                self.install_finished.emit(False, "Download timed out")
                return
            except httpx.ConnectError as exc:
                _logger.exception("tool_download_connect_error", extra={"tool_id": self._tool_id, "error": str(exc)})
                self.install_finished.emit(False, "Could not connect to download server")
                return

            self.progress.emit(85)

            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(self._install_path)
            except zipfile.BadZipFile as exc:
                _logger.exception("tool_extraction_bad_zip", extra={"tool_id": self._tool_id, "error": str(exc)})
                self.install_finished.emit(False, "Downloaded file is not a valid ZIP archive")
                return

            self.progress.emit(95)

            if self._tool_id == "ghidra":
                self._post_install_ghidra()
            elif self._tool_id == "radare2":
                self._post_install_radare2()

            self.progress.emit(100)
            self.install_finished.emit(True, f"{name} installed successfully")

    def _post_install_ghidra(self) -> None:
        """Post-installation setup for Ghidra.

        Raises:
            RuntimeError: If Ghidra installation not found or bridge install fails.
        """
        ghidra_root: Path | None = next(
            (
                item
                for item in self._install_path.iterdir()
                if item.is_dir() and item.name.startswith("ghidra_")
            ),
            None,
        )
        if ghidra_root is None:
            candidate = self._install_path / "ghidraRun.bat"
            if candidate.exists():
                ghidra_root = self._install_path

        if ghidra_root is None:
            error_message = "Ghidra installation not found after extraction"
            raise RuntimeError(error_message)

        process_manager = ProcessManager.get_instance()
        result = process_manager.run_tracked(
            [sys.executable, "-m", "pip", "install", "ghidra_bridge"],
            name="pip-install-ghidra-bridge",
            check=False,
            timeout=300,
        )
        if result.returncode != _RETURNCODE_SUCCESS:
            error_message = f"Failed to install ghidra_bridge: {result.stderr.strip()}"
            raise RuntimeError(error_message)

        scripts_dir = ghidra_root / "ghidra_scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)

        bridge_script_content = (
            'import ghidra_bridge_server\nghidra_bridge_server.GhidraBridgeServer(server_host="127.0.0.1", server_port=4768).start()\n'
        )

        script_path = scripts_dir / "intellicrack_bridge.py"
        script_path.write_text(bridge_script_content, encoding="utf-8")

        extensions_dir = ghidra_root / "Extensions" / "intellicrack_bridge"
        extensions_dir.mkdir(parents=True, exist_ok=True)

        ext_script_path = extensions_dir / "intellicrack_bridge.py"
        ext_script_path.write_text(bridge_script_content, encoding="utf-8")

        install_script_path = extensions_dir / "install_bridge.py"
        install_script_path.write_text(
            (
                "from pathlib import Path\n"
                "import shutil\n"
                "\n"
                "def main() -> None:\n"
                "    ext_dir = Path(__file__).resolve().parent\n"
                "    ghidra_root = ext_dir.parent\n"
                "    src_script = ext_dir / 'intellicrack_bridge.py'\n"
                "    dst_dir = ghidra_root / 'ghidra_scripts'\n"
                "    dst_dir.mkdir(parents=True, exist_ok=True)\n"
                "    shutil.copy2(src_script, dst_dir / src_script.name)\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
            encoding="utf-8",
        )

        support_dir = ghidra_root / "support"
        support_dir.mkdir(parents=True, exist_ok=True)
        headless_script_path = support_dir / "intellicrack_headless_bridge.bat"
        headless_script_path.write_text(
            (
                "@echo off\n"
                "setlocal\n"
                'set "GHIDRA_DIR=%~dp0.."\n'
                'set "PROJECT_DIR=%~1"\n'
                'set "PROJECT_NAME=%~2"\n'
                'if "%PROJECT_DIR%"=="" (\n'
                "  echo Usage: %~nx0 ^<project_dir^> [project_name] [extra args]\n"
                "  exit /b 1\n"
                ")\n"
                'if "%PROJECT_NAME%"=="" (\n'
                '  set "PROJECT_NAME=intellicrack"\n'
                ")\n"
                "shift\n"
                "shift\n"
                '"%GHIDRA_DIR%\\support\\analyzeHeadless.bat" "%PROJECT_DIR%" '
                '"%PROJECT_NAME%" -scriptPath "%GHIDRA_DIR%\\ghidra_scripts" '
                "-postScript intellicrack_bridge.py %*\n"
            ),
            encoding="utf-8",
        )

        verify_script_path = ghidra_root / "verify_intellicrack_bridge.py"
        verify_script_path.write_text(
            (
                "import socket\n"
                "import sys\n"
                "\n"
                "def main() -> int:\n"
                "    try:\n"
                "        import ghidra_bridge\n"
                "    except ImportError as exc:\n"
                '        print(f"ghidra_bridge import failed: {exc}")\n'
                "        return 1\n"
                "    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "    sock.settimeout(3.0)\n"
                "    try:\n"
                '        sock.connect(("127.0.0.1", 4768))\n'
                '        print("bridge server reachable")\n'
                "        return 0\n"
                "    except OSError as exc:\n"
                '        print(f"bridge server not reachable: {exc}")\n'
                "        return 2\n"
                "    finally:\n"
                "        sock.close()\n"
                "\n"
                'if __name__ == "__main__":\n'
                "    sys.exit(main())\n"
            ),
            encoding="utf-8",
        )

    def _post_install_radare2(self) -> None:
        """Post-installation setup for radare2."""
        bin_path = self._find_radare2_bin_path()
        self._update_radare2_path(bin_path)
        self._verify_radare2()
        self._ensure_radare2_config()

    def _find_radare2_bin_path(self) -> Path:
        """Locate the radare2 bin directory.

        Returns:
            Path to the radare2 bin directory.

        Raises:
            RuntimeError: If the bin directory cannot be found.
        """
        candidates: list[Path] = []
        direct_bin = self._install_path / "bin"
        if direct_bin.exists():
            candidates.append(direct_bin)

        for item in self._install_path.iterdir():
            if item.is_dir():
                candidate = item / "bin"
                if candidate.exists():
                    candidates.append(candidate)

        for candidate in candidates:
            if (candidate / "radare2.exe").exists() or (candidate / "r2.exe").exists():
                return candidate

        error_message = "radare2 bin directory not found after extraction"
        raise RuntimeError(error_message)

    def _update_radare2_path(self, bin_path: Path) -> None:
        """Update PATH to include radare2.

        Args:
            bin_path: Path to radare2 bin directory.

        Raises:
            RuntimeError: If updating PATH fails.
        """
        bin_path_str = str(bin_path)

        if os.name == "nt":
            if _winreg_module is None:
                error_message = "winreg not available for PATH updates"
                raise RuntimeError(error_message)

            try:
                key = _winreg_module.OpenKey(
                    _winreg_module.HKEY_CURRENT_USER,
                    "Environment",
                    0,
                    _winreg_module.KEY_READ | _winreg_module.KEY_WRITE,
                )
                try:
                    current_path, value_type = _winreg_module.QueryValueEx(key, "Path")
                except FileNotFoundError:
                    current_path = ""
                    value_type = _winreg_module.REG_EXPAND_SZ

                existing = [os.path.normcase(os.path.normpath(p.strip())) for p in current_path.split(os.pathsep) if p.strip()]
                if os.path.normcase(os.path.normpath(bin_path_str)) not in existing:
                    new_path = f"{bin_path_str}{os.pathsep}{current_path}" if current_path else bin_path_str
                    _winreg_module.SetValueEx(key, "Path", 0, value_type, new_path)
                _winreg_module.CloseKey(key)
            except OSError as exc:
                error_message = f"Failed to update PATH: {exc}"
                raise RuntimeError(error_message) from exc

            self._broadcast_environment_change()

        current_env_path = os.environ.get("PATH", "")
        if bin_path_str not in current_env_path:
            os.environ["PATH"] = f"{bin_path_str}{os.pathsep}{current_env_path}" if current_env_path else bin_path_str

    @staticmethod
    def _broadcast_environment_change() -> None:
        """Broadcast environment change to running processes."""
        _logger.debug("environment_change_broadcast_starting", extra={})
        try:
            ctypes.windll.user32.SendMessageTimeoutW(
                _hwnd_broadcast,
                _wm_settingchange,
                0,
                "Environment",
                _smto_abortifhung,
                5000,
                None,
            )
            _logger.debug("environment_change_broadcast_completed", extra={})
        except Exception as exc:
            _logger.warning("environment_change_broadcast_failed", extra={"error": str(exc)})

    @staticmethod
    def _verify_radare2() -> None:
        """Verify radare2 is available in PATH.

        Raises:
            RuntimeError: If verification fails.
        """
        process_manager = ProcessManager.get_instance()
        result = process_manager.run_tracked(
            ["radare2", "-v"],
            name="radare2-verify",
            check=False,
            timeout=10,
        )
        if result.returncode != _RETURNCODE_SUCCESS:
            error_message = "radare2 verification failed after PATH update"
            raise RuntimeError(error_message)

    @staticmethod
    def _ensure_radare2_config() -> None:
        """Create default radare2 configuration if missing."""
        config_dir = Path.home() / ".radare2"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "radare2rc"
        if not config_path.exists():
            config_path.write_text(
                "e asm.syntax=intel\ne asm.lines=true\ne scr.color=1\n",
                encoding="utf-8",
            )


class ToolStatusCheckWorker(QThread):
    """Worker thread for checking tool status.

    Attributes:
        status_checked: Signal emitted when check completes with (tool_id, is_available, message).
    """

    status_checked: pyqtSignal = pyqtSignal(str, bool, str)

    def __init__(
        self,
        tool_id: str,
        tool_path: str,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the status check worker.

        Args:
            tool_id: The tool identifier.
            tool_path: Path to the tool installation.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._tool_id = tool_id
        self._tool_path = tool_path

    def run(self) -> None:
        """Run the status check in a separate thread."""
        try:
            _logger.debug("tool_status_check_started", extra={"tool_id": self._tool_id, "tool_path": self._tool_path})
            is_available, message = self._check_tool()
            _logger.debug("tool_status_check_completed", extra={"tool_id": self._tool_id, "available": is_available, "status_message": message})
            self.status_checked.emit(self._tool_id, is_available, message)
        except Exception as e:
            _logger.exception("tool_status_check_failed", extra={"tool_id": self._tool_id, "error": str(e)})
            self.status_checked.emit(self._tool_id, False, f"Check failed: {e}")

    def _check_tool(self) -> tuple[bool, str]:
        """Check if the tool is available and working.

        Returns:
            Tuple of (is_available, status_message).
        """
        if self._tool_id in {"frida", "process", "binary"}:
            return self._check_builtin()

        if not self._tool_path:
            return False, "Path not configured"

        tool_path = Path(self._tool_path)
        if not tool_path.exists():
            return False, "Path does not exist"

        if self._tool_id == "ghidra":
            return self._check_ghidra(tool_path)
        if self._tool_id == "x64dbg":
            return self._check_x64dbg(tool_path)
        if self._tool_id == "radare2":
            return self._check_radare2(tool_path)

        return True, "Installed"

    def _check_builtin(self) -> tuple[bool, str]:
        """Check built-in tools.

        Returns:
            Tuple of (is_available, status_message).
        """
        if self._tool_id == "frida":
            if importlib.util.find_spec("frida") is None:
                return False, "Frida not installed (pip install frida)"
            frida_module = importlib.import_module("frida")
            version = getattr(frida_module, "__version__", "unknown")
            return True, f"Frida {version} available"

        return True, "Available (built-in)"

    @staticmethod
    def _check_ghidra(tool_path: Path) -> tuple[bool, str]:
        """Check Ghidra installation.

        Args:
            tool_path: Path to Ghidra installation.

        Returns:
            Tuple of (is_available, status_message).
        """
        ghidra_run = None
        for item in tool_path.iterdir():
            if item.is_dir() and item.name.startswith("ghidra_"):
                ghidra_run = item / "ghidraRun.bat"
                if not ghidra_run.exists():
                    ghidra_run = item / "ghidraRun"
                break

        if ghidra_run is None:
            for candidate in [
                tool_path / "ghidraRun.bat",
                tool_path / "ghidraRun",
            ]:
                if candidate.exists():
                    ghidra_run = candidate
                    break

        if ghidra_run and ghidra_run.exists():
            return True, "Ghidra installed"

        return False, "ghidraRun not found in installation"

    @staticmethod
    def _check_x64dbg(tool_path: Path) -> tuple[bool, str]:
        """Check x64dbg installation.

        Args:
            tool_path: Path to x64dbg installation.

        Returns:
            Tuple of (is_available, status_message).
        """
        x64dbg_exe = tool_path / "release" / "x64" / "x64dbg.exe"
        x32dbg_exe = tool_path / "release" / "x32" / "x32dbg.exe"

        return next(
            (
                (True, "x64dbg installed")
                for candidate in [
                    x64dbg_exe,
                    x32dbg_exe,
                    tool_path / "x64" / "x64dbg.exe",
                    tool_path / "x64dbg.exe",
                ]
                if candidate.exists()
            ),
            (False, "x64dbg.exe not found"),
        )

    @staticmethod
    def _check_radare2(tool_path: Path) -> tuple[bool, str]:
        """Check radare2 installation.

        Args:
            tool_path: Path to radare2 installation.

        Returns:
            Tuple of (is_available, status_message).
        """
        for candidate in [
            tool_path / "bin" / "radare2.exe",
            tool_path / "radare2.exe",
            tool_path / "bin" / "r2.exe",
        ]:
            if candidate.exists():
                return True, "radare2 installed"

        try:
            process_manager = ProcessManager.get_instance()
            result = process_manager.run_tracked(
                ["r2", "-v"],
                name="r2-path-check",
                check=False,
                timeout=5,
            )
            if result.returncode == _RETURNCODE_SUCCESS:
                return True, "radare2 available in PATH"
        except subprocess.TimeoutExpired:
            _logger.debug("radare2_path_check_timed_out", extra={})
        except FileNotFoundError:
            _logger.debug("radare2_executable_not_in_path", extra={})
        except OSError as e:
            _logger.debug("radare2_os_error", extra={"error": str(e)})

        return False, "radare2 executable not found"


class ToolConfigDialog(QDialog):
    """Dialog for configuring reverse engineering tools.

    Allows users to:
    - Configure tool installation paths
    - Enable/disable specific tools
    - Set startup timeouts
    - Install missing tools
    - Test tool connections

    Attributes:
        tool_updated: Signal emitted when a tool config changes.
    """

    tool_updated: pyqtSignal = pyqtSignal(str)

    def __init__(
        self,
        tool_registry: ToolRegistry | None = None,
        tools_directory: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the tool configuration dialog.

        Args:
            tool_registry: Registry containing tool bridge instances.
            tools_directory: Directory for tool installations.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._registry = tool_registry
        self._tools_directory = tools_directory or Path("D:/Intellicrack/tools")
        self._tool_widgets: dict[str, ToolSettingsWidget] = {}
        self._current_tool: str | None = None
        self._config_path = Path.home() / ".intellicrack" / "tools.json"

        self._setup_ui()
        self._load_tools()

        self.setWindowTitle("Tool Settings")
        self.resize(750, 550)

    def _setup_ui(self) -> None:
        """Set up the dialog UI layout."""
        layout = QVBoxLayout(self)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._tool_list = QListWidget()
        self._tool_list.setMaximumWidth(180)
        self._tool_list.currentRowChanged.connect(self._on_tool_selected)

        self._settings_stack = QStackedWidget()

        splitter.addWidget(self._tool_list)
        splitter.addWidget(self._settings_stack)
        splitter.setSizes([180, 570])

        layout.addWidget(splitter, stretch=1)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Apply
        )
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)

        if apply_button := button_box.button(
            QDialogButtonBox.StandardButton.Apply
        ):
            apply_button.clicked.connect(self._on_apply)

        layout.addWidget(button_box)

    def _load_tools(self) -> None:
        """Load tool configurations into the list."""
        tools = [
            ("Ghidra", "ghidra", "Static analysis and decompilation"),
            ("x64dbg", "x64dbg", "Windows debugger"),
            ("Frida", "frida", "Dynamic instrumentation"),
            ("radare2", "radare2", "Reverse engineering framework"),
            ("Process Control", "process", "Windows process manipulation"),
            ("Binary Operations", "binary", "Binary file analysis"),
        ]

        for display_name, tool_id, description in tools:
            item = QListWidgetItem(display_name)
            item.setData(Qt.ItemDataRole.UserRole, tool_id)
            item.setToolTip(description)
            self._tool_list.addItem(item)

            widget = ToolSettingsWidget(
                tool_id,
                display_name,
                description,
                self._tools_directory,
                self._registry,
                self._config_path,
            )
            self._settings_stack.addWidget(widget)
            self._tool_widgets[tool_id] = widget

        if self._tool_list.count() > 0:
            self._tool_list.setCurrentRow(0)

    def _on_tool_selected(self, index: int) -> None:
        """Handle tool selection change.

        Args:
            index: The selected tool index.
        """
        if index >= 0:
            if item := self._tool_list.item(index):
                tool_id = item.data(Qt.ItemDataRole.UserRole)
                self._current_tool = tool_id
                self._settings_stack.setCurrentIndex(index)

    def _on_accept(self) -> None:
        """Handle dialog acceptance."""
        self._save_all_settings()
        self.accept()

    def _on_apply(self) -> None:
        """Handle apply button click."""
        self._save_all_settings()

    def _save_all_settings(self) -> None:
        """Save settings for all tools."""
        for tool_id, widget in self._tool_widgets.items():
            widget.save_settings()
            self.tool_updated.emit(tool_id)

    def get_settings(self) -> dict[str, dict[str, Any]]:
        """Get all tool settings.

        Returns:
            Dictionary mapping tool IDs to their settings.
        """
        settings: dict[str, dict[str, Any]] = {
            tool_id: widget.get_settings()
            for tool_id, widget in self._tool_widgets.items()
        }
        return settings


class ToolSettingsWidget(QFrame):
    """Widget for configuring a single tool.

    Displays path configuration, enable/disable toggle, and
    installation options for a specific tool.

    Attributes:
        status_changed: Signal emitted when tool status changes.
    """

    status_changed: pyqtSignal = pyqtSignal(str, bool)

    def __init__(
        self,
        tool_id: str,
        display_name: str,
        description: str,
        tools_directory: Path,
        registry: ToolRegistry | None = None,
        config_path: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the tool settings widget.

        Args:
            tool_id: The tool identifier.
            display_name: Human-readable tool name.
            description: Tool description.
            tools_directory: Base directory for tool installations.
            registry: Tool registry for status checking.
            config_path: Path to configuration file.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._tool_id = tool_id
        self._display_name = display_name
        self._description = description
        self._tools_directory = tools_directory
        self._registry = registry
        self._config_path = config_path or Path.home() / ".intellicrack" / "tools.json"
        self._install_worker: ToolInstallWorker | None = None
        self._status_worker: ToolStatusCheckWorker | None = None

        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        """Set up the widget UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel(f"<h3>{self._display_name}</h3>")
        layout.addWidget(title)

        desc_label = QLabel(self._description)
        desc_label.setObjectName("description_label")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)

        status_group = QGroupBox("Status")
        status_layout = QFormLayout()

        self._enabled_checkbox = QCheckBox("Enable this tool")
        self._enabled_checkbox.setChecked(True)
        status_layout.addRow(self._enabled_checkbox)

        status_row = QHBoxLayout()
        self._status_icon = QLabel()
        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_idle", 16))
        self._status_icon.setFixedSize(20, 20)
        status_row.addWidget(self._status_icon)

        self._status_label = QLabel("Unknown")
        self._status_label.setObjectName("status_label")
        status_row.addWidget(self._status_label)
        status_row.addStretch()

        status_layout.addRow("Status:", status_row)

        self._check_status_btn = QPushButton("Check Status")
        self._check_status_btn.clicked.connect(self._check_status)
        status_layout.addRow(self._check_status_btn)

        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        path_group = QGroupBox("Installation")
        path_layout = QFormLayout()

        path_row = QHBoxLayout()
        self._path_input = QLineEdit()
        self._path_input.setMinimumWidth(300)
        path_row.addWidget(self._path_input)

        self._browse_btn = QPushButton("Browse...")
        self._browse_btn.clicked.connect(self._browse_path)
        path_row.addWidget(self._browse_btn)

        path_layout.addRow("Installation Path:", path_row)

        self._auto_install_checkbox = QCheckBox("Auto-install if missing")
        self._auto_install_checkbox.setChecked(True)
        path_layout.addRow(self._auto_install_checkbox)

        install_row = QHBoxLayout()
        self._install_btn = QPushButton("Install Now")
        self._install_btn.clicked.connect(self._install_tool)
        install_row.addWidget(self._install_btn)

        self._install_progress = QProgressBar()
        self._install_progress.setVisible(False)
        self._install_progress.setMaximumWidth(200)
        install_row.addWidget(self._install_progress)
        install_row.addStretch()

        path_layout.addRow(install_row)

        path_group.setLayout(path_layout)
        layout.addWidget(path_group)

        options_group = QGroupBox("Options")
        options_layout = QFormLayout()

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(5, 300)
        self._timeout_spin.setValue(60)
        self._timeout_spin.setSuffix(" seconds")
        options_layout.addRow("Startup Timeout:", self._timeout_spin)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        layout.addStretch()

    def _load_settings(self) -> None:
        """Load settings from config file."""
        saved_settings = self._load_from_config()

        default_paths: dict[str, str] = {
            "ghidra": str(self._tools_directory / "ghidra"),
            "x64dbg": str(self._tools_directory / "x64dbg"),
            "radare2": str(self._tools_directory / "radare2"),
            "frida": "",
            "process": "",
            "binary": "",
        }

        path = saved_settings.get("path", default_paths.get(self._tool_id, ""))
        self._path_input.setText(path)

        self._enabled_checkbox.setChecked(saved_settings.get("enabled", True))
        self._auto_install_checkbox.setChecked(saved_settings.get("auto_install", True))
        self._timeout_spin.setValue(saved_settings.get("startup_timeout_seconds", 60))

        if self._tool_id in {"frida", "process", "binary"}:
            self._path_input.setEnabled(False)
            self._browse_btn.setEnabled(False)
            self._install_btn.setEnabled(False)
            self._auto_install_checkbox.setEnabled(False)
            self._path_input.setToolTip("This tool does not require a path")

    def _load_from_config(self) -> dict[str, Any]:
        """Load settings from the config file.

        Returns:
            Dictionary of saved settings for this tool.
        """
        if not self._config_path.exists():
            return {}

        try:
            with open(self._config_path, encoding="utf-8") as f:
                all_settings: dict[str, Any] = json.load(f)
                result: dict[str, Any] = all_settings.get(self._tool_id, {})
                return result
        except (json.JSONDecodeError, OSError):
            return {}

    def _browse_path(self) -> None:
        """Open file browser for tool path."""
        if path := QFileDialog.getExistingDirectory(
            self,
            f"Select {self._display_name} Installation",
            str(self._tools_directory),
        ):
            self._path_input.setText(path)

    def _check_status(self) -> None:
        """Check the tool installation status."""
        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_loading", 16))
        self._status_label.setText("Checking...")
        self._check_status_btn.setEnabled(False)

        self._status_worker = ToolStatusCheckWorker(
            self._tool_id,
            self._path_input.text().strip(),
            self,
        )
        self._status_worker.status_checked.connect(self._on_status_checked)
        self._status_worker.start()

    def _on_status_checked(self, tool_id: str, is_available: bool, message: str) -> None:
        """Handle status check completion.

        Args:
            tool_id: The tool that was checked.
            is_available: Whether the tool is available.
            message: Status message.
        """
        self._check_status_btn.setEnabled(True)
        icon_manager = IconManager.get_instance()

        if is_available:
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_success", 16))
        else:
            self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
        self._status_label.setText(message)
        self.status_changed.emit(tool_id, is_available)

    def _install_tool(self) -> None:
        """Install the tool."""
        if self._tool_id in {"frida", "process", "binary"}:
            QMessageBox.information(
                self,
                "Installation",
                f"{self._display_name} is built-in and does not require installation.",
            )
            return

        if self._tool_id not in ToolInstallWorker.DOWNLOAD_URLS:
            QMessageBox.warning(
                self,
                "Installation",
                f"Automatic installation not available for {self._display_name}.\n\nPlease download and install manually.",
            )
            return

        install_path = Path(self._path_input.text().strip())
        if not install_path:
            install_path = self._tools_directory / self._tool_id
            self._path_input.setText(str(install_path))

        reply = QMessageBox.question(
            self,
            "Install Tool",
            f"Download and install {self._display_name}?\n\nInstallation path:\n{install_path}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            self._install_progress.setVisible(True)
            self._install_progress.setValue(0)
            self._install_btn.setEnabled(False)

            self._install_worker = ToolInstallWorker(self._tool_id, install_path, self)
            self._install_worker.progress.connect(self._install_progress.setValue)
            self._install_worker.install_finished.connect(self._on_install_finished)
            self._install_worker.start()

    def _on_install_finished(self, success: bool, message: str) -> None:
        """Handle installation completion.

        Args:
            success: Whether installation was successful.
            message: Status message.
        """
        self._install_btn.setEnabled(True)
        self._install_progress.setVisible(False)

        if success:
            QMessageBox.information(self, "Installation Complete", message)
            self._check_status()
        else:
            QMessageBox.warning(self, "Installation Failed", message)

    def get_settings(self) -> dict[str, Any]:
        """Get current settings as a dictionary.

        Returns:
            Dictionary of current settings.
        """
        return {
            "enabled": self._enabled_checkbox.isChecked(),
            "path": self._path_input.text().strip(),
            "auto_install": self._auto_install_checkbox.isChecked(),
            "startup_timeout_seconds": self._timeout_spin.value(),
        }

    def save_settings(self) -> None:
        """Save current settings to config file."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)

        all_settings: dict[str, dict[str, Any]] = {}
        if self._config_path.exists():
            try:
                with open(self._config_path, encoding="utf-8") as f:
                    all_settings = json.load(f)
            except (json.JSONDecodeError, OSError):
                all_settings = {}

        all_settings[self._tool_id] = self.get_settings()

        try:
            with open(self._config_path, "w", encoding="utf-8") as f:
                json.dump(all_settings, f, indent=2)
        except OSError as e:
            QMessageBox.warning(
                self,
                "Save Error",
                f"Failed to save settings: {e}",
            )


class ToolCapabilitiesWidget(QFrame):
    """Widget displaying tool capabilities in a grid format."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the capabilities widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the capabilities display UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        self._name_label = QLabel("Select a tool")
        self._name_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        layout.addWidget(self._name_label)

        caps_group = QGroupBox("Capabilities")
        caps_layout = QFormLayout(caps_group)
        caps_layout.setSpacing(4)

        self._cap_labels: dict[str, QLabel] = {}
        capabilities = [
            ("static_analysis", "Static Analysis"),
            ("dynamic_analysis", "Dynamic Analysis"),
            ("decompilation", "Decompilation"),
            ("debugging", "Debugging"),
            ("patching", "Patching"),
            ("scripting", "Scripting"),
            ("memory_access", "Memory Access"),
        ]

        for cap_id, cap_name in capabilities:
            indicator = QLabel("\u25cb")
            indicator.setStyleSheet("color: #888;")
            self._cap_labels[cap_id] = indicator
            caps_layout.addRow(cap_name, indicator)

        layout.addWidget(caps_group)

        arch_group = QGroupBox("Architectures")
        arch_layout = QVBoxLayout(arch_group)
        self._arch_label = QLabel("--")
        self._arch_label.setWordWrap(True)
        self._arch_label.setStyleSheet("color: #aaa;")
        arch_layout.addWidget(self._arch_label)
        layout.addWidget(arch_group)

        fmt_group = QGroupBox("Formats")
        fmt_layout = QVBoxLayout(fmt_group)
        self._fmt_label = QLabel("--")
        self._fmt_label.setWordWrap(True)
        self._fmt_label.setStyleSheet("color: #aaa;")
        fmt_layout.addWidget(self._fmt_label)
        layout.addWidget(fmt_group)

        layout.addStretch()

    def set_tool(self, name: str, capabilities: dict[str, bool], archs: list[str], formats: list[str]) -> None:
        """Update the display for a specific tool.

        Args:
            name: Tool display name.
            capabilities: Dict of capability flags.
            archs: List of supported architectures.
            formats: List of supported binary formats.
        """
        self._name_label.setText(name)

        cap_mapping = {
            "static_analysis": "supports_static_analysis",
            "dynamic_analysis": "supports_dynamic_analysis",
            "decompilation": "supports_decompilation",
            "debugging": "supports_debugging",
            "patching": "supports_patching",
            "scripting": "supports_scripting",
            "memory_access": "supports_memory_access",
        }

        for cap_id, cap_key in cap_mapping.items():
            if label := self._cap_labels.get(cap_id):
                if capabilities.get(cap_key, False):
                    label.setText("\u25cf")
                    label.setStyleSheet("color: #4ec9b0;")
                else:
                    label.setText("\u25cb")
                    label.setStyleSheet("color: #888;")

        self._arch_label.setText(", ".join(archs) if archs else "--")
        self._fmt_label.setText(", ".join(formats) if formats else "--")


class ToolStatusDialog(QDialog):
    """Dialog showing status and capabilities of all configured tools.

    Displays which tools are installed, their connection state,
    supported capabilities, architectures, and file formats.
    """

    TOOL_CAPABILITIES: ClassVar[dict[str, dict[str, Any]]] = {
        "ghidra": {
            "supports_static_analysis": True,
            "supports_dynamic_analysis": False,
            "supports_decompilation": True,
            "supports_debugging": False,
            "supports_patching": True,
            "supports_scripting": True,
            "supports_memory_access": False,
            "architectures": ["x86", "x86_64", "ARM", "ARM64", "MIPS", "PPC"],
            "formats": ["PE", "ELF", "Mach-O", "Raw"],
        },
        "x64dbg": {
            "supports_static_analysis": False,
            "supports_dynamic_analysis": True,
            "supports_decompilation": False,
            "supports_debugging": True,
            "supports_patching": True,
            "supports_scripting": True,
            "supports_memory_access": True,
            "architectures": ["x86", "x86_64"],
            "formats": ["PE"],
        },
        "frida": {
            "supports_static_analysis": False,
            "supports_dynamic_analysis": True,
            "supports_decompilation": False,
            "supports_debugging": False,
            "supports_patching": False,
            "supports_scripting": True,
            "supports_memory_access": True,
            "architectures": ["x86", "x86_64", "ARM", "ARM64"],
            "formats": ["PE", "ELF", "Mach-O"],
        },
        "radare2": {
            "supports_static_analysis": True,
            "supports_dynamic_analysis": True,
            "supports_decompilation": True,
            "supports_debugging": True,
            "supports_patching": True,
            "supports_scripting": True,
            "supports_memory_access": True,
            "architectures": ["x86", "x86_64", "ARM", "ARM64", "MIPS", "PPC", "SPARC"],
            "formats": ["PE", "ELF", "Mach-O", "Raw", "DEX"],
        },
        "process": {
            "supports_static_analysis": False,
            "supports_dynamic_analysis": True,
            "supports_decompilation": False,
            "supports_debugging": False,
            "supports_patching": False,
            "supports_scripting": False,
            "supports_memory_access": True,
            "architectures": ["x86", "x86_64"],
            "formats": [],
        },
        "binary": {
            "supports_static_analysis": True,
            "supports_dynamic_analysis": False,
            "supports_decompilation": False,
            "supports_debugging": False,
            "supports_patching": True,
            "supports_scripting": False,
            "supports_memory_access": False,
            "architectures": ["x86", "x86_64", "ARM", "ARM64"],
            "formats": ["PE", "ELF", "Mach-O", "Raw"],
        },
    }

    def __init__(
        self,
        tool_registry: ToolRegistry | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the tool status dialog.

        Args:
            tool_registry: Registry containing tool bridge instances.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._registry = tool_registry
        self._config_path = Path.home() / ".intellicrack" / "tools.json"
        self._status_workers: list[ToolStatusCheckWorker] = []
        self._tool_statuses: dict[str, tuple[bool, str]] = {}

        self._setup_ui()
        self._refresh_status()

        self.setWindowTitle("Tool Status & Capabilities")
        self.resize(700, 500)

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QFrame()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        list_label = QLabel("Tools")
        list_label.setStyleSheet("font-weight: bold;")
        left_layout.addWidget(list_label)

        self._status_list = QListWidget()
        self._status_list.currentRowChanged.connect(self._on_tool_selected)
        left_layout.addWidget(self._status_list)

        splitter.addWidget(left_panel)

        self._capabilities_widget = ToolCapabilitiesWidget()
        splitter.addWidget(self._capabilities_widget)

        splitter.setSizes([300, 400])
        layout.addWidget(splitter)

        button_layout = QHBoxLayout()

        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self._refresh_status)
        button_layout.addWidget(self._refresh_btn)

        self._configure_btn = QPushButton("Configure")
        self._configure_btn.clicked.connect(self._on_configure)
        button_layout.addWidget(self._configure_btn)

        button_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

    def _on_tool_selected(self, row: int) -> None:
        """Handle tool selection in the list.

        Args:
            row: Selected row index.
        """
        tools = list(self.TOOL_CAPABILITIES.keys())
        if 0 <= row < len(tools):
            tool_id = tools[row]
            caps = self.TOOL_CAPABILITIES.get(tool_id, {})
            tool_names = {
                "ghidra": "Ghidra",
                "x64dbg": "x64dbg",
                "frida": "Frida",
                "radare2": "radare2",
                "process": "Process Control",
                "binary": "Binary Operations",
            }
            display_name = tool_names.get(tool_id, tool_id)
            archs = caps.get("architectures", [])
            formats = caps.get("formats", [])
            self._capabilities_widget.set_tool(display_name, caps, archs, formats)

    def _on_configure(self) -> None:
        """Open configuration dialog for selected tool."""
        if self._status_list.currentItem():
            config_dialog = ToolConfigDialog(parent=self)
            config_dialog.exec()
            self._refresh_status()

    def _load_settings(self) -> dict[str, dict[str, Any]]:
        """Load all tool settings from config.

        Returns:
            Dictionary mapping tool IDs to their settings.
        """
        if not self._config_path.exists():
            return {}

        try:
            with open(self._config_path, encoding="utf-8") as f:
                result: dict[str, dict[str, Any]] = json.load(f)
                return result
        except (json.JSONDecodeError, OSError):
            return {}

    def _refresh_status(self) -> None:
        """Refresh tool status display."""
        self._status_list.clear()
        self._tool_statuses.clear()
        self._refresh_btn.setEnabled(False)

        tools = [
            ("Ghidra", "ghidra", "Static analysis"),
            ("x64dbg", "x64dbg", "Debugging"),
            ("Frida", "frida", "Dynamic instrumentation"),
            ("radare2", "radare2", "Analysis framework"),
            ("Process Control", "process", "Process manipulation"),
            ("Binary Operations", "binary", "File analysis"),
        ]

        saved_settings = self._load_settings()

        for display_name, tool_id, _category in tools:
            item = QListWidgetItem(f"... {display_name} - Checking...")
            self._status_list.addItem(item)

            tool_settings = saved_settings.get(tool_id, {})
            tool_path = tool_settings.get("path", "")

            worker = ToolStatusCheckWorker(tool_id, tool_path, self)
            worker.status_checked.connect(self._on_tool_status_received)
            self._status_workers.append(worker)
            worker.start()

    def _on_tool_status_received(self, tool_id: str, is_available: bool, message: str) -> None:
        """Handle status check completion for a single tool.

        Args:
            tool_id: The tool that was checked.
            is_available: Whether the tool is available.
            message: Status message.
        """
        self._tool_statuses[tool_id] = (is_available, message)

        tool_names = {
            "ghidra": "Ghidra",
            "x64dbg": "x64dbg",
            "frida": "Frida",
            "radare2": "radare2",
            "process": "Process Control",
            "binary": "Binary Operations",
        }

        display_name = tool_names.get(tool_id, tool_id)
        status_icon = "\u2713" if is_available else "\u2717"
        status_text = message

        for i in range(self._status_list.count()):
            item = self._status_list.item(i)
            if item and display_name in item.text():
                item.setText(f"{status_icon}  {display_name} - {status_text}")
                break

        if len(self._tool_statuses) == EXPECTED_TOOL_COUNT:
            self._refresh_btn.setEnabled(True)
            self._status_workers.clear()
            if self._status_list.count() > 0:
                self._status_list.setCurrentRow(0)
