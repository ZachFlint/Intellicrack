"""Ghidra reverse engineering tool embedding widget.

Provides integration with Ghidra for binary analysis within
Intellicrack's interface via Win32 window embedding.
"""

from __future__ import annotations

import asyncio
import os
import winreg
from collections.abc import Coroutine
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar

from intellicrack.core.logging import get_logger
from intellicrack.ui.embedding.embedded_widget import EmbeddedToolWidget
from intellicrack.ui.embedding.win32_helper import Win32WindowHelper


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from intellicrack.bridges.ghidra import GhidraBridge

_logger = get_logger("ui.embedding.ghidra")

_T = TypeVar("_T")


class GhidraWidget(EmbeddedToolWidget):
    """Widget for embedding Ghidra reverse engineering framework.

    Provides Ghidra embedding with GhidraBridge integration
    for synchronized analysis and decompilation.
    """

    _GHIDRA_TITLE_PATTERN: ClassVar[str] = "Ghidra"
    _GHIDRA_WINDOW_CLASS: ClassVar[str] = "SunAwtFrame"
    _COMMON_PATHS: ClassVar[list[Path]] = [
        Path(r"C:\Program Files\Ghidra"),
        Path(r"C:\Program Files (x86)\Ghidra"),
        Path(r"D:\Tools\Ghidra"),
        Path(r"C:\Ghidra"),
        Path(r"C:\ghidra"),
    ]
    _REGISTRY_PATHS: ClassVar[list[tuple[int, str]]] = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Ghidra"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Ghidra"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize Ghidra embedding widget.

        Args:
            parent: Parent widget.
        """
        self._exe_path: Path | None = None
        self._bridge: GhidraBridge | None = None
        self._ghidra_home: Path | None = None
        self._background_tasks: set[asyncio.Task[object]] = set()
        super().__init__(parent)

    def get_tool_display_name(self) -> str:
        """Get display name for Ghidra.

        Returns:
            Display name string.
        """
        return "Ghidra"

    def get_executable_path(self) -> Path | None:
        """Find the Ghidra launcher executable.

        Searches GHIDRA_HOME env var, registry, common paths,
        project tools directory, and PATH for ghidraRun.bat.

        Returns:
            Path to executable if found.
        """
        if self._exe_path and self._exe_path.exists():
            return self._exe_path

        if ghidra_home := os.environ.get("GHIDRA_HOME"):
            home_path = Path(ghidra_home)
            candidate = home_path / "ghidraRun.bat"
            if candidate.exists():
                self._exe_path = candidate
                self._ghidra_home = home_path
                return candidate
            candidate = home_path / "ghidraRun"
            if candidate.exists():
                self._exe_path = candidate
                self._ghidra_home = home_path
                return candidate

        for hkey, subkey in self._REGISTRY_PATHS:
            try:
                with winreg.OpenKey(hkey, subkey) as key:
                    install_path_str, _ = winreg.QueryValueEx(key, "InstallPath")
                    if install_path_str:
                        base = Path(str(install_path_str))
                        candidate = base / "ghidraRun.bat"
                        if candidate.exists():
                            self._exe_path = candidate
                            self._ghidra_home = base
                            return candidate
            except OSError:
                _logger.debug("registry_key_not_found", extra={"subkey": subkey})
                continue

        for base in self._COMMON_PATHS:
            if not base.exists():
                continue
            for entry in base.iterdir():
                if entry.is_dir() and entry.name.lower().startswith("ghidra"):
                    candidate = entry / "ghidraRun.bat"
                    if candidate.exists():
                        self._exe_path = candidate
                        self._ghidra_home = entry
                        return candidate
            candidate = base / "ghidraRun.bat"
            if candidate.exists():
                self._exe_path = candidate
                self._ghidra_home = base
                return candidate

        project_root = Path(__file__).parent.parent.parent.parent.parent
        local_tools = project_root / "tools" / "ghidra"
        if local_tools.exists():
            for entry in local_tools.iterdir():
                if entry.is_dir():
                    candidate = entry / "ghidraRun.bat"
                    if candidate.exists():
                        self._exe_path = candidate
                        self._ghidra_home = entry
                        return candidate
            candidate = local_tools / "ghidraRun.bat"
            if candidate.exists():
                self._exe_path = candidate
                self._ghidra_home = local_tools
                return candidate

        if found := Win32WindowHelper.find_executable_path("ghidraRun.bat"):
            self._exe_path = found
            self._ghidra_home = found.parent
            return found

        _logger.warning("executable_not_found", extra={"tool": "ghidra"})
        return None

    def get_window_search_params(self) -> dict[str, str | None]:
        """Get window search parameters for Ghidra.

        Returns:
            Dictionary with class name and title pattern for Ghidra window.
        """
        return {
            "class_name": self._GHIDRA_WINDOW_CLASS,
            "title_contains": self._GHIDRA_TITLE_PATTERN,
        }

    def prepare_launch_args(self, binary_path: Path | None = None) -> list[str]:
        """Prepare Ghidra launch arguments.

        Args:
            binary_path: Optional binary to analyze on launch.

        Returns:
            Command-line arguments list.
        """
        del binary_path
        exe_path = self.get_executable_path()
        return [str(exe_path)] if exe_path else []

    def start_tool(self, binary_path: Path | None = None) -> bool:
        """Launch Ghidra with extended startup delay for Java initialization.

        Args:
            binary_path: Optional path to binary to open in the tool.

        Returns:
            True if the tool was started successfully.
        """
        exe_path = self.get_executable_path()
        if not exe_path:
            return False

        self._status_label.setText("Starting Ghidra (Java startup may take a moment)...")
        return super().start_tool(binary_path)

    def _run_bridge_coroutine(self, coro: Coroutine[Any, Any, _T]) -> _T | None:
        """Run an async bridge coroutine synchronously.

        Args:
            coro: Coroutine to execute.

        Returns:
            Coroutine result, or None if scheduling asynchronously.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                task = asyncio.ensure_future(coro)
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)
                return None
            return loop.run_until_complete(coro)
        except RuntimeError:
            _logger.debug("bridge_async_fallback_to_asyncio_run", extra={})
            return asyncio.run(coro)

    def attach_to_bridge(self, bridge: GhidraBridge) -> None:
        """Attach a GhidraBridge instance for programmatic control.

        Args:
            bridge: The GhidraBridge instance to use.
        """
        self._bridge = bridge
        _logger.info("bridge_attached", extra={"tool": "ghidra"})

    def get_bridge(self) -> GhidraBridge | None:
        """Get the attached GhidraBridge instance.

        Returns:
            The attached bridge or None.
        """
        return self._bridge

    def load_binary(self, binary_path: Path) -> bool:
        """Load a binary into Ghidra via the bridge.

        Args:
            binary_path: Path to the binary to analyze.

        Returns:
            True if the binary was loaded successfully.
        """
        if self._bridge is None:
            _logger.warning("no_bridge_for_load", extra={"tool": "ghidra"})
            return False

        if not binary_path.exists():
            _logger.warning("binary_not_found", extra={"tool": "ghidra", "path": str(binary_path)})
            return False

        _logger.debug("loading_binary", extra={"tool": "ghidra", "path": str(binary_path)})
        try:
            self._run_bridge_coroutine(self._bridge.load_binary(binary_path))
            self._loaded_file = binary_path
            _logger.info("binary_loaded", extra={"tool": "ghidra", "path": str(binary_path)})
        except Exception as e:
            _logger.warning("binary_load_failed", extra={"tool": "ghidra", "error": str(e)})
            return False
        else:
            return True

    def set_executable_path(self, path: Path) -> None:
        """Manually set the Ghidra executable path.

        Args:
            path: Path to ghidraRun.bat or ghidraRun executable.
        """
        if path.exists():
            self._exe_path = path
            self._ghidra_home = path.parent
            _logger.info("executable_path_set", extra={"tool": "ghidra", "path": str(path)})
        else:
            _logger.warning("executable_path_not_found", extra={"tool": "ghidra", "path": str(path)})
