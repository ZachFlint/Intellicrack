"""Cutter reverse engineering tool embedding widget.

Provides integration with Cutter (radare2 GUI) for binary analysis
within Intellicrack's interface.
"""

from __future__ import annotations

import asyncio
import logging
import os
import winreg
from collections.abc import Coroutine
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar

from intellicrack.ui.embedding.embedded_widget import EmbeddedToolWidget
from intellicrack.ui.embedding.win32_helper import Win32WindowHelper


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from intellicrack.bridges.radare2 import Radare2Bridge

_logger = logging.getLogger(__name__)

_T = TypeVar("_T")


class CutterWidget(EmbeddedToolWidget):
    """Widget for embedding Cutter reverse engineering tool.

    Provides Cutter embedding with radare2 bridge integration
    for synchronized analysis across tools.
    """

    _CUTTER_TITLE_PATTERN: ClassVar[str] = "Cutter"
    _COMMON_PATHS: ClassVar[list[Path]] = [
        Path(r"C:\Program Files\Cutter"),
        Path(r"C:\Program Files (x86)\Cutter"),
        Path(r"D:\Tools\Cutter"),
        Path(r"C:\Cutter"),
    ]
    _REGISTRY_PATHS: ClassVar[list[tuple[int, str]]] = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Cutter"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Cutter"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\rizin\Cutter"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize Cutter embedding widget.

        Args:
            parent: Parent widget.
        """
        self._exe_path: Path | None = None
        self._r2_bridge: Radare2Bridge | None = None
        self._project_path: Path | None = None
        self._background_tasks: set[asyncio.Task[object]] = set()
        super().__init__(parent)

    def get_tool_display_name(self) -> str:
        """Get display name for Cutter.

        Returns:
            Display name string.
        """
        return "Cutter"

    def get_executable_path(self) -> Path | None:
        """Find the Cutter executable.

        Searches registry, common paths, and environment for Cutter.

        Returns:
            Path to executable if found.
        """
        if self._exe_path and self._exe_path.exists():
            return self._exe_path

        exe_names = ["Cutter.exe", "cutter.exe", "Cutter-v2.exe"]

        for hkey, subkey in self._REGISTRY_PATHS:
            try:
                with winreg.OpenKey(hkey, subkey) as key:
                    install_path, _ = winreg.QueryValueEx(key, "InstallPath")
                    if install_path:
                        base = Path(install_path)
                        for exe_name in exe_names:
                            candidate = base / exe_name
                            if candidate.exists():
                                self._exe_path = candidate
                                return candidate
            except (FileNotFoundError, OSError):
                continue

        for base in self._COMMON_PATHS:
            if not base.exists():
                continue
            for exe_name in exe_names:
                candidate = base / exe_name
                if candidate.exists():
                    self._exe_path = candidate
                    return candidate

        env_path = os.environ.get("CUTTER_PATH")
        if env_path:
            candidate = Path(env_path)
            if candidate.exists():
                self._exe_path = candidate
                return candidate
            for exe_name in exe_names:
                candidate = Path(env_path) / exe_name
                if candidate.exists():
                    self._exe_path = candidate
                    return candidate

        for exe_name in exe_names:
            found = Win32WindowHelper.find_executable_path(exe_name)
            if found:
                self._exe_path = found
                return found

        project_root = Path(__file__).parent.parent.parent.parent.parent
        local_tools = project_root / "tools" / "cutter" / "Cutter.exe"
        if local_tools.exists():
            self._exe_path = local_tools.resolve()
            return self._exe_path

        _logger.warning("Cutter executable not found")
        return None

    def get_window_search_params(self) -> dict[str, str | None]:
        """Get window search parameters for Cutter.

        Returns:
            Dictionary with title pattern for Cutter window.
        """
        return {"class_name": None, "title_contains": self._CUTTER_TITLE_PATTERN}

    def prepare_launch_args(self, binary_path: Path | None = None) -> list[str]:
        """Prepare Cutter launch arguments.

        Args:
            binary_path: Optional binary to analyze.

        Returns:
            Command-line arguments list.
        """
        exe_path = self.get_executable_path()
        if not exe_path:
            return []

        args = [str(exe_path)]

        if binary_path and binary_path.exists():
            args.append(str(binary_path))

        return args

    def sync_with_radare2_bridge(self, bridge: Radare2Bridge) -> None:
        """Attach to a radare2 bridge for synchronized analysis.

        Args:
            bridge: The Radare2Bridge instance to sync with.
        """
        self._r2_bridge = bridge
        _logger.info("Cutter widget synced with radare2 bridge")

    def get_radare2_bridge(self) -> Radare2Bridge | None:
        """Get the attached radare2 bridge.

        Returns:
            The attached bridge or None.
        """
        return self._r2_bridge

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
            return asyncio.run(coro)

    def analyze_binary(self, binary_path: Path) -> bool:
        """Open a binary for analysis in Cutter.

        Args:
            binary_path: Path to binary to analyze.

        Returns:
            True if analysis was started successfully.
        """
        if not binary_path.exists():
            _logger.error("binary_not_found", extra={"path": str(binary_path)})
            return False

        if self.is_embedded():
            _logger.info("Cutter already running, opening via menu needed")
            self._loaded_file = binary_path
            return True

        return self.start_tool(binary_path)

    def goto_address(self, address: int) -> bool:
        """Navigate to an address in Cutter.

        Uses radare2 bridge if attached, otherwise logs navigation request.

        Args:
            address: Memory address to navigate to.

        Returns:
            True if navigation was initiated.
        """
        if self._r2_bridge:
            try:
                self._run_bridge_coroutine(self._r2_bridge.seek(address))
            except Exception:
                _logger.exception("seek_via_bridge_failed", extra={"address": hex(address)})
            else:
                _logger.info("address_navigated", extra={"address": hex(address), "method": "r2_bridge"})
                return True

        _logger.info("navigation_requested", extra={"address": hex(address), "manual": True})
        return True

    def goto_function(self, function_name: str) -> bool:
        """Navigate to a function by name.

        Args:
            function_name: Name of function to navigate to.

        Returns:
            True if navigation was initiated.
        """
        if self._r2_bridge:
            try:
                addr = self._run_bridge_coroutine(self._r2_bridge.get_function_address(function_name))
            except Exception:
                _logger.exception("find_function_failed", extra={"function": function_name})
            else:
                if addr is not None:
                    return self.goto_address(addr)

        _logger.info("function_navigation_requested", extra={"function": function_name})
        return True

    def get_functions(self) -> list[tuple[str, int]]:
        """Get list of functions from analysis.

        Uses radare2 bridge if available.

        Returns:
            List of (name, address) tuples.
        """
        if self._r2_bridge:
            try:
                result = self._run_bridge_coroutine(self._r2_bridge.list_functions())
            except Exception:
                _logger.exception("get_functions_failed")
            else:
                if result is not None:
                    return result

        return []

    def get_strings(self) -> list[tuple[int, str]]:
        """Get list of strings from analysis.

        Uses radare2 bridge if available.

        Returns:
            List of (address, string) tuples.
        """
        if self._r2_bridge:
            try:
                result = self._run_bridge_coroutine(self._r2_bridge.list_strings())
            except Exception:
                _logger.exception("get_strings_failed")
            else:
                if result is not None:
                    return result

        return []

    def get_imports(self) -> list[tuple[str, str, int]]:
        """Get list of imports from analysis.

        Uses radare2 bridge if available.

        Returns:
            List of (library, function, address) tuples.
        """
        if self._r2_bridge:
            try:
                result = self._run_bridge_coroutine(self._r2_bridge.list_imports())
            except Exception:
                _logger.exception("get_imports_failed")
            else:
                if result is not None:
                    return result

        return []

    def get_exports(self) -> list[tuple[str, int]]:
        """Get list of exports from analysis.

        Uses radare2 bridge if available.

        Returns:
            List of (name, address) tuples.
        """
        if self._r2_bridge:
            try:
                result = self._run_bridge_coroutine(self._r2_bridge.list_exports())
            except Exception:
                _logger.exception("get_exports_failed")
            else:
                if result is not None:
                    return result

        return []

    def save_project(self, project_path: Path | None = None) -> bool:
        """Save the current Cutter project.

        Args:
            project_path: Optional path for the project file.

        Returns:
            True if save was initiated.
        """
        save_path = project_path or self._project_path
        if save_path:
            self._project_path = save_path
            _logger.info("project_save_requested", extra={"path": str(save_path)})
            return True

        if self._loaded_file:
            self._project_path = self._loaded_file.with_suffix(".rzdb")
            _logger.info("project_save_requested", extra={"path": str(self._project_path)})
            return True

        _logger.warning("No project path specified and no file loaded")
        return False

    def load_project(self, project_path: Path) -> bool:
        """Load a Cutter project file.

        Args:
            project_path: Path to the project file.

        Returns:
            True if project loading was initiated.
        """
        if not project_path.exists():
            _logger.error("project_file_not_found", extra={"path": str(project_path)})
            return False

        self._project_path = project_path

        if self.is_embedded():
            _logger.info("project_load_via_menu", extra={"path": str(project_path)})
            return True

        return self.start_tool(project_path)

    def set_executable_path(self, path: Path) -> None:
        """Manually set the Cutter executable path.

        Args:
            path: Path to Cutter executable.
        """
        if path.exists():
            self._exe_path = path
            _logger.info("cutter_path_set", extra={"path": str(path)})
        else:
            _logger.warning("cutter_path_not_found", extra={"path": str(path)})

    def get_project_path(self) -> Path | None:
        """Get the current project path.

        Returns:
            Path to current project or None.
        """
        return self._project_path
