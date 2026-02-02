"""radare2/iaito GUI embedding widget.

Provides integration with iaito (radare2 GUI) for binary analysis
within Intellicrack's interface via Win32 window embedding.
Falls back to Cutter if iaito is unavailable.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Coroutine
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, TypeVar

from intellicrack.core.logging import get_logger
from intellicrack.ui.embedding.embedded_widget import EmbeddedToolWidget
from intellicrack.ui.embedding.win32_helper import Win32WindowHelper


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from intellicrack.bridges.radare2 import Radare2Bridge

_logger = get_logger("ui.embedding.radare2")

_T = TypeVar("_T")


class Radare2Widget(EmbeddedToolWidget):
    """Widget for embedding iaito (radare2 GUI) or Cutter.

    Searches for iaito first, falls back to Cutter if unavailable.
    Provides radare2 bridge integration for synchronized analysis.
    """

    _IAITO_TITLE_PATTERN: ClassVar[str] = "iaito"
    _CUTTER_TITLE_PATTERN: ClassVar[str] = "Cutter"
    _COMMON_PATHS: ClassVar[list[Path]] = [
        Path(r"C:\Program Files\iaito"),
        Path(r"C:\Program Files (x86)\iaito"),
        Path(r"D:\Tools\iaito"),
        Path(r"C:\iaito"),
        Path(r"C:\Program Files\Cutter"),
        Path(r"C:\Program Files (x86)\Cutter"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize radare2/iaito embedding widget.

        Args:
            parent: Parent widget.
        """
        self._exe_path: Path | None = None
        self._bridge: Radare2Bridge | None = None
        self._using_iaito: bool = True
        self._background_tasks: set[asyncio.Task[object]] = set()
        super().__init__(parent)

    def get_tool_display_name(self) -> str:
        """Get display name for the radare2 GUI frontend.

        Returns:
            Display name string based on which frontend was found.
        """
        return "iaito" if self._using_iaito else "Cutter (r2)"

    def get_executable_path(self) -> Path | None:
        """Find iaito or Cutter executable.

        Searches for iaito first, then falls back to Cutter.
        Checks environment variables, common paths, project tools
        directory, and PATH.

        Returns:
            Path to executable if found.
        """
        if self._exe_path and self._exe_path.exists():
            return self._exe_path

        if iaito_path := os.environ.get("IAITO_PATH"):
            candidate = Path(iaito_path)
            if candidate.exists() and candidate.is_file():
                self._exe_path = candidate
                self._using_iaito = True
                return candidate
            for name in ("iaito.exe", "iaito"):
                candidate = Path(iaito_path) / name
                if candidate.exists():
                    self._exe_path = candidate
                    self._using_iaito = True
                    return candidate

        for base in self._COMMON_PATHS:
            if not base.exists():
                continue
            for exe_name in ("iaito.exe", "iaito"):
                candidate = base / exe_name
                if candidate.exists():
                    self._exe_path = candidate
                    self._using_iaito = True
                    return candidate

        project_root = Path(__file__).parent.parent.parent.parent.parent

        iaito_tools = project_root / "tools" / "iaito"
        if iaito_tools.exists():
            for exe_name in ("iaito.exe", "iaito"):
                candidate = iaito_tools / exe_name
                if candidate.exists():
                    self._exe_path = candidate.resolve()
                    self._using_iaito = True
                    return self._exe_path

        cutter_tools = project_root / "tools" / "cutter"
        if cutter_tools.exists():
            for exe_name in ("Cutter.exe", "cutter.exe"):
                candidate = cutter_tools / exe_name
                if candidate.exists():
                    self._exe_path = candidate.resolve()
                    self._using_iaito = False
                    return self._exe_path

        for exe_name in ("iaito.exe", "iaito"):
            if found := Win32WindowHelper.find_executable_path(exe_name):
                self._exe_path = found
                self._using_iaito = True
                return found

        for exe_name in ("Cutter.exe", "cutter.exe"):
            if found := Win32WindowHelper.find_executable_path(exe_name):
                self._exe_path = found
                self._using_iaito = False
                return found

        _logger.warning("executable_not_found", extra={"tool": "iaito_cutter"})
        return None

    def get_window_search_params(self) -> dict[str, str | None]:
        """Get window search parameters for iaito/Cutter.

        Returns:
            Dictionary with title pattern based on which frontend is active.
        """
        title = self._IAITO_TITLE_PATTERN if self._using_iaito else self._CUTTER_TITLE_PATTERN
        return {"class_name": None, "title_contains": title}

    def prepare_launch_args(self, binary_path: Path | None = None) -> list[str]:
        """Prepare iaito/Cutter launch arguments.

        Args:
            binary_path: Optional binary to analyze on launch.

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

    def sync_with_bridge(self, bridge: Radare2Bridge) -> None:
        """Attach a Radare2Bridge instance for programmatic control.

        Args:
            bridge: The Radare2Bridge instance to use.
        """
        self._bridge = bridge
        _logger.info("bridge_synced", extra={"tool": "radare2"})

    def get_bridge(self) -> Radare2Bridge | None:
        """Get the attached Radare2Bridge instance.

        Returns:
            The attached bridge or None.
        """
        return self._bridge

    def analyze_binary(self, binary_path: Path) -> bool:
        """Load and analyze a binary via the radare2 bridge.

        Args:
            binary_path: Path to the binary to analyze.

        Returns:
            True if analysis was started successfully.
        """
        if not binary_path.exists():
            _logger.warning("radare2_binary_not_found", extra={"path": str(binary_path)})
            return False

        self._loaded_file = binary_path

        if self._bridge is not None:
            _logger.debug("analyzing_binary_via_bridge", extra={"path": str(binary_path)})
            try:
                self._run_bridge_coroutine(self._bridge.load_binary(binary_path))
                self._run_bridge_coroutine(self._bridge.analyze())
                _logger.info("binary_analyzed", extra={"tool": "radare2", "path": str(binary_path)})
            except Exception as e:
                _logger.warning("radare2_analysis_failed", extra={"error": str(e)})
                return False
            else:
                return True

        if not self.is_tool_running():
            success = self.start_tool(binary_path)
            if not success:
                return False

        _logger.info("radare2_binary_queued", extra={"path": str(binary_path)})
        return True

    def goto_address(self, address: int) -> None:
        """Navigate to a specific address in the radare2 GUI.

        Args:
            address: The virtual address to navigate to.
        """
        if self._bridge is not None:
            try:
                self._run_bridge_coroutine(self._bridge.seek(address))
            except Exception as e:
                _logger.warning("radare2_seek_failed", extra={"error": str(e)})

    def set_executable_path(self, path: Path) -> None:
        """Manually set the iaito/Cutter executable path.

        Args:
            path: Path to iaito or Cutter executable.
        """
        if path.exists():
            self._exe_path = path
            self._using_iaito = "iaito" in path.name.lower()
            _logger.info("radare2_gui_path_set", extra={"path": str(path)})
        else:
            _logger.warning("radare2_gui_path_not_found", extra={"path": str(path)})
