"""HxD hex editor embedding widget.

Provides integration with HxD hex editor for viewing and editing
binary files within Intellicrack's interface.
"""

from __future__ import annotations

import ctypes
import winreg
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, override

from intellicrack.core._subprocess import Popen, TimeoutExpired
from intellicrack.core.logging import get_logger
from intellicrack.ui.embedding.embedded_widget import EmbeddedToolWidget
from intellicrack.ui.embedding.win32_helper import Win32WindowHelper


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

_logger = get_logger("ui.embedding.hxd")

_WM_COMMAND = 0x0111
_WM_KEYDOWN = 0x0100
_WM_CHAR = 0x0102
_VK_CONTROL = 0x11
_VK_G = 0x47


class HxDWidget(EmbeddedToolWidget):
    """Widget for embedding HxD hex editor.

    Provides file loading, offset navigation, and selection capabilities
    by interfacing with HxD through Win32 window messaging.
    """

    _HXD_CLASS_NAME: ClassVar[str] = "THxDFrame"
    _HXD_REGISTRY_PATHS: ClassVar[list[tuple[int, str]]] = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\HxD"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\HxD"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\HxD"),
    ]
    _HXD_COMMON_PATHS: ClassVar[list[Path]] = [
        Path(r"C:\Program Files\HxD\HxD.exe"),
        Path(r"C:\Program Files (x86)\HxD\HxD.exe"),
        Path(r"D:\Tools\HxD\HxD.exe"),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the HxD embedding widget.

        Args:
            parent: Parent widget.
        """
        self._exe_path: Path | None = None
        self._current_offset: int = 0
        super().__init__(parent)

    @override
    def get_tool_display_name(self) -> str:
        """Get the display name for HxD.

        Returns:
            Display name string.
        """
        return "HxD Hex Editor"

    def get_executable_path(self) -> Path | None:
        """Find and return the HxD executable path.

        Searches registry locations and common installation paths
        to locate the HxD executable.

        Returns:
            Path to HxD executable if found, None otherwise.
        """
        if self._exe_path and self._exe_path.exists():
            return self._exe_path

        for hkey, subkey in self._HXD_REGISTRY_PATHS:
            try:
                with winreg.OpenKey(hkey, subkey) as key:
                    install_path, _ = winreg.QueryValueEx(key, "InstallPath")
                    if install_path:
                        candidate = Path(install_path) / "HxD.exe"
                        if candidate.exists():
                            self._exe_path = candidate
                            _logger.info("hxd_found_via_registry", extra={"path": str(candidate)})
                            return candidate
            except OSError:
                _logger.debug("registry_key_not_found", extra={"subkey": subkey})
                continue

        for path in self._HXD_COMMON_PATHS:
            if path.exists():
                self._exe_path = path
                _logger.info("hxd_found_at_common_path", extra={"path": str(path)})
                return path

        if found := Win32WindowHelper.find_executable_path("HxD.exe"):
            self._exe_path = found
            _logger.info("hxd_found_via_path_search", extra={"path": str(found)})
            return found

        project_root = Path(__file__).parent.parent.parent.parent.parent
        local_tools = project_root / "tools" / "hxd" / "HxD.exe"
        if local_tools.exists():
            self._exe_path = local_tools.resolve()
            return self._exe_path

        _logger.warning("hxd_executable_not_found", extra={})
        return None

    def get_window_search_params(self) -> dict[str, str | None]:
        """Get HxD window search parameters.

        Returns:
            Dictionary with class_name for THxDFrame window.
        """
        return {"class_name": self._HXD_CLASS_NAME, "title_contains": None}

    def prepare_launch_args(self, binary_path: Path | None = None) -> list[str]:
        """Prepare HxD launch arguments.

        Args:
            binary_path: Optional file to open on launch.

        Returns:
            List of command-line arguments.
        """
        exe_path = self.get_executable_path()
        if not exe_path:
            return []

        args = [str(exe_path)]
        if binary_path and binary_path.exists():
            args.append(str(binary_path))
        return args

    def load_file(self, file_path: Path) -> bool:
        """Load a file in HxD.

        If HxD is not running, starts it with the file. If already
        running, sends commands to open the file.

        Args:
            file_path: Path to the file to load.

        Returns:
            True if file load was initiated successfully.
        """
        if not file_path.exists():
            _logger.error("file_does_not_exist", extra={"path": str(file_path)})
            return False

        if not self.is_embedded():
            _logger.debug("launching_hxd_for_file", extra={"path": str(file_path)})
            return self.start_tool(file_path)

        _logger.debug("sending_open_file_command", extra={"path": str(file_path)})
        self._send_open_file_command(file_path)
        self._loaded_file = file_path
        return True

    def _send_open_file_command(self, file_path: Path) -> None:
        """Send command to HxD to open a file via DDE or command.

        Args:
            file_path: Path to file to open.
        """
        if not self._embedded_hwnd:
            return

        main_children = Win32WindowHelper.enumerate_child_windows(
            self._embedded_hwnd,
            lambda _h, c, _t: "Edit" in c or "Memo" in c,
        )

        file_str = str(file_path)
        for hwnd, _class, _title in main_children:
            for char in file_str:
                ctypes.windll.user32.PostMessageW(hwnd, _WM_CHAR, ord(char), 0)

        _logger.info("hxd_open_file_command_sent", extra={"path": str(file_path)})

    def goto_offset(self, offset: int) -> bool:
        """Navigate to a specific offset in HxD.

        Sends Ctrl+G to open goto dialog and enters the offset.

        Args:
            offset: Byte offset to navigate to.

        Returns:
            True if navigation was initiated.
        """
        if not self._embedded_hwnd or not Win32WindowHelper.is_window_valid(self._embedded_hwnd):
            _logger.warning("hxd_goto_offset_failed", extra={"reason": "not_embedded"})
            return False

        self._current_offset = offset

        ctypes.windll.user32.PostMessageW(
            self._embedded_hwnd,
            _WM_KEYDOWN,
            _VK_G,
            0x00200001 | (0x22 << 16),
        )

        _logger.info("hxd_goto_offset_command_sent", extra={"offset": hex(offset)})
        return True

    def select_range(self, start: int, length: int) -> bool:
        """Select a range of bytes in HxD.

        Args:
            start: Starting offset.
            length: Number of bytes to select.

        Returns:
            True if selection command was sent.
        """
        if not self._embedded_hwnd or not Win32WindowHelper.is_window_valid(self._embedded_hwnd):
            return False

        if not self.goto_offset(start):
            return False

        _logger.info("hxd_selection_range_initiated", extra={"start": hex(start), "length": length})
        return True

    def get_current_offset(self) -> int:
        """Get the last navigated offset.

        Returns:
            Last offset navigated to, or 0 if none.
        """
        return self._current_offset

    def set_executable_path(self, path: Path) -> None:
        """Manually set the HxD executable path.

        Args:
            path: Path to HxD executable.
        """
        if path.exists():
            self._exe_path = path
            _logger.info("hxd_path_manually_set", extra={"path": str(path)})
        else:
            _logger.warning("hxd_specified_path_not_found", extra={"path": str(path)})


class HxDIntegration:
    """Standalone HxD integration for non-embedded usage.

    Provides methods to launch HxD and open files without
    embedding the window into a Qt widget. Standalone processes
    are tracked for monitoring but NOT auto-killed on app exit.
    """

    def __init__(self) -> None:
        """Initialize HxD integration."""
        self._exe_path: Path | None = None
        self._standalone_processes: list[Popen[bytes]] = []

    def find_hxd(self) -> Path | None:
        """Find HxD installation.

        Returns:
            Path to HxD executable or None.
        """
        widget = HxDWidget()
        self._exe_path = widget.get_executable_path()
        return self._exe_path

    def open_file(self, file_path: Path) -> bool:
        """Open a file in HxD as standalone process.

        Args:
            file_path: Path to file to open.

        Returns:
            True if HxD was launched successfully.
        """
        exe = self._exe_path or self.find_hxd()
        if not exe:
            _logger.error("hxd_not_found", extra={})
            return False

        if not file_path.exists():
            _logger.error("file_not_found", extra={"path": str(file_path)})
            return False

        try:
            proc = Popen([str(exe), str(file_path)])
        except OSError:
            _logger.exception("hxd_launch_failed", extra={"path": str(file_path)})
            return False
        else:
            self._standalone_processes.append(proc)
            _logger.info(
                "hxd_standalone_launched",
                extra={"pid": proc.pid, "path": str(file_path)},
            )
            return True

    def open_at_offset(self, file_path: Path, offset: int) -> bool:
        """Open a file in HxD and navigate to offset.

        HxD doesn't support offset via command line, so this opens
        the file normally. Manual navigation required.

        Args:
            file_path: Path to file.
            offset: Byte offset (for reference only).

        Returns:
            True if file was opened.
        """
        _logger.info(
            "hxd_opening_file_with_offset",
            extra={"path": str(file_path), "offset": hex(offset), "note": "manual_navigation_required"},
        )
        return self.open_file(file_path)

    def get_standalone_pids(self) -> list[int]:
        """Get PIDs of all tracked standalone HxD processes.

        Returns:
            List of PIDs for running standalone processes.
        """
        return [p.pid for p in self._standalone_processes if p.poll() is None]

    def cleanup_standalone(self) -> None:
        """Terminate all tracked standalone HxD processes.

        This is intended for manual invocation when the caller
        explicitly wants to close standalone HxD instances.
        """
        for proc in self._standalone_processes:
            if proc.poll() is None:
                _logger.info("hxd_standalone_terminating", extra={"pid": proc.pid})
                try:
                    proc.terminate()
                    proc.wait(timeout=5.0)
                except TimeoutExpired:
                    proc.kill()
                except OSError:
                    _logger.debug("hxd_standalone_cleanup_error", extra={"pid": proc.pid})
        self._standalone_processes.clear()
