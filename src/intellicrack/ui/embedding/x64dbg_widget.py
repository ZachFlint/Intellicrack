"""x64dbg debugger embedding widget.

Provides integration with x64dbg/x32dbg debugger for debugging
binaries within Intellicrack's interface.
"""

from __future__ import annotations

import asyncio
import logging
import os
import winreg
from collections.abc import Coroutine
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from intellicrack.ui.embedding.embedded_widget import EmbeddedToolWidget
from intellicrack.ui.embedding.win32_helper import Win32WindowHelper


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from intellicrack.bridges.x64dbg import X64DbgBridge

_logger = logging.getLogger(__name__)


class X64DbgWidget(EmbeddedToolWidget):
    """Widget for embedding x64dbg/x32dbg debugger.

    Provides debugger embedding with bitness selection and bridge
    integration for programmatic control.
    """

    _X64DBG_CLASS: ClassVar[str] = "x64dbg"
    _X32DBG_CLASS: ClassVar[str] = "x32dbg"
    _COMMON_PATHS: ClassVar[list[Path]] = [
        Path(r"C:\Program Files\x64dbg"),
        Path(r"C:\Program Files (x86)\x64dbg"),
        Path(r"D:\Tools\x64dbg"),
        Path(r"C:\x64dbg"),
    ]
    _REGISTRY_PATHS: ClassVar[list[tuple[int, str]]] = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\x64dbg"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\x64dbg"),
    ]

    def __init__(self, parent: QWidget | None = None, use_64bit: bool = True) -> None:
        """Initialize x64dbg embedding widget.

        Args:
            parent: Parent widget.
            use_64bit: If True, use x64dbg; if False, use x32dbg.
        """
        self._use_64bit = use_64bit
        self._install_dir: Path | None = None
        self._bridge: X64DbgBridge | None = None
        self._attached_pid: int | None = None
        super().__init__(parent)

    def get_tool_display_name(self) -> str:
        """Get display name based on bitness.

        Returns:
            'x64dbg' or 'x32dbg' based on configuration.
        """
        return "x64dbg" if self._use_64bit else "x32dbg"

    def get_executable_path(self) -> Path | None:
        """Find the x64dbg/x32dbg executable.

        Returns:
            Path to executable if found.
        """
        exe_name = "x64dbg.exe" if self._use_64bit else "x32dbg.exe"
        release_dir = "release"
        arch_dir = "x64" if self._use_64bit else "x32"

        if self._install_dir:
            candidates = [
                self._install_dir / release_dir / arch_dir / exe_name,
                self._install_dir / arch_dir / exe_name,
                self._install_dir / exe_name,
            ]
            for candidate in candidates:
                if candidate.exists():
                    return candidate

        for hkey, subkey in self._REGISTRY_PATHS:
            try:
                with winreg.OpenKey(hkey, subkey) as key:
                    install_path, _ = winreg.QueryValueEx(key, "InstallPath")
                    if install_path:
                        base = Path(install_path)
                        candidates = [
                            base / release_dir / arch_dir / exe_name,
                            base / arch_dir / exe_name,
                            base / exe_name,
                        ]
                        for candidate in candidates:
                            if candidate.exists():
                                self._install_dir = base
                                return candidate
            except (FileNotFoundError, OSError):
                continue

        for base in self._COMMON_PATHS:
            if not base.exists():
                continue
            candidates = [
                base / release_dir / arch_dir / exe_name,
                base / arch_dir / exe_name,
                base / exe_name,
            ]
            for candidate in candidates:
                if candidate.exists():
                    self._install_dir = base
                    return candidate

        env_path = os.environ.get("X64DBG_PATH")
        if env_path:
            base = Path(env_path)
            candidates = [
                base / release_dir / arch_dir / exe_name,
                base / arch_dir / exe_name,
                base / exe_name,
            ]
            for candidate in candidates:
                if candidate.exists():
                    self._install_dir = base
                    return candidate

        found = Win32WindowHelper.find_executable_path(exe_name)
        if found:
            self._install_dir = found.parent.parent
            return found

        project_root = Path(__file__).parent.parent.parent.parent.parent
        local_tools = project_root / "tools" / "x64dbg" / "release" / arch_dir / exe_name
        if local_tools.exists():
            self._install_dir = local_tools.parent.parent.parent.resolve()
            return local_tools.resolve()

        _logger.warning("executable_not_found", extra={"exe_name": exe_name})
        return None

    def get_window_search_params(self) -> dict[str, str | None]:
        """Get window search parameters for x64dbg.

        Returns:
            Dictionary with class name based on bitness.
        """
        class_name = self._X64DBG_CLASS if self._use_64bit else self._X32DBG_CLASS
        return {"class_name": class_name, "title_contains": None}

    def prepare_launch_args(self, binary_path: Path | None = None) -> list[str]:
        """Prepare x64dbg launch arguments.

        Args:
            binary_path: Optional binary to debug.

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

    def set_64bit(self, use_64bit: bool) -> None:
        """Set whether to use 64-bit or 32-bit debugger.

        If the tool is running, it must be stopped first.

        Args:
            use_64bit: True for x64dbg, False for x32dbg.
        """
        if self.is_embedded() or self.is_tool_running():
            _logger.warning("bitness_change_blocked", extra={"reason": "debugger_running"})
            return

        self._use_64bit = use_64bit
        _logger.info("bitness_set", extra={"bitness": 64 if use_64bit else 32})

    def is_64bit(self) -> bool:
        """Check if using 64-bit debugger.

        Returns:
            True if using x64dbg, False if using x32dbg.
        """
        return self._use_64bit

    def attach_to_bridge(self, bridge: X64DbgBridge) -> None:
        """Attach to an X64DbgBridge instance for programmatic control.

        Args:
            bridge: The X64DbgBridge instance to use.
        """
        self._bridge = bridge
        _logger.info("bridge_attached", extra={"tool": "x64dbg"})

    def get_bridge(self) -> X64DbgBridge | None:
        """Get the attached bridge instance.

        Returns:
            The attached X64DbgBridge or None.
        """
        return self._bridge

    def _run_bridge_async(self, coro: Coroutine[Any, Any, Any]) -> None:
        """Run an async bridge coroutine in the background.

        Args:
            coro: Coroutine to execute.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                task = asyncio.ensure_future(coro)
                del task
            else:
                loop.run_until_complete(coro)
        except RuntimeError:
            asyncio.run(coro)

    def debug_file(self, binary_path: Path) -> bool:
        """Start debugging a binary file.

        Args:
            binary_path: Path to the binary to debug.

        Returns:
            True if debugging was started successfully.
        """
        if not binary_path.exists():
            _logger.error("binary_not_found", extra={"path": str(binary_path)})
            return False

        if self.is_embedded():
            return self._send_debug_command(binary_path)

        return self.start_tool(binary_path)

    def _send_debug_command(self, binary_path: Path) -> bool:
        """Send debug command to running x64dbg.

        Args:
            binary_path: Path to binary to debug.

        Returns:
            True if command was sent.
        """
        if self._bridge:
            try:
                self._run_bridge_async(self._bridge.load(binary_path))
                self._loaded_file = binary_path
            except Exception:
                _logger.exception("bridge_debug_command_failed")
            else:
                return True

        _logger.info("file_open_via_menu", extra={"path": str(binary_path)})
        self._loaded_file = binary_path
        return True

    def attach_to_process(self, pid: int) -> bool:
        """Attach debugger to a running process.

        Args:
            pid: Process ID to attach to.

        Returns:
            True if attach command was sent.
        """
        if self._bridge:
            try:
                self._run_bridge_async(self._bridge.attach(pid))
                self._attached_pid = pid
            except Exception:
                _logger.exception("bridge_attach_failed")
            else:
                return True
            return False

        _logger.warning("no_bridge_attached", extra={"operation": "attach_to_pid", "pid": pid})
        return False

    def set_breakpoint(self, address: int) -> bool:
        """Set a breakpoint at the specified address.

        Args:
            address: Memory address for breakpoint.

        Returns:
            True if breakpoint command was sent.
        """
        if self._bridge:
            try:
                self._run_bridge_async(self._bridge.set_breakpoint(address))
                _logger.info("breakpoint_set", extra={"address": hex(address)})
            except Exception:
                _logger.exception("breakpoint_set_failed")
                return False
            else:
                return True

        _logger.warning("no_bridge_attached", extra={"operation": "set_breakpoint"})
        return False

    def remove_breakpoint(self, address: int) -> bool:
        """Remove a breakpoint at the specified address.

        Args:
            address: Memory address of breakpoint to remove.

        Returns:
            True if breakpoint removal was sent.
        """
        if self._bridge:
            try:
                self._run_bridge_async(self._bridge.remove_breakpoint(address))
                _logger.info("breakpoint_removed", extra={"address": hex(address)})
            except Exception:
                _logger.exception("breakpoint_remove_failed")
                return False
            else:
                return True

        _logger.warning("no_bridge_attached", extra={"operation": "remove_breakpoint"})
        return False

    def step_into(self) -> bool:
        """Execute single step into instruction.

        Returns:
            True if step command was sent.
        """
        if self._bridge:
            try:
                self._run_bridge_async(self._bridge.step_into())
            except Exception:
                _logger.exception("step_into_failed")
                return False
            else:
                return True
        return False

    def step_over(self) -> bool:
        """Execute single step over instruction.

        Returns:
            True if step command was sent.
        """
        if self._bridge:
            try:
                self._run_bridge_async(self._bridge.step_over())
            except Exception:
                _logger.exception("step_over_failed")
                return False
            else:
                return True
        return False

    def run(self) -> bool:
        """Continue execution.

        Returns:
            True if run command was sent.
        """
        if self._bridge:
            try:
                self._run_bridge_async(self._bridge.run())
            except Exception:
                _logger.exception("run_failed")
                return False
            else:
                return True
        return False

    def pause(self) -> bool:
        """Pause execution.

        Returns:
            True if pause command was sent.
        """
        if self._bridge:
            try:
                self._run_bridge_async(self._bridge.pause())
            except Exception:
                _logger.exception("pause_failed")
                return False
            else:
                return True
        return False

    def goto_address(self, address: int) -> bool:
        """Navigate disassembly view to address.

        Args:
            address: Memory address to navigate to.

        Returns:
            True if navigation command was sent.
        """
        if self._bridge:
            try:
                self._run_bridge_async(self._bridge.run_command(f"goto {hex(address)}"))
            except Exception:
                _logger.exception("goto_address_failed")
                return False
            else:
                return True

        _logger.warning("no_bridge_attached", extra={"operation": "goto_address", "address": hex(address)})
        return False

    def get_attached_pid(self) -> int | None:
        """Get the PID of the attached/debugged process.

        Returns:
            Process ID or None if not debugging.
        """
        return self._attached_pid

    def set_install_directory(self, path: Path) -> None:
        """Manually set the x64dbg installation directory.

        Args:
            path: Path to x64dbg installation directory.
        """
        if path.exists() and path.is_dir():
            self._install_dir = path
            _logger.info("install_directory_set", extra={"path": str(path)})
        else:
            _logger.warning("invalid_install_directory", extra={"path": str(path)})
