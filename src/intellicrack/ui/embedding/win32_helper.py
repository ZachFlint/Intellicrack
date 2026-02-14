"""Win32 API helper for window embedding operations.

Provides low-level Windows API wrappers for finding, reparenting,
and manipulating external application windows to embed them within
Qt container widgets.
"""

from __future__ import annotations

import ctypes
import shutil
import time
import winreg
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable

_logger = get_logger("ui.embedding.win32")

_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32

GWL_STYLE = -16
GWL_EXSTYLE = -20
WS_CHILD = 0x40000000
WS_POPUP = 0x80000000
WS_CAPTION = 0x00C00000
WS_THICKFRAME = 0x00040000
WS_BORDER = 0x00800000
WS_SYSMENU = 0x00080000
WS_MINIMIZEBOX = 0x00020000
WS_MAXIMIZEBOX = 0x00010000
WS_EX_APPWINDOW = 0x00040000
WS_EX_WINDOWEDGE = 0x00000100
WS_EX_CLIENTEDGE = 0x00000200
WS_EX_DLGMODALFRAME = 0x00000001
SWP_FRAMECHANGED = 0x0020
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
SWP_SHOWWINDOW = 0x0040
WM_CLOSE = 0x0010
WM_SETFOCUS = 0x0007
WM_KILLFOCUS = 0x0008
WM_SIZE = 0x0005
GW_OWNER = 4
_TH32CS_SNAPPROCESS = 0x00000002
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value or -1

_ENUM_CALLBACK_TYPE = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


class _PROCESSENTRY32W(ctypes.Structure):
    """Win32 PROCESSENTRY32W structure for process enumeration."""

    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def _configure_api_signatures() -> None:
    """Configure ctypes function signatures for type safety."""
    _user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    _user32.FindWindowW.restype = wintypes.HWND

    _user32.FindWindowExW.argtypes = [
        wintypes.HWND,
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
    ]
    _user32.FindWindowExW.restype = wintypes.HWND

    _user32.SetParent.argtypes = [wintypes.HWND, wintypes.HWND]
    _user32.SetParent.restype = wintypes.HWND

    _user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
    _user32.GetWindowLongW.restype = wintypes.LONG

    _user32.SetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.LONG]
    _user32.SetWindowLongW.restype = wintypes.LONG

    _user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
    _user32.GetWindowLongPtrW.restype = ctypes.c_void_p

    _user32.SetWindowLongPtrW.argtypes = [
        wintypes.HWND,
        ctypes.c_int,
        ctypes.c_void_p,
    ]
    _user32.SetWindowLongPtrW.restype = ctypes.c_void_p

    _user32.MoveWindow.argtypes = [
        wintypes.HWND,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.BOOL,
    ]
    _user32.MoveWindow.restype = wintypes.BOOL

    _user32.SetWindowPos.argtypes = [
        wintypes.HWND,
        wintypes.HWND,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.UINT,
    ]
    _user32.SetWindowPos.restype = wintypes.BOOL

    _user32.IsWindow.argtypes = [wintypes.HWND]
    _user32.IsWindow.restype = wintypes.BOOL

    _user32.IsWindowVisible.argtypes = [wintypes.HWND]
    _user32.IsWindowVisible.restype = wintypes.BOOL

    _user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    _user32.ShowWindow.restype = wintypes.BOOL

    _user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    _user32.SetForegroundWindow.restype = wintypes.BOOL

    _user32.PostMessageW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    _user32.PostMessageW.restype = wintypes.BOOL

    _user32.SendMessageW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    _user32.SendMessageW.restype = wintypes.LPARAM

    _user32.EnumWindows.argtypes = [_ENUM_CALLBACK_TYPE, wintypes.LPARAM]
    _user32.EnumWindows.restype = wintypes.BOOL

    _user32.EnumChildWindows.argtypes = [
        wintypes.HWND,
        _ENUM_CALLBACK_TYPE,
        wintypes.LPARAM,
    ]
    _user32.EnumChildWindows.restype = wintypes.BOOL

    _user32.GetWindowTextW.argtypes = [
        wintypes.HWND,
        wintypes.LPWSTR,
        ctypes.c_int,
    ]
    _user32.GetWindowTextW.restype = ctypes.c_int

    _user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    _user32.GetWindowTextLengthW.restype = ctypes.c_int

    _user32.GetClassNameW.argtypes = [
        wintypes.HWND,
        wintypes.LPWSTR,
        ctypes.c_int,
    ]
    _user32.GetClassNameW.restype = ctypes.c_int

    _user32.GetWindowThreadProcessId.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _user32.GetWindowThreadProcessId.restype = wintypes.DWORD

    _user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    _user32.GetWindow.restype = wintypes.HWND

    _user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    _user32.GetWindowRect.restype = wintypes.BOOL

    _user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    _user32.GetClientRect.restype = wintypes.BOOL

    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    _kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    _kernel32.Process32FirstW.restype = wintypes.BOOL

    _kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    _kernel32.Process32NextW.restype = wintypes.BOOL

    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL


_configure_api_signatures()


class Win32WindowHelper:
    """Win32 API wrapper for window embedding operations.

    Provides methods to find, reparent, style, and position windows
    for embedding external applications within Qt container widgets.
    """

    @staticmethod
    def find_window(
        class_name: str | None = None,
        window_title: str | None = None,
    ) -> int:
        """Find a top-level window by class name and/or title.

        Args:
            class_name: Window class name to search for.
            window_title: Window title to search for.

        Returns:
            Window handle (HWND) if found, 0 otherwise.
        """
        hwnd = _user32.FindWindowW(class_name, window_title)
        result = int(hwnd) if hwnd else 0
        _logger.debug(
            "find_window",
            extra={"class_name": class_name, "title": window_title, "hwnd": hex(result)},
        )
        return result

    @staticmethod
    def find_window_by_pid(
        pid: int,
        timeout: float = 10.0,
        class_name: str | None = None,
        title_contains: str | None = None,
        include_hidden: bool = False,
    ) -> int:
        """Find a window belonging to a specific process.

        Uses EnumWindows to scan all top-level windows, filtering by
        process ID, optional class name, and optional title substring.
        When timeout is 0 or negative, performs a single non-blocking
        enumeration pass suitable for use with external retry loops.

        Args:
            pid: Process ID to search for.
            timeout: Maximum time to wait for window appearance. Use 0
                for a single non-blocking enumeration pass.
            class_name: Optional window class name filter (exact match).
            title_contains: Optional title substring filter (case-insensitive).
            include_hidden: If True, include non-visible windows in search
                results. Useful when the target process was launched with
                SW_HIDE or has not yet shown its window.

        Returns:
            Window handle (HWND) if found, 0 otherwise.
        """
        found_hwnd: list[int] = []

        def enum_callback(hwnd: int, _lparam: int) -> bool:
            proc_id = wintypes.DWORD()
            _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(proc_id))

            if proc_id.value != pid:
                return True

            if not include_hidden and not _user32.IsWindowVisible(hwnd):
                return True

            owner = _user32.GetWindow(hwnd, GW_OWNER)
            if owner:
                return True

            if class_name:
                buf = ctypes.create_unicode_buffer(256)
                length = _user32.GetClassNameW(hwnd, buf, 256)
                if length <= 0 or buf.value != class_name:
                    return True

            if title_contains:
                title_buf = ctypes.create_unicode_buffer(512)
                title_len = _user32.GetWindowTextW(hwnd, title_buf, 512)
                if title_len <= 0 or title_contains.lower() not in title_buf.value.lower():
                    return True

            found_hwnd.append(hwnd)
            return False

        callback = _ENUM_CALLBACK_TYPE(enum_callback)
        deadline = time.monotonic() + timeout

        _logger.debug(
            "find_window_by_pid_started",
            extra={
                "pid": pid,
                "timeout": timeout,
                "class_name": class_name,
                "title_contains": title_contains,
                "include_hidden": include_hidden,
            },
        )
        while True:
            found_hwnd.clear()
            _user32.EnumWindows(callback, 0)
            if found_hwnd:
                _logger.debug("find_window_by_pid_found", extra={"pid": pid, "hwnd": hex(found_hwnd[0])})
                return found_hwnd[0]
            if time.monotonic() >= deadline:
                break
            time.sleep(0.1)

        _logger.debug("find_window_by_pid_timeout", extra={"pid": pid})
        return 0

    @staticmethod
    def get_descendant_pids(root_pid: int) -> list[int]:
        """Get all descendant process IDs of a root process.

        Uses CreateToolhelp32Snapshot to enumerate all running processes
        and traverses the parent-child relationship tree from root_pid
        downward. This is essential for finding windows belonging to
        child processes when the launched process is a script or launcher
        (e.g. .bat files that spawn separate executables).

        Args:
            root_pid: Root process ID to find descendants of.

        Returns:
            List of descendant PIDs (not including root_pid itself).
        """
        snapshot_handle = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        if snapshot_handle == _INVALID_HANDLE_VALUE:
            _logger.debug("toolhelp_snapshot_failed", extra={"root_pid": root_pid})
            return []

        parent_to_children: dict[int, list[int]] = {}
        try:
            entry = _PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)

            if not _kernel32.Process32FirstW(snapshot_handle, ctypes.byref(entry)):
                return []

            while True:
                child_pid = entry.th32ProcessID
                parent_pid = entry.th32ParentProcessID
                if parent_pid not in parent_to_children:
                    parent_to_children[parent_pid] = []
                parent_to_children[parent_pid].append(child_pid)

                entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
                if not _kernel32.Process32NextW(snapshot_handle, ctypes.byref(entry)):
                    break
        finally:
            _kernel32.CloseHandle(snapshot_handle)

        descendants: list[int] = []
        queue = list(parent_to_children.get(root_pid, []))
        visited: set[int] = {root_pid}

        while queue:
            pid = queue.pop(0)
            if pid in visited:
                continue
            visited.add(pid)
            descendants.append(pid)
            queue.extend(parent_to_children.get(pid, []))

        if descendants:
            _logger.debug(
                "descendant_pids_found",
                extra={"root_pid": root_pid, "descendant_count": len(descendants)},
            )

        return descendants

    @staticmethod
    def find_child_window(
        parent_hwnd: int,
        class_name: str | None = None,
        window_title: str | None = None,
    ) -> int:
        """Find a child window within a parent.

        Args:
            parent_hwnd: Parent window handle.
            class_name: Optional child class name.
            window_title: Optional child window title.

        Returns:
            Child window handle if found, 0 otherwise.
        """
        hwnd = _user32.FindWindowExW(parent_hwnd, None, class_name, window_title)
        return int(hwnd) if hwnd else 0

    @staticmethod
    def enumerate_child_windows(
        parent_hwnd: int,
        filter_func: Callable[[int, str, str], bool] | None = None,
    ) -> list[tuple[int, str, str]]:
        """Enumerate all child windows of a parent.

        Args:
            parent_hwnd: Parent window handle.
            filter_func: Optional filter function(hwnd, class_name, title) -> bool.

        Returns:
            List of (hwnd, class_name, title) tuples for matching children.
        """
        results: list[tuple[int, str, str]] = []

        def enum_callback(hwnd: int, _lparam: int) -> bool:
            class_buf = ctypes.create_unicode_buffer(256)
            _user32.GetClassNameW(hwnd, class_buf, 256)
            class_name = class_buf.value

            title_buf = ctypes.create_unicode_buffer(512)
            _user32.GetWindowTextW(hwnd, title_buf, 512)
            title = title_buf.value

            if filter_func is None or filter_func(hwnd, class_name, title):
                results.append((hwnd, class_name, title))
            return True

        callback = _ENUM_CALLBACK_TYPE(enum_callback)
        _user32.EnumChildWindows(parent_hwnd, callback, 0)
        return results

    @staticmethod
    def set_parent(child_hwnd: int, parent_hwnd: int) -> int:
        """Set the parent of a window.

        Args:
            child_hwnd: Window to reparent.
            parent_hwnd: New parent window handle.

        Returns:
            Previous parent handle, or 0 on failure.
        """
        old_parent = _user32.SetParent(child_hwnd, parent_hwnd)
        if not old_parent and parent_hwnd:
            error = _kernel32.GetLastError()
            _logger.warning("set_parent_failed", extra={"error_code": error})
        return int(old_parent) if old_parent else 0

    @staticmethod
    def get_window_style(hwnd: int) -> int:
        """Get the window style flags.

        Args:
            hwnd: Window handle.

        Returns:
            Window style flags.
        """
        return _user32.GetWindowLongW(hwnd, GWL_STYLE)

    @staticmethod
    def set_window_style(hwnd: int, style: int) -> int:
        """Set the window style flags.

        Args:
            hwnd: Window handle.
            style: New style flags.

        Returns:
            Previous style flags.
        """
        return _user32.SetWindowLongW(hwnd, GWL_STYLE, style)

    @staticmethod
    def get_ex_style(hwnd: int) -> int:
        """Get the extended window style flags.

        Args:
            hwnd: Window handle.

        Returns:
            Extended style flags.
        """
        return _user32.GetWindowLongW(hwnd, GWL_EXSTYLE)

    @staticmethod
    def set_ex_style(hwnd: int, style: int) -> int:
        """Set the extended window style flags.

        Args:
            hwnd: Window handle.
            style: New extended style flags.

        Returns:
            Previous extended style flags.
        """
        return _user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)

    @staticmethod
    def remove_window_borders(hwnd: int) -> None:
        """Remove window decorations (title bar, borders, etc.).

        Args:
            hwnd: Window handle to modify.
        """
        style = Win32WindowHelper.get_window_style(hwnd)
        _logger.debug("removing_window_borders", extra={"hwnd": hex(hwnd), "original_style": hex(style)})
        style &= ~(WS_CAPTION | WS_THICKFRAME | WS_BORDER | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_POPUP)
        style |= WS_CHILD
        Win32WindowHelper.set_window_style(hwnd, style)

        ex_style = Win32WindowHelper.get_ex_style(hwnd)
        ex_style &= ~(WS_EX_APPWINDOW | WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE | WS_EX_DLGMODALFRAME)
        Win32WindowHelper.set_ex_style(hwnd, ex_style)

        _user32.SetWindowPos(
            hwnd,
            None,
            0,
            0,
            0,
            0,
            SWP_FRAMECHANGED | SWP_NOZORDER | SWP_NOACTIVATE,
        )

    @staticmethod
    def restore_window_borders(hwnd: int) -> None:
        """Restore default window decorations.

        Args:
            hwnd: Window handle to modify.
        """
        _logger.debug("restoring_window_borders", extra={"hwnd": hex(hwnd)})
        style = Win32WindowHelper.get_window_style(hwnd)
        style &= ~WS_CHILD
        style |= WS_POPUP | WS_CAPTION | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX
        Win32WindowHelper.set_window_style(hwnd, style)

        ex_style = Win32WindowHelper.get_ex_style(hwnd)
        ex_style |= WS_EX_APPWINDOW | WS_EX_WINDOWEDGE
        Win32WindowHelper.set_ex_style(hwnd, ex_style)

        _user32.SetWindowPos(
            hwnd,
            None,
            0,
            0,
            0,
            0,
            SWP_FRAMECHANGED | SWP_NOZORDER | SWP_SHOWWINDOW,
        )

    @staticmethod
    def move_window(
        hwnd: int,
        x: int,
        y: int,
        width: int,
        height: int,
        repaint: bool = True,
    ) -> bool:
        """Move and resize a window.

        Args:
            hwnd: Window handle.
            x: New X position.
            y: New Y position.
            width: New width.
            height: New height.
            repaint: Whether to repaint after move.

        Returns:
            True if successful, False otherwise.
        """
        return bool(_user32.MoveWindow(hwnd, x, y, width, height, repaint))

    @staticmethod
    def is_window_valid(hwnd: int) -> bool:
        """Check if a window handle is still valid.

        Args:
            hwnd: Window handle to check.

        Returns:
            True if valid, False otherwise.
        """
        return bool(_user32.IsWindow(hwnd))

    @staticmethod
    def is_window_visible(hwnd: int) -> bool:
        """Check if a window is visible.

        Args:
            hwnd: Window handle to check.

        Returns:
            True if visible, False otherwise.
        """
        return bool(_user32.IsWindowVisible(hwnd))

    @staticmethod
    def show_window(hwnd: int, show_cmd: int = 1) -> bool:
        """Show or hide a window.

        Args:
            hwnd: Window handle.
            show_cmd: Show command (1=show, 0=hide, 3=maximize, etc.).

        Returns:
            True if window was previously visible.
        """
        return bool(_user32.ShowWindow(hwnd, show_cmd))

    @staticmethod
    def set_foreground_window(hwnd: int) -> bool:
        """Bring a window to the foreground.

        Args:
            hwnd: Window handle.

        Returns:
            True if successful, False otherwise.
        """
        return bool(_user32.SetForegroundWindow(hwnd))

    @staticmethod
    def post_message(
        hwnd: int,
        msg: int,
        wparam: int = 0,
        lparam: int = 0,
    ) -> bool:
        """Post a message to a window asynchronously.

        Args:
            hwnd: Window handle.
            msg: Message ID.
            wparam: WPARAM value.
            lparam: LPARAM value.

        Returns:
            True if message was posted successfully.
        """
        return bool(_user32.PostMessageW(hwnd, msg, wparam, lparam))

    @staticmethod
    def send_message(
        hwnd: int,
        msg: int,
        wparam: int = 0,
        lparam: int = 0,
    ) -> int:
        """Send a message to a window synchronously.

        Args:
            hwnd: Window handle.
            msg: Message ID.
            wparam: WPARAM value.
            lparam: LPARAM value.

        Returns:
            Message result value.
        """
        return int(_user32.SendMessageW(hwnd, msg, wparam, lparam))

    @staticmethod
    def close_window(hwnd: int) -> bool:
        """Request a window to close via WM_CLOSE.

        Args:
            hwnd: Window handle.

        Returns:
            True if message was posted successfully.
        """
        return Win32WindowHelper.post_message(hwnd, WM_CLOSE)

    @staticmethod
    def get_window_rect(hwnd: int) -> tuple[int, int, int, int]:
        """Get window screen coordinates.

        Args:
            hwnd: Window handle.

        Returns:
            Tuple of (left, top, right, bottom) screen coordinates.
        """
        rect = wintypes.RECT()
        _user32.GetWindowRect(hwnd, ctypes.byref(rect))
        return (rect.left, rect.top, rect.right, rect.bottom)

    @staticmethod
    def get_client_rect(hwnd: int) -> tuple[int, int, int, int]:
        """Get window client area dimensions.

        Args:
            hwnd: Window handle.

        Returns:
            Tuple of (left, top, right, bottom) where left/top are always 0.
        """
        rect = wintypes.RECT()
        _user32.GetClientRect(hwnd, ctypes.byref(rect))
        return (rect.left, rect.top, rect.right, rect.bottom)

    @staticmethod
    def get_window_text(hwnd: int) -> str:
        """Get window title text.

        Args:
            hwnd: Window handle.

        Returns:
            Window title string.
        """
        length = _user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return ""
        buf = ctypes.create_unicode_buffer(length + 1)
        _user32.GetWindowTextW(hwnd, buf, length + 1)
        return buf.value

    @staticmethod
    def get_class_name(hwnd: int) -> str:
        """Get window class name.

        Args:
            hwnd: Window handle.

        Returns:
            Window class name string.
        """
        buf = ctypes.create_unicode_buffer(256)
        length = _user32.GetClassNameW(hwnd, buf, 256)
        return buf.value if length > 0 else ""

    @staticmethod
    def get_process_id(hwnd: int) -> int:
        """Get process ID that owns a window.

        Args:
            hwnd: Window handle.

        Returns:
            Process ID, or 0 on failure.
        """
        pid = wintypes.DWORD()
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return pid.value

    @staticmethod
    def find_executable_path(executable_name: str) -> Path | None:
        """Search for an executable in common locations.

        Args:
            executable_name: Name of executable to find.

        Returns:
            Path to executable if found, None otherwise.
        """
        if path := shutil.which(executable_name):
            return Path(path)

        common_paths = [
            Path(r"C:\Program Files"),
            Path(r"C:\Program Files (x86)"),
            Path.home() / "AppData" / "Local",
            Path.home() / "AppData" / "Local" / "Programs",
        ]

        for base in common_paths:
            for candidate in base.rglob(executable_name):
                if candidate.is_file():
                    return candidate

        registry_locations = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
        ]

        for hkey, subkey in registry_locations:
            try:
                with winreg.OpenKey(hkey, f"{subkey}\\{executable_name}") as key:
                    value, _ = winreg.QueryValueEx(key, "")
                    if value:
                        return Path(value)
            except OSError:
                _logger.debug("registry_app_path_not_found", extra={"executable": executable_name})
                continue

        return None
