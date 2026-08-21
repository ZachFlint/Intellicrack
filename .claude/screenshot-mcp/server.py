"""Screenshot MCP server for Claude Code.

Provides tools to bring a background window to the foreground,
capture a screenshot of just that window, then restore the previous
foreground window (Claude Code's terminal).

Uses pure Win32 API (ctypes) for window management and PowerShell/.NET
for image capture -- zero external Python dependencies beyond the MCP SDK.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from mcp.server import MCPServer


if platform.system() != "Windows":
    sys.stderr.write("This MCP server only runs on Windows.\n")
    sys.exit(1)

mcp = MCPServer("Screenshot")

_SW_RESTORE = 9
_SW_MINIMIZE = 6
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

user32: Any = ctypes.windll.user32
kernel32: Any = ctypes.windll.kernel32

user32.SetProcessDPIAware()

_WNDENUMPROC = ctypes.WINFUNCTYPE(
    ctypes.wintypes.BOOL,
    ctypes.wintypes.HWND,
    ctypes.wintypes.LPARAM,
)


def _get_window_text(hwnd: int) -> str:
    length: int = user32.GetWindowTextLengthW(hwnd)
    if length == 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buf, length + 1)
    result: str = buf.value
    return result


def _get_window_pid(hwnd: int) -> int:
    pid = ctypes.wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def _get_process_name(hwnd: int) -> str:
    pid = _get_window_pid(hwnd)

    handle: int = kernel32.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if not handle:
        return ""

    try:
        buf = ctypes.create_unicode_buffer(260)
        size = ctypes.wintypes.DWORD(260)
        kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
        full_path: str = buf.value
        return Path(full_path).stem.lower() if full_path else ""
    finally:
        kernel32.CloseHandle(handle)


def _enumerate_windows() -> list[tuple[int, int, str, str]]:
    results: list[tuple[int, int, str, str]] = []

    def callback(hwnd: int, _lparam: int) -> bool:
        if not user32.IsWindowVisible(hwnd):
            return True
        title = _get_window_text(hwnd)
        if not title:
            return True
        proc = _get_process_name(hwnd)
        pid = _get_window_pid(hwnd)
        if proc:
            results.append((hwnd, pid, proc, title))
        return True

    cb = _WNDENUMPROC(callback)
    user32.EnumWindows(cb, 0)
    return results


def _find_window(
    process_name: str | None = None,
    window_title: str | None = None,
    pid: int | None = None,
) -> tuple[int, str]:
    if not process_name and not window_title and pid is None:
        msg = "Provide at least one of process_name, window_title, or pid"
        raise ValueError(msg)

    pn = (process_name or "").lower()
    wt = (window_title or "").lower()

    for hwnd, wpid, proc, title in _enumerate_windows():
        pid_ok = (pid is None) or pid == wpid
        proc_ok = (not pn) or pn == proc or pn in proc
        title_ok = (not wt) or wt in title.lower()
        if pid_ok and proc_ok and title_ok:
            return hwnd, title

    criteria: list[str] = []
    if process_name:
        criteria.append(f"process='{process_name}'")
    if window_title:
        criteria.append(f"title='{window_title}'")
    if pid is not None:
        criteria.append(f"pid={pid}")
    msg = f"No visible window found matching {', '.join(criteria)}"
    raise ValueError(msg)


def _force_foreground(hwnd: int) -> None:
    current_thread: int = kernel32.GetCurrentThreadId()
    target_thread: int = user32.GetWindowThreadProcessId(hwnd, None)

    attached = False
    if current_thread != target_thread:
        user32.AttachThreadInput(current_thread, target_thread, True)
        attached = True

    user32.ShowWindow(hwnd, _SW_RESTORE)
    user32.SetForegroundWindow(hwnd)
    user32.BringWindowToTop(hwnd)

    if attached:
        user32.AttachThreadInput(current_thread, target_thread, False)


def _capture_window_region(hwnd: int, output_path: str) -> tuple[int, int]:
    rect = ctypes.wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))

    left: int = rect.left
    top: int = rect.top
    width = rect.right - rect.left
    height = rect.bottom - rect.top

    escaped_path = output_path.replace("'", "''")
    ps_script = (
        "Add-Type -AssemblyName System.Drawing; "
        f"$b = New-Object System.Drawing.Bitmap({width}, {height}); "
        "$g = [System.Drawing.Graphics]::FromImage($b); "
        f"$g.CopyFromScreen({left}, {top}, 0, 0, "
        f"[System.Drawing.Size]::new({width}, {height})); "
        f"$b.Save('{escaped_path}', "
        "[System.Drawing.Imaging.ImageFormat]::Png); "
        "$g.Dispose(); $b.Dispose()"
    )

    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    if result.returncode != 0:
        msg = f"Screenshot capture failed: {result.stderr.strip()}"
        raise RuntimeError(msg)

    return width, height


@mcp.tool()
def capture_window(
    process_name: str | None = None,
    window_title: str | None = None,
    pid: int | None = None,
) -> str:
    """Bring a window to foreground, capture it, then restore Claude Code.

    Provide at least one of process_name, window_title, or pid to identify
    the target. Use the list_windows tool first if you need to discover
    available windows and their PIDs.

    After this tool returns, use the Read tool on the returned file path to
    view the screenshot image.

    Args:
        process_name: Process name (e.g. 'notepad', 'chrome'). Case-insensitive.
        window_title: Substring to match in window title. Case-insensitive.
        pid: Exact process ID to target. Use list_windows to find PIDs.

    Returns:
        Path to the saved PNG screenshot and capture metadata.
    """
    original_hwnd: int = user32.GetForegroundWindow()

    target_hwnd, target_title = _find_window(process_name, window_title, pid)

    _force_foreground(target_hwnd)

    time.sleep(0.6)

    temp_dir = Path(tempfile.gettempdir())
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_path = temp_dir / f"claude_screenshot_{timestamp}.png"

    width, height = _capture_window_region(target_hwnd, str(output_path))

    user32.ShowWindow(target_hwnd, _SW_MINIMIZE)
    time.sleep(0.2)

    if original_hwnd:
        _force_foreground(original_hwnd)

    return (
        f"Screenshot saved: {output_path}\n"
        f"Window: {target_title}\n"
        f"Size: {width}x{height}\n\n"
        f"Use the Read tool on the file path above to view the screenshot."
    )


@mcp.tool()
def list_windows() -> str:
    """List all visible windows with their process names, PIDs, and titles.

    Use this to discover what process_name, window_title, or pid values
    to pass to capture_window.

    Returns:
        Formatted table of visible windows with PIDs.
    """
    windows = _enumerate_windows()

    lines: list[str] = ["PID | Process | Window Title", "--- | --- | ---"]
    for _hwnd, wpid, proc, title in sorted(
        windows, key=lambda x: x[2].lower()
    ):
        lines.append(f"{wpid} | {proc} | {title}")

    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
