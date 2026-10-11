# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage for the QEMU sandbox's wait on a daemonized QEMU that the caller may not synchronize with.

``QEMUSandbox._await_qemu_exit`` polls a daemonized QEMU by PID through ``psutil.Process.wait``. When the
operating system refuses that wait with an error that is neither "process gone" nor "timed out", the
sandbox must report that QEMU is not known to have exited and log the refusal. Here a real child process
stands in for the daemon. A child interpreter drops its own ``SeDebugPrivilege`` (which would otherwise
bypass access lists), denies ``SYNCHRONIZE`` on the target through ``SetKernelObjectSecurity`` and runs the
production method against the target's PID. The parent asserts on the JSON that child prints.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Final

import pytest

import intellicrack


_SOURCE_ROOT: Final[Path] = Path(intellicrack.__file__).resolve().parent.parent
_DRIVER_TIMEOUT_S: Final[float] = 180.0
_WAIT_BUDGET_S: Final[float] = 0.5
_REFUSAL_EVENT: Final[str] = "qemu_exit_wait_failed"

_DRIVER: Final[str] = """
import asyncio
import ctypes
import json
import subprocess
import sys
from ctypes import wintypes

from structlog.testing import capture_logs

from intellicrack.bridges.win32_types import LUID, TOKEN_PRIVILEGES
from intellicrack.sandbox.qemu import QEMUSandbox

deny_mode = sys.argv[1]
budget = float(sys.argv[2])

SYNCHRONIZE = 0x00100000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
SPECIFIC_RIGHTS = 0xFFFF
TOKEN_QUERY = 0x8
TOKEN_ADJUST_PRIVILEGES = 0x20
SE_PRIVILEGE_REMOVED = 0x4
DACL_SECURITY_INFORMATION = 0x4
SDDL_REVISION_1 = 1
ALLOWED = SYNCHRONIZE | READ_CONTROL | WRITE_DAC | SPECIFIC_RIGHTS

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
]
advapi32.SetKernelObjectSecurity.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]

token = wintypes.HANDLE()
assert advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ctypes.byref(token))
luid = LUID()
assert advapi32.LookupPrivilegeValueW(None, 'SeDebugPrivilege', ctypes.byref(luid))
request = TOKEN_PRIVILEGES()
request.PrivilegeCount = 1
request.Privileges[0].Luid = luid
request.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED
assert advapi32.AdjustTokenPrivileges(token, 0, ctypes.byref(request), ctypes.sizeof(request), None, None)
kernel32.CloseHandle(token)

target = subprocess.Popen(
    [sys.executable, '-c', 'import sys\\nprint("ready", flush=True)\\nsys.stdin.read()\\n'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
)
result = {}
try:
    assert target.stdout.readline().strip() == b'ready'
    result['pid'] = target.pid
    if deny_mode == 'deny_sync':
        sddl = 'D:(D;;0x%x;;;WD)(A;;0x%x;;;WD)' % (SYNCHRONIZE, ALLOWED)
        descriptor = ctypes.c_void_p()
        assert advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, ctypes.byref(descriptor), None,
        )
        assert advapi32.SetKernelObjectSecurity(int(target._handle), DACL_SECURITY_INFORMATION, descriptor)
        kernel32.LocalFree(descriptor)

    sandbox = QEMUSandbox()
    setattr(sandbox, '_qemu_pid', target.pid)
    with capture_logs() as logs:
        result['returned'] = asyncio.run(sandbox._await_qemu_exit(budget))
    result['events'] = [
        [entry.get('event'), entry.get('pid'), entry.get('error'), entry.get('log_level')] for entry in logs
    ]
    result['alive'] = target.poll() is None
finally:
    if target.poll() is None:
        target.kill()
    target.wait(timeout=15)
    target.stdin.close()
    target.stdout.close()
sys.stdout.write(json.dumps(result) + '\\n')
sys.stdout.flush()
"""


def _child_environment(base: Path) -> dict[str, str]:
    """Build an environment that lets a child import the product without touching user state.

    Args:
        base: Directory under which the child's state and local application data are redirected.

    Returns:
        dict[str, str]: The inherited environment with the state redirected and ``src`` on the path.
    """
    local_app_data = base / "localappdata"
    state_dir = base / "state"
    local_app_data.mkdir(exist_ok=True)
    state_dir.mkdir(exist_ok=True)
    env = dict(os.environ)
    env["LOCALAPPDATA"] = str(local_app_data)
    env["INTELLICRACK_STATE_DIR"] = str(state_dir)
    env["QT_QPA_PLATFORM"] = "offscreen"
    env["PYTHONIOENCODING"] = "utf-8"
    inherited = env.get("PYTHONPATH")
    paths = [str(_SOURCE_ROOT)]
    env["PYTHONPATH"] = os.pathsep.join([*paths, inherited] if inherited else paths)
    return env


def _run_driver(base: Path, deny_mode: str) -> dict[str, Any]:
    """Run the driver in a child interpreter and parse the JSON line it prints last.

    Args:
        base: Per-test directory used for the child's working directory and redirected state.
        deny_mode: ``"deny_sync"`` to deny ``SYNCHRONIZE`` on the target, ``"none"`` to leave it alone.

    Returns:
        dict[str, Any]: The facts the driver reported.
    """
    completed = subprocess.run(
        [sys.executable, "-c", _DRIVER, deny_mode, str(_WAIT_BUDGET_S)],
        capture_output=True,
        text=True,
        timeout=_DRIVER_TIMEOUT_S,
        env=_child_environment(base),
        cwd=base,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    facts: dict[str, Any] = json.loads(lines[-1])
    return facts


@pytest.mark.spawns_process
def test_wait_refused_by_the_os_is_reported_as_not_exited_and_logged(tmp_path: Path) -> None:
    """A wait the OS refuses with ``AccessDenied`` yields False and a logged warning naming the PID.

    Args:
        tmp_path: Per-test temporary directory.
    """
    facts = _run_driver(tmp_path, "deny_sync")

    pid = facts["pid"]
    assert facts["returned"] is False
    assert facts["events"] == [[_REFUSAL_EVENT, pid, f"(pid={pid})", "warning"]]
    assert facts["alive"] is True


@pytest.mark.spawns_process
def test_wait_that_merely_times_out_logs_no_refusal(tmp_path: Path) -> None:
    """The same wait on an unrestricted, still-running process times out quietly and returns False.

    Args:
        tmp_path: Per-test temporary directory.
    """
    facts = _run_driver(tmp_path, "none")

    assert facts["returned"] is False
    assert facts["events"] == []
    assert facts["alive"] is True
