# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Third-pass critical-coverage tests for ``intellicrack.bridges.installer``.

These tests reach the lines that need a different interpreter, token or path than the one
pytest runs with, and each one starts a real child process or uses a real path that
the operating system refuses to resolve:

* the ``pefile`` import fallback runs in a child interpreter in which ``import pefile``
  raises ``ImportError`` because ``sys.modules["pefile"]`` is ``None``;
* the architecture alias fallback runs in a child interpreter in which ``platform.machine()``
  is answered from ``PROCESSOR_ARCHITECTURE`` (the standard library falls back to that
  variable when its ``_wmi`` module is unavailable; the child blocks ``_wmi`` and reloads
  ``platform`` so that this holds whether or not another startup hook imported it first);
* the Program Files refusal runs in a child started with a real restricted token
  (``CreateRestrictedToken`` with the Administrators SID set to deny-only and every
  privilege except bypass-traverse removed, started with ``CreateProcessAsUserW``), whose
  ``IsUserAnAdmin()`` is 0;
* the two ``Path.resolve()`` failure branches use a Win32 device-namespace path that
  ``os.path.realpath`` cannot resolve (Windows error 6), once as the target and once as a
  Program Files prefix taken from the environment.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Final, cast

import pytest

from intellicrack.bridges import installer as installer_mod
from intellicrack.bridges.installer import path_requires_admin


pytestmark = pytest.mark.spawns_process

_SRC_DIR: Final[Path] = Path(installer_mod.__file__).resolve().parents[2]
_MARKER: Final[str] = "CHILD_JSON "
_UNRESOLVABLE: Final[str] = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\x"
_EBADF: Final[int] = 9
_X86_64_ALIASES: Final[list[str]] = ["amd64", "win64", "x64", "x86_64"]

_PEFILE_CHILD: Final[str] = """\
import json, os, sys
if os.environ.get("BLOCK_PEFILE") == "1":
    sys.modules["pefile"] = None
from pathlib import Path
from intellicrack.bridges import installer as m
version = m._read_pe_version_info(Path(sys.argv[1]))
print("CHILD_JSON " + json.dumps({
    "flag": m._pefile_available,
    "module_is_none": m._pefile_mod is None,
    "public_flag": m.pefile_available(),
    "version": version,
}))
"""

_ARCH_CHILD: Final[str] = """\
import importlib, json, sys
sys.modules["_wmi"] = None
import platform
importlib.reload(platform)
wmi_blocked = platform._wmi is None
machine = platform.machine()
from intellicrack.bridges import installer as m
print("CHILD_JSON " + json.dumps({
    "wmi_blocked": wmi_blocked,
    "machine": machine,
    "aliases": sorted(m._host_arch_aliases()),
}))
"""

_RESTRICTED_CHILD: Final[str] = """\
import ctypes, json, os, sys
from pathlib import Path
out_path = Path(sys.argv[1])
out = {}
try:
    out["is_admin"] = int(ctypes.windll.shell32.IsUserAnAdmin())
    sys.path.insert(0, sys.argv[2])
    from intellicrack.bridges import installer as m
    out["product_admin"] = m.is_user_admin()
    target = Path(os.environ["PROGRAMFILES"]) / "IntellicrackR3Target"
    out["requires_admin"] = m.path_requires_admin(target)
    out["target"] = str(target)
    if out["requires_admin"] and not out["product_admin"]:
        plugin_root = Path(sys.argv[3])
        bin_dir = plugin_root / "x64dbg-plugin" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        (bin_dir / "intellicrack_bridge_x64.dp64").write_bytes(b"r3")
        result = m.deploy_x64dbg_plugin_detailed(target, plugin_root)
        out["success"] = result.success
        out["per_arch"] = [
            {"arch": a.arch, "filename": a.filename, "status": a.status,
             "target": None if a.target is None else str(a.target), "error": a.error}
            for a in result.per_arch
        ]
        out["target_exists"] = target.exists()
except BaseException as exc:
    out["error"] = repr(exc)
out_path.write_text(json.dumps(out), encoding="utf-8")
"""

_LAUNCHER: Final[str] = """\
import ctypes, json, subprocess, sys
from ctypes import wintypes

class SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

class StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
    ]

class ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]

adv = ctypes.WinDLL("advapi32", use_last_error=True)
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.WaitForSingleObject.restype = wintypes.DWORD
k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
k32.LocalFree.argtypes = [ctypes.c_void_p]
adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
adv.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(SidAndAttributes),
    wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.HANDLE),
]
adv.CreateProcessAsUserW.argtypes = [
    wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
    wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
    ctypes.POINTER(StartupInfo), ctypes.POINTER(ProcessInformation),
]

out = {}
token = wintypes.HANDLE()
restricted = wintypes.HANDLE()
admin_sid = ctypes.c_void_p()
try:
    own = 0x1 | 0x2 | 0x8 | 0x80
    out["open_ok"] = bool(adv.OpenProcessToken(k32.GetCurrentProcess(), own, ctypes.byref(token)))
    out["sid_ok"] = bool(adv.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(admin_sid)))
    sid_attr = SidAndAttributes(admin_sid, 0)
    out["restrict_ok"] = bool(adv.CreateRestrictedToken(
        token, 0x1, 1, ctypes.byref(sid_attr), 0, None, 0, None, ctypes.byref(restricted)))
    cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline([sys.executable, *sys.argv[1:]]))
    si = StartupInfo()
    si.cb = ctypes.sizeof(StartupInfo)
    pi = ProcessInformation()
    out["create_ok"] = bool(adv.CreateProcessAsUserW(
        restricted, None, cmdline, None, None, False, 0x08000000, None, None,
        ctypes.byref(si), ctypes.byref(pi)))
    if out["create_ok"]:
        try:
            out["wait_result"] = k32.WaitForSingleObject(pi.hProcess, 90000)
            code = wintypes.DWORD()
            k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
            out["exit_code"] = code.value
        finally:
            k32.CloseHandle(pi.hProcess)
            k32.CloseHandle(pi.hThread)
    else:
        out["last_error"] = ctypes.get_last_error()
finally:
    if admin_sid.value:
        k32.LocalFree(admin_sid)
    if restricted.value:
        k32.CloseHandle(restricted)
    if token.value:
        k32.CloseHandle(token)
print("CHILD_JSON " + json.dumps(out))
"""


def _child_env(extra: dict[str, str]) -> dict[str, str]:
    """Build the environment for a child interpreter that imports the product from ``src``.

    Args:
        extra: Variables to add or replace.

    Returns:
        dict[str, str]: A copy of the current environment with ``PYTHONPATH`` set to the
        product source directory, ``PROCESSOR_ARCHITEW6432`` removed and ``extra`` applied.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_SRC_DIR)
    env.pop("PROCESSOR_ARCHITEW6432", None)
    env.update(extra)
    return env


def _run_child(code: str, extra_env: dict[str, str], *args: str) -> dict[str, object]:
    """Run ``code`` in a child interpreter and return the JSON object it prints after the marker.

    Args:
        code: Python source for ``python -c``.
        extra_env: Environment variables for the child.
        *args: Command-line arguments forwarded to the child.

    Returns:
        dict[str, object]: The decoded JSON object from the child's last marker line.

    Raises:
        AssertionError: If the child fails or prints no marker line.
    """
    proc = subprocess.run(
        [sys.executable, "-c", code, *args],
        capture_output=True,
        text=True,
        env=_child_env(extra_env),
        timeout=120,
        check=False,
    )
    lines = [line for line in proc.stdout.splitlines() if line.startswith(_MARKER)]
    if proc.returncode != 0 or not lines:
        message = f"child failed rc={proc.returncode} stdout={proc.stdout[-1500:]!r} stderr={proc.stderr[-1500:]!r}"
        raise AssertionError(message)
    return cast("dict[str, object]", json.loads(lines[-1][len(_MARKER) :]))


def _as_dict(value: object) -> dict[str, object]:
    """Narrow a decoded JSON value to an object.

    Args:
        value: A value taken from decoded JSON.

    Returns:
        dict[str, object]: The same value, typed as a JSON object.

    Raises:
        TypeError: If the value is not an object.
    """
    if not isinstance(value, dict):
        message = f"expected a JSON object, got {value!r}"
        raise TypeError(message)
    return cast("dict[str, object]", value)


def _as_list(value: object) -> list[object]:
    """Narrow a decoded JSON value to an array.

    Args:
        value: A value taken from decoded JSON.

    Returns:
        list[object]: The same value, typed as a JSON array.

    Raises:
        TypeError: If the value is not an array.
    """
    if not isinstance(value, list):
        message = f"expected a JSON array, got {value!r}"
        raise TypeError(message)
    return cast("list[object]", value)


def test_module_imports_without_pefile_and_reports_it_unavailable() -> None:
    """With ``import pefile`` failing the module still imports and every pefile probe is disabled."""
    cmd_exe = str(Path(os.environ["SYSTEMROOT"]) / "System32" / "cmd.exe")

    blocked = _run_child(_PEFILE_CHILD, {"BLOCK_PEFILE": "1"}, cmd_exe)
    control = _run_child(_PEFILE_CHILD, {"BLOCK_PEFILE": "0"}, cmd_exe)

    assert control["flag"] is True
    assert control["module_is_none"] is False
    assert isinstance(control["version"], str)
    assert control["version"]

    assert blocked["flag"] is False
    assert blocked["module_is_none"] is True
    assert blocked["public_flag"] is False
    assert blocked["version"] is None


@pytest.mark.parametrize(
    ("processor_architecture", "expected_machine", "expected_aliases"),
    [
        pytest.param("ARM64", "ARM64", ["aarch64", "arm64"], id="arm64"),
        pytest.param("x86", "x86", ["i386", "i686", "win32", "x86"], id="x86"),
        pytest.param("FOO", "FOO", _X86_64_ALIASES, id="unrecognized-defaults-to-x86_64"),
        pytest.param("", "", _X86_64_ALIASES, id="empty-defaults-to-x86_64"),
    ],
)
def test_host_arch_aliases_follow_the_reported_architecture(
    processor_architecture: str,
    expected_machine: str,
    expected_aliases: list[str],
) -> None:
    """The alias set is the group that names the host architecture, else the x86_64 group.

    Args:
        processor_architecture: Value of ``PROCESSOR_ARCHITECTURE`` given to the child.
        expected_machine: What ``platform.machine()`` must then report in the child.
        expected_aliases: The sorted aliases the product must return.
    """
    result = _run_child(_ARCH_CHILD, {"PROCESSOR_ARCHITECTURE": processor_architecture})

    assert result["wmi_blocked"] is True
    assert result["machine"] == expected_machine
    assert result["aliases"] == expected_aliases


def test_deploy_refuses_program_files_for_a_non_administrator_token(tmp_path: Path) -> None:
    """A child with the Administrators SID deny-only is not an admin and is refused Program Files.

    Args:
        tmp_path: Directory for the child script, its result file and its plugin source tree.
    """
    script = tmp_path / "restricted_child.py"
    script.write_text(_RESTRICTED_CHILD, encoding="utf-8")
    result_file = tmp_path / "result.json"
    plugin_root = tmp_path / "plugin_root"

    launch = _run_child(
        _LAUNCHER,
        {},
        str(script),
        str(result_file),
        str(_SRC_DIR),
        str(plugin_root),
    )

    assert launch["open_ok"] is True
    assert launch["sid_ok"] is True
    assert launch["restrict_ok"] is True
    assert launch["create_ok"] is True
    assert launch["wait_result"] == 0
    assert launch["exit_code"] == 0

    outcome = _as_dict(json.loads(result_file.read_text(encoding="utf-8")))
    assert "error" not in outcome
    assert outcome["is_admin"] == 0
    assert outcome["product_admin"] is False
    assert outcome["requires_admin"] is True
    assert outcome["success"] is False
    assert outcome["target_exists"] is False

    per_arch = [_as_dict(item) for item in _as_list(outcome["per_arch"])]
    assert [(item["arch"], item["filename"]) for item in per_arch] == [
        ("x64", "intellicrack_bridge_x64.dp64"),
        ("x32", "intellicrack_bridge_x32.dp32"),
    ]
    for item in per_arch:
        assert item["status"] == "failed"
        assert item["target"] is None
        assert item["error"] == (
            f"deployment to {outcome['target']} requires administrator rights; "
            "rerun Intellicrack elevated or relocate x64dbg outside Program Files"
        )


def test_path_requires_admin_is_false_when_the_target_cannot_be_resolved() -> None:
    """A target whose ``Path.resolve()`` raises ``OSError`` is reported as not needing admin."""
    with pytest.raises(OSError, match="GLOBALROOT") as raised:
        Path(_UNRESOLVABLE).resolve()
    assert raised.value.errno == _EBADF

    assert path_requires_admin(Path(_UNRESOLVABLE)) is False


def test_path_requires_admin_skips_a_program_files_prefix_that_cannot_be_resolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unresolvable ``PROGRAMFILES`` value is skipped and the next prefix still decides.

    Args:
        tmp_path: Directory standing in for the second Program Files prefix.
        monkeypatch: Used only to set the three Program Files environment variables.
    """
    program_files = tmp_path / "pf"
    monkeypatch.setenv("PROGRAMFILES", _UNRESOLVABLE)
    monkeypatch.delenv("PROGRAMFILES(X86)", raising=False)
    monkeypatch.setenv("PROGRAMW6432", str(program_files))

    with pytest.raises(OSError, match="GLOBALROOT") as raised:
        Path(os.environ["PROGRAMFILES"]).resolve()
    assert raised.value.errno == _EBADF

    assert path_requires_admin(program_files / "tool") is True
    assert path_requires_admin(tmp_path / "elsewhere" / "tool") is False
