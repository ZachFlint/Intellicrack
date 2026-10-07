# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Third-pass coverage for the Windows Sandbox backend, written from facts measured in the test container.

Windows Sandbox never starts here. Programs the backend would find on the host or in the guest are copies
of System32 programs placed under the names it searches for, on a ``PATH`` the test controls: ``tree.com`` as
``pwsh`` (prints a plain-text message, exits 0) and as ``procdump64.exe`` (exits 0), and ``cmd.exe`` as the
guest's ``mofcomp.exe`` (exits 0 when its stdin is at end of file, which is how the guest dispatcher starts it).
The guest command channel is the production dispatcher script run under the real ``powershell.exe`` with a guest
``PATH`` that holds only the stand-ins, so the real ``mofcomp`` can never be found, let alone run.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest
from structlog.testing import capture_logs

import intellicrack.sandbox.windows as windows_module
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen, TimeoutExpired, run
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.windows import WindowsSandbox, find_sandbox_session_pid
from tests._helpers.polling import wait_until


if TYPE_CHECKING:
    from collections.abc import Generator, Mapping, Sequence


pytestmark = [pytest.mark.spawns_process]

_COMMAND_BUDGET_S: Final[int] = 90
_READY_BUDGET_S: Final[float] = 90.0
_LOOKUP_BUDGET_S: Final[float] = 60.0
_ORACLE_BUDGET_S: Final[float] = 30.0
_ESCAPE_BUDGET_S: Final[float] = 110.0
_POLL_S: Final[float] = 0.05
_NONEXISTENT_PID: Final[int] = 0xFFFFFFFC
_PWSH_ARGS: Final[tuple[str, ...]] = ("-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "stand-in")
_DUMP_BYTES: Final[bytes] = b"existing dump bytes"
_WMI_TECHNIQUES: Final[list[str]] = [
    "wmi_hijack_win32_computersystem",
    "wmi_hijack_win32_computersystemproduct",
    "wmi_hijack_win32_bios",
]
_GUEST_STEP_TECHNIQUES: Final[list[str]] = ["hostname_change", "decoy_user_profile", "decoy_documents"]

_POWERSHELL_TEMPLATE: Final[str] = (
    "@echo off\r\n"
    'if /I "%~1"=="-NoProfile" goto verify\r\n'
    "exit /b @RC@\r\n"
    ":verify\r\n"
    '"@PYTHON@" "@SCRIPT@" "@SHARE@"\r\n'
    "exit /b %ERRORLEVEL%\r\n"
)

_VERIFY_SCRIPT: Final[str] = r"""import json
import re
import sys
from pathlib import Path

share = Path(sys.argv[1])
mofs = list((share / "input").glob("intellicrack_antievasion_*.mof"))
newest = max(mofs, key=lambda path: path.stat().st_mtime_ns)
text = newest.read_text(encoding="utf-8")


def grab(pattern):
    match = re.search(pattern, text)
    return match.group(1) if match else ""


print(json.dumps({
    "Manufacturer": grab(r'\binstance of Win32_ComputerSystem\b[\s\S]*?Manufacturer\s*=\s*"([^"]+)";'),
    "Model": grab(r'\binstance of Win32_ComputerSystem\b[\s\S]*?Model\s*=\s*"([^"]+)";'),
    "ProductName": grab(r'\binstance of Win32_ComputerSystemProduct\b[\s\S]*?Name\s*=\s*"([^"]+)";'),
    "ProductVendor": grab(r'\binstance of Win32_ComputerSystemProduct\b[\s\S]*?Vendor\s*=\s*"([^"]+)";'),
    "BIOSVendor": grab(r'\binstance of Win32_BIOS\b[\s\S]*?Manufacturer\s*=\s*"([^"]+)";'),
    "BIOSVersion": grab(r'\binstance of Win32_BIOS\b[\s\S]*?SMBIOSBIOSVersion\s*=\s*"([^"]+)";'),
}))
"""

_ESCAPE_CODE: Final[str] = """
import json

from intellicrack.sandbox.windows import find_sandbox_session_pid

results = []
for _ in range(2):
    try:
        results.append({"returned": find_sandbox_session_pid("intellicrack_critcov_third_pass.wsb")})
    except BaseException as exc:
        results.append({"raised": type(exc).__module__ + "." + type(exc).__qualname__})
        break
print(json.dumps(results))
"""


class _Exposed(WindowsSandbox):
    """WindowsSandbox with the private state and steps these tests drive made reachable."""

    def __init__(self) -> None:
        """Create the backend with a bounded command budget."""
        super().__init__(SandboxConfig(timeout_seconds=_COMMAND_BUDGET_S))

    def bind(self, shared: Path) -> None:
        """Point the backend at a host directory standing in for the guest's shared folder.

        Args:
            shared: Directory the guest dispatcher watches.
        """
        self.SANDBOX_SHARED_PATH = str(shared)
        self._shared_folder = shared
        self.state.status = "running"

    def stage_into(self, folder: Path) -> None:
        """Choose the folder the monitor scripts are staged into.

        Args:
            folder: Destination monitor folder.
        """
        self._monitor_folder = folder

    async def stage_monitor_scripts(self) -> None:
        """Forward to :meth:`WindowsSandbox._create_monitor_scripts`."""
        await self._create_monitor_scripts()

    async def find_worker(self) -> int | None:
        """Forward to :meth:`WindowsSandbox._resolve_worker_pid`.

        Returns:
            int | None: The worker process id, or None.
        """
        return await self._resolve_worker_pid()

    def dispatcher_source(self) -> str:
        """Return the dispatcher script the backend would stage.

        Returns:
            str: The generated PowerShell source.
        """
        return self._dispatcher_ps1_source()

    def ready_flag_path(self) -> Path:
        """Return the flag the dispatcher writes when it comes up.

        Returns:
            Path: Host path of the readiness flag.
        """
        assert self._shared_folder is not None
        return self._shared_folder / "flags" / self.DISPATCHER_READY_MARKER

    async def dump_with_procdump(self, pid: int, dump_path: Path) -> bool:
        """Forward to :meth:`WindowsSandbox._minidump_via_procdump`.

        Args:
            pid: Process to dump.
            dump_path: Destination dump path.

        Returns:
            bool: Whether a dump file was reported produced.
        """
        return await self._minidump_via_procdump(pid, dump_path)


@dataclass(frozen=True)
class _Guest:
    """A running guest: the backend bound to a share, and the files its guest tools are built from.

    Attributes:
        sandbox: Backend whose commands the dispatcher serves.
        share: Host directory the dispatcher watches.
        guest_bin: The only directory on the guest ``PATH``.
        verify_script: Python script the guest ``powershell`` stand-in runs to answer the identity query.
        guest_path: The exact ``PATH`` value the dispatcher was started with.
    """

    sandbox: _Exposed
    share: Path
    guest_bin: Path
    verify_script: Path
    guest_path: str


def _events(captured: Sequence[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    """Select the captured log records with a given event name.

    Args:
        captured: Records collected by ``capture_logs``.
        name: Event name to select.

    Returns:
        list[Mapping[str, Any]]: Matching records in order.
    """
    return [entry for entry in captured if entry.get("event") == name]


def _install_standin(directory: Path, source_name: str, target_name: str) -> Path:
    """Place a copy of a host program in ``directory`` under another name.

    Args:
        directory: Destination directory.
        source_name: Program to copy, located on the host ``PATH``.
        target_name: File name to give the copy.

    Returns:
        Path: Path of the copy.
    """
    source = shutil.which(source_name)
    assert source is not None, f"{source_name} is required to build the stand-in"
    target = directory / target_name
    shutil.copy2(source, target)
    return target


def _prepend_path(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
    """Put ``directory`` first on ``PATH``.

    Args:
        monkeypatch: Restores ``PATH`` afterwards.
        directory: Directory to search first.
    """
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ['PATH']}")


def _standin_run(standin: Path, args: Sequence[str]) -> tuple[int, str]:
    """Run a stand-in with its stdin at end of file and report how it behaves on its own.

    Args:
        standin: The stand-in program.
        args: Arguments to pass.

    Returns:
        tuple[int, str]: Exit code and stripped stdout decoded the way the backend decodes it.
    """
    done = run([str(standin), *args], stdin=DEVNULL, capture_output=True, timeout=_ORACLE_BUDGET_S, check=False)
    return int(done.returncode), bytes(done.stdout).decode("utf-8", errors="replace").strip()


def _assert_found_first(name: str, expected: Path) -> None:
    """Assert that a program name resolves to ``expected`` on the current ``PATH``.

    Args:
        name: Program name to resolve.
        expected: The stand-in that must win.
    """
    resolved = shutil.which(name)
    assert resolved is not None
    assert Path(resolved).samefile(expected)


def _assert_guest_path_is_confined(guest: _Guest) -> None:
    """Assert that the only ``mofcomp.exe`` the guest can start is the stand-in.

    The guest ``PATH`` must name nothing but the stand-in directory, and the working directory, which the guest
    shell searches first, must not hold a ``mofcomp.exe`` of its own.

    Args:
        guest: The running guest.
    """
    assert guest.guest_path == str(guest.guest_bin)
    assert [Path(entry) for entry in guest.guest_path.split(os.pathsep)] == [guest.guest_bin]
    found = shutil.which("mofcomp.exe", path=guest.guest_path)
    assert found is not None
    assert Path(found).samefile(guest.guest_bin / "mofcomp.exe")
    assert not (Path.cwd() / "mofcomp.exe").exists()


@contextlib.contextmanager
def _guest(root: Path) -> Generator[_Guest]:
    """Run the production dispatcher script as the guest of a sandbox bound to ``root``.

    The guest ``PATH`` holds only copies of ``cmd.exe``: one under its own name, which the dispatcher needs, and
    one named ``mofcomp.exe``. The ``powershell`` stand-in is written by the test.

    Args:
        root: Scratch directory for the share, the guest ``PATH`` directory and the dispatcher script.

    Yields:
        _Guest: A running guest whose dispatcher is polling.
    """
    powershell = shutil.which("powershell.exe")
    assert powershell is not None, "this test needs the real powershell.exe to run the dispatcher"
    share = root / "IntellicrackShared"
    share.mkdir()
    guest_bin = root / "guest_bin"
    guest_bin.mkdir()
    _install_standin(guest_bin, "cmd.exe", "cmd.exe")
    _install_standin(guest_bin, "cmd.exe", "mofcomp.exe")
    verify_script = root / "verify_identity.py"
    verify_script.write_text(_VERIFY_SCRIPT, encoding="utf-8")
    sandbox = _Exposed()
    sandbox.bind(share)
    guest_path = str(guest_bin)
    environment = dict(os.environ)
    environment["PATH"] = guest_path
    script = root / "dispatcher.ps1"
    script.write_text(sandbox.dispatcher_source(), encoding="utf-8")
    process = Popen(
        [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        stdin=DEVNULL,
        stdout=DEVNULL,
        stderr=DEVNULL,
        env=environment,
    )
    try:
        deadline = time.monotonic() + _READY_BUDGET_S
        while time.monotonic() < deadline and not sandbox.ready_flag_path().is_file():
            if process.poll() is not None:
                pytest.fail("the dispatcher exited before signalling ready")
            time.sleep(0.25)
        assert sandbox.ready_flag_path().is_file(), "the real dispatcher never signalled ready"
        yield _Guest(sandbox=sandbox, share=share, guest_bin=guest_bin, verify_script=verify_script, guest_path=guest_path)
    finally:
        process.terminate()
        try:
            process.wait(timeout=_READY_BUDGET_S)
        except TimeoutExpired:
            process.kill()
            process.wait(timeout=_READY_BUDGET_S)


def _write_guest_powershell(guest: _Guest, other_exit_code: int) -> None:
    """Write the guest ``powershell`` stand-in.

    It answers the identity query (its first argument is ``-NoProfile``) with the identity staged in the newest
    MOF, and exits with ``other_exit_code`` for every other invocation.

    Args:
        guest: The running guest.
        other_exit_code: Exit code for every invocation that is not the identity query.
    """
    body = (
        _POWERSHELL_TEMPLATE
        .replace("@RC@", str(other_exit_code))
        .replace("@PYTHON@", sys.executable)
        .replace("@SCRIPT@", str(guest.verify_script))
        .replace("@SHARE@", str(guest.share))
    )
    (guest.guest_bin / "powershell.cmd").write_bytes(body.encode("ascii"))


def test_a_session_lookup_whose_powershell_prints_text_finds_no_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Output that is not JSON ends the lookup with no session and one parse-failure log record.

    ``pwsh`` is a copy of ``tree.com``, which prints a plain-text message and exits 0 for any arguments.

    Args:
        tmp_path: Pytest scratch directory.
        monkeypatch: Used to put the stand-in first on ``PATH``.
    """
    standin = _install_standin(tmp_path, "tree.com", "pwsh.exe")
    _prepend_path(monkeypatch, tmp_path)
    _assert_found_first("pwsh", standin)
    exit_code, expected = _standin_run(standin, _PWSH_ARGS)
    assert exit_code == 0
    assert expected
    with pytest.raises(ValueError, match="Expecting value"):
        json.loads(expected)

    with capture_logs() as captured:
        found = find_sandbox_session_pid("intellicrack_critcov_third_pass.wsb")

    assert found is None
    failures = _events(captured, "sandbox_session_json_parse_failed")
    assert len(failures) == 1
    assert failures[0]["output_prefix"] == expected[:120]
    assert str(failures[0]["error"]).startswith("Expecting value")


@pytest.mark.asyncio
async def test_a_worker_lookup_whose_powershell_prints_text_logs_it_and_keeps_polling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Output that is not JSON is logged with its size and prefix, and the lookup goes on polling.

    The lookup is cancelled as soon as the first parse-failure record appears, so it never waits out its budget.

    Args:
        tmp_path: Pytest scratch directory.
        monkeypatch: Used to put the stand-in first on ``PATH``.
    """
    standin = _install_standin(tmp_path, "tree.com", "pwsh.exe")
    _prepend_path(monkeypatch, tmp_path)
    _assert_found_first("pwsh", standin)
    exit_code, expected = _standin_run(standin, _PWSH_ARGS)
    assert exit_code == 0
    assert expected
    sandbox = _Exposed()

    with capture_logs() as captured:
        lookup = asyncio.create_task(sandbox.find_worker())
        try:
            await wait_until(
                lambda: bool(_events(captured, "vmwp_json_parse_failed")) or lookup.done(),
                budget=_LOOKUP_BUDGET_S,
                interval=_POLL_S,
            )
            finished_early = lookup.done()
        finally:
            lookup.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await lookup

    assert not finished_early
    failures = _events(captured, "vmwp_json_parse_failed")
    assert len(failures) == 1
    assert failures[0]["output_size"] == len(expected)
    assert failures[0]["output_prefix"] == expected[:120]
    assert str(failures[0]["error"]).startswith("Expecting value")


@pytest.mark.asyncio
async def test_staging_the_monitor_scripts_fails_when_the_bundled_directory_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bundled scripts directory that does not exist is reported, naming it, and nothing is staged.

    Args:
        tmp_path: Pytest scratch directory.
        monkeypatch: Points the bundled scripts location at a directory that does not exist.
    """
    missing = tmp_path / "no_such_scripts"
    monitor = tmp_path / "monitor"
    monitor.mkdir()
    monkeypatch.setattr(windows_module, "_SCRIPTS_DIR", missing)
    sandbox = _Exposed()
    sandbox.stage_into(monitor)
    assert not missing.exists()

    with capture_logs() as captured, pytest.raises(SandboxError) as excinfo:
        await sandbox.stage_monitor_scripts()

    assert str(excinfo.value) == "Sandbox monitor scripts directory not found"
    assert [entry.get("scripts_dir") for entry in _events(captured, "monitor_scripts_dir_not_found")] == [str(missing)]
    assert list(monitor.iterdir()) == []


@pytest.mark.asyncio
async def test_staging_the_monitor_scripts_copies_only_powershell_and_command_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Of a scripts directory's entries only the files ending in ``.ps1`` or ``.cmd`` (any case) are copied.

    A text file and a directory whose name ends in ``.cmd`` are left behind; the three inline monitors the
    backend writes itself are staged as well.

    Args:
        tmp_path: Pytest scratch directory.
        monkeypatch: Points the bundled scripts location at a directory the test fills.
    """
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "a.ps1").write_text("script a", encoding="ascii")
    (scripts / "B.CMD").write_text("script b", encoding="ascii")
    (scripts / "notes.txt").write_text("not a script", encoding="ascii")
    (scripts / "folder.cmd").mkdir()
    monitor = tmp_path / "monitor"
    monitor.mkdir()
    monkeypatch.setattr(windows_module, "_SCRIPTS_DIR", scripts)
    sandbox = _Exposed()
    sandbox.stage_into(monitor)

    with capture_logs() as captured:
        await sandbox.stage_monitor_scripts()

    assert sorted(path.name for path in monitor.iterdir()) == [
        "B.CMD",
        "a.ps1",
        "file_monitor.ps1",
        "network_monitor.ps1",
        "process_monitor.ps1",
    ]
    assert (monitor / "a.ps1").read_text(encoding="ascii") == "script a"
    assert (monitor / "B.CMD").read_text(encoding="ascii") == "script b"
    created = _events(captured, "monitoring_scripts_created")
    assert [sorted(entry["copied"]) for entry in created] == [["B.CMD", "a.ps1"]]


@pytest.mark.slow
@pytest.mark.asyncio
async def test_anti_evasion_lists_only_the_guest_steps_that_exit_zero(tmp_path: Path) -> None:
    """After a successful MOF compile and verification each later guest step is listed only if it exits 0.

    The guest ``mofcomp.exe`` is a copy of ``cmd.exe``, which exits 0 with its stdin at end of file. The guest
    ``powershell`` answers the identity query from the staged MOF and exits 1, then 0, for the other steps.

    Args:
        tmp_path: Pytest scratch directory.
    """
    root = tmp_path / "guest"
    root.mkdir()
    with _guest(root) as guest:
        _assert_guest_path_is_confined(guest)

        _write_guest_powershell(guest, other_exit_code=1)
        failing = await guest.sandbox.apply_anti_evasion("default")
        for stale in (guest.share / "input").glob("intellicrack_antievasion_*.mof"):
            stale.unlink()
        _write_guest_powershell(guest, other_exit_code=0)
        passing = await guest.sandbox.apply_anti_evasion("default")

    assert failing["wmi_hijack"]["status"] == "verified"
    assert failing["techniques"] == _WMI_TECHNIQUES
    assert failing["count"] == len(_WMI_TECHNIQUES)
    assert passing["wmi_hijack"]["status"] == "verified"
    assert passing["techniques"] == [*_WMI_TECHNIQUES, *_GUEST_STEP_TECHNIQUES]
    assert passing["count"] == len(_WMI_TECHNIQUES) + len(_GUEST_STEP_TECHNIQUES)


@pytest.mark.asyncio
async def test_a_procdump_that_exits_zero_beside_a_dump_file_is_reported_as_a_dump(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the in-process dump fails and procdump exits 0 with the dump file in place, the result is True.

    ``procdump64.exe`` is a copy of ``tree.com``, which exits 0 for any arguments. It cannot write a dump, so
    the dump file is put in place by the test, as a real procdump would leave it.

    Args:
        tmp_path: Pytest scratch directory.
        monkeypatch: Used to put the stand-in procdump first on ``PATH``.
    """
    bin_dir = tmp_path / "fake_bin"
    bin_dir.mkdir()
    standin = _install_standin(bin_dir, "tree.com", "procdump64.exe")
    _prepend_path(monkeypatch, bin_dir)
    _assert_found_first("procdump64.exe", standin)
    dump = tmp_path / "existing.dmp"
    dump.write_bytes(_DUMP_BYTES)
    exit_code, _ = _standin_run(standin, ("-accepteula", "-ma", str(_NONEXISTENT_PID), str(dump)))
    assert exit_code == 0

    with capture_logs() as captured:
        produced = await _Exposed().dump_with_procdump(_NONEXISTENT_PID, dump)

    assert produced is True
    assert dump.read_bytes() == _DUMP_BYTES
    assert [entry.get("pid") for entry in _events(captured, "minidump_via_dbghelp_failed_trying_procdump")] == [_NONEXISTENT_PID]
    assert _events(captured, "procdump_failed") == []
    assert _events(captured, "procdump_not_found") == []


@pytest.mark.slow
def test_a_powershell_that_outlives_the_lookup_timeout_does_not_crash_the_session_lookup(tmp_path: Path) -> None:
    """A PowerShell that never finishes ends the lookup with no session instead of raising.

    The lookup runs in a child interpreter whose stdin pipe the test holds open, so a ``pwsh`` that is a copy of
    ``cmd.exe`` waits on it past the lookup's 30-second limit. The child tries twice and reports each outcome.
    A lookup that lets the timeout escape reports the exception class instead of ``None``.

    Args:
        tmp_path: Pytest scratch directory.
    """
    _install_standin(tmp_path, "cmd.exe", "pwsh.exe")
    source_root = Path(windows_module.__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PATH"] = f"{tmp_path}{os.pathsep}{environment['PATH']}"
    environment["PYTHONPATH"] = str(source_root) + os.pathsep + environment.get("PYTHONPATH", "")
    out_path = tmp_path / "child.out"
    err_path = tmp_path / "child.err"
    with out_path.open("wb") as out_file, err_path.open("wb") as err_file:
        child = Popen([sys.executable, "-c", _ESCAPE_CODE], stdin=PIPE, stdout=out_file, stderr=err_file, env=environment)
        try:
            child.wait(timeout=_ESCAPE_BUDGET_S)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            if child.stdin is not None:
                child.stdin.close()

    printed = out_path.read_bytes().decode("utf-8", errors="replace").strip().splitlines()
    assert printed, err_path.read_bytes().decode("utf-8", errors="replace")
    assert json.loads(printed[-1]) == [{"returned": None}, {"returned": None}]
