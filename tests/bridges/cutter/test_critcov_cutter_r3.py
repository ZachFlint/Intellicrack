# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Third-pass coverage tests for ``CutterBridge`` built on measured rizin 0.9.1 behavior.

Static tests load ``where.exe`` through a real rizin session and compare the bridge
with the ``pefile`` entry point, the SHA-256 of a byte-identical copy, and the
program counter that a second rizin command reports. Debug tests let rizin start
``where.exe`` under its debugger (``rizin -d``), attach the bridge to the
reported pid, and compare against the registers that rizin reports itself and
against ``ReadProcessMemory`` on the same process. Several tests come from
defects measured in the container: rizin 0.9.1 has no ``dbj`` and no ``dr?PC``
command, the thread and module listings come back empty for a live process, an
unmapped address reads as ``0xff`` bytes, and loading a directory, a locked file
or a non-executable in debug mode never returns. Rizin's ``db`` takes its address
through ``@``; ``db <address>`` adds no breakpoint. The first steps of a process
that rizin has just started consume its startup debug events, so the step tests
step past them before they compare program counters.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

import pefile
import pytest
import pytest_asyncio

from intellicrack.bridges import cutter as cutter_mod
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.win32_types import PROCESS_VM_READ
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


pytestmark = pytest.mark.spawns_process

_SRC_DIR: Final[Path] = Path(cutter_mod.__file__).resolve().parents[2]
_SYSTEM32: Final[Path] = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
_WHERE_EXE: Final[Path] = _SYSTEM32 / "where.exe"
_TASKKILL: Final[Path] = _SYSTEM32 / "taskkill.exe"
_MARKER: Final[str] = "CHILD_JSON "
_LOAD_DEADLINE_SECONDS: Final[float] = 25.0
_STARTUP_STEP_LIMIT: Final[int] = 16

_LOAD_CHILD: Final[str] = """\
import asyncio, ctypes, json, os, shutil, sys
from pathlib import Path
from intellicrack.bridges.cutter import CutterBridge

variant = sys.argv[1]
work = Path(sys.argv[2])
source = Path(sys.argv[3])
debug = False
handle = None
kernel32 = None
if variant == "dir":
    target = work / "adir"
    target.mkdir()
elif variant == "locked":
    target = work / "locked.exe"
    shutil.copyfile(source, target)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    ]
    handle = kernel32.CreateFileW(str(target), 0x80000000, 0, None, 3, 0x80, None)
else:
    target = work / "plain.txt"
    target.write_text("plain text\\n")
    debug = True


async def main():
    bridge = CutterBridge()
    try:
        await bridge.load_binary(target, debug=debug)
        return "loaded"
    except Exception as exc:
        return type(exc).__name__
    finally:
        await bridge.shutdown()


outcome = asyncio.run(main())
print("CHILD_JSON " + json.dumps({"outcome": outcome}), flush=True)
os._exit(0)
"""


def _entry_point(path: Path) -> int:
    """Return the virtual address of the entry point of a PE file.

    Args:
        path: PE file on disk.

    Returns:
        int: Image base plus the address-of-entry-point field of the optional header.
    """
    pe = pefile.PE(str(path), fast_load=True)
    try:
        return int(pe.OPTIONAL_HEADER.ImageBase) + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    finally:
        pe.close()


def _sha256(path: Path) -> str:
    """Return the SHA-256 digest of a file.

    Args:
        path: File on disk.

    Returns:
        str: Lowercase hex digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def _register_json(bridge: CutterBridge) -> dict[str, Any]:
    """Read the debuggee registers straight from rizin's ``drj`` command.

    Args:
        bridge: Bridge attached to a debuggee.

    Returns:
        dict[str, Any]: Register name to integer value.
    """
    return cast("dict[str, Any]", json.loads(await bridge.r2_cmd("drj")))


async def _rip(bridge: CutterBridge) -> int:
    """Return the instruction pointer that rizin reports for the debuggee.

    Args:
        bridge: Bridge attached to a debuggee.

    Returns:
        int: Value of ``rip``.
    """
    return int((await _register_json(bridge))["rip"])


async def _step_past_process_startup(bridge: CutterBridge) -> int:
    """Step with rizin's ``ds`` until one step executes exactly one instruction.

    Measured in the container with rizin 0.9.1: a process that rizin has just
    started is stopped on its first debug event, and the next ``ds`` commands
    consume the startup events. The first leaves the instruction pointer where
    it was, the second runs to the loader's breakpoint, and from the fifth on
    each one advances by the length of the instruction it started on.

    Args:
        bridge: Bridge attached to a freshly started debuggee.

    Returns:
        int: Instruction pointer after the first step that advanced by one instruction.

    Raises:
        AssertionError: When no step advances by one instruction within the limit.
    """
    for _ in range(_STARTUP_STEP_LIMIT):
        before = await _rip(bridge)
        decoded = cast("list[dict[str, Any]]", json.loads(await bridge.r2_cmd(f"pdj 1 @ {before}")))
        await bridge.r2_cmd("ds")
        after = await _rip(bridge)
        if after == before + int(decoded[0]["size"]):
            return after
    msg = f"no step advanced by one instruction within {_STARTUP_STEP_LIMIT} steps"
    raise AssertionError(msg)


async def _esil_pc(bridge: CutterBridge) -> int:
    """Read the ESIL program counter through ``ar rip``.

    Args:
        bridge: Bridge whose ESIL state has been initialized.

    Returns:
        int: Program counter parsed from the ``rip = 0x...`` line.
    """
    text = await bridge.r2_cmd("ar rip")
    match = re.search(r"0x[0-9a-fA-F]+", text)
    assert match is not None, text
    return int(match.group(), 16)


async def _prime_esil(bridge: CutterBridge, entry: int) -> None:
    """Initialize the ESIL machine and put its program counter at ``entry``.

    Args:
        bridge: Analyzed bridge.
        entry: Address of the first instruction to emulate.
    """
    assert await bridge.esil_init_state() is True
    assert await bridge.esil_init_memory() is True
    assert await bridge.esil_set_pc(entry) is True


def _can_read(pid: int, address: int) -> bool:
    """Ask the operating system whether one process can read four bytes of another.

    Args:
        pid: Process whose memory is read.
        address: Address in that process.

    Returns:
        bool: ``True`` when ``ReadProcessMemory`` succeeds.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.restype = wintypes.HANDLE
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    read_process_memory = kernel32.ReadProcessMemory
    read_process_memory.restype = wintypes.BOOL
    read_process_memory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    close_handle = kernel32.CloseHandle
    close_handle.restype = wintypes.BOOL
    close_handle.argtypes = [wintypes.HANDLE]
    handle = open_process(PROCESS_VM_READ, 0, pid)
    assert handle
    try:
        buffer = ctypes.create_string_buffer(4)
        done = ctypes.c_size_t(0)
        return bool(read_process_memory(handle, ctypes.c_void_p(address), buffer, 4, ctypes.byref(done)))
    finally:
        close_handle(handle)


def _terminate(pid: int, *, tree: bool) -> None:
    """Force-terminate a process, and optionally every process it started.

    Args:
        pid: Process to terminate.
        tree: Also terminate the process's descendants when ``True``.
    """
    command = [str(_TASKKILL), "/F", *(["/T"] if tree else []), "/PID", str(pid)]
    subprocess.run(command, capture_output=True, check=False, timeout=30)


def _marker_outcome(output: str) -> str:
    """Extract the outcome that a load child printed.

    Args:
        output: Combined output of the child.

    Returns:
        str: The reported outcome, or ``"no result"`` when the child printed none.
    """
    for line in output.splitlines():
        if line.startswith(_MARKER):
            return str(json.loads(line[len(_MARKER) :])["outcome"])
    return "no result"


def _load_outcomes(work: Path) -> dict[str, str]:
    """Run ``load_binary`` for three unopenable targets in separate children.

    A child that has not finished within the deadline is killed together with
    every process it started, and reported as ``"timeout"``.

    Args:
        work: Scratch directory.

    Returns:
        dict[str, str]: Variant name to the exception class name the load raised,
        ``"loaded"``, ``"timeout"`` or ``"no result"``.
    """
    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(_SRC_DIR) if not existing else str(_SRC_DIR) + os.pathsep + existing
    env["PYTHONIOENCODING"] = "utf-8"
    children: dict[str, subprocess.Popen[str]] = {}
    outcomes: dict[str, str] = {}
    try:
        for variant in ("dir", "locked", "debug_text"):
            directory = work / variant
            directory.mkdir()
            children[variant] = subprocess.Popen(
                [sys.executable, "-c", _LOAD_CHILD, variant, str(directory), str(_WHERE_EXE)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        deadline = time.monotonic() + _LOAD_DEADLINE_SECONDS
        for variant, child in children.items():
            try:
                output, _ = child.communicate(timeout=max(deadline - time.monotonic(), 1.0))
            except subprocess.TimeoutExpired:
                outcomes[variant] = "timeout"
                continue
            outcomes[variant] = _marker_outcome(output)
    finally:
        for child in children.values():
            if child.poll() is None:
                _terminate(child.pid, tree=True)
            child.communicate(timeout=60)
    return outcomes


@pytest_asyncio.fixture
async def where_bridge() -> AsyncIterator[CutterBridge]:
    """Load ``where.exe`` into a real bridge and run the quick analysis.

    Yields:
        CutterBridge: Bridge with the executable loaded and analyzed.
    """
    bridge = CutterBridge()
    try:
        await bridge.load_binary(_WHERE_EXE)
        await bridge.analyze("quick")
        yield bridge
    finally:
        await bridge.shutdown()


@pytest_asyncio.fixture
async def debug_session() -> AsyncIterator[tuple[CutterBridge, int]]:
    """Start ``where.exe`` under rizin's debugger and attach the bridge to it.

    The pid comes from rizin's own ``dpj`` listing. The debuggee is terminated
    by pid after the session is closed.

    Yields:
        tuple[CutterBridge, int]: Attached bridge and the pid of the debuggee.
    """
    bridge = CutterBridge()
    pid = 0
    try:
        await bridge.load_binary(_WHERE_EXE, debug=True)
        listing = cast("list[dict[str, Any]]", json.loads(await bridge.r2_cmd("dpj")))
        pid = int(listing[0]["pid"])
        await bridge.attach(pid)
        yield bridge, pid
    finally:
        await bridge.shutdown()
        if pid:
            _terminate(pid, tree=False)


class TestFlagAndComparison:
    """Flag resolution and file comparison on a statically loaded executable."""

    @pytest.mark.asyncio
    async def test_resolve_flag_is_none_when_no_flag_precedes_the_address(self, where_bridge: CutterBridge) -> None:
        """Address zero has no flag before it, while the entry point is flagged ``entry0``.

        Args:
            where_bridge: Analyzed bridge for ``where.exe``.
        """
        entry = _entry_point(_WHERE_EXE)
        assert await where_bridge.resolve_flag(entry) == "entry0"
        assert await where_bridge.resolve_flag(0) is None

    @pytest.mark.asyncio
    async def test_compare_disassembly_of_identical_file_is_empty(self, where_bridge: CutterBridge, tmp_path: Path) -> None:
        """Comparing the executable with a byte-identical copy reports no difference.

        Args:
            where_bridge: Analyzed bridge for ``where.exe``.
            tmp_path: Directory that receives the copy.
        """
        duplicate = tmp_path / "where_copy.exe"
        shutil.copyfile(_WHERE_EXE, duplicate)
        assert _sha256(duplicate) == _sha256(_WHERE_EXE)
        entry = _entry_point(_WHERE_EXE)
        difference = await where_bridge.compare_disassembly(str(duplicate), entry)
        assert not difference


class TestEsilStepping:
    """Emulated stepping from the entry point of ``where.exe``."""

    @pytest.mark.asyncio
    async def test_one_esil_step_advances_by_the_instruction_length(self, where_bridge: CutterBridge) -> None:
        """One step moves the program counter past the first instruction.

        Args:
            where_bridge: Analyzed bridge for ``where.exe``.
        """
        entry = _entry_point(_WHERE_EXE)
        decoded = cast("list[dict[str, Any]]", json.loads(await where_bridge.r2_cmd(f"pdj 1 @ {entry}")))
        length = int(decoded[0]["size"])
        await _prime_esil(where_bridge, entry)
        assert await _esil_pc(where_bridge) == entry
        await where_bridge.esil_step(1)
        assert await _esil_pc(where_bridge) == entry + length

    @pytest.mark.asyncio
    async def test_esil_step_count_equals_repeated_single_steps(self, where_bridge: CutterBridge) -> None:
        """Stepping twice in one call ends where two calls of one step end.

        Args:
            where_bridge: Analyzed bridge for ``where.exe``.
        """
        entry = _entry_point(_WHERE_EXE)
        await _prime_esil(where_bridge, entry)
        await where_bridge.esil_step(1)
        after_one = await _esil_pc(where_bridge)
        await where_bridge.esil_step(1)
        after_two = await _esil_pc(where_bridge)
        assert after_two != after_one
        assert await where_bridge.esil_set_pc(entry) is True
        await where_bridge.esil_step(2)
        assert await _esil_pc(where_bridge) == after_two


class TestDebugSession:
    """Dynamic-analysis calls against ``where.exe`` stopped under rizin's debugger."""

    @pytest.mark.asyncio
    async def test_get_breakpoints_reports_the_bridge_breakpoint(self, debug_session: tuple[CutterBridge, int]) -> None:
        """A breakpoint set through the bridge is listed once, with the values it was given.

        Args:
            debug_session: Bridge attached to the debuggee, and its pid.
        """
        bridge, _pid = debug_session
        pc = await _rip(bridge)
        assert await bridge.get_breakpoints() == []
        assert await bridge.set_breakpoint(pc) == pc
        listed = await bridge.get_breakpoints()
        assert len(listed) == 1
        assert listed[0].id == pc
        assert listed[0].address == pc
        assert listed[0].bp_type == "software"
        assert listed[0].enabled is True
        assert listed[0].hit_count == 0
        assert listed[0].condition is None

    @pytest.mark.asyncio
    async def test_get_breakpoints_lists_a_breakpoint_set_outside_the_bridge(self, debug_session: tuple[CutterBridge, int]) -> None:
        """A breakpoint added with rizin's own ``db`` command appears in the listing.

        Rizin 0.9.1 has no ``dbj`` command (it prints ``Command 'dbj' does not
        exist`` and its help for ``db``); its JSON listing is ``dblj``. The
        breakpoint is added as ``db @ <address>`` because ``db <address>`` adds
        nothing, and rizin's own listing is checked before the bridge's.

        Args:
            debug_session: Bridge attached to the debuggee, and its pid.
        """
        bridge, _pid = debug_session
        pc = await _rip(bridge)
        await bridge.r2_cmd(f"db @ {pc}")
        own_listing = cast("list[dict[str, Any]]", json.loads(await bridge.r2_cmd("dblj")))
        assert pc in {int(entry["addr"]) for entry in own_listing}
        assert pc in {entry.address for entry in await bridge.get_breakpoints()}

    @pytest.mark.asyncio
    async def test_step_into_returns_the_new_program_counter(self, debug_session: tuple[CutterBridge, int]) -> None:
        """Stepping into one instruction returns the instruction pointer rizin then reports.

        Rizin 0.9.1 has no ``dr?PC`` command; it prints the program counter for
        ``dr PC``. The debuggee is stepped past its startup events first, since
        a step taken before that does not execute one instruction.

        Args:
            debug_session: Bridge attached to the debuggee, and its pid.
        """
        bridge, _pid = debug_session
        before = await _step_past_process_startup(bridge)
        returned = await bridge.step_into()
        assert returned == await _rip(bridge)
        assert returned != before

    @pytest.mark.asyncio
    async def test_step_over_returns_the_new_program_counter(self, debug_session: tuple[CutterBridge, int]) -> None:
        """Stepping over one instruction returns the instruction pointer rizin then reports.

        The debuggee is stepped past its startup events first, since a step
        taken before that does not execute one instruction.

        Args:
            debug_session: Bridge attached to the debuggee, and its pid.
        """
        bridge, _pid = debug_session
        before = await _step_past_process_startup(bridge)
        returned = await bridge.step_over()
        assert returned == await _rip(bridge)
        assert returned != before

    @pytest.mark.asyncio
    async def test_get_threads_lists_the_debuggee_thread(self, debug_session: tuple[CutterBridge, int]) -> None:
        """A live process has at least one thread, and the listing reports it.

        Args:
            debug_session: Bridge attached to the debuggee, and its pid.
        """
        bridge, _pid = debug_session
        threads = await bridge.get_threads()
        assert len(threads) >= 1
        assert all(thread.tid > 0 for thread in threads)

    @pytest.mark.asyncio
    async def test_get_modules_lists_ntdll(self, debug_session: tuple[CutterBridge, int]) -> None:
        """Every Windows process has ``ntdll.dll`` mapped, so the module listing names it.

        Args:
            debug_session: Bridge attached to the debuggee, and its pid.
        """
        bridge, _pid = debug_session
        modules = await bridge.get_modules()
        names = {module.name.lower() for module in modules} | {module.path.name.lower() for module in modules}
        assert "ntdll.dll" in names

    @pytest.mark.asyncio
    async def test_read_memory_of_unmapped_address_does_not_invent_bytes(self, debug_session: tuple[CutterBridge, int]) -> None:
        """Address zero is not readable, so the read returns no bytes or raises.

        Rizin's ``p8`` prints ``ffffffff`` for it, and the bridge returns those bytes.

        Args:
            debug_session: Bridge attached to the debuggee, and its pid.
        """
        bridge, pid = debug_session
        assert _can_read(pid, 0) is False
        outcome: bytes | ToolError
        try:
            outcome = await bridge.read_memory(0, 4)
        except ToolError as exc:
            outcome = exc
        assert isinstance(outcome, ToolError) or outcome == b""


class TestUnopenableTargets:
    """``load_binary`` for targets that rizin cannot open as a normal binary."""

    def test_load_binary_reports_a_tool_error_instead_of_hanging(self, tmp_path: Path) -> None:
        """A directory, a locked file and a text file in debug mode each end in ``ToolError``.

        Measured in the container: for each of the three, rzpipe never gets the
        prompt from rizin, so ``load_binary`` does not return within 25 seconds.

        Args:
            tmp_path: Scratch directory for the children.
        """
        assert _load_outcomes(tmp_path) == {"dir": "ToolError", "locked": "ToolError", "debug_text": "ToolError"}
