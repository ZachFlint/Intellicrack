# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Fourth-pass coverage tests for ``CutterBridge`` helpers and debug listings.

The module-level helpers ``_json_dicts``, ``_mapped_images`` and
``_require_openable_target`` are called directly with real values and checked
against independent expectations: the ``psutil`` view of a spawned child, the
exceptions the operating system raises for a locked file, and the bytes that
``ReadProcessMemory`` returns for the same debuggee. The debug tests drive a
real rizin 0.9.1 session and a real radare2 session that have started
``where.exe`` under their debuggers. The expectations on the radare2 session
come from measurements in the container: ``dbj`` and ``dptj`` print arrays,
``dmIj`` prints nothing, and ``p8`` prints ``ffffffff`` for address zero and
nothing for a one-tebibyte read.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

import psutil
import pytest
import pytest_asyncio

from intellicrack.bridges import cutter as cutter_mod
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.win32_types import PROCESS_VM_READ
from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.types import ModuleInfo, ToolError


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable, Iterator


pytestmark = pytest.mark.spawns_process

_SYSTEM32: Final[Path] = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
_WHERE_EXE: Final[Path] = _SYSTEM32 / "where.exe"
_TASKKILL: Final[Path] = _SYSTEM32 / "taskkill.exe"
_IDLE_CHILD: Final[str] = "import sys\nprint('ready', flush=True)\nsys.stdin.read()\n"
_GENERIC_READ: Final[int] = 0x80000000
_OPEN_EXISTING: Final[int] = 3
_FILE_ATTRIBUTE_NORMAL: Final[int] = 0x80
_ONE_TEBIBYTE: Final[int] = 1 << 40
_SPAN: Final[int] = 0x2000

_json_dicts: Callable[[object], list[dict[str, Any]]] = cast(
    "Callable[[object], list[dict[str, Any]]]",
    getattr(cutter_mod, "_json_dicts"),
)
_mapped_images: Callable[[int, list[tuple[int, int]]], list[ModuleInfo]] = cast(
    "Callable[[int, list[tuple[int, int]]], list[ModuleInfo]]",
    getattr(cutter_mod, "_mapped_images"),
)
_require_openable_target: Callable[..., None] = cast(
    "Callable[..., None]",
    getattr(cutter_mod, "_require_openable_target"),
)


def _radare2_directory() -> Path:
    """Return the directory that holds the real radare2 executable.

    Returns:
        Path: Resolved directory that contains ``radare2``.
    """
    home = os.environ.get("RADARE2_HOME")
    if home:
        return (Path(home) / "bin").resolve()
    located = shutil.which("radare2")
    assert located is not None, "radare2 is not on PATH and RADARE2_HOME is not set"
    return Path(located).resolve().parent


def _backend_process(bridge: CutterBridge) -> subprocess.Popen[bytes]:
    """Return the ``Popen`` handle of the backend child behind ``bridge``.

    Args:
        bridge: Bridge with a loaded binary.

    Returns:
        subprocess.Popen[bytes]: The rizin or radare2 child process.
    """
    return cast("subprocess.Popen[bytes]", getattr(bridge.r2, "process"))


def _file_digests(path: Path) -> tuple[str, str]:
    """Hash a file with the standard library.

    Args:
        path: File on disk.

    Returns:
        tuple[str, str]: Lowercase hex MD5 and SHA-256 digests of the content.
    """
    content = path.read_bytes()
    return hashlib.md5(content, usedforsecurity=False).hexdigest(), hashlib.sha256(content).hexdigest()


def _terminate(pid: int) -> None:
    """Force-terminate a process.

    Args:
        pid: Process to terminate.
    """
    subprocess.run([str(_TASKKILL), "/F", "/PID", str(pid)], capture_output=True, check=False, timeout=30)


def _read_remote(pid: int, address: int, size: int) -> bytes | None:
    """Read bytes from another process with ``ReadProcessMemory``.

    Args:
        pid: Process whose memory is read.
        address: Address in that process.
        size: Number of bytes to read.

    Returns:
        bytes | None: The bytes the operating system returned, or ``None`` when the read fails.
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
        buffer = ctypes.create_string_buffer(size)
        done = ctypes.c_size_t(0)
        succeeded = bool(read_process_memory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(done)))
        return buffer.raw[: done.value] if succeeded else None
    finally:
        close_handle(handle)


async def _start_debuggee(bridge: CutterBridge) -> int:
    """Start ``where.exe`` under the backend's debugger and attach the bridge to it.

    Args:
        bridge: Bridge with no binary loaded.

    Returns:
        int: Process id that the backend reported for the debuggee.
    """
    await bridge.load_binary(_WHERE_EXE, debug=True)
    listing = cast("list[dict[str, Any]]", json.loads(await bridge.r2_cmd("dpj")))
    pid = int(listing[0]["pid"])
    await bridge.attach(pid)
    return pid


async def _program_counter(bridge: CutterBridge) -> int:
    """Return the instruction pointer that the backend reports for the debuggee.

    Args:
        bridge: Bridge attached to a debuggee.

    Returns:
        int: Value of ``rip`` from ``drj``.
    """
    registers = cast("dict[str, Any]", json.loads(await bridge.r2_cmd("drj")))
    return int(registers["rip"])


@pytest_asyncio.fixture
async def rizin_debug() -> AsyncIterator[tuple[CutterBridge, int]]:
    """Attach a bridge to ``where.exe`` stopped under rizin's debugger.

    Yields:
        tuple[CutterBridge, int]: Attached bridge and the pid of the debuggee.
    """
    bridge = CutterBridge()
    pid = 0
    try:
        pid = await _start_debuggee(bridge)
        yield bridge, pid
    finally:
        await bridge.shutdown()
        if pid:
            _terminate(pid)


@pytest_asyncio.fixture
async def radare2_debug(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[tuple[CutterBridge, int]]:
    """Attach a bridge to ``where.exe`` stopped under radare2's debugger.

    ``PATH`` is restricted to the radare2 install directory so the bridge
    selects its radare2 backend.

    Args:
        monkeypatch: Fixture used to restrict ``PATH``.

    Yields:
        tuple[CutterBridge, int]: Attached bridge and the pid of the debuggee.
    """
    monkeypatch.setenv("PATH", str(_radare2_directory()))
    bridge = CutterBridge()
    pid = 0
    try:
        pid = await _start_debuggee(bridge)
        yield bridge, pid
    finally:
        await bridge.shutdown()
        if pid:
            _terminate(pid)


@pytest.fixture
def idle_child() -> Iterator[subprocess.Popen[str]]:
    """Start a python child that has printed a ready marker and blocks on stdin.

    Yields:
        subprocess.Popen[str]: The running child.
    """
    child = subprocess.Popen(
        [sys.executable, "-c", _IDLE_CHILD],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "ready"
        yield child
    finally:
        child.kill()
        child.communicate(timeout=60)


@pytest.fixture
def locked_file(tmp_path: Path) -> Iterator[Path]:
    """Create a file that another handle holds open with share mode zero.

    Args:
        tmp_path: Directory that receives the file.

    Yields:
        Path: The locked file; opening it for reading fails while the fixture is active.
    """
    target = tmp_path / "locked.bin"
    target.write_bytes(b"MZ\x90\x00")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = cast("int | None", kernel32.CreateFileW(str(target), _GENERIC_READ, 0, None, _OPEN_EXISTING, _FILE_ATTRIBUTE_NORMAL, None))
    assert handle not in {None, ctypes.c_void_p(-1).value}
    try:
        yield target
    finally:
        kernel32.CloseHandle(handle)


class TestJsonDicts:
    """``_json_dicts`` keeps the objects of a parsed JSON array."""

    @pytest.mark.parametrize("value", [None, 5, "text", {"key": 1}])
    def test_non_array_values_give_an_empty_list(self, value: object) -> None:
        """A value that is not an array has no objects to keep.

        Args:
            value: A parsed JSON value that is not a list.
        """
        assert _json_dicts(value) == []

    def test_only_objects_of_an_array_are_kept_in_order(self) -> None:
        """Numbers, strings, nulls and nested arrays are dropped; objects keep their order."""
        value: list[object] = [{"a": 1}, 3, "x", None, [{"hidden": 1}], {"b": 2}]
        assert _json_dicts(value) == [{"a": 1}, {"b": 2}]


class TestMappedImages:
    """``_mapped_images`` names image regions by the files the system maps there."""

    def test_regions_of_one_file_merge_and_images_are_ordered_by_base(self, idle_child: subprocess.Popen[str]) -> None:
        """Two ranges inside the interpreter executable merge; a third inside ntdll stays separate.

        Ranges are built from the region addresses ``psutil`` lists for the
        child, the oracle for which file is mapped where.

        Args:
            idle_child: Running python child.
        """
        regions = psutil.Process(idle_child.pid).memory_maps(grouped=False)
        executable = Path(sys.executable).name.lower()
        exe_regions = sorted((int(region.addr, 16), region.path) for region in regions if region.path.lower().endswith("\\" + executable))
        ntdll_regions = sorted((int(region.addr, 16), region.path) for region in regions if region.path.lower().endswith("\\ntdll.dll"))
        assert len(exe_regions) >= 2
        assert ntdll_regions
        first, exe_path = exe_regions[0]
        second = exe_regions[1][0]
        ntdll_start, ntdll_path = ntdll_regions[0]
        images = _mapped_images(idle_child.pid, [(ntdll_start, ntdll_start + 1), (second, second + 1), (first, first + 1)])
        assert {image.name: (image.path, image.base_address, image.size) for image in images} == {
            Path(exe_path).name: (Path(exe_path), first, second + 1 - first),
            Path(ntdll_path).name: (Path(ntdll_path), ntdll_start, 1),
        }
        assert [image.base_address for image in images] == sorted(image.base_address for image in images)
        assert all(image.entry_point == 0 for image in images)

    def test_process_that_has_exited_has_no_images(self) -> None:
        """The system cannot report mappings of a process that no longer exists."""
        finished = subprocess.Popen([sys.executable, "-c", "pass"])
        finished.wait(timeout=60)
        assert _mapped_images(finished.pid, [(0, 1)]) == []


class TestRequireOpenableTarget:
    """``_require_openable_target`` rejects what the backend would hang on."""

    def test_directory_is_not_a_regular_file(self, tmp_path: Path) -> None:
        """A directory is rejected in both modes with the not-a-regular-file reason.

        Args:
            tmp_path: Directory used as the target.
        """
        for debug in (False, True):
            with pytest.raises(ToolError) as excinfo:
                _require_openable_target(tmp_path, debug=debug)
            assert str(excinfo.value) == "failed to load binary"
            assert excinfo.value.details == {"reason": "target is not a regular file"}

    def test_locked_file_cannot_be_read(self, locked_file: Path) -> None:
        """A file held open without sharing fails to open, and the reason names the operating-system error.

        Args:
            locked_file: File held by another handle with share mode zero.
        """
        with pytest.raises(PermissionError) as os_error:
            locked_file.open("rb").close()
        with pytest.raises(ToolError) as excinfo:
            _require_openable_target(locked_file, debug=False)
        assert excinfo.value.details == {"reason": f"target cannot be read: {os_error.value}"}
        assert excinfo.value.__cause__ is not None
        assert isinstance(excinfo.value.__cause__, PermissionError)

    def test_text_file_is_refused_only_when_launched_under_the_debugger(self, tmp_path: Path) -> None:
        """A file without an executable signature opens for analysis but cannot be launched.

        Args:
            tmp_path: Directory that receives the text file.
        """
        text = tmp_path / "plain.txt"
        text.write_text("plain text\n", encoding="utf-8")
        _require_openable_target(text, debug=False)
        with pytest.raises(ToolError) as excinfo:
            _require_openable_target(text, debug=True)
        assert excinfo.value.details == {"reason": "target is not an executable image"}

    @pytest.mark.parametrize("header", [b"MZ\x90\x00", b"\x7fELF", b"#!/b"])
    def test_executable_signatures_are_accepted_for_launch(self, tmp_path: Path, header: bytes) -> None:
        """The PE, ELF and script signatures pass the debug-launch check.

        Args:
            tmp_path: Directory that receives the file.
            header: First four bytes of the file.
        """
        target = tmp_path / "image.bin"
        target.write_bytes(header + b"\x00" * 60)
        _require_openable_target(target, debug=True)


class TestSessionClose:
    """Closing a session whose process id was never recorded."""

    @pytest.mark.asyncio
    async def test_close_existing_session_resets_state_without_a_recorded_pid(self, real_pe_dll: Path) -> None:
        """The session closes, the backend exits and the debug state resets although no pid is recorded.

        Args:
            real_pe_dll: DLL loaded into the bridge.
        """
        bridge = CutterBridge()
        registered = 0
        try:
            await bridge.load_binary(real_pe_dll)
            process = _backend_process(bridge)
            registered = cast("int", getattr(bridge, "_r2_pid"))
            assert registered == process.pid
            setattr(bridge, "_r2_pid", None)
            setattr(bridge, "_debug_mode", True)
            bridge.state.process_attached = True
            close = cast("Callable[[], Awaitable[None]]", getattr(bridge, "_close_existing_r2"))
            await close()
            assert bridge.r2 is None
            assert getattr(bridge, "_debug_mode") is False
            assert getattr(bridge, "_attached_pid") is None
            assert bridge.state.process_attached is False
            assert bridge.state.target_pid is None
            process.wait(timeout=60)
            assert process.poll() is not None
        finally:
            if registered:
                ProcessManager.get_instance().unregister_external_pid(registered)
            await bridge.shutdown()


class TestHashes:
    """Hashes reported for a statically loaded DLL."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("backend", ["rizin", "radare2"])
    async def test_hashes_are_true_digests_of_the_file(self, backend: str, monkeypatch: pytest.MonkeyPatch, real_pe_dll: Path) -> None:
        """The loaded SHA-256 is the file's digest.

        Args:
            backend: Which backend the bridge must use.
            monkeypatch: Fixture used to restrict ``PATH`` for radare2.
            real_pe_dll: DLL loaded into the bridge.
        """
        if backend == "radare2":
            monkeypatch.setenv("PATH", str(_radare2_directory()))
        _, true_sha256 = _file_digests(real_pe_dll)
        bridge = CutterBridge()
        try:
            info = await bridge.load_binary(real_pe_dll)
        finally:
            await bridge.shutdown()
        assert info.sha256 == true_sha256


class TestRizinDebugListings:
    """Readability checks and breakpoint listings against ``where.exe`` stopped under rizin."""

    @pytest.mark.asyncio
    async def test_read_memory_returns_the_bytes_the_system_reports(self, rizin_debug: tuple[CutterBridge, int]) -> None:
        """Reads inside the executable mapping return the bytes ``ReadProcessMemory`` returns.

        Args:
            rizin_debug: Bridge attached to the debuggee, and its pid.
        """
        bridge, pid = rizin_debug
        pc = await _program_counter(bridge)
        expected_short = _read_remote(pid, pc, 16)
        expected_span = _read_remote(pid, pc, _SPAN)
        assert expected_short is not None
        assert expected_span is not None
        assert await bridge.read_memory(pc, 16) == expected_short
        assert await bridge.read_memory(pc, _SPAN) == expected_span

    @pytest.mark.asyncio
    async def test_read_memory_past_the_end_of_the_mappings_is_refused(self, rizin_debug: tuple[CutterBridge, int]) -> None:
        """A range of one tebibyte starting at the program counter is not covered by readable pages.

        Args:
            rizin_debug: Bridge attached to the debuggee, and its pid.
        """
        bridge, _pid = rizin_debug
        pc = await _program_counter(bridge)
        with pytest.raises(ToolError, match="no readable memory"):
            await bridge.read_memory(pc, _ONE_TEBIBYTE)

    @pytest.mark.asyncio
    async def test_breakpoint_set_outside_the_bridge_has_no_condition(self, rizin_debug: tuple[CutterBridge, int]) -> None:
        """A breakpoint added with rizin's own ``db`` has no condition, so the listing reports ``None``.

        The bridge reports ``None`` for a breakpoint it set without a condition;
        rizin lists ``"cond":""`` for the same breakpoint, and the listing
        returns that empty string.

        Args:
            rizin_debug: Bridge attached to the debuggee, and its pid.
        """
        bridge, _pid = rizin_debug
        pc = await _program_counter(bridge)
        await bridge.r2_cmd(f"db @ {pc}")
        listed = [entry for entry in await bridge.get_breakpoints() if entry.address == pc]
        assert len(listed) == 1
        assert listed[0].bp_type == "software"
        assert listed[0].enabled is True
        assert listed[0].condition is None


class TestRadare2DebugSession:
    """Dynamic-analysis calls against ``where.exe`` stopped under radare2's debugger."""

    @pytest.mark.asyncio
    async def test_read_memory_of_a_one_tebibyte_range_does_not_invent_bytes(self, radare2_debug: tuple[CutterBridge, int]) -> None:
        """A read far larger than any mapping returns no bytes or raises.

        Args:
            radare2_debug: Bridge attached to the debuggee, and its pid.
        """
        bridge, _pid = radare2_debug
        pc = await _program_counter(bridge)
        outcome: bytes | ToolError
        try:
            outcome = await bridge.read_memory(pc, _ONE_TEBIBYTE)
        except ToolError as exc:
            outcome = exc
        assert isinstance(outcome, ToolError) or outcome == b""

    @pytest.mark.asyncio
    async def test_read_memory_of_unmapped_address_does_not_invent_bytes(self, radare2_debug: tuple[CutterBridge, int]) -> None:
        """Address zero is not readable, so the read returns no bytes or raises.

        Measured: radare2's ``p8 4 @ 0`` prints ``ffffffff`` and the bridge
        returns those four bytes, as it did for rizin before PD-092 was fixed.

        Args:
            radare2_debug: Bridge attached to the debuggee, and its pid.
        """
        bridge, pid = radare2_debug
        assert _read_remote(pid, 0, 4) is None
        outcome: bytes | ToolError
        try:
            outcome = await bridge.read_memory(0, 4)
        except ToolError as exc:
            outcome = exc
        assert isinstance(outcome, ToolError) or outcome == b""

    @pytest.mark.asyncio
    async def test_get_modules_lists_ntdll(self, radare2_debug: tuple[CutterBridge, int]) -> None:
        """Every Windows process has ``ntdll.dll`` mapped, so the module listing names it.

        Measured: radare2's ``dmIj`` prints nothing for the debuggee, and the
        bridge returns an empty list.

        Args:
            radare2_debug: Bridge attached to the debuggee, and its pid.
        """
        bridge, _pid = radare2_debug
        modules = await bridge.get_modules()
        names = {module.name.lower() for module in modules} | {module.path.name.lower() for module in modules}
        assert "ntdll.dll" in names
