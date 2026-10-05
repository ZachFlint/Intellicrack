# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Second-pass coverage tests for ``CutterBridge`` against real rizin and radare2 sessions.

Every expectation is derived independently of the bridge: the ``pefile`` parse of
the same System32 DLL, the file's own size on disk, the argument vector of the
child process that the pipe library started, and the documented error contract of
the bridge methods. Sessions start real rizin or radare2 children, and every
session is closed in a ``finally`` or fixture teardown. The radare2 fallback is
reached by pointing ``PATH`` at the real radare2 install directory only.
"""

from __future__ import annotations

import multiprocessing
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pefile
import pytest
import pytest_asyncio
import r2pipe

from intellicrack.bridges import cutter as cutter_mod
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    import subprocess
    from collections.abc import AsyncIterator, Awaitable, Callable


_select_pipe_backend: Callable[[], Any] = cast(
    "Callable[[], Any]",
    getattr(cutter_mod, "_select_pipe_backend"),
)
_open_analysis_pipe: Callable[[str, list[str]], object] = cast(
    "Callable[[str, list[str]], object]",
    getattr(cutter_mod, "_open_analysis_pipe"),
)


_PE_PLUS_MAGIC: int = cast("int", getattr(pefile, "OPTIONAL_HEADER_MAGIC_PE_PLUS"))


def _radare2_directory() -> Path:
    """Return the directory that holds the real radare2 executable.

    The directory comes from the ``RADARE2_HOME`` environment variable when it
    is set, and otherwise from the real ``PATH``.

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


def _launched_executable(bridge: CutterBridge) -> Path:
    """Return the executable the pipe library started for ``bridge``.

    Args:
        bridge: Bridge with a loaded binary.

    Returns:
        Path: Resolved path of the first element of the child's argument vector.
    """
    launched = _backend_process(bridge).args
    assert isinstance(launched, list)
    return Path(str(launched[0])).resolve()


def _file_size(path: Path) -> int:
    """Return the size of ``path`` in bytes.

    Args:
        path: File on disk.

    Returns:
        int: Size reported by the file system.
    """
    return path.stat().st_size


def _kill_backend(bridge: CutterBridge) -> subprocess.Popen[bytes]:
    """Kill the backend child of ``bridge`` and wait until it has exited.

    Args:
        bridge: Bridge with a loaded binary.

    Returns:
        subprocess.Popen[bytes]: The exited child process.
    """
    process = _backend_process(bridge)
    process.kill()
    process.wait(timeout=60)
    return process


def _close_backend_pipes(process: subprocess.Popen[bytes]) -> None:
    """Close the parent's ends of the pipes of an exited backend child.

    Args:
        process: Exited child process whose pipes are still open.
    """
    for stream in (process.stdin, process.stdout):
        if stream is not None:
            stream.close()


def _tracked_pids() -> set[int]:
    """Return every PID the process manager currently tracks.

    Returns:
        set[int]: PIDs of tracked subprocesses and registered external PIDs.
    """
    return {entry.pid for entry in ProcessManager.get_instance().get_all_tracked_entries()}


def _pe_facts(path: Path) -> tuple[bool, str]:
    """Read word width and first section name straight from the PE headers.

    Args:
        path: PE file on disk.

    Returns:
        tuple[bool, str]: Whether the optional header is PE32+, and the name of
        the first section.
    """
    pe = pefile.PE(str(path), fast_load=True)
    try:
        is_pe_plus = pe.OPTIONAL_HEADER.Magic == _PE_PLUS_MAGIC
        first_section = pe.sections[0].Name.rstrip(b"\x00").decode("ascii")
    finally:
        pe.close()
    return is_pe_plus, first_section


@pytest_asyncio.fixture
async def loaded_bridge(real_pe_dll: Path) -> AsyncIterator[CutterBridge]:
    """Load the System32 DLL into a real bridge without analyzing it.

    Args:
        real_pe_dll: Path of the DLL to load.

    Yields:
        CutterBridge: Bridge with the binary loaded and ``analyze`` not yet run.
    """
    bridge = CutterBridge()
    try:
        await bridge.load_binary(real_pe_dll)
        yield bridge
    finally:
        await bridge.shutdown()


@pytest_asyncio.fixture
async def analyzed_bridge(loaded_bridge: CutterBridge) -> CutterBridge:
    """Run the quick analysis on the loaded bridge.

    Args:
        loaded_bridge: Bridge with the DLL loaded.

    Returns:
        CutterBridge: The same bridge after ``analyze("quick")``.
    """
    await loaded_bridge.analyze("quick")
    return loaded_bridge


class TestRadare2Fallback:
    """Backend selection and sessions when only radare2 can be found on ``PATH``."""

    def test_select_pipe_backend_falls_back_to_radare2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """With no rizin on ``PATH`` the radare2 pipe and its install directory are chosen.

        Args:
            monkeypatch: Fixture used to restrict ``PATH`` to the radare2 directory.
        """
        directory = _radare2_directory()
        monkeypatch.setenv("PATH", str(directory))
        backend = _select_pipe_backend()
        assert backend is not None
        assert backend.binary == "radare2"
        assert backend.module is r2pipe
        assert backend.install_dir == directory

    @pytest.mark.asyncio
    @pytest.mark.spawns_process
    async def test_bridge_drives_a_real_radare2_session(self, monkeypatch: pytest.MonkeyPatch, real_pe_dll: Path) -> None:
        """A bridge loads a DLL through radare2 started from the install directory.

        Args:
            monkeypatch: Fixture used to restrict ``PATH`` to the radare2 directory.
            real_pe_dll: Path of the DLL to load.
        """
        directory = _radare2_directory()
        monkeypatch.setenv("PATH", str(directory))
        is_pe_plus, first_section = _pe_facts(real_pe_dll)
        bridge = CutterBridge()
        try:
            info = await bridge.load_binary(real_pe_dll)
            assert _launched_executable(bridge) == (directory / "radare2.exe").resolve()
            assert info.name == real_pe_dll.name
            assert info.size == _file_size(real_pe_dll)
            assert info.is_64bit is is_pe_plus
            assert first_section in {section.name for section in info.sections}
        finally:
            await bridge.shutdown()


class TestBackendExit:
    """Bridge behavior when the backend child exits underneath an open session."""

    @pytest.mark.asyncio
    @pytest.mark.spawns_process
    async def test_command_after_backend_exit_reports_command_failure(self, loaded_bridge: CutterBridge) -> None:
        """A command written to a backend that has exited fails with the command-failure error.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
        """
        process = _kill_backend(loaded_bridge)
        try:
            with pytest.raises(ToolError, match=r"command execution failed: \?V") as excinfo:
                await loaded_bridge.r2_cmd("?V")
            assert isinstance(excinfo.value.__cause__, OSError)
        finally:
            await loaded_bridge.shutdown()
            _close_backend_pipes(process)

    @pytest.mark.asyncio
    @pytest.mark.spawns_process
    async def test_reload_replaces_session_whose_backend_has_exited(
        self,
        loaded_bridge: CutterBridge,
        real_pe_dll: Path,
    ) -> None:
        """Loading again replaces a session whose backend can no longer be asked to quit.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            real_pe_dll: Path of the loaded DLL.
        """
        old_pipe = loaded_bridge.r2
        process = _kill_backend(loaded_bridge)
        try:
            info = await loaded_bridge.load_binary(real_pe_dll)
            assert info.name == real_pe_dll.name
            assert loaded_bridge.r2 is not None
            assert loaded_bridge.r2 is not old_pipe
            assert await loaded_bridge.get_sections()
        finally:
            _close_backend_pipes(process)

    @pytest.mark.asyncio
    @pytest.mark.spawns_process
    async def test_register_rizin_process_ignores_child_whose_pid_is_not_an_integer(
        self,
        loaded_bridge: CutterBridge,
        real_pe_dll: Path,
    ) -> None:
        """A child handle whose ``pid`` is ``None`` is not registered with the process manager.

        An unstarted ``multiprocessing.Process`` has a ``pid`` attribute that is
        ``None`` until the process starts.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            real_pe_dll: Path of the loaded DLL.
        """
        before = _tracked_pids()
        child = multiprocessing.Process()
        assert child.pid is None
        setattr(loaded_bridge.r2, "_child", child)
        register = cast("Callable[[Path], None]", getattr(loaded_bridge, "_register_rizin_process"))
        register(real_pe_dll)
        assert getattr(loaded_bridge, "_r2_pid") is None
        assert _tracked_pids() == before


class TestSessionGuards:
    """Argument and state checks that need no more than a loaded session."""

    @pytest.mark.asyncio
    async def test_search_bytes_wildcard_rejects_missing_binary(self) -> None:
        """Without a loaded binary the wildcard byte search raises the no-binary error."""
        with pytest.raises(ToolError, match="no binary loaded"):
            await CutterBridge().search_bytes_wildcard("48 8B ?? ??")

    @pytest.mark.asyncio
    @pytest.mark.spawns_process
    async def test_search_bytes_wildcard_rejects_unanalyzed_binary(self, loaded_bridge: CutterBridge) -> None:
        """A loaded but unanalyzed binary makes the wildcard byte search raise the not-analyzed error.

        Args:
            loaded_bridge: Bridge with the DLL loaded but not analyzed.
        """
        with pytest.raises(ToolError, match="binary not analyzed"):
            await loaded_bridge.search_bytes_wildcard("48 8B ?? ??")

    @pytest.mark.asyncio
    @pytest.mark.spawns_process
    async def test_read_bytes_of_zero_length_is_empty(self, loaded_bridge: CutterBridge, real_pe_dll: Path) -> None:
        """Asking for zero bytes returns no bytes.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            real_pe_dll: Path of the loaded DLL.
        """
        pe = pefile.PE(str(real_pe_dll), fast_load=True)
        try:
            address = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        finally:
            pe.close()
        assert await loaded_bridge.read_bytes(address, 0) == b""

    @pytest.mark.asyncio
    @pytest.mark.spawns_process
    async def test_type_listings_return_lists_of_dictionaries(self, loaded_bridge: CutterBridge) -> None:
        """Union, typedef and function-type listings are lists of dictionaries.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
        """
        listings: list[Callable[[], Awaitable[list[dict[str, Any]]]]] = [
            loaded_bridge.get_unions,
            loaded_bridge.get_typedefs,
            loaded_bridge.get_function_types,
        ]
        for listing in listings:
            result = await listing()
            assert isinstance(result, list)
            assert all(isinstance(item, dict) for item in result)


class TestCrossReferenceKinds:
    """Cross-reference kinds reported for references added through the bridge."""

    @pytest.mark.asyncio
    @pytest.mark.spawns_process
    async def test_outbound_call_reference_is_reported_as_call(self, analyzed_bridge: CutterBridge) -> None:
        """A call reference added from a function entry is reported as a call from that address.

        Args:
            analyzed_bridge: Analyzed bridge.
        """
        functions = [function for function in await analyzed_bridge.get_functions() if function.size > 8]
        source, target = functions[0].address, functions[1].address
        assert await analyzed_bridge.add_xref(source, target, "call") is True
        outbound = await analyzed_bridge.get_xrefs_from(source)
        assert all(xref.from_address == source for xref in outbound)
        assert "call" in [xref.ref_type for xref in outbound]

    @pytest.mark.asyncio
    @pytest.mark.spawns_process
    async def test_inbound_code_reference_is_reported_as_jump(self, analyzed_bridge: CutterBridge) -> None:
        """A code (non-call) reference is reported as a jump, not as data.

        Args:
            analyzed_bridge: Analyzed bridge.
        """
        functions = [function for function in await analyzed_bridge.get_functions() if function.size > 8]
        source, target = functions[0].address, functions[1].address
        assert await analyzed_bridge.add_xref(source, target, "code") is True
        inbound = await analyzed_bridge.get_xrefs_to(target)
        kinds = [xref.ref_type for xref in inbound if xref.from_address == source]
        assert kinds == ["jump"]
