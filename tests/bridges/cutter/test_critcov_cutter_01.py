# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage-gap tests for ``CutterBridge`` against a real radare2/rizin backend.

Every expectation here is derived independently of the bridge: the ``pefile``
parse and ``hashlib`` digest of the same System32 DLL, the file's own bytes at
the reported virtual addresses, the C type sizes, and the documented
no-binary / not-analyzed error contract. Tests that start a backend load a
real DLL through the real bridge and shut it down in a ``finally``/fixture
teardown. Tests that need a "different" backend binary on ``PATH`` use a plain
file or a copy of a System32 executable in ``tmp_path``.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pefile
import pytest
import pytest_asyncio
import rzpipe

from intellicrack.bridges import cutter as cutter_mod
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    import subprocess
    from collections.abc import AsyncIterator, Awaitable, Callable


_balanced_json_slice: Callable[[str, int], str | None] = cast(
    "Callable[[str, int], str | None]",
    getattr(cutter_mod, "_balanced_json_slice"),
)
_extract_rizin_json: Callable[[str, str], object] = cast(
    "Callable[[str, str], object]",
    getattr(cutter_mod, "_extract_rizin_json"),
)
_parse_int_response: Callable[[str], int] = cast(
    "Callable[[str], int]",
    getattr(cutter_mod, "_parse_int_response"),
)
_resolve_ghidra_sleighhome: Callable[[Path], Path | None] = cast(
    "Callable[[Path], Path | None]",
    getattr(cutter_mod, "_resolve_ghidra_sleighhome"),
)
_select_pipe_backend: Callable[[], Any] = cast(
    "Callable[[], Any]",
    getattr(cutter_mod, "_select_pipe_backend"),
)
_open_analysis_pipe: Callable[[str, list[str]], object] = cast(
    "Callable[[str, list[str]], object]",
    getattr(cutter_mod, "_open_analysis_pipe"),
)
_size_for_type: Callable[[str, int], int] = cast(
    "Callable[[str, int], int]",
    getattr(CutterBridge, "_size_for_type"),
)
_normalize_class_methods: Callable[[list[Any]], list[dict[str, Any]]] = cast(
    "Callable[[list[Any]], list[dict[str, Any]]]",
    getattr(CutterBridge, "_normalize_class_methods"),
)
_normalize_class_fields: Callable[[list[Any]], list[dict[str, Any]]] = cast(
    "Callable[[list[Any]], list[dict[str, Any]]]",
    getattr(CutterBridge, "_normalize_class_fields"),
)
_resolve_stored_binary: Callable[[Path], Path | None] = cast(
    "Callable[[Path], Path | None]",
    getattr(CutterBridge, "_resolve_stored_binary"),
)


_NO_BINARY_CASES: list[tuple[str, tuple[object, ...]]] = [
    ("_cmd_json", ("iSj",)),
    ("_get_sections_internal", ()),
    ("_get_imports_internal", ()),
    ("_get_exports_internal", ()),
    ("analyze_basic_blocks", ()),
    ("analyze_function_calls", ()),
    ("analyze_references", (64,)),
    ("autoname_functions", ()),
    ("get_functions", ()),
    ("get_function", (0x1000,)),
    ("disassemble", (0x1000, 4)),
    ("disassemble_range", (0x1000, 16)),
    ("get_xrefs_to", (0x1000,)),
    ("get_xrefs_from", (0x1000,)),
    ("add_xref", (0x1000, 0x2000)),
    ("remove_xref", (0x2000,)),
    ("search_strings", ("abc",)),
    ("get_imports", ()),
    ("get_exports", ()),
    ("rename_function", (0x1000, "renamed")),
    ("add_comment", (0x1000, "note")),
    ("assemble_at", (0x1000, "nop")),
    ("get_function_graph", (0x1000,)),
    ("get_function_address", ("CreateFileW",)),
    ("get_relocations", ()),
    ("_get_image_base", ()),
    ("search_rop_gadgets", ()),
    ("read_bytes", (0x1000, 4)),
    ("save_binary", ("out.bin",)),
    ("get_comments", ()),
    ("remove_flag", ("flag",)),
    ("rename_flag", ("old_flag", "new_flag")),
    ("add_flagspace", ("space",)),
    ("list_flagspaces", ()),
    ("remove_flagspace", ("space",)),
    ("resolve_flag", (0x1000,)),
    ("get_structs", ()),
    ("get_unions", ()),
    ("get_enums", ()),
    ("get_typedefs", ()),
    ("get_function_types", ()),
    ("esil_eval", ("1,1,+",)),
    ("esil_step", (0,)),
    ("esil_step_until", (0x1000,)),
    ("esil_emulate_function", (0x1000,)),
    ("esil_init_state", ()),
    ("esil_init_memory", ()),
    ("esil_set_pc", (0x1000,)),
    ("add_esil_watchpoint", ("r", "reg", "rax")),
    ("get_zignatures", ()),
    ("generate_zignatures", ()),
    ("add_zignature", ("zig", "bytes:90")),
    ("search_zignatures", ()),
    ("create_flirt_signatures", ("out.sig",)),
    ("_resolve_projects_dir", ()),
    ("get_config", ("asm.arch",)),
    ("set_config", ("asm.arch", "x86")),
    ("search_string_live", ("abc",)),
    ("search_assembly_pattern", ("mov eax, ebx",)),
    ("hexdump", (0x1000, 16)),
    ("get_basic_blocks", (0x1000,)),
    ("list_attachable_processes", ()),
]

_SIZE_CASES: list[tuple[str, int, int]] = [
    ("", 8, 0),
    ("char *", 8, 8),
    ("void*", 4, 4),
    ("uint8_t", 8, 1),
    ("int16_t", 8, 2),
    ("uint32_t", 8, 4),
    ("int64_t", 4, 8),
    ("size_t", 8, 8),
    ("size_t", 4, 4),
    ("uintptr_t", 4, 4),
    ("ptrdiff_t", 8, 8),
    ("char", 8, 1),
    ("bool", 8, 1),
    ("_Bool", 8, 1),
    ("short", 8, 2),
    ("wchar_t", 8, 2),
    ("int", 8, 4),
    ("  INT  ", 8, 4),
    ("unsigned int", 8, 4),
    ("uint", 8, 4),
    ("float", 8, 4),
    ("long", 8, 8),
    ("long", 4, 4),
    ("unsigned long", 8, 8),
    ("long long", 4, 8),
    ("unsigned long long", 4, 8),
    ("double", 4, 8),
    ("struct tagFOO", 8, 0),
]


def _exe_name(stem: str) -> str:
    """Return the platform executable file name for ``stem``.

    Args:
        stem: Executable name without a suffix.

    Returns:
        str: ``stem`` with ``.exe`` appended on Windows, otherwise ``stem``.
    """
    return f"{stem}.exe" if os.name == "nt" else stem


def _make_dir(path: Path) -> Path:
    """Create ``path`` and any missing parents.

    Args:
        path: Directory to create.

    Returns:
        Path: The created directory.
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


def _touch_file(path: Path, data: bytes = b"") -> Path:
    """Write ``data`` to ``path``.

    Args:
        path: File to create.
        data: Bytes to store in the file.

    Returns:
        Path: The created file.
    """
    path.write_bytes(data)
    return path


def _resolved(path: Path) -> Path:
    """Resolve ``path`` to its long, absolute form.

    Args:
        path: Path to resolve.

    Returns:
        Path: The resolved path.
    """
    return path.resolve()


def _make_fake_rizin(root: Path) -> Path:
    """Create a directory holding a non-executable file named like the rizin binary.

    Args:
        root: Parent directory for the new ``fakebin`` directory.

    Returns:
        Path: The directory to place on ``PATH``.
    """
    bin_dir = _make_dir(root / "fakebin")
    _touch_file(bin_dir / _exe_name("rizin"), b"MZ this is not an executable image")
    return bin_dir


def _prepend_path(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
    """Put ``directory`` first on ``PATH`` for the duration of the test.

    Args:
        monkeypatch: Fixture that restores ``PATH`` at teardown.
        directory: Directory to search first.
    """
    monkeypatch.setenv("PATH", os.pathsep.join([str(directory), os.environ.get("PATH", "")]))


def _isolate_path(monkeypatch: pytest.MonkeyPatch, root: Path) -> Path:
    """Replace ``PATH`` with a single empty directory so no backend is discoverable.

    Args:
        monkeypatch: Fixture that restores ``PATH`` at teardown.
        root: Parent directory for the empty directory.

    Returns:
        Path: The empty directory now forming the whole ``PATH``.
    """
    empty = _make_dir(root / "emptybin")
    monkeypatch.setenv("PATH", str(empty))
    return empty


def _install_failing_probe(bin_dir: Path) -> Path:
    """Copy System32's ``reg.exe`` into ``bin_dir`` under the rizin binary name.

    ``reg.exe`` exits with status 1 when given the unknown operation ``-v``,
    which is exactly how the bridge probes a backend.

    Args:
        bin_dir: Directory to receive the copy.

    Returns:
        Path: The copied executable.
    """
    source = Path(os.environ["SYSTEMROOT"]) / "System32" / "reg.exe"
    target = bin_dir / _exe_name("rizin")
    shutil.copy(source, target)
    return target


def _tracked_pids() -> set[int]:
    """Return every PID the process manager currently tracks.

    Returns:
        set[int]: PIDs of tracked subprocesses and registered external PIDs.
    """
    return {entry.pid for entry in ProcessManager.get_instance().get_all_tracked_entries()}


def _backend_process(bridge: CutterBridge) -> subprocess.Popen[bytes]:
    """Return the ``Popen`` handle of the backend process behind ``bridge``.

    Args:
        bridge: Bridge with a loaded binary.

    Returns:
        subprocess.Popen[bytes]: The radare2/rizin child process.
    """
    return cast("subprocess.Popen[bytes]", getattr(bridge.r2, "process"))


class PeOracle:
    """Independent view of a PE file built from ``pefile`` and ``hashlib``."""

    def __init__(self, path: Path) -> None:
        """Parse ``path`` and hash its bytes.

        Args:
            path: PE file on disk.
        """
        data = path.read_bytes()
        self.sha256: str = hashlib.sha256(data).hexdigest()
        self._pe: pefile.PE = pefile.PE(data=data, fast_load=True)
        self.image_base: int = self._pe.OPTIONAL_HEADER.ImageBase

    def text_section_va(self) -> int:
        """Return the virtual address of the ``.text`` section.

        Returns:
            int: ``ImageBase`` plus the section's relative virtual address.
        """
        text = next(section for section in self._pe.sections if section.Name.rstrip(b"\x00") == b".text")
        return self.image_base + text.VirtualAddress

    def bytes_at_va(self, address: int, length: int) -> bytes:
        """Return the file's bytes mapped at virtual address ``address``.

        Args:
            address: Absolute virtual address.
            length: Number of bytes to read.

        Returns:
            bytes: The mapped bytes taken straight from the file.
        """
        return self._pe.get_data(address - self.image_base, length)


@pytest.fixture
def pe_oracle(real_pe_dll: Path) -> PeOracle:
    """Build the independent oracle for the System32 DLL.

    Args:
        real_pe_dll: Path of the DLL under test.

    Returns:
        PeOracle: Oracle over the same file the bridge loads.
    """
    return PeOracle(real_pe_dll)


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


class TestPureHelpers:
    """Module-level helpers and static methods that need no backend."""

    def test_balanced_json_slice_skips_escaped_quote_and_backslash(self) -> None:
        """Escaped quotes and escaped backslashes inside strings do not end the string."""
        quoted = r'{"k": "a\"}b"} trailing'
        assert _balanced_json_slice(quoted, 0) == r'{"k": "a\"}b"}'
        backslash = '{"k": "a\\\\"} tail'
        assert _balanced_json_slice(backslash, 0) == '{"k": "a\\\\"}'

    def test_extract_rizin_json_rejects_blank_output(self) -> None:
        """Empty or whitespace-only output has no JSON and names the command."""
        for raw in ("", "   \n\t"):
            with pytest.raises(ToolError, match="failed to parse rizin JSON output: ilj"):
                _extract_rizin_json(raw, "ilj")

    def test_parse_int_response_accepts_decimal_and_hex(self) -> None:
        """Decimal and ``0x`` hexadecimal text, padded by whitespace, parse to the same integers."""
        assert _parse_int_response("0x1f") == 31
        assert _parse_int_response(" 42\n") == 42

    def test_parse_int_response_rejects_empty_response(self) -> None:
        """An empty or blank program-counter response is an error rather than zero."""
        for raw in ("", "  \n"):
            with pytest.raises(ToolError, match="empty integer response") as excinfo:
                _parse_int_response(raw)
            assert excinfo.value.tool_name == "cutter"

    def test_parse_int_response_rejects_non_numeric_text(self) -> None:
        """Text that is not an integer is reported with the offending value quoted."""
        with pytest.raises(ToolError, match="cannot parse 'not-a-number' as integer") as excinfo:
            _parse_int_response("not-a-number")
        assert excinfo.value.tool_name == "cutter"
        assert isinstance(excinfo.value.__cause__, ValueError)

    @pytest.mark.parametrize(("type_name", "word_size", "expected"), _SIZE_CASES)
    def test_size_for_type_matches_c_type_sizes(self, type_name: str, word_size: int, expected: int) -> None:
        """C type names map to their sizes; pointers and word-sized types follow the word size.

        Args:
            type_name: C type name as reported by the backend.
            word_size: Pointer width in bytes.
            expected: Size in bytes from the C type definitions.
        """
        assert _size_for_type(type_name, word_size) == expected

    def test_normalize_class_methods_skips_non_dict_entries(self) -> None:
        """Only dictionary method entries are kept, with address and flags fallbacks."""
        raw: list[Any] = [
            1,
            "text",
            None,
            {"name": "m1", "addr": 16, "type": "METHOD"},
            {"name": "m2", "vaddr": 32, "flags": "static", "type": "FUNC"},
        ]
        assert _normalize_class_methods(raw) == [
            {"name": "m1", "address": 16, "flags": "METHOD", "type": "METHOD"},
            {"name": "m2", "address": 32, "flags": "static", "type": "FUNC"},
        ]

    def test_normalize_class_fields_skips_non_dict_entries(self) -> None:
        """Only dictionary field entries are kept, with offset fallbacks."""
        raw: list[Any] = [
            7,
            [],
            {"name": "f1", "offset": 4, "size": 2, "type": "short"},
            {"name": "f2", "paddr": 8, "size": 4, "type": "int"},
            {"name": "f3", "addr": 12},
        ]
        assert _normalize_class_fields(raw) == [
            {"name": "f1", "offset": 4, "size": 2, "type": "short"},
            {"name": "f2", "offset": 8, "size": 4, "type": "int"},
            {"name": "f3", "offset": 12, "size": 0, "type": ""},
        ]

    def test_resolve_ghidra_sleighhome_finds_share_layout(self, tmp_path: Path) -> None:
        """The ``share/rizin/rz_ghidra_sleigh`` layout under the install directory is found.

        Args:
            tmp_path: Per-test temporary directory.
        """
        install = _make_dir(tmp_path / "bin")
        spec = _make_dir(install / "share" / "rizin" / "rz_ghidra_sleigh")
        assert _resolve_ghidra_sleighhome(install) == spec.resolve()

    def test_resolve_ghidra_sleighhome_finds_parent_layout(self, tmp_path: Path) -> None:
        """A spec directory next to the install directory is found through ``..``.

        Args:
            tmp_path: Per-test temporary directory.
        """
        install = _make_dir(tmp_path / "bin")
        spec = _make_dir(tmp_path / "lib" / "rizin" / "plugins" / "rz_ghidra_sleigh")
        assert _resolve_ghidra_sleighhome(install) == spec.resolve()

    def test_resolve_ghidra_sleighhome_none_without_layout(self, tmp_path: Path) -> None:
        """No known layout means no SLEIGH directory.

        Args:
            tmp_path: Per-test temporary directory.
        """
        assert _resolve_ghidra_sleighhome(_make_dir(tmp_path / "bin")) is None

    def test_resolve_stored_binary_file_and_directory(self, tmp_path: Path) -> None:
        """A file is returned as-is; a directory yields its rizin, then radare2, binary.

        Args:
            tmp_path: Per-test temporary directory.
        """
        single = _touch_file(tmp_path / "any_name.bin", b"x")
        assert _resolve_stored_binary(single) == single

        directory = _make_dir(tmp_path / "install")
        assert _resolve_stored_binary(directory) is None
        radare2 = _touch_file(directory / _exe_name("radare2"), b"x")
        assert _resolve_stored_binary(directory) == radare2
        rizin = _touch_file(directory / _exe_name("rizin"), b"x")
        assert _resolve_stored_binary(directory) == rizin


class TestNoBinaryGuards:
    """Methods called on a bridge that never loaded a binary."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("method_name", "args"), _NO_BINARY_CASES, ids=[case[0] for case in _NO_BINARY_CASES])
    async def test_methods_reject_when_no_binary_loaded(self, method_name: str, args: tuple[object, ...]) -> None:
        """Each method raises the "no binary loaded" error instead of touching a pipe.

        Args:
            method_name: Name of the bridge method under test.
            args: Positional arguments for the call.
        """
        bridge = CutterBridge()
        method = cast("Callable[..., Awaitable[object]]", getattr(bridge, method_name))
        with pytest.raises(ToolError, match="no binary loaded"):
            await method(*args)

    @pytest.mark.asyncio
    async def test_configure_ghidra_sleighhome_noop_without_session(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Without an open session nothing is configured, even when a SLEIGH directory exists.

        Args:
            monkeypatch: Fixture used to put a backend with a spec directory on ``PATH``.
            tmp_path: Per-test temporary directory.
        """
        bin_dir = _make_fake_rizin(tmp_path)
        _make_dir(bin_dir / "share" / "rizin" / "rz_ghidra_sleigh")
        _prepend_path(monkeypatch, bin_dir)
        bridge = CutterBridge()
        configure = cast("Callable[[], Awaitable[None]]", getattr(bridge, "_configure_ghidra_sleighhome"))
        await configure()
        assert getattr(bridge, "_ghidra_sleighhome_applied") is False


class TestBackendDiscovery:
    """Backend selection and availability without starting an analysis session."""

    def test_select_pipe_backend_prefers_rizin(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """A rizin binary on ``PATH`` wins and carries its own install directory.

        Args:
            monkeypatch: Fixture used to put the rizin file on ``PATH``.
            tmp_path: Per-test temporary directory.
        """
        bin_dir = _make_fake_rizin(tmp_path)
        _prepend_path(monkeypatch, bin_dir)
        backend = _select_pipe_backend()
        assert backend is not None
        assert backend.binary == "rizin"
        assert backend.module is rzpipe
        assert backend.install_dir == bin_dir.resolve()

    @pytest.mark.asyncio
    async def test_open_analysis_pipe_without_backend_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        real_pe_dll: Path,
    ) -> None:
        """With neither rizin nor radare2 on ``PATH`` opening a pipe is a ``ToolError``.

        Args:
            monkeypatch: Fixture used to empty ``PATH``.
            tmp_path: Per-test temporary directory.
            real_pe_dll: Path of a real DLL to open.
        """
        _isolate_path(monkeypatch, tmp_path)
        with pytest.raises(ToolError, match="cutter not available"):
            _open_analysis_pipe(str(real_pe_dll), ["-2"])

    @pytest.mark.asyncio
    async def test_is_available_false_without_backend(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """No backend on ``PATH`` and no stored tool path means unavailable.

        Args:
            monkeypatch: Fixture used to empty ``PATH``.
            tmp_path: Per-test temporary directory.
        """
        _isolate_path(monkeypatch, tmp_path)
        assert await CutterBridge().is_available() is False

    @pytest.mark.asyncio
    async def test_load_binary_requires_backend(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        real_pe_dll: Path,
    ) -> None:
        """Loading an existing file still fails when no backend is available.

        Args:
            monkeypatch: Fixture used to empty ``PATH``.
            tmp_path: Per-test temporary directory.
            real_pe_dll: Path of a real DLL that exists on disk.
        """
        _isolate_path(monkeypatch, tmp_path)
        with pytest.raises(ToolError, match="cutter not available"):
            await CutterBridge().load_binary(real_pe_dll)


@pytest.mark.asyncio
@pytest.mark.spawns_process
class TestBackendLaunch:
    """Probing and opening backend binaries that cannot serve as an analysis backend."""

    async def test_open_analysis_pipe_passes_rizin_home(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        real_pe_dll: Path,
    ) -> None:
        """With rizin selected the pipe is opened through ``rizin_home`` and launches that binary.

        The rizin file is not a real executable, so rzpipe reports it cannot start rizin; a
        different keyword would fail earlier with a ``TypeError``.

        Args:
            monkeypatch: Fixture used to put the rizin file on ``PATH``.
            tmp_path: Per-test temporary directory.
            real_pe_dll: Path of a real DLL to open.
        """
        _prepend_path(monkeypatch, _make_fake_rizin(tmp_path))
        with pytest.raises(Exception, match="Cannot find rizin"):
            _open_analysis_pipe(str(real_pe_dll), ["-2"])

    async def test_is_available_false_when_probe_cannot_launch(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A backend file that the OS cannot start reports unavailable instead of raising.

        Args:
            monkeypatch: Fixture used to put the rizin file on ``PATH``.
            tmp_path: Per-test temporary directory.
        """
        _prepend_path(monkeypatch, _make_fake_rizin(tmp_path))
        assert await CutterBridge().is_available() is False

    async def test_is_available_false_when_probe_exits_nonzero(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A backend whose ``-v`` probe exits with a failure status reports unavailable.

        Args:
            monkeypatch: Fixture used to put the failing binary on ``PATH``.
            tmp_path: Per-test temporary directory.
        """
        bin_dir = _make_dir(tmp_path / "failbin")
        _install_failing_probe(bin_dir)
        _prepend_path(monkeypatch, bin_dir)
        assert await CutterBridge().is_available() is False


@pytest.mark.asyncio
@pytest.mark.spawns_process
class TestRealSession:
    """Behavior of a bridge driving a real radare2/rizin session on a System32 DLL."""

    async def test_load_binary_reports_file_sha256(self, real_pe_dll: Path, pe_oracle: PeOracle) -> None:
        """``BinaryInfo.sha256`` equals the SHA-256 of the file on disk.

        Args:
            real_pe_dll: Path of the DLL to load.
            pe_oracle: Independent digest of the same file.
        """
        bridge = CutterBridge()
        try:
            info = await bridge.load_binary(real_pe_dll)
        finally:
            await bridge.shutdown()
        assert info.sha256 == pe_oracle.sha256

    async def test_unanalyzed_session_rejects_analysis_calls(self, loaded_bridge: CutterBridge) -> None:
        """Calls that need analysis fail with the not-analyzed error while plain listings still work.

        Args:
            loaded_bridge: Bridge with the DLL loaded but not analyzed.
        """
        cases: list[tuple[str, tuple[object, ...]]] = [
            ("get_function", (0x1000,)),
            ("disassemble_range", (0x1000, 16)),
            ("get_xrefs_from", (0x1000,)),
            ("add_xref", (0x1000, 0x2000)),
            ("remove_xref", (0x2000,)),
            ("rename_function", (0x1000, "renamed")),
            ("get_function_graph", (0x1000,)),
            ("get_function_address", ("CreateFileW",)),
        ]
        for method_name, args in cases:
            method = cast("Callable[..., Awaitable[object]]", getattr(loaded_bridge, method_name))
            with pytest.raises(ToolError, match="binary not analyzed"):
                await method(*args)
        assert await loaded_bridge.get_sections()

    async def test_search_assembly_pattern_rejects_empty_pattern(self, loaded_bridge: CutterBridge) -> None:
        """An empty assembly pattern is refused.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
        """
        with pytest.raises(ToolError, match="pattern must not be empty"):
            await loaded_bridge.search_assembly_pattern("")

    async def test_save_project_rejects_names_that_are_not_plain(self, loaded_bridge: CutterBridge) -> None:
        """Empty names, dot names and names with path separators are refused.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
        """
        for name in ("", ".", "..", "a\\b", "a/b"):
            with pytest.raises(ToolError, match="path separators"):
                await loaded_bridge.save_project(name)

    async def test_save_binary_default_target_rules(self, loaded_bridge: CutterBridge, tmp_path: Path) -> None:
        """Without a path the tracked binary path is the target, and it must exist and be safe.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            tmp_path: Per-test temporary directory.
        """
        setattr(loaded_bridge, "_binary_path", None)
        with pytest.raises(ToolError, match="no binary loaded"):
            await loaded_bridge.save_binary()
        setattr(loaded_bridge, "_binary_path", tmp_path / "bad;name.bin")
        with pytest.raises(ToolError, match="save_binary path"):
            await loaded_bridge.save_binary()

    async def test_esil_step_zero_count_runs_no_commands(self, loaded_bridge: CutterBridge) -> None:
        """Stepping zero times returns an empty result.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
        """
        result = await loaded_bridge.esil_step(0)
        assert isinstance(result, str)
        assert not result

    async def test_get_function_address_rejects_empty_name(self, analyzed_bridge: CutterBridge) -> None:
        """An empty function name is refused once the binary is analyzed.

        Args:
            analyzed_bridge: Analyzed bridge.
        """
        with pytest.raises(ToolError, match="name must not be empty"):
            await analyzed_bridge.get_function_address("")

    async def test_rename_function_renames_in_listing(self, analyzed_bridge: CutterBridge) -> None:
        """The function at the given address carries the new name afterwards.

        Args:
            analyzed_bridge: Analyzed bridge.
        """
        functions = await analyzed_bridge.get_functions()
        target = next(function for function in functions if function.size > 8)
        new_name = "critcov_renamed_fn"
        assert await analyzed_bridge.rename_function(target.address, new_name) is True
        after = await analyzed_bridge.get_functions()
        assert [function.address for function in after if function.name == new_name] == [target.address]

    async def test_seek_moves_current_offset(self, loaded_bridge: CutterBridge, pe_oracle: PeOracle) -> None:
        """``seek`` leaves the session positioned at the requested virtual address.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            pe_oracle: Independent section layout of the same file.
        """
        text_va = pe_oracle.text_section_va()
        for address in (text_va, text_va + 16):
            await loaded_bridge.seek(address)
            current = await loaded_bridge.execute_command("s")
            assert int(current.strip(), 0) == address

    async def test_function_graph_blocks_carry_real_instruction_bytes(
        self,
        analyzed_bridge: CutterBridge,
        pe_oracle: PeOracle,
    ) -> None:
        """Every graph block starts with the instruction bytes stored in the file at that address.

        Args:
            analyzed_bridge: Analyzed bridge.
            pe_oracle: Independent view of the file bytes.
        """
        functions = await analyzed_bridge.get_functions()
        function = next(item for item in functions if item.size > 8)
        graph = await analyzed_bridge.get_function_graph(function.address)
        entry_blocks = [block for block in graph if block["offset"] == function.address]
        assert len(entry_blocks) == 1
        verified = 0
        for block in graph:
            ops = cast("list[dict[str, Any]]", block["ops"])
            assert block["jump"] is None or isinstance(block["jump"], int)
            assert block["fail"] is None or isinstance(block["fail"], int)
            if not ops:
                continue
            assert ops[0]["offset"] == block["offset"]
            raw = bytes.fromhex(cast("str", ops[0]["bytes"]))
            assert raw == pe_oracle.bytes_at_va(block["offset"], len(raw))
            verified += 1
        assert verified >= 1
        assert entry_blocks[0]["ops"]

    async def test_xrefs_to_report_added_references(self, analyzed_bridge: CutterBridge) -> None:
        """Data and call references added between functions are reported at their target.

        Args:
            analyzed_bridge: Analyzed bridge.
        """
        functions = [function for function in await analyzed_bridge.get_functions() if function.size > 8]
        source, target, caller = functions[0].address, functions[1].address, functions[2].address
        assert await analyzed_bridge.add_xref(source, target, "data") is True
        assert await analyzed_bridge.add_xref(caller, target, "call") is True

        inbound = await analyzed_bridge.get_xrefs_to(target)
        seen = [(xref.from_address, xref.to_address, xref.ref_type) for xref in inbound]
        assert all(to_address == target for _, to_address, _ in seen), seen
        assert (source, target, "data") in seen, seen
        assert (caller, target, "call") in seen, seen

    async def test_xrefs_from_report_added_references(self, analyzed_bridge: CutterBridge) -> None:
        """Data and call references added between functions are reported at their source.

        Args:
            analyzed_bridge: Analyzed bridge.
        """
        functions = [function for function in await analyzed_bridge.get_functions() if function.size > 8]
        source, target, caller = functions[0].address, functions[1].address, functions[2].address
        assert await analyzed_bridge.add_xref(source, target, "data") is True
        assert await analyzed_bridge.add_xref(caller, target, "call") is True

        outbound = await analyzed_bridge.get_xrefs_from(source)
        data_seen = [(xref.from_address, xref.to_address, xref.ref_type) for xref in outbound]
        assert all(from_address == source for from_address, _, _ in data_seen), data_seen
        assert (source, target, "data") in data_seen, data_seen

        call_out = await analyzed_bridge.get_xrefs_from(caller)
        call_seen = [(xref.from_address, xref.to_address, xref.ref_type) for xref in call_out]
        assert (caller, target, "call") in call_seen, call_seen

    async def test_search_strings_label_matches_encoding(self, loaded_bridge: CutterBridge, pe_oracle: PeOracle) -> None:
        """Wide strings are reported as UTF-16LE and every label matches the bytes in the file.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            pe_oracle: Independent view of the file bytes.
        """
        results = await loaded_bridge.search_strings(r"^[A-Za-z0-9_.]{8,}$")
        wide = [item for item in results if item.encoding == "utf-16le"]
        narrow = [item for item in results if item.encoding != "utf-16le"]
        assert wide, "kernel32 contains UTF-16LE strings but none were labeled utf-16le"
        assert narrow
        mismatches: list[tuple[str, str, str]] = []
        for item in [*wide[:300], *narrow[:300]]:
            codec = "utf-16le" if item.encoding == "utf-16le" else "ascii"
            expected = item.value.encode(codec)
            if pe_oracle.bytes_at_va(item.address, len(expected)) != expected:
                mismatches.append((hex(item.address), item.value, item.encoding))
        assert not mismatches

    async def test_command_queued_behind_lock_rejects_after_session_dropped(self, loaded_bridge: CutterBridge) -> None:
        """A command waiting for the pipe lock fails cleanly if the session is dropped meanwhile.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
        """
        lock = cast("asyncio.Lock", getattr(loaded_bridge, "_r2_lock"))
        pipe = loaded_bridge.r2
        await lock.acquire()
        queued = asyncio.create_task(loaded_bridge.r2_cmd("?V"))
        try:
            await asyncio.sleep(0)
            loaded_bridge.r2 = None
        finally:
            lock.release()
        try:
            with pytest.raises(ToolError, match="no binary loaded"):
                await queued
        finally:
            loaded_bridge.r2 = pipe

    async def test_discard_session_tolerates_invalid_child_pid(self, loaded_bridge: CutterBridge) -> None:
        """Discarding a session whose registered PID cannot be terminated still resets all state.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
        """
        pipe = loaded_bridge.r2
        setattr(loaded_bridge, "_r2_pid", -1)
        discard = cast("Callable[..., Awaitable[None]]", getattr(loaded_bridge, "_discard_r2_session_locked"))
        try:
            await discard(command="probe")
            assert loaded_bridge.r2 is None
            assert getattr(loaded_bridge, "_r2_pid") is None
            assert loaded_bridge.state.connected is False
            assert loaded_bridge.state.tool_running is False
            assert loaded_bridge.state.process_attached is False
            assert loaded_bridge.state.target_pid is None
        finally:
            loaded_bridge.r2 = pipe

    async def test_register_rizin_process_tracks_backend_child(self, loaded_bridge: CutterBridge, real_pe_dll: Path) -> None:
        """A backend exposing its child process is registered, and shutdown releases it.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            real_pe_dll: Path of the loaded DLL.
        """
        process = _backend_process(loaded_bridge)
        register = cast("Callable[[Path], None]", getattr(loaded_bridge, "_register_rizin_process"))
        register(real_pe_dll)
        assert getattr(loaded_bridge, "_r2_pid") == process.pid
        entry = next(item for item in ProcessManager.get_instance().get_all_tracked_entries() if item.pid == process.pid)
        assert entry.name == f"cutter-rizin-{real_pe_dll.name}"
        assert entry.process_type is ProcessType.EXTERNAL_TOOL
        assert entry.metadata == {"binary": str(real_pe_dll)}

        await loaded_bridge.shutdown()
        assert getattr(loaded_bridge, "_r2_pid") is None
        assert process.pid not in _tracked_pids()

    async def test_register_rizin_process_ignores_child_without_pid(
        self,
        loaded_bridge: CutterBridge,
        real_pe_dll: Path,
    ) -> None:
        """A missing child, or a child object without a PID, registers nothing.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            real_pe_dll: Path of the loaded DLL.
        """
        register = cast("Callable[[Path], None]", getattr(loaded_bridge, "_register_rizin_process"))
        process = _backend_process(loaded_bridge)
        ProcessManager.get_instance().unregister_external_pid(process.pid)
        setattr(loaded_bridge, "_r2_pid", None)
        try:
            for child in (None, object()):
                setattr(loaded_bridge.r2, "process", child)
                register(real_pe_dll)
                assert getattr(loaded_bridge, "_r2_pid") is None
                assert process.pid not in _tracked_pids()
        finally:
            setattr(loaded_bridge.r2, "process", process)

    async def test_reload_unregisters_previous_process(self, loaded_bridge: CutterBridge, real_pe_dll: Path) -> None:
        """Loading another binary closes the old session and releases its registered PID.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            real_pe_dll: Path of the loaded DLL.
        """
        old_process = _backend_process(loaded_bridge)
        register = cast("Callable[[Path], None]", getattr(loaded_bridge, "_register_rizin_process"))
        register(real_pe_dll)
        assert old_process.pid in _tracked_pids()

        await loaded_bridge.load_binary(real_pe_dll)
        assert old_process.pid not in _tracked_pids()
        assert getattr(loaded_bridge, "_r2_pid") != old_process.pid

    async def test_load_binary_registers_backend_process(self, loaded_bridge: CutterBridge) -> None:
        """The backend process started by ``load_binary`` is tracked by the process manager.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
        """
        assert _backend_process(loaded_bridge).pid in _tracked_pids()

    async def test_configure_ghidra_sleighhome_applies_once_found(
        self,
        loaded_bridge: CutterBridge,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A SLEIGH directory next to the resolved backend is configured and remembered.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            monkeypatch: Fixture used to put a backend with a spec directory on ``PATH``.
            tmp_path: Per-test temporary directory.
        """
        bin_dir = _make_fake_rizin(tmp_path)
        _make_dir(bin_dir / "share" / "rizin" / "rz_ghidra_sleigh")
        _prepend_path(monkeypatch, bin_dir)
        configure = cast("Callable[[], Awaitable[None]]", getattr(loaded_bridge, "_configure_ghidra_sleighhome"))
        await configure()
        assert getattr(loaded_bridge, "_ghidra_sleighhome_applied") is True

    async def test_configure_ghidra_sleighhome_without_backend_leaves_unset(
        self,
        loaded_bridge: CutterBridge,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """When no backend can be resolved the SLEIGH home stays unconfigured.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            monkeypatch: Fixture used to empty ``PATH`` after the session started.
            tmp_path: Per-test temporary directory.
        """
        _isolate_path(monkeypatch, tmp_path)
        configure = cast("Callable[[], Awaitable[None]]", getattr(loaded_bridge, "_configure_ghidra_sleighhome"))
        await configure()
        assert getattr(loaded_bridge, "_ghidra_sleighhome_applied") is False

    async def test_list_projects_reports_uncreatable_directory(self, loaded_bridge: CutterBridge, tmp_path: Path) -> None:
        """A configured projects directory that cannot be created is reported as a ``ToolError``.

        Args:
            loaded_bridge: Bridge with the DLL loaded.
            tmp_path: Per-test temporary directory.
        """
        blocker = _touch_file(_resolved(tmp_path) / "blocker", b"file, not a directory")
        target = (blocker / "projects").as_posix()
        await loaded_bridge.set_config("dir.projects", target)
        assert await loaded_bridge.get_config("dir.projects") == target
        with pytest.raises(ToolError, match="cannot create projects directory"):
            await loaded_bridge.list_projects()
