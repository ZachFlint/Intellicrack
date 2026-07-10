# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the CutterBridge Cutter/Rizin integration.

Tests validate:
- Bridge instantiation and capability flags
- Tool definition completeness (80 functions, all resolve to methods)
- Tool definition parameter names match method signatures
- initialize() verifies Rizin availability and raises ToolError when absent
- initialize() stores tool_path and prepends to PATH
- load_binary() coerces string paths to Path objects
- search_bytes() accepts both bytes and str inputs
- write_bytes() accepts hex string and returns True
- assemble_at() uses r2pipe pa command instead of standalone rasm2
- add_comment() maps comment_type to correct Rizin commands
- _close_existing_r2() handles quit() failures gracefully
- Methods raise ToolError when no binary is loaded or not analyzed
- Section permission integer to rwx string conversion
- Bug fixes: entry point double-baddr, save_binary wtf command
- New methods: get_symbols, get_libraries, read_bytes, get_flags, etc.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest
import r2pipe

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.schemas import is_recognized_type, normalize_type
from intellicrack.core.types import ToolError, ToolName
from intellicrack.ui.panels.cutter_panel import perm_to_rwx


if TYPE_CHECKING:
    from collections.abc import Iterator


_EXPECTED_TOOL_FUNC_COUNT: Final[int] = 95
_TEST_ADDRESS: Final[int] = 0x401000
_MIN_DESC_LEN: Final[int] = 5

_RIZIN_BINARY: Final[str | None] = shutil.which("rizin") or shutil.which("radare2")
_requires_rizin = pytest.mark.skipif(
    _RIZIN_BINARY is None,
    reason="rizin/radare2 backend not installed on PATH; real-backend integration gate cannot run",
)

_MARKER: Final[bytes] = b"\xde\xad\xbe\xef"
_UNIQUE_MARKER: Final[bytes] = b"\xca\xfe\x12\x34"
_ABSENT_PATTERN: Final[bytes] = b"\x99\x88\x77\x66\x55\x44"
_MARKER_OFFSETS: Final[tuple[int, ...]] = (0x10, 0x80, 0x140)
_UNIQUE_OFFSET: Final[int] = 0x40
_MARKER_BLOB_SIZE: Final[int] = 0x200


def _count_occurrences(data: bytes, pattern: bytes) -> int:
    """Count non-overlapping-start occurrences of ``pattern`` in ``data``.

    Independent oracle for byte-search match counts. Scans the buffer with
    :meth:`bytes.find`, advancing one byte past each hit so overlapping
    matches are counted the same way Rizin's ``/x`` reports them.

    Args:
        data: Buffer to scan.
        pattern: Byte sequence to locate.

    Returns:
        int: Number of occurrences of ``pattern`` in ``data``.
    """
    count = 0
    start = 0
    while True:
        index = data.find(pattern, start)
        if index < 0:
            return count
        count += 1
        start = index + 1


def _build_marker_blob() -> bytes:
    """Build a deterministic raw blob with markers at independently-known offsets.

    The blob is zero-filled except for three copies of :data:`_MARKER` and a
    single copy of :data:`_UNIQUE_MARKER`, all written at the fixed offsets in
    :data:`_MARKER_OFFSETS` / :data:`_UNIQUE_OFFSET`. Because the offsets are
    chosen by the test (not derived from the bridge), they are an independent
    oracle for the search results.

    Returns:
        bytes: The constructed blob of length :data:`_MARKER_BLOB_SIZE`.
    """
    data = bytearray(b"\x00" * _MARKER_BLOB_SIZE)
    for offset in _MARKER_OFFSETS:
        data[offset : offset + len(_MARKER)] = _MARKER
    data[_UNIQUE_OFFSET : _UNIQUE_OFFSET + len(_UNIQUE_MARKER)] = _UNIQUE_MARKER
    return bytes(data)


class _CommandRecorder:
    """r2pipe stand-in that records commands and returns configurable JSON.

    Captures every command sent through ``cmd()`` so tests can verify the
    exact Rizin commands the bridge constructs.

    Attributes:
        commands: Running list of every command string passed to ``cmd()``.
        responses: Mapping of command prefix to response string used by
            ``cmd()`` to select a canned reply.

    Attributes:
        commands: Running list of every command string passed to ``cmd()``.
        responses: Mapping of command prefix to response string used by
            ``cmd()`` to select a canned reply.

    Args:
        responses: Mapping of command prefix to response string.  If a
            command starts with a key, the corresponding value is returned.
            Falls back to empty string.
    """

    commands: list[str]
    responses: dict[str, str]

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        self.commands = []
        self.responses = responses or {}

    def cmd(self, command: str) -> str:
        """Record ``command`` and return the configured response.

        Args:
            command: The r2 command string issued by the bridge.

        Returns:
            str: Configured response for the longest matching prefix, or
            an empty string when no configured prefix matches.
        """
        self.commands.append(command)
        return next(
            (response for prefix, response in self.responses.items() if command.startswith(prefix)),
            "",
        )

    def quit(self) -> None:
        """No-op ``quit`` for test cleanup."""


class _FailingQuitR2:
    """r2pipe stand-in whose ``quit()`` raises ``RuntimeError``."""

    def cmd(self, _command: str) -> str:
        """Return an empty response regardless of the command.

        Args:
            _command: Ignored command string.

        Returns:
            str: Empty string.
        """
        return ""

    def quit(self) -> None:
        """Raise ``RuntimeError`` to simulate a dead session.

        Raises:
            RuntimeError: Always.
        """
        msg = "broken pipe"
        raise RuntimeError(msg)


def _as_r2pipe(double: _CommandRecorder | _FailingQuitR2) -> r2pipe.open:
    """Cast a test double to the ``r2pipe.open`` type.

    Runtime invariant: ``_CommandRecorder`` and ``_FailingQuitR2`` implement
    the exact subset of the ``r2pipe.open`` interface that ``CutterBridge``
    consumes -- ``cmd(str) -> str`` and ``quit() -> None``.  The bridge
    never accesses any other r2pipe member in production, so these test
    doubles are duck-type equivalents for assignment to ``bridge.r2``.
    Centralising the cast here keeps the invariant documented in one
    place rather than scattered across every call site.

    Args:
        double: Test double that duck-types the ``r2pipe.open`` interface.

    Returns:
        r2pipe.open: The same instance, typed as ``r2pipe.open`` for the
        bridge's setter signature.
    """
    return cast(r2pipe.open, double)


@pytest.fixture
def bridge() -> CutterBridge:
    """Create a fresh CutterBridge instance.

    Returns:
        CutterBridge: Unconnected CutterBridge.
    """
    return CutterBridge()


@pytest.fixture
def recorder() -> _CommandRecorder:
    """Create a default CommandRecorder with common responses.

    Returns:
        _CommandRecorder: Recorder with analysis/metadata stubs.
    """
    return _CommandRecorder({
        "e asm.arch": "x86",
        "e asm.bits": "64",
        "/xj": "[]",
        "aflj": "[]",
        "izj": "[]",
        "iSj": "[]",
        "iij": "[]",
        "iEj": "[]",
        "axtj": "[]",
        "axfj": "[]",
        "pdj": "[]",
        "afij": "[]",
        "itj": "[]",
        "ij": '[{"bin":{"class":"PE","arch":"x86","bits":64,"baddr":0,"entry":0}}]',
        "agj": "[]",
    })


@pytest.fixture
def loaded_bridge(recorder: _CommandRecorder) -> CutterBridge:
    """Create a bridge with an r2 session and analyzed state.

    Uses the public ``r2`` property setter and ``analyze()`` method
    to avoid accessing protected members.

    Args:
        recorder: Command recorder fixture.

    Returns:
        CutterBridge: Bridge ready for method calls.
    """
    b = CutterBridge()
    b.r2 = _as_r2pipe(recorder)
    asyncio.run(b.analyze())
    recorder.commands.clear()
    return b


@pytest.fixture
def marker_blob_path(tmp_path: Path) -> Path:
    """Write the deterministic marker blob to a real file on disk.

    Args:
        tmp_path: Per-test temporary directory from pytest.

    Returns:
        Path: Path to the written blob.
    """
    target = tmp_path / "marker_blob.bin"
    target.write_bytes(_build_marker_blob())
    return target


@pytest.fixture
def real_search_bridge(marker_blob_path: Path) -> Iterator[CutterBridge]:
    """Provide a CutterBridge backed by a real Rizin session over the marker blob.

    Drives the genuine ``initialize`` -> ``load_binary`` -> ``analyze`` path
    against the installed rizin/radare2 backend (no doubles), then yields the
    bridge for byte-search assertions and tears the session down afterwards.

    Args:
        marker_blob_path: Path to the deterministic marker blob.

    Yields:
        CutterBridge: Bridge with the marker blob loaded and analyzed.
    """
    b = CutterBridge()
    asyncio.run(b.initialize())
    asyncio.run(b.load_binary(marker_blob_path))
    asyncio.run(b.analyze("quick"))
    try:
        yield b
    finally:
        asyncio.run(b.shutdown())


class TestBridgeInstantiation:
    """Verify CutterBridge basic properties after construction."""

    def test_instantiation(self) -> None:
        """Verify a fresh CutterBridge exposes a usable, fully-wired surface.

        A constructed bridge must report its identity, start with no live
        Rizin session, advertise the static-analysis/patching capability
        surface the Cutter integration is built around, and expose a tool
        definition whose every declared function resolves to a real callable
        bridge method. Asserting the wiring (not mere object existence) makes
        this fail if the bridge ships a function without a backing method, a
        wrong tool name, or a stale residual session handle.
        """
        b = CutterBridge()
        assert b.name == ToolName.CUTTER
        assert b.r2 is None
        caps = b.capabilities
        assert caps.supports_static_analysis is True
        assert caps.supports_decompilation is True
        assert caps.supports_patching is True
        td = b.tool_definition
        assert td.tool_name == ToolName.CUTTER
        names = [f.name for f in td.functions]
        assert len(names) == _EXPECTED_TOOL_FUNC_COUNT
        resolved = [n for n in names if callable(getattr(b, n.removeprefix("cutter."), None))]
        assert resolved == names

    def test_name(self, bridge: CutterBridge) -> None:
        """Verify bridge reports ToolName.CUTTER.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.name == ToolName.CUTTER

    def test_r2_is_none_initially(self, bridge: CutterBridge) -> None:
        """Verify r2 connection is None before initialization.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.r2 is None

    def test_r2_property_settable(self) -> None:
        """Verify the public r2 property setter works."""
        bridge = CutterBridge()
        typed_rec = _as_r2pipe(_CommandRecorder())
        bridge.r2 = typed_rec
        assert bridge.r2 is typed_rec


class TestCapabilities:
    """Verify capability flags match actual bridge functionality."""

    def test_supports_static_analysis(self, bridge: CutterBridge) -> None:
        """Verify static analysis is supported.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_static_analysis is True

    def test_supports_dynamic_analysis(self, bridge: CutterBridge) -> None:
        """Verify dynamic analysis is supported.

        The CutterBridge exposes rizin's full debug subsystem
        (attach/detach, breakpoints, stepping, register and memory
        access, thread and module enumeration), so the capability
        flag must advertise it.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_dynamic_analysis is True

    def test_supports_decompilation(self, bridge: CutterBridge) -> None:
        """Verify decompilation is supported.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_decompilation is True

    def test_supports_debugging(self, bridge: CutterBridge) -> None:
        """Verify debugging is supported.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_debugging is True

    def test_supports_memory_access(self, bridge: CutterBridge) -> None:
        """Verify process memory access is supported.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_memory_access is True

    def test_supports_patching(self, bridge: CutterBridge) -> None:
        """Verify patching is supported.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_patching is True

    def test_supports_scripting(self, bridge: CutterBridge) -> None:
        """Verify scripting is supported.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_scripting is True


class TestToolDefinition:
    """Verify tool_definition completeness and method alignment."""

    def test_tool_definition_exists(self, bridge: CutterBridge) -> None:
        """Verify tool_definition property returns a valid definition.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        assert td is not None
        assert td.tool_name == ToolName.CUTTER

    def test_expected_function_count(self, bridge: CutterBridge) -> None:
        """Verify the tool function count is exact, unique, and fully backed.

        The declared count must equal :data:`_EXPECTED_TOOL_FUNC_COUNT`, the
        function names must be unique (no accidental duplicate exposure), and
        every counted function must resolve to a callable bound method on the
        bridge. Tying the count to uniqueness and method resolution means a
        regression that adds a phantom function name, duplicates one, or drops
        the backing method breaks this gate rather than silently passing.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        names = [f.name for f in td.functions]
        assert len(names) == _EXPECTED_TOOL_FUNC_COUNT
        assert len(set(names)) == _EXPECTED_TOOL_FUNC_COUNT
        backed = [n for n in names if callable(getattr(bridge, n.removeprefix("cutter."), None))]
        assert len(backed) == _EXPECTED_TOOL_FUNC_COUNT

    def test_all_expected_functions_present(self, bridge: CutterBridge) -> None:
        """Verify every expected function name is in the definition.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        names = {f.name for f in td.functions}
        assert len(names) == _EXPECTED_TOOL_FUNC_COUNT
        core_funcs = {
            "cutter.load_binary",
            "cutter.analyze",
            "cutter.get_functions",
            "cutter.decompile",
            "cutter.disassemble",
            "cutter.get_xrefs_to",
            "cutter.get_xrefs_from",
            "cutter.search_strings",
            "cutter.search_bytes",
            "cutter.get_imports",
            "cutter.get_exports",
            "cutter.get_sections",
            "cutter.rename_function",
            "cutter.add_comment",
            "cutter.write_bytes",
            "cutter.execute_command",
            "cutter.get_function",
            "cutter.search_bytes_wildcard",
            "cutter.assemble_at",
            "cutter.seek",
            "cutter.get_function_address",
            "cutter.get_function_graph",
            "cutter.get_all_strings",
            "cutter.get_symbols",
            "cutter.get_libraries",
            "cutter.get_headers",
            "cutter.get_debug_info",
            "cutter.get_classes",
            "cutter.get_relocations",
            "cutter.get_resources",
            "cutter.search_rop_gadgets",
            "cutter.get_callgraph",
            "cutter.get_vtables",
            "cutter.get_syscalls",
            "cutter.read_bytes",
            "cutter.save_binary",
            "cutter.get_comments",
            "cutter.get_flags",
            "cutter.add_flag",
            "cutter.resolve_flag",
        }
        assert core_funcs.issubset(names), f"Missing: {core_funcs - names}"

    def test_no_duplicate_cutter_assemble(self, bridge: CutterBridge) -> None:
        """Verify cutter.assemble (duplicate of assemble_at) was removed.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        names = [f.name for f in td.functions]
        assert "cutter.assemble" not in names

    def test_execute_command_not_execute(self, bridge: CutterBridge) -> None:
        """Verify the tool function is named execute_command, not execute.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        names = {f.name for f in td.functions}
        assert "cutter.execute" not in names
        assert "cutter.execute_command" in names

    def test_all_functions_have_descriptions(self, bridge: CutterBridge) -> None:
        """Verify every tool function has a non-trivial description.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        for func in td.functions:
            assert len(func.description) > _MIN_DESC_LEN, f"{func.name} description too short"

    def test_all_function_parameters_have_recognized_types(self, bridge: CutterBridge) -> None:
        """Verify every tool-function parameter declares a recognized schema type.

        A non-empty ``type`` string is insufficient: a parameter advertised
        with an unrecognized type (a parameterized generic, an optional union,
        or an arbitrary class name) cannot be serialized into a JSON Schema for
        LLM providers without information loss. This gate recomputes the
        validity of each declared type with the production
        :func:`is_recognized_type` oracle from :mod:`intellicrack.bridges.schemas`
        -- the same predicate the schema builder uses -- so a malformed type
        string fails here rather than silently degrading at provider-serialization
        time. Array parameters additionally have their ``items_type`` validated,
        since strict providers reject array element schemas with unrecognized
        element types.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        for func in td.functions:
            for param in func.parameters:
                assert param.type, f"Param {param.name} in {func.name} has no type"
                assert is_recognized_type(param.type), f"Param {param.name} in {func.name} has unrecognized type {param.type!r}"
                if normalize_type(param.type) == "array":
                    assert is_recognized_type(param.items_type), (
                        f"Array param {param.name} in {func.name} has unrecognized items_type {param.items_type!r}"
                    )

    def test_parameter_names_match_method_signatures(self, bridge: CutterBridge) -> None:
        """Verify tool_def parameter names match the Python method parameters.

        This is critical: execute_tool_call passes arguments as **kwargs,
        so the LLM parameter names MUST match the method parameter names.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        for func in td.functions:
            method_name = func.name.replace("cutter.", "")
            method = getattr(bridge, method_name)
            sig = inspect.signature(method)
            method_params = [p.name for p in sig.parameters.values() if p.name != "self"]
            tooldef_params = [p.name for p in func.parameters]
            assert tooldef_params == method_params[: len(tooldef_params)], (
                f"{func.name}: tool_def={tooldef_params} != method={method_params}"
            )


def _path_without_backends(path_value: str) -> str:
    """Return ``path_value`` with every directory holding a backend binary removed.

    Strips any PATH entry containing a real ``rizin``/``radare2`` executable so
    the genuine :meth:`CutterBridge.is_available` discovery path observes no
    backend, without mocking ``shutil.which``.

    Args:
        path_value: The ``os.pathsep``-joined PATH string to filter.

    Returns:
        str: PATH string with backend-bearing directories removed.
    """
    suffix = ".exe" if os.name == "nt" else ""
    kept: list[str] = []
    for entry in path_value.split(os.pathsep):
        if not entry:
            continue
        directory = Path(entry)
        has_backend = (directory / f"rizin{suffix}").exists() or (directory / f"radare2{suffix}").exists()
        if not has_backend:
            kept.append(entry)
    return os.pathsep.join(kept)


class TestInitialize:
    """Verify initialize() validates Rizin availability against the real backend."""

    @pytest.mark.asyncio
    async def test_raises_when_rizin_not_available(self, tmp_path: Path) -> None:
        """Verify initialize raises ToolError when no backend is discoverable.

        Drives the real :meth:`is_available` check: PATH is genuinely scrubbed
        of every rizin/radare2 directory and ``tool_path`` points at an empty
        directory holding no backend binary, so the bridge truly cannot find a
        backend. No ``shutil.which`` mock is involved, so the assertion gates
        the real discovery-and-failure path.

        Args:
            tmp_path: Temporary directory from pytest.
        """
        bridge = CutterBridge()
        empty_dir = tmp_path / "no_backend"
        empty_dir.mkdir()
        original_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = _path_without_backends(original_path)
            with pytest.raises(ToolError, match="cutter not available"):
                await bridge.initialize(tool_path=empty_dir)
        finally:
            os.environ["PATH"] = original_path

    @_requires_rizin
    @pytest.mark.asyncio
    async def test_stores_tool_path_modifies_env(self, tmp_path: Path) -> None:
        """Verify initialize prepends a real tool_path directory to PATH.

        Calls the genuine ``initialize`` with a real on-disk directory and
        asserts the directory becomes the first PATH entry, exercising the
        real environment-mutation branch with no patching.

        Args:
            tmp_path: Temporary directory from pytest.
        """
        bridge = CutterBridge()
        tool_dir = tmp_path / "rizin"
        tool_dir.mkdir()
        original_path = os.environ.get("PATH", "")
        try:
            await bridge.initialize(tool_path=tool_dir)
            first_entry = os.environ["PATH"].split(os.pathsep)[0]
            assert first_entry == str(tool_dir)
        finally:
            os.environ["PATH"] = original_path
            await bridge.shutdown()

    @_requires_rizin
    @pytest.mark.asyncio
    async def test_prepends_tool_dir_to_path(self, tmp_path: Path) -> None:
        """Verify initialize places the tool directory ahead of the prior PATH.

        Asserts both that the directory is prepended and that the previously
        present PATH content is preserved after it, proving the real prepend
        (rather than overwrite) semantics of ``initialize``.

        Args:
            tmp_path: Temporary directory from pytest.
        """
        bridge = CutterBridge()
        tool_dir = tmp_path / "rizin"
        tool_dir.mkdir()
        sentinel = tmp_path / "sentinel_marker_dir"
        sentinel.mkdir()
        original_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = str(sentinel) + os.pathsep + original_path
            await bridge.initialize(tool_path=tool_dir)
            entries = os.environ["PATH"].split(os.pathsep)
            assert entries[0] == str(tool_dir)
            assert str(sentinel) in entries[1:]
        finally:
            os.environ["PATH"] = original_path
            await bridge.shutdown()

    @_requires_rizin
    @pytest.mark.asyncio
    async def test_does_not_duplicate_path_entry(self, tmp_path: Path) -> None:
        """Verify initialize does not add the same directory twice to PATH.

        Pre-seeds PATH with the tool directory, then runs the real
        ``initialize``; the directory must appear exactly once afterwards,
        gating the real ``if tool_dir not in current_path`` dedup branch.

        Args:
            tmp_path: Temporary directory from pytest.
        """
        bridge = CutterBridge()
        tool_dir = tmp_path / "rizin"
        tool_dir.mkdir()
        tool_dir_str = str(tool_dir)
        original_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = tool_dir_str + os.pathsep + original_path
            await bridge.initialize(tool_path=tool_dir)
            entries = os.environ["PATH"].split(os.pathsep)
            assert entries.count(tool_dir_str) == 1
        finally:
            os.environ["PATH"] = original_path
            await bridge.shutdown()


class TestLoadBinary:
    """Verify load_binary handles string and Path inputs."""

    @_requires_rizin
    @pytest.mark.asyncio
    async def test_string_path_coerced_to_path(self, real_pe_dll: Path) -> None:
        """Verify load_binary accepts a string path and parses the real PE.

        Drives a real ``load_binary`` against ``kernel32.dll`` through the
        installed rizin backend. The returned :class:`BinaryInfo` is checked
        field-by-field against independently-known PE facts: the file name,
        the on-disk size (computed here, not from the bridge), the PE32+
        classification, the 64-bit flag, the resolved path type, and the
        presence of the canonical ``.text``/``.rdata`` sections every PE DLL
        carries. The string path must be coerced to a ``Path`` without error.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        stat_result = await asyncio.to_thread(real_pe_dll.stat)
        expected_size = stat_result.st_size
        bridge = CutterBridge()
        await bridge.initialize()
        try:
            info = await bridge.load_binary(str(real_pe_dll))
        finally:
            await bridge.shutdown()
        assert info.name == real_pe_dll.name
        assert info.size == expected_size
        assert info.file_type == "pe32+"
        assert info.is_64bit is True
        assert info.architecture == "x86"
        assert isinstance(info.path, Path)
        assert info.path.name == real_pe_dll.name
        section_names = {s.name for s in info.sections}
        assert ".text" in section_names
        assert ".rdata" in section_names

    @_requires_rizin
    @pytest.mark.asyncio
    async def test_path_object_accepted(self, real_pe_dll: Path) -> None:
        """Verify load_binary accepts a Path object and yields equal metadata.

        Loads the same real PE twice -- once via ``str`` and once via a
        ``Path`` -- and asserts the core identifying metadata is byte-for-byte
        equal across both input forms, proving the path-coercion branch leaves
        a ``Path`` argument's parse result indistinguishable from the string
        form rather than silently diverging.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        bridge_str = CutterBridge()
        await bridge_str.initialize()
        bridge_path = CutterBridge()
        await bridge_path.initialize()
        try:
            info_str = await bridge_str.load_binary(str(real_pe_dll))
            info_path = await bridge_path.load_binary(real_pe_dll)
        finally:
            await bridge_str.shutdown()
            await bridge_path.shutdown()
        assert info_path.name == info_str.name
        assert info_path.size == info_str.size
        assert info_path.file_type == info_str.file_type
        assert info_path.is_64bit == info_str.is_64bit
        assert info_path.architecture == info_str.architecture
        assert info_path.path == info_str.path

    @pytest.mark.asyncio
    async def test_nonexistent_path_raises(self, bridge: CutterBridge) -> None:
        """Verify load_binary raises ToolError for missing files.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="file not found"):
            await bridge.load_binary("/nonexistent/path/to/binary.exe")

    @pytest.mark.asyncio
    async def test_nonexistent_path_string_raises(self, bridge: CutterBridge) -> None:
        """Verify load_binary string path raises ToolError for missing files.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="file not found"):
            await bridge.load_binary(Path("/nonexistent/path/to/binary.exe"))


class TestSearchBytes:
    """Verify search_bytes handles both bytes and str input types."""

    @_requires_rizin
    @pytest.mark.asyncio
    async def test_string_hex_pattern(self, real_search_bridge: CutterBridge) -> None:
        """Verify search_bytes finds the exact occurrences of a spaced-hex pattern.

        Runs a real ``/x`` byte search through the installed rizin backend over
        a deterministic blob that the test itself planted with three copies of
        :data:`_MARKER` and one copy of :data:`_UNIQUE_MARKER`. The space-
        separated hex string must be cleaned and searched correctly: the marker
        result count must equal the count produced by an independent
        :func:`_count_occurrences` scan of the same blob (three), and the unique
        marker must be found exactly once. This gates the real search behaviour
        end to end, not merely the command string.

        Args:
            real_search_bridge: Bridge with the marker blob loaded via real rizin.
        """
        blob = _build_marker_blob()
        expected_markers = _count_occurrences(blob, _MARKER)
        assert expected_markers == len(_MARKER_OFFSETS)

        marker_hits = await real_search_bridge.search_bytes("DE AD BE EF")
        assert len(marker_hits) == expected_markers

        unique_hits = await real_search_bridge.search_bytes("CA FE 12 34")
        assert len(unique_hits) == _count_occurrences(blob, _UNIQUE_MARKER)
        assert len(unique_hits) == 1

    @_requires_rizin
    @pytest.mark.asyncio
    async def test_bytes_pattern(self, real_search_bridge: CutterBridge) -> None:
        """Verify bytes input is hex-encoded and yields the same hits as str input.

        Searches the same deterministic blob with raw ``bytes`` input and
        asserts the hit count matches the independent :func:`_count_occurrences`
        oracle, then asserts that the ``bytes`` form and the equivalent spaced-
        hex ``str`` form return an identical number of hits. An absent pattern
        must return an empty list. This proves the ``bytes.hex()`` encoding
        branch drives a real, correct search rather than a recorded command.

        Args:
            real_search_bridge: Bridge with the marker blob loaded via real rizin.
        """
        blob = _build_marker_blob()
        expected_markers = _count_occurrences(blob, _MARKER)

        bytes_hits = await real_search_bridge.search_bytes(_MARKER)
        assert len(bytes_hits) == expected_markers

        str_hits = await real_search_bridge.search_bytes("DE AD BE EF")
        assert len(bytes_hits) == len(str_hits)

        absent_hits = await real_search_bridge.search_bytes(_ABSENT_PATTERN)
        assert absent_hits == []

    @pytest.mark.asyncio
    async def test_no_binary_raises(self, bridge: CutterBridge) -> None:
        """Verify search_bytes raises ToolError when no binary loaded.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.search_bytes("90 90")


class TestWriteBytes:
    """Verify write_bytes accepts hex string and returns True."""

    @pytest.mark.asyncio
    async def test_returns_true(
        self,
        loaded_bridge: CutterBridge,
    ) -> None:
        """Verify write_bytes returns True on success.

        Args:
            loaded_bridge: Bridge with r2 session.
        """
        result = await loaded_bridge.write_bytes(_TEST_ADDRESS, "90909090")
        assert result is True

    @pytest.mark.asyncio
    async def test_strips_spaces_from_hex(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify write_bytes strips spaces from hex data before sending.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.write_bytes(_TEST_ADDRESS, "90 90 90 90")
        wx_cmds = [c for c in recorder.commands if c.startswith("wx")]
        assert len(wx_cmds) == 1
        assert "90909090" in wx_cmds[0]

    @pytest.mark.asyncio
    async def test_sends_correct_address(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify write_bytes includes the target address in the command.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.write_bytes(0xDEAD, "CC")
        wx_cmds = [c for c in recorder.commands if c.startswith("wx")]
        assert f"@ 57005" in wx_cmds[0]

    @pytest.mark.asyncio
    async def test_no_binary_raises(self, bridge: CutterBridge) -> None:
        """Verify write_bytes raises ToolError when no binary loaded.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.write_bytes(_TEST_ADDRESS, "90")


class TestAssembleAt:
    """Verify assemble_at uses pa command instead of standalone rasm2."""

    @pytest.mark.asyncio
    async def test_writes_at_address(
        self,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify assemble_at commits the validated hex via wx at the address.

        ``assemble_at`` dry-runs the encoding with ``pa`` and then commits a
        single ``wx <hex>`` write, rather than re-running the assembler with
        ``wa``, so the committed bytes match the validated encoding exactly.

        Args:
            recorder: Command recorder fixture.
        """
        recorder.responses["pa"] = "90"
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        await b.assemble_at(0x401000, "nop")
        wx_cmds = [c for c in recorder.commands if c.startswith("wx")]
        assert len(wx_cmds) == 1
        assert "90" in wx_cmds[0]
        assert f"@ 4198400" in wx_cmds[0]

    @pytest.mark.asyncio
    async def test_uses_pa_not_rasm2(
        self,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify assemble_at uses r2pipe pa command, not standalone rasm2.

        Args:
            recorder: Command recorder fixture.
        """
        recorder.responses["pa"] = "90"
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        await b.assemble_at(0x1000, "nop")
        pa_cmds = [c for c in recorder.commands if c.startswith("pa")]
        rasm2_cmds = [c for c in recorder.commands if c.startswith("rasm2")]
        assert len(pa_cmds) == 1
        assert not rasm2_cmds
        assert "nop" in pa_cmds[0]

    @pytest.mark.asyncio
    async def test_returns_assembled_bytes(
        self,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify assemble_at returns the assembled bytes.

        Args:
            recorder: Command recorder fixture.
        """
        recorder.responses["pa"] = "9090"
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        result = await b.assemble_at(0x1000, "nop; nop")
        assert result == b"\x90\x90"

    @pytest.mark.asyncio
    async def test_raises_on_failure(
        self,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify assemble_at raises ToolError when assembly fails.

        Args:
            recorder: Command recorder fixture.
        """
        recorder.responses["pa"] = "Cannot assemble"
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        with pytest.raises(ToolError, match="failed to assemble"):
            await b.assemble_at(0x1000, "invalid_instruction")


class TestAddComment:
    """Verify add_comment maps comment_type to Rizin commands."""

    @pytest.mark.asyncio
    async def test_eol_comment(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify EOL type uses CC command.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.add_comment(_TEST_ADDRESS, "test comment", "EOL")
        cc_cmds = [c for c in recorder.commands if "test comment" in c]
        assert len(cc_cmds) == 1
        assert cc_cmds[0].startswith("CC ")

    @pytest.mark.asyncio
    async def test_function_comment(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify function type uses CCf command.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.add_comment(_TEST_ADDRESS, "func note", "function")
        cc_cmds = [c for c in recorder.commands if "func note" in c]
        assert len(cc_cmds) == 1
        assert cc_cmds[0].startswith("CCf ")

    @pytest.mark.asyncio
    async def test_unique_comment(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify unique type uses CCu command.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.add_comment(_TEST_ADDRESS, "unique note", "unique")
        cc_cmds = [c for c in recorder.commands if "unique note" in c]
        assert len(cc_cmds) == 1
        assert cc_cmds[0].startswith("CCu ")

    @pytest.mark.asyncio
    async def test_default_comment_type(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify default comment type falls back to CC.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.add_comment(_TEST_ADDRESS, "default")
        cc_cmds = [c for c in recorder.commands if "default" in c]
        assert len(cc_cmds) == 1
        assert cc_cmds[0].startswith("CC ")

    @pytest.mark.asyncio
    async def test_returns_true(self, loaded_bridge: CutterBridge) -> None:
        """Verify add_comment returns True on success.

        Args:
            loaded_bridge: Bridge with r2 session.
        """
        result = await loaded_bridge.add_comment(_TEST_ADDRESS, "test")
        assert result is True

    @pytest.mark.asyncio
    async def test_escapes_quotes(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify add_comment escapes double quotes in comment text.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.add_comment(_TEST_ADDRESS, 'say "hello"')
        cc_cmds = [c for c in recorder.commands if "hello" in c]
        assert len(cc_cmds) == 1
        assert '\\"hello\\"' in cc_cmds[0]


class TestShutdownCleanup:
    """Verify shutdown() handles r2 quit errors gracefully."""

    @pytest.mark.asyncio
    async def test_nulls_r2_on_success(self) -> None:
        """Verify r2 is None after successful shutdown."""
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(_CommandRecorder())
        await bridge.shutdown()
        assert bridge.r2 is None

    @pytest.mark.asyncio
    async def test_nulls_r2_on_quit_failure(self) -> None:
        """Verify r2 is None even when quit() raises during shutdown."""
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(_FailingQuitR2())
        await bridge.shutdown()
        assert bridge.r2 is None

    @pytest.mark.asyncio
    async def test_does_not_propagate_quit_error(self) -> None:
        """Verify quit() RuntimeError is caught by shutdown, not propagated."""
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(_FailingQuitR2())
        await bridge.shutdown()

    @pytest.mark.asyncio
    async def test_noop_when_r2_is_none(self) -> None:
        """Verify shutdown is safe when r2 is already None."""
        bridge = CutterBridge()
        assert bridge.r2 is None
        await bridge.shutdown()
        assert bridge.r2 is None


class TestMethodsRequireBinaryLoaded:
    """Verify methods raise ToolError when no binary is loaded."""

    @pytest.mark.asyncio
    async def test_search_bytes_no_binary(self, bridge: CutterBridge) -> None:
        """Verify search_bytes raises when no binary.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.search_bytes("90")

    @pytest.mark.asyncio
    async def test_write_bytes_no_binary(self, bridge: CutterBridge) -> None:
        """Verify write_bytes raises when no binary.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.write_bytes(0, "90")

    @pytest.mark.asyncio
    async def test_execute_command_no_binary(self, bridge: CutterBridge) -> None:
        """Verify execute_command raises when no binary.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.execute_command("?V")

    @pytest.mark.asyncio
    async def test_decompile_no_binary(self, bridge: CutterBridge) -> None:
        """Verify decompile raises when no binary.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.decompile(_TEST_ADDRESS)


class TestMethodsRequireAnalysis:
    """Verify analysis-dependent methods raise ToolError when not analyzed."""

    @pytest.fixture
    def unanalyzed(self, recorder: _CommandRecorder) -> CutterBridge:
        """Create bridge with r2 session but not yet analyzed.

        Sets r2 via the public property setter; does NOT call analyze()
        so the bridge remains in the unanalyzed state.

        Args:
            recorder: Command recorder fixture.

        Returns:
            CutterBridge: Bridge with binary loaded but not analyzed.
        """
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        return b

    @pytest.mark.asyncio
    async def test_get_functions_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify get_functions raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.get_functions()

    @pytest.mark.asyncio
    async def test_disassemble_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify disassemble raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.disassemble(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_search_bytes_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify search_bytes raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.search_bytes("90")

    @pytest.mark.asyncio
    async def test_assemble_at_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify assemble_at raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.assemble_at(_TEST_ADDRESS, "nop")

    @pytest.mark.asyncio
    async def test_add_comment_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify add_comment raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.add_comment(_TEST_ADDRESS, "test")

    @pytest.mark.asyncio
    async def test_get_xrefs_to_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify get_xrefs_to raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.get_xrefs_to(_TEST_ADDRESS)


class TestGetExportsOrdinal:
    """Verify get_exports uses Rizin ordinal with index fallback."""

    @pytest.mark.asyncio
    async def test_uses_rizin_ordinal_when_present(self) -> None:
        """Verify ordinal from Rizin data is preferred over enumerate index."""
        rec = _CommandRecorder({
            "iEj": '[{"name":"Export1","vaddr":4096,"ordinal":42}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        await b.analyze()
        exports = await b.get_exports()
        assert len(exports) == 1
        assert exports[0].ordinal == 42

    @pytest.mark.asyncio
    async def test_falls_back_to_index_when_no_ordinal(self) -> None:
        """Verify enumerate index is used when Rizin has no ordinal field."""
        rec = _CommandRecorder({
            "iEj": '[{"name":"Export1","vaddr":4096}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        await b.analyze()
        exports = await b.get_exports()
        assert len(exports) == 1
        assert exports[0].ordinal == 0


class TestPermToRwx:
    """Verify perm_to_rwx converts permission integers to rwx strings."""

    def test_all_permissions(self) -> None:
        """Verify rwx for all-permissions (7)."""
        assert perm_to_rwx(7) == "rwx"

    def test_read_execute(self) -> None:
        """Verify r-x for read+execute (5)."""
        assert perm_to_rwx(5) == "r-x"

    def test_no_permissions(self) -> None:
        """Verify --- for no permissions (0)."""
        assert perm_to_rwx(0) == "---"

    def test_read_only(self) -> None:
        """Verify r-- for read-only (4)."""
        assert perm_to_rwx(4) == "r--"

    def test_write_only(self) -> None:
        """Verify -w- for write-only (2)."""
        assert perm_to_rwx(2) == "-w-"

    def test_execute_only(self) -> None:
        """Verify --x for execute-only (1)."""
        assert perm_to_rwx(1) == "--x"

    def test_read_write(self) -> None:
        """Verify rw- for read+write (6)."""
        assert perm_to_rwx(6) == "rw-"

    def test_write_execute(self) -> None:
        """Verify -wx for write+execute (3)."""
        assert perm_to_rwx(3) == "-wx"


class TestExecuteCommand:
    """Verify execute_command passes commands to r2."""

    @pytest.mark.asyncio
    async def test_passes_command_through(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify execute_command forwards the exact command string.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.execute_command("pd 10")
        assert "pd 10" in recorder.commands

    @pytest.mark.asyncio
    async def test_returns_command_output(self, recorder: _CommandRecorder) -> None:
        """Verify execute_command returns the r2 output.

        Args:
            recorder: Command recorder fixture.
        """
        recorder.responses["?V"] = "5.9.4"
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        result = await b.execute_command("?V")
        assert result == "5.9.4"


class _MetadataProbeBridge(CutterBridge):
    """Testing subclass exposing protected metadata extraction.

    Subclasses may access protected members of their parent, so this
    wrapper lets tests exercise ``_extract_binary_metadata`` without
    accessing a protected method from outside the class hierarchy.
    """

    async def extract_metadata(self) -> tuple[str, str, int, int]:
        """Expose the protected metadata extractor for tests.

        Returns:
            tuple[str, str, int, int]: Tuple of (file_type, arch, bits, entry_point).
        """
        return await self._extract_binary_metadata()


class TestEntryPointBug:
    """Verify entry point is not double-added with baddr (Bug 2 fix)."""

    @pytest.mark.asyncio
    async def test_entry_point_not_double_baddr(self) -> None:
        """Verify _extract_binary_metadata returns bin.entry directly."""
        rec = _CommandRecorder({
            "ij": '[{"bin":{"class":"PE","arch":"x86","bits":64,"baddr":4194304,"entry":4198400}}]',
            "itj": "[]",
            "iSj": "[]",
            "iij": "[]",
            "iEj": "[]",
        })
        b = _MetadataProbeBridge()
        b.r2 = _as_r2pipe(rec)
        _, _, _, entry = await b.extract_metadata()
        assert entry == 4198400


class TestSaveBinary:
    """Verify save_binary sends wtf command (Bug 3 fix)."""

    @pytest.mark.asyncio
    async def test_sends_wcf_command(
        self,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify save_binary writes the full IO cache via wcf to the path.

        ``save_binary`` uses ``wcf <file>`` (write cache to file) so the
        entire patched IO image is emitted, rather than ``wtf`` which dumps
        only the current 256-byte block.

        Args:
            recorder: Command recorder fixture.
        """
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        output_path = f"{tempfile.gettempdir()}/output.exe"
        result = await b.save_binary(output_path)
        assert result is True
        wcf_cmds = [c for c in recorder.commands if c.startswith("wcf")]
        assert len(wcf_cmds) == 1
        assert output_path in wcf_cmds[0]


class TestGetSymbols:
    """Verify get_symbols returns SymbolInfo objects."""

    @pytest.mark.asyncio
    async def test_returns_symbol_info(self) -> None:
        """Verify get_symbols parses isj output correctly."""
        rec = _CommandRecorder({
            "isj": '[{"name":"main","vaddr":4096,"libname":""}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        symbols = await b.get_symbols()
        assert len(symbols) == 1
        assert symbols[0].name == "main"
        assert symbols[0].address == 4096

    @pytest.mark.asyncio
    async def test_no_binary_raises(self, bridge: CutterBridge) -> None:
        """Verify get_symbols raises when no binary.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.get_symbols()


class TestReadBytes:
    """Verify read_bytes returns raw bytes."""

    @pytest.mark.asyncio
    async def test_returns_bytes(self) -> None:
        r"""Verify read_bytes converts the p8 hex response to the exact byte value.

        Independent oracle: the recorder is pre-loaded to return the hex string
        "48 8b 05" for the p8 command prefix.  bytes.fromhex("48 8b 05") equals
        b"\x48\x8b\x05", so the bridge must return that exact value and must have
        issued "p8 3 @ 4096" to the session.  Mutation caught: returning b"" or
        any incorrect byte sequence, or emitting the wrong command form, would
        fail the exact-value or command assertions.
        """
        rec = _CommandRecorder({
            "p8": "48 8b 05",
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.read_bytes(0x1000, 3)
        assert result == b"\x48\x8b\x05"
        assert f"p8 3 @ 4096" in rec.commands

    @pytest.mark.asyncio
    async def test_sends_p8_command(self) -> None:
        """Verify read_bytes sends p8 command with count and address."""
        rec = _CommandRecorder({
            "p8": "90",
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        await b.read_bytes(0x1000, 1)
        p8_cmds = [c for c in rec.commands if c.startswith("p8")]
        assert len(p8_cmds) == 1
        assert "1" in p8_cmds[0]
        assert f"@ 4096" in p8_cmds[0]


class TestGetFlags:
    """Verify get_flags returns FlagInfo objects."""

    @pytest.mark.asyncio
    async def test_returns_flag_info(self) -> None:
        """Verify get_flags parses fj output correctly."""
        rec = _CommandRecorder({
            "fj": '[{"name":"entry0","offset":4096,"size":1}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        flags = await b.get_flags()
        assert len(flags) == 1
        assert flags[0].name == "entry0"
        assert flags[0].address == 4096
        assert flags[0].size == 1


class TestAddFlag:
    """Verify add_flag sends f command."""

    @pytest.mark.asyncio
    async def test_sends_f_command(self) -> None:
        """Verify add_flag sends the correct Rizin command."""
        rec = _CommandRecorder()
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.add_flag("test_flag", 4, 0x1000)
        assert result is True
        f_cmds = [c for c in rec.commands if c.startswith("f ")]
        assert len(f_cmds) == 1
        assert "test_flag" in f_cmds[0]
        assert f"@ 4096" in f_cmds[0]


class TestGetComments:
    """Verify get_comments returns CommentInfo objects."""

    @pytest.mark.asyncio
    async def test_returns_comment_info(self) -> None:
        """Verify get_comments parses CCj output correctly."""
        rec = _CommandRecorder({
            "CCj": '[{"offset":4096,"name":"test comment","type":"inline"}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        comments = await b.get_comments()
        assert len(comments) == 1
        assert comments[0].address == 4096
        assert comments[0].text == "test comment"


class TestHexdump:
    """Verify hexdump returns string output."""

    @pytest.mark.asyncio
    async def test_sends_px_command(self) -> None:
        """Verify hexdump issues the exact px command and returns the raw response string.

        Independent oracle: the recorder is pre-loaded to return a known hexdump
        string for the px command prefix.  The bridge must (1) emit exactly
        "px 128 @ 4096" and (2) return the recorder-provided string verbatim without
        modification.  Mutation caught: issuing "pxw 128 @ 4096" instead of
        "px 128 @ 4096" would fail the command assertion; truncating or modifying
        the output would fail the content assertion.
        """
        rec = _CommandRecorder({
            "px": "- offset -   0 1  2 3\n0x00001000  9090 9090",
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.hexdump(0x1000, 128)
        assert result == "- offset -   0 1  2 3\n0x00001000  9090 9090"
        assert f"px 128 @ 4096" in rec.commands


class TestGetBasicBlocks:
    """Verify get_basic_blocks returns BlockInfo objects."""

    @pytest.mark.asyncio
    async def test_returns_block_info(self) -> None:
        """Verify get_basic_blocks parses afbj output correctly."""
        rec = _CommandRecorder({
            "afbj": '[{"addr":4096,"size":20,"jump":4116,"fail":null,"ops":[]}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        blocks = await b.get_basic_blocks(0x1000)
        assert len(blocks) == 1
        assert blocks[0].address == 4096
        assert blocks[0].size == 20
        assert blocks[0].jump == 4116


class TestEsilOps:
    """Verify ESIL emulation operations."""

    @pytest.mark.asyncio
    async def test_esil_eval(self) -> None:
        """Verify esil_eval sends ae command."""
        rec = _CommandRecorder({
            "ae": "0x42",
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.esil_eval("1,1,+")
        assert isinstance(result, str)
        ae_cmds = [c for c in rec.commands if c.startswith("ae ")]
        assert len(ae_cmds) == 1

    @pytest.mark.asyncio
    async def test_esil_init_memory(self) -> None:
        """Verify esil_init_memory sends aeim command."""
        rec = _CommandRecorder()
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.esil_init_memory()
        assert result is True
        assert "aeim" in rec.commands


class TestGetConfig:
    """Verify configuration get/set operations."""

    @pytest.mark.asyncio
    async def test_get_config(self) -> None:
        """Verify get_config reads a configuration value."""
        rec = _CommandRecorder({
            "e asm.arch": "x86",
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.get_config("asm.arch")
        assert result == "x86"

    @pytest.mark.asyncio
    async def test_set_config(self) -> None:
        """Verify set_config sends e key=value command."""
        rec = _CommandRecorder()
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.set_config("asm.arch", "arm")
        assert result is True
        e_cmds = [c for c in rec.commands if "asm.arch=arm" in c]
        assert len(e_cmds) == 1
