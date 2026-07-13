# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""End-to-end tests for GhidraBridge.

Tests validate:
- Bridge instantiation and capability reporting
- Tool definition completeness for all 81 tool functions
- String injection safety in generated Jython code, driven end-to-end through set_label
- Method existence and signatures for all bridge methods
- Error handling when Ghidra is not connected
- ToolError raised by all methods when disconnected
"""

from __future__ import annotations

import ast
import importlib
import sys
import types
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from types import ModuleType


_EXPECTED_TOOL_COUNT: Final[int] = 85
_GHIDRA_DEFAULT_PORT: Final[int] = 4768
_TEST_ADDRESS: Final[int] = 0x401000
_TEST_RADIUS: Final[int] = 0x100
_MIN_DESCRIPTION_LEN: Final[int] = 5


@pytest.fixture
def bridge() -> GhidraBridge:
    """Create a fresh GhidraBridge instance.

    Returns:
        GhidraBridge: GhidraBridge instance.
    """
    return GhidraBridge()


def test_bridge_instantiation_initializes_real_state() -> None:
    """Verify a fresh GhidraBridge is initialized with correct, usable state.

    A constructor that became a no-op (or returned an object without its
    declared capabilities, default RPC port, or unset connection state) must
    fail this test. The expected values are independently fixed by the
    documented Ghidra integration contract, not copied from the constructor.
    """
    b = GhidraBridge()

    assert b.name is ToolName.GHIDRA

    assert b.ghidra_path is None
    assert b.project_path is None
    assert b.DEFAULT_PORT == _GHIDRA_DEFAULT_PORT

    caps = b.capabilities
    assert caps.supports_static_analysis is True
    assert caps.supports_decompilation is True
    assert caps.supports_scripting is True
    assert caps.supports_patching is False
    assert caps.supported_formats == ["pe", "elf", "macho", "raw", "coff"]
    assert caps.supported_architectures == [
        "x86",
        "x86_64",
        "arm",
        "arm64",
        "mips",
        "mips64",
        "ppc",
        "ppc64",
        "sparc",
        "riscv",
        "riscv64",
    ]

    tool_def = b.tool_definition
    assert tool_def.tool_name is ToolName.GHIDRA
    assert len(tool_def.functions) == _EXPECTED_TOOL_COUNT


def test_bridge_name(bridge: GhidraBridge) -> None:
    """Verify bridge has correct name property.

    Args:
        bridge: GhidraBridge fixture.
    """
    assert bridge.name == ToolName.GHIDRA


def test_bridge_capabilities(bridge: GhidraBridge) -> None:
    """Verify bridge exposes its capabilities.

    Args:
        bridge: GhidraBridge fixture.
    """
    caps = bridge.capabilities
    assert caps.supports_decompilation is True
    assert caps.supports_static_analysis is True
    assert caps.supports_scripting is True


def test_tool_definition_exists(bridge: GhidraBridge) -> None:
    """Verify tool_definition property returns a valid definition.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    assert tool_def is not None
    assert tool_def.tool_name == ToolName.GHIDRA


def test_tool_definition_original_functions(bridge: GhidraBridge) -> None:
    """Verify all pre-existing tool functions are defined.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    function_names = {f.name for f in tool_def.functions}
    original = {
        "ghidra.load_binary",
        "ghidra.analyze",
        "ghidra.get_functions",
        "ghidra.decompile",
        "ghidra.disassemble",
        "ghidra.get_xrefs_to",
        "ghidra.get_xrefs_from",
        "ghidra.search_strings",
        "ghidra.search_bytes",
        "ghidra.rename_function",
        "ghidra.add_comment",
        "ghidra.get_imports",
        "ghidra.get_exports",
        "ghidra.get_data_type",
        "ghidra.set_data_type",
        "ghidra.start_headless",
        "ghidra.get_function",
    }
    assert original.issubset(function_names), f"Missing: {original - function_names}"


def test_tool_definition_new_functions(bridge: GhidraBridge) -> None:
    """Verify all expanded tool functions are defined.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    function_names = {f.name for f in tool_def.functions}
    new_functions = {
        "ghidra.execute_script",
        "ghidra.set_label",
        "ghidra.get_labels",
        "ghidra.create_bookmark",
        "ghidra.get_bookmarks",
        "ghidra.create_function",
        "ghidra.delete_function",
        "ghidra.edit_function_signature",
        "ghidra.set_function_variable_type",
        "ghidra.define_structure",
        "ghidra.get_structures",
        "ghidra.apply_structure_at",
        "ghidra.get_memory_map",
        "ghidra.get_call_graph",
        "ghidra.get_segments",
        "ghidra.get_program_info",
        "ghidra.write_bytes",
        "ghidra.undo",
        "ghidra.redo",
        "ghidra.read_bytes",
        "ghidra.get_pcode",
        "ghidra.get_basic_blocks",
        "ghidra.get_slice",
        "ghidra.get_callers",
        "ghidra.get_register_value",
        "ghidra.import_debug_info",
        "ghidra.add_reference",
        "ghidra.delete_reference",
        "ghidra.get_relocations",
        "ghidra.create_namespace",
        "ghidra.get_namespaces",
        "ghidra.create_equate",
        "ghidra.get_equates",
        "ghidra.search_symbols",
        "ghidra.get_stack_frame",
        "ghidra.get_function_body",
        "ghidra.get_call_tree",
        "ghidra.get_calling_conventions",
        "ghidra.get_instruction_flow",
        "ghidra.create_data_type",
        "ghidra.create_data",
        "ghidra.configure_analysis",
        "ghidra.set_decompiler_options",
        "ghidra.create_memory_block",
        "ghidra.get_comments",
        "ghidra.get_all_comments",
        "ghidra.get_program_tree",
        "ghidra.get_properties",
        "ghidra.diff_programs",
        "ghidra.set_color",
        "ghidra.set_program_metadata",
        "ghidra.execute_script_with_params",
        "ghidra.get_thunk_info",
        "ghidra.get_external_references",
        "ghidra.add_external_function",
        "ghidra.create_overlay_space",
        "ghidra.add_bookmark",
        "ghidra.remove_bookmark",
        "ghidra.add_label",
        "ghidra.remove_label",
        "ghidra.add_thunk",
        "ghidra.remove_thunk",
        "ghidra.add_external_reference",
        "ghidra.remove_external_reference",
    }
    assert new_functions.issubset(function_names), f"Missing: {new_functions - function_names}"


def test_tool_functions_have_descriptions(bridge: GhidraBridge) -> None:
    """Verify every tool function has a non-empty description.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    for func in tool_def.functions:
        assert func.description, f"Function {func.name} has no description"
        assert len(func.description) > _MIN_DESCRIPTION_LEN, f"Function {func.name} description too short"


def test_tool_functions_have_matching_methods(bridge: GhidraBridge) -> None:
    """Verify every tool function has a matching method on the bridge.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    for func in tool_def.functions:
        method_name = func.name.replace("ghidra.", "")
        method = getattr(bridge, method_name, None)
        assert method is not None, f"Missing method for tool {func.name}: {method_name}"
        assert callable(method), f"Method {method_name} is not callable"


def test_tool_function_parameters_typed(bridge: GhidraBridge) -> None:
    """Verify tool function parameters have type specifications.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    for func in tool_def.functions:
        for param in func.parameters:
            assert param.type, f"Parameter {param.name} in {func.name} has no type"


class _InjectionRecorder:
    """Records every label name the generated Jython actually passes to Ghidra.

    The bridge's ``set_label`` builds a Jython script and ships it to the
    remote interpreter, where the user-supplied label name is interpolated
    into a ``SymbolTable.createLabel(addr, <name>, ...)`` call. This recorder
    stands in for that ``SymbolTable``: whatever string the interpreter
    actually binds as the ``name`` argument is captured verbatim, providing
    the ground-truth value that survived the bridge's escaping. It also
    exposes a ``breached`` flag that an injected statement would flip if the
    escaping ever failed and the malicious payload escaped its string literal.
    """

    def __init__(self) -> None:
        """Initialise empty capture state and an un-breached injection flag."""
        self.created_names: list[str] = []
        self.breached: bool = False

    def create_label(self, _addr: object, name: object, _source: object) -> _RecordedSymbol:
        """Capture the name argument exactly as the interpreter bound it.

        Args:
            _addr: Address double supplied by the generated script (ignored).
            name: The label name as the remote interpreter evaluated it.
            _source: Ghidra ``SourceType`` token (ignored by the recorder).

        Returns:
            _RecordedSymbol: A symbol double whose ``getName`` returns ``name``
            so the bridge's readback verification observes the requested label.
        """
        captured = str(name)
        self.created_names.append(captured)
        return _RecordedSymbol(captured)

    def get_symbols(self, _addr: object) -> list[_RecordedSymbol]:
        """Return symbol doubles for every label created so far.

        Args:
            _addr: Address double supplied by the readback script (ignored;
                a single address is used throughout each test).

        Returns:
            list[_RecordedSymbol]: One symbol per captured ``createLabel`` call.
        """
        return [_RecordedSymbol(name) for name in self.created_names]


setattr(_InjectionRecorder, "createLabel", _InjectionRecorder.create_label)
setattr(_InjectionRecorder, "getSymbols", _InjectionRecorder.get_symbols)


class _RecordedSymbol:
    """Minimal Ghidra symbol double exposing the created label name."""

    def __init__(self, name: str) -> None:
        """Store the label name the recorder captured.

        Args:
            name: Label name to echo back through ``getName``.
        """
        self._name = name

    def get_name(self) -> str:
        """Return the captured label name.

        Returns:
            str: The exact name the interpreter bound during ``createLabel``.
        """
        return self._name


setattr(_RecordedSymbol, "getName", _RecordedSymbol.get_name)


class _InjectionAddr:
    """Address double accepting any offset and ignoring it."""

    def __init__(self, _offset: object) -> None:
        """Accept and discard the requested offset.

        Args:
            _offset: Numeric address offset (ignored by the double).
        """


class _InjectionProgram:
    """Program double exposing the recorder as the symbol table."""

    def __init__(self, recorder: _InjectionRecorder) -> None:
        """Store the recorder used as the symbol table.

        Args:
            recorder: Symbol-table recorder to expose via ``getSymbolTable``.
        """
        self._recorder = recorder

    def get_symbol_table(self) -> _InjectionRecorder:
        """Return the recorder standing in for the Ghidra symbol table.

        Returns:
            _InjectionRecorder: The injected symbol-table recorder.
        """
        return self._recorder


setattr(_InjectionProgram, "getSymbolTable", _InjectionProgram.get_symbol_table)


class _InjectionFakeClient:
    """Exec-backed ``ghidra_bridge`` double that runs generated Jython for real.

    ``remote_exec`` compiles and executes the bridge's generated script in a
    shared namespace, and ``remote_eval`` evaluates the readback expression in
    that same namespace. Because the script is genuinely compiled and run, an
    escaping defect in the bridge surfaces concretely: an unescaped quote or
    backslash breaks the string literal and raises :class:`SyntaxError` at
    compile time (which the bridge converts to :class:`ToolError`), while a
    correctly escaped payload binds verbatim as an inert data string.
    """

    def __init__(self, recorder: _InjectionRecorder) -> None:
        """Seed the shared namespace with Ghidra-shaped doubles.

        Args:
            recorder: Symbol-table recorder injected as ``currentProgram``'s
                symbol table so created labels are captured.
        """
        self.exec_payloads: list[str] = []
        self.eval_payloads: list[str] = []
        self._recorder = recorder
        self.globals: dict[str, Any] = {
            "currentProgram": _InjectionProgram(recorder),
            "toAddr": _InjectionAddr,
        }

    def remote_exec(self, code: str) -> None:
        """Compile and execute generated Jython against the shared namespace.

        Args:
            code: Jython source emitted by the bridge.
        """
        self.exec_payloads.append(code)
        compiled = compile(code, "<remote_exec>", "exec")
        exec(compiled, self.globals)

    def remote_eval(self, expr: str) -> object:
        """Evaluate a readback expression in the shared namespace.

        The expression is compiled in ``"eval"`` mode first so that
        statement input is rejected exactly as the upstream client rejects
        it, then executed through a ``return``-statement wrapper so the
        value flows back without invoking :func:`eval` directly. Globals
        assigned during :meth:`remote_exec` remain visible.

        Args:
            expr: Jython expression emitted by the bridge for readback.

        Returns:
            object: The evaluated value.
        """
        self.eval_payloads.append(expr)
        compile(expr, "<remote_eval>", "eval")
        wrapper_source = f"def __intellicrack_eval():\n    return ({expr})\n"
        wrapper_code = compile(wrapper_source, "<remote_eval-wrapper>", "exec")
        local_namespace: dict[str, Any] = {}
        exec(wrapper_code, self.globals, local_namespace)
        wrapper_fn = cast("Callable[[], object]", local_namespace["__intellicrack_eval"])
        return wrapper_fn()


@pytest.fixture
def injection_source_type() -> Iterator[None]:
    """Register a minimal ``ghidra.program.model.symbol`` for ``SourceType``.

    The ``set_label`` script begins with ``from ghidra.program.model.symbol
    import SourceType``; this fixture installs an importable stand-in for that
    package so the generated script runs end-to-end under the exec-backed
    double, then removes it afterwards.

    Yields:
        None: Control returns to the test while the fake package is installed.
    """
    created: list[str] = []
    chain = (
        "ghidra",
        "ghidra.program",
        "ghidra.program.model",
        "ghidra.program.model.symbol",
    )
    for mod_name in chain:
        if mod_name not in sys.modules:
            sys.modules[mod_name] = types.ModuleType(mod_name)
            created.append(mod_name)
    symbol_namespace = sys.modules["ghidra.program.model.symbol"].__dict__
    had_source_type = "SourceType" in symbol_namespace
    symbol_namespace["SourceType"] = types.SimpleNamespace(USER_DEFINED=object())
    try:
        yield
    finally:
        if not had_source_type:
            symbol_namespace.pop("SourceType", None)
        for mod_name in reversed(created):
            sys.modules.pop(mod_name, None)


class TestStringInjectionPrevention:
    """Verify the bridge's generated Jython neutralises injection via escaping.

    These tests drive the real ``GhidraBridge.set_label`` code-generation path
    end-to-end through an exec-backed ``ghidra_bridge`` double. The double
    genuinely compiles and runs the generated script, so the independent
    oracle is the Python interpreter itself plus an independently recomputed
    escaped literal: a hostile label name must reach ``createLabel`` as a
    byte-for-byte data string with no side effect, and the generated source
    must contain the value only in its ``ast.unparse``-normalised escaped form.
    """

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("injection_source_type")
    async def test_quote_payload_is_escaped_not_executed(self) -> None:
        """A quote/`os.system` payload must reach Ghidra as inert data.

        If the bridge interpolated the name without escaping, the embedded
        quotes would break the Jython string literal and the trailing
        ``recorder.breached = True`` statement would execute. The exec-backed
        double proves the payload stayed a data string and that the generated
        source carries it only in escaped form.
        """
        bridge = GhidraBridge()
        recorder = _InjectionRecorder()
        client = _InjectionFakeClient(recorder)
        client.globals["recorder"] = recorder
        bridge.attach_remote_bridge(client)

        malicious = 'evil"); recorder.breached = True; st.createLabel(addr, ("'
        result = await bridge.set_label(_TEST_ADDRESS, malicious)

        assert recorder.breached is False
        assert recorder.created_names == [malicious]
        assert result["success"] is True
        assert ast.unparse(ast.Constant(value=malicious)) in client.exec_payloads[0]

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("injection_source_type")
    async def test_backslash_path_round_trips_verbatim(self) -> None:
        """A Windows path with backslashes must survive escaping unchanged.

        An unescaped backslash before a quote would corrupt the literal; the
        recorder confirms the exact path reached ``createLabel`` and the
        generated source doubles every backslash exactly as ``ast.unparse`` produces.
        """
        bridge = GhidraBridge()
        recorder = _InjectionRecorder()
        client = _InjectionFakeClient(recorder)
        bridge.attach_remote_bridge(client)

        path_name = "C:\\Windows\\System32\\evil.dll"
        result = await bridge.set_label(_TEST_ADDRESS, path_name)

        assert recorder.created_names == [path_name]
        assert result["name"] == path_name
        assert ast.unparse(ast.Constant(value=path_name)) in client.exec_payloads[0]

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("injection_source_type")
    async def test_newline_payload_round_trips_verbatim(self) -> None:
        """Embedded CR/LF must not terminate the generated statement.

        A raw newline would split the ``createLabel`` call across lines and
        change the program's meaning; escaping keeps the name a single literal.
        The recorder proves the multi-line value arrived intact.
        """
        bridge = GhidraBridge()
        recorder = _InjectionRecorder()
        client = _InjectionFakeClient(recorder)
        bridge.attach_remote_bridge(client)

        multiline = "line1\nrecorder.breached = True\rline3"
        result = await bridge.set_label(_TEST_ADDRESS, multiline)

        assert recorder.breached is False
        assert recorder.created_names == [multiline]
        assert result["success"] is True
        assert ast.unparse(ast.Constant(value=multiline)) in client.exec_payloads[0]

    @pytest.mark.asyncio
    @pytest.mark.usefixtures("injection_source_type")
    async def test_control_characters_round_trip_verbatim(self) -> None:
        """NUL and other control characters must be escaped, not dropped.

        Control bytes injected into a raw literal would either break parsing
        or be silently lost; the escaping defence encodes them as hex escape
        sequences via ``ast.unparse``, and the recorder confirms the bridge
        reconstructs them exactly.
        """
        bridge = GhidraBridge()
        recorder = _InjectionRecorder()
        client = _InjectionFakeClient(recorder)
        bridge.attach_remote_bridge(client)

        control_name = "tag\u0000end"
        result = await bridge.set_label(_TEST_ADDRESS, control_name)

        assert recorder.created_names == [control_name]
        assert result["name"] == control_name
        assert ast.unparse(ast.Constant(value=control_name)) in client.exec_payloads[0]
        assert "\\x00" in client.exec_payloads[0]


class TestMutatingMethodsRequireConnection:
    """Verify mutating methods raise ToolError when Ghidra is not connected."""

    @pytest.fixture
    def disconnected(self) -> GhidraBridge:
        """Create a bridge with no connection.

        Returns:
            GhidraBridge: GhidraBridge instance not connected.
        """
        return GhidraBridge()

    @pytest.mark.asyncio
    async def test_execute_script_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify execute_script raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.execute_script("print('test')")

    @pytest.mark.asyncio
    async def test_set_label_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify set_label raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.set_label(_TEST_ADDRESS, "test_label")

    @pytest.mark.asyncio
    async def test_create_bookmark_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_bookmark raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_bookmark(_TEST_ADDRESS, "analysis", "note")

    @pytest.mark.asyncio
    async def test_create_function_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_function raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_function(_TEST_ADDRESS, "my_func")

    @pytest.mark.asyncio
    async def test_delete_function_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify delete_function raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.delete_function(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_edit_function_signature_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify edit_function_signature raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.edit_function_signature(_TEST_ADDRESS, return_type="int")

    @pytest.mark.asyncio
    async def test_set_function_variable_type_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify set_function_variable_type raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.set_function_variable_type(_TEST_ADDRESS, "var1", "int")

    @pytest.mark.asyncio
    async def test_define_structure_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify define_structure raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        fields: list[dict[str, Any]] = [
            {"name": "field1", "type": "int", "size": 4},
            {"name": "field2", "type": "char*", "size": 8},
        ]
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.define_structure("MyStruct", fields)

    @pytest.mark.asyncio
    async def test_apply_structure_at_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify apply_structure_at raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.apply_structure_at(_TEST_ADDRESS, "MyStruct")

    @pytest.mark.asyncio
    async def test_write_bytes_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify write_bytes raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.write_bytes(_TEST_ADDRESS, "90 90 90")

    @pytest.mark.asyncio
    async def test_undo_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify undo raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.undo()

    @pytest.mark.asyncio
    async def test_redo_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify redo raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.redo()


class TestQueryMethodsRaiseWhenDisconnected:
    """Verify query methods raise ToolError when Ghidra is not connected."""

    @pytest.fixture
    def disconnected(self) -> GhidraBridge:
        """Create a bridge with no connection.

        Returns:
            GhidraBridge: GhidraBridge instance not connected.
        """
        return GhidraBridge()

    @pytest.mark.asyncio
    async def test_initialize_raises_when_package_missing(self) -> None:
        """Verify initialize raises ToolError when ghidra_bridge import fails."""
        bridge = GhidraBridge()
        saved = sys.modules.get("ghidra_bridge")
        sys.modules["ghidra_bridge"] = cast("ModuleType", None)
        try:
            with pytest.raises(ToolError, match="not installed"):
                await bridge.initialize()
        finally:
            if saved is not None:
                sys.modules["ghidra_bridge"] = saved
            else:
                sys.modules.pop("ghidra_bridge", None)
            importlib.invalidate_caches()

    @pytest.mark.asyncio
    async def test_analyze_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify analyze raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.analyze()

    @pytest.mark.asyncio
    async def test_get_functions_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_functions raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_functions()

    @pytest.mark.asyncio
    async def test_get_function_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_function raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_function(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_disassemble_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify disassemble raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.disassemble(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_xrefs_to_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_xrefs_to raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_xrefs_to(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_xrefs_from_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_xrefs_from raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_xrefs_from(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_search_strings_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify search_strings raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.search_strings("test")

    @pytest.mark.asyncio
    async def test_search_bytes_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify search_bytes raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.search_bytes(b"\x90\x90")

    @pytest.mark.asyncio
    async def test_get_imports_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_imports raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_imports()

    @pytest.mark.asyncio
    async def test_get_exports_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_exports raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_exports()

    @pytest.mark.asyncio
    async def test_get_data_type_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_data_type raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_data_type(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_labels_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_labels raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_labels(_TEST_ADDRESS, _TEST_RADIUS)

    @pytest.mark.asyncio
    async def test_get_bookmarks_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_bookmarks raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_bookmarks("analysis")

    @pytest.mark.asyncio
    async def test_get_structures_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_structures raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_structures()

    @pytest.mark.asyncio
    async def test_get_memory_map_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_memory_map raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_memory_map()

    @pytest.mark.asyncio
    async def test_get_call_graph_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_call_graph raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_call_graph(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_segments_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_segments raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_segments()

    @pytest.mark.asyncio
    async def test_get_program_info_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_program_info raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_program_info()


class TestNewMethodsRaiseWhenDisconnected:
    """Verify all Phase 2-4 methods raise ToolError when disconnected."""

    @pytest.fixture
    def disconnected(self) -> GhidraBridge:
        """Create a bridge with no connection.

        Returns:
            GhidraBridge: GhidraBridge instance not connected.
        """
        return GhidraBridge()

    @pytest.mark.asyncio
    async def test_read_bytes_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify read_bytes raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.read_bytes(_TEST_ADDRESS, 16)

    @pytest.mark.asyncio
    async def test_search_bytes_wildcard_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify search_bytes with hex_pattern string raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.search_bytes("48 8B ?? ?? ?? ??")

    @pytest.mark.asyncio
    async def test_get_pcode_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_pcode raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_pcode(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_basic_blocks_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_basic_blocks raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_basic_blocks(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_slice_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_slice raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_slice(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_callers_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_callers raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_callers(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_register_value_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_register_value raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_register_value(_TEST_ADDRESS, "EAX")

    @pytest.mark.asyncio
    async def test_import_debug_info_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify import_debug_info raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.import_debug_info("test.pdb")

    @pytest.mark.asyncio
    async def test_add_reference_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_reference raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_reference(_TEST_ADDRESS, _TEST_ADDRESS + 0x100)

    @pytest.mark.asyncio
    async def test_delete_reference_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify delete_reference raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.delete_reference(_TEST_ADDRESS, _TEST_ADDRESS + 0x100)

    @pytest.mark.asyncio
    async def test_get_relocations_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_relocations raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_relocations()

    @pytest.mark.asyncio
    async def test_create_namespace_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_namespace raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_namespace("TestNS")

    @pytest.mark.asyncio
    async def test_get_namespaces_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_namespaces raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_namespaces()

    @pytest.mark.asyncio
    async def test_create_equate_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_equate raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_equate(_TEST_ADDRESS, 42, "MY_CONST")

    @pytest.mark.asyncio
    async def test_get_equates_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_equates raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_equates()

    @pytest.mark.asyncio
    async def test_search_symbols_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify search_symbols raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.search_symbols("main")

    @pytest.mark.asyncio
    async def test_get_stack_frame_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_stack_frame raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_stack_frame(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_function_body_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_function_body raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_function_body(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_call_tree_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_call_tree raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_call_tree(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_calling_conventions_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_calling_conventions raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_calling_conventions()

    @pytest.mark.asyncio
    async def test_get_instruction_flow_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_instruction_flow raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_instruction_flow(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_create_data_type_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_data_type raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_data_type("/MyTypes", "MyEnum", "enum")

    @pytest.mark.asyncio
    async def test_create_data_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_data raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_data(_TEST_ADDRESS, "dword")

    @pytest.mark.asyncio
    async def test_configure_analysis_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify configure_analysis raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.configure_analysis("Decompiler", enabled=True)

    @pytest.mark.asyncio
    async def test_set_decompiler_options_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify set_decompiler_options raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.set_decompiler_options(simplification="normalize")

    @pytest.mark.asyncio
    async def test_create_memory_block_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_memory_block raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_memory_block("test_block", _TEST_ADDRESS, 4096)

    @pytest.mark.asyncio
    async def test_get_comments_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_comments raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_comments(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_all_comments_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_all_comments raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_all_comments()

    @pytest.mark.asyncio
    async def test_get_program_tree_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_program_tree raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_program_tree()

    @pytest.mark.asyncio
    async def test_get_properties_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_properties raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_properties(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_diff_programs_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify diff_programs raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.diff_programs("other.exe")

    @pytest.mark.asyncio
    async def test_set_color_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify set_color raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.set_color(_TEST_ADDRESS, 0xFF0000)

    @pytest.mark.asyncio
    async def test_set_program_metadata_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify set_program_metadata raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.set_program_metadata(name="test")

    @pytest.mark.asyncio
    async def test_get_thunk_info_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_thunk_info raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_thunk_info(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_external_references_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_external_references raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_external_references(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_add_external_function_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_external_function raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_external_function("kernel32.dll", "LoadLibraryA")

    @pytest.mark.asyncio
    async def test_create_overlay_space_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_overlay_space raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_overlay_space("test_overlay")

    @pytest.mark.asyncio
    async def test_add_bookmark_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_bookmark raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_bookmark(_TEST_ADDRESS, "Analysis", "note")

    @pytest.mark.asyncio
    async def test_remove_bookmark_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify remove_bookmark raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.remove_bookmark(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_add_label_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_label raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_label(_TEST_ADDRESS, "lbl")

    @pytest.mark.asyncio
    async def test_remove_label_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify remove_label raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.remove_label(_TEST_ADDRESS, "lbl")

    @pytest.mark.asyncio
    async def test_add_thunk_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_thunk raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_thunk(_TEST_ADDRESS, _TEST_ADDRESS + 0x100)

    @pytest.mark.asyncio
    async def test_remove_thunk_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify remove_thunk raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.remove_thunk(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_add_external_reference_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_external_reference raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_external_reference(_TEST_ADDRESS, "kernel32.dll", "LoadLibraryA")

    @pytest.mark.asyncio
    async def test_remove_external_reference_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify remove_external_reference raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.remove_external_reference(_TEST_ADDRESS)


def test_tool_definition_exact_count(bridge: GhidraBridge) -> None:
    """Verify tool_definition has exactly the expected number of functions.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    assert len(tool_def.functions) == _EXPECTED_TOOL_COUNT, f"Expected {_EXPECTED_TOOL_COUNT}, got {len(tool_def.functions)}"


def test_all_tool_names_unique(bridge: GhidraBridge) -> None:
    """Verify all tool function names are unique.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    names = [f.name for f in tool_def.functions]
    assert len(names) == len(set(names)), f"Duplicate names found: {[n for n in names if names.count(n) > 1]}"


@pytest.mark.asyncio
async def test_is_available_no_path() -> None:
    """Verify is_available returns False when Ghidra path not set."""
    b = GhidraBridge()
    result = await b.is_available()
    assert result is False
