# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GHIDRA-B wave-2a: real falsifiable gates for CFG/pcode/flow/slice/callgraph/frames.

Methods gated (all were disconnected-state-only before this file):
  get_pcode, get_basic_blocks, get_instruction_flow, get_slice, get_callers,
  get_program_tree, get_properties, get_register_value, get_stack_frame.

Methods skipped (already REAL in section-02 audit):
  get_call_graph (test_f0011_call_graph_uses_get_called_functions in test_ghidra_audit6.py)
  get_call_tree  (test_f0011_call_tree_uses_get_called_functions  in test_ghidra_audit6.py)

The test seam is a self-contained ``_FakeBridgeClient`` that mirrors the
upstream ``BridgeClient.remote_exec`` / ``remote_eval`` contract.  Fake Ghidra
domain objects are injected into ``fake.globals`` so that the real bridge method
script runs end-to-end against known values. Assertions cover both the exact
return-value structure (independent oracle) and the Ghidra API framing present
in the emitted script (mutation guard).
"""

from __future__ import annotations

import asyncio
import sys
import types
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.bridges.ghidra import GhidraBridge


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine


_TEST_ADDRESS: Final[int] = 0x401000
_TEST_CALLER_ENTRY: Final[int] = 0x402000
_TEST_CALL_SITE: Final[int] = 0x402010
_TEST_FALL_THROUGH: Final[int] = 0x401005
_TEST_FLOW_TARGET: Final[int] = 0x403000


class _FakeBridgeClient:
    """In-process double for the upstream ``ghidra_bridge`` client.

    Mirrors the ``remote_exec`` / ``remote_eval`` contract that
    ``_execute_remote`` depends on.  Both methods share a single globals dict
    so variables assigned by ``remote_exec`` are visible to a follow-up
    ``remote_eval``, matching real bridge semantics.
    """

    def __init__(self) -> None:
        """Initialise the shared global namespace."""
        self.globals: dict[str, Any] = {}
        self.exec_payloads: list[str] = []
        self.eval_payloads: list[str] = []

    def remote_exec(self, code: str) -> None:
        """Execute ``code`` against the shared globals via :func:`exec`.

        Args:
            code: Python source to execute.
        """
        self.exec_payloads.append(code)
        compiled = compile(code, "<remote_exec>", "exec")
        exec(compiled, self.globals)

    def remote_eval(self, expr: str) -> object:
        """Evaluate ``expr`` against the shared globals.

        Args:
            expr: Python expression to evaluate.

        Returns:
            object: Deserialized expression value.
        """
        self.eval_payloads.append(expr)
        compile(expr, "<remote_eval>", "eval")
        wrapper_source = f"def __intellicrack_test_eval():\n    return ({expr})\n"
        wrapper_code = compile(wrapper_source, "<remote_eval-wrapper>", "exec")
        local_namespace: dict[str, Any] = {}
        exec(wrapper_code, self.globals, local_namespace)
        wrapper_fn: Any = local_namespace["__intellicrack_test_eval"]
        return wrapper_fn()


class _FakeIterator:
    """Java-style hasNext/next iterator double for Ghidra collection returns."""

    def __init__(self, items: list[object]) -> None:
        """Initialise with the items to iterate.

        Args:
            items: Sequence of items to return on successive ``next()`` calls.
        """
        self._items: list[object] = list(items)
        self._pos: int = 0
        self.hasNext = lambda: self._pos < len(self._items)
        self.next = self._advance

    def _advance(self) -> object:
        """Return the current item and advance the internal cursor.

        Returns:
            object: The next item in the sequence.
        """
        item = self._items[self._pos]
        self._pos += 1
        return item


@pytest.fixture
def bridge_with_fake() -> tuple[GhidraBridge, _FakeBridgeClient]:
    """Wire a ``GhidraBridge`` to a deterministic fake RPC client.

    Returns:
        tuple[GhidraBridge, _FakeBridgeClient]: Live bridge plus the fake
        client for direct introspection.
    """
    bridge = GhidraBridge()
    fake = _FakeBridgeClient()
    bridge.attach_remote_bridge(fake)
    return bridge, fake


def _run(coro: Coroutine[Any, Any, object]) -> object:
    """Run an async coroutine to completion in a fresh event loop.

    Args:
        coro: Coroutine to run.

    Returns:
        object: Return value of the coroutine.
    """
    return asyncio.run(coro)


def test_get_instruction_flow_returns_call_flow_payload(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """get_instruction_flow must map mnemonic/flow_type/fall_through/flows to exact keys.

    Independent oracle: the fake listing returns a single instruction whose
    fields have known values.  The bridge script must read them via the Ghidra
    Listing API and pack them under the canonical key names.

    Mutation caught: renaming the ``mnemonic`` key to ``opcode`` in the
    returned dict — or using ``instr.getFlowType()`` as the mnemonic — would
    make the exact-value assertions fail.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeFlowType:
        """Fake FlowType whose str representation is the expected value."""

        def __str__(self) -> str:
            """Return the flow type string.

            Returns:
                str: Canonical flow type name.
            """
            return "UNCONDITIONAL_CALL"

    class _FakeAddr:
        """Fake Ghidra address for flow and fall-through offsets."""

        def __init__(self, off: int) -> None:
            """Initialise with address offset.

            Args:
                off: Numeric address offset.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    class _FakeInstr:
        """Fake instruction with known flow information."""

        def __init__(self) -> None:
            """Initialise with known mnemonic and flow targets."""
            self.getMnemonicString = lambda: "CALL"
            self.getFlowType = _FakeFlowType
            self.getFallThrough = lambda: _FakeAddr(_TEST_FALL_THROUGH)
            self.getFlows = lambda: [_FakeAddr(_TEST_FLOW_TARGET)]

    class _FakeListing:
        """Fake program listing."""

        def __init__(self, instr: object) -> None:
            """Initialise with the instruction to return.

            Args:
                instr: Instruction object returned for any address.
            """
            self._instr: object = instr
            self.getInstructionAt: Callable[[object], object] = lambda _a: self._instr

    class _FakeProgram:
        """Fake currentProgram."""

        def __init__(self, listing: _FakeListing) -> None:
            """Initialise with a fake listing.

            Args:
                listing: Listing double to expose.
            """
            self._listing: _FakeListing = listing
            self.getListing = lambda: self._listing

    fake_instr = _FakeInstr()
    fake.globals["currentProgram"] = _FakeProgram(_FakeListing(fake_instr))
    fake.globals["toAddr"] = _FakeAddr

    result = _run(bridge.get_instruction_flow(_TEST_ADDRESS))

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["address"] == _TEST_ADDRESS
    assert payload["mnemonic"] == "CALL"
    assert payload["flow_type"] == "UNCONDITIONAL_CALL"
    assert payload["fall_through"] == _TEST_FALL_THROUGH
    assert payload["flows"] == [_TEST_FLOW_TARGET]

    exec_src = fake.exec_payloads[0]
    assert "getListing" in exec_src
    assert "getInstructionAt" in exec_src


def test_get_instruction_flow_null_instruction_returns_null_payload(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """Null-instruction path must return None mnemonic and empty flows list.

    Mutation caught: returning a filled payload when ``getInstructionAt``
    returns ``None`` would produce a non-null mnemonic.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeAddr:
        """Fake address."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    class _FakeListing:
        """Listing that returns None for every instruction query."""

        def __init__(self) -> None:
            """Initialise."""
            self.getInstructionAt: Callable[[object], None] = lambda _a: None

    class _FakeProgram:
        """Fake program."""

        def __init__(self) -> None:
            """Initialise."""
            self.getListing = _FakeListing

    fake.globals["currentProgram"] = _FakeProgram()
    fake.globals["toAddr"] = _FakeAddr

    result = _run(bridge.get_instruction_flow(_TEST_ADDRESS))

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["address"] == _TEST_ADDRESS
    assert payload["mnemonic"] is None
    assert payload["flow_type"] is None
    assert payload["fall_through"] is None
    assert payload["flows"] == []


def test_get_stack_frame_returns_exact_frame_layout(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """get_stack_frame must map frame_size and each variable to the exact dict keys.

    Independent oracle: the fake function exposes a stack frame with one
    variable whose name, offset, size, and data-type string are known.

    Mutation caught: using ``v.getOffset()`` instead of ``v.getStackOffset()``
    for the variable offset field — or placing the frame size under ``size``
    instead of ``frame_size`` — would produce wrong values.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeDataType:
        """Fake data type whose str representation is the type name."""

        def __str__(self) -> str:
            """Return type name.

            Returns:
                str: Data type descriptor string.
            """
            return "int"

    class _FakeStackVar:
        """Fake stack variable with known fields."""

        def __init__(self) -> None:
            """Initialise with deterministic field values."""
            self.getName = lambda: "local_var"
            self.getStackOffset = lambda: -8
            self.getLength = lambda: 4
            self.getDataType = _FakeDataType

    class _FakeStackFrame:
        """Fake stack frame with one variable and a known size."""

        def __init__(self) -> None:
            """Initialise."""
            var = _FakeStackVar()
            self.getStackVariables = lambda: [var]
            self.getFrameSize = lambda: 32

    class _FakeAddr:
        """Fake address."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    class _FakeFunction:
        """Fake function exposing a stack frame."""

        def __init__(self) -> None:
            """Initialise."""
            self.getName = lambda: "target_fn"
            self.getStackFrame = _FakeStackFrame

    def _get_stack_fn(_a: object) -> _FakeFunction:
        return _FakeFunction()

    fake.globals["toAddr"] = _FakeAddr
    fake.globals["getFunctionContaining"] = _get_stack_fn

    result = _run(bridge.get_stack_frame(_TEST_ADDRESS))

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["function"] == "target_fn"
    assert payload["frame_size"] == 32
    variables = cast("list[dict[str, Any]]", payload["variables"])
    assert len(variables) == 1
    var = variables[0]
    assert var["name"] == "local_var"
    assert var["offset"] == -8
    assert var["size"] == 4
    assert var["type"] == "int"

    exec_src = fake.exec_payloads[0]
    assert "getStackFrame" in exec_src
    assert "getStackOffset" in exec_src


def test_get_stack_frame_function_not_found_returns_empty(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """Null-function path must return empty variables list and zero frame_size.

    Mutation caught: returning non-zero frame_size when ``getFunctionContaining``
    returns ``None``.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeAddr:
        """Fake address."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    def _get_no_fn(_a: object) -> None:
        return None

    fake.globals["toAddr"] = _FakeAddr
    fake.globals["getFunctionContaining"] = _get_no_fn

    result = _run(bridge.get_stack_frame(_TEST_ADDRESS))

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["function"] is None
    assert payload["frame_size"] == 0
    assert payload["variables"] == []


def test_get_register_value_returns_known_register_payload(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """get_register_value must pack address, register, value, and has_value correctly.

    Independent oracle: the fake program context returns a register value of 42
    for the ``EAX`` query.

    Mutation caught: dropping the ``has_value`` key from the result dict, or
    placing the numeric value under ``register_value`` instead of ``value``.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeRegVal:
        """Fake RegisterValue returning a known unsigned integer."""

        def __init__(self) -> None:
            """Initialise."""
            self.getUnsignedValue = lambda: 42

    class _FakeProgramContext:
        """Fake ProgramContext that resolves EAX to a non-None register."""

        def __init__(self) -> None:
            """Initialise."""
            self._reg_val = _FakeRegVal()
            self.getRegister: Callable[[str], object | None] = lambda name: object() if name == "EAX" else None
            self.getRegisterValue: Callable[[object, object], _FakeRegVal] = lambda _reg, _addr: self._reg_val

    class _FakeAddr:
        """Fake address."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    class _FakeProgram:
        """Fake currentProgram."""

        def __init__(self) -> None:
            """Initialise."""
            self.getProgramContext = _FakeProgramContext

    fake.globals["currentProgram"] = _FakeProgram()
    fake.globals["toAddr"] = _FakeAddr

    result = _run(bridge.get_register_value(_TEST_ADDRESS, "EAX"))

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["address"] == _TEST_ADDRESS
    assert payload["register"] == "EAX"
    assert payload["value"] == 42
    assert payload["has_value"] is True

    exec_src = fake.exec_payloads[0]
    assert "getProgramContext" in exec_src
    assert "getRegisterValue" in exec_src


def test_get_register_value_unknown_register_has_value_false(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """Unknown register must yield has_value=False and value=None.

    Mutation caught: returning ``has_value=True`` when
    ``ctx.getRegister(name)`` returns ``None``.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeProgramContext:
        """Fake ProgramContext that always returns None for any register."""

        def __init__(self) -> None:
            """Initialise."""
            self.getRegister: Callable[[object], None] = lambda _name: None
            self.getRegisterValue: Callable[[object, object], None] = lambda _reg, _addr: None

    class _FakeAddr:
        """Fake address."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    class _FakeProgram:
        """Fake currentProgram."""

        def __init__(self) -> None:
            """Initialise."""
            self.getProgramContext = _FakeProgramContext

    fake.globals["currentProgram"] = _FakeProgram()
    fake.globals["toAddr"] = _FakeAddr

    result = _run(bridge.get_register_value(_TEST_ADDRESS, "UNKNOWN_REG"))

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["has_value"] is False
    assert payload["value"] is None


def test_get_callers_returns_caller_info_dict(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """get_callers must populate caller_address, caller_function, call_site, ref_type.

    Independent oracle: the fake reference list has one call reference whose
    from-address, caller-function name, and ref-type string are all known.

    Mutation caught: using ``from_addr`` instead of ``call_site`` as the dict key
    for the call-site address — or dropping ``caller_function`` — would fail.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeAddr:
        """Fake address double."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    class _FakeRefType:
        """Fake reference type that reports as a call."""

        def __init__(self) -> None:
            """Initialise."""
            self.isCall = lambda: True

        def __str__(self) -> str:
            """Return the reference type name.

            Returns:
                str: Reference type descriptor.
            """
            return "UNCONDITIONAL_CALL"

    class _FakeCallerFunc:
        """Fake function object for the caller."""

        def __init__(self) -> None:
            """Initialise."""
            self._entry = _FakeAddr(_TEST_CALLER_ENTRY)
            self.getEntryPoint = lambda: self._entry
            self.getName = lambda: "caller_fn"

    class _FakeRef:
        """Fake cross-reference that represents a call instruction."""

        def __init__(self) -> None:
            """Initialise."""
            self._ref_type = _FakeRefType()
            self._from_addr = _FakeAddr(_TEST_CALL_SITE)
            self.getReferenceType = lambda: self._ref_type
            self.getFromAddress = lambda: self._from_addr

    caller_func = _FakeCallerFunc()
    ref = _FakeRef()

    def _get_refs_to(_addr: object) -> list[object]:
        return [ref]

    def _get_caller_fn(_addr: object) -> _FakeCallerFunc:
        return caller_func

    fake.globals["toAddr"] = _FakeAddr
    fake.globals["getReferencesTo"] = _get_refs_to
    fake.globals["getFunctionContaining"] = _get_caller_fn

    result = _run(bridge.get_callers(_TEST_ADDRESS))

    assert isinstance(result, list)
    callers = cast("list[dict[str, Any]]", result)
    assert len(callers) == 1
    entry = callers[0]
    assert entry["caller_address"] == _TEST_CALLER_ENTRY
    assert entry["caller_function"] == "caller_fn"
    assert entry["call_site"] == _TEST_CALL_SITE
    assert entry["ref_type"] == "UNCONDITIONAL_CALL"

    exec_src = fake.exec_payloads[0]
    assert "getReferencesTo" in exec_src
    assert "isCall" in exec_src


def test_get_callers_non_call_ref_excluded(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """Non-call references must be filtered out of the callers list.

    Mutation caught: removing the ``isCall()`` guard in the script so that
    data references are included in the result.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeAddr:
        """Fake address."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    class _FakeDataRefType:
        """Fake reference type that does NOT report as a call."""

        def __init__(self) -> None:
            """Initialise."""
            self.isCall = lambda: False

    class _FakeDataRef:
        """Fake data cross-reference."""

        def __init__(self) -> None:
            """Initialise."""
            self.getReferenceType = _FakeDataRefType
            self.getFromAddress = lambda: _FakeAddr(0x500000)

    def _get_data_refs(_addr: object) -> list[object]:
        return [_FakeDataRef()]

    def _get_no_fn_callers(_addr: object) -> None:
        return None

    fake.globals["toAddr"] = _FakeAddr
    fake.globals["getReferencesTo"] = _get_data_refs
    fake.globals["getFunctionContaining"] = _get_no_fn_callers

    result = _run(bridge.get_callers(_TEST_ADDRESS))

    assert result == []


def test_get_properties_returns_address_and_properties_map(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """get_properties must include the queried address and a populated properties map.

    Independent oracle: the fake property manager has one named property with
    a known object value at the test address.

    Mutation caught: dropping the ``address`` key from the result dict, or
    using ``prop_value`` instead of the property name as the key in the nested
    ``properties`` dict.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeAddr:
        """Fake address."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    class _FakePropMap:
        """Fake property map that returns a known string value."""

        def __init__(self) -> None:
            """Initialise."""
            self.hasProperty: Callable[[object], bool] = lambda _addr: True
            self.getObject: Callable[[object], str] = lambda _addr: "advanced"

    class _FakeUsrPropertyManager:
        """Fake user property manager with one property."""

        def __init__(self) -> None:
            """Initialise."""
            self._prop_map = _FakePropMap()
            self.propertyNames = lambda: ["analysis.level"]
            self.getPropertyMap: Callable[[object], _FakePropMap] = lambda _name: self._prop_map

    class _FakeProgram:
        """Fake currentProgram."""

        def __init__(self) -> None:
            """Initialise."""
            self.getUsrPropertyManager = _FakeUsrPropertyManager

    fake.globals["currentProgram"] = _FakeProgram()
    fake.globals["toAddr"] = _FakeAddr

    result = _run(bridge.get_properties(_TEST_ADDRESS))

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["address"] == _TEST_ADDRESS
    props = cast("dict[str, Any]", payload["properties"])
    assert props["analysis.level"] == "advanced"

    exec_src = fake.exec_payloads[0]
    assert "getUsrPropertyManager" in exec_src
    assert "propertyNames" in exec_src


def test_get_pcode_returns_known_pcode_ops(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """get_pcode must return a dict with function name and a pcode_ops list.

    Independent oracle: the fake decompiler produces one P-code op with
    address ``_TEST_ADDRESS``, opcode 1, mnemonic ``COPY``, one output
    varnode (space ``ram``, offset 0x10, size 4), and one input varnode
    (space ``const``, offset 1, size 4).

    Mutation caught: placing the list under ``operations`` instead of
    ``pcode_ops``, or reading mnemonic via ``getDescription()`` instead of
    ``getMnemonic()``.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeAddrSpace:
        """Fake address space."""

        def __init__(self, name: str) -> None:
            """Initialise.

            Args:
                name: Space name.
            """
            self._name: str = name
            self.getName = lambda: self._name

    class _FakeVarnodeAddr:
        """Fake varnode address combining space and offset."""

        def __init__(self, space_name: str, off: int) -> None:
            """Initialise.

            Args:
                space_name: Address space name.
                off: Offset within the space.
            """
            self._space = _FakeAddrSpace(space_name)
            self._off: int = off
            self.getAddressSpace = lambda: self._space
            self.getOffset = lambda: self._off

    class _FakeVarnode:
        """Fake varnode (P-code variable)."""

        def __init__(self, space_name: str, off: int, size: int) -> None:
            """Initialise.

            Args:
                space_name: Address space name.
                off: Address offset.
                size: Varnode size in bytes.
            """
            self._addr = _FakeVarnodeAddr(space_name, off)
            self._size: int = size
            self.getAddress = lambda: self._addr
            self.getSize = lambda: self._size
            self.getDef = lambda: None

    class _FakeSeqnum:
        """Fake PcodeOp sequence number."""

        def __init__(self, target_off: int) -> None:
            """Initialise.

            Args:
                target_off: Target instruction address offset.
            """

            class _FakeTarget:
                """Inner target address."""

                def __init__(self, off: int) -> None:
                    """Initialise.

                    Args:
                        off: Address offset.
                    """
                    self._off: int = off
                    self.getOffset = lambda: self._off

            self._target = _FakeTarget(target_off)
            self.getTarget = lambda: self._target

    class _FakePcodeOp:
        """Fake P-code operation with one output and one input varnode."""

        def __init__(self) -> None:
            """Initialise with deterministic field values."""
            out_vn = _FakeVarnode("ram", 0x10, 4)
            in_vn = _FakeVarnode("const", 1, 4)
            self._inputs: list[object] = [in_vn]
            self._seqnum = _FakeSeqnum(_TEST_ADDRESS)
            self.getSeqnum = lambda: self._seqnum
            self.getOpcode = lambda: 1
            self.getMnemonic = lambda: "COPY"
            self.getOutput = lambda: out_vn
            self.getNumInputs = lambda: len(self._inputs)
            self.getInput: Callable[[int], object] = lambda idx: self._inputs[idx]

    class _FakeHighFunction:
        """Fake HighFunction exposing one P-code op iterator."""

        def __init__(self) -> None:
            """Initialise."""
            self._op = _FakePcodeOp()
            self.getPcodeOps = lambda: _FakeIterator([self._op])

    class _FakeDecompResult:
        """Fake decompile result that always succeeds."""

        def __init__(self) -> None:
            """Initialise."""
            self._hfunc = _FakeHighFunction()
            self.decompileCompleted = lambda: True
            self.getHighFunction = lambda: self._hfunc

    class _FakeDecompIfc:
        """Fake DecompInterface."""

        def __init__(self) -> None:
            """Initialise."""
            self.openProgram: Callable[[object], None] = lambda _prog: None
            self.decompileFunction: Callable[[object, object, object], _FakeDecompResult] = lambda _fn, _t, _m: _FakeDecompResult()

    class _FakeAddr:
        """Fake address."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    class _FakeFunction:
        """Fake Ghidra function."""

        def __init__(self) -> None:
            """Initialise."""
            self.getName = lambda: "pcode_fn"

    decompiler_mod = types.ModuleType("ghidra.app.decompiler")
    setattr(decompiler_mod, "DecompInterface", _FakeDecompIfc)
    sys.modules.setdefault("ghidra", types.ModuleType("ghidra"))
    sys.modules.setdefault("ghidra.app", types.ModuleType("ghidra.app"))
    sys.modules["ghidra.app.decompiler"] = decompiler_mod

    def _get_pcode_fn(_a: object) -> _FakeFunction:
        return _FakeFunction()

    fake.globals["currentProgram"] = object()
    fake.globals["toAddr"] = _FakeAddr
    fake.globals["getFunctionContaining"] = _get_pcode_fn
    fake.globals["monitor"] = object()

    try:
        result = _run(bridge.get_pcode(_TEST_ADDRESS, max_ops=10))
    finally:
        sys.modules.pop("ghidra.app.decompiler", None)
        sys.modules.pop("ghidra.app", None)
        sys.modules.pop("ghidra", None)

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["function"] == "pcode_fn"
    ops = cast("list[dict[str, Any]]", payload["pcode_ops"])
    assert len(ops) == 1
    op = ops[0]
    assert op["address"] == _TEST_ADDRESS
    assert op["opcode"] == 1
    assert op["mnemonic"] == "COPY"
    output = cast("dict[str, Any]", op["output"])
    assert output["space"] == "ram"
    assert output["offset"] == 0x10
    assert output["size"] == 4
    inputs = cast("list[dict[str, Any]]", op["inputs"])
    assert len(inputs) == 1
    assert inputs[0]["space"] == "const"
    assert inputs[0]["offset"] == 1

    exec_src = fake.exec_payloads[0]
    assert "DecompInterface" in exec_src
    assert "getPcodeOps" in exec_src
    assert "getMnemonic" in exec_src


def test_get_pcode_function_not_found_returns_empty_ops(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """Null-function path must return pcode_ops=[] and function=None.

    Mutation caught: returning a non-empty pcode_ops list when
    ``getFunctionContaining`` returns ``None``.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeDecompIfc:
        """Fake DecompInterface that is never actually called."""

        def __init__(self) -> None:
            """Initialise."""
            self.openProgram: Callable[[object], None] = lambda _prog: None

    class _FakeAddr:
        """Fake address."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    decompiler_mod = types.ModuleType("ghidra.app.decompiler")
    setattr(decompiler_mod, "DecompInterface", _FakeDecompIfc)
    sys.modules.setdefault("ghidra", types.ModuleType("ghidra"))
    sys.modules.setdefault("ghidra.app", types.ModuleType("ghidra.app"))
    sys.modules["ghidra.app.decompiler"] = decompiler_mod

    def _get_no_pcode_fn(_a: object) -> None:
        return None

    fake.globals["currentProgram"] = object()
    fake.globals["toAddr"] = _FakeAddr
    fake.globals["getFunctionContaining"] = _get_no_pcode_fn
    fake.globals["monitor"] = object()

    try:
        result = _run(bridge.get_pcode(_TEST_ADDRESS))
    finally:
        sys.modules.pop("ghidra.app.decompiler", None)
        sys.modules.pop("ghidra.app", None)
        sys.modules.pop("ghidra", None)

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["function"] is None
    assert payload["pcode_ops"] == []


def test_get_basic_blocks_returns_block_structure(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """get_basic_blocks must map each block to start/end/sources/destinations.

    Independent oracle: the fake block model returns one basic block with
    known start (``_TEST_ADDRESS``), end (``_TEST_ADDRESS + 0x0f``),
    sources ``[0x400ff0]``, and destinations ``[0x401020]``.

    Mutation caught: swapping ``sources`` and ``destinations`` in the returned
    block dict, or using ``block.getStart()`` instead of ``block.getMinAddress()``
    for the start offset.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    block_start: int = _TEST_ADDRESS
    block_end: int = _TEST_ADDRESS + 0x0F
    source_addr: int = 0x400FF0
    dest_addr: int = 0x401020

    class _FakeAddr:
        """Fake Ghidra address."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    class _FakeSourceRef:
        """Fake block source reference."""

        def __init__(self) -> None:
            """Initialise."""
            self._src_addr = _FakeAddr(source_addr)
            self.getSourceAddress = lambda: self._src_addr

    class _FakeDestRef:
        """Fake block destination reference."""

        def __init__(self) -> None:
            """Initialise."""
            self._dst_addr = _FakeAddr(dest_addr)
            self.getDestinationAddress = lambda: self._dst_addr

    class _FakeBlock:
        """Fake basic block with one source and one destination."""

        def __init__(self) -> None:
            """Initialise."""
            self._min = _FakeAddr(block_start)
            self._max = _FakeAddr(block_end)
            self.getMinAddress = lambda: self._min
            self.getMaxAddress = lambda: self._max
            self.getSources: Callable[[object], _FakeIterator] = lambda _mon: _FakeIterator([_FakeSourceRef()])
            self.getDestinations: Callable[[object], _FakeIterator] = lambda _mon: _FakeIterator([_FakeDestRef()])

    class _FakeAddrRange:
        """Fake address range covering the test block."""

        def __init__(self) -> None:
            """Initialise."""
            self._min = _FakeAddr(block_start)
            self.getMinAddress = lambda: self._min

    class _FakeFuncBody:
        """Fake function body yielding one address range."""

        def __init__(self) -> None:
            """Initialise."""
            self._range = _FakeAddrRange()
            self.getAddressRanges = lambda: _FakeIterator([self._range])

    class _FakeFunction:
        """Fake function with a body and a name."""

        def __init__(self) -> None:
            """Initialise."""
            self._body = _FakeFuncBody()
            self.getName = lambda: "block_fn"
            self.getBody = lambda: self._body

    class _FakeBasicBlockModel:
        """Fake BasicBlockModel constructor callable."""

        def __init__(self, _prog: object) -> None:
            """Initialise (program argument accepted but ignored).

            Args:
                _prog: Ghidra program (ignored by this test double).
            """
            self._block = _FakeBlock()
            self.getCodeBlocksContaining: Callable[[object, object], _FakeIterator] = lambda _addr, _mon: _FakeIterator([self._block])

    block_mod = types.ModuleType("ghidra.program.model.block")
    setattr(block_mod, "BasicBlockModel", _FakeBasicBlockModel)
    sys.modules.setdefault("ghidra", types.ModuleType("ghidra"))
    sys.modules.setdefault("ghidra.program", types.ModuleType("ghidra.program"))
    sys.modules.setdefault("ghidra.program.model", types.ModuleType("ghidra.program.model"))
    sys.modules["ghidra.program.model.block"] = block_mod

    def _get_block_fn(_a: object) -> _FakeFunction:
        return _FakeFunction()

    fake.globals["currentProgram"] = object()
    fake.globals["toAddr"] = _FakeAddr
    fake.globals["getFunctionContaining"] = _get_block_fn
    fake.globals["monitor"] = object()

    try:
        result = _run(bridge.get_basic_blocks(_TEST_ADDRESS, max_blocks=10))
    finally:
        sys.modules.pop("ghidra.program.model.block", None)
        sys.modules.pop("ghidra.program.model", None)
        sys.modules.pop("ghidra.program", None)
        sys.modules.pop("ghidra", None)

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["function"] == "block_fn"
    blocks = cast("list[dict[str, Any]]", payload["blocks"])
    assert len(blocks) == 1
    blk = blocks[0]
    assert blk["start"] == block_start
    assert blk["end"] == block_end
    assert blk["sources"] == [source_addr]
    assert blk["destinations"] == [dest_addr]

    exec_src = fake.exec_payloads[0]
    assert "BasicBlockModel" in exec_src
    assert "getMinAddress" in exec_src
    assert "getSources" in exec_src
    assert "getDestinations" in exec_src


def test_get_slice_backward_returns_known_ops(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """get_slice backward must populate slice_addresses and slice_pcode_ops.

    Independent oracle: the fake decompiler produces one P-code op at
    ``_TEST_ADDRESS`` with opcode 5 and mnemonic ``INT_ADD``.  A backward
    slice from that op (with no input defines) yields exactly that one op.

    Mutation caught: returning an empty ``slice_addresses`` list when a valid
    target op exists at the queried address.

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeAddr:
        """Fake address."""

        def __init__(self, off: int) -> None:
            """Initialise.

            Args:
                off: Offset value.
            """
            self._off: int = off
            self.getOffset = lambda: self._off

    class _FakeSeqnum:
        """Fake sequence number."""

        def __init__(self) -> None:
            """Initialise."""
            self._target = _FakeAddr(_TEST_ADDRESS)
            self.getTarget = lambda: self._target

        def __str__(self) -> str:
            """Return a unique key string.

            Returns:
                str: Unique sequence key.
            """
            return f"seq_{_TEST_ADDRESS}"

    class _FakeSliceOp:
        """Fake P-code op for slice traversal (no inputs, so slice terminates)."""

        def __init__(self) -> None:
            """Initialise."""
            self._seqnum = _FakeSeqnum()
            self.getSeqnum = lambda: self._seqnum
            self.getOpcode = lambda: 5
            self.getMnemonic = lambda: "INT_ADD"
            self.getNumInputs = lambda: 0

    class _FakeHighFunction:
        """Fake HighFunction for the slice test."""

        def __init__(self) -> None:
            """Initialise."""
            self._op = _FakeSliceOp()
            self.getPcodeOps: Callable[[object], _FakeIterator] = lambda _addr: _FakeIterator([self._op])

    class _FakeDecompResult:
        """Fake decompile result that succeeds."""

        def __init__(self) -> None:
            """Initialise."""
            self._hfunc = _FakeHighFunction()
            self.decompileCompleted = lambda: True
            self.getHighFunction = lambda: self._hfunc

    class _FakeDecompIfc:
        """Fake DecompInterface."""

        def __init__(self) -> None:
            """Initialise."""
            self.openProgram: Callable[[object], None] = lambda _prog: None
            self.decompileFunction: Callable[[object, object, object], _FakeDecompResult] = lambda _fn, _t, _m: _FakeDecompResult()

    class _FakeFunction:
        """Fake function."""

        def __init__(self) -> None:
            """Initialise."""
            self.getName = lambda: "slice_fn"

    decompiler_mod = types.ModuleType("ghidra.app.decompiler")
    setattr(decompiler_mod, "DecompInterface", _FakeDecompIfc)
    sys.modules.setdefault("ghidra", types.ModuleType("ghidra"))
    sys.modules.setdefault("ghidra.app", types.ModuleType("ghidra.app"))
    sys.modules["ghidra.app.decompiler"] = decompiler_mod

    def _get_slice_fn(_a: object) -> _FakeFunction:
        return _FakeFunction()

    fake.globals["currentProgram"] = object()
    fake.globals["toAddr"] = _FakeAddr
    fake.globals["getFunctionContaining"] = _get_slice_fn
    fake.globals["monitor"] = object()

    try:
        result = _run(bridge.get_slice(_TEST_ADDRESS, direction="backward"))
    finally:
        sys.modules.pop("ghidra.app.decompiler", None)
        sys.modules.pop("ghidra.app", None)
        sys.modules.pop("ghidra", None)

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    assert payload["address"] == _TEST_ADDRESS
    assert payload["direction"] == "backward"
    slice_addrs = cast("list[int]", payload["slice_addresses"])
    assert _TEST_ADDRESS in slice_addrs
    slice_ops = cast("list[dict[str, Any]]", payload["slice_pcode_ops"])
    assert len(slice_ops) == 1
    assert slice_ops[0]["mnemonic"] == "INT_ADD"
    assert slice_ops[0]["opcode"] == 5
    assert slice_ops[0]["address"] == _TEST_ADDRESS

    exec_src = fake.exec_payloads[0]
    assert "DecompInterface" in exec_src
    assert "collect_backward" in exec_src


def test_get_program_tree_returns_trees_with_fragment(
    bridge_with_fake: tuple[GhidraBridge, _FakeBridgeClient],
) -> None:
    """get_program_tree must return a ``trees`` list with typed fragment children.

    Independent oracle: the fake listing exposes one tree (``Program Tree``)
    whose root module has one fragment child (``.text``) with a known address
    range [0x1000, 0x1FFF].

    Mutation caught: placing the tree list under a key other than ``trees``,
    or misidentifying the fragment as a module (wrong ``type`` field).

    Args:
        bridge_with_fake: Fixture providing a live bridge plus a fake client.
    """
    bridge, fake = bridge_with_fake

    class _FakeRange:
        """Fake address range."""

        def __init__(self, start: int, end: int) -> None:
            """Initialise.

            Args:
                start: Range start offset.
                end: Range end offset (inclusive).
            """

            class _MinAddr:
                """Minimum address."""

                def __init__(self, off: int) -> None:
                    """Initialise.

                    Args:
                        off: Offset.
                    """
                    self.getOffset = lambda: off

            class _MaxAddr:
                """Maximum address."""

                def __init__(self, off: int) -> None:
                    """Initialise.

                    Args:
                        off: Offset.
                    """
                    self.getOffset = lambda: off

            self.getMinAddress = lambda: _MinAddr(start)
            self.getMaxAddress = lambda: _MaxAddr(end)

    listing_mod = types.ModuleType("ghidra.program.model.listing")

    class _FakeProgramFragment:
        """Fake ProgramFragment (injected as the real class for isinstance checks)."""

        def __init__(self, name: str, rng: _FakeRange) -> None:
            """Initialise.

            Args:
                name: Fragment name.
                rng: Address range covered by the fragment.
            """
            self.getName = lambda: name
            self.getAddressRanges = lambda: _FakeIterator([rng])

    class _FakeProgramModule:
        """Fake ProgramModule (injected as the real class for isinstance checks)."""

        def __init__(self, name: str, children: list[object]) -> None:
            """Initialise.

            Args:
                name: Module name.
                children: Child nodes (modules or fragments).
            """
            self.getName = lambda: name
            self.getChildren = lambda: children

    setattr(listing_mod, "ProgramFragment", _FakeProgramFragment)
    setattr(listing_mod, "ProgramModule", _FakeProgramModule)
    sys.modules.setdefault("ghidra", types.ModuleType("ghidra"))
    sys.modules.setdefault("ghidra.program", types.ModuleType("ghidra.program"))
    sys.modules.setdefault("ghidra.program.model", types.ModuleType("ghidra.program.model"))
    sys.modules["ghidra.program.model.listing"] = listing_mod

    fake_range = _FakeRange(0x1000, 0x1FFF)
    fragment = _FakeProgramFragment(".text", fake_range)
    root_module = _FakeProgramModule("Program Tree", [fragment])

    class _FakeListing:
        """Fake program listing with one named tree."""

        def __init__(self) -> None:
            """Initialise."""
            self.getTreeNames = lambda: ["Program Tree"]
            self.getRootModule: Callable[[object], _FakeProgramModule] = lambda _name: root_module

    class _FakeProgram:
        """Fake currentProgram."""

        def __init__(self) -> None:
            """Initialise."""
            self.getListing = _FakeListing

    fake.globals["currentProgram"] = _FakeProgram()

    try:
        result = _run(bridge.get_program_tree())
    finally:
        sys.modules.pop("ghidra.program.model.listing", None)
        sys.modules.pop("ghidra.program.model", None)
        sys.modules.pop("ghidra.program", None)
        sys.modules.pop("ghidra", None)

    assert isinstance(result, dict)
    payload = cast("dict[str, Any]", result)
    trees = cast("list[dict[str, Any]]", payload["trees"])
    assert len(trees) == 1
    tree = trees[0]
    assert tree["name"] == "Program Tree"
    root = cast("dict[str, Any]", tree["root"])
    assert root["name"] == "Program Tree"
    assert root["type"] == "module"
    children = cast("list[dict[str, Any]]", root["children"])
    assert len(children) == 1
    frag = children[0]
    assert frag["name"] == ".text"
    assert frag["type"] == "fragment"
    ranges = cast("list[dict[str, Any]]", frag["ranges"])
    assert len(ranges) == 1
    assert ranges[0]["start"] == 0x1000
    assert ranges[0]["end"] == 0x1FFF

    exec_src = fake.exec_payloads[0]
    assert "getTreeNames" in exec_src
    assert "getRootModule" in exec_src
    assert "build_fragment" in exec_src
