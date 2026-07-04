# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit5 U3 regression tests for ``intellicrack.core.hexpat.*`` (core-hexpat).

Each test pins a specific F-#### finding from ``audit5.md``. Tests in this
module only exercise the pure-Python interpreter pipeline (preprocessor →
lexer → parser → evaluator + stdlib) and avoid the optional native hexcore
crate. They are deliberately written to fail on the unfixed code and pass
once the audit5 root-cause repairs land.

Findings exercised:

* F-0001 / F-0017 / F-0027 — bare ``print(...)`` and bare ``format(...)``
  must reach the ``std::print`` / ``std::format`` pipeline rather than the
  no-op shadow defined by the evaluator.
* F-0002 — ``std::mem::base_address()`` must return the active
  ``#pragma base_address`` rather than literal ``0``.
* F-0003 / F-0020 — ``std::core::array_index()`` must reflect the active
  evaluator-owned iteration index rather than the last value passed to
  the unused ``set_array_index`` setter.
* F-0004 / F-0025 — multi-segment ``builtin::std::*::name`` namespace
  access paths must resolve through the flat scope-key lookup.
* F-0005 — ``HexPatInterpreter.compile_to_json`` must not downgrade
  precise ``HexPatRuntimeError`` / ``HexPatTypeError`` instances raised by
  the underlying compiler module to a generic ``HexPatError``.
* F-0006 / F-0021 — wiring the interpreter must install an evaluator-backed
  reflection provider so ``std::core::has_attribute`` and friends resolve
  rather than raising ``"requires evaluator metadata not yet wired"``.
* F-0007 / F-0021 — registering a print sink on the interpreter must be
  observable from inside a pattern via ``std::print``.
* F-0008 / F-0009 / F-0018 / F-0021 / F-0022 — ``std::core::set_endian``
  must drive the evaluator's primitive read default; ``#pragma endian``
  must seed both the evaluator and the stdlib defaults.
* F-0010 / F-0011 — ``builtin::std::string::parse_int`` and the full set
  of ``builtin::std::mem::*`` callees referenced by the audited
  ``vendor/ImHex-Patterns/includes/std/*`` library must be registered.
* F-0012 — variadic ``auto ... pack`` parameters must capture trailing
  arguments rather than silently dropping them.
* F-0013 — generic struct templates must propagate template arguments so
  ``Foo<u32>`` and ``Foo<u8>`` produce different layouts.
* F-0014 — ``using`` aliases must accept array, pointer, and padding
  targets.
* F-0015 — namespaced struct/union/enum/bitfield declarations must keep
  qualified registrations distinct in the type registry.
* F-0016 — legitimate ``break``/``continue`` inside ``while``/``for`` must
  log at DEBUG, not WARNING.
* F-0019 — pointer-array fields (``T *name[N]``) must be recognised as a
  pointer-array shape, not flattened to a non-pointer array.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from structlog.testing import capture_logs


if TYPE_CHECKING:
    from collections.abc import Callable

from intellicrack.core.hexpat.ast_nodes import StructDecl
from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatError, HexPatRuntimeError
from intellicrack.core.hexpat.evaluator import BuiltinCallable, HexPatEvaluator, PatternValue
from intellicrack.core.hexpat.interpreter import HexPatInterpreter
from intellicrack.core.hexpat.pragma import PragmaInfo
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.stdlib import BuiltinFunctions, set_print_sink
from intellicrack.core.hexpat.type_system import StructTypeInfo, TypeRegistry


@pytest.fixture
def interp() -> HexPatInterpreter:
    """Return a fresh :class:`HexPatInterpreter` for each test.

    Returns:
        HexPatInterpreter: A fresh interpreter with no preconfigured sink.
    """
    return HexPatInterpreter()


@pytest.fixture
def vendor_std_lib() -> Path:
    """Locate the vendored standard-library include directory.

    The test fixture covers integration-smoke assertions against the
    real ``includes/std/`` library shipped under ``vendor/``. When the
    vendor copy of the upstream pattern repository is missing (sparse
    checkouts) the dependent tests skip rather than fail.

    Returns:
        Path: Absolute path to the ``includes/`` directory.
    """
    repo_root = Path(__file__).resolve().parents[3]
    candidate = repo_root / "vendor" / "ImHex-Patterns" / "includes"
    if not candidate.is_dir():
        pytest.skip(f"vendor pattern includes missing at {candidate}")
    return candidate


def _zeros(size: int = 64) -> bytes:
    """Return a zeroed buffer used as the binary fixture.

    Args:
        size: Number of zero bytes to allocate.

    Returns:
        bytes: ``size`` bytes of zeros.
    """
    return bytes(size)


def _bound(target: object, attr: str) -> Callable[..., PatternValue]:
    """Return ``getattr(target, attr)`` typed as a callable returning ``PatternValue``.

    Tests use this helper to call ``_*`` methods on the production
    classes without tripping basedpyright's ``reportPrivateUsage``
    diagnostic. The helper centralises the dynamic lookup so individual
    callers stay statement-level type-clean.

    Args:
        target: The instance whose method should be returned.
        attr: The attribute name to bind.

    Returns:
        Callable[..., PatternValue]: The bound method/attribute, typed for
        the common ``-> PatternValue`` shape used throughout the audited
        builtins.
    """
    fn: object = getattr(target, attr)
    assert callable(fn), f"{type(target).__name__}.{attr} is not callable"
    return cast("Callable[..., PatternValue]", fn)


def _attr(target: object, attr: str) -> object:
    """Return ``getattr(target, attr)`` for inspection-only test access.

    Args:
        target: The instance whose attribute should be returned.
        attr: The attribute name to read.

    Returns:
        object: The attribute value (may be ``None`` or any type).
    """
    return getattr(target, attr)


# ---------------------------------------------------------------------------
# F-0002: pragma base_address propagated into std::mem::base_address
# ---------------------------------------------------------------------------


def test_mem_base_address_uses_pragma_directly() -> None:
    """Constructing the stdlib with a pragma must report the right base address.

    The reproduction here calls the builtin directly so the regression
    is unambiguous: pre-fix the call returned ``0`` regardless of the
    pragma supplied.
    """
    pragma = PragmaInfo(base_address=0x10_0000)
    reader = DataReader.from_bytes(_zeros(16))
    stdlib = BuiltinFunctions(reader, pragma)
    result = _bound(stdlib, "_mem_base_address")()
    assert result == 0x10_0000


def test_mem_base_address_smoke_through_pattern(interp: HexPatInterpreter) -> None:
    """The flat ``builtin::std::mem::base_address`` path must resolve at offset.

    Args:
        interp: A fresh interpreter fixture.
    """
    source = """
    #pragma base_address 0x4000
    u8 marker @ builtin::std::mem::base_address();
    """
    results = interp.execute_bytes(source, _zeros(0x4001 + 4))
    assert results[0]["offset"] == 0x4000


# ---------------------------------------------------------------------------
# F-0003 / F-0020: array_index reflects the live evaluator stack
# ---------------------------------------------------------------------------


def test_array_index_listener_returns_live_value() -> None:
    """The evaluator's array-index provider must be wired into the stdlib."""
    pragma = PragmaInfo()
    reader = DataReader.from_bytes(_zeros(16))
    evaluator = HexPatEvaluator(reader, TypeRegistry(), pragma)
    stdlib = BuiltinFunctions(reader, pragma)
    stdlib.set_array_index_provider(evaluator.current_array_index)
    array_index = _bound(stdlib, "_core_array_index")
    assert array_index() == 0
    raw_stack = _attr(evaluator, "_array_index_stack")
    assert isinstance(raw_stack, list)
    stack = cast("list[int]", raw_stack)
    stack.append(7)
    try:
        assert array_index() == 7
    finally:
        stack.pop()
    assert array_index() == 0


# ---------------------------------------------------------------------------
# F-0004 / F-0025: namespace-access flat-key lookup
# ---------------------------------------------------------------------------


def test_namespace_chain_resolves_in_pattern(interp: HexPatInterpreter) -> None:
    """``builtin::std::mem::read_unsigned`` must resolve through flat-key lookup.

    Args:
        interp: A fresh interpreter fixture.
    """
    source = "u8 mark @ builtin::std::mem::read_unsigned(0, 1, 0);"
    data = bytes([0x12, 0x34])
    results = interp.execute_bytes(source, data + bytes(0x100))
    assert results[0]["offset"] == 0x12


def test_namespace_chain_three_levels(interp: HexPatInterpreter) -> None:
    """Three-segment ``a::b::c`` paths must resolve.

    Args:
        interp: A fresh interpreter fixture.
    """
    source = "u8 mark @ std::mem::read_unsigned(1, 1, 0);"
    data = bytes([0x00, 0x55])
    results = interp.execute_bytes(source, data + bytes(0x80))
    assert results[0]["offset"] == 0x55


# ---------------------------------------------------------------------------
# F-0005: compile_to_json must not downgrade typed errors
# ---------------------------------------------------------------------------


def test_compile_to_json_propagates_codegen_error_no_struct() -> None:
    """``compile_to_json`` must propagate a codegen error for an enum-only source.

    An enum-only pattern has no struct declaration. The real codegen raises
    :class:`HexPatError` with the diagnostic ``"no struct declaration
    found"``. The gate asserts this error is not swallowed and reaches the
    caller unchanged.

    Mutation caught: making ``compile_to_json`` swallow compiler errors and
    return ``{}`` instead of raising turns this gate red because no exception
    is raised.
    """
    source = "enum Status : u8 { Ok = 0, Err = 1 };"
    with pytest.raises(HexPatError, match=r"no struct declaration found"):
        HexPatInterpreter.compile_to_json(source)


def test_compile_to_json_propagates_error_runtime_construct() -> None:
    """``compile_to_json`` must propagate an error for a function-only source.

    A source containing only a function declaration is rejected by the real
    codegen as a runtime construct. The gate asserts the resulting
    :class:`HexPatError` propagates unchanged rather than being swallowed.

    Mutation caught: making ``compile_to_json`` swallow compiler errors and
    return ``{}`` instead of raising turns this gate red because no exception
    is raised.
    """
    source = "fn process() { return 0; };"
    with pytest.raises(HexPatError, match=r"runtime construct"):
        HexPatInterpreter.compile_to_json(source)


# ---------------------------------------------------------------------------
# F-0006 / F-0021: reflection provider wired by interpreter
# ---------------------------------------------------------------------------


def test_reflection_provider_unwired_raises() -> None:
    """When no provider is wired, reflection builtins must raise loud errors."""
    reader = DataReader.from_bytes(_zeros(16))
    stdlib = BuiltinFunctions(reader)
    pattern = PatternValue(value=None)
    has_attribute = _bound(stdlib, "_core_has_attribute")
    with pytest.raises(HexPatRuntimeError):
        has_attribute(pattern, "comment")


def test_reflection_provider_wired_resolves_member_count() -> None:
    """Wiring the evaluator-backed provider must answer ``member_count``."""
    pragma = PragmaInfo()
    reader = DataReader.from_bytes(_zeros(16))
    evaluator = HexPatEvaluator(reader, TypeRegistry(), pragma)
    stdlib = BuiltinFunctions(reader, pragma)
    stdlib.set_reflection_provider(evaluator.reflection_provider())
    pattern = PatternValue(value=None)
    pattern.members["a"] = PatternValue(value=1)
    pattern.members["b"] = PatternValue(value=2)
    member_count = _bound(stdlib, "_core_member_count")
    has_member = _bound(stdlib, "_core_has_member")
    assert member_count(pattern).value == 2
    assert has_member(pattern, "a").value is True
    assert has_member(pattern, "missing").value is False


# ---------------------------------------------------------------------------
# F-0007 / F-0021: print sink installed by interpreter
# ---------------------------------------------------------------------------


def test_print_sink_constructor_registers_callback() -> None:
    """The interpreter constructor argument must reach the ``std::print`` sink."""
    captured: list[str] = []
    custom = HexPatInterpreter(print_sink=captured.append)
    source = """
    fn ping() {
        builtin::std::io::print("hello");
        return 0;
    };
    u8 mark @ ping();
    """
    custom.execute_bytes(source, _zeros(8))
    assert any("hello" in line for line in captured)


def test_print_sink_disable_silences_output() -> None:
    """Clearing the sink with ``None`` must stop forwarding output."""
    captured: list[str] = []
    set_print_sink(captured.append)
    set_print_sink(None)
    interp_no_sink = HexPatInterpreter()
    source = """
    fn ping() {
        builtin::std::io::print("hello");
        return 0;
    };
    u8 mark @ ping();
    """
    interp_no_sink.execute_bytes(source, _zeros(8))
    assert not captured


# ---------------------------------------------------------------------------
# F-0008 / F-0009 / F-0018 / F-0022: pragma+set_endian propagate to evaluator
# ---------------------------------------------------------------------------


def test_pragma_endian_seeds_stdlib_default() -> None:
    """The stdlib endian default must mirror ``#pragma endian``."""
    pragma = PragmaInfo(endian="big")
    reader = DataReader.from_bytes(_zeros(16))
    stdlib = BuiltinFunctions(reader, pragma)
    assert stdlib.endian == "big"


def test_set_endian_updates_evaluator_default() -> None:
    """Calling ``_core_set_endian`` must invoke the registered listener."""
    pragma = PragmaInfo()
    reader = DataReader.from_bytes(_zeros(16))
    evaluator = HexPatEvaluator(reader, TypeRegistry(), pragma)
    stdlib = BuiltinFunctions(reader, pragma)
    stdlib.set_endian_listener(evaluator.set_default_endian)
    set_endian = _bound(stdlib, "_core_set_endian")
    set_endian(1)
    assert _attr(evaluator, "_default_endian") == "big"
    set_endian(2)
    assert _attr(evaluator, "_default_endian") == "little"


def test_set_endian_native_resets_to_pragma() -> None:
    """``set_endian(0)`` must restore the pragma-configured endian."""
    pragma = PragmaInfo(endian="big")
    reader = DataReader.from_bytes(_zeros(16))
    stdlib = BuiltinFunctions(reader, pragma)
    set_endian = _bound(stdlib, "_core_set_endian")
    set_endian(2)
    assert stdlib.endian == "little"
    set_endian(0)
    assert stdlib.endian == "big"


def test_set_endian_invalid_tag_raises() -> None:
    """Unknown endian tags must raise instead of being silently coerced."""
    pragma = PragmaInfo()
    reader = DataReader.from_bytes(_zeros(16))
    stdlib = BuiltinFunctions(reader, pragma)
    set_endian = _bound(stdlib, "_core_set_endian")
    with pytest.raises(HexPatRuntimeError):
        set_endian(99)


# ---------------------------------------------------------------------------
# F-0010 / F-0011: missing builtin registrations
# ---------------------------------------------------------------------------


def test_string_parse_int_registered_in_scope() -> None:
    """``builtin::std::string::parse_int`` must be registered in the scope."""
    pragma = PragmaInfo()
    reader = DataReader.from_bytes(_zeros(16))
    evaluator = HexPatEvaluator(reader, TypeRegistry(), pragma)
    stdlib = BuiltinFunctions(reader, pragma)
    stdlib.register_all(evaluator.scope)
    binding = evaluator.scope.get("builtin::std::string::parse_int")
    assert binding is not None
    binding_short = evaluator.scope.get("std::string::parse_int")
    assert binding_short is not None


def test_string_parse_int_returns_value() -> None:
    """``parse_int`` must return integer values for valid inputs."""
    reader = DataReader.from_bytes(_zeros(16))
    stdlib = BuiltinFunctions(reader)
    parse_int = _bound(stdlib, "_string_parse_int")
    assert parse_int("123", 10) == 123
    assert parse_int("ff", 16) == 0xFF


def test_string_parse_int_invalid_raises() -> None:
    """``parse_int`` of bogus text must raise rather than silently return 0."""
    reader = DataReader.from_bytes(_zeros(16))
    stdlib = BuiltinFunctions(reader)
    parse_int = _bound(stdlib, "_string_parse_int")
    with pytest.raises(HexPatRuntimeError):
        parse_int("not_a_number", 10)


def test_string_parse_float_returns_value() -> None:
    """``parse_float`` must round-trip a finite float string."""
    reader = DataReader.from_bytes(_zeros(16))
    stdlib = BuiltinFunctions(reader)
    parse_float = _bound(stdlib, "_string_parse_float")
    parsed = parse_float("3.5")
    assert isinstance(parsed, float)
    assert abs(parsed - 3.5) < 1e-12


def test_mem_read_bits_extracts_high_nibble() -> None:
    """``builtin::std::mem::read_bits`` must return the requested bit slice."""
    reader = DataReader.from_bytes(bytes([0b1011_0101]))
    stdlib = BuiltinFunctions(reader)
    read_bits = _bound(stdlib, "_mem_read_bits")
    result = read_bits(0, 0, 4)
    assert result == 0b1011


def test_mem_read_bits_low_nibble() -> None:
    """``read_bits`` honours the bit-offset to extract low-nibble bits."""
    reader = DataReader.from_bytes(bytes([0b1011_0101]))
    stdlib = BuiltinFunctions(reader)
    read_bits = _bound(stdlib, "_mem_read_bits")
    assert read_bits(0, 4, 4) == 0b0101


def test_mem_section_lifecycle() -> None:
    """``create/copy_to/get_section_size/delete_section`` must wire end-to-end."""
    reader = DataReader.from_bytes(bytes([0xCA, 0xFE, 0xBA, 0xBE]))
    stdlib = BuiltinFunctions(reader)
    create_section = _bound(stdlib, "_mem_create_section")
    set_size = _bound(stdlib, "_mem_set_section_size")
    get_size = _bound(stdlib, "_mem_get_section_size")
    copy_to = _bound(stdlib, "_mem_copy_to_section")
    delete_section = _bound(stdlib, "_mem_delete_section")
    handle_pv = create_section("scratch")
    handle = handle_pv.value
    assert isinstance(handle, int)
    assert handle > 0
    set_size(handle, 4)
    assert get_size(handle).value == 4
    copy_to(0, 0, handle, 0, 4)
    raw_sections = _attr(stdlib, "_sections")
    assert isinstance(raw_sections, dict)
    sections = cast("dict[int, object]", raw_sections)
    section_obj = sections[handle]
    section_data = _attr(section_obj, "data")
    assert isinstance(section_data, bytearray)
    assert bytes(section_data) == bytes([0xCA, 0xFE, 0xBA, 0xBE])
    delete_section(handle)
    assert handle not in sections


def test_mem_find_string_in_range_locates_match() -> None:
    """``find_string_in_range`` must report the match offset."""
    reader = DataReader.from_bytes(b"\x00\x00MZheader" + bytes(8))
    stdlib = BuiltinFunctions(reader)
    find_str = _bound(stdlib, "_mem_find_string_in_range")
    result = find_str(0, 0, 16, "MZ")
    assert result == 2


def test_mem_current_bit_offset_default_zero() -> None:
    """The bit-offset builtin must return 0 when no reflection provider is wired."""
    reader = DataReader.from_bytes(bytes(8))
    stdlib = BuiltinFunctions(reader)
    bit_offset = _bound(stdlib, "_mem_current_bit_offset")
    assert bit_offset() == 0


def test_mem_builtins_registered_in_scope() -> None:
    """Every audited mem-builtin must be registered under both flat aliases."""
    pragma = PragmaInfo()
    reader = DataReader.from_bytes(_zeros(16))
    evaluator = HexPatEvaluator(reader, TypeRegistry(), pragma)
    stdlib = BuiltinFunctions(reader, pragma)
    stdlib.register_all(evaluator.scope)
    expected = (
        "read_bits",
        "find_string_in_range",
        "create_section",
        "delete_section",
        "get_section_size",
        "set_section_size",
        "copy_to_section",
        "copy_value_to_section",
        "current_bit_offset",
    )
    for name in expected:
        assert evaluator.scope.get(f"builtin::std::mem::{name}") is not None, name
        assert evaluator.scope.get(f"std::mem::{name}") is not None, name


# ---------------------------------------------------------------------------
# F-0012: variadic parameters captured
# ---------------------------------------------------------------------------


def test_variadic_pack_captures_trailing_arguments(interp: HexPatInterpreter) -> None:
    """``auto ... values`` parameters must collect every trailing argument.

    The fix records the pack length under a synthetic ``size`` member on the
    bound parameter, so user code can introspect the captured count via
    ``values.size``. Pre-fix the function ignored every argument past the
    first declared parameter, so ``values.size`` resolved to ``1``.

    Args:
        interp: A fresh interpreter fixture.
    """
    source = """
    fn count(auto ... values) {
        return values.size;
    };

    u8 mark @ count(1, 2, 3, 4, 5);
    """
    results = interp.execute_bytes(source, _zeros(16))
    assert results[0]["offset"] == 5


# ---------------------------------------------------------------------------
# F-0013: template arguments differentiate layouts
# ---------------------------------------------------------------------------


def test_template_args_select_field_size(interp: HexPatInterpreter) -> None:
    """``Slot<Small>`` and ``Slot<Big>`` must produce different layouts.

    Template arguments propagate type bindings through the evaluator; the
    test uses user-defined structs as template arguments because the parser
    only treats identifier expressions (not primitive-type tokens) as
    template arguments.

    Args:
        interp: A fresh interpreter fixture.
    """
    source = """
    struct Small { u8 a; };

    struct Big {
        u8 a;
        u8 b;
        u8 c;
        u8 d;
    };

    struct Slot<T> {
        T width;
    };

    Slot<Small> tight @ 0;
    Slot<Big> wide @ 4;
    """
    payload = bytes([1, 2, 3, 4]) + bytes([0xAA, 0xBB, 0xCC, 0xDD])
    results = interp.execute_bytes(source, payload)
    tight = next(r for r in results if r["name"] == "tight")
    wide = next(r for r in results if r["name"] == "wide")
    assert tight["size"] == 1
    assert wide["size"] == 4


# ---------------------------------------------------------------------------
# F-0014: using accepts composite targets
# ---------------------------------------------------------------------------


def test_using_alias_accepts_array_target(interp: HexPatInterpreter) -> None:
    """``using Bytes = u8[4];`` must instantiate as a 4-byte array.

    Args:
        interp: A fresh interpreter fixture.
    """
    source = """
    using Bytes = u8[4];

    Bytes block @ 0;
    """
    payload = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0])
    results = interp.execute_bytes(source, payload)
    assert results[0]["size"] == 4


# ---------------------------------------------------------------------------
# F-0015: namespace type collisions resolved
# ---------------------------------------------------------------------------


def test_namespaced_struct_qualified_lookup_distinct() -> None:
    """Qualified namespace lookups must not collapse into a single registration.

    The :class:`TypeRegistry` registers a struct under both its local
    name and its qualified ``namespace::name`` path. Re-registering a
    struct that shares the local name from another namespace must not
    overwrite the qualified path of the first registration.
    """
    decl_a = StructDecl(name="Header", parent=None, body=(), annotations=(), line=1, column=1)
    decl_b = StructDecl(name="Header", parent=None, body=(), annotations=(), line=2, column=1)
    registry = TypeRegistry()
    registry.register_struct(decl_a, namespace="alpha")
    registry.register_struct(decl_b, namespace="beta")
    qualified_alpha = registry.resolve("alpha::Header")
    qualified_beta = registry.resolve("beta::Header")
    assert isinstance(qualified_alpha, StructTypeInfo)
    assert isinstance(qualified_beta, StructTypeInfo)
    assert qualified_alpha is not qualified_beta
    assert qualified_alpha.decl is decl_a
    assert qualified_beta.decl is decl_b


# ---------------------------------------------------------------------------
# F-0016: legitimate break/continue at DEBUG, not WARNING
# ---------------------------------------------------------------------------


def test_break_continue_no_warning_log(interp: HexPatInterpreter) -> None:
    """Legitimate break/continue in while/for loops must not emit WARNING logs.

    The audit calls out that the legitimate ``break``/``continue`` paths
    inside :meth:`HexPatEvaluator._eval_while` and
    :meth:`HexPatEvaluator._run_for_body` were emitting WARNING records on
    every legitimate exit, polluting structured logs. The fix downgrades
    those branches to DEBUG. This exercises the interpreter directly and
    asserts the four loop-control events are emitted at DEBUG and that none
    of them is emitted at WARNING or higher. Events are captured with
    :func:`structlog.testing.capture_logs` because the evaluator logs through
    structlog, whose events do not reach the stdlib ``caplog`` fixture.

    Args:
        interp: A fresh interpreter fixture.
    """
    source = """
    fn loops() {
        u32 acc = 0;
        for (u32 i = 0; i < 4; i = i + 1) {
            if (i == 1) {
                continue;
            }
            if (i == 3) {
                break;
            }
            acc = acc + 1;
        }
        u32 j = 0;
        while (j < 4) {
            if (j == 1) {
                j = j + 1;
                continue;
            }
            if (j == 3) {
                break;
            }
            j = j + 1;
        }
        return acc;
    };

    u8 mark @ loops();
    """
    with capture_logs() as captured:
        interp.execute_bytes(source, _zeros(8))

    control_events = {
        "hexpat_for_break",
        "hexpat_for_continue",
        "hexpat_while_break",
        "hexpat_while_continue",
    }
    control_records = [entry for entry in captured if entry.get("event") in control_events]
    elevated = [str(entry.get("event")) for entry in control_records if entry.get("log_level") in {"warning", "error", "critical"}]
    assert not elevated, elevated

    debug_events = {str(entry["event"]) for entry in control_records if entry.get("log_level") == "debug"}
    assert debug_events == control_events, f"missing debug control events: {control_events - debug_events}"


# ---------------------------------------------------------------------------
# F-0019: pointer-array fields recognised
# ---------------------------------------------------------------------------


def test_pointer_array_field_routes_through_pointer_array(
    interp: HexPatInterpreter,
) -> None:
    """``T *array[N] : u32`` must be evaluated as a pointer-array, not a plain array.

    Args:
        interp: A fresh interpreter fixture.
    """
    payload = bytearray(64)
    struct.pack_into("<I", payload, 0, 16)
    struct.pack_into("<I", payload, 4, 20)
    payload[16] = 0x77
    payload[20] = 0x88
    source = """
    #pragma pointer_size 4

    struct Tag { u8 raw; };

    struct Container {
        Tag *entries[2];
    };

    Container c @ 0;
    """
    results = interp.execute_bytes(source, bytes(payload))
    container = results[0]
    entries_field = container["children"][0]
    assert entries_field["size"] == 8
    assert len(entries_field["children"]) == 2
    for child in entries_field["children"]:
        assert child["children"], "pointer slot must dereference its pointee"


# ---------------------------------------------------------------------------
# Integration smoke: vendor std/{mem,string}.pat behaviour
# ---------------------------------------------------------------------------


def test_vendor_mem_base_address_smoke(vendor_std_lib: Path) -> None:
    """``import std.mem`` must inline the real ``mem.pat`` and resolve base_address.

    This is an integration gate over two real behaviours, asserted
    unconditionally (no skip-on-interpreter-failure mask):

    * The preprocessor, configured with the vendor include directory the
      interpreter uses, must resolve ``import std.mem;`` against the
      on-disk ``includes/std/mem.pat`` and inline its real contents. The
      independent oracle is the exact ``fn base_address()`` definition
      line read directly from the vendored file: if the include-path /
      ``import`` resolution regresses, the inlined output no longer
      contains that signature.
    * The real interpreter must resolve the short ``std::mem::base_address``
      alias end-to-end and place the field at the pragma-configured base.
      The upstream ``mem.pat`` opens with ``namespace auto std::mem`` whose
      leading ``auto`` keyword is outside this audit unit's parser scope, so
      the end-to-end leg uses a parser-supported source rather than the
      vendored namespace block; both legs together gate that the vendored
      library is on the include path and the stdlib bridge is wired.

    Args:
        vendor_std_lib: The vendor includes directory fixture.
    """
    mem_pat = vendor_std_lib / "std" / "mem.pat"
    signature = next(line.strip() for line in mem_pat.read_text(encoding="utf-8").splitlines() if "fn base_address()" in line)
    preprocessor = HexPatPreprocessor([vendor_std_lib])
    processed, _pragma = preprocessor.process("import std.mem;\n")
    assert signature in processed

    interp = HexPatInterpreter(std_lib_path=vendor_std_lib)
    source = """
    #pragma base_address 0x4000
    u8 mark @ std::mem::base_address();
    """
    payload = _zeros(0x4001 + 16)
    results = interp.execute_bytes(source, payload)
    assert results[0]["offset"] == 0x4000


def test_vendor_string_parse_int_smoke(vendor_std_lib: Path) -> None:
    r"""``import std.string`` must inline the real ``string.pat`` and parse_int must work.

    Asserted unconditionally (no skip-on-interpreter-failure mask), mirroring
    :func:`test_vendor_mem_base_address_smoke`:

    * The preprocessor configured with the vendor include directory must
      resolve ``import std.string;`` against the on-disk
      ``includes/std/string.pat`` and inline its real contents. The
      independent oracle is the exact ``fn parse_int(...)`` definition line
      read directly from the vendored file.
    * The real interpreter must resolve the short ``std::string::parse_int``
      alias end-to-end and return the parsed integer. The end-to-end leg
      uses a parser-supported source because the vendored ``string.pat``
      opens with ``namespace auto std::string`` (outside this unit's parser
      scope), so the two legs together gate include-path wiring plus the
      ``parse_int`` builtin.

    Args:
        vendor_std_lib: The vendor includes directory fixture.
    """
    string_pat = vendor_std_lib / "std" / "string.pat"
    signature = next(line.strip() for line in string_pat.read_text(encoding="utf-8").splitlines() if "fn parse_int(" in line)
    preprocessor = HexPatPreprocessor([vendor_std_lib])
    processed, _pragma = preprocessor.process("import std.string;\n")
    assert signature in processed

    interp = HexPatInterpreter(std_lib_path=vendor_std_lib)
    source = """
    u8 mark @ std::string::parse_int("123", 10);
    """
    payload = _zeros(256)
    results = interp.execute_bytes(source, payload)
    assert results[0]["offset"] == 123


# ---------------------------------------------------------------------------
# F-0001 / F-0017 / F-0027: bare-name print/format reach stdlib
# ---------------------------------------------------------------------------


def test_bare_name_print_reaches_sink() -> None:
    """A bare ``print(...)`` call must traverse the stdlib pipeline."""
    captured: list[str] = []
    interp = HexPatInterpreter(print_sink=captured.append)
    source = """
    fn say() {
        print("hi");
        return 0;
    };

    u8 mark @ say();
    """
    interp.execute_bytes(source, _zeros(8))
    assert any("hi" in line for line in captured)


def test_bare_name_format_supports_format_spec() -> None:
    """Bare ``format`` must honour the full ``{:spec}`` placeholder syntax."""
    pragma = PragmaInfo()
    reader = DataReader.from_bytes(_zeros(16))
    evaluator = HexPatEvaluator(reader, TypeRegistry(), pragma)
    stdlib = BuiltinFunctions(reader, pragma)
    stdlib.register_all(evaluator.scope)
    fmt_pv = evaluator.scope.get("format")
    assert fmt_pv is not None
    callable_box = fmt_pv.value
    assert isinstance(callable_box, BuiltinCallable)
    result = callable_box.fn(PatternValue(value="0x{:08X}"), PatternValue(value=0xCAFE))
    assert result == "0x0000CAFE"
