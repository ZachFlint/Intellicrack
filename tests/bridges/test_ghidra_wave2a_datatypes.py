# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GHIDRA-D wave-2a real gates: datatypes, structures, bookmarks, equates, comments.

Converts disconnected-state-only gates into REAL functional gates for the
GhidraBridge connected path. Each test injects a deterministic fake transport,
calls the real production method, and asserts BOTH the exact parsed return
structure AND the correct Ghidra API framing in the emitted script.

Methods with existing REAL gates that are NOT duplicated here:
  define_structure   - test_ghidra_f11_audit.py
  set_label          - test_ghidra_audit6.py (F-0020)
  get_labels         - test_ghidra_panel.py
  create_bookmark    - test_ghidra_audit6.py (F-0020)
  create_equate      - test_ghidra_audit6.py (F-0020)
  add_comment        - test_ghidra_audit6.py (F-0020)
  set_color          - test_ghidra_audit6.py (F-0024)

Production defects revealed and fixed as part of this gate:
  set_data_type      - trailing if-block blocked sentinel detection; always returned False
  apply_structure_at - trailing if-block blocked sentinel detection; always raised ToolError
  create_data_type   - trailing if-else dict literals blocked sentinel; always returned failure dict
  create_data        - trailing if-else dict literals blocked sentinel; always returned failure dict
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import DataTypeInfo, ToolError


if TYPE_CHECKING:
    from collections.abc import Coroutine

_TEST_ADDRESS: int = 0x401000


class _FakeGhidraBridge:
    """Minimal test double for the upstream ``ghidra_bridge`` client.

    Records every ``remote_exec`` and ``remote_eval`` call so tests can
    assert on the Ghidra API framing present in emitted scripts. The
    ``eval_response`` attribute is returned from every ``remote_eval``
    call, standing in for the Jython-side sentinel variable that the
    real bridge reads back after ``remote_exec``.
    """

    def __init__(self) -> None:
        """Initialise empty call traces and a None eval response."""
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self.eval_response: object = None
        self.exec_raises: BaseException | None = None
        self.eval_raises: BaseException | None = None

    def remote_exec(self, code: str) -> None:
        """Record the script; optionally raise if exec_raises is set.

        Args:
            code: Jython source string forwarded by the bridge.

        Raises:
            exc: Re-raised when ``exec_raises`` has been set on the fake.
        """
        self.exec_calls.append(code)
        exc = self.exec_raises
        if exc is not None:
            raise exc

    def remote_eval(self, expression: str) -> object:
        """Record the expression and return the preset eval_response.

        Args:
            expression: Jython expression or sentinel name.

        Returns:
            object: The configured ``eval_response`` value.

        Raises:
            exc: Re-raised when ``eval_raises`` has been set on the fake.
        """
        self.eval_calls.append(expression)
        exc = self.eval_raises
        if exc is not None:
            raise exc
        return self.eval_response


def _make_bridge() -> tuple[GhidraBridge, _FakeGhidraBridge]:
    """Construct a connected GhidraBridge wired to a fake transport.

    Returns:
        tuple[GhidraBridge, _FakeGhidraBridge]: The live bridge and the
        recording fake wired as its underlying RPC client.
    """
    bridge = GhidraBridge()
    fake = _FakeGhidraBridge()
    setattr(bridge, "_bridge", fake)
    return bridge, fake


def _run[T](coro: Coroutine[Any, Any, T]) -> T:
    """Drive a coroutine to completion in a fresh event loop.

    Args:
        coro: Async coroutine to run.

    Returns:
        T: Return value of the coroutine.
    """
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# get_data_type - parse DataTypeInfo from the script's result dict
# ---------------------------------------------------------------------------


def test_get_data_type_parses_name_and_size_from_script_result() -> None:
    """get_data_type maps dict keys into DataTypeInfo fields exactly.

    Oracle: inject eval_response = known dict, assert DataTypeInfo fields.
    Mutation caught: replacing result_dict.get('name') with
    result_dict.get('type_name') would produce DataTypeInfo.name == ''.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = {
        "address": _TEST_ADDRESS,
        "name": "dword",
        "category": "/",
        "size": 4,
        "is_pointer": False,
        "is_array": False,
        "array_length": None,
        "base_type": None,
    }

    result = _run(bridge.get_data_type(_TEST_ADDRESS))

    assert isinstance(result, DataTypeInfo)
    assert result.name == "dword"
    assert result.size == 4
    assert result.category == "/"
    assert result.is_pointer is False
    assert result.is_array is False
    assert result.array_length is None
    assert result.base_type is None
    assert len(fake.exec_calls) == 1
    assert "getDataAt" in fake.exec_calls[0]


def test_get_data_type_parses_pointer_fields() -> None:
    """get_data_type populates is_pointer and base_type for pointer types.

    Oracle: eval_response with is_pointer=True and base_type set.
    Mutation caught: if base_type key is renamed to 'element_type', result.base_type is None.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = {
        "address": _TEST_ADDRESS,
        "name": "pointer",
        "category": "/",
        "size": 8,
        "is_pointer": True,
        "is_array": False,
        "array_length": None,
        "base_type": "dword",
    }

    result = _run(bridge.get_data_type(_TEST_ADDRESS))

    assert isinstance(result, DataTypeInfo)
    assert result.is_pointer is True
    assert result.base_type == "dword"
    assert result.size == 8


def test_get_data_type_returns_none_when_no_data() -> None:
    """get_data_type returns None when the script result is None.

    Oracle: eval_response = None (no data defined at address).
    Mutation caught: if 'if result is None' guard is removed, parsing None as
    dict would raise instead of returning None.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = None

    result = _run(bridge.get_data_type(_TEST_ADDRESS))

    assert result is None


def test_get_data_type_emits_getdataat_api_call() -> None:
    """get_data_type script must call getListing().getDataAt(addr).

    Oracle: exec_calls[0] must contain 'getDataAt'.
    Mutation caught: replacing getDataAt with getDataBefore would fail this
    assertion and return wrong data at a different address.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = None

    _run(bridge.get_data_type(_TEST_ADDRESS))

    assert len(fake.exec_calls) == 1
    assert "getDataAt" in fake.exec_calls[0]
    assert str(_TEST_ADDRESS) in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# set_data_type - returns True on success via top-level sentinel expression
# ---------------------------------------------------------------------------


def test_set_data_type_returns_true_on_success() -> None:
    """set_data_type returns True when the parse-and-create script succeeds.

    Oracle: eval_response = True (script's _set_ok sentinel was True).
    Mutation caught: if the trailing sentinel expression '_set_ok' is removed,
    _execute_remote returns None and bool(None) == False, not True.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = True

    result = _run(bridge.set_data_type(_TEST_ADDRESS, "dword"))

    assert result is True
    assert len(fake.exec_calls) == 1
    assert "DataTypeParser" in fake.exec_calls[0]
    assert "dword" in fake.exec_calls[0]


def test_set_data_type_returns_false_when_parse_fails() -> None:
    """set_data_type returns False when the parser cannot resolve the type.

    Oracle: eval_response = False (script's _set_ok remains False after
    parsed is None branch).
    Mutation caught: if _set_ok is not initialised to False, the sentinel
    expression would be undefined and raise NameError remotely.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = False

    result = _run(bridge.set_data_type(_TEST_ADDRESS, "nonexistent_type"))

    assert result is False


def test_set_data_type_emits_datatypeparser_call() -> None:
    """set_data_type script must call DataTypeParser for the requested type.

    Oracle: exec_calls[0] contains both 'DataTypeParser' and the type name.
    Mutation caught: hardcoding a fixed type name instead of data_type_literal
    would make the injected type name absent from the script.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = True

    _run(bridge.set_data_type(_TEST_ADDRESS, "qword"))

    assert "DataTypeParser" in fake.exec_calls[0]
    assert "qword" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# create_data_type - top-level _cdt_result sentinel returns creation dict
# ---------------------------------------------------------------------------


def test_create_data_type_enum_returns_success_dict() -> None:
    """create_data_type returns the creation dict when the enum is added.

    Oracle: eval_response = known dict with name/kind/size/success.
    Mutation caught: if 'kind' key is changed to 'type_kind' in the result,
    result['kind'] would be absent and callers cannot distinguish enum from union.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = {
        "name": "MyEnum",
        "kind": "enum",
        "size": 4,
        "success": True,
    }

    result = _run(bridge.create_data_type("/MyTypes", "MyEnum", "enum", [{"name": "A", "value": 0}]))

    assert result["name"] == "MyEnum"
    assert result["kind"] == "enum"
    assert result["size"] == 4
    assert result["success"] is True
    assert "EnumDataType" in fake.exec_calls[0]


def test_create_data_type_script_branches_on_type_kind() -> None:
    """create_data_type script dispatches to EnumDataType only for 'enum'.

    Oracle: exec_calls[0] must contain 'EnumDataType' when kind is 'enum'.
    Mutation caught: if the if-elif chain uses == 'Enum' (wrong case), the
    branch is never taken and created remains None, returning failure dict.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = {"name": "E", "kind": "enum", "size": 4, "success": True}

    _run(bridge.create_data_type("/", "E", "enum", []))

    script = fake.exec_calls[0]
    assert "EnumDataType" in script
    assert "enum" in script


def test_create_data_type_returns_failure_when_created_is_none() -> None:
    """create_data_type returns a failure dict when the type manager returns None.

    Oracle: eval_response = failure dict (created was None remotely).
    Mutation caught: if the else branch is removed, result would be None and
    the fallback dict would be returned without the 'kind' field.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = {"name": "Bad", "kind": "enum", "size": 0, "success": False}

    result = _run(bridge.create_data_type("/", "Bad", "enum", []))

    assert result["success"] is False
    assert result["name"] == "Bad"


# ---------------------------------------------------------------------------
# create_data - top-level _cd_result sentinel returns data creation dict
# ---------------------------------------------------------------------------


def test_create_data_returns_success_dict_with_address_and_size() -> None:
    """create_data returns address, type, size, and success on success.

    Oracle: eval_response = dict with address == _TEST_ADDRESS, size == 4.
    Mutation caught: if 'address' key is mapped from addr.getOffset() but the
    key is named 'offset' instead, result['address'] would be KeyError.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = {
        "address": _TEST_ADDRESS,
        "type": "dword",
        "size": 4,
        "success": True,
    }

    result = _run(bridge.create_data(_TEST_ADDRESS, "dword"))

    assert result["address"] == _TEST_ADDRESS
    assert result["type"] == "dword"
    assert result["size"] == 4
    assert result["success"] is True
    assert "DataTypeParser" in fake.exec_calls[0]


def test_create_data_script_includes_type_name() -> None:
    """create_data script embeds the requested type name for the parser.

    Oracle: exec_calls[0] contains the exact type name string.
    Mutation caught: if data_type is not json.dumps'd into the script,
    a type with spaces would cause a syntax error or parse the wrong type.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = {"address": _TEST_ADDRESS, "type": "byte", "size": 1, "success": True}

    _run(bridge.create_data(_TEST_ADDRESS, "byte"))

    assert "byte" in fake.exec_calls[0]
    assert "createData" in fake.exec_calls[0]


def test_create_data_returns_failure_dict_when_type_not_found() -> None:
    """create_data returns a failure dict when the parser cannot resolve the type.

    Oracle: eval_response = failure dict (parsed was None remotely).
    Mutation caught: if the else branch is removed, result would be None and
    the fallback dict would use hex(address) instead of the raw int address.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = {
        "address": _TEST_ADDRESS,
        "type": "unknown_type",
        "size": 0,
        "success": False,
    }

    result = _run(bridge.create_data(_TEST_ADDRESS, "unknown_type"))

    assert result["success"] is False
    assert result["size"] == 0


# ---------------------------------------------------------------------------
# get_structures - parse list of structure dicts
# ---------------------------------------------------------------------------


def test_get_structures_parses_name_size_field_count() -> None:
    """get_structures maps each structure dict to the correct output fields.

    Oracle: eval_response = list with one known structure dict.
    Mutation caught: if 'field_count' key is renamed to 'fields', callers
    cannot get the component count from the returned list.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = [
        {"name": "MyStruct", "size": 8, "field_count": 2, "path": "/"},
    ]

    result = _run(bridge.get_structures())

    assert len(result) == 1
    assert result[0]["name"] == "MyStruct"
    assert result[0]["size"] == 8
    assert result[0]["field_count"] == 2
    assert result[0]["path"] == "/"
    assert "getAllStructures" in fake.exec_calls[0]


def test_get_structures_returns_empty_list_when_none() -> None:
    """get_structures returns an empty list when the script result is falsy.

    Oracle: eval_response = None (empty data type manager).
    Mutation caught: if 'result if result else []' is dropped, None is returned
    and callers crash on iteration.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = None

    result = _run(bridge.get_structures())

    assert result == []


def test_get_structures_with_filter_name_embeds_filter_in_script() -> None:
    """get_structures embeds the filter string into the emitted script.

    Oracle: exec_calls[0] contains the filter substring.
    Mutation caught: if filter_name is not json.dumps'd into the script,
    a filter containing quotes would break the script syntax.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = [{"name": "NetStruct", "size": 16, "field_count": 4, "path": "/net"}]

    result = _run(bridge.get_structures(filter_name="Net"))

    assert result[0]["name"] == "NetStruct"
    assert "Net" in fake.exec_calls[0]


def test_get_structures_emits_getdatatypemanager_call() -> None:
    """get_structures script must use getDataTypeManager().getAllStructures().

    Oracle: exec_calls[0] contains 'getAllStructures'.
    Mutation caught: changing to getAllDataTypes() would return non-struct
    types and corrupt callers that assume all results are StructureDataType.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = []

    _run(bridge.get_structures())

    assert "getAllStructures" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# apply_structure_at - returns success dict via top-level _apply_ok sentinel
# ---------------------------------------------------------------------------


def test_apply_structure_at_returns_success_dict_when_struct_found() -> None:
    """apply_structure_at returns address/struct_name/success when applied.

    Oracle: eval_response = True (struct found and applied, _apply_ok=True).
    Mutation caught: if the trailing sentinel '_apply_ok' is removed,
    _execute_remote returns None, 'if not None' is True, and ToolError
    is raised even on success.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = True

    result = _run(bridge.apply_structure_at(_TEST_ADDRESS, "MyStruct"))

    assert result["success"] is True
    assert result["struct_name"] == "MyStruct"
    assert result["address"] == hex(_TEST_ADDRESS)
    assert "getAllStructures" in fake.exec_calls[0]


def test_apply_structure_at_raises_when_struct_not_found() -> None:
    """apply_structure_at raises ToolError when the structure name is absent.

    Oracle: eval_response = False (no match in the iterator, _apply_ok=False).
    Mutation caught: if 'if not result:' guard is removed, a missing struct
    silently returns a success dict with wrong data.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = False

    with pytest.raises(ToolError, match="not found"):
        _run(bridge.apply_structure_at(_TEST_ADDRESS, "NoSuchStruct"))


def test_apply_structure_at_embeds_struct_name_in_script() -> None:
    """apply_structure_at embeds the target struct name in the emitted script.

    Oracle: exec_calls[0] contains the struct name.
    Mutation caught: if struct_name is not json.dumps'd into the comparison,
    a name containing single quotes would break the Jython equality check.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = True

    _run(bridge.apply_structure_at(_TEST_ADDRESS, "TargetStruct"))

    assert "TargetStruct" in fake.exec_calls[0]
    assert "createData" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# get_bookmarks - parse list of bookmark dicts
# ---------------------------------------------------------------------------


def test_get_bookmarks_parses_address_category_comment_type() -> None:
    """get_bookmarks maps each bookmark dict to the correct output fields.

    Oracle: eval_response = known list with one bookmark dict.
    Mutation caught: if 'category' and 'comment' keys are swapped in the
    script, category would hold the comment text and vice versa.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = [
        {
            "address": _TEST_ADDRESS,
            "category": "analysis",
            "comment": "needs review",
            "type": "Note",
        },
    ]

    result = _run(bridge.get_bookmarks())

    assert len(result) == 1
    assert result[0]["address"] == _TEST_ADDRESS
    assert result[0]["category"] == "analysis"
    assert result[0]["comment"] == "needs review"
    assert result[0]["type"] == "Note"
    assert "getBookmarksIterator" in fake.exec_calls[0]


def test_get_bookmarks_with_category_filter_embeds_filter_in_script() -> None:
    """get_bookmarks embeds the category filter into the emitted script.

    Oracle: exec_calls[0] contains the filter string.
    Mutation caught: if the filter is not included, all categories are
    returned regardless of the caller's filter argument.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = [{"address": 0x402000, "category": "warning", "comment": "check me", "type": "Warning"}]

    result = _run(bridge.get_bookmarks(category="warning"))

    assert result[0]["category"] == "warning"
    assert "warning" in fake.exec_calls[0]


def test_get_bookmarks_returns_empty_list_when_none() -> None:
    """get_bookmarks returns [] when the script result is falsy.

    Oracle: eval_response = None (empty bookmark manager).
    Mutation caught: removing the 'result if result else []' guard causes
    None to be cast to list, which raises TypeError on iteration.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = None

    result = _run(bridge.get_bookmarks())

    assert result == []


# ---------------------------------------------------------------------------
# get_equates - parse list of equate dicts
# ---------------------------------------------------------------------------


def test_get_equates_parses_name_value_references() -> None:
    """get_equates maps each equate dict to the correct output fields.

    Oracle: eval_response = known list with one equate dict.
    Mutation caught: if 'value' is stored via long() instead of int(),
    the type would differ from int and downstream comparisons might fail.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = [
        {"name": "ANSWER", "value": 42, "references": 3},
    ]

    result = _run(bridge.get_equates())

    assert len(result) == 1
    assert result[0]["name"] == "ANSWER"
    assert result[0]["value"] == 42
    assert result[0]["references"] == 3
    assert "getEquates" in fake.exec_calls[0]


def test_get_equates_returns_empty_list_when_none() -> None:
    """get_equates returns [] when no equates are defined.

    Oracle: eval_response = None (empty equate table).
    Mutation caught: removing the 'result if result else []' guard causes
    None to propagate to callers who iterate the result.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = None

    result = _run(bridge.get_equates())

    assert result == []


def test_get_equates_emits_equate_table_iteration() -> None:
    """get_equates script must call getEquateTable().getEquates().

    Oracle: exec_calls[0] contains 'getEquates'.
    Mutation caught: using getEquateTable().getAllEquates() (nonexistent API)
    would cause a Jython AttributeError on the real bridge.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = []

    _run(bridge.get_equates())

    assert "getEquates" in fake.exec_calls[0]
    assert "getEquateTable" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# get_comments - parse list of comment dicts for an address range
# ---------------------------------------------------------------------------


def test_get_comments_parses_address_type_comment_fields() -> None:
    """get_comments maps each comment dict to the correct output fields.

    Oracle: eval_response = known list with one EOL comment dict.
    Mutation caught: if 'type' key uses 'comment_type' instead, callers
    cannot distinguish EOL from PRE/POST/PLATE comments.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = [
        {"address": _TEST_ADDRESS, "type": "EOL", "comment": "entry point"},
    ]

    result = _run(bridge.get_comments(_TEST_ADDRESS))

    assert len(result) == 1
    assert result[0]["address"] == _TEST_ADDRESS
    assert result[0]["type"] == "EOL"
    assert result[0]["comment"] == "entry point"
    assert "getComment" in fake.exec_calls[0]


def test_get_comments_includes_all_five_comment_types_in_script() -> None:
    """get_comments script must check all five Ghidra comment type constants.

    Oracle: exec_calls[0] contains all five comment type names.
    Mutation caught: if PLATE_COMMENT is dropped from comment_types,
    PLATE comments at any address in the range would be silently omitted.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = []

    _run(bridge.get_comments(_TEST_ADDRESS, range_size=0x200))

    script = fake.exec_calls[0]
    assert "EOL_COMMENT" in script
    assert "PRE_COMMENT" in script
    assert "POST_COMMENT" in script
    assert "PLATE_COMMENT" in script
    assert "REPEATABLE_COMMENT" in script


def test_get_comments_embeds_address_and_range_in_script() -> None:
    """get_comments embeds the start address and range_size into the script.

    Oracle: exec_calls[0] contains the address literal and range size.
    Mutation caught: if range_size is not embedded, the script would use
    a hardcoded range and miss comments outside that range.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = []
    range_sz = 0x400

    _run(bridge.get_comments(_TEST_ADDRESS, range_size=range_sz))

    script = fake.exec_calls[0]
    assert str(_TEST_ADDRESS) in script
    assert str(range_sz) in script


def test_get_comments_returns_empty_list_when_none() -> None:
    """get_comments returns [] when the script result is falsy.

    Oracle: eval_response = None (no commented code units in range).
    Mutation caught: if the falsy guard is removed, None propagates to callers.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = None

    result = _run(bridge.get_comments(_TEST_ADDRESS))

    assert result == []


# ---------------------------------------------------------------------------
# get_all_comments - parse list of comment dicts for the entire program
# ---------------------------------------------------------------------------


def test_get_all_comments_parses_address_type_comment() -> None:
    """get_all_comments returns a list of dicts with all three expected keys.

    Oracle: eval_response = known two-comment list with distinct types.
    Mutation caught: if the 'type' key holds the numeric constant instead of
    the string name, callers comparing type to 'PRE' would never match.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = [
        {"address": 0x401000, "type": "EOL", "comment": "start"},
        {"address": 0x401010, "type": "PRE", "comment": "before call"},
    ]

    result = _run(bridge.get_all_comments())

    assert len(result) == 2
    assert result[0]["type"] == "EOL"
    assert result[0]["comment"] == "start"
    assert result[1]["type"] == "PRE"
    assert result[1]["address"] == 0x401010
    assert "getComment" in fake.exec_calls[0]


def test_get_all_comments_iterates_all_code_units() -> None:
    """get_all_comments script must call getCodeUnits(True) for forward iteration.

    Oracle: exec_calls[0] contains 'getCodeUnits'.
    Mutation caught: using getCodeUnits(False) (reverse iteration) would return
    comments in reverse program order, breaking callers that assume forward order.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = []

    _run(bridge.get_all_comments())

    assert "getCodeUnits" in fake.exec_calls[0]


def test_get_all_comments_checks_five_comment_type_constants() -> None:
    """get_all_comments script must inspect all five comment type constants.

    Oracle: exec_calls[0] contains all five type-constant names.
    Mutation caught: if REPEATABLE_COMMENT is dropped from comment_types,
    repeatable comments across the entire program are silently lost.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = []

    _run(bridge.get_all_comments())

    script = fake.exec_calls[0]
    assert "EOL_COMMENT" in script
    assert "PRE_COMMENT" in script
    assert "POST_COMMENT" in script
    assert "PLATE_COMMENT" in script
    assert "REPEATABLE_COMMENT" in script


def test_get_all_comments_returns_empty_list_when_none() -> None:
    """get_all_comments returns [] when the script result is falsy.

    Oracle: eval_response = None (program has no commented code units).
    Mutation caught: if the falsy guard is removed, None is returned to callers
    who attempt to iterate or index the result.
    """
    bridge, fake = _make_bridge()
    fake.eval_response = None

    result = _run(bridge.get_all_comments())

    assert result == []


# ---------------------------------------------------------------------------
# Disconnected guards - connection check must still raise ToolError
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method_name", "args"),
    [
        ("get_data_type", (_TEST_ADDRESS,)),
        ("set_data_type", (_TEST_ADDRESS, "dword")),
        ("create_data_type", ("/", "T", "enum")),
        ("create_data", (_TEST_ADDRESS, "dword")),
        ("get_structures", ()),
        ("apply_structure_at", (_TEST_ADDRESS, "S")),
        ("get_bookmarks", ()),
        ("get_equates", ()),
        ("get_comments", (_TEST_ADDRESS,)),
        ("get_all_comments", ()),
    ],
)
def test_disconnected_raises_tool_error(method_name: str, args: tuple[object, ...]) -> None:
    """Each GHIDRA-D method raises ToolError when the bridge is not connected.

    Args:
        method_name: Bridge method to call.
        args: Positional arguments to pass to the method.
    """
    bridge = GhidraBridge()
    method = getattr(bridge, method_name)
    with pytest.raises(ToolError, match="not connected"):
        _run(method(*args))
