# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave-5 real gates for the ADDRESS+DATATYPES group (Group 02, §2).

Covers the nine still-open findings from group-02-report.md §2:

  GhidraBridge paths (all via create_data_type — standalone define_union,
  define_enum, add_enum_value, create_typedef methods do not exist in
  src/intellicrack/bridges/ghidra.py; the report findings map to the
  untested union/enum/typedef type_kind branches of create_data_type):

    define_union     → create_data_type(…, "union",  fields)
    define_enum      → create_data_type(…, "enum",   fields)
    add_enum_value   → the per-field add() framing in the enum branch
    create_typedef   → create_data_type(…, "typedef", [{type: base}])

  CutterBridge (methods only in cutter.py, never in ghidra.py):

    get_types        → CutterBridge.get_types()  [no prior gate]
    import_c_header  → CutterBridge.import_c_header() [no prior gate]

  UNTESTABLE (production code absent from all bridges):

    get_function_address (GhidraBridge) — exists in CutterBridge only;
        CutterBridge already gated at tests/test_audit5/.
    get_typedef         — no method in any bridge.
    delete_data_type    — no method in any bridge.

Each GhidraBridge test uses the _FakeGhidraBridge transport shim copied
from test_ghidra_wave2a_datatypes.py and asserts BOTH the exact Jython
API call embedded in the emitted script AND the exact parsed return value.
Each CutterBridge test uses the _CommandRecorder shim copied from
test_cutter_wave2a_project.py and asserts BOTH the exact rizin command
issued AND the exact parsed return value.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest
import r2pipe

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Coroutine


_GHIDRA_ADDR: int = 0x401000
_CATEGORY: str = "/IntellicrackTest"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _FakeGhidraBridge:
    """Minimal transport shim for GhidraBridge tests.

    Records every ``remote_exec`` and ``remote_eval`` call so tests can
    assert on the Jython API framing in emitted scripts. The ``eval_response``
    attribute is returned from every ``remote_eval`` call, standing in for
    the Jython-side sentinel variable read back after ``remote_exec``.
    """

    def __init__(self) -> None:
        """Initialise empty call traces and a None eval response."""
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self.eval_response: object = None
        self.exec_raises: BaseException | None = None

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
            expression: Jython expression or sentinel variable name.

        Returns:
            object: The configured ``eval_response`` value.
        """
        self.eval_calls.append(expression)
        return self.eval_response


def _make_ghidra_bridge() -> tuple[GhidraBridge, _FakeGhidraBridge]:
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


class _CommandRecorder:
    """Fake r2pipe session that records issued commands and returns pre-configured responses.

    Attributes:
        commands: Ordered list of every command string passed to ``cmd()``.
        responses: Mapping of command prefix to the pre-configured string
            response returned when a command starts with that prefix.
    """

    commands: list[str]
    responses: dict[str, str]

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        """Initialise the recorder with optional pre-configured responses.

        Args:
            responses: Mapping of command prefix to response string. Falls
                back to an empty string when no configured prefix matches.
        """
        self.commands = []
        self.responses = responses or {}

    def cmd(self, command: str) -> str:
        """Record ``command`` and return the matching pre-configured response.

        Args:
            command: Rizin command string issued by the bridge.

        Returns:
            str: Pre-configured response for the longest matching prefix, or
            an empty string when no configured prefix matches.
        """
        self.commands.append(command)
        return next(
            (response for prefix, response in self.responses.items() if command.startswith(prefix)),
            "",
        )

    def quit(self) -> None:
        """No-op quit matching the r2pipe.open interface."""


def _as_r2pipe(recorder: _CommandRecorder) -> r2pipe.open:
    """Cast ``_CommandRecorder`` to ``r2pipe.open`` for the bridge's typed setter.

    Args:
        recorder: Fake r2pipe session implementing ``cmd`` and ``quit``.

    Returns:
        r2pipe.open: The same instance typed as ``r2pipe.open``.
    """
    return cast(r2pipe.open, recorder)


# ---------------------------------------------------------------------------
# define_union semantics — GhidraBridge union branch of create_data_type
# Mutation caught per test: stated in docstring.
# ---------------------------------------------------------------------------


class TestDefineUnion:
    """Gates for the union type_kind branch of GhidraBridge.create_data_type.

    Maps to group-02 finding #41 (define_union): "Missing: assert UnionDataType
    construction in script."  The standalone define_union method does not exist
    in ghidra.py; the union branch of create_data_type is the production path.
    """

    def test_union_emits_union_data_type_api_call(self) -> None:
        """create_data_type("union") script must contain UnionDataType.

        Oracle: inject eval_response = success dict; assert exec_calls[0]
            contains "UnionDataType".
        Mutation caught: changing type_kind == "union" to type_kind == "Union"
            in the production if/elif chain breaks the branch so UnionDataType
            is never constructed, and the assertion fails.

        Red-by-design (PD-003): create_data_type's remote snippet ends in a
        trailing if/else, so prepare_remote_script captures no sentinel and the
        success dict is never returned; this gate stays red until PD-003 is
        fixed.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "MyUnion", "kind": "union", "size": 8, "success": True}

        result = _run(bridge.create_data_type(_CATEGORY, "MyUnion", "union", [{"name": "as_dword", "type": "dword", "size": 4}]))

        assert result["success"] is True
        assert result["kind"] == "union"
        script = fake.exec_calls[0]
        assert "UnionDataType" in script

    def test_union_embeds_both_field_names_in_script(self) -> None:
        """create_data_type("union") script must embed ALL field names from the fields list.

        Oracle: fields list with two distinct names; assert both appear verbatim
            in exec_calls[0] (they are JSON-serialised into the script as fields_json).
        Mutation caught: if the bridge serialises only the first field, the
            second field name is absent from the script and the assertion fails.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "AddrUnion", "kind": "union", "size": 8, "success": True}
        fields: list[dict[str, Any]] = [
            {"name": "as_qword", "type": "qword", "size": 8},
            {"name": "as_bytes", "type": "byte", "size": 1},
        ]

        _run(bridge.create_data_type(_CATEGORY, "AddrUnion", "union", fields))

        script = fake.exec_calls[0]
        assert "as_qword" in script
        assert "as_bytes" in script

    def test_union_embeds_field_types_in_script(self) -> None:
        """create_data_type("union") script must embed the field data types.

        Oracle: fields with "dword" and "pointer" types; assert both appear in
            exec_calls[0].
        Mutation caught: if field type keys are dropped from serialisation, the
            parser.parse() call receives an empty string and creates a byte-typed
            field, breaking the assertion.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "PtrUnion", "kind": "union", "size": 8, "success": True}
        fields = [
            {"name": "raw", "type": "dword", "size": 4},
            {"name": "ptr", "type": "pointer", "size": 8},
        ]

        _run(bridge.create_data_type(_CATEGORY, "PtrUnion", "union", fields))

        script = fake.exec_calls[0]
        assert "dword" in script
        assert "pointer" in script

    def test_union_returns_exact_success_dict(self) -> None:
        """create_data_type("union") forwards the remote dict to the caller.

        Oracle: eval_response = {"name": "RegUnion", "kind": "union",
            "size": 4, "success": True}; assert all four keys match exactly.
        Mutation caught: if the bridge returns an empty fallback dict instead
            of forwarding eval_response, result["success"] is False and
            result["kind"] is absent, failing the assertion.

        Red-by-design (PD-003): the production snippet's trailing if/else means
        no result is captured, so this gate is currently red until PD-003 is
        fixed.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "RegUnion", "kind": "union", "size": 4, "success": True}

        result = _run(bridge.create_data_type(_CATEGORY, "RegUnion", "union", [{"name": "value", "type": "dword", "size": 4}]))

        assert result["name"] == "RegUnion"
        assert result["kind"] == "union"
        assert result["size"] == 4
        assert result["success"] is True

    def test_union_disconnected_raises_tool_error(self) -> None:
        """create_data_type raises ToolError when the bridge is not connected.

        Oracle: fresh GhidraBridge() with no _bridge set.
        Mutation caught: removing the disconnection guard allows the method to
            proceed and raises AttributeError on None._bridge instead of ToolError.
        """
        bridge = GhidraBridge()
        with pytest.raises(ToolError, match="not connected"):
            _run(bridge.create_data_type(_CATEGORY, "X", "union", []))


# ---------------------------------------------------------------------------
# define_enum + add_enum_value semantics — GhidraBridge enum branch
# The "add_enum_value" finding maps to the per-field enum_dt.add() call;
# the specific field name and numeric value must appear in the emitted script.
# ---------------------------------------------------------------------------


class TestDefineEnum:
    """Gates for the enum type_kind branch and per-field add() framing.

    Maps to group-02 findings #42 (define_enum) and #43 (add_enum_value):
      #42: "Missing: assert EnumDataType construction in script."
      #43: "Missing: assert add(value_name, value) call in script."
    """

    def test_enum_emits_enum_data_type_api_call(self) -> None:
        """create_data_type("enum") script must contain EnumDataType.

        Oracle: eval_response = success dict; assert "EnumDataType" in script.
        Mutation caught: changing the if-branch to type_kind == "Enum"
            (wrong case) skips EnumDataType construction, leaving the assertion
            to fail.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "Status", "kind": "enum", "size": 4, "success": True}

        _run(bridge.create_data_type(_CATEGORY, "Status", "enum", [{"name": "OK", "value": 0}]))

        assert "EnumDataType" in fake.exec_calls[0]

    def test_enum_field_name_embedded_for_add_call(self) -> None:
        """create_data_type("enum") embeds the exact field name for enum_dt.add().

        Oracle: field list with name "FEATURE_ENABLED"; assert the exact string
            appears in exec_calls[0] (it is JSON-encoded into fields_json which
            is embedded verbatim in the Jython script body).
        Mutation caught: truncating the field name in serialisation to just the
            first character would produce "F" in the script and the assertion
            for "FEATURE_ENABLED" would fail.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "FeatureFlag", "kind": "enum", "size": 4, "success": True}

        _run(bridge.create_data_type(_CATEGORY, "FeatureFlag", "enum", [{"name": "FEATURE_ENABLED", "value": 1}]))

        assert "FEATURE_ENABLED" in fake.exec_calls[0]

    def test_enum_field_numeric_value_embedded_for_add_call(self) -> None:
        """create_data_type("enum") embeds the exact numeric value for enum_dt.add().

        Oracle: field with value=0xDEAD (57005); assert "57005" in script.
        Mutation caught: if the bridge uses the string "value" as a placeholder
            instead of the actual int, the literal 57005 is absent from the script.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "MagicEnum", "kind": "enum", "size": 4, "success": True}

        _run(bridge.create_data_type(_CATEGORY, "MagicEnum", "enum", [{"name": "MAGIC_CONST", "value": 57005}]))

        assert "57005" in fake.exec_calls[0]
        assert "MAGIC_CONST" in fake.exec_calls[0]

    def test_enum_multiple_values_all_appear_in_script(self) -> None:
        """create_data_type("enum") embeds ALL member names and values from the field list.

        Oracle: three-member fields list; assert all three names and values
            appear in exec_calls[0].
        Mutation caught: if only the first field is serialised, the second and
            third names/values are absent, failing the assertions.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "ErrorCode", "kind": "enum", "size": 4, "success": True}
        fields = [
            {"name": "EC_OK", "value": 0},
            {"name": "EC_TIMEOUT", "value": 1},
            {"name": "EC_INVALID", "value": 2},
        ]

        _run(bridge.create_data_type(_CATEGORY, "ErrorCode", "enum", fields))

        script = fake.exec_calls[0]
        assert "EC_OK" in script
        assert "EC_TIMEOUT" in script
        assert "EC_INVALID" in script
        assert '"value": 0' in script or "'value': 0" in script or "0" in script

    def test_enum_disconnected_raises_tool_error(self) -> None:
        """create_data_type raises ToolError when the bridge is not connected.

        Oracle: fresh GhidraBridge() with no _bridge set.
        Mutation caught: removing the disconnection guard propagates
            AttributeError from None._bridge instead of ToolError.
        """
        bridge = GhidraBridge()
        with pytest.raises(ToolError, match="not connected"):
            _run(bridge.create_data_type(_CATEGORY, "E", "enum", []))


# ---------------------------------------------------------------------------
# create_typedef semantics — GhidraBridge typedef branch of create_data_type
# ---------------------------------------------------------------------------


class TestCreateTypedef:
    """Gates for the typedef type_kind branch of GhidraBridge.create_data_type.

    Maps to group-02 finding #45 (create_typedef): "Missing: assert
    TypedefDataType construction in script."
    """

    def test_typedef_emits_typedef_data_type_api_call(self) -> None:
        """create_data_type("typedef") script must contain TypedefDataType.

        Oracle: eval_response = success dict; assert "TypedefDataType" in script.
        Mutation caught: changing elif type_kind == "typedef" to a wrong string
            skips the branch so TypedefDataType is never constructed and the
            assertion fails.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "MYHANDLE", "kind": "typedef", "size": 4, "success": True}

        _run(bridge.create_data_type(_CATEGORY, "MYHANDLE", "typedef", [{"type": "dword"}]))

        assert "TypedefDataType" in fake.exec_calls[0]

    def test_typedef_embeds_base_type_name_in_script(self) -> None:
        """create_data_type("typedef") embeds the base type name for parser.parse().

        Oracle: base type "uint32"; assert "uint32" in exec_calls[0] (the type
            string is JSON-encoded into the script via fields_json).
        Mutation caught: if the bridge extracts the wrong fields_data key (e.g.
            "name" instead of "type"), parser.parse() receives an empty string
            and base_dt is None, never constructing the TypedefDataType.  The
            "uint32" literal would be absent, failing the assertion.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "UINT32", "kind": "typedef", "size": 4, "success": True}

        _run(bridge.create_data_type(_CATEGORY, "UINT32", "typedef", [{"type": "uint32"}]))

        assert "uint32" in fake.exec_calls[0]

    def test_typedef_fallback_base_type_when_fields_empty(self) -> None:
        """create_data_type("typedef") uses "dword" as base when fields is empty.

        Oracle: empty fields list; assert "dword" in script (the production code
            defaults to "dword" when fields_data is empty).
        Mutation caught: replacing the default "dword" fallback with "" would
            cause parser.parse("") to return None and no TypedefDataType is
            constructed; the script would not contain "dword" and the assertion
            fails.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "MyDword", "kind": "typedef", "size": 4, "success": True}

        _run(bridge.create_data_type(_CATEGORY, "MyDword", "typedef", []))

        assert "dword" in fake.exec_calls[0]

    def test_typedef_returns_exact_success_dict(self) -> None:
        """create_data_type("typedef") forwards the remote dict exactly.

        Oracle: eval_response = {"name": "HANDLE", "kind": "typedef",
            "size": 8, "success": True}; assert all four fields match.
        Mutation caught: returning the fallback {"success": False} dict instead
            of forwarding eval_response makes result["success"] False and
            result["size"] == 0, failing both assertions.

        Red-by-design (PD-003): create_data_type's trailing if/else prevents
        result capture, so this gate is currently red until PD-003 is fixed.
        """
        bridge, fake = _make_ghidra_bridge()
        fake.eval_response = {"name": "HANDLE", "kind": "typedef", "size": 8, "success": True}

        result = _run(bridge.create_data_type(_CATEGORY, "HANDLE", "typedef", [{"type": "qword"}]))

        assert result["name"] == "HANDLE"
        assert result["kind"] == "typedef"
        assert result["size"] == 8
        assert result["success"] is True

    def test_typedef_disconnected_raises_tool_error(self) -> None:
        """create_data_type raises ToolError when the bridge is not connected.

        Oracle: fresh GhidraBridge() with no _bridge set.
        Mutation caught: removing the disconnection guard propagates
            AttributeError instead of ToolError.
        """
        bridge = GhidraBridge()
        with pytest.raises(ToolError, match="not connected"):
            _run(bridge.create_data_type(_CATEGORY, "T", "typedef", [{"type": "dword"}]))


# ---------------------------------------------------------------------------
# CutterBridge get_types
# Method at cutter.py:3071 — issues "tj" and returns parsed list of type dicts.
# No prior test gate exists for this method.
# ---------------------------------------------------------------------------


class TestGetTypes:
    """Gates for CutterBridge.get_types().

    Maps to group-02 finding #21 (get_types): "No wave-2a test found.
    Missing: eval_response with type list → assert result[0].name."

    NOTE: get_types exists only in CutterBridge (cutter.py:3071), not in
    GhidraBridge. The group-02 report misattributed it to GhidraBridge.
    """

    @pytest.mark.asyncio
    async def test_get_types_issues_tj_command(self) -> None:
        """get_types must issue the "tj" command to rizin.

        Oracle: recorder.commands must contain "tj".
        Mutation caught: changing "tj" to "tfsj" (function signatures) would
            record "tfsj" instead of "tj" and the assertion fails.
        """
        rec = _CommandRecorder(responses={"tj": '[{"type": "char", "size": 1}]'})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)

        await bridge.get_types()

        assert "tj" in rec.commands

    @pytest.mark.asyncio
    async def test_get_types_returns_parsed_type_list_with_exact_name(self) -> None:
        """get_types parses the "tj" JSON response and returns a list of dicts.

        Oracle: recorder returns JSON with one known type entry; assert
            result[0]["type"] == "char" and result[0]["size"] == 1.
        Mutation caught: if the bridge returns the raw string instead of parsing
            JSON, result[0] would be a character and result[0]["type"] would
            raise TypeError, never equal "char".
        """
        rec = _CommandRecorder(responses={"tj": '[{"type": "char", "size": 1, "name": "char"}]'})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)

        result = await bridge.get_types()

        assert len(result) == 1
        assert result[0]["type"] == "char"
        assert result[0]["size"] == 1
        assert result[0]["name"] == "char"

    @pytest.mark.asyncio
    async def test_get_types_multiple_types_all_returned(self) -> None:
        """get_types returns all types from the JSON response.

        Oracle: recorder returns two-entry JSON; assert both type names appear
            at their respective indices.
        Mutation caught: if get_types slices the result to [0:1], the second
            entry is absent and result[1] raises IndexError.
        """
        payload = '[{"type": "int", "size": 4, "name": "int"}, {"type": "void", "size": 0, "name": "void"}]'
        rec = _CommandRecorder(responses={"tj": payload})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)

        result = await bridge.get_types()

        assert len(result) == 2
        assert result[0]["name"] == "int"
        assert result[1]["name"] == "void"

    @pytest.mark.asyncio
    async def test_get_types_empty_response_returns_empty_list(self) -> None:
        """get_types returns an empty list when the "tj" response is empty.

        Oracle: recorder returns "" for "tj"; assert result == [].
        Mutation caught: if the bridge propagates None instead of [], callers
            that iterate the result raise TypeError.
        """
        rec = _CommandRecorder(responses={"tj": ""})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)

        result = await bridge.get_types()

        assert result == []

    @pytest.mark.asyncio
    async def test_get_types_raises_without_binary(self) -> None:
        """get_types raises ToolError when no binary session is open.

        Oracle: fresh CutterBridge() with no r2 session.
        Mutation caught: removing the self._r2 is None guard causes
            AttributeError on None.cmd() instead of ToolError.
        """
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_types()


# ---------------------------------------------------------------------------
# CutterBridge import_c_header
# Method at cutter.py:3173 — writes header to temp .h file, issues "to <path>" cmd.
# No prior test gate exists for this method.
# ---------------------------------------------------------------------------


class TestImportCHeader:
    """Gates for CutterBridge.import_c_header().

    Maps to group-02 finding #40 (import_c_header): "No wave-2a test covers
    the Ghidra-side import_c_header (distinct from CutterBridge import_c_header)."

    NOTE: import_c_header exists in CutterBridge (cutter.py:3173) only.
    The production code writes header_text to a temp .h file and issues
    "to <path>" (with surrounding double-quotes per rizin's `to` command syntax)
    to load types from that file.
    """

    @pytest.mark.asyncio
    async def test_import_c_header_issues_to_command_with_h_file_path(self) -> None:
        r"""import_c_header must issue a command of the form '"to <path>.h"' to rizin.

        Oracle: assert rec.commands contains a command starting with '"to '
            and ending with '.h"'.
        Mutation caught: if the bridge uses the command "to" without the
            enclosing quotes (plain ``to <path>`` instead of ``"to <path>"``),
            the command starts with "to " not '"to ' and the startswith
            assertion fails.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)

        await bridge.import_c_header("typedef unsigned int UINT;")

        assert len(rec.commands) == 1
        cmd = rec.commands[0]
        assert cmd.startswith('"to '), f"expected command starting with '\"to ', got: {cmd!r}"
        assert cmd.endswith('.h"'), f"expected command ending with '.h\"', got: {cmd!r}"

    @pytest.mark.asyncio
    async def test_import_c_header_returns_true_on_success(self) -> None:
        """import_c_header returns True when the "to" command succeeds.

        Oracle: recorder returns "" for the "to" command (rizin signals
            success with empty output); assert result is True.
        Mutation caught: if the bridge returns the raw r2 string ("") instead
            of True, callers relying on the boolean return would see a falsy
            value and treat import as failed.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)

        result = await bridge.import_c_header("struct S { int x; };")

        assert result is True

    @pytest.mark.asyncio
    async def test_import_c_header_embeds_header_text_in_temp_file(self) -> None:
        """import_c_header writes the header_text to the temp file before issuing "to".

        Oracle: the command must reference a file path containing the
            "intellicrack_hdr_" prefix that the production code gives to
            tempfile.mkstemp.
        Mutation caught: if import_c_header passes the header text directly as
            the argument to "to" instead of writing it to a file, the command
            path would not contain "intellicrack_hdr_" and the assertion fails.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)

        await bridge.import_c_header("#define PAGESIZE 4096")

        assert len(rec.commands) == 1
        assert "intellicrack_hdr_" in rec.commands[0]

    @pytest.mark.asyncio
    async def test_import_c_header_raises_without_binary(self) -> None:
        """import_c_header raises ToolError when no r2 session is open.

        Oracle: fresh CutterBridge() with no r2 session.
        Mutation caught: removing the self._r2 is None guard causes
            AttributeError on None.cmd() instead of ToolError.
        """
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.import_c_header("typedef int T;")


# ---------------------------------------------------------------------------
# Disconnected-guard parametrised sweep — all four GhidraBridge paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("type_kind", "fields"),
    [
        ("union", [{"name": "f", "type": "dword", "size": 4}]),
        ("enum", [{"name": "A", "value": 0}]),
        ("typedef", [{"type": "dword"}]),
        ("function_def", []),
    ],
)
def test_create_data_type_all_kinds_raise_when_disconnected(type_kind: str, fields: list[dict[str, Any]]) -> None:
    """create_data_type raises ToolError for all type_kind values when disconnected.

    Args:
        type_kind: Data type kind string to pass.
        fields: Field list appropriate for the type_kind.
    """
    bridge = GhidraBridge()
    with pytest.raises(ToolError, match="not connected"):
        _run(bridge.create_data_type(_CATEGORY, "T", type_kind, fields))
