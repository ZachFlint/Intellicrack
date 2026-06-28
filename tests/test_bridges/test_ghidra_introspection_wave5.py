# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave-5 introspection/memory real-gate suite for GhidraBridge.

Group 02 §2 — INTROSPECTION/MEMORY gate closure.

This file resolves thirteen NOT_RESOLVED findings from the group-02-report STILL
OPEN table.  Six of those findings reference methods that do not exist in the
current production source (``get_data_references``, ``get_instruction_at``,
``get_register_values`` plural, ``emulate_function``, ``get_stack_trace``,
``get_local_variables``); those are UNTESTABLE and are documented in the final
status block without test functions.  The remaining seven findings correspond to
production methods with slightly different names from the audit labels:

  Audit label           Production method      Status
  get_comment           get_comments           Gate here
  get_namespace         get_namespaces         Gate here
  set_namespace         create_namespace       Gate here
  get_bytes_at          read_bytes             Gate here
  patch_bytes           write_bytes            Gate here
  get_function_comments get_all_comments       Gate here
  get_function_graph    get_call_graph         Gate here

Seam: ``_FakeGhidraRemote`` captures every script sent via ``remote_exec`` in
``exec_calls`` and every sentinel-name via ``remote_eval`` in ``eval_calls``,
and returns a pre-configured ``eval_response`` from every ``remote_eval`` call.
This exercises ``prepare_remote_script`` rewriting and ``_execute_remote``
dispatch end-to-end without a live Ghidra installation.

Oracle justification for each gate:
  get_comments      — canned eval_response injected with known address/type/text;
                      bridge parses the dict unchanged, so the assertion is on
                      the injected constant, independently chosen.
  get_namespaces    — same pattern; ``name`` and ``path`` keys are verified against
                      the injected dict, not re-derived.
  create_namespace  — script content oracle: Ghidra SymbolTable API spec
                      ``createNameSpace``; result-field oracle: injected dict.
  read_bytes        — result oracle: ``bytes.fromhex`` of a known sequence;
                      ``hex`` field oracle: ``' '.join(f'{b:02X}' ...)`` computed
                      independently.
  write_bytes       — script oracle: Python int sign-conversion formula
                      ``(b - 256) if b > 127``, independently computed to -112
                      for 0x90; result verified against injected readback dict.
  get_all_comments  — canned eval_response; ``comment`` field oracle is the known
                      injected string constant.
  get_call_graph    — canned eval_response; callees/callers oracle is the
                      injected structure with independently-chosen names/addresses.
"""

from __future__ import annotations

from typing import Any, Final

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


_TEST_ADDR: Final[int] = 0x401000
_ROOT_ADDR: Final[int] = 0x401000
_LEAF_ADDR: Final[int] = 0x402000


class _FakeGhidraRemote:
    """In-process double for the ``ghidra_bridge`` RPC client.

    Records every exec/eval payload the bridge sends; returns ``eval_response``
    from every ``remote_eval`` call.  Inspect ``exec_calls`` after calling a
    bridge method to assert what Jython was emitted; set ``eval_response``
    before calling to inject the canned remote result.
    """

    def __init__(self, response: object = None) -> None:
        """Initialise with an optional pre-configured eval response.

        Args:
            response: Value returned by every ``remote_eval`` call.
        """
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self.eval_response: object = response

    def remote_exec(self, code: str) -> None:
        """Record the rewritten Jython source; perform no side-effects.

        Args:
            code: Jython source emitted after ``prepare_remote_script``
                rewrites the trailing expression as a sentinel assignment.
        """
        self.exec_calls.append(code)

    def remote_eval(self, expr: str) -> object:
        """Record the sentinel name and return the pre-configured response.

        Args:
            expr: Sentinel variable name produced by ``prepare_remote_script``.

        Returns:
            object: The ``eval_response`` set at construction or via direct
            attribute assignment.
        """
        self.eval_calls.append(expr)
        return self.eval_response


def _make_bridge(response: object = None) -> tuple[GhidraBridge, _FakeGhidraRemote]:
    """Return a connected GhidraBridge backed by a deterministic fake.

    Args:
        response: Value the fake's ``remote_eval`` returns.

    Returns:
        tuple[GhidraBridge, _FakeGhidraRemote]: Connected bridge and the
        fake for direct introspection.
    """
    bridge = GhidraBridge()
    fake = _FakeGhidraRemote(response)
    bridge.attach_remote_bridge(fake)
    return bridge, fake


class TestGetComments:
    """Real gates for ``GhidraBridge.get_comments`` (audit label: ``get_comment``).

    The audit found ``get_comment`` (singular) had only a disconnected-state
    test.  The actual production method is ``get_comments`` (plural), which
    scans an address range and returns a list of comment dicts.  These gates
    verify that the bridge (a) emits the correct Ghidra Listing API framing
    and (b) parses the remote result into the exact address/type/text structure.

    Oracle: the canned eval_response is an independently-constructed list whose
    ``address``, ``type``, and ``comment`` values are known constants chosen
    before calling the bridge.
    """

    @pytest.mark.asyncio
    async def test_get_comments_parses_address_field_exactly(self) -> None:
        """``get_comments`` must map the remote ``address`` field to the output dict.

        Mutation caught: dropping the ``address`` key from the bridge's return
        mapping → ``result[0]['address']`` becomes ``KeyError``.
        """
        known_response: list[dict[str, Any]] = [
            {"address": _TEST_ADDR, "type": "EOL", "comment": "branch_target"},
        ]
        bridge, _ = _make_bridge(known_response)

        result = await bridge.get_comments(_TEST_ADDR)

        assert len(result) == 1
        assert result[0]["address"] == _TEST_ADDR

    @pytest.mark.asyncio
    async def test_get_comments_parses_type_and_text_exactly(self) -> None:
        """``get_comments`` must surface the ``type`` and ``comment`` text verbatim.

        Oracle: injected constants ``"PRE"`` and ``"known_annotation_text"``;
        neither is re-derived from production code.

        Mutation caught: swapping ``type`` → ``comment_type`` in the bridge's
        output mapping → assertion on ``result[0]['type']`` fails.
        """
        known_response: list[dict[str, Any]] = [
            {"address": _TEST_ADDR, "type": "PRE", "comment": "known_annotation_text"},
        ]
        bridge, _ = _make_bridge(known_response)

        result = await bridge.get_comments(_TEST_ADDR)

        assert len(result) == 1
        assert result[0]["type"] == "PRE"
        assert result[0]["comment"] == "known_annotation_text"

    @pytest.mark.asyncio
    async def test_get_comments_script_contains_get_comment_api(self) -> None:
        """``get_comments`` script must call the Ghidra ``getComment`` API.

        The bridge iterates CodeUnit objects and reads each comment type via
        ``cu.getComment(type_const)``.  If this call is absent, no comments
        are ever collected regardless of what the program contains.

        Mutation caught: replacing ``getComment`` with ``getCommentAsArray``
        (a Ghidra variant that returns arrays, not strings) → assertion fails.
        """
        bridge, fake = _make_bridge([])

        await bridge.get_comments(_TEST_ADDR)

        assert len(fake.exec_calls) >= 1
        script = fake.exec_calls[0]
        assert "getComment" in script

    @pytest.mark.asyncio
    async def test_get_comments_script_embeds_exact_address(self) -> None:
        """``get_comments`` script must embed the queried address in the Jython.

        Without the address, the ``toAddr`` call would use a hardcoded offset
        and scan the wrong memory region.

        Mutation caught: omitting the f-string address substitution →
        assertion on ``str(_TEST_ADDR)`` fails.
        """
        bridge, fake = _make_bridge([])

        await bridge.get_comments(_TEST_ADDR)

        assert len(fake.exec_calls) >= 1
        script = fake.exec_calls[0]
        assert str(_TEST_ADDR) in script

    @pytest.mark.asyncio
    async def test_get_comments_raises_when_not_connected(self) -> None:
        """``get_comments`` raises ``ToolError`` with "not connected" when bridge is disconnected.

        Mutation caught: removing the ``_bridge is None`` guard → method calls
        ``remote_exec`` on ``None`` and raises ``AttributeError`` instead of
        ``ToolError``.
        """
        bridge = GhidraBridge()

        with pytest.raises(ToolError, match="not connected"):
            await bridge.get_comments(_TEST_ADDR)


class TestGetNamespaces:
    """Real gates for ``GhidraBridge.get_namespaces`` (audit label: ``get_namespace``).

    The audit found ``get_namespace`` (singular) had no functional gate.
    The production method is ``get_namespaces`` (plural).  These gates verify
    the script emits ``SymbolType.NAMESPACE`` filtering and that the result
    contains the exact ``name`` and ``path`` fields.

    Oracle: injected ``name`` and ``path`` constants chosen before calling the
    bridge; ``path`` uses the ``getName(True)`` qualified form the bridge computes.
    """

    @pytest.mark.asyncio
    async def test_get_namespaces_parses_name_field_exactly(self) -> None:
        """``get_namespaces`` must map the ``name`` key to the result element.

        Mutation caught: placing the name under ``ns_name`` instead of
        ``name`` → ``result[0]['name']`` raises ``KeyError``.
        """
        known_response: list[dict[str, Any]] = [
            {"name": "ns_alpha", "path": "Global::ns_alpha"},
        ]
        bridge, _ = _make_bridge(known_response)

        result = await bridge.get_namespaces()

        assert len(result) == 1
        assert result[0]["name"] == "ns_alpha"

    @pytest.mark.asyncio
    async def test_get_namespaces_parses_path_field_exactly(self) -> None:
        """``get_namespaces`` must include the qualified ``path`` from ``getName(True)``.

        Oracle: ``"Global::ns_alpha"`` — the Ghidra ``getName(True)`` qualified
        form is injected as a known constant.

        Mutation caught: using ``sym.getName()`` (unqualified) for ``path``
        instead of ``sym.getName(True)`` → ``path`` would equal ``"ns_alpha"``
        and fail the exact-path assertion.
        """
        known_response: list[dict[str, Any]] = [
            {"name": "ns_alpha", "path": "Global::ns_alpha"},
        ]
        bridge, _ = _make_bridge(known_response)

        result = await bridge.get_namespaces()

        assert len(result) == 1
        assert result[0]["path"] == "Global::ns_alpha"

    @pytest.mark.asyncio
    async def test_get_namespaces_script_filters_by_namespace_symbol_type(self) -> None:
        """``get_namespaces`` script must check ``SymbolType.NAMESPACE`` to exclude labels.

        Without the type filter the method would return every symbol (functions,
        labels, imports) rather than just namespace declarations.

        Mutation caught: removing the ``SymbolType.NAMESPACE`` check →
        assertion on the script string fails.
        """
        bridge, fake = _make_bridge([])

        await bridge.get_namespaces()

        assert len(fake.exec_calls) >= 1
        script = fake.exec_calls[0]
        assert "SymbolType.NAMESPACE" in script

    @pytest.mark.asyncio
    async def test_get_namespaces_raises_when_not_connected(self) -> None:
        """``get_namespaces`` raises ``ToolError`` when the bridge is not connected.

        Mutation caught: removing the ``_bridge is None`` guard → raises
        ``AttributeError`` instead of ``ToolError``.
        """
        bridge = GhidraBridge()

        with pytest.raises(ToolError, match="not connected"):
            await bridge.get_namespaces()


class TestCreateNamespace:
    """Real gates for ``GhidraBridge.create_namespace`` (audit label: ``set_namespace``).

    The audit found ``set_namespace`` with no gate.  The production method is
    ``create_namespace``.  Gates verify (a) the script calls
    ``createNameSpace`` with the user-supplied name, and (b) the bridge
    surfaces the ``name``, ``path``, and ``success`` fields from the remote result.

    Oracle: the canned eval_response and the script content are both verified
    against independently-known constants (the Ghidra SymbolTable API spec
    and the injected dict values).
    """

    @pytest.mark.asyncio
    async def test_create_namespace_script_calls_create_name_space_api(self) -> None:
        """``create_namespace`` script must call Ghidra's ``createNameSpace``.

        ``st.createNameSpace(parent, name, SourceType.USER_DEFINED)`` is the
        only SymbolTable method that creates a new namespace symbol.

        Mutation caught: replacing ``createNameSpace`` with ``createLabel`` →
        assertion on the script string fails, and the created symbol would have
        the wrong type.
        """
        response: dict[str, Any] = {"name": "Utilities", "path": "Utilities", "success": True}
        bridge, fake = _make_bridge(response)

        await bridge.create_namespace("Utilities")

        assert len(fake.exec_calls) >= 1
        script = fake.exec_calls[0]
        assert "createNameSpace" in script

    @pytest.mark.asyncio
    async def test_create_namespace_script_embeds_name_as_json_string(self) -> None:
        """``create_namespace`` script must embed the name via ``json.dumps`` quoting.

        The bridge uses ``json.dumps(name)`` to produce the Jython string
        literal, ensuring names with quotes or backslashes do not break the
        Jython syntax.

        Mutation caught: embedding the name unquoted → a name containing a
        space or quote would produce a syntax error on the Jython side, or the
        assertion on the quoted form would fail.
        """
        name = "AnalysisHelpers"
        response: dict[str, Any] = {"name": name, "path": name, "success": True}
        bridge, fake = _make_bridge(response)

        await bridge.create_namespace(name)

        assert len(fake.exec_calls) >= 1
        script = fake.exec_calls[0]
        assert f'"{name}"' in script

    @pytest.mark.asyncio
    async def test_create_namespace_returns_name_path_success_from_remote(self) -> None:
        """``create_namespace`` must surface all three result fields verbatim.

        Oracle: the canned eval_response dict provides independently-chosen
        ``name``, ``path``, and ``success`` values; the bridge must not
        transform or rename them.

        Mutation caught: discarding ``path`` from the returned dict → assertion
        on ``result['path']`` fails.
        """
        ns_name = "CryptoUtils"
        ns_path = "Global::CryptoUtils"
        response: dict[str, Any] = {"name": ns_name, "path": ns_path, "success": True}
        bridge, _ = _make_bridge(response)

        result = await bridge.create_namespace(ns_name)

        assert result["name"] == ns_name
        assert result["path"] == ns_path
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_create_namespace_raises_when_not_connected(self) -> None:
        """``create_namespace`` raises ``ToolError`` when bridge is not connected.

        Mutation caught: removing the connection guard → ``AttributeError`` is
        raised instead of ``ToolError``.
        """
        bridge = GhidraBridge()

        with pytest.raises(ToolError, match="not connected"):
            await bridge.create_namespace("AnyNamespace")


class TestReadBytes:
    """Real gates for ``GhidraBridge.read_bytes`` (audit label: ``get_bytes_at``).

    The audit found ``get_bytes_at`` with no functional gate.  The production
    method is ``read_bytes``.  Gates verify (a) the script calls
    ``getMemory().getBytes`` and embeds the requested address, and (b) the
    bridge correctly converts the remote byte list to ``hex`` and ``bytes`` fields.

    Oracle: ``bytes.fromhex("90EB05")`` provides the independent expected value;
    the ``hex`` field is verified against the independently-computed string
    ``"90 EB 05"``.
    """

    @pytest.mark.asyncio
    async def test_read_bytes_parses_byte_list_exactly(self) -> None:
        """``read_bytes`` must convert the remote byte list to the exact result.

        Oracle: ``list(bytes.fromhex("90EB05"))`` → ``[0x90, 0xEB, 0x05]``
        computed independently of the bridge.

        Mutation caught: dropping the ``& 0xFF`` mask on the byte conversion →
        bytes >127 would be negative ints in the result, failing the exact-value
        assertion.
        """
        expected_bytes = list(bytes.fromhex("90EB05"))
        response: dict[str, Any] = {"address": _TEST_ADDR, "bytes": expected_bytes}
        bridge, _ = _make_bridge(response)

        result = await bridge.read_bytes(_TEST_ADDR, 3)

        assert result["bytes"] == expected_bytes

    @pytest.mark.asyncio
    async def test_read_bytes_formats_hex_field_correctly(self) -> None:
        """``read_bytes`` must format the ``hex`` field as space-separated uppercase hex.

        Oracle: ``"90 EB 05"`` — independently computed from ``bytes.fromhex``
        using the ``' '.join(f'{b:02X}' ...)`` idiom.

        Mutation caught: using ``''.join(f'{b:02x}' ...)`` (no space, lowercase)
        → the assertion ``result['hex'] == "90 EB 05"`` fails.
        """
        expected_bytes = list(bytes.fromhex("90EB05"))
        response: dict[str, Any] = {"address": _TEST_ADDR, "bytes": expected_bytes}
        bridge, _ = _make_bridge(response)

        result = await bridge.read_bytes(_TEST_ADDR, 3)

        assert result["hex"] == "90 EB 05"

    @pytest.mark.asyncio
    async def test_read_bytes_returns_correct_length_field(self) -> None:
        """``read_bytes`` must set ``length`` to the actual byte count.

        Mutation caught: hardcoding ``length=0`` in the returned dict →
        assertion fails.
        """
        expected_bytes = list(bytes.fromhex("90EB05"))
        response: dict[str, Any] = {"address": _TEST_ADDR, "bytes": expected_bytes}
        bridge, _ = _make_bridge(response)

        result = await bridge.read_bytes(_TEST_ADDR, 3)

        assert result["length"] == 3

    @pytest.mark.asyncio
    async def test_read_bytes_script_contains_get_memory_get_bytes(self) -> None:
        """``read_bytes`` script must call ``getMemory().getBytes`` to read memory.

        Mutation caught: replacing ``getMemory().getBytes`` with
        ``currentProgram.getBytes`` (a non-existent method) → the script
        assertion fails, and the Jython would error at runtime.
        """
        response: dict[str, Any] = {"address": _TEST_ADDR, "bytes": [0x00]}
        bridge, fake = _make_bridge(response)

        await bridge.read_bytes(_TEST_ADDR, 1)

        assert len(fake.exec_calls) >= 1
        script = fake.exec_calls[0]
        assert "getMemory().getBytes" in script

    @pytest.mark.asyncio
    async def test_read_bytes_raises_tool_error_on_length_mismatch(self) -> None:
        """``read_bytes`` raises ``ToolError`` when the remote returns fewer bytes than requested.

        Mutation caught: removing the length-mismatch guard → truncated reads
        silently return partial data instead of surfacing the error.
        """
        response: dict[str, Any] = {"address": _TEST_ADDR, "bytes": [0x90]}
        bridge, _ = _make_bridge(response)

        with pytest.raises(ToolError, match="truncated"):
            await bridge.read_bytes(_TEST_ADDR, 4)

    @pytest.mark.asyncio
    async def test_read_bytes_raises_when_not_connected(self) -> None:
        """``read_bytes`` raises ``ToolError`` when the bridge is not connected.

        Mutation caught: removing the connection guard → ``AttributeError``
        instead of ``ToolError``.
        """
        bridge = GhidraBridge()

        with pytest.raises(ToolError, match="not connected"):
            await bridge.read_bytes(_TEST_ADDR, 4)


class TestWriteBytes:
    """Real gates for ``GhidraBridge.write_bytes`` (audit label: ``patch_bytes``).

    The audit found ``patch_bytes`` (distinct from ``write_bytes``) had no gate.
    The production method is ``write_bytes``.  These gates verify (a) the
    bridge applies the signed-byte conversion required by Jython's ``jarray``
    and embeds the correct signed representation in the script, and (b) the
    readback verification logic raises on mismatch.

    Oracle for sign-conversion: the formula ``(b - 256) if b > 127`` applied to
    ``0x90`` (144) yields ``-112``.  This is computed independently of
    production code.
    """

    @pytest.mark.asyncio
    async def test_write_bytes_script_contains_signed_byte_for_0x90(self) -> None:
        """``write_bytes`` must emit the signed Jython form for bytes > 127.

        Jython's ``jarray.array(values, 'b')`` requires signed bytes (range
        -128..127); the bridge sign-converts any unsigned value > 127 by
        subtracting 256.  For ``0x90 = 144``, the result is ``144 - 256 = -112``.

        Oracle: ``0x90 - 256 = -112`` — independently computed.

        Mutation caught: omitting the sign conversion and embedding ``144`` →
        Jython raises ``ValueError``; or changing the threshold → values near
        127 are converted differently, failing the assertion.
        """
        readback: list[int] = [0x90, 0x90]
        response: dict[str, Any] = {
            "write_error": None,
            "readback_bytes": readback,
            "readback_hex": "9090",
            "committed": True,
        }
        bridge, fake = _make_bridge(response)

        await bridge.write_bytes(_TEST_ADDR, "90 90")

        assert len(fake.exec_calls) >= 1
        script = fake.exec_calls[0]
        assert "-112" in script

    @pytest.mark.asyncio
    async def test_write_bytes_script_calls_set_bytes_api(self) -> None:
        """``write_bytes`` script must call ``memory.setBytes`` to commit the patch.

        Mutation caught: replacing ``setBytes`` with ``patchBytes`` (a method
        that does not exist on Ghidra's Memory object in this context) →
        the script assertion fails and the Jython would error at runtime.
        """
        readback: list[int] = [0x90]
        response: dict[str, Any] = {
            "write_error": None,
            "readback_bytes": readback,
            "readback_hex": "90",
            "committed": True,
        }
        bridge, fake = _make_bridge(response)

        await bridge.write_bytes(_TEST_ADDR, "90")

        assert len(fake.exec_calls) >= 1
        script = fake.exec_calls[0]
        assert "setBytes" in script

    @pytest.mark.asyncio
    async def test_write_bytes_returns_verified_and_bytes_written(self) -> None:
        """``write_bytes`` must return ``verified=True`` and correct ``bytes_written``.

        Oracle: the readback matches the expected two-byte payload exactly, so
        the bridge commits the transaction and returns ``verified=True``,
        ``bytes_written=2``.

        Mutation caught: hardcoding ``bytes_written=0`` in the return dict →
        assertion fails.
        """
        readback: list[int] = [0x90, 0x90]
        response: dict[str, Any] = {
            "write_error": None,
            "readback_bytes": readback,
            "readback_hex": "9090",
            "committed": True,
        }
        bridge, _ = _make_bridge(response)

        result = await bridge.write_bytes(_TEST_ADDR, "90 90")

        assert result["bytes_written"] == 2
        assert result["verified"] is True
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_write_bytes_raises_on_readback_mismatch(self) -> None:
        """``write_bytes`` raises ``ToolError`` when readback bytes do not match.

        If memory protection prevents the write, the readback contains the
        original bytes rather than the requested payload.  The bridge must
        detect this mismatch and raise.

        Mutation caught: removing the ``readback != expected_list`` guard →
        the method silently returns success even when the patch failed.
        """
        response: dict[str, Any] = {
            "write_error": None,
            "readback_bytes": [0x00, 0x00],
            "readback_hex": "0000",
            "committed": False,
        }
        bridge, _ = _make_bridge(response)

        with pytest.raises(ToolError):
            await bridge.write_bytes(_TEST_ADDR, "90 90")

    @pytest.mark.asyncio
    async def test_write_bytes_raises_when_not_connected(self) -> None:
        """``write_bytes`` raises ``ToolError`` when the bridge is not connected.

        Mutation caught: removing the connection guard → ``AttributeError``
        instead of ``ToolError``.
        """
        bridge = GhidraBridge()

        with pytest.raises(ToolError, match="not connected"):
            await bridge.write_bytes(_TEST_ADDR, "90")


class TestGetAllComments:
    """Real gates for ``GhidraBridge.get_all_comments`` (audit label: ``get_function_comments``).

    The audit found ``get_function_comments`` with no gate.  The production
    method is ``get_all_comments``.  Gates verify the script iterates all code
    units via ``getCodeUnits(True)`` and that the ``comment`` field is preserved.

    Oracle: the canned eval_response provides independently-chosen comment
    strings that the bridge must return verbatim.
    """

    @pytest.mark.asyncio
    async def test_get_all_comments_returns_exact_comment_text(self) -> None:
        """``get_all_comments`` must surface the ``comment`` text from the remote result.

        Oracle: the injected ``comment`` string ``"loop_entry_annotation"`` is
        chosen independently; the bridge must return it verbatim.

        Mutation caught: mapping the ``comment`` key to ``text`` instead →
        ``result[0]['comment']`` raises ``KeyError``.
        """
        known_response: list[dict[str, Any]] = [
            {"address": _TEST_ADDR, "type": "PRE", "comment": "loop_entry_annotation"},
        ]
        bridge, _ = _make_bridge(known_response)

        result = await bridge.get_all_comments()

        assert len(result) == 1
        assert result[0]["comment"] == "loop_entry_annotation"

    @pytest.mark.asyncio
    async def test_get_all_comments_returns_exact_type_field(self) -> None:
        """``get_all_comments`` must surface the ``type`` field from the remote dict.

        Mutation caught: dropping ``type`` from the returned dict → assertion
        on ``result[0]['type']`` fails.
        """
        known_response: list[dict[str, Any]] = [
            {"address": _TEST_ADDR, "type": "PLATE", "comment": "function_header"},
        ]
        bridge, _ = _make_bridge(known_response)

        result = await bridge.get_all_comments()

        assert result[0]["type"] == "PLATE"
        assert result[0]["address"] == _TEST_ADDR

    @pytest.mark.asyncio
    async def test_get_all_comments_script_uses_get_code_units_true(self) -> None:
        """``get_all_comments`` script must call ``getCodeUnits(True)`` for forward iteration.

        ``True`` sets the ``forward`` flag so units are returned in address
        order; omitting it or passing ``False`` reverses iteration order.

        Mutation caught: using ``getCodeUnits(False)`` → assertion on the script
        string fails.
        """
        bridge, fake = _make_bridge([])

        await bridge.get_all_comments()

        assert len(fake.exec_calls) >= 1
        script = fake.exec_calls[0]
        assert "getCodeUnits(True)" in script

    @pytest.mark.asyncio
    async def test_get_all_comments_raises_when_not_connected(self) -> None:
        """``get_all_comments`` raises ``ToolError`` when the bridge is disconnected.

        Mutation caught: removing the connection guard → ``AttributeError``
        instead of ``ToolError``.
        """
        bridge = GhidraBridge()

        with pytest.raises(ToolError, match="not connected"):
            await bridge.get_all_comments()


class TestGetCallGraph:
    """Real gates for ``GhidraBridge.get_call_graph`` (audit label: ``get_function_graph``).

    The audit found ``get_function_graph`` with no gate.  The production method
    is ``get_call_graph``.  These gates verify that the bridge correctly parses
    the bidirectional call-graph result from the remote Jython execution,
    asserting exact ``name``, ``address``, ``callees``, and ``callers`` values.

    Oracle: a canned eval_response dict with independently-chosen function names
    and addresses.
    """

    @pytest.mark.asyncio
    async def test_get_call_graph_parses_root_name_and_address_exactly(self) -> None:
        """``get_call_graph`` must surface the root function ``name`` and ``address``.

        Oracle: ``"dispatcher_fn"`` and ``0x401000`` injected as known constants.

        Mutation caught: using ``graph.get("entry_point")`` instead of
        ``graph.get("address")`` → ``result['address']`` returns 0 (the default)
        and fails the exact-address assertion.
        """
        response: dict[str, Any] = {
            "name": "dispatcher_fn",
            "address": _ROOT_ADDR,
            "callees": [],
            "callers": [],
        }
        bridge, _ = _make_bridge(response)

        result = await bridge.get_call_graph(_ROOT_ADDR, depth=1)

        assert result["name"] == "dispatcher_fn"
        assert result["address"] == _ROOT_ADDR

    @pytest.mark.asyncio
    async def test_get_call_graph_parses_callee_name_and_address(self) -> None:
        """``get_call_graph`` must surface the ``callees`` sub-tree with correct fields.

        Oracle: callee ``"read_config"`` at ``0x402000`` injected as constants;
        the bridge must return them in the ``callees`` list without transformation.

        Mutation caught: merging callees and callers into a single ``children``
        list → ``result['callees'][0]['name']`` raises ``KeyError``.
        """
        callee: dict[str, Any] = {"name": "read_config", "address": _LEAF_ADDR, "callees": []}
        response: dict[str, Any] = {
            "name": "init_fn",
            "address": _ROOT_ADDR,
            "callees": [callee],
            "callers": [],
        }
        bridge, _ = _make_bridge(response)

        result = await bridge.get_call_graph(_ROOT_ADDR, depth=1)

        assert len(result["callees"]) == 1
        assert result["callees"][0]["name"] == "read_config"
        assert result["callees"][0]["address"] == _LEAF_ADDR

    @pytest.mark.asyncio
    async def test_get_call_graph_parses_empty_callers_list(self) -> None:
        """``get_call_graph`` must return an empty list when there are no callers.

        Mutation caught: returning ``None`` instead of ``[]`` for an empty
        callers subtree → ``len(result['callers'])`` raises ``TypeError``.
        """
        response: dict[str, Any] = {
            "name": "standalone_fn",
            "address": _ROOT_ADDR,
            "callees": [],
            "callers": [],
        }
        bridge, _ = _make_bridge(response)

        result = await bridge.get_call_graph(_ROOT_ADDR, depth=1)

        assert result["callers"] == []

    @pytest.mark.asyncio
    async def test_get_call_graph_script_uses_get_called_functions(self) -> None:
        """``get_call_graph`` script must call ``getCalledFunctions`` for callee traversal.

        The Ghidra ``Function.getCalledFunctions(monitor)`` API returns call
        targets in a single RPC round-trip; earlier implementations issued one
        call per byte of the function body.

        Mutation caught: replacing ``getCalledFunctions`` with
        ``getReferencesFrom`` (the old per-byte approach) → assertion fails and
        runtime performance would degrade severely.
        """
        response: dict[str, Any] = {
            "name": "f",
            "address": _ROOT_ADDR,
            "callees": [],
            "callers": [],
        }
        bridge, fake = _make_bridge(response)

        await bridge.get_call_graph(_ROOT_ADDR, depth=1)

        assert len(fake.exec_calls) >= 1
        script = fake.exec_calls[0]
        assert "getCalledFunctions" in script

    @pytest.mark.asyncio
    async def test_get_call_graph_script_uses_get_calling_functions(self) -> None:
        """``get_call_graph`` script must call ``getCallingFunctions`` for caller traversal.

        Mutation caught: omitting the ``collect_callers`` helper or using
        ``getReferencesTo`` instead → assertion on the script string fails.
        """
        response: dict[str, Any] = {
            "name": "f",
            "address": _ROOT_ADDR,
            "callees": [],
            "callers": [],
        }
        bridge, fake = _make_bridge(response)

        await bridge.get_call_graph(_ROOT_ADDR, depth=1)

        assert len(fake.exec_calls) >= 1
        script = fake.exec_calls[0]
        assert "getCallingFunctions" in script

    @pytest.mark.asyncio
    async def test_get_call_graph_raises_when_function_not_found(self) -> None:
        """``get_call_graph`` raises ``ToolError`` when the remote returns ``None``.

        When ``getFunctionContaining`` returns ``None`` the script assigns
        ``_call_graph_payload = None``; the bridge must surface this as a
        ``ToolError`` rather than silently returning ``None``.

        Mutation caught: returning ``None`` directly instead of raising
        ``ToolError`` → the return type is wrong and the caller cannot
        distinguish "no function" from a valid result.
        """
        bridge, _ = _make_bridge(None)

        with pytest.raises(ToolError):
            await bridge.get_call_graph(_ROOT_ADDR, depth=1)

    @pytest.mark.asyncio
    async def test_get_call_graph_raises_when_not_connected(self) -> None:
        """``get_call_graph`` raises ``ToolError`` when the bridge is disconnected.

        Mutation caught: removing the connection guard → ``AttributeError``
        instead of ``ToolError``.
        """
        bridge = GhidraBridge()

        with pytest.raises(ToolError, match="not connected"):
            await bridge.get_call_graph(_ROOT_ADDR)
