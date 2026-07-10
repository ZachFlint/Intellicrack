# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""GHIDRA-E regression gates: edits, memory, search, options, diff.

Converts the following disconnected-gate-only operations into real,
falsifiable body tests that exercise the bridge's Jython-script
generation (wire framing) and response-parsing logic:

    create_function, delete_function, edit_function_signature,
    set_function_variable_type, write_bytes, undo, redo, search_strings,
    search_bytes, create_memory_block, configure_analysis,
    set_decompiler_options, import_debug_info, diff_programs.

Already REAL (skipped): rename_function, execute_script, read_bytes.

Each test injects a _FakeGhidraBridge whose eval_response is the
independent oracle (the canned Ghidra-side result), asserts that the
Ghidra API name appears in the emitted exec script (wire framing), and
asserts the exact parsed return structure against the known oracle.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any, Final, cast


if TYPE_CHECKING:
    from pathlib import Path

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import StringInfo, ToolError


_TEST_ADDR: Final[int] = 0x401000
_TEST_ADDR_HEX: Final[str] = "0x401000"
_OTHER_PROGRAM_PATH: Final[str] = r"C:\analysis\other.exe"

_EvalResponder = Callable[[str], object]


class _FakeGhidraBridge:
    """In-process double for the ghidra_bridge RPC client.

    Records every call to remote_exec and remote_eval so tests can
    inspect the Jython wire framing emitted by the production bridge.
    eval_response supplies the canned Ghidra-side return value that
    _execute_remote delivers back to the production method body.
    """

    def __init__(self) -> None:
        """Initialise empty call traces and default response values."""
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self.eval_response: object = None
        self.exec_response: object = None
        self._eval_responder: _EvalResponder | None = None
        self.exec_raises: BaseException | None = None
        self.eval_raises: BaseException | None = None

    def set_eval_responder(self, responder: _EvalResponder) -> None:
        """Install a callable that computes the eval response from the expression.

        Args:
            responder: Callable receiving the expression string and
                returning the desired response value.
        """
        self._eval_responder = responder

    def remote_exec(self, code: str) -> object:
        """Record the script payload and optionally raise or return exec_response.

        Args:
            code: Jython source string emitted by the production bridge.

        Returns:
            object: exec_response when set, otherwise None.

        Raises:
            exc: Re-raised when the caller has set exec_raises on the fake.
                exc is bound to whatever exception instance the caller installed.
        """
        self.exec_calls.append(code)
        exc = self.exec_raises
        if exc is not None:
            raise exc
        return self.exec_response

    def remote_eval(self, expression: str, **_kwargs: object) -> object:
        """Record the expression and return the programmed eval_response.

        Args:
            expression: Sentinel variable name produced by prepare_remote_script
                or a direct eval expression from _execute_remote_eval.
            **_kwargs: Extra keyword arguments accepted to match the real
                jfx_bridge signature; ignored by the fake.

        Returns:
            object: Responder's return value when a responder is installed,
            otherwise the static eval_response field.

        Raises:
            exc: Re-raised when the caller has set eval_raises on the fake.
                exc is bound to whatever exception instance the caller installed.
        """
        self.eval_calls.append(expression)
        exc = self.eval_raises
        if exc is not None:
            raise exc
        if self._eval_responder is not None:
            return self._eval_responder(expression)
        return self.eval_response


@pytest.fixture
def fake() -> _FakeGhidraBridge:
    """Provide a fresh _FakeGhidraBridge with empty traces.

    Returns:
        _FakeGhidraBridge: A test double with empty call lists.
    """
    return _FakeGhidraBridge()


@pytest.fixture
def connected_bridge(fake: _FakeGhidraBridge) -> GhidraBridge:
    """Provide a GhidraBridge wired to the _FakeGhidraBridge.

    Args:
        fake: The recording fake fixture.

    Returns:
        GhidraBridge: A bridge instance whose _bridge attribute is the
        fake and whose state.connected is True.
    """
    bridge = GhidraBridge()
    setattr(bridge, "_bridge", fake)
    bridge.state.connected = True
    return bridge


def _run(coro: Coroutine[Any, Any, object]) -> object:
    """Run an async coroutine to completion in a fresh event loop.

    Args:
        coro: Coroutine to execute.

    Returns:
        object: The coroutine's return value.
    """
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# create_function
# ---------------------------------------------------------------------------


def test_create_function_happy_path_returns_dict_with_correct_fields(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """create_function happy path must parse remote result into name/address/size.

    Oracle: eval_response supplies the canned Jython dict that Ghidra
    returns after createFunction succeeds. Independent oracle: the bridge
    must map the dict's 'name' key to result['name'], 'address' key to
    result['address'], and 'size' key to result['size'].

    Mutation caught: if result['address'] is populated from the wrong
    key (e.g., 'entry' instead of 'address'), this assertion fails.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake providing the oracle via eval_response.
    """
    fake.eval_response = {"name": "sub_1000", "address": _TEST_ADDR, "size": 32}

    result = cast("dict[str, Any]", _run(connected_bridge.create_function(_TEST_ADDR, "sub_1000")))

    assert result["name"] == "sub_1000"
    assert result["address"] == _TEST_ADDR
    assert result["size"] == 32
    assert len(fake.exec_calls) == 1
    assert "createFunction" in fake.exec_calls[0]


def test_create_function_none_result_raises_tool_error(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """create_function must raise ToolError when Ghidra returns None.

    Oracle: eval_response is None (Ghidra returned no function object),
    which happens when createFunction is called on an address that
    already has a conflicting definition.

    Mutation caught: if the None guard is removed, the method would
    return None (or crash on cast) instead of raising ToolError.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake whose eval_response is None.
    """
    fake.eval_response = None

    with pytest.raises(ToolError, match="Failed to create function"):
        _run(connected_bridge.create_function(_TEST_ADDR))


# ---------------------------------------------------------------------------
# delete_function
# ---------------------------------------------------------------------------


def test_delete_function_happy_path_returns_correct_dict(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """delete_function happy path must surface address, name, and success.

    Oracle: Ghidra returns {'exists': True, 'name': 'old_fn', 'removed': True}.
    The bridge must parse this into {'address': hex(addr), 'name': 'old_fn',
    'success': True}.

    Mutation caught: if 'removed' is read from the wrong key (e.g.,
    'deleted'), the method raises ToolError instead of returning success.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake providing the oracle via eval_response.
    """
    fake.eval_response = {"exists": True, "name": "old_fn", "removed": True}

    result = cast("dict[str, Any]", _run(connected_bridge.delete_function(_TEST_ADDR)))

    assert result["address"] == _TEST_ADDR_HEX
    assert result["name"] == "old_fn"
    assert result["success"] is True
    assert len(fake.exec_calls) == 1
    assert "removeFunction" in fake.exec_calls[0]


def test_delete_function_not_found_raises_tool_error(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """delete_function must raise ToolError when no function exists at address.

    Oracle: Ghidra returns {'exists': False, 'name': None, 'removed': False}.

    Mutation caught: if the exists guard is removed, the method would
    return a partial dict instead of raising ToolError.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake whose eval_response reports no function found.
    """
    fake.eval_response = {"exists": False, "name": None, "removed": False}

    with pytest.raises(ToolError, match="Function not found"):
        _run(connected_bridge.delete_function(_TEST_ADDR))


# ---------------------------------------------------------------------------
# edit_function_signature
# ---------------------------------------------------------------------------


def test_edit_function_signature_happy_path_returns_correct_dict(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """edit_function_signature must parse remote dict into all four fields.

    Oracle: Ghidra returns name, address, return_type, and
    calling_convention after the edit. The bridge must surface all four.

    Mutation caught: if return_type is populated from the wrong key
    (e.g., 'ret_type' instead of 'return_type'), the assertion fails.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake providing the oracle via eval_response.
    """
    fake.eval_response = {
        "name": "decrypt",
        "address": _TEST_ADDR,
        "return_type": "int",
        "calling_convention": "__cdecl",
    }

    result = cast(
        "dict[str, Any]",
        _run(
            connected_bridge.edit_function_signature(
                _TEST_ADDR,
                return_type="int",
                calling_convention="__cdecl",
                name="decrypt",
            ),
        ),
    )

    assert result["name"] == "decrypt"
    assert result["address"] == _TEST_ADDR
    assert result["return_type"] == "int"
    assert result["calling_convention"] == "__cdecl"
    assert len(fake.exec_calls) == 1
    assert "getFunctionContaining" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# set_function_variable_type
# ---------------------------------------------------------------------------


def test_set_function_variable_type_found_returns_success_dict(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """set_function_variable_type must return var_name/new_type/success when found.

    Oracle: Ghidra returns True (variable found and retyped). The bridge
    maps this to {'var_name': 'local_8', 'new_type': 'DWORD', 'success': True}.

    Mutation caught: if the result['var_name'] key is changed (e.g., to
    'variable'), the assertion fails because we check the exact key name.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake whose eval_response is True.
    """
    fake.eval_response = True

    result = cast(
        "dict[str, Any]",
        _run(
            connected_bridge.set_function_variable_type(_TEST_ADDR, "local_8", "DWORD"),
        ),
    )

    assert result["var_name"] == "local_8"
    assert result["new_type"] == "DWORD"
    assert result["success"] is True
    assert len(fake.exec_calls) == 1
    assert "getAllVariables" in fake.exec_calls[0]


def test_set_function_variable_type_not_found_raises_tool_error(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """set_function_variable_type must raise ToolError when variable not found.

    Oracle: Ghidra returns False (no matching variable name).

    Mutation caught: if the not-found guard is removed, the method
    would return an incomplete dict instead of raising ToolError.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake whose eval_response is False.
    """
    fake.eval_response = False

    with pytest.raises(ToolError, match="not found"):
        _run(
            connected_bridge.set_function_variable_type(_TEST_ADDR, "nonexistent", "DWORD"),
        )


# ---------------------------------------------------------------------------
# write_bytes
# ---------------------------------------------------------------------------


def test_write_bytes_happy_path_returns_verified_dict(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """write_bytes happy path must return bytes_written count and verified flag.

    Oracle: Ghidra returns readback_bytes matching the written payload
    [0x90, 0x90], no write_error, committed=True. The bridge must
    compare expected_list == readback, commit, and return
    {address, bytes_written: 2, verified: True, success: True}.

    Mutation caught: if bytes_written is set to len(data) instead of
    len(unsigned_bytes), the byte count would be wrong for hex input
    with spaces. Here 'data' length would be 5 ('90 90') vs 2 (unsigned bytes).

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake providing the oracle via eval_response.
    """
    fake.eval_response = {
        "write_error": None,
        "readback_bytes": [0x90, 0x90],
        "readback_hex": "9090",
        "committed": True,
    }

    result = cast("dict[str, Any]", _run(connected_bridge.write_bytes(_TEST_ADDR, "90 90")))

    assert result["address"] == _TEST_ADDR_HEX
    assert result["bytes_written"] == 2
    assert result["verified"] is True
    assert result["success"] is True
    assert len(fake.exec_calls) == 1
    assert "setBytes" in fake.exec_calls[0]


def test_write_bytes_readback_mismatch_raises_tool_error(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """write_bytes must raise ToolError when readback does not match payload.

    Oracle: Ghidra returns readback_bytes [0x80, 0x90] but the written
    payload was [0x90, 0x90]. The comparison readback != expected_list
    must trigger the verification-failed ToolError.

    Mutation caught: if the readback comparison is removed, the mismatch
    would go undetected and the method would return success=True despite
    the memory not reflecting the write.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake whose readback_bytes differ from the payload.
    """
    fake.eval_response = {
        "write_error": None,
        "readback_bytes": [0x80, 0x90],
        "readback_hex": "8090",
        "committed": False,
    }

    with pytest.raises(ToolError, match="verification failed"):
        _run(connected_bridge.write_bytes(_TEST_ADDR, "90 90"))


def test_write_bytes_invalid_hex_raises_before_dispatch(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """write_bytes must raise ToolError for odd-length hex before any RPC call.

    Oracle: '9' is an odd-length hex string (no complete bytes). The
    bridge must detect this before calling remote_exec so zero RPC
    calls are made.

    Mutation caught: if the length check is removed, the invalid hex
    would be forwarded to Ghidra, causing a harder-to-diagnose remote error.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake whose exec_calls must remain empty.
    """
    with pytest.raises(ToolError, match="Invalid hex payload"):
        _run(connected_bridge.write_bytes(_TEST_ADDR, "9"))

    assert len(fake.exec_calls) == 0


# ---------------------------------------------------------------------------
# undo / redo  (production defect fixed: script was syntactically invalid)
# ---------------------------------------------------------------------------


def test_undo_emits_undo_call_and_returns_success(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """Undo must emit a script containing currentProgram.undo() and return success.

    Oracle: eval_response is True (Ghidra's undo() completed). The bridge
    must return {'success': True}.

    Mutation caught: if the script calls redo() instead of undo(), the
    assertion on exec_calls would detect the wrong API name.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake whose eval_response is True.
    """
    fake.eval_response = True

    result = cast("dict[str, Any]", _run(connected_bridge.undo()))

    assert result == {"success": True}
    assert len(fake.exec_calls) == 1
    assert "undo" in fake.exec_calls[0]
    assert "redo" not in fake.exec_calls[0]


def test_redo_emits_redo_call_and_returns_success(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """Redo must emit a script containing currentProgram.redo() and return success.

    Oracle: eval_response is True (Ghidra's redo() completed). The bridge
    must return {'success': True}.

    Mutation caught: if the script calls undo() instead of redo(), the
    assertion on exec_calls would detect the wrong API name.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake whose eval_response is True.
    """
    fake.eval_response = True

    result = cast("dict[str, Any]", _run(connected_bridge.redo()))

    assert result == {"success": True}
    assert len(fake.exec_calls) == 1
    assert "redo" in fake.exec_calls[0]
    assert "undo" not in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# search_strings
# ---------------------------------------------------------------------------


def test_search_strings_result_fields_populated_correctly(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """search_strings must map remote dict fields into StringInfo attributes.

    Oracle: Ghidra returns a list with one record containing address,
    value, and type_name. The bridge must build StringInfo(address=0x401000,
    value='hello world', encoding='ascii', section='').

    Mutation caught: if s.get('value', '') is changed to s.get('text', ''),
    the StringInfo.value would be '' instead of 'hello world'.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake providing the oracle via eval_response.
    """
    fake.eval_response = [
        {"address": _TEST_ADDR, "value": "hello world", "type_name": "string"},
    ]

    result = cast("list[StringInfo]", _run(connected_bridge.search_strings("hello")))

    assert len(result) == 1
    assert result[0].address == _TEST_ADDR
    assert result[0].value == "hello world"
    assert result[0].encoding == "ascii"
    assert len(fake.exec_calls) == 1
    assert "getListing" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# search_bytes (hex_pattern path — address list parsing)
# ---------------------------------------------------------------------------


def test_search_bytes_hex_pattern_parses_address_list_as_ints(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """search_bytes must convert every element of the remote address list to int.

    Oracle: Ghidra returns floating-point addresses (Java longs sometimes
    arrive as floats). The bridge must convert them with int() before
    returning. Providing floats as oracle makes the conversion observable.

    Mutation caught: if int(addr) is removed from the list comprehension,
    the result contains floats and isinstance(result[0], int) fails.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake providing float addresses as oracle.
    """
    fake.eval_response = [float(_TEST_ADDR), float(_TEST_ADDR + 0x1000)]

    result = cast("list[int]", _run(connected_bridge.search_bytes(hex_pattern="90 90")))

    assert result == [_TEST_ADDR, _TEST_ADDR + 0x1000]
    assert all(isinstance(a, int) for a in result)
    assert len(fake.exec_calls) == 1
    assert "findBytes" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# create_memory_block
# ---------------------------------------------------------------------------


def test_create_memory_block_happy_path_returns_correct_dict(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """create_memory_block must surface name, start, size, permissions, success.

    Oracle: Ghidra returns the block attributes after createInitializedBlock
    and permission-setter calls succeed.

    Mutation caught: if size is populated from the wrong remote key (e.g.,
    'length' instead of 'size'), the assertion on result['size'] fails.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake providing the oracle via eval_response.
    """
    fake.eval_response = {
        "name": ".custom",
        "start": 0x10000,
        "size": 0x1000,
        "permissions": "rw",
        "success": True,
    }

    result = cast(
        "dict[str, Any]",
        _run(
            connected_bridge.create_memory_block(".custom", 0x10000, 0x1000, "rw"),
        ),
    )

    assert result["name"] == ".custom"
    assert result["start"] == 0x10000
    assert result["size"] == 0x1000
    assert result["permissions"] == "rw"
    assert result["success"] is True
    assert len(fake.exec_calls) == 1
    assert "createInitializedBlock" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# configure_analysis
# ---------------------------------------------------------------------------


def test_configure_analysis_happy_path_returns_correct_dict(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """configure_analysis must return analyzer name, enabled flag, and success.

    Oracle: Ghidra returns {'analyzer': 'ByteAnalyzer', 'enabled': True,
    'success': True} after the analyzer is found and enabled.

    Mutation caught: if success is read from the wrong key (e.g., 'found'
    instead of 'success'), the returned dict shows False instead of True.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake providing the oracle via eval_response.
    """
    fake.eval_response = {
        "analyzer": "ByteAnalyzer",
        "enabled": True,
        "success": True,
    }

    result = cast(
        "dict[str, Any]",
        _run(
            connected_bridge.configure_analysis("ByteAnalyzer", enabled=True),
        ),
    )

    assert result["analyzer"] == "ByteAnalyzer"
    assert result["enabled"] is True
    assert result["success"] is True
    assert len(fake.exec_calls) == 1
    assert "getAnalyzers" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# set_decompiler_options
# ---------------------------------------------------------------------------


def test_set_decompiler_options_persists_and_returns_correct_dict(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """set_decompiler_options must store options and return them in the result dict.

    Oracle: The persisted values come from the method's own assignment
    (self._decompiler_simplification = simplification), not from the remote
    response. eval_response simulates a successful remote apply.

    Mutation caught: if 'self._decompiler_simplification = simplification'
    is removed, effective_simp remains None and result['simplification'] is
    None instead of 'normalize', failing the assertion.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake providing the oracle via eval_response.
    """
    fake.eval_response = {
        "simplification": "normalize",
        "max_instructions": 256,
        "extra": {},
        "success": True,
    }

    result = cast(
        "dict[str, Any]",
        _run(
            connected_bridge.set_decompiler_options(
                simplification="normalize",
                max_instructions=256,
            ),
        ),
    )

    assert result["simplification"] == "normalize"
    assert result["max_instructions"] == 256
    assert result["success"] is True
    assert len(fake.exec_calls) == 1
    assert "DecompInterface" in fake.exec_calls[0]
    opts = connected_bridge.decompiler_options
    assert opts["simplification"] == "normalize"
    assert opts["max_instructions"] == 256


# ---------------------------------------------------------------------------
# import_debug_info (connected happy path)
# ---------------------------------------------------------------------------


def test_import_debug_info_connected_pdb_path_returns_correct_dict(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
    tmp_path: Path,
) -> None:
    """Import_debug_info must parse the remote result into path/success/type/analyzer.

    Oracle: A real .pdb file is written to tmp_path so path resolution
    succeeds. eval_response simulates PdbUniversalAnalyzer success.

    Mutation caught: if result['type'] is read from the wrong remote key
    (e.g., 'format' instead of 'type'), the assertion fails because 'type'
    key maps to 'pdb' but a wrong key would map to the default or empty string.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake providing the oracle via eval_response.
        tmp_path: Pytest temporary directory for creating the stub .pdb file.
    """
    pdb_file = tmp_path / "symbols.pdb"
    pdb_file.write_bytes(b"MRSOFT")

    fake.eval_response = {
        "path": str(pdb_file),
        "success": True,
        "type": "pdb",
        "analyzer": "PdbUniversalAnalyzer",
        "error": None,
    }

    result = cast("dict[str, Any]", _run(connected_bridge.import_debug_info(str(pdb_file))))

    assert result["success"] is True
    assert result["type"] == "pdb"
    assert result["analyzer"] == "PdbUniversalAnalyzer"
    assert result["error"] is None
    assert len(fake.exec_calls) == 1
    assert "PdbUniversalAnalyzer" in fake.exec_calls[0]


# ---------------------------------------------------------------------------
# diff_programs
# ---------------------------------------------------------------------------


def test_diff_programs_parses_differences_and_details(
    connected_bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """diff_programs must surface the differences count and details list.

    Oracle: Ghidra returns {'differences': 3, 'details': [{'address': 0x1000}]}.
    The bridge returns it directly via cast after the isinstance check.

    Mutation caught: if the isinstance guard is removed and a non-dict is
    returned, the method would raise ToolError instead of returning the dict.
    If the dict is returned but 'details' key is wrong, details assertion fails.

    Args:
        connected_bridge: Bridge fixture wired to the fake.
        fake: Recording fake providing the oracle via eval_response.
    """
    fake.eval_response = {
        "differences": 3,
        "details": [{"address": 0x1000}],
    }

    result = cast("dict[str, Any]", _run(connected_bridge.diff_programs(_OTHER_PROGRAM_PATH)))

    assert result["differences"] == 3
    assert len(result["details"]) == 1
    assert result["details"][0]["address"] == 0x1000
    assert len(fake.exec_calls) == 1
    assert "ProgramDiff" in fake.exec_calls[0]
