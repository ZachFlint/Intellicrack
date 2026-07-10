# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave-2A GHIDRA-A: real connected-state gates for core analysis methods.

Covers the following GhidraBridge operations that were previously gated only
by disconnected-state ToolError guards (the guard verifies only that the method
exists and raises on the connection check — it does NOT gate the script
generation, Ghidra API framing, or response-parsing logic that runs when
connected):

  load_binary, get_functions, get_function, disassemble, get_imports,
  get_exports, get_program_info, get_function_body

Operations already carrying REAL functional gates in test_ghidra_audit6.py
(analyze, decompile) are intentionally omitted here.

Each test asserts BOTH:
  (1) the Ghidra Flat API call that must appear in the emitted Jython script
  (2) the exact typed value the bridge produces by parsing the fake response

The oracle is the independently-known dict/list we inject as the fake
remote_eval return value. Any mutation that changes the dict key the bridge
reads, the field the bridge maps the value to, or the type it constructs will
break the exact-value assertion.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


_TEST_ADDR: int = 0x401000
_TEST_IMPORT_ADDR: int = 0x5000
_TEST_EXPORT_ADDR: int = 0x6000
_TEST_FUNC_ADDR: int = 0x8000

_EvalResponder = Callable[[str], object]


def _build_elf64_header() -> bytes:
    """Build a minimal syntactically-valid ELF64 x86-64 header (256 bytes).

    Encodes EI_CLASS=ELFCLASS64, EI_DATA=ELFDATA2LSB, e_machine=EM_X86_64
    (0x3E) so format and architecture detection produces ``"elf"`` /
    ``("x86_64", True)``.

    Returns:
        bytes: 256-byte buffer whose first 64 bytes form a valid ELF64 header.
    """
    data = bytearray(256)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<H", data, 16, 2)
    struct.pack_into("<H", data, 18, 0x3E)
    struct.pack_into("<I", data, 20, 1)
    return bytes(data)


_ELF64_DATA: bytes = _build_elf64_header()


class _FakeGhidraBridge:
    """In-process double for the ghidra_bridge RPC client.

    Records every exec/eval payload. Serves eval responses from a
    pre-loaded queue (for sequential multi-call scenarios), a dynamic
    responder callable, or a static ``eval_response`` value.
    """

    def __init__(self) -> None:
        """Initialise empty traces, empty response queue, and nil response."""
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self.eval_response: object = None
        self._response_queue: list[object] = []
        self._eval_responder: _EvalResponder | None = None
        self.exec_raises: BaseException | None = None

    def load_sequence(self, responses: list[object]) -> None:
        """Enqueue a sequence of eval return values to consume in order.

        Args:
            responses: Ordered values to return on successive
                ``remote_eval`` calls.
        """
        self._response_queue = list(responses)

    def set_eval_responder(self, responder: _EvalResponder) -> None:
        """Install a callable mapping each eval expression to its response.

        Args:
            responder: Callable receiving the eval expression and returning
                the desired value; overrides ``eval_response``.
        """
        self._eval_responder = responder

    def remote_exec(self, code: str) -> None:
        """Record the script; raise ``exec_raises`` if set.

        Args:
            code: Jython source forwarded from the bridge.

        Raises:
            exc: Re-raised when ``exec_raises`` is not ``None``.
        """
        self.exec_calls.append(code)
        exc = self.exec_raises
        if exc is not None:
            raise exc

    def remote_eval(self, expression: str, **_kwargs: object) -> object:
        """Return the next queued value, responder result, or static response.

        Args:
            expression: Sentinel variable expression from
                ``prepare_remote_script``.
            **_kwargs: Ignored keyword arguments matching the real client.

        Returns:
            object: Next value from the queue, the responder result, or
            ``eval_response``.
        """
        self.eval_calls.append(expression)
        if self._response_queue:
            return self._response_queue.pop(0)
        if self._eval_responder is not None:
            responder = self._eval_responder
            return responder(expression)
        return self.eval_response


def _make_connected_bridge(fake: _FakeGhidraBridge) -> GhidraBridge:
    """Wire a GhidraBridge to the fake and mark it connected.

    Args:
        fake: The fake double to attach as the bridge's RPC backend.

    Returns:
        GhidraBridge: Live bridge instance backed by the fake.
    """
    bridge = GhidraBridge()
    setattr(bridge, "_bridge", fake)
    bridge.state.connected = True
    return bridge


@pytest.fixture
def fake() -> _FakeGhidraBridge:
    """Provide a fresh recording fake.

    Returns:
        _FakeGhidraBridge: Empty fake with no pre-wired responses.
    """
    return _FakeGhidraBridge()


@pytest.fixture
def bridge(fake: _FakeGhidraBridge) -> GhidraBridge:
    """Provide a connected GhidraBridge backed by the recording fake.

    Args:
        fake: The fake double fixture.

    Returns:
        GhidraBridge: Bridge whose ``_bridge`` attribute is the fake.
    """
    return _make_connected_bridge(fake)


@pytest.mark.asyncio
async def test_get_functions_parses_exact_field_values(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_functions maps every Ghidra field into FunctionInfo.

    The fake returns a one-item list with known values. If the bridge
    reads the wrong dict key (e.g. ``"addr"`` instead of ``"address"``)
    or maps the value to the wrong FunctionInfo field, the assertion fails.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake.
    """
    fake.eval_response = [
        {
            "name": "main",
            "address": 4096,
            "size": 64,
            "calling_convention": "__cdecl",
            "return_type": "int",
        },
    ]

    functions = await bridge.get_functions()

    assert len(functions) == 1
    fn = functions[0]
    assert fn.name == "main"
    assert fn.address == 4096
    assert fn.size == 64
    assert fn.calling_convention == "__cdecl"
    assert fn.return_type == "int"


@pytest.mark.asyncio
async def test_get_functions_script_queries_function_manager(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_functions script calls getFunctionManager and getFunctions.

    Mutation caught: swapping ``getFunctionManager`` for a direct function
    lookup would break the iteration pattern that Ghidra requires for
    enumerating all functions in the program.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake.
    """
    fake.eval_response = []
    await bridge.get_functions()

    assert len(fake.exec_calls) >= 1
    script = fake.exec_calls[0]
    assert "getFunctions" in script
    assert "getFunctionManager" in script


@pytest.mark.asyncio
async def test_get_functions_filter_excludes_non_matching_names(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_functions filter_pattern keeps only matching names.

    Mutation caught: applying the filter to the address field or inverting
    the search condition would return the wrong subset.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake.
    """
    fake.eval_response = [
        {"name": "main", "address": 4096, "size": 64, "calling_convention": "__cdecl", "return_type": "int"},
        {"name": "helper_init", "address": 8192, "size": 32, "calling_convention": "__cdecl", "return_type": "void"},
    ]

    functions = await bridge.get_functions(filter_pattern="^main$")

    assert len(functions) == 1
    assert functions[0].name == "main"


@pytest.mark.asyncio
async def test_get_function_returns_none_when_not_found(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_function returns None when no function exists at address.

    Mutation caught: returning an empty FunctionInfo instead of None would
    break callers that use ``if info is None`` guards.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake with None response simulating missing function.
    """
    fake.eval_response = None

    result = await bridge.get_function(_TEST_FUNC_ADDR)

    assert result is None


@pytest.mark.asyncio
async def test_get_function_parses_parameters_and_variables(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_function maps ``parameters`` and ``variables`` correctly.

    Mutation caught: swapping the ``parameters`` and ``variables`` keys would
    produce FunctionInfo with parameters in local_variables and vice versa.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake with a known function response.
    """
    fake.eval_response = {
        "name": "decrypt",
        "address": _TEST_FUNC_ADDR,
        "size": 128,
        "calling_convention": "__stdcall",
        "return_type": "void",
        "parameters": [{"name": "key", "type": "int *"}],
        "variables": [{"name": "i", "type": "int", "offset": -8}],
    }

    info = await bridge.get_function(_TEST_FUNC_ADDR)

    assert info is not None
    assert info.name == "decrypt"
    assert info.address == _TEST_FUNC_ADDR
    assert len(info.parameters) == 1
    assert info.parameters[0].name == "key"
    assert info.parameters[0].type == "int *"
    assert len(info.local_variables) == 1
    assert info.local_variables[0].name == "i"
    assert info.local_variables[0].offset == -8


@pytest.mark.asyncio
async def test_get_function_script_uses_containing_lookup(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_function script calls getFunctionContaining and toAddr.

    Mutation caught: using ``getFunctionAt`` instead of
    ``getFunctionContaining`` would fail for addresses inside a function
    body that are not the entry point.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake.
    """
    fake.eval_response = None
    await bridge.get_function(_TEST_FUNC_ADDR)

    assert len(fake.exec_calls) >= 1
    script = fake.exec_calls[0]
    assert "getFunctionContaining" in script
    assert "toAddr" in script


@pytest.mark.asyncio
async def test_disassemble_parses_address_mnemonic_bytes_operands(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge disassemble maps instruction fields into DisassemblyLine.

    Mutation caught: reading ``"offset"`` instead of ``"address"`` from the
    response dict would produce address=0 for every line.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake returning two known instructions.
    """
    fake.eval_response = [
        {"address": 0x1000, "bytes": "90", "mnemonic": "NOP", "operands": ""},
        {"address": 0x1001, "bytes": "C3", "mnemonic": "RET", "operands": ""},
    ]

    lines = await bridge.disassemble(0x1000, count=2)

    assert len(lines) == 2
    assert lines[0].address == 0x1000
    assert lines[0].mnemonic == "NOP"
    assert lines[0].bytes_str == "90"
    assert len(lines[0].operands) == 0
    assert lines[1].address == 0x1001
    assert lines[1].mnemonic == "RET"


@pytest.mark.asyncio
async def test_disassemble_script_uses_listing_instruction_api(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge disassemble script emits getListing and getInstructionAt.

    Mutation caught: using a non-existent Flat-API name instead of
    ``getListing().getInstructionAt`` would silently produce an empty list.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake.
    """
    fake.eval_response = []
    await bridge.disassemble(_TEST_ADDR, count=5)

    assert len(fake.exec_calls) >= 1
    script = fake.exec_calls[0]
    assert "getListing" in script
    assert "getInstructionAt" in script
    assert "toAddr" in script


@pytest.mark.asyncio
async def test_get_imports_parses_dll_function_address_fields(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_imports maps ``dll``, ``function``, and ``address`` correctly.

    Mutation caught: reading ``sym.getName()`` for both ``dll`` and
    ``function`` (forgetting ``getParentSymbol().getName()``) would produce
    dll == "VirtualAlloc" instead of "kernel32.dll".

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake with two known imports.
    """
    fake.eval_response = [
        {"dll": "kernel32.dll", "function": "VirtualAlloc", "address": _TEST_IMPORT_ADDR},
        {"dll": "ntdll.dll", "function": "NtQueryInformationProcess", "address": _TEST_IMPORT_ADDR + 8},
    ]

    imports = await bridge.get_imports()

    assert len(imports) == 2
    assert imports[0].dll == "kernel32.dll"
    assert imports[0].function == "VirtualAlloc"
    assert imports[0].address == _TEST_IMPORT_ADDR
    assert imports[1].dll == "ntdll.dll"
    assert imports[1].function == "NtQueryInformationProcess"


@pytest.mark.asyncio
async def test_get_imports_script_queries_external_symbols(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_imports script calls getExternalSymbols on the symbol table.

    Mutation caught: iterating ``getAllSymbols`` instead of
    ``getExternalSymbols`` would include internal symbols and produce a
    wrong import list.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake.
    """
    fake.eval_response = []
    await bridge.get_imports()

    assert len(fake.exec_calls) >= 1
    assert "getExternalSymbols" in fake.exec_calls[0]


@pytest.mark.asyncio
async def test_get_exports_ordinal_is_enumeration_index(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_exports ordinal equals the enumerate index, not a raw field.

    Mutation caught: reading a raw ``"ordinal"`` key from the response would
    assign the wrong ordinal; the production code uses ``enumerate`` so
    ordinal is always the list position (0-based).

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake with two exports.
    """
    fake.eval_response = [
        {"name": "DllMain", "address": _TEST_EXPORT_ADDR},
        {"name": "DllRegisterServer", "address": _TEST_EXPORT_ADDR + 0x100},
    ]

    exports = await bridge.get_exports()

    assert len(exports) == 2
    assert exports[0].name == "DllMain"
    assert exports[0].ordinal == 0
    assert exports[0].address == _TEST_EXPORT_ADDR
    assert exports[1].name == "DllRegisterServer"
    assert exports[1].ordinal == 1
    assert exports[1].address == _TEST_EXPORT_ADDR + 0x100


@pytest.mark.asyncio
async def test_get_exports_script_filters_entry_points(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_exports script uses getAllSymbols with entry-point filter.

    Mutation caught: using ``getExternalSymbols`` instead of the
    ``getAllSymbols`` + ``isExternalEntryPoint`` filter would return
    imported symbols as exports.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake.
    """
    fake.eval_response = []
    await bridge.get_exports()

    assert len(fake.exec_calls) >= 1
    script = fake.exec_calls[0]
    assert "getAllSymbols" in script
    assert "isExternalEntryPoint" in script


@pytest.mark.asyncio
async def test_get_program_info_returns_exact_dict_values(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_program_info forwards the remote dict without mangling.

    Mutation caught: remapping ``"pointer_size"`` to ``"ptr_sz"`` or
    coercing ``"language"`` to a different key would break the assertion.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake with a known program-info payload.
    """
    fake.eval_response = {
        "name": "ntdll.dll",
        "language": "x86:LE:64:default",
        "language_description": "x86 64-bit",
        "compiler": "windows",
        "endianness": "little",
        "pointer_size": 8,
        "address_size": 64,
        "image_base": 0x7FF800000000,
        "executable_format": "Portable Executable (PE)",
        "executable_path": "C:/Windows/System32/ntdll.dll",
        "num_functions": 3,
        "num_symbols": 42,
    }

    result: dict[str, Any] = await bridge.get_program_info()

    assert result["name"] == "ntdll.dll"
    assert result["language"] == "x86:LE:64:default"
    assert result["compiler"] == "windows"
    assert result["endianness"] == "little"
    assert result["pointer_size"] == 8
    assert result["image_base"] == 0x7FF800000000
    assert result["num_functions"] == 3
    assert result["num_symbols"] == 42


@pytest.mark.asyncio
async def test_get_program_info_script_queries_language_and_compiler(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_program_info script calls getLanguage and getCompilerSpec.

    Mutation caught: removing either call from the script would produce a
    result dict that is missing ``language`` or ``compiler`` keys.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake.
    """
    fake.eval_response = {}
    await bridge.get_program_info()

    assert len(fake.exec_calls) >= 1
    script = fake.exec_calls[0]
    assert "getLanguage" in script
    assert "getCompilerSpec" in script


@pytest.mark.asyncio
async def test_get_function_body_parses_exact_fields(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_function_body returns the remote dict with all fields.

    Mutation caught: omitting the ``ranges`` key from the assembled dict
    in the Jython script would produce an empty ``ranges`` list rather
    than the single range we injected.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake with a non-thunk function body payload.
    """
    fake.eval_response = {
        "name": "encrypt",
        "address": 0x3000,
        "is_thunk": False,
        "thunked_function": None,
        "ranges": [{"start": 0x3000, "end": 0x307F}],
        "total_size": 128,
    }

    result: dict[str, Any] = await bridge.get_function_body(0x3000)

    assert result["name"] == "encrypt"
    assert result["address"] == 0x3000
    assert result["is_thunk"] is False
    assert result["thunked_function"] is None
    assert len(result["ranges"]) == 1
    assert result["ranges"][0]["start"] == 0x3000
    assert result["ranges"][0]["end"] == 0x307F
    assert result["total_size"] == 128


@pytest.mark.asyncio
async def test_get_function_body_thunk_fields_preserved(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_function_body exposes is_thunk and thunked_function name.

    Mutation caught: hardcoding ``is_thunk: False`` in the Jython script or
    failing to call ``getThunkedFunction`` would produce None here instead
    of the thunked name.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake with a thunk function payload.
    """
    fake.eval_response = {
        "name": "printf",
        "address": 0x2000,
        "is_thunk": True,
        "thunked_function": "printf_impl",
        "ranges": [{"start": 0x2000, "end": 0x2005}],
        "total_size": 6,
    }

    result: dict[str, Any] = await bridge.get_function_body(0x2000)

    assert result["is_thunk"] is True
    assert result["thunked_function"] == "printf_impl"


@pytest.mark.asyncio
async def test_get_function_body_not_found_returns_null_name(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_function_body returns name=None when address is unmapped.

    Mutation caught: returning a default name string instead of None when
    ``getFunctionContaining`` yields no function would break callers that
    check ``result["name"] is None`` to detect the not-found case.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake with a not-found payload.
    """
    fake.eval_response = {
        "name": None,
        "address": 0x9999,
        "is_thunk": False,
        "thunked_function": None,
        "ranges": [],
        "total_size": 0,
    }

    result: dict[str, Any] = await bridge.get_function_body(0x9999)

    assert result["name"] is None
    assert result["ranges"] == []
    assert result["total_size"] == 0


@pytest.mark.asyncio
async def test_get_function_body_raises_when_result_not_dict(
    bridge: GhidraBridge,
    fake: _FakeGhidraBridge,
) -> None:
    """GhidraBridge get_function_body raises ToolError when result is not a dict.

    Mutation caught: removing the ``isinstance(result, dict)`` guard and
    returning ``None`` directly would turn a network failure into a silent
    empty response instead of an explicit error.

    Args:
        bridge: Connected bridge fixture.
        fake: Recording fake returning a non-dict value.
    """
    fake.eval_response = None

    with pytest.raises(ToolError, match="no payload"):
        await bridge.get_function_body(_TEST_ADDR)


@pytest.mark.asyncio
async def test_load_binary_raises_on_nonexistent_path() -> None:
    """GhidraBridge load_binary raises ToolError before any RPC when file missing.

    Mutation caught: removing the path-existence check would allow the
    bridge to call ``importFile`` against a non-existent path, producing
    a confusing JVM-level error instead of an immediate ToolError.
    """
    bridge = GhidraBridge()
    missing = Path("C:/no_such_dir_intellicrack_test/no_such.bin")

    with pytest.raises(ToolError):
        await bridge.load_binary(missing)


@pytest.mark.asyncio
async def test_load_binary_sha256_matches_independent_oracle(tmp_path: Path) -> None:
    """GhidraBridge load_binary SHA-256 matches the independently-computed hash.

    Mutation caught: substituting MD5 or CRC32 for SHA-256 in the bridge
    would produce a different hex string; this oracle detects any hash
    algorithm substitution.

    Args:
        tmp_path: Pytest temporary directory.
    """
    target = tmp_path / "test.elf"
    target.write_bytes(_ELF64_DATA)

    expected_sha256 = hashlib.sha256(_ELF64_DATA).hexdigest()

    bridge = GhidraBridge()
    info = await bridge.load_binary(target)

    assert info.sha256 == expected_sha256


@pytest.mark.asyncio
async def test_load_binary_size_equals_file_byte_count(tmp_path: Path) -> None:
    """GhidraBridge load_binary size field equals the exact byte count of the file.

    Mutation caught: reporting ``path.stat().st_size`` vs ``len(data)``
    differs for sparse files; this gate pins the byte-count behaviour.

    Args:
        tmp_path: Pytest temporary directory.
    """
    target = tmp_path / "test.elf"
    target.write_bytes(_ELF64_DATA)

    bridge = GhidraBridge()
    info = await bridge.load_binary(target)

    assert info.size == len(_ELF64_DATA)


@pytest.mark.asyncio
async def test_load_binary_detects_elf_format(tmp_path: Path) -> None:
    """GhidraBridge load_binary reports ``"elf"`` file_type for an ELF magic header.

    Mutation caught: defaulting ``file_type`` to ``"pe"`` or ``"raw"``
    regardless of the magic bytes would silently misclassify the binary.

    Args:
        tmp_path: Pytest temporary directory.
    """
    target = tmp_path / "test.elf"
    target.write_bytes(_ELF64_DATA)

    bridge = GhidraBridge()
    info = await bridge.load_binary(target)

    assert info.file_type == "elf"


@pytest.mark.asyncio
async def test_load_binary_with_bridge_dispatches_import_file_call(tmp_path: Path) -> None:
    """GhidraBridge load_binary emits the Jython importFile call when connected.

    Mutation caught: omitting the ``importFile`` call would cause Ghidra to
    never actually load the binary, yet the bridge would still proceed to
    extract metadata, returning silently incorrect results.

    Args:
        tmp_path: Pytest temporary directory.
    """
    target = tmp_path / "test.elf"
    target.write_bytes(_ELF64_DATA)

    fake = _FakeGhidraBridge()
    metadata_response: dict[str, Any] = {
        "entry_point": 0x1000,
        "sections": [],
        "imports": [],
        "exports": [],
    }
    fake.load_sequence([{"imported": True, "name": "test.elf"}, metadata_response])

    bridge = _make_connected_bridge(fake)
    await bridge.load_binary(target)

    assert len(fake.exec_calls) >= 1
    first_script = fake.exec_calls[0]
    assert "importFile" in first_script


@pytest.mark.asyncio
async def test_load_binary_with_bridge_parses_metadata_entry_point(tmp_path: Path) -> None:
    """GhidraBridge load_binary extracts entry_point from the metadata remote call.

    Mutation caught: hard-coding ``entry_point = 0`` in the metadata
    parser instead of reading ``result_dict.get("entry_point")`` would
    always produce zero regardless of what Ghidra reports.

    Args:
        tmp_path: Pytest temporary directory.
    """
    target = tmp_path / "test.elf"
    target.write_bytes(_ELF64_DATA)

    fake = _FakeGhidraBridge()
    metadata_response: dict[str, Any] = {
        "entry_point": 0x4000,
        "sections": [
            {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 0x200,
                "raw_size": 0x200,
                "characteristics": 0x5,
                "entropy": 0.0,
            },
        ],
        "imports": [{"dll": "libc.so.6", "function": "printf", "address": 0x5000}],
        "exports": [],
    }
    fake.load_sequence([{"imported": True, "name": "test.elf"}, metadata_response])

    bridge = _make_connected_bridge(fake)
    info = await bridge.load_binary(target)

    assert info.entry_point == 0x4000
    assert len(info.sections) == 1
    assert info.sections[0].name == ".text"
    assert info.sections[0].virtual_address == 0x1000
    assert len(info.imports) == 1
    assert info.imports[0].dll == "libc.so.6"
    assert info.imports[0].function == "printf"
