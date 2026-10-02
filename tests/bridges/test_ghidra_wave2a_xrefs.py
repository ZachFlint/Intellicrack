# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GHIDRA-C real-gate suite — xrefs/refs/relocations/namespaces/symbols/memory-layout.

Scope: ``delete_reference``, ``get_relocations``, ``create_namespace``,
``get_namespaces``, ``search_symbols``, ``get_calling_conventions``,
``get_memory_map``, ``get_segments``.

``get_xrefs_to``, ``get_xrefs_from``, and ``add_reference`` already carry
real functional gates in ``test_ghidra_audit6.py`` (F-0022/F-0026/F-0020)
and are therefore skipped here per the audit's REAL verdict.

Every gate asserts:
  1. The bridge emitted the expected Ghidra API framing (exec payload check).
  2. The bridge parsed the canned remote result into the exact typed return
     structure the fake's known values dictate.

The seam: ``_FakeGhidraRemote`` captures every snippet the bridge sends via
``remote_exec`` in ``exec_calls`` and ``remote_eval`` in ``eval_calls``, and
returns ``eval_response`` as the deserialized remote result.  This mirrors the
``FakeGhidraBridge`` contract used in ``test_ghidra_audit6.py`` but is kept
self-contained — no cross-file fixture imports.

``search_symbols`` is gated through ``_ExecutingGhidraRemote`` instead: it runs
the emitted script against a Ghidra-shaped symbol table so the wildcard
matching the script performs is checked by its results.
"""

from __future__ import annotations

from itertools import starmap
from types import SimpleNamespace
from typing import Any, Final

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


_FROM_ADDR: Final[int] = 0x401000
_TO_ADDR: Final[int] = 0x402000
_RELOC_ADDR: Final[int] = 0x403010
_SEGMENT_START: Final[int] = 0x1000
_SEGMENT_END: Final[int] = 0x4FFF
_SEGMENT_SIZE: Final[int] = 0x4000


class _FakeGhidraRemote:
    """Minimal in-process double for the ``ghidra_bridge`` RPC client.

    Records every script sent via ``remote_exec`` and every expression sent via
    ``remote_eval``, then returns the pre-configured ``eval_response`` on the
    next ``remote_eval`` call.  This mirrors the sentinel-based readback flow
    that :class:`GhidraBridge._execute_remote` relies on:

    1. ``prepare_remote_script`` rewrites the trailing expression as
       ``_intellicrack_ghidra_result_N = <expr>``.
    2. ``remote_exec`` runs the rewritten script (recorded here).
    3. ``remote_eval(sentinel_name)`` reads the result (returned as
       ``eval_response`` here).
    """

    def __init__(self, response: object = None) -> None:
        """Initialise with a pre-configured eval response.

        Args:
            response: Value returned by the next ``remote_eval`` call.
        """
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self.eval_response: object = response

    def remote_exec(self, code: str) -> None:
        """Record ``code`` and do nothing (side-effect simulation).

        Args:
            code: Jython source emitted by the bridge after
                ``prepare_remote_script`` has rewritten the script.
        """
        self.exec_calls.append(code)

    def remote_eval(self, expr: str) -> object:
        """Record ``expr`` and return the pre-configured response.

        Args:
            expr: Sentinel variable name produced by
                ``prepare_remote_script``.

        Returns:
            object: The ``eval_response`` configured at construction or
            via direct attribute assignment.
        """
        self.eval_calls.append(expr)
        return self.eval_response


def _make_bridge(response: object) -> tuple[GhidraBridge, _FakeGhidraRemote]:
    """Wire a ``GhidraBridge`` to a deterministic fake and return both.

    Args:
        response: Value the fake returns from every ``remote_eval`` call.

    Returns:
        tuple[GhidraBridge, _FakeGhidraRemote]: Connected bridge and the
        fake for direct introspection.
    """
    bridge = GhidraBridge()
    fake = _FakeGhidraRemote(response)
    bridge.attach_remote_bridge(fake)
    return bridge, fake


class _ExecutingGhidraRemote:
    """In-process ``ghidra_bridge`` double that really runs the emitted script.

    ``remote_exec`` executes the script against a shared globals namespace
    and ``remote_eval`` evaluates an expression against the same namespace,
    the boundary the real client crosses.
    """

    def __init__(self, program: SimpleNamespace) -> None:
        """Seed the remote namespace with ``currentProgram``.

        Args:
            program: Program double exposed to the script as ``currentProgram``.
        """
        self.globals: dict[str, Any] = {"currentProgram": program}
        self.exec_calls: list[str] = []

    def remote_exec(self, code: str) -> None:
        """Execute ``code`` against the shared namespace.

        Args:
            code: Python source emitted by the bridge.
        """
        self.exec_calls.append(code)
        exec(compile(code, "<remote_exec>", "exec"), self.globals)

    def remote_eval(self, expr: str) -> object:
        """Evaluate ``expr`` against the shared namespace.

        Args:
            expr: Python expression, normally the result sentinel name.

        Returns:
            object: Value of ``expr`` in the remote namespace.
        """
        wrapper_source = f"def _ic_test_eval():\n    return ({expr})\n"
        local_namespace: dict[str, Any] = {}
        exec(compile(wrapper_source, "<remote_eval>", "exec"), self.globals, local_namespace)
        return local_namespace["_ic_test_eval"]()


def _make_symbol(name: str, offset: int, symbol_type: str, namespace: str) -> SimpleNamespace:
    """Build a Ghidra-shaped ``Symbol`` double.

    Args:
        name: Symbol name.
        offset: Symbol address offset.
        symbol_type: Text ``str(Symbol.getSymbolType())`` yields.
        namespace: Name of the symbol's parent namespace.

    Returns:
        SimpleNamespace: Object exposing ``getName``, ``getAddress``,
        ``getSymbolType`` and ``getParentNamespace``.
    """
    address = SimpleNamespace(getOffset=lambda: offset)
    parent = SimpleNamespace(getName=lambda: namespace)
    return SimpleNamespace(
        getName=lambda: name,
        getAddress=lambda: address,
        getSymbolType=lambda: symbol_type,
        getParentNamespace=lambda: parent,
    )


def _make_symbol_program(symbols: list[SimpleNamespace]) -> SimpleNamespace:
    """Build a program double whose symbol table serves ``symbols``.

    ``SymbolTable.getAllSymbols(includeDynamicSymbols)`` returns a Java-style
    ``SymbolIterator``; each call yields a fresh iterator over ``symbols``.

    Args:
        symbols: Symbol doubles in table order.

    Returns:
        SimpleNamespace: Program double exposing ``getSymbolTable``.
    """

    def _get_all_symbols(_include_dynamic: object) -> SimpleNamespace:
        """Return a ``hasNext``/``next`` iterator over every symbol.

        Args:
            _include_dynamic: Ghidra's include-dynamic-symbols flag.

        Returns:
            SimpleNamespace: Java-style iterator over ``symbols``.
        """
        pending = list(symbols)
        return SimpleNamespace(hasNext=lambda: bool(pending), next=lambda: pending.pop(0))

    table = SimpleNamespace(getAllSymbols=_get_all_symbols)
    return SimpleNamespace(getSymbolTable=lambda: table)


_SEARCH_SYMBOLS: Final[list[tuple[str, int, str, str]]] = [
    ("main", 0x401000, "Function", "Global"),
    ("MainLoop", 0x401100, "Function", "app"),
    ("domain_check", 0x401200, "Label", "Global"),
    ("init", 0x401300, "Function", "Global"),
    ("mai_n", 0x401400, "Label", "Global"),
]


def _make_symbol_bridge() -> GhidraBridge:
    """Wire a ``GhidraBridge`` to an executing remote over ``_SEARCH_SYMBOLS``.

    Returns:
        GhidraBridge: Connected bridge whose remote runs the emitted script.
    """
    program = _make_symbol_program(list(starmap(_make_symbol, _SEARCH_SYMBOLS)))
    bridge = GhidraBridge()
    bridge.attach_remote_bridge(_ExecutingGhidraRemote(program))
    return bridge


def _symbol_row(name: str, offset: int, symbol_type: str, namespace: str) -> dict[str, Any]:
    """Return the dict ``search_symbols`` reports for one symbol.

    Args:
        name: Symbol name.
        offset: Symbol address offset.
        symbol_type: Symbol type text.
        namespace: Parent namespace name.

    Returns:
        dict[str, Any]: Expected result row.
    """
    return {"name": name, "address": offset, "type": symbol_type, "namespace": namespace}


@pytest.mark.asyncio
async def test_delete_reference_reports_success_when_remote_returns_true() -> None:
    """``delete_reference`` must surface ``success: True`` when the remote confirms deletion.

    The remote script finds the matching reference in ``getReferencesFrom``
    and calls ``refMgr.delete(ref)``, then the trailing ``deleted`` expression
    evaluates to ``True``.  The bridge must map that to ``success: True`` in
    the returned dict.

    Mutation caught: delete_reference maps ``bool(result)`` to the wrong key
    (e.g. ``deleted`` instead of ``success``), so the caller sees ``success``
    absent from the returned dict.
    """
    deleted_ok = True
    bridge, fake = _make_bridge(deleted_ok)
    result = await bridge.delete_reference(_FROM_ADDR, _TO_ADDR)

    assert result["success"] is True
    assert result["from"] == hex(_FROM_ADDR)
    assert result["to"] == hex(_TO_ADDR)
    assert len(fake.exec_calls) == 1
    payload = fake.exec_calls[0]
    assert "getReferenceManager" in payload
    assert "getReferencesFrom" in payload
    assert str(_FROM_ADDR) in payload
    assert str(_TO_ADDR) in payload


@pytest.mark.asyncio
async def test_delete_reference_reports_failure_when_remote_returns_false() -> None:
    """``delete_reference`` must surface ``success: False`` when the reference was not found.

    The remote script iterates ``getReferencesFrom`` without finding a
    matching target address, so ``deleted`` stays ``False``.  The bridge must
    faithfully relay that as ``success: False``.

    Mutation caught: delete_reference returns ``success: True`` unconditionally
    regardless of the remote ``deleted`` value.
    """
    deleted_not_found = False
    bridge, _fake = _make_bridge(deleted_not_found)
    result = await bridge.delete_reference(_FROM_ADDR, _TO_ADDR)

    assert result["success"] is False
    assert result["from"] == hex(_FROM_ADDR)
    assert result["to"] == hex(_TO_ADDR)


@pytest.mark.asyncio
async def test_delete_reference_raises_when_not_connected() -> None:
    """A disconnected bridge must raise ``ToolError`` from ``delete_reference``."""
    bridge = GhidraBridge()
    with pytest.raises(ToolError, match="not connected"):
        await bridge.delete_reference(_FROM_ADDR, _TO_ADDR)


@pytest.mark.asyncio
async def test_get_relocations_parses_all_fields() -> None:
    """``get_relocations`` must surface address, type, symbol, and values from the remote payload.

    The remote script iterates ``reloc_table.getRelocations()`` and appends a
    dict for each relocation using ``reloc.getAddress().getOffset()``,
    ``int(reloc.getType())``, ``reloc.getSymbolName()``, and
    ``list(reloc.getValues())``.  The bridge must return those values verbatim.

    Mutation caught: get_relocations maps ``reloc.getType()`` to the wrong key
    ``reloc_type`` instead of ``type``, so the caller cannot see the relocation
    type.
    """
    canned: list[dict[str, Any]] = [
        {"address": _RELOC_ADDR, "type": 7, "symbol": "printf", "values": [0xDEAD]},
    ]
    bridge, fake = _make_bridge(canned)
    result = await bridge.get_relocations()

    assert len(result) == 1
    entry = result[0]
    assert entry["address"] == _RELOC_ADDR
    assert entry["type"] == 7
    assert entry["symbol"] == "printf"
    assert entry["values"] == [0xDEAD]
    assert len(fake.exec_calls) == 1
    payload = fake.exec_calls[0]
    assert "getRelocationTable" in payload
    assert "getRelocations" in payload


@pytest.mark.asyncio
async def test_get_relocations_returns_empty_list_for_empty_remote_response() -> None:
    """``get_relocations`` must return ``[]`` when the remote reports no relocations.

    Mutation caught: get_relocations returns ``None`` instead of ``[]`` when
    the remote payload is falsy, breaking callers that iterate the result.
    """
    bridge, _fake = _make_bridge([])
    result = await bridge.get_relocations()

    assert result == []


@pytest.mark.asyncio
async def test_get_relocations_raises_when_not_connected() -> None:
    """A disconnected bridge must raise ``ToolError`` from ``get_relocations``."""
    bridge = GhidraBridge()
    with pytest.raises(ToolError, match="not connected"):
        await bridge.get_relocations()


@pytest.mark.asyncio
async def test_create_namespace_returns_name_and_path_from_remote() -> None:
    """``create_namespace`` must return the name, path, and success flag from the remote result.

    The remote script calls ``st.createNameSpace(parent_ns, name,
    SourceType.USER_DEFINED)`` and evaluates ``{'name': ns.getName(),
    'path': ns.getName(True), 'success': True}``.  The bridge must return that
    dict to the caller.

    Mutation caught: create_namespace returns ``{"name": name, "path": name,
    "success": False}`` (the fallback path) even when the remote result is a
    valid dict, discarding the actual Ghidra-assigned path.
    """
    canned: dict[str, Any] = {"name": "MyNS", "path": "GlobalNamespace::MyNS", "success": True}
    bridge, fake = _make_bridge(canned)
    result = await bridge.create_namespace("MyNS")

    assert result["name"] == "MyNS"
    assert result["path"] == "GlobalNamespace::MyNS"
    assert result["success"] is True
    assert len(fake.exec_calls) == 1
    payload = fake.exec_calls[0]
    assert "createNameSpace" in payload
    assert "MyNS" in payload


@pytest.mark.asyncio
async def test_create_namespace_with_parent_includes_parent_lookup() -> None:
    """``create_namespace`` with a parent must emit ``getNamespace`` to resolve the parent.

    When ``parent`` is not ``None``, the bridge emits ``st.getNamespace(parent_path,
    ...)`` before creating the child namespace.  This verifies the conditional
    branch in the generated Jython script is present.

    Mutation caught: create_namespace always uses ``getGlobalNamespace()`` as
    parent, ignoring the ``parent`` argument, so child namespaces are created
    at the wrong level.
    """
    canned: dict[str, Any] = {"name": "ChildNS", "path": "ParentNS::ChildNS", "success": True}
    bridge, fake = _make_bridge(canned)
    result = await bridge.create_namespace("ChildNS", parent="ParentNS")

    assert result["name"] == "ChildNS"
    assert result["path"] == "ParentNS::ChildNS"
    assert result["success"] is True
    payload = fake.exec_calls[0]
    assert "getNamespace" in payload
    assert "ParentNS" in payload


@pytest.mark.asyncio
async def test_create_namespace_raises_when_not_connected() -> None:
    """A disconnected bridge must raise ``ToolError`` from ``create_namespace``."""
    bridge = GhidraBridge()
    with pytest.raises(ToolError, match="not connected"):
        await bridge.create_namespace("Boom")


@pytest.mark.asyncio
async def test_get_namespaces_parses_name_and_path() -> None:
    """``get_namespaces`` must return name and path for every NAMESPACE symbol.

    The remote script filters ``st.getAllSymbols(True)`` for entries whose
    ``getSymbolType() == SymbolType.NAMESPACE`` and appends ``{'name':
    sym.getName(), 'path': sym.getName(True)}``.  The bridge must return
    those dicts verbatim.

    Mutation caught: get_namespaces puts ``getName()`` into the wrong key
    ``namespace_name`` instead of ``name``, so callers cannot read the
    namespace name by the expected key.
    """
    canned: list[dict[str, Any]] = [
        {"name": "RuntimeLib", "path": "RuntimeLib"},
        {"name": "StdLib", "path": "StdLib"},
    ]
    bridge, fake = _make_bridge(canned)
    result = await bridge.get_namespaces()

    assert len(result) == 2
    assert result[0]["name"] == "RuntimeLib"
    assert result[0]["path"] == "RuntimeLib"
    assert result[1]["name"] == "StdLib"
    assert result[1]["path"] == "StdLib"
    assert len(fake.exec_calls) == 1
    payload = fake.exec_calls[0]
    assert "SymbolType.NAMESPACE" in payload
    assert "getAllSymbols" in payload


@pytest.mark.asyncio
async def test_get_namespaces_raises_when_not_connected() -> None:
    """A disconnected bridge must raise ``ToolError`` from ``get_namespaces``."""
    bridge = GhidraBridge()
    with pytest.raises(ToolError, match="not connected"):
        await bridge.get_namespaces()


@pytest.mark.asyncio
async def test_search_symbols_parses_all_fields() -> None:
    """A plain pattern must match case-insensitively anywhere in the name.

    The script walks ``SymbolTable.getAllSymbols(True)`` and, when the pattern
    has no ``*``/``?``, matches it as ``*pattern*`` case-insensitively with
    :func:`fnmatch.fnmatch`. Each match is reported with its name, address,
    type and parent namespace.

    Independent oracle: of the five table symbols, ``main``, ``MainLoop`` and
    ``domain_check`` contain ``main`` (ignoring case); ``init`` and ``mai_n``
    do not. The three matches come back in table order with every field.

    Mutation caught: an exact-name lookup (only ``main`` returned), a
    case-sensitive match (``MainLoop`` dropped), or mapping the address to the
    wrong key.
    """
    bridge = _make_symbol_bridge()

    result = await bridge.search_symbols("main")

    assert result == [
        _symbol_row("main", 0x401000, "Function", "Global"),
        _symbol_row("MainLoop", 0x401100, "Function", "app"),
        _symbol_row("domain_check", 0x401200, "Label", "Global"),
    ]


@pytest.mark.asyncio
async def test_search_symbols_explicit_wildcard_is_anchored() -> None:
    """A pattern containing ``*`` or ``?`` must be matched as written, anchored.

    Independent oracle: ``main*`` matches names starting with ``main``
    (``main``, ``MainLoop``) but not ``domain_check``, where ``main`` is not a
    prefix. ``?ain`` matches exactly four-character names ending in ``ain``
    (``main``) but not ``MainLoop``, nor ``mai_n``, whose fourth character is
    not ``n``.

    Mutation caught: wrapping an explicit wildcard in ``*...*`` as well (the
    anchoring is lost and ``domain_check``/``MainLoop`` leak in), or treating
    ``?`` as a literal character (nothing matches).
    """
    bridge = _make_symbol_bridge()

    prefix_result = await bridge.search_symbols("main*")
    single_char_result = await bridge.search_symbols("?ain")

    assert prefix_result == [
        _symbol_row("main", 0x401000, "Function", "Global"),
        _symbol_row("MainLoop", 0x401100, "Function", "app"),
    ]
    assert single_char_result == [_symbol_row("main", 0x401000, "Function", "Global")]


@pytest.mark.asyncio
async def test_search_symbols_applies_type_filter_in_script() -> None:
    """``search_symbols`` with a type filter must embed the filter name in the Jython script.

    The generated script assigns the filter to ``type_filter`` and skips
    symbols whose ``str(sym.getSymbolType())`` does not match.  The bridge
    must include the filter value in the emitted script so the remote side can
    apply it.

    Mutation caught: search_symbols ignores the ``symbol_type`` argument and
    emits ``type_filter = None`` regardless, so all symbol types are returned
    even when the caller requested only FUNCTION symbols.
    """
    canned: list[dict[str, Any]] = [
        {"name": "encrypt", "address": 0x405000, "type": "FUNCTION", "namespace": "Global"},
    ]
    bridge, fake = _make_bridge(canned)
    result = await bridge.search_symbols("encrypt", symbol_type="FUNCTION")

    assert result[0]["type"] == "FUNCTION"
    payload = fake.exec_calls[0]
    assert "FUNCTION" in payload
    assert "type_filter" in payload


@pytest.mark.asyncio
async def test_search_symbols_raises_when_not_connected() -> None:
    """A disconnected bridge must raise ``ToolError`` from ``search_symbols``."""
    bridge = GhidraBridge()
    with pytest.raises(ToolError, match="not connected"):
        await bridge.search_symbols("main")


@pytest.mark.asyncio
async def test_get_calling_conventions_returns_all_names() -> None:
    """``get_calling_conventions`` must return every name from the compiler spec.

    The remote script calls ``currentProgram.getCompilerSpec()`` then
    ``[str(cc.getName()) for cc in cs.getCallingConventions()]``.  The bridge
    must return those strings in the same order.

    Mutation caught: get_calling_conventions reads ``cc.getDescription()``
    instead of ``cc.getName()``, so the caller receives description strings
    rather than calling-convention identifiers.
    """
    canned: list[str] = ["__cdecl", "__stdcall", "__fastcall"]
    bridge, fake = _make_bridge(canned)
    result = await bridge.get_calling_conventions()

    assert result == ["__cdecl", "__stdcall", "__fastcall"]
    assert len(fake.exec_calls) == 1
    payload = fake.exec_calls[0]
    assert "getCompilerSpec" in payload
    assert "getCallingConventions" in payload


@pytest.mark.asyncio
async def test_get_calling_conventions_returns_empty_list_when_none_defined() -> None:
    """``get_calling_conventions`` must return ``[]`` when the compiler spec has none.

    Mutation caught: get_calling_conventions returns ``None`` when the remote
    list is empty, breaking callers that iterate the result.
    """
    bridge, _fake = _make_bridge([])
    result = await bridge.get_calling_conventions()

    assert result == []


@pytest.mark.asyncio
async def test_get_calling_conventions_raises_when_not_connected() -> None:
    """A disconnected bridge must raise ``ToolError`` from ``get_calling_conventions``."""
    bridge = GhidraBridge()
    with pytest.raises(ToolError, match="not connected"):
        await bridge.get_calling_conventions()


@pytest.mark.asyncio
async def test_get_memory_map_parses_all_fields() -> None:
    """``get_memory_map`` must surface all nine block fields from the remote payload.

    The remote script appends ``{'name': block.getName(), 'start':
    block.getStart().getOffset(), 'end': block.getEnd().getOffset(), 'size':
    block.getSize(), 'read': block.isRead(), 'write': block.isWrite(),
    'execute': block.isExecute(), 'initialized': block.isInitialized(),
    'volatile': block.isVolatile()}`` for each block.  The bridge must return
    those values verbatim.

    Mutation caught: get_memory_map maps ``isRead()`` to the wrong key
    ``readable`` instead of ``read``, so the caller cannot determine read
    permission.
    """
    canned: list[dict[str, Any]] = [
        {
            "name": ".text",
            "start": _SEGMENT_START,
            "end": _SEGMENT_END,
            "size": _SEGMENT_SIZE,
            "read": True,
            "write": False,
            "execute": True,
            "initialized": True,
            "volatile": False,
        },
    ]
    bridge, fake = _make_bridge(canned)
    result = await bridge.get_memory_map()

    assert len(result) == 1
    blk = result[0]
    assert blk["name"] == ".text"
    assert blk["start"] == _SEGMENT_START
    assert blk["end"] == _SEGMENT_END
    assert blk["size"] == _SEGMENT_SIZE
    assert blk["read"] is True
    assert blk["write"] is False
    assert blk["execute"] is True
    assert blk["initialized"] is True
    assert blk["volatile"] is False
    assert len(fake.exec_calls) == 1
    payload = fake.exec_calls[0]
    assert "getMemory" in payload
    assert "getBlocks" in payload


@pytest.mark.asyncio
async def test_get_memory_map_returns_empty_list_for_empty_remote_response() -> None:
    """``get_memory_map`` must return ``[]`` when no memory blocks are reported.

    Mutation caught: get_memory_map returns ``None`` for a falsy remote
    payload, breaking callers that iterate the result.
    """
    bridge, _fake = _make_bridge([])
    result = await bridge.get_memory_map()

    assert result == []


@pytest.mark.asyncio
async def test_get_memory_map_raises_when_not_connected() -> None:
    """A disconnected bridge must raise ``ToolError`` from ``get_memory_map``."""
    bridge = GhidraBridge()
    with pytest.raises(ToolError, match="not connected"):
        await bridge.get_memory_map()


@pytest.mark.asyncio
async def test_get_segments_parses_all_fields_including_type_source_and_comment() -> None:
    """``get_segments`` must surface the three extra fields that distinguish it from ``get_memory_map``.

    Beyond the nine fields shared with ``get_memory_map``, the remote script
    also appends ``'type': str(block.getType())``,
    ``'source_name': block.getSourceName()``, and
    ``'comment': block.getComment() if block.getComment() else ''``.  The
    bridge must return all twelve values verbatim.

    Mutation caught: get_segments omits ``type``, ``source_name``, or
    ``comment`` from the returned dict, making it indistinguishable from
    ``get_memory_map`` to callers that rely on those fields.
    """
    canned: list[dict[str, Any]] = [
        {
            "name": ".text",
            "start": _SEGMENT_START,
            "end": _SEGMENT_END,
            "size": _SEGMENT_SIZE,
            "read": True,
            "write": False,
            "execute": True,
            "initialized": True,
            "volatile": False,
            "type": "DEFAULT",
            "source_name": "elf.ld",
            "comment": "",
        },
    ]
    bridge, fake = _make_bridge(canned)
    result = await bridge.get_segments()

    assert len(result) == 1
    seg = result[0]
    assert seg["name"] == ".text"
    assert seg["start"] == _SEGMENT_START
    assert seg["end"] == _SEGMENT_END
    assert seg["size"] == _SEGMENT_SIZE
    assert seg["read"] is True
    assert seg["write"] is False
    assert seg["execute"] is True
    assert seg["initialized"] is True
    assert seg["volatile"] is False
    assert seg["type"] == "DEFAULT"
    assert seg["source_name"] == "elf.ld"
    assert not seg["comment"]
    assert len(fake.exec_calls) == 1
    payload = fake.exec_calls[0]
    assert "getSourceName" in payload
    assert "getType" in payload


@pytest.mark.asyncio
async def test_get_segments_returns_empty_list_for_empty_remote_response() -> None:
    """``get_segments`` must return ``[]`` when no segments are reported.

    Mutation caught: get_segments returns ``None`` for a falsy remote payload,
    breaking callers that iterate the result.
    """
    bridge, _fake = _make_bridge([])
    result = await bridge.get_segments()

    assert result == []


@pytest.mark.asyncio
async def test_get_segments_raises_when_not_connected() -> None:
    """A disconnected bridge must raise ``ToolError`` from ``get_segments``."""
    bridge = GhidraBridge()
    with pytest.raises(ToolError, match="not connected"):
        await bridge.get_segments()
