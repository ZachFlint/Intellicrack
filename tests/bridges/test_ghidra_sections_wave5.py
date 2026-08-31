# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave-5 real-gate suite — sections/listing group (13 methods).

Source-attribution note: The group-02-report.md lists these 13 methods under
"GhidraBridge" findings (items 57-73 in the findings table, STILL OPEN items
12-20 and 24-27).  Code search confirms the methods do NOT exist in
``src/intellicrack/bridges/ghidra.py``; they live in
``src/intellicrack/bridges/cutter.py`` as part of CutterBridge.  The audit
misattributed the file. Gates are written against the ACTUAL implementations.

Methods covered (all in ``CutterBridge``, ``src/intellicrack/bridges/cutter.py``):

  ``get_sections``    — ``iSj`` command → ``SectionInfo`` field mapping
  ``get_classes``     — ``icj`` command → ``ClassInfo`` + method/field normalisation
  ``get_vtables``     — ``avj`` command → ``VtableInfo`` field mapping
  ``get_syscalls``    — ``asj`` command → pass-through list
  ``get_callgraph``   — ``agcj`` command → pass-through list
  ``get_resources``   — ``irj`` command → ``ResourceInfo`` field mapping
  ``get_symbols``     — ``isj`` command → ``SymbolInfo`` field mapping
  ``get_flags``       — ``fj`` command → ``FlagInfo`` (address ← ``offset`` key)
  ``add_flag``        — ``f {name} {size} @ {address}`` exact command form
  ``get_libraries``   — ``ilj`` command → ``LibraryInfo``; string and dict entry forms
  ``get_headers``     — ``ihj`` command → ``HeaderInfo`` with ``str(value)`` coercion
  ``get_debug_info``  — ``iDj`` command → first element or ``{}`` on empty
  ``get_all_strings`` — ``izzj`` command (NOT ``izj``) → ``StringInfo`` + encoding map

Every gate asserts BOTH the exact rizin command the bridge emits AND the exact
parsed return value fields against independently-specified oracle payloads.

Oracle: all oracle values are independently specified by the test (chosen by
the test author, not derived from the production code).  No gate re-implements
the production logic to compare against itself.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar, Final, cast

import pytest
import r2pipe

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.types import (
    ClassInfo,
    FlagInfo,
    HeaderInfo,
    LibraryInfo,
    ResourceInfo,
    SectionInfo,
    StringInfo,
    SymbolInfo,
    ToolError,
    VtableInfo,
)


_ADDR: Final[int] = 0x1000
_SECTION_VADDR: Final[int] = 0x1000
_SECTION_VSIZE: Final[int] = 0x800
_SECTION_RAW_SIZE: Final[int] = 0x600
_SECTION_PERM: Final[int] = 0x20
_SECTION_ENTROPY: Final[float] = 3.5
_CLASS_ADDR: Final[int] = 0x1234
_METHOD_ADDR: Final[int] = 0x1300
_FIELD_OFFSET: Final[int] = 8
_VTABLE_ADDR: Final[int] = 0x5000
_VTABLE_METHOD_ADDR: Final[int] = 0x5010
_RESOURCE_PADDR: Final[int] = 0x6000
_RESOURCE_SIZE: Final[int] = 256
_SYMBOL_VADDR: Final[int] = 0x4000
_FLAG_OFFSET: Final[int] = 0x2000
_FLAG_SIZE: Final[int] = 4
_FLAG_ADDR: Final[int] = 0x1000
_FLAG_NAME: Final[str] = "my_label"
_FLAG_COVER_SIZE: Final[int] = 8
_HEADER_PADDR: Final[int] = 0x3C
_STRING_VADDR: Final[int] = 0x8000
_DEBUG_FILE: Final[str] = "program.pdb"
_DEBUG_TYPE: Final[str] = "codeview"


class _CommandRecorder:
    """r2pipe stand-in that records issued commands and returns configurable responses.

    Attributes:
        commands: Ordered list of every command string passed to ``cmd()``.
        responses: Mapping of command prefix to pre-configured response string.
    """

    commands: list[str]
    responses: dict[str, str]

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        """Initialise the recorder with optional pre-configured responses.

        Args:
            responses: Mapping of command prefix to response string.  Falls
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
            (response for prefix, response in self.responses.items() if command == prefix or command.startswith(prefix)),
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


def _make_bridge(responses: dict[str, str] | None = None) -> tuple[CutterBridge, _CommandRecorder]:
    """Return a CutterBridge wired to a deterministic fake transport.

    Args:
        responses: Mapping of command prefix to response string injected into
            the ``_CommandRecorder``.

    Returns:
        tuple[CutterBridge, _CommandRecorder]: The bridge and the recorder for
        direct introspection of issued commands.
    """
    bridge = CutterBridge()
    rec = _CommandRecorder(responses)
    bridge.r2 = _as_r2pipe(rec)
    return bridge, rec


class TestGetSections:
    """Gate ``get_sections``: ``iSj`` command + ``SectionInfo`` field mapping.

    The method delegates to ``_get_sections_internal`` which issues ``iSj``
    and maps JSON keys ``name``/``vaddr``/``vsize``/``size``/``perm``/``entropy``
    to ``SectionInfo`` fields.  Key mutation targets:

    - Changing ``"iSj"`` to ``"iSjJ"`` → command assertion fails.
    - Reading ``"addr"`` instead of ``"vaddr"`` → ``virtual_address`` is 0.
    - Reading ``"rawsize"`` instead of ``"size"`` → ``raw_size`` is 0.
    - Reading ``"characteristics"`` instead of ``"perm"`` → ``characteristics`` is 0.
    """

    _RESPONSE: str = json.dumps([
        {
            "name": ".text",
            "vaddr": _SECTION_VADDR,
            "vsize": _SECTION_VSIZE,
            "size": _SECTION_RAW_SIZE,
            "perm": _SECTION_PERM,
            "entropy": _SECTION_ENTROPY,
        },
    ])

    @pytest.mark.asyncio
    async def test_isj_command_issued(self) -> None:
        """``get_sections`` must emit the ``iSj`` rizin command.

        Mutation caught: replacing ``iSj`` with ``iSSj`` or any other variant
        means the command assertion fails, and sections are never returned.
        """
        bridge, rec = _make_bridge({"iSj": self._RESPONSE})

        await bridge.get_sections()

        assert "iSj" in rec.commands

    @pytest.mark.asyncio
    async def test_section_name_parsed_exactly(self) -> None:
        """``get_sections`` must map the ``name`` JSON key to ``SectionInfo.name``.

        Mutation caught: reading ``"section"`` instead of ``"name"`` →
        ``result[0].name`` is empty.
        """
        bridge, _ = _make_bridge({"iSj": self._RESPONSE})

        result: list[SectionInfo] = await bridge.get_sections()

        assert len(result) == 1
        assert result[0].name == ".text"

    @pytest.mark.asyncio
    async def test_section_virtual_address_from_vaddr_key(self) -> None:
        """``get_sections`` must map ``vaddr`` to ``SectionInfo.virtual_address``.

        Mutation caught: reading ``"addr"`` instead of ``"vaddr"`` →
        ``virtual_address`` is 0 for standard rizin output.
        """
        bridge, _ = _make_bridge({"iSj": self._RESPONSE})

        result: list[SectionInfo] = await bridge.get_sections()

        assert result[0].virtual_address == _SECTION_VADDR

    @pytest.mark.asyncio
    async def test_section_raw_size_from_size_key(self) -> None:
        """``get_sections`` must map ``size`` to ``SectionInfo.raw_size``.

        Mutation caught: reading ``"rawsize"`` instead of ``"size"`` →
        ``raw_size`` is 0.
        """
        bridge, _ = _make_bridge({"iSj": self._RESPONSE})

        result: list[SectionInfo] = await bridge.get_sections()

        assert result[0].raw_size == _SECTION_RAW_SIZE

    @pytest.mark.asyncio
    async def test_section_characteristics_from_perm_key(self) -> None:
        """``get_sections`` must map ``perm`` to ``SectionInfo.characteristics``.

        Mutation caught: reading ``"flags"`` instead of ``"perm"`` →
        ``characteristics`` is 0.
        """
        bridge, _ = _make_bridge({"iSj": self._RESPONSE})

        result: list[SectionInfo] = await bridge.get_sections()

        assert result[0].characteristics == _SECTION_PERM

    @pytest.mark.asyncio
    async def test_section_entropy_parsed(self) -> None:
        """``get_sections`` must map ``entropy`` to ``SectionInfo.entropy``.

        Mutation caught: dropping the ``entropy`` field → ``result[0].entropy``
        defaults to 0.0, not 3.5.
        """
        bridge, _ = _make_bridge({"iSj": self._RESPONSE})

        result: list[SectionInfo] = await bridge.get_sections()

        assert result[0].entropy == pytest.approx(_SECTION_ENTROPY)

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """``get_sections`` returns ``[]`` when rizin reports no sections.

        Mutation caught: returning ``None`` instead of ``[]`` for an empty
        response would break callers that iterate the result.
        """
        bridge, _ = _make_bridge({"iSj": "[]"})

        result: list[SectionInfo] = await bridge.get_sections()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_sections`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``r2`` is ``None`` and
        ``AttributeError`` is raised instead of ``ToolError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_sections()


class TestGetClasses:
    """Gate ``get_classes``: ``icj`` command + ``ClassInfo`` + method/field normalisation.

    Key mutation targets:

    - Changing ``"icj"`` to ``"icjj"`` → command assertion fails.
    - Reading ``"name"`` before ``"classname"`` → wrong class name on real rizin output.
    - Reading method ``"vaddr"`` before ``"addr"`` → method address is 0.
    """

    _RESPONSE: str = json.dumps([
        {
            "classname": "Widget",
            "addr": _CLASS_ADDR,
            "methods": [
                {"name": "draw", "addr": _METHOD_ADDR, "flags": "virtual", "type": "method"},
            ],
            "fields": [
                {"name": "width", "offset": _FIELD_OFFSET, "size": 4, "type": "int"},
            ],
        },
    ])

    @pytest.mark.asyncio
    async def test_icj_command_issued(self) -> None:
        """``get_classes`` must emit the ``icj`` rizin command.

        Mutation caught: emitting ``icjj`` or ``ic`` → ``icj`` not in commands.
        """
        bridge, rec = _make_bridge({"icj": self._RESPONSE})

        await bridge.get_classes()

        assert "icj" in rec.commands

    @pytest.mark.asyncio
    async def test_class_name_from_classname_key(self) -> None:
        """``get_classes`` must read ``classname`` (falling back to ``name``).

        Mutation caught: reading only ``"name"`` → ``result[0].name`` is
        empty when rizin uses ``classname`` (standard output).
        """
        bridge, _ = _make_bridge({"icj": self._RESPONSE})

        result: list[ClassInfo] = await bridge.get_classes()

        assert len(result) == 1
        assert result[0].name == "Widget"

    @pytest.mark.asyncio
    async def test_class_address_from_addr_key(self) -> None:
        """``get_classes`` must map ``addr`` to ``ClassInfo.address``.

        Mutation caught: reading ``"vaddr"`` first → address is 0 when only
        ``"addr"`` is present.
        """
        bridge, _ = _make_bridge({"icj": self._RESPONSE})

        result: list[ClassInfo] = await bridge.get_classes()

        assert result[0].address == _CLASS_ADDR

    @pytest.mark.asyncio
    async def test_method_name_normalised(self) -> None:
        """``get_classes`` must normalise method ``name`` into ``methods[0]["name"]``.

        Mutation caught: forwarding raw method dict unchanged with a different
        key name → ``result[0].methods[0]["name"]`` is absent.
        """
        bridge, _ = _make_bridge({"icj": self._RESPONSE})

        result: list[ClassInfo] = await bridge.get_classes()

        assert result[0].methods[0]["name"] == "draw"

    @pytest.mark.asyncio
    async def test_method_address_normalised(self) -> None:
        """``get_classes`` must normalise method ``addr`` into ``methods[0]["address"]``.

        Mutation caught: not normalising ``addr`` → ``"address"`` key absent
        from the method dict.
        """
        bridge, _ = _make_bridge({"icj": self._RESPONSE})

        result: list[ClassInfo] = await bridge.get_classes()

        assert result[0].methods[0]["address"] == _METHOD_ADDR

    @pytest.mark.asyncio
    async def test_field_name_and_offset_normalised(self) -> None:
        """``get_classes`` must normalise field ``name`` and ``offset`` keys.

        Mutation caught: forwarding raw field dict → ``"offset"`` key absent
        or wrong value.
        """
        bridge, _ = _make_bridge({"icj": self._RESPONSE})

        result: list[ClassInfo] = await bridge.get_classes()

        assert result[0].fields[0]["name"] == "width"
        assert result[0].fields[0]["offset"] == _FIELD_OFFSET

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """``get_classes`` returns ``[]`` for an empty ``icj`` response.

        Mutation caught: returning ``None`` instead of ``[]``.
        """
        bridge, _ = _make_bridge({"icj": "[]"})

        result: list[ClassInfo] = await bridge.get_classes()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_classes`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError`` from None r2.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_classes()


class TestGetVtables:
    """Gate ``get_vtables``: ``avj`` command + ``VtableInfo`` field mapping.

    Key mutation targets:

    - ``"avj"`` command changed → command assertion fails.
    - Reading ``"vaddr"`` instead of ``"offset"`` → address is 0.
    - Reading ``"name"`` before ``"classname"`` → wrong name on real rizin output.
    """

    _METHODS: ClassVar[list[dict[str, Any]]] = [{"name": "Foo::bar", "addr": _VTABLE_METHOD_ADDR}]
    _RESPONSE: str = json.dumps([
        {
            "offset": _VTABLE_ADDR,
            "classname": "CBase",
            "methods": _METHODS,
        },
    ])

    @pytest.mark.asyncio
    async def test_avj_command_issued(self) -> None:
        """``get_vtables`` must emit the ``avj`` rizin command.

        Mutation caught: emitting ``avjj`` → ``avj`` not in recorded commands.
        """
        bridge, rec = _make_bridge({"avj": self._RESPONSE})

        await bridge.get_vtables()

        assert "avj" in rec.commands

    @pytest.mark.asyncio
    async def test_vtable_address_from_offset_key(self) -> None:
        """``get_vtables`` must map ``offset`` to ``VtableInfo.address``.

        Mutation caught: reading ``"vaddr"`` instead of ``"offset"`` →
        ``address`` is 0 for standard rizin vtable output.
        """
        bridge, _ = _make_bridge({"avj": self._RESPONSE})

        result: list[VtableInfo] = await bridge.get_vtables()

        assert len(result) == 1
        assert result[0].address == _VTABLE_ADDR

    @pytest.mark.asyncio
    async def test_vtable_name_from_classname_key(self) -> None:
        """``get_vtables`` must read ``classname`` (falling back to ``name``).

        Mutation caught: reading only ``"name"`` → name is empty on real rizin
        output where key is ``classname``.
        """
        bridge, _ = _make_bridge({"avj": self._RESPONSE})

        result: list[VtableInfo] = await bridge.get_vtables()

        assert result[0].name == "CBase"

    @pytest.mark.asyncio
    async def test_vtable_methods_list_preserved(self) -> None:
        """``get_vtables`` must forward the ``methods`` list unchanged.

        Mutation caught: returning an empty list for ``methods`` → caller
        cannot enumerate vtable entries.
        """
        bridge, _ = _make_bridge({"avj": self._RESPONSE})

        result: list[VtableInfo] = await bridge.get_vtables()

        assert result[0].methods == self._METHODS

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """``get_vtables`` returns ``[]`` for an empty ``avj`` response."""
        bridge, _ = _make_bridge({"avj": "[]"})

        result: list[VtableInfo] = await bridge.get_vtables()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_vtables`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_vtables()


class TestGetSyscalls:
    """Gate ``get_syscalls``: ``asj`` command + pass-through list.

    Rizin's ``asj`` emits a list of syscall dictionaries; the bridge
    forwards them verbatim.  Key mutation targets:

    - ``"asj"`` changed to ``"aSj"`` → command assertion fails.
    - Dropping the result → caller sees ``[]`` instead of populated list.
    """

    _RESPONSE: str = json.dumps([
        {"name": "write", "num": 4, "address": 0xCAFE},
        {"name": "read", "num": 3, "address": 0xBEEF},
    ])

    @pytest.mark.asyncio
    async def test_asj_command_issued(self) -> None:
        """``get_syscalls`` must emit the ``asj`` rizin command.

        Mutation caught: emitting ``aSSj`` → ``asj`` not in recorded commands.
        """
        bridge, rec = _make_bridge({"asj": self._RESPONSE})

        await bridge.get_syscalls()

        assert "asj" in rec.commands

    @pytest.mark.asyncio
    async def test_syscall_name_and_number_returned(self) -> None:
        """``get_syscalls`` must return the exact syscall entries from rizin.

        Mutation caught: returning an empty list regardless of the response
        → first entry name/num assertions fail.
        """
        bridge, _ = _make_bridge({"asj": self._RESPONSE})

        result: list[dict[str, Any]] = await bridge.get_syscalls()

        assert len(result) == 2
        assert result[0]["name"] == "write"
        assert result[0]["num"] == 4

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """``get_syscalls`` returns ``[]`` for an empty ``asj`` response."""
        bridge, _ = _make_bridge({"asj": "[]"})

        result: list[dict[str, Any]] = await bridge.get_syscalls()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_syscalls`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_syscalls()


class TestGetCallgraph:
    """Gate ``get_callgraph``: ``agcj`` command + pass-through list.

    Rizin's ``agcj`` emits callgraph edge dictionaries; the bridge forwards
    them verbatim.  Key mutation targets:

    - ``"agcj"`` changed to ``"agj"`` → command assertion fails.
    - Returning ``None`` instead of the list → callers that iterate fail.
    """

    _RESPONSE: str = json.dumps([
        {"fcn_addr": 0x401000, "fcn_name": "main", "calls": [{"fcn_addr": 0x401100}]},
    ])

    @pytest.mark.asyncio
    async def test_agcj_command_issued(self) -> None:
        """``get_callgraph`` must emit the ``agcj`` rizin command.

        Mutation caught: emitting ``agj`` → ``agcj`` not in recorded commands.
        """
        bridge, rec = _make_bridge({"agcj": self._RESPONSE})

        await bridge.get_callgraph()

        assert "agcj" in rec.commands

    @pytest.mark.asyncio
    async def test_callgraph_entry_returned(self) -> None:
        """``get_callgraph`` must return the exact edge list from rizin.

        Mutation caught: filtering or dropping entries → ``fcn_name``
        assertion fails.
        """
        bridge, _ = _make_bridge({"agcj": self._RESPONSE})

        result: list[dict[str, Any]] = await bridge.get_callgraph()

        assert len(result) == 1
        assert result[0]["fcn_name"] == "main"
        assert result[0]["fcn_addr"] == 0x401000

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """``get_callgraph`` returns ``[]`` for an empty ``agcj`` response."""
        bridge, _ = _make_bridge({"agcj": "[]"})

        result: list[dict[str, Any]] = await bridge.get_callgraph()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_callgraph`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_callgraph()


class TestGetResources:
    """Gate ``get_resources``: ``iRj`` command + ``ResourceInfo`` field mapping.

    Key mutation targets:

    - ``"iRj"`` changed to ``"irj"`` (the relocations command) → command
      assertion fails.
    - Reading ``"vaddr"`` instead of ``"paddr"`` → ``address`` is 0.
    - Dropping ``"type"`` parse → ``type`` field is empty.
    """

    _RESPONSE: str = json.dumps([
        {
            "name": "RT_VERSION",
            "paddr": _RESOURCE_PADDR,
            "size": _RESOURCE_SIZE,
            "type": "RT_VERSION",
            "language": "LANG_ENGLISH",
        },
    ])

    @pytest.mark.asyncio
    async def test_irj_command_issued(self) -> None:
        """``get_resources`` must emit the ``iRj`` rizin command.

        Mutation caught: emitting ``irj`` (the relocations command) →
        ``iRj`` not in recorded commands.
        """
        bridge, rec = _make_bridge({"iRj": self._RESPONSE})

        await bridge.get_resources()

        assert "iRj" in rec.commands

    @pytest.mark.asyncio
    async def test_resource_name_parsed(self) -> None:
        """``get_resources`` must map the ``name`` key to ``ResourceInfo.name``.

        Mutation caught: reading ``"id"`` instead of ``"name"`` → name empty.
        """
        bridge, _ = _make_bridge({"iRj": self._RESPONSE})

        result: list[ResourceInfo] = await bridge.get_resources()

        assert len(result) == 1
        assert result[0].name == "RT_VERSION"

    @pytest.mark.asyncio
    async def test_resource_address_from_paddr_key(self) -> None:
        """``get_resources`` must map ``paddr`` to ``ResourceInfo.address``.

        Mutation caught: reading ``"vaddr"`` instead of ``"paddr"`` →
        ``address`` is 0 for standard PE resource output.
        """
        bridge, _ = _make_bridge({"iRj": self._RESPONSE})

        result: list[ResourceInfo] = await bridge.get_resources()

        assert result[0].address == _RESOURCE_PADDR

    @pytest.mark.asyncio
    async def test_resource_size_parsed(self) -> None:
        """``get_resources`` must map ``size`` to ``ResourceInfo.size``.

        Mutation caught: hardcoding size to 0 → assertion fails.
        """
        bridge, _ = _make_bridge({"iRj": self._RESPONSE})

        result: list[ResourceInfo] = await bridge.get_resources()

        assert result[0].size == _RESOURCE_SIZE

    @pytest.mark.asyncio
    async def test_resource_type_parsed(self) -> None:
        """``get_resources`` must map ``type`` to ``ResourceInfo.type``.

        Mutation caught: dropping ``type`` parse → type is empty string.
        """
        bridge, _ = _make_bridge({"iRj": self._RESPONSE})

        result: list[ResourceInfo] = await bridge.get_resources()

        assert result[0].type == "RT_VERSION"

    @pytest.mark.asyncio
    async def test_resource_language_parsed(self) -> None:
        """``get_resources`` must map ``language`` to ``ResourceInfo.language``.

        Mutation caught: dropping ``language`` parse → language is empty string.
        """
        bridge, _ = _make_bridge({"iRj": self._RESPONSE})

        result: list[ResourceInfo] = await bridge.get_resources()

        assert result[0].language == "LANG_ENGLISH"

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """``get_resources`` returns ``[]`` for an empty ``iRj`` response."""
        bridge, _ = _make_bridge({"iRj": "[]"})

        result: list[ResourceInfo] = await bridge.get_resources()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_resources`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_resources()


class TestGetSymbols:
    """Gate ``get_symbols``: ``isj`` command + ``SymbolInfo`` field mapping.

    Existing tests in test_cutter.py:1448 assert ``name`` and ``address`` but
    do NOT assert that ``isj`` was issued or that ``module_name`` (from the
    ``libname`` key) is mapped correctly.  This class closes those gaps.

    Key mutation targets:

    - ``"isj"`` changed to ``"iSj"`` → command assertion fails.
    - Reading ``"addr"`` instead of ``"vaddr"`` → address is 0.
    - Reading ``"module"`` instead of ``"libname"`` → module_name is empty.
    """

    _RESPONSE: str = json.dumps([
        {"name": "main", "vaddr": _SYMBOL_VADDR, "libname": "test.dll"},
    ])

    @pytest.mark.asyncio
    async def test_isj_command_issued(self) -> None:
        """``get_symbols`` must emit the ``isj`` rizin command.

        Mutation caught: emitting ``iSj`` (sections command) → wrong output
        and command assertion fails.
        """
        bridge, rec = _make_bridge({"isj": self._RESPONSE})

        await bridge.get_symbols()

        assert "isj" in rec.commands

    @pytest.mark.asyncio
    async def test_symbol_name_parsed(self) -> None:
        """``get_symbols`` must map the ``name`` key to ``SymbolInfo.name``.

        Mutation caught: reading ``"sym_name"`` → name is empty.
        """
        bridge, _ = _make_bridge({"isj": self._RESPONSE})

        result: list[SymbolInfo] = await bridge.get_symbols()

        assert len(result) == 1
        assert result[0].name == "main"

    @pytest.mark.asyncio
    async def test_symbol_address_from_vaddr_key(self) -> None:
        """``get_symbols`` must map ``vaddr`` to ``SymbolInfo.address``.

        Mutation caught: reading ``"addr"`` instead of ``"vaddr"`` →
        address is 0 for standard rizin symbol output.
        """
        bridge, _ = _make_bridge({"isj": self._RESPONSE})

        result: list[SymbolInfo] = await bridge.get_symbols()

        assert result[0].address == _SYMBOL_VADDR

    @pytest.mark.asyncio
    async def test_symbol_module_name_from_libname_key(self) -> None:
        """``get_symbols`` must map ``libname`` to ``SymbolInfo.module_name``.

        Mutation caught: reading ``"module"`` instead of ``"libname"`` →
        module_name is None or empty, failing the exact-value assertion.
        """
        bridge, _ = _make_bridge({"isj": self._RESPONSE})

        result: list[SymbolInfo] = await bridge.get_symbols()

        assert result[0].module_name == "test.dll"

    @pytest.mark.asyncio
    async def test_multiple_symbols_all_returned(self) -> None:
        """``get_symbols`` must include all symbols, not just the first.

        Mutation caught: returning only the first element → length assertion fails.
        """
        resp = json.dumps([
            {"name": "foo", "vaddr": 0x4000, "libname": ""},
            {"name": "bar", "vaddr": 0x4100, "libname": ""},
        ])
        bridge, _ = _make_bridge({"isj": resp})

        result: list[SymbolInfo] = await bridge.get_symbols()

        assert len(result) == 2
        assert result[1].name == "bar"
        assert result[1].address == 0x4100

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """``get_symbols`` returns ``[]`` for an empty ``isj`` response."""
        bridge, _ = _make_bridge({"isj": "[]"})

        result: list[SymbolInfo] = await bridge.get_symbols()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_symbols`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_symbols()


class TestGetFlags:
    """Gate ``get_flags``: ``fj`` command + ``FlagInfo`` field mapping.

    The critical mapping is ``offset`` → ``FlagInfo.address``.  The existing
    test (test_cutter.py:1513) asserts name/address/size but does NOT assert
    the ``fj`` command was issued.  This class closes that gap.

    Key mutation targets:

    - ``"fj"`` changed to ``"fdj"`` → command assertion fails.
    - Reading ``"address"`` instead of ``"offset"`` → address is 0 (rizin
      uses ``offset`` as the flag address key in ``fj`` output).
    """

    _RESPONSE: str = json.dumps([
        {"name": "entry0", "offset": _FLAG_OFFSET, "size": _FLAG_SIZE},
    ])

    @pytest.mark.asyncio
    async def test_fj_command_issued(self) -> None:
        """``get_flags`` must emit the ``fj`` rizin command.

        Mutation caught: emitting ``fdj`` → ``fj`` not in recorded commands.
        """
        bridge, rec = _make_bridge({"fj": self._RESPONSE})

        await bridge.get_flags()

        assert "fj" in rec.commands

    @pytest.mark.asyncio
    async def test_flag_name_parsed(self) -> None:
        """``get_flags`` must map the ``name`` key to ``FlagInfo.name``.

        Mutation caught: reading ``"flag_name"`` → name is empty.
        """
        bridge, _ = _make_bridge({"fj": self._RESPONSE})

        result: list[FlagInfo] = await bridge.get_flags()

        assert len(result) == 1
        assert result[0].name == "entry0"

    @pytest.mark.asyncio
    async def test_flag_address_from_offset_key(self) -> None:
        """``get_flags`` must map ``offset`` to ``FlagInfo.address``.

        The rizin ``fj`` output uses ``offset`` for the flag address, NOT
        ``"address"``.  Mutation caught: reading ``"address"`` instead of
        ``"offset"`` → address is 0 for every flag in real rizin output.
        """
        bridge, _ = _make_bridge({"fj": self._RESPONSE})

        result: list[FlagInfo] = await bridge.get_flags()

        assert result[0].address == _FLAG_OFFSET

    @pytest.mark.asyncio
    async def test_flag_size_parsed(self) -> None:
        """``get_flags`` must map ``size`` to ``FlagInfo.size``.

        Mutation caught: hardcoding size to 0 or 1 → assertion fails.
        """
        bridge, _ = _make_bridge({"fj": self._RESPONSE})

        result: list[FlagInfo] = await bridge.get_flags()

        assert result[0].size == _FLAG_SIZE

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """``get_flags`` returns ``[]`` for an empty ``fj`` response."""
        bridge, _ = _make_bridge({"fj": "[]"})

        result: list[FlagInfo] = await bridge.get_flags()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_flags`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_flags()


class TestAddFlag:
    """Gate ``add_flag``: exact ``f {name} {size} @ {address}`` command form.

    The existing test (test_cutter.py:1531) checks that the name and address
    appear in the command but does NOT check that size is embedded in the exact
    correct position.  This class closes that gap.

    Key mutation targets:

    - Omitting ``{size}`` from the command → size assertion fails.
    - Swapping name and address → position assertions fail.
    - Returning ``False`` → return-value assertion fails.
    """

    @pytest.mark.asyncio
    async def test_exact_command_form(self) -> None:
        """``add_flag`` must emit ``f {name} {size} @ {address}`` exactly.

        The oracle is the rizin ``f`` command specification:
        ``f <name> <size> @ <addr>`` — each field must appear in that order.
        Mutation caught: omitting size → the size-check assertion fails, and
        rizin would use a default flag size instead of the caller's intent.
        """
        bridge, rec = _make_bridge()

        result: bool = await bridge.add_flag(_FLAG_NAME, _FLAG_COVER_SIZE, _FLAG_ADDR)

        expected_cmd = f"f {_FLAG_NAME} {_FLAG_COVER_SIZE} @ {_FLAG_ADDR}"
        assert expected_cmd in rec.commands
        assert result

    @pytest.mark.asyncio
    async def test_name_embedded_in_command(self) -> None:
        """``add_flag`` must embed the flag name in the rizin command.

        Mutation caught: hardcoding the name to ``"flag"`` → the name assertion
        fails for any other requested name.
        """
        bridge, rec = _make_bridge()

        await bridge.add_flag("custom_flag", 1, 0x2000)

        flag_cmds = [c for c in rec.commands if c.startswith("f ")]
        assert len(flag_cmds) == 1
        assert "custom_flag" in flag_cmds[0]

    @pytest.mark.asyncio
    async def test_size_embedded_in_command(self) -> None:
        """``add_flag`` must embed the size in the rizin command.

        Mutation caught: hardcoding size to 1 → the exact-command assertion
        fails for any size other than 1.
        """
        bridge, rec = _make_bridge()

        await bridge.add_flag("sz_test", 16, 0x3000)

        flag_cmds = [c for c in rec.commands if c.startswith("f ")]
        assert len(flag_cmds) == 1
        assert "16" in flag_cmds[0]
        assert "sz_test" in flag_cmds[0]

    @pytest.mark.asyncio
    async def test_address_embedded_in_command(self) -> None:
        """``add_flag`` must embed the address in the rizin command.

        Mutation caught: hardcoding address to 0 → ``@ 0x5000`` not present
        in the command for a non-zero target address.
        """
        target_addr: int = 0x5000
        bridge, rec = _make_bridge()

        await bridge.add_flag("addr_test", 4, target_addr)

        flag_cmds = [c for c in rec.commands if c.startswith("f ")]
        assert len(flag_cmds) == 1
        assert f"@ {target_addr}" in flag_cmds[0]

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``add_flag`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.add_flag("x", 1, 0)


class TestGetLibraries:
    """Gate ``get_libraries``: ``ilj`` command + ``LibraryInfo`` for both string and dict entries.

    Rizin's ``ilj`` can return either a JSON array of strings or an array of
    dicts.  Both forms must be handled.  Key mutation targets:

    - ``"ilj"`` changed to ``"iLj"`` → command assertion fails.
    - Not handling the string-array form → name stays empty.
    - Reading a wrong dict key → name stays empty for dict form.
    """

    @pytest.mark.asyncio
    async def test_ilj_command_issued(self) -> None:
        """``get_libraries`` must emit the ``ilj`` rizin command.

        Mutation caught: emitting ``iLj`` → ``ilj`` not in recorded commands.
        """
        resp = json.dumps(["kernel32.dll"])
        bridge, rec = _make_bridge({"ilj": resp})

        await bridge.get_libraries()

        assert "ilj" in rec.commands

    @pytest.mark.asyncio
    async def test_string_entry_wrapped_in_library_info(self) -> None:
        """``get_libraries`` must wrap a string list entry in ``LibraryInfo``.

        Mutation caught: not handling the string-array form → the string
        entry is skipped and the result is empty.
        """
        resp = json.dumps(["kernel32.dll"])
        bridge, _ = _make_bridge({"ilj": resp})

        result: list[LibraryInfo] = await bridge.get_libraries()

        assert len(result) == 1
        assert result[0].name == "kernel32.dll"

    @pytest.mark.asyncio
    async def test_dict_entry_name_key(self) -> None:
        """``get_libraries`` must extract ``name`` from a dict-form list entry.

        Some rizin builds emit ``[{"name": "lib.dll", ...}]`` instead of the
        plain string form.  Mutation caught: reading ``"file"`` instead of
        ``"name"`` → name is empty.
        """
        resp = json.dumps([{"name": "user32.dll"}])
        bridge, _ = _make_bridge({"ilj": resp})

        result: list[LibraryInfo] = await bridge.get_libraries()

        assert len(result) == 1
        assert result[0].name == "user32.dll"

    @pytest.mark.asyncio
    async def test_multiple_libraries_all_returned(self) -> None:
        """``get_libraries`` must return all entries from the response.

        Mutation caught: returning only the first entry → length assertion fails.
        """
        resp = json.dumps(["ntdll.dll", "kernel32.dll", "user32.dll"])
        bridge, _ = _make_bridge({"ilj": resp})

        result: list[LibraryInfo] = await bridge.get_libraries()

        assert len(result) == 3
        assert result[2].name == "user32.dll"

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """``get_libraries`` returns ``[]`` for an empty ``ilj`` response."""
        bridge, _ = _make_bridge({"ilj": ""})

        result: list[LibraryInfo] = await bridge.get_libraries()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_libraries`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_libraries()


class TestGetHeaders:
    """Gate ``get_headers``: ``ihj`` command + ``HeaderInfo`` field mapping.

    The ``value`` field is cast to ``str`` in the bridge, so integer values
    from rizin are coerced.  Key mutation targets:

    - ``"ihj"`` changed to ``"iHj"`` → command assertion fails.
    - Reading ``"vaddr"`` instead of ``"paddr"`` → address is 0.
    - Omitting ``str(value)`` cast → integer value fails string equality.
    """

    _RESPONSE: str = json.dumps([
        {"name": "e_magic", "value": 0x5A4D, "paddr": _HEADER_PADDR},
    ])

    @pytest.mark.asyncio
    async def test_ihj_command_issued(self) -> None:
        """``get_headers`` must emit the ``ihj`` rizin command.

        Mutation caught: emitting ``iHj`` → ``ihj`` not in recorded commands.
        """
        bridge, rec = _make_bridge({"ihj": self._RESPONSE})

        await bridge.get_headers()

        assert "ihj" in rec.commands

    @pytest.mark.asyncio
    async def test_header_name_parsed(self) -> None:
        """``get_headers`` must map the ``name`` key to ``HeaderInfo.name``.

        Mutation caught: reading ``"field"`` → name is empty.
        """
        bridge, _ = _make_bridge({"ihj": self._RESPONSE})

        result: list[HeaderInfo] = await bridge.get_headers()

        assert len(result) == 1
        assert result[0].name == "e_magic"

    @pytest.mark.asyncio
    async def test_header_value_str_coercion(self) -> None:
        """``get_headers`` must convert the integer ``value`` to a string.

        Rizin emits ``value`` as an integer; the bridge casts it with
        ``str(value)``.  Mutation caught: omitting the cast → the field holds
        the integer ``23117`` instead of the string ``"23117"``, failing
        string-equality assertions.
        """
        bridge, _ = _make_bridge({"ihj": self._RESPONSE})

        result: list[HeaderInfo] = await bridge.get_headers()

        assert result[0].value == str(0x5A4D)

    @pytest.mark.asyncio
    async def test_header_address_from_paddr_key(self) -> None:
        """``get_headers`` must map ``paddr`` to ``HeaderInfo.address``.

        Mutation caught: reading ``"vaddr"`` → address is 0 for PE header
        fields that have no virtual mapping.
        """
        bridge, _ = _make_bridge({"ihj": self._RESPONSE})

        result: list[HeaderInfo] = await bridge.get_headers()

        assert result[0].address == _HEADER_PADDR

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """``get_headers`` returns ``[]`` for an empty ``ihj`` response."""
        bridge, _ = _make_bridge({"ihj": "[]"})

        result: list[HeaderInfo] = await bridge.get_headers()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_headers`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_headers()


class TestGetDebugInfo:
    """Gate ``get_debug_info``: ``iDj`` command + first-element-or-empty logic.

    The bridge returns ``result[0] if result else {}``.  Key mutation targets:

    - ``"iDj"`` changed to ``"idj"`` → command assertion fails.
    - Returning the list instead of the first element → type assertion fails.
    - Returning ``None`` on empty → empty-dict assertion fails.
    """

    _RESPONSE: str = json.dumps([
        {"debug_file": _DEBUG_FILE, "debug_type": _DEBUG_TYPE, "format": "pdb"},
    ])

    @pytest.mark.asyncio
    async def test_idj_command_issued(self) -> None:
        """``get_debug_info`` must emit the ``iDj`` rizin command.

        Mutation caught: emitting ``idj`` (lowercase d) → ``iDj`` not in
        recorded commands.
        """
        bridge, rec = _make_bridge({"iDj": self._RESPONSE})

        await bridge.get_debug_info()

        assert "iDj" in rec.commands

    @pytest.mark.asyncio
    async def test_debug_file_field_returned(self) -> None:
        """``get_debug_info`` must return the first element of the ``iDj`` response.

        Mutation caught: returning the whole list → ``result["debug_file"]``
        raises ``TypeError``.
        """
        bridge, _ = _make_bridge({"iDj": self._RESPONSE})

        result: dict[str, Any] = await bridge.get_debug_info()

        assert result["debug_file"] == _DEBUG_FILE

    @pytest.mark.asyncio
    async def test_debug_type_field_returned(self) -> None:
        """``get_debug_info`` must include ``debug_type`` from the response.

        Mutation caught: returning ``{}`` instead of the actual element →
        ``debug_type`` key is absent.
        """
        bridge, _ = _make_bridge({"iDj": self._RESPONSE})

        result: dict[str, Any] = await bridge.get_debug_info()

        assert result["debug_type"] == _DEBUG_TYPE

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_dict(self) -> None:
        """``get_debug_info`` returns ``{}`` when ``iDj`` returns an empty list.

        Mutation caught: returning ``None`` or raising → callers that do
        ``result.get(...)`` receive ``AttributeError``.
        """
        bridge, _ = _make_bridge({"iDj": "[]"})

        result: dict[str, Any] = await bridge.get_debug_info()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_debug_info`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_debug_info()


class TestGetAllStrings:
    """Gate ``get_all_strings``: ``izzj`` command (NOT ``izj``) + ``StringInfo`` fields + encoding map.

    The difference between ``izzj`` (all strings, all sections) and ``izj``
    (data-section strings only) is the defining capability distinction.

    The encoding normalisation map:
      ``"utf-16be"``          → ``"utf-16be"``
      ``"utf-8"``             → ``"utf-8"``
      ``"wide"`` / ``"utf-16le"``  → ``"utf-16le"``
      anything else           → ``"ascii"``

    Key mutation targets:

    - ``"izzj"`` changed to ``"izj"`` → izzj-command assertion fails AND
      non-data strings are silently dropped.
    - Reading ``"paddr"`` instead of ``"vaddr"`` → address is 0.
    - Mapping ``"wide"`` to ``"utf-16be"`` instead of ``"utf-16le"`` →
      encoding assertion fails.
    - Returning the raw ``"type"`` string instead of normalising →
      encoding field would be ``"wide"``, not ``"utf-16le"``.
    """

    @pytest.mark.asyncio
    async def test_izzj_command_issued_not_izj(self) -> None:
        """``get_all_strings`` must emit ``izzj``, not ``izj``.

        ``izzj`` scans all sections; ``izj`` is limited to data sections.
        The method name ``get_all_strings`` promises complete coverage.
        Mutation caught: emitting ``izj`` → ``izzj`` not in recorded commands,
        and strings from code or resource sections are silently dropped.
        """
        resp = json.dumps([{"vaddr": _STRING_VADDR, "string": "Hello", "type": "ascii", "section": ".text"}])
        bridge, rec = _make_bridge({"izzj": resp})

        await bridge.get_all_strings()

        assert "izzj" in rec.commands
        assert all(c != "izj" for c in rec.commands)

    @pytest.mark.asyncio
    async def test_string_address_from_vaddr_key(self) -> None:
        """``get_all_strings`` must map ``vaddr`` to ``StringInfo.address``.

        Mutation caught: reading ``"paddr"`` instead of ``"vaddr"`` →
        address is 0 for all strings.
        """
        resp = json.dumps([{"vaddr": _STRING_VADDR, "string": "Hello", "type": "ascii", "section": ".rdata"}])
        bridge, _ = _make_bridge({"izzj": resp})

        result: list[StringInfo] = await bridge.get_all_strings()

        assert len(result) == 1
        assert result[0].address == _STRING_VADDR

    @pytest.mark.asyncio
    async def test_string_value_from_string_key(self) -> None:
        """``get_all_strings`` must map ``string`` to ``StringInfo.value``.

        Mutation caught: reading ``"content"`` instead of ``"string"`` →
        value is empty.
        """
        resp = json.dumps([{"vaddr": 0x100, "string": "Intellicrack", "type": "ascii", "section": ".rdata"}])
        bridge, _ = _make_bridge({"izzj": resp})

        result: list[StringInfo] = await bridge.get_all_strings()

        assert result[0].value == "Intellicrack"

    @pytest.mark.asyncio
    async def test_encoding_ascii_for_unknown_type(self) -> None:
        """``get_all_strings`` must normalise unknown type strings to ``"ascii"``.

        Mutation caught: forwarding the raw ``type`` field → encoding is
        ``"utf8"`` or similar non-Literal value rather than ``"ascii"``.
        """
        resp = json.dumps([{"vaddr": 0x200, "string": "test", "type": "utf8", "section": ".rdata"}])
        bridge, _ = _make_bridge({"izzj": resp})

        result: list[StringInfo] = await bridge.get_all_strings()

        assert result[0].encoding == "ascii"

    @pytest.mark.asyncio
    async def test_encoding_wide_maps_to_utf16le(self) -> None:
        """``get_all_strings`` must map ``"wide"`` type to ``"utf-16le"``.

        Rizin emits ``"wide"`` for UTF-16 LE strings.  The bridge normalises
        this to the canonical ``"utf-16le"`` Literal.  Mutation caught:
        mapping ``"wide"`` to ``"utf-16be"`` or forwarding ``"wide"`` raw →
        encoding assertion fails.
        """
        resp = json.dumps([{"vaddr": 0x300, "string": "Wide", "type": "wide", "section": ".rdata"}])
        bridge, _ = _make_bridge({"izzj": resp})

        result: list[StringInfo] = await bridge.get_all_strings()

        assert result[0].encoding == "utf-16le"

    @pytest.mark.asyncio
    async def test_encoding_utf16le_raw_maps_to_utf16le(self) -> None:
        """``get_all_strings`` must also accept ``"utf-16le"`` as the type input.

        Mutation caught: handling ``"wide"`` but not ``"utf-16le"`` → encoding
        falls through to ``"ascii"`` when rizin emits the spelled-out variant.
        """
        resp = json.dumps([{"vaddr": 0x400, "string": "LE", "type": "utf-16le", "section": ".rdata"}])
        bridge, _ = _make_bridge({"izzj": resp})

        result: list[StringInfo] = await bridge.get_all_strings()

        assert result[0].encoding == "utf-16le"

    @pytest.mark.asyncio
    async def test_encoding_utf16be_preserved(self) -> None:
        """``get_all_strings`` must pass ``"utf-16be"`` through unchanged.

        Mutation caught: normalising ``"utf-16be"`` to ``"utf-16le"`` →
        encoding assertion fails.
        """
        resp = json.dumps([{"vaddr": 0x500, "string": "BE", "type": "utf-16be", "section": ".rdata"}])
        bridge, _ = _make_bridge({"izzj": resp})

        result: list[StringInfo] = await bridge.get_all_strings()

        assert result[0].encoding == "utf-16be"

    @pytest.mark.asyncio
    async def test_encoding_utf8_preserved(self) -> None:
        """``get_all_strings`` must map ``"utf-8"`` type to ``"utf-8"``.

        Mutation caught: normalising ``"utf-8"`` to ``"ascii"`` →
        encoding assertion fails.
        """
        resp = json.dumps([{"vaddr": 0x600, "string": "UTF8", "type": "utf-8", "section": ".rdata"}])
        bridge, _ = _make_bridge({"izzj": resp})

        result: list[StringInfo] = await bridge.get_all_strings()

        assert result[0].encoding == "utf-8"

    @pytest.mark.asyncio
    async def test_section_field_parsed(self) -> None:
        """``get_all_strings`` must map ``section`` to ``StringInfo.section``.

        Mutation caught: reading ``"seg"`` instead of ``"section"`` →
        section field is empty.
        """
        resp = json.dumps([{"vaddr": 0x700, "string": "sect", "type": "ascii", "section": ".text"}])
        bridge, _ = _make_bridge({"izzj": resp})

        result: list[StringInfo] = await bridge.get_all_strings()

        assert result[0].section == ".text"

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """``get_all_strings`` returns ``[]`` for an empty ``izzj`` response."""
        bridge, _ = _make_bridge({"izzj": "[]"})

        result: list[StringInfo] = await bridge.get_all_strings()

        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """``get_all_strings`` raises ``ToolError`` when no binary is loaded.

        Mutation caught: removing the guard → ``AttributeError``.
        """
        bridge = CutterBridge()

        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_all_strings()
