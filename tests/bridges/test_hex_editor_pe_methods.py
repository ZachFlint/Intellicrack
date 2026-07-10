# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Bridge-layer contract tests for the new PE introspection methods.

These tests do not require ``intellicrack_hexcore`` to be built; they
verify the ``HexEditorBridge.get_pe_sections`` /
``get_pe_imports`` / ``get_pe_exports`` API surface that
``ToolRegistry.execute_tool_call`` dispatches against. End-to-end
behaviour against a real ``HexDocument`` lives in
``tests/test_hexcore_e2e/test_bridge_pe_introspection.py``.
"""

from __future__ import annotations

import asyncio
import inspect
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.pe_format import (
    PE32_OPTIONAL_HEADER_SIZE,
    PE32PLUS_OPTIONAL_HEADER_SIZE,
    PE_DATA_DIRECTORY_ENTRY_SIZE,
    PE_DOS_HEADER_SIZE,
    PE_DOS_LFANEW_OFFSET,
    PE_DOS_SIGNATURE,
    PE_OPTIONAL_HEADER_MAGIC_PE32,
    PE_OPTIONAL_HEADER_MAGIC_PE32PLUS,
    PE_SIGNATURE,
)
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import Coroutine


_NEW_METHOD_NAMES: Final[tuple[str, ...]] = (
    "get_pe_sections",
    "get_pe_imports",
    "get_pe_exports",
)


_NEW_TOOL_NAMES: Final[tuple[str, ...]] = (
    "hex_editor.get_pe_sections",
    "hex_editor.get_pe_imports",
    "hex_editor.get_pe_exports",
)


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


@pytest.fixture
def bridge() -> HexEditorBridge:
    """Construct a fresh ``HexEditorBridge`` with no document attached.

    Returns:
        HexEditorBridge: Bridge instance for contract-level tests.
    """
    return HexEditorBridge()


class TestToolDefinitionsRegistered:
    """Verify each new method is registered with the bridge tool definition."""

    @pytest.mark.parametrize("tool_name", _NEW_TOOL_NAMES)
    def test_tool_function_exposed(self, bridge: HexEditorBridge, tool_name: str) -> None:
        """Verify each advertised tool name dispatches successfully via ToolRegistry.

        Registers the bridge directly into a ToolRegistry and calls
        ``execute_tool_call`` with no document attached. The registry must
        resolve the method and raise :class:`ToolError` wrapping the
        ``RuntimeError`` from the no-document guard, proving that the
        function name is present, callable, and reachable through the
        production dispatch path.

        Args:
            bridge: HexEditorBridge fixture.
            tool_name: Fully-qualified tool function name to dispatch.
        """
        names = {fn.name for fn in bridge.tool_definition.functions}
        assert tool_name in names, f"{tool_name} missing from bridge.tool_definition"

        registry = ToolRegistry(tools_dir=Path())
        registry.register_bridge(ToolName.HEX_EDITOR, bridge)
        bare_name = tool_name.split(".", maxsplit=1)[-1]
        with pytest.raises(ToolError):
            asyncio.run(registry.execute_tool_call("hex_editor", tool_name, {}))

        method = getattr(bridge, bare_name)
        assert inspect.iscoroutinefunction(method), f"{bare_name} must be async for the registry to await it"

    def test_tool_owner_is_hex_editor(self, bridge: HexEditorBridge) -> None:
        """Verify the bridge registers under :attr:`ToolName.HEX_EDITOR` and is reachable.

        Registers the bridge in a ToolRegistry and confirms:
        (1) ``tool_definition.tool_name`` is :attr:`ToolName.HEX_EDITOR`,
        (2) the bridge is retrievable from the registry under that name,
        (3) the registry's dispatch path is active for the HEX_EDITOR tool.

        Args:
            bridge: HexEditorBridge fixture.
        """
        assert bridge.tool_definition.tool_name is ToolName.HEX_EDITOR

        registry = ToolRegistry(tools_dir=Path())
        registry.register_bridge(ToolName.HEX_EDITOR, bridge)

        registered: HexEditorBridge = registry.get_hex_editor_bridge()
        assert registered is bridge, "get_hex_editor_bridge() must return the exact bridge instance registered for HEX_EDITOR"

        with pytest.raises(ToolError):
            asyncio.run(registry.execute_tool_call("hex_editor", "hex_editor.get_pe_sections", {}))

    @pytest.mark.parametrize("tool_name", _NEW_TOOL_NAMES)
    def test_tool_function_has_no_required_params(
        self,
        bridge: HexEditorBridge,
        tool_name: str,
    ) -> None:
        """Verify each new tool definition exposes zero parameters.

        Args:
            bridge: HexEditorBridge fixture.
            tool_name: Fully-qualified tool function name to look up.
        """
        functions = {fn.name: fn for fn in bridge.tool_definition.functions}
        fn = functions[tool_name]
        assert not list(fn.parameters), f"{tool_name} should have no parameters"


_ZERO_ARG_EXPECTED: Final[dict[str, int]] = {
    "get_pe_sections": 2,
    "get_pe_imports": 0,
    "get_pe_exports": 0,
}


class TestMethodDispatchSurface:
    """Verify the zero-argument contract and live return values of each PE method.

    Combines the signature-shape contract (no parameters beyond ``self``)
    with a real invocation against an in-memory PE32 document so that the
    assertions are falsifiable: a required-parameter addition causes a
    ``TypeError`` on the zero-arg call, and a method that returns wrong data
    fails the length check.
    """

    @pytest.mark.parametrize("method_name", _NEW_METHOD_NAMES)
    def test_method_signature_and_return_value(
        self,
        bridge: HexEditorBridge,
        method_name: str,
    ) -> None:
        """Verify zero-parameter signature and correct return value for a known PE32 image.

        Confirms two gating properties simultaneously:

        1. ``inspect.signature`` exposes no parameters beyond ``self``,
           so any addition of a required argument causes this test to fail
           via ``TypeError`` on the bare call.
        2. The method is invoked with zero arguments against an
           :class:`_InMemoryDocument` backed by a deterministic PE32 image
           built from :func:`_build_pe_buffer`.  The expected length is the
           independent oracle derived directly from the PE structure:
           ``get_pe_sections`` must return exactly 2 dicts (one per section
           inserted by :func:`_build_pe_buffer`); ``get_pe_imports`` and
           ``get_pe_exports`` must return ``[]`` because the image carries
           no import or export data directory.

        Args:
            bridge: HexEditorBridge fixture with no document attached initially.
            method_name: Bare method name (``get_pe_sections``,
                ``get_pe_imports``, or ``get_pe_exports``) to inspect and
                invoke.
        """
        method = getattr(bridge, method_name)
        sig = inspect.signature(method)
        assert not list(sig.parameters), f"{method_name} must accept no arguments beyond self"

        bridge.document = _InMemoryDocument(_build_pe_buffer(is_pe64=False))
        result: list[dict[str, Any]] = _run(method())

        expected_len: int = int(_ZERO_ARG_EXPECTED[method_name])
        assert len(result) == expected_len, (
            f"{method_name}() returned {len(result)} entries against a two-section PE32 image "
            f"with no import/export directory; expected {expected_len}"
        )

        if method_name == "get_pe_sections":
            assert result[0]["name"] == ".text", "first section must be '.text' as packed by _build_pe_buffer"
            assert result[1]["name"] == ".rdata", "second section must be '.rdata' as packed by _build_pe_buffer"


class TestRuntimeContract:
    """Verify the no-document and non-PE contracts of the new methods."""

    @pytest.mark.parametrize("method_name", _NEW_METHOD_NAMES)
    def test_no_document_raises_runtime_error(
        self,
        bridge: HexEditorBridge,
        method_name: str,
    ) -> None:
        """Verify each method raises ``RuntimeError`` with "no document" when unloaded.

        The bridge's no-document guard message is the literal string
        ``"no document open"``. A test that only checks the exception
        type cannot distinguish a missing-document guard from a parse
        error or any other ``RuntimeError``; the match pattern locks the
        assertion to the specific guard contract.

        Args:
            bridge: HexEditorBridge fixture (initialized but unloaded).
            method_name: Bare method name under test.
        """
        assert bridge.document is None, f"precondition: bridge.document must be None before calling {method_name}"
        method = getattr(bridge, method_name)
        with pytest.raises(RuntimeError, match=r"no document"):
            _run(method())


class _InMemoryDocument:
    """Minimal ``HexDocument`` surrogate exposing only ``length`` and ``read``.

    Used to feed deterministic byte buffers into the bridge so tests
    can validate section/import/export parsing without depending on
    the optional ``intellicrack_hexcore`` Rust extension.
    """

    def __init__(self, data: bytes) -> None:
        """Store the in-memory buffer.

        Args:
            data: Backing bytes to expose through ``read``.
        """
        self._data: bytes = data

    def length(self) -> int:
        """Return the document length.

        Returns:
            int: Total number of bytes in the document.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        """Return ``length`` bytes starting at ``offset``.

        Args:
            offset: Byte offset to read from.
            length: Number of bytes to read.

        Returns:
            bytes: Slice of the underlying buffer.
        """
        return self._data[offset : offset + length]


_NUM_DATA_DIRECTORIES: Final[int] = 16
_DEFAULT_IMAGE_BASE_PE32: Final[int] = 0x00400000
_DEFAULT_IMAGE_BASE_PE64: Final[int] = 0x00007FF600000000
_TEXT_VADDR: Final[int] = 0x1000
_TEXT_VSIZE: Final[int] = 0x100
_TEXT_RAW_SIZE: Final[int] = 0x200
_TEXT_RAW_OFFSET: Final[int] = 0x400
_TEXT_CHARACTERISTICS: Final[int] = 0x60000020
_RDATA_VADDR: Final[int] = 0x2000
_RDATA_VSIZE: Final[int] = 0x150
_RDATA_RAW_SIZE: Final[int] = 0x200
_RDATA_RAW_OFFSET: Final[int] = 0x600
_RDATA_CHARACTERISTICS: Final[int] = 0x40000040


def _build_pe_buffer(*, is_pe64: bool) -> bytes:
    """Assemble a deterministic PE buffer with a .text and .rdata section.

    The buffer is sized to fit through the second section's raw bytes
    so the bridge's section-table walk operates on a fully-addressable
    image.

    Args:
        is_pe64: ``True`` for PE32+ (64-bit), ``False`` for PE32.

    Returns:
        bytes: Complete PE image buffer.
    """
    e_lfanew = PE_DOS_HEADER_SIZE
    machine = 0x8664 if is_pe64 else 0x014C
    image_base = _DEFAULT_IMAGE_BASE_PE64 if is_pe64 else _DEFAULT_IMAGE_BASE_PE32

    base_opt_size = PE32PLUS_OPTIONAL_HEADER_SIZE if is_pe64 else PE32_OPTIONAL_HEADER_SIZE
    opt_buf = bytearray(base_opt_size)
    if is_pe64:
        struct.pack_into("<H", opt_buf, 0, PE_OPTIONAL_HEADER_MAGIC_PE32PLUS)
        struct.pack_into("<Q", opt_buf, 24, image_base)
    else:
        struct.pack_into("<H", opt_buf, 0, PE_OPTIONAL_HEADER_MAGIC_PE32)
        struct.pack_into("<I", opt_buf, 28, image_base)
    opt_full = bytes(opt_buf) + (b"\x00" * (PE_DATA_DIRECTORY_ENTRY_SIZE * _NUM_DATA_DIRECTORIES))

    coff = struct.pack(
        "<HHIIIHH",
        machine,
        2,
        0,
        0,
        0,
        len(opt_full),
        0x2102,
    )

    def _build_section(
        name: bytes,
        vsize: int,
        vaddr: int,
        rsize: int,
        roff: int,
        chars: int,
    ) -> bytes:
        return name.ljust(8, b"\x00")[:8] + struct.pack(
            "<IIIIIIHHI",
            vsize,
            vaddr,
            rsize,
            roff,
            0,
            0,
            0,
            0,
            chars,
        )

    text = _build_section(
        b".text",
        _TEXT_VSIZE,
        _TEXT_VADDR,
        _TEXT_RAW_SIZE,
        _TEXT_RAW_OFFSET,
        _TEXT_CHARACTERISTICS,
    )
    rdata = _build_section(
        b".rdata",
        _RDATA_VSIZE,
        _RDATA_VADDR,
        _RDATA_RAW_SIZE,
        _RDATA_RAW_OFFSET,
        _RDATA_CHARACTERISTICS,
    )

    nt_headers = PE_SIGNATURE + coff + opt_full + text + rdata
    final_size = _RDATA_RAW_OFFSET + _RDATA_RAW_SIZE
    buf = bytearray(final_size)
    buf[:2] = PE_DOS_SIGNATURE
    struct.pack_into("<I", buf, PE_DOS_LFANEW_OFFSET, e_lfanew)
    buf[e_lfanew : e_lfanew + len(nt_headers)] = nt_headers
    return bytes(buf)


class TestSectionWalkAgainstInMemoryDocument:
    """Validate ``get_pe_sections`` against an in-memory document surrogate.

    These tests bypass ``open_file`` (which would require the Rust
    hexcore) by attaching an :class:`_InMemoryDocument` directly to the
    bridge so the parse path is exercised end-to-end against bytes the
    test owns.
    """

    def test_pe32_two_sections(self, bridge: HexEditorBridge) -> None:
        """Verify the bridge yields both sections for PE32.

        Args:
            bridge: HexEditorBridge fixture.
        """
        bridge.document = _InMemoryDocument(_build_pe_buffer(is_pe64=False))
        sections: Any = _run(bridge.get_pe_sections())
        assert len(sections) == 2
        assert sections[0]["name"] == ".text"
        assert sections[0]["virtual_address"] == _TEXT_VADDR
        assert sections[0]["raw_offset"] == _TEXT_RAW_OFFSET
        assert sections[1]["name"] == ".rdata"
        assert sections[1]["raw_size"] == _RDATA_RAW_SIZE

    def test_pe32plus_two_sections(self, bridge: HexEditorBridge) -> None:
        """Verify the bridge yields both sections for PE32+.

        Args:
            bridge: HexEditorBridge fixture.
        """
        bridge.document = _InMemoryDocument(_build_pe_buffer(is_pe64=True))
        sections: Any = _run(bridge.get_pe_sections())
        assert len(sections) == 2
        assert sections[0]["virtual_size"] == _TEXT_VSIZE
        assert sections[1]["virtual_address"] == _RDATA_VADDR

    def test_non_pe_returns_empty(self, bridge: HexEditorBridge) -> None:
        """Verify ELF magic produces an empty section list.

        Args:
            bridge: HexEditorBridge fixture.
        """
        bridge.document = _InMemoryDocument(b"\x7fELF" + b"\x00" * 256)
        sections: Any = _run(bridge.get_pe_sections())
        assert sections == []

    def test_truncated_pe_returns_empty(self, bridge: HexEditorBridge) -> None:
        """Verify a truncated PE header yields an empty list rather than raising.

        Args:
            bridge: HexEditorBridge fixture.
        """
        bridge.document = _InMemoryDocument(b"MZ")
        sections: Any = _run(bridge.get_pe_sections())
        assert sections == []

    def test_imports_for_pe_without_directory(self, bridge: HexEditorBridge) -> None:
        """Verify ``get_pe_imports`` returns ``[]`` when no import directory exists.

        Args:
            bridge: HexEditorBridge fixture.
        """
        bridge.document = _InMemoryDocument(_build_pe_buffer(is_pe64=False))
        imports: Any = _run(bridge.get_pe_imports())
        assert imports == []

    def test_exports_for_pe_without_directory(self, bridge: HexEditorBridge) -> None:
        """Verify ``get_pe_exports`` returns ``[]`` when no export directory exists.

        Args:
            bridge: HexEditorBridge fixture.
        """
        bridge.document = _InMemoryDocument(_build_pe_buffer(is_pe64=True))
        exports: Any = _run(bridge.get_pe_exports())
        assert exports == []

    def test_imports_for_non_pe(self, bridge: HexEditorBridge) -> None:
        """Verify ``get_pe_imports`` skips non-PE buffers.

        Args:
            bridge: HexEditorBridge fixture.
        """
        bridge.document = _InMemoryDocument(b"\x7fELF" + b"\x00" * 256)
        imports: Any = _run(bridge.get_pe_imports())
        assert imports == []

    def test_exports_for_non_pe(self, bridge: HexEditorBridge) -> None:
        """Verify ``get_pe_exports`` skips non-PE buffers.

        Args:
            bridge: HexEditorBridge fixture.
        """
        bridge.document = _InMemoryDocument(b"\x7fELF" + b"\x00" * 256)
        exports: Any = _run(bridge.get_pe_exports())
        assert exports == []
