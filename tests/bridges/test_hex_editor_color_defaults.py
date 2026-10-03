# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates that the hex-editor bridge takes its colours from the shared defaults module.

The colours the bridge advertises in its tool schema, writes into bookmarks and emits in the exported HTML are a contract with tools and
with saved sessions. These gates drive the real bridge over a real ``intellicrack_hexcore.HexDocument`` and check that each of those
colours is the constant in :mod:`intellicrack.core.color_defaults`, so the bridge and the dark theme entries built from the same constants
cannot drift apart.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import intellicrack_hexcore
import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.color_defaults import (
    DEFAULT_BOOKMARK_COLOR,
    DEFAULT_HIGHLIGHT_COLOR,
    HTML_EXPORT_ASCII,
    HTML_EXPORT_BACKGROUND,
    HTML_EXPORT_OFFSET,
    HTML_EXPORT_TEXT,
    STRUCTURE_HEADER_COLOR,
    UNSAFE_COLOR_FALLBACK,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Generator


_DOS_STUB_SIZE: int = 64
_E_LFANEW_OFFSET: int = 0x3C
_ATTR_BOOKMARK_PE_STRUCTURE: str = "_bookmark_pe_structure"


@pytest.fixture
def dos_stub_bridge() -> Generator[HexEditorBridge]:
    """Open a bridge on a file that is a DOS header and nothing else.

    Yields:
        HexEditorBridge: A bridge whose document starts with ``MZ`` and whose ``e_lfanew`` points at bytes that are not a PE signature.
    """
    data = bytearray(_DOS_STUB_SIZE)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, _E_LFANEW_OFFSET, 0)
    handle, name = tempfile.mkstemp(suffix=".bin")
    os.close(handle)
    path = Path(name)
    _ = path.write_bytes(bytes(data))
    bridge = HexEditorBridge()
    bridge.document = intellicrack_hexcore.HexDocument.open(str(path))
    yield bridge
    bridge.document = None
    path.unlink(missing_ok=True)


def _parameter_default(bridge: HexEditorBridge, function: str, parameter: str) -> object:
    """Read the default a tool function advertises for one parameter.

    Args:
        bridge: The bridge whose tool definition is read.
        function: Dotted tool function name.
        parameter: Parameter name.

    Returns:
        object: The advertised default.
    """
    matches = [candidate for candidate in bridge.tool_definition.functions if candidate.name == function]
    assert len(matches) == 1, f"expected one {function} tool function, found {len(matches)}"
    parameters = [candidate for candidate in matches[0].parameters if candidate.name == parameter]
    assert len(parameters) == 1, f"{function} has {len(parameters)} parameters named {parameter!r}"
    return parameters[0].default


def test_tool_schema_advertises_the_shared_bookmark_default() -> None:
    """The ``add_bookmark`` tool advertises the shared default, and its implementation uses the same one."""
    bridge = HexEditorBridge()
    assert _parameter_default(bridge, "hex_editor.add_bookmark", "color") == DEFAULT_BOOKMARK_COLOR
    assert inspect.signature(bridge.add_bookmark).parameters["color"].default == DEFAULT_BOOKMARK_COLOR


def test_tool_schema_advertises_the_shared_highlight_default() -> None:
    """The ``add_highlight_rule`` tool advertises the shared default, and its implementation uses the same one."""
    bridge = HexEditorBridge()
    assert _parameter_default(bridge, "hex_editor.add_highlight_rule", "color") == DEFAULT_HIGHLIGHT_COLOR
    assert inspect.signature(bridge.add_highlight_rule).parameters["color"].default == DEFAULT_HIGHLIGHT_COLOR


def test_bookmark_added_without_a_colour_stores_the_shared_default(dos_stub_bridge: HexEditorBridge) -> None:
    """A bookmark added through the bridge with no colour persists the shared default.

    Args:
        dos_stub_bridge: Bridge with a small document open.
    """
    _ = asyncio.run(dos_stub_bridge.add_bookmark(4, 2, "note"))
    listed = asyncio.run(dos_stub_bridge.list_bookmarks())
    assert [bookmark["color"] for bookmark in listed if bookmark["label"] == "note"] == [DEFAULT_BOOKMARK_COLOR]


def test_structure_bookmark_uses_the_shared_header_colour(dos_stub_bridge: HexEditorBridge) -> None:
    """The DOS header bookmark the structure pass creates carries the shared header colour.

    Args:
        dos_stub_bridge: Bridge whose document is a bare DOS header.
    """
    bookmark_structure = cast("Callable[[], list[dict[str, Any]]]", getattr(dos_stub_bridge, _ATTR_BOOKMARK_PE_STRUCTURE))
    created = bookmark_structure()
    assert [(bookmark["label"], bookmark["color"]) for bookmark in created] == [("DOS Header", STRUCTURE_HEADER_COLOR)]


def test_html_export_uses_the_shared_page_palette(dos_stub_bridge: HexEditorBridge) -> None:
    """The exported hex dump is styled with the shared page, offset and ASCII colours.

    Args:
        dos_stub_bridge: Bridge with a small document open.
    """
    exported = asyncio.run(dos_stub_bridge.export_annotated_html(0, 16))
    assert f"background: {HTML_EXPORT_BACKGROUND}; color: {HTML_EXPORT_TEXT};" in exported
    assert f".offset {{ color: {HTML_EXPORT_OFFSET}; }}" in exported
    assert f".ascii {{ color: {HTML_EXPORT_ASCII}; }}" in exported
    assert f".hex {{ color: {HTML_EXPORT_TEXT}; }}" in exported


def test_html_export_replaces_an_unsafe_colour_with_the_shared_fallback(dos_stub_bridge: HexEditorBridge) -> None:
    """A bookmark colour that is not a plain hex value is exported as the shared neutral fallback.

    Args:
        dos_stub_bridge: Bridge with a small document open.
    """
    document = dos_stub_bridge.document
    assert document is not None
    _ = document.add_bookmark(0, 4, "Header", "javascript:alert(1)")
    exported = asyncio.run(dos_stub_bridge.export_annotated_html(0, 16))
    assert "javascript:alert(1)" not in exported
    assert UNSAFE_COLOR_FALLBACK in exported
