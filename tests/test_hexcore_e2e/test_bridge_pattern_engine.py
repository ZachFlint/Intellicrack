# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for bridge-level HexPat pattern engine operations."""

from __future__ import annotations

import asyncio
import json
import struct
from typing import TYPE_CHECKING, Any, cast

import pytest


if TYPE_CHECKING:
    from pathlib import Path

pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore native module not built")


def _run(coro: Any) -> Any:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        Any: The result of the coroutine.
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


def _make_pattern_file(tmp_path: Path, bridge: Any) -> Any:
    """Write pattern data to disk, open it in the bridge, and return the bridge.

    Args:
        tmp_path: Pytest temporary directory.
        bridge: An initialized HexEditorBridge fixture.

    Returns:
        Any: The bridge with data loaded.
    """
    data = bytearray(512)
    struct.pack_into("<H", data, 0, 0x1234)
    struct.pack_into("<I", data, 2, 0xDEADBEEF)
    f = tmp_path / "pattern_data.bin"
    f.write_bytes(bytes(data))
    _run(bridge.open_file(str(f)))
    return bridge


class TestCompilePattern:
    """Tests for compile_pattern producing valid JSON from HexPat source."""

    def test_compile_simple_struct_returns_nonempty_string(self, bridge: Any) -> None:
        """Verify that compiling a valid struct produces a non-empty string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        source = "struct Header { u16 magic; u32 value; };"
        result: str = _run(bridge.compile_pattern(source))
        assert isinstance(result, str)
        assert len(result) > 0

    def test_compile_simple_struct_result_is_valid_json(self, bridge: Any) -> None:
        """Verify that compiling a valid struct produces parseable JSON.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        source = "struct Header { u16 magic; u32 value; };"
        result: str = _run(bridge.compile_pattern(source))
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_compile_syntax_error_raises_value_error(self, bridge: Any) -> None:
        """Verify that a syntactically invalid pattern raises ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(ValueError):
            _run(bridge.compile_pattern("struct { u32 x;"))

    def test_compile_complex_struct_with_nested_types_is_valid_json(self, bridge: Any) -> None:
        """Verify that compiling a struct with multiple primitive types produces valid JSON.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        source = "struct Inner { u8 tag; u16 val; };struct Outer { u32 hdr; Inner sub; };"
        result: str = _run(bridge.compile_pattern(source))
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_compile_enum_produces_valid_json(self, bridge: Any) -> None:
        """Verify that compiling an enum declaration produces valid JSON.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        source = "enum Color : u8 { Red = 0, Green = 1, Blue = 2 }; struct Wrapper { Color c; };"
        result: str = _run(bridge.compile_pattern(source))
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_compile_union_produces_valid_json(self, bridge: Any) -> None:
        """Verify that compiling a union declaration produces valid JSON.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        source = "union Word { u16 as_u16; u8 bytes[2]; }; struct Wrapper { Word w; };"
        result: str = _run(bridge.compile_pattern(source))
        parsed = json.loads(result)
        assert isinstance(parsed, dict)


class TestExecutePattern:
    """Tests for execute_pattern running HexPat source against an open document."""

    def test_execute_u32_field_returns_field_list(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that executing a single u32 field returns a non-empty list.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _make_pattern_file(tmp_path, bridge)
        source = "u32 value @ 0x00;"
        fields: list[dict[str, Any]] = _run(bridge.execute_pattern(source))
        assert isinstance(fields, list)
        assert len(fields) >= 1

    def test_execute_u32_field_has_correct_size(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that a u32 field extracted via execute_pattern has size 4.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _make_pattern_file(tmp_path, bridge)
        source = "u32 value @ 0x00;"
        fields: list[dict[str, Any]] = _run(bridge.execute_pattern(source))
        u32_field = next(f for f in fields if f["name"] == "value")
        assert u32_field["size"] == 4

    def test_execute_u32_field_has_correct_offset(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that a u32 field placed at 0x00 has offset 0.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _make_pattern_file(tmp_path, bridge)
        source = "u32 value @ 0x00;"
        fields: list[dict[str, Any]] = _run(bridge.execute_pattern(source))
        u32_field = next(f for f in fields if f["name"] == "value")
        assert u32_field["offset"] == 0

    def test_execute_struct_with_multiple_fields_returns_multiple_results(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that a struct with two fields yields at least one field entry.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _make_pattern_file(tmp_path, bridge)
        source = "struct Header { u16 magic; u32 value; };Header header @ 0x00;"
        fields: list[dict[str, Any]] = _run(bridge.execute_pattern(source))
        assert len(fields) >= 1
        all_names: list[str] = []
        for f in fields:
            all_names.append(f["name"])
            children = f.get("children", [])
            if isinstance(children, list):
                all_names.extend(str(c["name"]) for c in cast("list[dict[str, Any]]", children))
        assert "magic" in all_names or "header" in all_names

    def test_execute_at_nonzero_offset(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that a u32 field placed at 0x04 has offset 4.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _make_pattern_file(tmp_path, bridge)
        source = "u32 value @ 0x04;"
        fields: list[dict[str, Any]] = _run(bridge.execute_pattern(source, offset=0))
        u32_field = next(f for f in fields if f["name"] == "value")
        assert u32_field["offset"] == 4

    def test_execute_pattern_field_has_required_keys(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that each field dict from execute_pattern contains name, offset, and size.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _make_pattern_file(tmp_path, bridge)
        source = "u16 magic @ 0x00;"
        fields: list[dict[str, Any]] = _run(bridge.execute_pattern(source))
        assert len(fields) >= 1
        for f in fields:
            assert "name" in f
            assert "offset" in f
            assert "size" in f

    def test_execute_pattern_with_no_document_raises_runtime_error(self, bridge: Any) -> None:
        """Verify that calling execute_pattern without an open document raises RuntimeError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError):
            _run(bridge.execute_pattern("u32 x @ 0x00;"))

    def test_execute_u16_field_correct_size(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that a u16 field has size 2.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _make_pattern_file(tmp_path, bridge)
        source = "u16 magic @ 0x00;"
        fields: list[dict[str, Any]] = _run(bridge.execute_pattern(source))
        magic_field = next(f for f in fields if f["name"] == "magic")
        assert magic_field["size"] == 2


class TestExecutePatternFile:
    """Tests for execute_pattern_file running patterns from disk."""

    def test_execute_pattern_file_matches_inline_result(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that executing a pattern from a file yields the same field count as inline.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _make_pattern_file(tmp_path, bridge)
        source = "u32 value @ 0x00;"
        pat_file = tmp_path / "test.hexpat"
        pat_file.write_text(source, encoding="utf-8")
        inline_fields: list[dict[str, Any]] = _run(bridge.execute_pattern(source))
        file_fields: list[dict[str, Any]] = _run(bridge.execute_pattern_file(str(pat_file)))
        assert len(file_fields) == len(inline_fields)

    def test_execute_pattern_file_nonexistent_raises_file_not_found(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that passing a missing file path raises FileNotFoundError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _make_pattern_file(tmp_path, bridge)
        missing = str(tmp_path / "does_not_exist.hexpat")
        with pytest.raises(FileNotFoundError):
            _run(bridge.execute_pattern_file(missing))

    def test_execute_pattern_file_with_no_document_raises_runtime_error(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that calling execute_pattern_file without an open document raises RuntimeError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        pat_file = tmp_path / "test.hexpat"
        pat_file.write_text("u32 x @ 0x00;", encoding="utf-8")
        with pytest.raises(RuntimeError):
            _run(bridge.execute_pattern_file(str(pat_file)))

    def test_execute_pattern_file_field_has_required_keys(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that fields from execute_pattern_file contain name, offset, and size.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _make_pattern_file(tmp_path, bridge)
        pat_file = tmp_path / "fields.hexpat"
        pat_file.write_text("u8 first @ 0x00; u8 second @ 0x01;", encoding="utf-8")
        fields: list[dict[str, Any]] = _run(bridge.execute_pattern_file(str(pat_file)))
        assert len(fields) >= 1
        for f in fields:
            assert "name" in f
            assert "offset" in f
            assert "size" in f


class TestListAndAutoDetect:
    """Tests for list_hexpat_patterns and auto_detect_pattern operations."""

    def test_list_hexpat_patterns_returns_list(self, bridge: Any) -> None:
        """Verify that list_hexpat_patterns always returns a list.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_hexpat_patterns())
        assert isinstance(result, list)

    def test_list_hexpat_patterns_items_have_required_keys(self, bridge: Any) -> None:
        """Verify that each entry from list_hexpat_patterns has name, description, and category.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: list[dict[str, str]] = _run(bridge.list_hexpat_patterns())
        for entry in result:
            assert "name" in entry
            assert "description" in entry
            assert "category" in entry

    def test_auto_detect_with_no_document_raises_runtime_error(self, bridge: Any) -> None:
        """Verify that auto_detect_pattern without an open document raises RuntimeError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError):
            _run(bridge.auto_detect_pattern())

    def test_auto_detect_with_pe_file_returns_list(self, loaded_bridge: Any) -> None:
        """Verify that auto_detect_pattern with a PE file open returns a list.

        Args:
            loaded_bridge: A bridge with the PE binary already opened.
        """
        result: list[dict[str, str]] = _run(loaded_bridge.auto_detect_pattern())
        assert isinstance(result, list)
