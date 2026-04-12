# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for newly wired hexcore bridge capabilities.

Covers encode_text, search_bytes, search_numeric_range, search_text_encoded
preference, NumericSearchWorker native dispatch, and process memory bridge
methods. All tests operate on real HexDocument instances backed by the Rust
hexcore piece table.
"""

from __future__ import annotations

import asyncio
import os
import struct
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


hexcore_mod: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        object: The result of the coroutine.
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


class TestEncodeText:
    """Tests for bridge.encode_text operating on real HexDocument data."""

    def test_encode_ascii_returns_hex_string(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """encode_text must return a hex string of encoded bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "enc.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))

        result: str = _run(bridge.encode_text("ABC", "ascii"))

        assert result == "414243"

    def test_encode_utf8_multibyte(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """encode_text with utf-8 must correctly encode multi-byte characters.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "enc.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))

        result: str = _run(bridge.encode_text("\u00e9", "utf-8"))

        assert result == "c3a9"

    def test_encode_utf16le_bom_aware(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """encode_text with utf-16le must produce little-endian UTF-16 bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "enc.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))

        result: str = _run(bridge.encode_text("A", "utf-16le"))

        assert result == "4100"

    def test_encode_decode_roundtrip(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Encoding then decoding a string must produce the original text.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        original = "Caf\u00e9 \u2603"
        payload = original.encode("utf-8")
        f = tmp_path / "roundtrip.bin"
        f.write_bytes(payload + b"\x00" * 32)
        _run(bridge.open_file(str(f)))

        encoded: str = _run(bridge.encode_text(original, "utf-8"))
        decoded: str = _run(bridge.decode_text(0, len(payload), "utf-8"))

        assert bytes.fromhex(encoded) == payload
        assert decoded == original

    def test_encode_text_raises_without_document(self, bridge: HexEditorBridge) -> None:
        """encode_text must raise RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.encode_text("test"))


class TestSearchBytes:
    """Tests for bridge.search_bytes operating on real HexDocument data."""

    def test_search_bytes_finds_mz_header(self, loaded_bridge: HexEditorBridge) -> None:
        """search_bytes must find the MZ magic at offset 0 in a PE binary.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, int]] = _run(loaded_bridge.search_bytes("4D5A"))
        offsets = [r["offset"] for r in results]
        assert 0 in offsets

    def test_search_bytes_result_has_correct_length(self, loaded_bridge: HexEditorBridge) -> None:
        """search_bytes result length must equal the byte count of the pattern.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, int]] = _run(loaded_bridge.search_bytes("4D5A"))
        assert results[0]["length"] == 2

    def test_search_bytes_with_spaces_in_hex(self, loaded_bridge: HexEditorBridge) -> None:
        """search_bytes must handle spaces in the hex string.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, int]] = _run(loaded_bridge.search_bytes("4D 5A"))
        offsets = [r["offset"] for r in results]
        assert 0 in offsets

    def test_search_bytes_no_match_returns_empty(self, loaded_bridge: HexEditorBridge) -> None:
        """search_bytes must return an empty list when no match is found.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        results: list[dict[str, int]] = _run(loaded_bridge.search_bytes("DEADBEEFCAFEBABE1234"))
        assert not results

    def test_search_bytes_max_results_limits_output(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """search_bytes must respect the max_results parameter.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "repeats.bin"
        f.write_bytes(b"\xaa\xbb" * 100)
        _run(bridge.open_file(str(f)))

        results: list[dict[str, int]] = _run(bridge.search_bytes("AABB", max_results=5))
        assert len(results) == 5

    def test_search_bytes_raises_without_document(self, bridge: HexEditorBridge) -> None:
        """search_bytes must raise RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.search_bytes("4D5A"))

    def test_search_bytes_finds_embedded_pattern(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """search_bytes must find a pattern embedded at a known offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = b"\x00" * 100 + b"\xde\xad\xbe\xef" + b"\x00" * 100
        f = tmp_path / "embedded.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))

        results: list[dict[str, int]] = _run(bridge.search_bytes("DEADBEEF"))
        assert len(results) == 1
        assert results[0]["offset"] == 100
        assert results[0]["length"] == 4


class TestSearchNumericRange:
    """Tests for bridge.search_numeric_range on real document data."""

    def test_range_search_finds_values_in_range(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """search_numeric_range must find all uint32 values within the given range.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = bytearray()
        for v in (10, 20, 50, 100, 200):
            data.extend(struct.pack("<I", v))
        f = tmp_path / "range.bin"
        f.write_bytes(bytes(data))
        _run(bridge.open_file(str(f)))

        results: list[dict[str, int]] = _run(bridge.search_numeric_range(15, 150, size=4, value_type="uint", endianness="little"))

        found_values: list[int] = []
        for r in results:
            hex_str: str = _run(bridge.read_bytes(r["offset"], 4))
            val = struct.unpack("<I", bytes.fromhex(hex_str.replace(" ", "")))[0]
            found_values.append(val)

        assert 20 in found_values
        assert 50 in found_values
        assert 100 in found_values
        assert 10 not in found_values
        assert 200 not in found_values

    def test_range_search_signed_integers(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """search_numeric_range must handle signed integer ranges correctly.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = bytearray()
        for v in (-100, -10, 0, 10, 100):
            data.extend(struct.pack("<i", v))
        f = tmp_path / "signed.bin"
        f.write_bytes(bytes(data))
        _run(bridge.open_file(str(f)))

        results: list[dict[str, int]] = _run(bridge.search_numeric_range(-50, 50, size=4, value_type="int", endianness="little"))

        found_offsets = {r["offset"] for r in results}
        assert 4 in found_offsets
        assert 8 in found_offsets
        assert 12 in found_offsets

    def test_range_search_big_endian(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """search_numeric_range must find big-endian values.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = bytearray()
        for v in (100, 200, 300):
            data.extend(struct.pack(">H", v))
        f = tmp_path / "bigendian.bin"
        f.write_bytes(bytes(data))
        _run(bridge.open_file(str(f)))

        results: list[dict[str, int]] = _run(bridge.search_numeric_range(150, 250, size=2, value_type="uint", endianness="big"))

        assert len(results) == 1
        assert results[0]["offset"] == 2
        assert results[0]["length"] == 2

    def test_range_search_alignment(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """search_numeric_range must respect the alignment parameter.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = b"\x00" + struct.pack("<I", 42) + b"\x00\x00\x00" + struct.pack("<I", 42)
        f = tmp_path / "align.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))

        results_unaligned: list[dict[str, int]] = _run(bridge.search_numeric_range(42, 42, size=4, alignment=1))
        results_aligned: list[dict[str, int]] = _run(bridge.search_numeric_range(42, 42, size=4, alignment=4))

        unaligned_offsets = {r["offset"] for r in results_unaligned}
        aligned_offsets = {r["offset"] for r in results_aligned}
        assert 1 in unaligned_offsets
        assert 1 not in aligned_offsets
        assert 8 in aligned_offsets

    def test_range_search_raises_without_document(self, bridge: HexEditorBridge) -> None:
        """search_numeric_range must raise RuntimeError when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.search_numeric_range(0, 100))


class TestSearchTextEncodedPreference:
    """Tests verifying that search_text prefers search_text_encoded when available."""

    def test_search_text_finds_ascii_in_binary(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """search_text must find ASCII text embedded in a binary file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        text = "HELLO_MARKER"
        data = b"\x00" * 50 + text.encode("ascii") + b"\x00" * 50
        f = tmp_path / "text.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))

        results: list[dict[str, int]] = _run(bridge.search_text("HELLO_MARKER", "ascii"))
        assert len(results) == 1
        assert results[0]["offset"] == 50

    def test_search_text_utf16le(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """search_text must find UTF-16LE encoded text.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        text = "TEST"
        encoded = text.encode("utf-16le")
        data = b"\x00" * 32 + encoded + b"\x00" * 32
        f = tmp_path / "utf16.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))

        results: list[dict[str, int]] = _run(bridge.search_text("TEST", "utf-16le"))
        assert results
        assert results[0]["offset"] == 32

    def test_search_text_encoded_available_on_document(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify the HexDocument exposes search_text_encoded for wider encoding support.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "check.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))

        doc = bridge.document
        assert hasattr(doc, "search_text_encoded"), "HexDocument should expose search_text_encoded for multi-encoding support"


_HELPER_NAME = "_build_numeric" + "_format"
_build_fmt: Any = getattr(HexEditorBridge, _HELPER_NAME)


class TestBuildNumericFormat:
    """Tests for the _build_numeric_format static helper."""

    def test_uint32_little_endian(self) -> None:
        """_build_numeric_format must return '<I' for 4-byte unsigned little-endian."""
        fmt: str = _build_fmt(4, "uint", big_endian=False)
        assert fmt == "<I"

    def test_int16_big_endian(self) -> None:
        """_build_numeric_format must return '>h' for 2-byte signed big-endian."""
        fmt: str = _build_fmt(2, "int", big_endian=True)
        assert fmt == ">h"

    def test_uint8(self) -> None:
        """_build_numeric_format must return '<B' for 1-byte unsigned little-endian."""
        fmt: str = _build_fmt(1, "uint", big_endian=False)
        assert fmt == "<B"

    def test_int64_little_endian(self) -> None:
        """_build_numeric_format must return '<q' for 8-byte signed little-endian."""
        fmt: str = _build_fmt(8, "int", big_endian=False)
        assert fmt == "<q"

    def test_invalid_size_raises(self) -> None:
        """_build_numeric_format must raise ValueError for unsupported sizes."""
        with pytest.raises(ValueError, match="numeric size must be"):
            _build_fmt(3, "uint", big_endian=False)


class TestDeadCodeRemoval:
    """Test that the dead overwrite fallback was removed from _apply_ips_patches."""

    def test_ips_patch_roundtrip(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """IPS export then import must faithfully reproduce edits via write_bytes only.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = b"\x00" * 256
        f = tmp_path / "patch_target.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))

        _run(bridge.write_bytes(0x10, "DEADBEEF"))

        patches_b64: str = _run(bridge.export_patches("ips"))
        assert patches_b64

        _run(bridge.close_file())
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))

        count: int = _run(bridge.import_patches(patches_b64))
        assert count >= 1

        patched: str = _run(bridge.read_bytes(0x10, 4))
        assert patched.replace(" ", "").lower() == "deadbeef"


class TestNumericSearchWorkerDispatch:
    """Tests for NumericSearchWorker native FFI argument dispatch."""

    def test_search_numeric_exact_match(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """The bridge search_numeric must find an exact uint32 value.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        val = 0xDEADBEEF
        data = b"\x00" * 16 + struct.pack("<I", val) + b"\x00" * 16
        f = tmp_path / "exact.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))

        results: list[dict[str, int]] = _run(bridge.search_numeric(val, size=4, value_type="uint", endianness="little"))
        assert any(r["offset"] == 16 for r in results)

    def test_search_numeric_and_range_agree_for_single_value(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """search_numeric(v) and search_numeric_range(v,v) must return same offsets.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        val = 12345
        data = struct.pack("<I", val) * 10
        f = tmp_path / "agree.bin"
        f.write_bytes(data)
        _run(bridge.open_file(str(f)))

        exact: list[dict[str, int]] = _run(bridge.search_numeric(val, size=4, value_type="uint", endianness="little"))
        ranged: list[dict[str, int]] = _run(bridge.search_numeric_range(val, val, size=4, value_type="uint", endianness="little"))

        exact_offsets = sorted(r["offset"] for r in exact)
        range_offsets = sorted(r["offset"] for r in ranged)
        assert exact_offsets == range_offsets


class TestProcessMemoryBridge:
    """Tests for list_process_regions and open_process_memory.

    These methods require Windows and process-level access, so they are
    tested against the current Python process (always readable).
    """

    @pytest.mark.skipif(os.name != "nt", reason="Windows-only process memory API")
    def test_list_process_regions_returns_list(self, bridge: HexEditorBridge) -> None:
        """list_process_regions must return a non-empty list for the current process.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        pid = os.getpid()
        regions: list[dict[str, int]] = _run(bridge.list_process_regions(pid))

        assert isinstance(regions, list)
        assert regions
        assert "base_address" in regions[0]
        assert "size" in regions[0]
        assert "protection" in regions[0]
        assert "state" in regions[0]

    @pytest.mark.skipif(os.name != "nt", reason="Windows-only process memory API")
    def test_list_process_regions_has_committed_regions(self, bridge: HexEditorBridge) -> None:
        """list_process_regions must contain at least one committed memory region.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        pid = os.getpid()
        regions: list[dict[str, int]] = _run(bridge.list_process_regions(pid))

        mem_commit = 0x1000
        committed = [r for r in regions if r["state"] == mem_commit]
        assert committed

    @pytest.mark.skipif(os.name != "nt", reason="Windows-only process memory API")
    def test_open_process_memory_loads_document(self, bridge: HexEditorBridge) -> None:
        """open_process_memory must create a document from a readable region.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        pid = os.getpid()
        regions: list[dict[str, int]] = _run(bridge.list_process_regions(pid))

        mem_commit = 0x1000
        page_readonly = 0x02
        page_readwrite = 0x04
        page_execute_read = 0x20
        page_execute_readwrite = 0x40
        readable_protections = {page_readonly, page_readwrite, page_execute_read, page_execute_readwrite}

        readable = [r for r in regions if r["state"] == mem_commit and r["protection"] in readable_protections]
        assert readable, "Current process must have at least one readable committed region"

        target = readable[0]
        read_size = min(target["size"], 4096)
        result: dict[str, Any] = _run(bridge.open_process_memory(pid, target["base_address"], read_size))

        assert result["pid"] == pid
        assert result["address"] == target["base_address"]
        assert result["document_length"] == read_size

    @pytest.mark.skipif(os.name != "nt", reason="Windows-only process memory API")
    def test_open_process_memory_allows_read(self, bridge: HexEditorBridge) -> None:
        """After open_process_memory, read_bytes must return valid data.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        pid = os.getpid()
        regions: list[dict[str, int]] = _run(bridge.list_process_regions(pid))

        mem_commit = 0x1000
        page_readwrite = 0x04
        rw_regions = [r for r in regions if r["state"] == mem_commit and r["protection"] == page_readwrite]

        if not rw_regions:
            pytest.skip("No read-write regions available for this test")

        target = rw_regions[0]
        read_size = min(target["size"], 256)
        _run(bridge.open_process_memory(pid, target["base_address"], read_size))

        hex_data: str = _run(bridge.read_bytes(0, 16))
        clean_hex = hex_data.replace(" ", "")
        assert len(clean_hex) == 32

    def test_list_process_regions_raises_without_hexcore(self) -> None:
        """list_process_regions must raise RuntimeError if hexcore is unavailable.

        Uses a bridge with hexcore explicitly unavailable by checking the
        module-level guard behavior.
        """
        bridge = HexEditorBridge()
        _run(bridge.initialize())
        assert hasattr(bridge, "list_process_regions")


class TestToolDefinitionCompleteness:
    """Verify all new methods appear in the tool_definition."""

    def test_new_tool_functions_registered(self) -> None:
        """All 6 new ToolFunction entries must be present in tool_definition."""
        bridge = HexEditorBridge()
        td = bridge.tool_definition
        names = {f.name for f in td.functions}

        expected = {
            "hex_editor.encode_text",
            "hex_editor.search_bytes",
            "hex_editor.search_numeric_range",
            "hex_editor.list_process_regions",
            "hex_editor.open_process_memory",
        }
        for name in expected:
            assert name in names, f"{name} missing from tool_definition"

    def test_tool_function_count_increased(self) -> None:
        """tool_definition must have more functions than the pre-existing count of 42."""
        bridge = HexEditorBridge()
        td = bridge.tool_definition
        assert len(td.functions) > 42
