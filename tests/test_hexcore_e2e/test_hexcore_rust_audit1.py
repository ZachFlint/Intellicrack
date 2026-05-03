# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""Integration tests for Audit-1 hexcore-rust findings (F-0001..F-0005).

Each test class targets a single audit finding and exercises the code
through the Python bridge or the ``intellicrack_hexcore`` native module
to confirm the Rust fix is observable end-to-end. The tests focus on
behavioural outcomes rather than implementation details so that future
refactors of the Rust core are free to evolve internals.
"""

from __future__ import annotations

import asyncio
import json
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
    """Run an async coroutine synchronously for sync test bodies.

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


_ANCHOR_THRESHOLD = 1_048_576


class TestF0001MoveBlockUndo:
    """F-0001: ``move_block`` must restore both source and destination on undo."""

    def test_undo_after_move_restores_source_zeroes_and_destination(self) -> None:
        """Verify that undoing a move repaints the source bytes and old destination.

        The original implementation recorded only the destination overwrite,
        so undo left a hole of zeros where the source used to live.
        """
        doc = hexcore_mod.HexDocument.open_bytes(b"AAAABBBBCCCCDDDD")
        doc.move_block(0, 4, 12)
        assert doc.read(0, 4) == b"\x00\x00\x00\x00"
        assert doc.read(12, 4) == b"AAAA"

        assert doc.undo() is True
        assert doc.read(0, doc.length()) == b"AAAABBBBCCCCDDDD"

    def test_redo_after_undo_reapplies_source_zeroing_and_dest_overwrite(self) -> None:
        """Verify redo reproduces the original move (source cleared, dest written).

        Confirms the undo manager's MoveBlock variant carries enough state
        to round-trip in both directions.
        """
        doc = hexcore_mod.HexDocument.open_bytes(b"AAAABBBBCCCCDDDD")
        doc.move_block(0, 4, 12)
        doc.undo()
        assert doc.read(0, doc.length()) == b"AAAABBBBCCCCDDDD"

        assert doc.redo() is True
        assert doc.read(0, doc.length()) == b"\x00\x00\x00\x00BBBBCCCCAAAA"


class TestF0002SwapBlocksRequiresEqualLengths:
    """F-0002: ``swap_blocks`` must reject unequal-length operands."""

    def test_unequal_lengths_raise_value_error_on_native(self) -> None:
        """Verify the Rust core raises a ValueError when len_a != len_b."""
        doc = hexcore_mod.HexDocument.open_bytes(b"\x00" * 64)
        doc.write_bytes(0, b"\xaa\xbb\xcc\xdd")
        doc.write_bytes(32, b"\x11\x22\x33\x44\x55\x66\x77\x88")
        with pytest.raises(ValueError, match="equal-length"):
            doc.swap_blocks(0, 4, 32, 8)

    def test_unequal_lengths_raise_via_bridge(self, tmp_path: Path) -> None:
        """Verify HexEditorBridge propagates the equal-length requirement.

        Args:
            tmp_path: Pytest temp directory.
        """
        bridge = HexEditorBridge()
        _run(bridge.initialize())
        f = tmp_path / "swap_unequal.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "AA BB CC DD"))
        _run(bridge.write_bytes(32, "11 22 33 44 55 66 77 88"))
        with pytest.raises(ValueError, match="equal-length"):
            _run(bridge.swap_blocks(0, 4, 32, 8))

    def test_equal_lengths_swap_succeeds(self) -> None:
        """Equal-length swap remains a supported, lossless operation."""
        doc = hexcore_mod.HexDocument.open_bytes(b"\x00" * 16)
        doc.write_bytes(0, b"AAAA")
        doc.write_bytes(8, b"BBBB")
        doc.swap_blocks(0, 4, 8, 4)
        assert doc.read(0, 4) == b"BBBB"
        assert doc.read(8, 4) == b"AAAA"


class TestF0003DiffDataBlockRemoval:
    """F-0003: large-buffer diff dispatch must use the anchored algorithm."""

    def test_large_buffer_diff_uses_byte_precise_offsets(self) -> None:
        """Verify ``diff_bytes`` over a >1 MiB buffer reports byte-precise regions.

        The deleted ``diff_data_block`` fallback emitted block-aligned
        regions (multiples of 64 bytes); the anchored algorithm should
        pinpoint a single-byte change without rounding it up.
        """
        size = _ANCHOR_THRESHOLD + 4096
        data_a = bytearray(size)
        for idx in range(size):
            data_a[idx] = (idx * 31 + 7) & 0xFF
        data_b = bytearray(data_a)
        change_offset = size // 2
        data_b[change_offset] ^= 0xFF

        result: dict[str, Any] = hexcore_mod.diff_bytes(bytes(data_a), bytes(data_b))
        assert result["files_identical"] is False

        non_match: list[dict[str, Any]] = [r for r in result["regions"] if r["diff_type"] != "match" and r["length"] > 0]
        assert non_match, "expected at least one non-match region"
        first = non_match[0]
        assert first["length"] < 64, f"expected a sub-block-sized diff region, got length={first['length']}"

    def test_identical_large_buffers_report_identical(self) -> None:
        """Verify the anchored path preserves the identical-files fast path."""
        size = _ANCHOR_THRESHOLD + 256
        data = bytes(((idx * 13 + 1) & 0xFF) for idx in range(size))
        result: dict[str, Any] = hexcore_mod.diff_bytes(data, data)
        assert result["files_identical"] is True
        assert result["total_differences"] == 0


_TEMPLATE_WITH_BAD_POINTER = json.dumps({
    "name": "AuditPtrBad",
    "description": "Pointer to a struct that references a missing field.",
    "default_endianness": "little",
    "fields": [
        {
            "name": "ptr",
            "field_type": {
                "type": "Pointer",
                "params": {
                    "pointer_type": {"type": "UInt32"},
                    "target_template": "AuditPtrTarget",
                },
            },
            "description": "Pointer field whose target struct is faulty.",
        },
    ],
})

_TEMPLATE_BAD_TARGET = json.dumps({
    "name": "AuditPtrTarget",
    "description": "Computes against a field that does not exist.",
    "default_endianness": "little",
    "fields": [
        {
            "name": "broken",
            "field_type": {
                "type": "Computed",
                "params": {
                    "expression": "missing_field + 1",
                    "display_type": {"type": "UInt32"},
                },
            },
            "description": "References missing_field, must error.",
        },
    ],
})


class TestF0004PointerErrorPropagation:
    """F-0004: ``eval_pointer`` must propagate inner template errors."""

    def test_pointer_target_error_propagates(self) -> None:
        """Verify a Pointer field surfaces InvalidFieldReference upward.

        The audit removed the ``unwrap_or_default()`` that previously
        absorbed the inner error, so applying the outer template now
        raises ``ValueError`` carrying the original message.
        """
        doc = hexcore_mod.HexDocument.open_bytes(b"\x08\x00\x00\x00" + b"\x00" * 28)
        doc.register_json_template(_TEMPLATE_BAD_TARGET)
        doc.register_json_template(_TEMPLATE_WITH_BAD_POINTER)
        with pytest.raises(ValueError, match="missing_field"):
            doc.apply_template("AuditPtrBad", 0)


_TEMPLATE_SIZEOF_BAD = json.dumps({
    "name": "AuditSizeofBad",
    "description": "Uses sizeof of an unknown type in a computed field.",
    "default_endianness": "little",
    "fields": [
        {
            "name": "anchor",
            "field_type": {"type": "UInt32"},
            "description": "Anchor field for layout.",
        },
        {
            "name": "computed",
            "field_type": {
                "type": "Computed",
                "params": {
                    "expression": "sizeof(uint128) + anchor",
                    "display_type": {"type": "UInt32"},
                },
            },
            "description": "Computed field referencing unknown type.",
        },
    ],
})


_TEMPLATE_SIZEOF_OK = json.dumps({
    "name": "AuditSizeofOk",
    "description": "Resolves sizeof against a primitive type name.",
    "default_endianness": "little",
    "fields": [
        {
            "name": "anchor",
            "field_type": {"type": "UInt32"},
            "description": "Anchor field for layout.",
        },
        {
            "name": "computed",
            "field_type": {
                "type": "Computed",
                "params": {
                    "expression": "sizeof(uint16) + anchor",
                    "display_type": {"type": "UInt32"},
                },
            },
            "description": "Computed via sizeof of a primitive.",
        },
    ],
})


class TestF0005SizeofUnknownType:
    """F-0005: ``sizeof()`` of an unknown name must raise ``UnknownType``."""

    def test_sizeof_unknown_type_raises_value_error(self) -> None:
        """Verify ``sizeof(<unknown>)`` errors instead of silently producing 0."""
        doc = hexcore_mod.HexDocument.open_bytes(b"\x05\x00\x00\x00" + b"\x00" * 28)
        doc.register_json_template(_TEMPLATE_SIZEOF_BAD)
        with pytest.raises(ValueError, match="uint128"):
            doc.apply_template("AuditSizeofBad", 0)

    def test_sizeof_primitive_still_resolves(self) -> None:
        """Verify primitive types continue to resolve in ``sizeof``."""
        doc = hexcore_mod.HexDocument.open_bytes(b"\x05\x00\x00\x00" + b"\x00" * 28)
        doc.register_json_template(_TEMPLATE_SIZEOF_OK)
        parsed: list[dict[str, Any]] = doc.apply_template("AuditSizeofOk", 0)
        names = [field["name"] for field in parsed]
        assert "anchor" in names
        assert "computed" in names
        computed = next(field for field in parsed if field["name"] == "computed")
        assert "7" in computed["display_value"], f"expected computed display to include 7 (=2+5), got {computed['display_value']}"
