# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression test for finding M9: float numeric search must not truncate to int.

Pre-fix, ``execute_numeric_search`` always routed native searches through
``search_numeric(int(min_val), ...)``. A Float search for ``1.5`` was therefore
coerced to ``int(1.5) == 1`` and matched the integer bit pattern ``01 00 00 00``
rather than the IEEE-754 f32 bytes of ``1.5`` (``00 00 C0 3F``). This test builds
a real ``HexDocument`` containing both byte patterns and asserts that a float
search finds the IEEE-754 location and does *not* match the integer-1 location.
"""

from __future__ import annotations

import struct
from typing import Any, Final

import pytest

from intellicrack.ui.panels.hex_editor.search import execute_numeric_search


_INT_ONE_OFFSET: Final[int] = 0
_FLOAT_ONE_HALF_OFFSET: Final[int] = 16
_F32_WIDTH: Final[int] = 4
_ALIGNMENT: Final[int] = 1
_MAX_RESULTS: Final[int] = 100
_SEARCH_VALUE: Final[float] = 1.5


def _build_doc() -> object:
    """Build a 64-byte ``HexDocument`` holding int-1 and float-1.5 byte patterns.

    Returns:
        object: A native ``HexDocument`` with ``01 00 00 00`` at offset 0 and the
            little-endian f32 bytes of ``1.5`` at offset 16.
    """
    hexcore_mod: Any = pytest.importorskip(
        "intellicrack_hexcore",
        reason="intellicrack_hexcore native module not built",
    )
    data = bytearray(64)
    data[_INT_ONE_OFFSET : _INT_ONE_OFFSET + _F32_WIDTH] = struct.pack("<I", 1)
    data[_FLOAT_ONE_HALF_OFFSET : _FLOAT_ONE_HALF_OFFSET + _F32_WIDTH] = struct.pack("<f", _SEARCH_VALUE)
    doc: object = hexcore_mod.HexDocument.open_bytes(bytes(data))
    return doc


def _float_search(document: object) -> list[tuple[int, int]]:
    """Run a single-value 32-bit float search for ``1.5`` on the document.

    Args:
        document: Native ``HexDocument`` to scan.

    Returns:
        list[tuple[int, int]]: ``(offset, byte_width)`` match tuples.
    """
    return execute_numeric_search(
        document,
        _SEARCH_VALUE,
        _SEARCH_VALUE,
        "<f",
        _F32_WIDTH,
        _ALIGNMENT,
        _MAX_RESULTS,
        use_native=True,
        size=_F32_WIDTH,
        signed=False,
        big_endian=False,
        is_range=False,
        is_float=True,
    )


class TestFloatNumericSearch:
    """M9: a Float search must match IEEE-754 bytes, never the truncated integer."""

    @staticmethod
    def test_float_search_finds_ieee754_offset() -> None:
        """Assert the float search locates the offset holding the f32 bytes of 1.5."""
        document = _build_doc()
        offsets = [off for off, _ in _float_search(document)]
        assert _FLOAT_ONE_HALF_OFFSET in offsets, (
            f"float 1.5 search must find the IEEE-754 f32 bytes at offset {_FLOAT_ONE_HALF_OFFSET}, got {offsets}"
        )

    @staticmethod
    def test_float_search_does_not_match_integer_one() -> None:
        """Assert the float search never matches the integer-1 bit pattern (int truncation)."""
        document = _build_doc()
        offsets = [off for off, _ in _float_search(document)]
        assert _INT_ONE_OFFSET not in offsets, (
            f"float 1.5 search must not match the integer-1 pattern at offset {_INT_ONE_OFFSET} (int() truncation path taken), got {offsets}"
        )
