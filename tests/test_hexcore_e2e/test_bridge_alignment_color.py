# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge alignment grid snapping and color mode operations."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


hexcore_mod: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


def _run(coro: Coroutine[object, object, object]) -> object:
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


class TestSnapToAlignment:
    """Tests for cursor alignment snapping."""

    def test_snap_to_alignment_512(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify snapping cursor at 1000 to 512-byte alignment returns 512.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "align.bin"
        f.write_bytes(b"\x00" * 4096)
        _run(bridge.open_file(str(f)))
        _run(bridge.goto_offset(1000))
        result = cast(int, _run(bridge.snap_to_alignment(512)))
        assert result == 512

    def test_snap_to_alignment_4096(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify snapping cursor at 5000 to 4096-byte alignment returns 4096.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "align2.bin"
        f.write_bytes(b"\x00" * 8192)
        _run(bridge.open_file(str(f)))
        _run(bridge.goto_offset(5000))
        result = cast(int, _run(bridge.snap_to_alignment(4096)))
        assert result == 4096

    def test_snap_at_boundary_unchanged(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify snapping cursor already at a boundary returns the same offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "align3.bin"
        f.write_bytes(b"\x00" * 4096)
        _run(bridge.open_file(str(f)))
        _run(bridge.goto_offset(1024))
        result = cast(int, _run(bridge.snap_to_alignment(512)))
        assert result == 1024

    def test_snap_at_zero(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify snapping cursor at 0 returns 0.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "align4.bin"
        f.write_bytes(b"\x00" * 4096)
        _run(bridge.open_file(str(f)))
        _run(bridge.goto_offset(0))
        result = cast(int, _run(bridge.snap_to_alignment(512)))
        assert result == 0


class TestAlignmentGrid:
    """Tests for setting the alignment grid size."""

    def test_set_alignment_grid(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify setting alignment grid returns True.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "grid.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = cast(bool, _run(bridge.set_alignment_grid(4096)))
        assert result is True


class TestColorMode:
    """Tests for byte color-mapping mode get/set."""

    def test_set_color_mode(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify setting color mode to entropy returns True.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "color.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = cast(bool, _run(bridge.set_color_mode("entropy")))
        assert result is True

    def test_get_color_mode_default(self, bridge: HexEditorBridge) -> None:
        """Verify default color mode is none.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result = cast(str, _run(bridge.get_color_mode()))
        assert result == "none"

    def test_color_mode_roundtrip(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify setting then getting color mode returns the set value.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "color_rt.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_color_mode("byte_value"))
        result = cast(str, _run(bridge.get_color_mode()))
        assert result == "byte_value"

    def test_all_color_modes_accepted(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify all valid color modes are accepted without error.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "color_all.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        modes = ["none", "entropy", "byte_value", "template", "content_type"]
        for mode in modes:
            result = cast(bool, _run(bridge.set_color_mode(mode)))
            assert result is True
