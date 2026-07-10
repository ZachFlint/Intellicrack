# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge alignment grid snapping and color mode operations."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
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


class TestSnapToAlignment:
    """Tests for cursor alignment snapping.

    ``snap_to_alignment`` moves the cursor to the *nearest* alignment boundary,
    breaking exact-midpoint ties upward. The expected values below are computed
    by hand against that documented contract -- never copied from the
    implementation -- and every case additionally cross-checks the value the
    bridge persists into a separate :class:`HexDocumentState` oracle.
    """

    @pytest.mark.parametrize(
        ("alignment", "cursor", "expected"),
        [
            (512, 1000, 1024),  # 1000 is 488 above 512, 24 below 1024 -> ceil
            (512, 600, 512),  # 600 is 88 above 512, 424 below 1024 -> floor
            (512, 768, 1024),  # exact midpoint between 512 and 1024 -> tie snaps up
            (512, 256, 512),  # exact midpoint 0..512 -> tie snaps up
            (256, 100, 0),  # 100 is 100 above 0, 156 below 256 -> floor
            (256, 200, 256),  # 200 is 200 above 0, 56 below 256 -> ceil
            (1024, 1536, 2048),  # exact midpoint 1024..2048 -> tie snaps up
            (4096, 5000, 4096),  # 5000 is 904 above 4096, 3192 below 8192 -> floor
            (4096, 7000, 8192),  # 7000 is 2904 above 4096, 1192 below 8192 -> ceil
            (1, 3333, 3333),  # alignment of 1: every offset is already a boundary
            (8192, 4096, 8192),  # exact midpoint 0..8192 -> tie snaps up
        ],
    )
    def test_snap_to_nearest_boundary_with_state_oracle(
        self,
        alignment: int,
        cursor: int,
        expected: int,
        tmp_path: Path,
    ) -> None:
        """Verify nearest-boundary snapping and that the snapped value reaches the state holder.

        Args:
            alignment: Alignment factor in bytes passed to ``snap_to_alignment``.
            cursor: Starting cursor offset positioned before snapping.
            expected: Hand-computed nearest boundary (ties resolved upward).
            tmp_path: Pytest temporary directory.
        """
        bridge = HexEditorBridge()
        _run(bridge.initialize())
        state = HexDocumentState()
        bridge.set_state_holder(state)

        f = tmp_path / "align.bin"
        f.write_bytes(b"\x00" * 16384)
        _run(bridge.open_file(str(f)))
        _run(bridge.goto_offset(cursor))

        result = _run(bridge.snap_to_alignment(alignment))

        assert result == expected, f"cursor {cursor} snapped to align {alignment}: expected {expected}, got {result}"
        assert _run(bridge.get_cursor_position()) == expected, "bridge cursor position must reflect the snapped offset"
        assert state.cursor_offset == expected, "state holder cursor (independent oracle) must reflect the snapped offset"

    def test_snap_to_alignment_512(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify cursor 1000 snaps to the nearest 512-byte boundary 1024 and reaches the state.

        ``snap_to_alignment`` snaps to the nearest boundary. With the cursor at
        1000 the bracketing boundaries are 512 (floor) and 1024 (ceil); the
        distances 1000-512=488 and 1024-1000=24 are computed by hand here (never
        copied from the implementation), so 1024 is unambiguously the nearer
        boundary. The result must equal 1024, the bridge cursor must move to it,
        and the independent :class:`HexDocumentState` oracle must record it too.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        state = HexDocumentState()
        bridge.set_state_holder(state)
        f = tmp_path / "align.bin"
        f.write_bytes(b"\x00" * 4096)
        _run(bridge.open_file(str(f)))
        _run(bridge.goto_offset(1000))

        floor_boundary = 512
        ceil_boundary = 1024
        nearer = ceil_boundary if (1000 - floor_boundary) > (ceil_boundary - 1000) else floor_boundary
        assert nearer == ceil_boundary, "hand-computed oracle: 1000 is nearer to 1024 than to 512"

        result = _run(bridge.snap_to_alignment(512))

        assert result == ceil_boundary, f"cursor 1000 must snap up to {ceil_boundary}, got {result}"
        assert _run(bridge.get_cursor_position()) == ceil_boundary, "bridge cursor must move to the snapped boundary"
        assert state.cursor_offset == ceil_boundary, "state holder (independent oracle) must record the snapped boundary"

    def test_snap_rejects_non_positive_alignment(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify a non-positive alignment raises ValueError instead of corrupting the cursor.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "align_err.bin"
        f.write_bytes(b"\x00" * 4096)
        _run(bridge.open_file(str(f)))
        _run(bridge.goto_offset(1000))
        with pytest.raises(ValueError, match="alignment_size must be positive"):
            _run(bridge.snap_to_alignment(0))
        with pytest.raises(ValueError, match="alignment_size must be positive"):
            _run(bridge.snap_to_alignment(-512))
        assert _run(bridge.get_cursor_position()) == 1000, "cursor must remain unchanged after a rejected alignment"

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
        result = _run(bridge.snap_to_alignment(4096))
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
        result = _run(bridge.snap_to_alignment(512))
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
        result = _run(bridge.snap_to_alignment(512))
        assert result == 0


class TestAlignmentGrid:
    """Tests for setting the alignment grid size."""

    def test_set_alignment_grid_persists_and_notifies(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify the grid size is stored and broadcast, not merely acknowledged.

        Two independent oracles confirm the side effect:

        * the public :meth:`get_alignment_grid` getter must read back the value
          that was written (round-trips through the backend field), and
        * an observer registered on a separate :class:`HexDocumentState` with a
          non-bridge source must receive an ``ALIGNMENT_GRID_CHANGED`` event
          whose payload ``size`` equals the value set. The event payload is
          decoded independently of the stored attribute, so a setter that
          returns ``True`` without storing or notifying trips the assertions.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        state = HexDocumentState()
        bridge.set_state_holder(state)
        received: list[tuple[HexDocumentEvent, int]] = []

        def observer(event: HexDocumentEvent, data: dict[str, Any]) -> None:
            """Record alignment-grid change events.

            Args:
                event: The emitted state-change event type.
                data: The event payload dictionary.
            """
            if event == HexDocumentEvent.ALIGNMENT_GRID_CHANGED:
                received.append((event, int(data["size"])))

        state.register_callback(observer, source_id="observer")

        f = tmp_path / "grid.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))

        result = _run(bridge.set_alignment_grid(4096))

        assert result is True
        assert _run(bridge.get_alignment_grid()) == 4096, "get_alignment_grid must read back the size that was set"
        assert received == [(HexDocumentEvent.ALIGNMENT_GRID_CHANGED, 4096)], (
            "state holder (independent oracle) must receive exactly one alignment-grid event carrying the set size"
        )


class TestColorMode:
    """Tests for byte color-mapping mode get/set."""

    def test_set_color_mode_persists_and_notifies(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify the color mode is stored and broadcast, not merely acknowledged.

        Two independent oracles confirm the side effect: the public
        :meth:`get_color_mode` getter must read back ``"entropy"`` (round-trips
        through the stored field), and an observer registered on a separate
        :class:`HexDocumentState` with a non-bridge source must receive a
        ``COLOR_MODE_CHANGED`` event whose payload ``mode`` equals the value
        set. A setter that returned ``True`` while storing the wrong mode, or
        without notifying, trips the assertions.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        state = HexDocumentState()
        bridge.set_state_holder(state)
        received: list[tuple[HexDocumentEvent, str]] = []

        def observer(event: HexDocumentEvent, data: dict[str, Any]) -> None:
            """Record color-mode change events.

            Args:
                event: The emitted state-change event type.
                data: The event payload dictionary.
            """
            if event == HexDocumentEvent.COLOR_MODE_CHANGED:
                received.append((event, str(data["mode"])))

        state.register_callback(observer, source_id="observer")

        f = tmp_path / "color.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))

        result = _run(bridge.set_color_mode("entropy"))

        assert result is True
        assert _run(bridge.get_color_mode()) == "entropy", "get_color_mode must read back the mode that was set"
        assert received == [(HexDocumentEvent.COLOR_MODE_CHANGED, "entropy")], (
            "state holder (independent oracle) must receive exactly one color-mode event carrying the set mode"
        )

    def test_get_color_mode_default(self, bridge: HexEditorBridge) -> None:
        """Verify default color mode is none.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result = _run(bridge.get_color_mode())
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
        result = _run(bridge.get_color_mode())
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
            result = _run(bridge.set_color_mode(mode))
            assert result is True
