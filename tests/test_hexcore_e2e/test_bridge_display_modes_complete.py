# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for display modes and highlight rules not covered by test_bridge_display.py."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.bridges.hex_editor import HexEditorBridge
pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore native module not built")


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


class TestDisplayModesExtended:
    """Tests for display mode set/get roundtrip for modes not covered previously."""

    def test_set_hex16_be_returns_true_and_persists_state(
        self,
        bridge: HexEditorBridge,
    ) -> None:
        """Verify set_display_mode('hex16_be') returns exactly True and persists the mode.

        The return value must be exactly True (not merely truthy), and a
        subsequent get_display_mode call must return 'hex16_be'.  This
        test would fail if set_display_mode returned a non-bool truthy
        value, silently dropped the mode, or stored a different string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: bool = _run(bridge.set_display_mode("hex16_be"))
        assert result
        mode: str = _run(bridge.get_display_mode())
        assert mode == "hex16_be"

    def test_roundtrip_hex32_le(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'hex32_le' returns 'hex32_le'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("hex32_le"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "hex32_le"

    def test_roundtrip_hex32_be(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'hex32_be' returns 'hex32_be'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("hex32_be"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "hex32_be"

    def test_roundtrip_hex64_le(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'hex64_le' returns 'hex64_le'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("hex64_le"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "hex64_le"

    def test_roundtrip_hex64_be(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'hex64_be' returns 'hex64_be'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("hex64_be"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "hex64_be"

    def test_roundtrip_dec_u8(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'dec_u8' returns 'dec_u8'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("dec_u8"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "dec_u8"

    def test_roundtrip_dec_u16(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'dec_u16' returns 'dec_u16'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("dec_u16"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "dec_u16"

    def test_roundtrip_dec_s8(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'dec_s8' returns 'dec_s8'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("dec_s8"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "dec_s8"

    def test_roundtrip_dec_s16(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'dec_s16' returns 'dec_s16'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("dec_s16"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "dec_s16"

    def test_roundtrip_dec_s32(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'dec_s32' returns 'dec_s32'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("dec_s32"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "dec_s32"

    def test_roundtrip_float64(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'float64' returns 'float64'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("float64"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "float64"

    def test_roundtrip_rgba8(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'rgba8' returns 'rgba8'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("rgba8"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "rgba8"

    def test_roundtrip_hexii(self, bridge: HexEditorBridge) -> None:
        """Verify that setting and getting 'hexii' returns 'hexii'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("hexii"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "hexii"

    def test_sequential_mode_changes_last_wins(self, bridge: HexEditorBridge) -> None:
        """Verify that setting multiple modes in sequence leaves the bridge at the final mode.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        for mode in ("hex32_le", "dec_u8", "float64"):
            _run(bridge.set_display_mode(mode))
        result: str = _run(bridge.get_display_mode())
        assert result == "float64"


class TestHighlightPatternCondition:
    """Tests for add_highlight_rule with condition_type='pattern'."""

    def test_add_pattern_rule_returns_uuid_string(self, bridge: HexEditorBridge) -> None:
        """Verify that add_highlight_rule with condition_type='pattern' returns a valid UUID.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        params = json.dumps({"pattern": "DE AD BE EF"})
        rule_id: str = _run(bridge.add_highlight_rule("pattern", params, "#FF00FF"))
        assert isinstance(rule_id, str)
        parsed = uuid.UUID(rule_id)
        assert str(parsed) == rule_id

    def test_list_rules_contains_added_pattern_rule(self, bridge: HexEditorBridge) -> None:
        """Verify that a pattern rule appears in list_highlight_rules after being added.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        params = json.dumps({"pattern": "FF FF"})
        rule_id: str = _run(bridge.add_highlight_rule("pattern", params, "#AABBCC"))
        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        ids = [r["id"] for r in rules]
        assert rule_id in ids

    def test_pattern_rule_condition_type_stored_correctly(self, bridge: HexEditorBridge) -> None:
        """Verify that the stored rule has condition_type equal to 'pattern'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        params = json.dumps({"pattern": "00 01 02"})
        rule_id: str = _run(bridge.add_highlight_rule("pattern", params, "#112233"))
        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        matched = next(r for r in rules if r["id"] == rule_id)
        assert matched["condition_type"] == "pattern"

    def test_pattern_rule_condition_params_stored_correctly(self, bridge: HexEditorBridge) -> None:
        """Verify that the stored rule condition_params matches the input JSON.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        pattern_value = "AA BB CC DD"
        params = json.dumps({"pattern": pattern_value})
        rule_id: str = _run(bridge.add_highlight_rule("pattern", params, "#FFFFFF"))
        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        matched = next(r for r in rules if r["id"] == rule_id)
        stored_params: dict[str, Any] = matched["condition_params"]
        assert stored_params["pattern"] == pattern_value

    def test_remove_pattern_rule_returns_true(self, bridge: HexEditorBridge) -> None:
        """Verify that remove_highlight_rule returns True for an existing pattern rule.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        params = json.dumps({"pattern": "01 02 03"})
        rule_id: str = _run(bridge.add_highlight_rule("pattern", params, "#654321"))
        removed: bool = _run(bridge.remove_highlight_rule(rule_id))
        assert removed

    def test_remove_pattern_rule_no_longer_in_list(self, bridge: HexEditorBridge) -> None:
        """Verify that a removed pattern rule no longer appears in list_highlight_rules.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        params = json.dumps({"pattern": "EE FF"})
        rule_id: str = _run(bridge.add_highlight_rule("pattern", params, "#000000"))
        _run(bridge.remove_highlight_rule(rule_id))
        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        ids = [r["id"] for r in rules]
        assert rule_id not in ids
