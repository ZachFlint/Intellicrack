# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge display mode and highlight rule management."""

from __future__ import annotations

import asyncio
import json
from typing import Any


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


class TestBridgeDisplayMode:
    """Tests covering display mode get and set operations."""

    def test_get_display_mode_returns_hex8_by_default(self, bridge: Any) -> None:
        """Verify that the default display mode is hex8 after initialization.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        mode: str = _run(bridge.get_display_mode())
        assert mode == "hex8"

    def test_set_display_mode_returns_true(self, bridge: Any) -> None:
        """Verify that set_display_mode always returns True.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        result: bool = _run(bridge.set_display_mode("hex16_le"))
        assert result is True

    def test_get_display_mode_returns_new_mode_after_set(self, bridge: Any) -> None:
        """Verify that get_display_mode reflects the mode set by set_display_mode.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("float32"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "float32"

    def test_set_display_mode_binary(self, bridge: Any) -> None:
        """Verify that the binary display mode can be set and retrieved.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("binary"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "binary"

    def test_set_display_mode_dec_u32(self, bridge: Any) -> None:
        """Verify that the dec_u32 display mode can be set and retrieved.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _run(bridge.set_display_mode("dec_u32"))
        mode: str = _run(bridge.get_display_mode())
        assert mode == "dec_u32"


class TestBridgeHighlights:
    """Tests covering highlight rule add, list, and remove operations."""

    def test_add_highlight_rule_returns_nonempty_string_id(
        self, bridge: Any
    ) -> None:
        """Verify that add_highlight_rule returns a non-empty string rule ID.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        rule_id: str = _run(
            bridge.add_highlight_rule(
                "byte_value",
                json.dumps({"value": 0}),
                "#FF0000",
            )
        )
        assert isinstance(rule_id, str)
        assert len(rule_id) > 0

    def test_list_highlight_rules_contains_added_rule(self, bridge: Any) -> None:
        """Verify that list_highlight_rules returns the newly added rule.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        rule_id: str = _run(
            bridge.add_highlight_rule(
                "byte_value",
                json.dumps({"value": 255}),
                "#00FF00",
            )
        )
        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        ids = [r["id"] for r in rules]
        assert rule_id in ids

    def test_remove_highlight_rule_returns_true_for_valid_id(
        self, bridge: Any
    ) -> None:
        """Verify that remove_highlight_rule returns True for an existing rule.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        rule_id: str = _run(
            bridge.add_highlight_rule(
                "byte_range",
                json.dumps({"min": 0, "max": 127}),
                "#0000FF",
            )
        )
        removed: bool = _run(bridge.remove_highlight_rule(rule_id))
        assert removed is True

    def test_remove_highlight_rule_no_longer_in_list(self, bridge: Any) -> None:
        """Verify that a removed rule does not appear in list_highlight_rules.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        rule_id: str = _run(
            bridge.add_highlight_rule(
                "byte_value",
                json.dumps({"value": 42}),
                "#FFFF00",
            )
        )
        _run(bridge.remove_highlight_rule(rule_id))
        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        ids = [r["id"] for r in rules]
        assert rule_id not in ids

    def test_remove_highlight_rule_invalid_id_returns_false(
        self, bridge: Any
    ) -> None:
        """Verify that remove_highlight_rule returns False for an unknown ID.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        removed: bool = _run(
            bridge.remove_highlight_rule("nonexistent-rule-id-00000000")
        )
        assert removed is False

    def test_list_highlight_rules_empty_on_fresh_bridge(
        self, bridge: Any
    ) -> None:
        """Verify that a fresh bridge starts with no highlight rules.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        assert rules == []
