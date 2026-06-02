# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge display mode and highlight rule management.

These tests drive the real :class:`HexEditorBridge` together with the real
:class:`HexDocumentState` orchestration holder. The state holder is a separate
component with its own storage, so it serves as an independent oracle: after the
bridge accepts a display mode or highlight rule, the value the bridge propagated
into the state holder (and the payload it emitted to a registered observer
callback) is compared against the exact value the caller supplied. A bridge that
silently dropped, mangled, or fabricated values would fail these assertions even
though its own return value looks healthy.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.bridges.hex_editor import HexEditorBridge


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


class _EventRecorder:
    """Independent observer that captures bridge-emitted state events.

    Registered with the real :class:`HexDocumentState` under an empty source id
    so that every event the bridge emits with ``source="bridge"`` is delivered.
    Records the exact event payloads, giving the test an oracle for what the
    bridge surfaced to the orchestration layer.
    """

    def __init__(self) -> None:
        """Initialize empty per-event payload lists."""
        self.display_modes: list[str] = []
        self.added_rules: list[dict[str, Any]] = []
        self.removed_rule_ids: list[str] = []

    def __call__(self, event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
        """Record a single state-change notification.

        Args:
            event_type: The event type emitted by the state holder.
            data: The event payload dictionary.
        """
        if event_type is HexDocumentEvent.DISPLAY_MODE_CHANGED:
            self.display_modes.append(str(data["mode"]))
        elif event_type is HexDocumentEvent.HIGHLIGHT_RULE_ADDED:
            self.added_rules.append(dict(data["rule"]))
        elif event_type is HexDocumentEvent.HIGHLIGHT_RULE_REMOVED:
            self.removed_rule_ids.append(str(data["rule_id"]))


def _attach_state(bridge: HexEditorBridge) -> tuple[HexDocumentState, _EventRecorder]:
    """Attach a real state holder and observer to the bridge.

    Args:
        bridge: An initialized HexEditorBridge.

    Returns:
        tuple[HexDocumentState, _EventRecorder]: The attached state holder and
            the registered event recorder, in that order.
    """
    state = HexDocumentState()
    recorder = _EventRecorder()
    state.register_callback(recorder, source_id="observer")
    bridge.set_state_holder(state)
    return state, recorder


class TestBridgeDisplayMode:
    """Tests covering display mode get and set operations."""

    def test_default_mode_is_hex8_and_matches_state_holder(self, bridge: HexEditorBridge) -> None:
        """The default mode is ``hex8`` and a freshly attached state holder agrees.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state, _ = _attach_state(bridge)
        assert _run(bridge.get_display_mode()) == "hex8"
        assert state.get_display_mode() == "hex8"

    def test_set_mode_propagates_exact_value_to_state_and_observer(self, bridge: HexEditorBridge) -> None:
        """Setting a mode round-trips and lands verbatim in state and observer payload.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state, recorder = _attach_state(bridge)

        accepted: bool = _run(bridge.set_display_mode("hex16_le"))

        assert accepted is True
        assert _run(bridge.get_display_mode()) == "hex16_le"
        assert state.get_display_mode() == "hex16_le"
        assert recorder.display_modes == ["hex16_le"]

    def test_sequential_modes_persist_until_next_change(self, bridge: HexEditorBridge) -> None:
        """Each set mode persists exactly until the next set, across the full enum sample.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state, recorder = _attach_state(bridge)
        sequence: list[str] = ["hex16_le", "float32", "binary", "dec_u32", "rgba8", "hexii"]

        for mode in sequence:
            accepted: bool = _run(bridge.set_display_mode(mode))
            assert accepted is True
            assert _run(bridge.get_display_mode()) == mode
            assert state.get_display_mode() == mode

        assert recorder.display_modes == sequence

    def test_invalid_mode_raises_value_error_and_does_not_mutate_state(self, bridge: HexEditorBridge) -> None:
        """An unknown mode raises ValueError and leaves the prior mode intact.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state, recorder = _attach_state(bridge)
        _run(bridge.set_display_mode("float64"))

        with pytest.raises(ValueError, match="unknown display mode"):
            _run(bridge.set_display_mode("not_a_real_mode"))

        assert _run(bridge.get_display_mode()) == "float64"
        assert state.get_display_mode() == "float64"
        assert recorder.display_modes == ["float64"]

    def test_empty_mode_string_rejected(self, bridge: HexEditorBridge) -> None:
        """The empty string is not a valid display mode and is rejected.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _attach_state(bridge)

        with pytest.raises(ValueError, match="unknown display mode"):
            _run(bridge.set_display_mode(""))

        assert _run(bridge.get_display_mode()) == "hex8"


class TestBridgeHighlights:
    """Tests covering highlight rule add, list, and remove operations."""

    def test_list_highlight_rules_empty_on_fresh_bridge(self, bridge: HexEditorBridge) -> None:
        """A fresh bridge starts with no highlight rules.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        assert rules == []

    def test_added_rule_preserves_all_properties_in_list(self, bridge: HexEditorBridge) -> None:
        """A retrieved rule carries the exact condition type, params, color, and id.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        rule_id: str = _run(
            bridge.add_highlight_rule(
                "byte_value",
                json.dumps({"value": 255}),
                "#00FF00",
            ),
        )

        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        matching = [r for r in rules if r["id"] == rule_id]
        assert len(matching) == 1
        rule = matching[0]
        assert rule == {
            "id": rule_id,
            "condition_type": "byte_value",
            "condition_params": {"value": 255},
            "color": "#00FF00",
        }

    def test_added_rule_propagates_full_object_to_state_and_observer(self, bridge: HexEditorBridge) -> None:
        """The rule the bridge stores in the state holder and emits matches verbatim.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state, recorder = _attach_state(bridge)

        rule_id: str = _run(
            bridge.add_highlight_rule(
                "byte_range",
                json.dumps({"min": 16, "max": 240}),
                "#0000FF",
            ),
        )

        expected_rule: dict[str, Any] = {
            "id": rule_id,
            "condition_type": "byte_range",
            "condition_params": {"min": 16, "max": 240},
            "color": "#0000FF",
        }
        assert state.get_highlight_rules() == {rule_id: expected_rule}
        assert recorder.added_rules == [expected_rule]

    def test_distinct_rules_get_distinct_uuid_ids_and_coexist(self, bridge: HexEditorBridge) -> None:
        """Two rules receive distinct UUID-shaped ids and both persist with their values.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        first_id: str = _run(bridge.add_highlight_rule("byte_value", json.dumps({"value": 0}), "#FF0000"))
        second_id: str = _run(bridge.add_highlight_rule("byte_value", json.dumps({"value": 1}), "#00FF00"))

        assert first_id != second_id
        assert len(first_id) == 36
        assert first_id.count("-") == 4

        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        by_id = {r["id"]: r for r in rules}
        assert by_id[first_id]["condition_params"] == {"value": 0}
        assert by_id[first_id]["color"] == "#FF0000"
        assert by_id[second_id]["condition_params"] == {"value": 1}
        assert by_id[second_id]["color"] == "#00FF00"

    def test_remove_rule_returns_true_and_purges_from_list_and_state(self, bridge: HexEditorBridge) -> None:
        """Removing a rule returns True and the rule disappears from list and state.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        state, recorder = _attach_state(bridge)
        rule_id: str = _run(bridge.add_highlight_rule("byte_value", json.dumps({"value": 42}), "#FFFF00"))

        removed: bool = _run(bridge.remove_highlight_rule(rule_id))

        assert removed is True
        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        assert all(r["id"] != rule_id for r in rules)
        assert rule_id not in state.get_highlight_rules()
        assert recorder.removed_rule_ids == [rule_id]

    def test_remove_keeps_other_rules_intact(self, bridge: HexEditorBridge) -> None:
        """Removing one rule leaves a second, independent rule fully intact.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        keep_id: str = _run(bridge.add_highlight_rule("byte_value", json.dumps({"value": 7}), "#123456"))
        drop_id: str = _run(bridge.add_highlight_rule("byte_value", json.dumps({"value": 8}), "#654321"))

        assert _run(bridge.remove_highlight_rule(drop_id)) is True

        rules: list[dict[str, Any]] = _run(bridge.list_highlight_rules())
        ids = [r["id"] for r in rules]
        assert ids == [keep_id]
        assert rules[0]["condition_params"] == {"value": 7}
        assert rules[0]["color"] == "#123456"

    def test_remove_unknown_id_returns_false_and_emits_no_event(self, bridge: HexEditorBridge) -> None:
        """Removing an id that was never added returns False and emits no removal event.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        _, recorder = _attach_state(bridge)

        removed: bool = _run(bridge.remove_highlight_rule("00000000-0000-0000-0000-000000000000"))

        assert removed is False
        assert recorder.removed_rule_ids == []
