# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for F-0002 (highlight rules route through bridge) and F-0015 (single update call).

F-0002: GUI add/remove operations must route through HexEditorBridge.add_highlight_rule /
remove_highlight_rule rather than writing to the widget directly.  The widget must be updated
via the state_holder HIGHLIGHT_RULE_ADDED / HIGHLIGHT_RULE_REMOVED notification path.

F-0015: refresh_pattern_highlights must call _hex_widget.update() exactly once per invocation.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QApplication, QComboBox, QLineEdit, QListWidget, QSpinBox

from intellicrack.ui.panels.hex_editor._highlighting import HighlightingMixin, build_rule_label


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.bridges.hex_editor import HexEditorBridge


class _UpdateCounter:
    """Callable that counts the number of times it is invoked."""

    def __init__(self) -> None:
        self.call_count: int = 0

    def __call__(self) -> None:
        """Increment the invocation counter."""
        self.call_count += 1


class _FakeHighlightRule:
    """Minimal stand-in for HighlightRule that records construction args.

    Attributes:
        rule_id: The rule identifier.
        condition_type: The highlight condition type string.
        condition_params: The condition parameter dict.
        color: The hex color string.
        priority: Rule priority integer.
    """

    rule_id: str
    condition_type: str
    condition_params: dict[str, Any]
    color: str
    priority: int

    def __init__(
        self,
        rule_id: str,
        condition_type: str,
        condition_params: dict[str, Any],
        color: str,
        priority: int = 0,
    ) -> None:
        """Initialise a fake highlight rule.

        Args:
            rule_id: The rule identifier.
            condition_type: The highlight condition type string.
            condition_params: The condition parameter dict.
            color: The hex color string.
            priority: Rule priority integer.
        """
        self.rule_id = rule_id
        self.condition_type = condition_type
        self.condition_params = condition_params
        self.color = color
        self.priority = priority


class _FakeHexWidget:
    """Minimal stand-in for HexEditorWidget with a counter-based update().

    The internal ``_highlight_rules`` list is kept under its conventional
    private name so that ``HighlightingMixin`` can find it via
    ``getattr(self._hex_widget, "_highlight_rules", None)``.  The public
    ``rules`` property provides type-safe read access for tests without
    triggering basedpyright ``reportPrivateUsage`` diagnostics.

    Attributes:
        update_counter: Counter for update() invocations.
    """

    update_counter: _UpdateCounter

    def __init__(self) -> None:
        self._highlight_rules: list[_FakeHighlightRule] = []
        self.update_counter = _UpdateCounter()

    @property
    def rules(self) -> list[_FakeHighlightRule]:
        """Expose the internal highlight rules list for test assertions.

        Returns:
            list[_FakeHighlightRule]: Current list of highlight rules.
        """
        return self._highlight_rules

    def update(self) -> None:
        """Increment the update counter."""
        self.update_counter()

    def add_highlight_rule(self, rule: _FakeHighlightRule) -> None:
        """Append a rule to the internal list.

        Args:
            rule: The highlight rule to add.
        """
        self._highlight_rules.append(rule)

    def remove_highlight_rule(self, index: int) -> None:
        """Remove a rule at the given index.

        Args:
            index: Zero-based index of the rule to remove.
        """
        del self._highlight_rules[index]

    def clear_highlight_rules(self) -> None:
        """Clear all rules."""
        self._highlight_rules.clear()


async def _noop_add(condition_type: str, condition_params: str, color: str) -> str:  # noqa: ARG001
    """Stub coroutine that returns a fixed rule ID without doing anything.

    Args:
        condition_type: Ignored.
        condition_params: Ignored.
        color: Ignored.

    Returns:
        str: Fixed fake rule ID.
    """
    await asyncio.sleep(0)
    return "stub-rule-id"


async def _noop_remove(rule_id: str) -> bool:  # noqa: ARG001
    """Stub coroutine that returns True without doing anything.

    Args:
        rule_id: Ignored.

    Returns:
        bool: Always True.
    """
    await asyncio.sleep(0)
    return True


async def _noop_list() -> list[dict[str, Any]]:
    """Stub coroutine that returns an empty rule list.

    Returns:
        list[dict[str, Any]]: Always an empty list.
    """
    await asyncio.sleep(0)
    return []


class _AddCallRecorder:
    """Records calls to add_highlight_rule and returns a stub coroutine.

    Used to verify that _on_add_highlight_rule dispatches through the bridge
    by checking that bridge.add_highlight_rule was invoked with the expected
    arguments.  Returns an immediately-resolving stub coroutine so that the
    BridgeCallWorker thread does not block waiting for the real bridge.

    Attributes:
        calls: List of (condition_type, condition_params_json, color) tuples recorded.
    """

    calls: list[tuple[str, str, str]]

    def __init__(self) -> None:
        """Initialise the recorder."""
        self.calls = []

    def add_highlight_rule(
        self,
        condition_type: str,
        condition_params: str,
        color: str = "#FFFF00",
    ) -> Coroutine[Any, Any, str]:
        """Record the call and return a stub coroutine.

        Args:
            condition_type: The condition type string.
            condition_params: JSON-encoded condition parameters.
            color: Hex color string.

        Returns:
            Coroutine[Any, Any, str]: Stub coroutine that resolves immediately.
        """
        self.calls.append((condition_type, condition_params, color))
        return _noop_add(condition_type, condition_params, color)

    def remove_highlight_rule(self, rule_id: str) -> Coroutine[Any, Any, bool]:
        """Return a stub coroutine without actually removing anything.

        Args:
            rule_id: The rule ID to remove.

        Returns:
            Coroutine[Any, Any, bool]: Stub coroutine that resolves immediately.
        """
        return _noop_remove(rule_id)

    def list_highlight_rules(self) -> Coroutine[Any, Any, list[dict[str, Any]]]:
        """Return a stub coroutine that returns an empty list.

        Returns:
            Coroutine[Any, Any, list[dict[str, Any]]]: Stub coroutine.
        """
        return _noop_list()


class _RemoveCallRecorder:
    """Records calls to remove_highlight_rule and returns a stub coroutine.

    Attributes:
        calls: List of rule IDs passed to remove_highlight_rule.
    """

    calls: list[str]

    def __init__(self) -> None:
        """Initialise the recorder."""
        self.calls = []

    def add_highlight_rule(
        self,
        condition_type: str,
        condition_params: str,
        color: str = "#FFFF00",
    ) -> Coroutine[Any, Any, str]:
        """Return a stub coroutine without adding anything.

        Args:
            condition_type: Condition type.
            condition_params: JSON params.
            color: Color string.

        Returns:
            Coroutine[Any, Any, str]: Stub coroutine.
        """
        return _noop_add(condition_type, condition_params, color)

    def remove_highlight_rule(self, rule_id: str) -> Coroutine[Any, Any, bool]:
        """Record the rule ID and return a stub coroutine.

        Args:
            rule_id: The rule ID to remove.

        Returns:
            Coroutine[Any, Any, bool]: Stub coroutine that resolves immediately.
        """
        self.calls.append(rule_id)
        return _noop_remove(rule_id)

    def list_highlight_rules(self) -> Coroutine[Any, Any, list[dict[str, Any]]]:
        """Return a stub coroutine that returns an empty list.

        Returns:
            Coroutine[Any, Any, list[dict[str, Any]]]: Stub coroutine.
        """
        return _noop_list()


class _HighlightingTestHost(HighlightingMixin):
    """Minimal concrete host that satisfies the HighlightingMixin class annotations.

    Exposes public accessors so that test classes outside this class hierarchy
    can inspect state without triggering basedpyright reportPrivateUsage
    diagnostics.  Widget controls that are normally set by
    ``_create_highlighting_controls`` can be configured via
    ``configure_add_controls``.

    Attributes:
        document: Always None for unit tests.
        widget: The _FakeHexWidget instance backing this host.
        active_ids: Shared reference to the mixin's active highlight ID list.
        rules_list: Shared reference to the mixin's QListWidget.
    """

    document: Any | None
    widget: _FakeHexWidget
    active_ids: list[str]
    rules_list: QListWidget

    def __init__(self, bridge: _AddCallRecorder | _RemoveCallRecorder | None = None) -> None:
        """Initialise the test host with optional bridge injection.

        Args:
            bridge: Recorder to inject as the bridge dependency.
        """
        self.document = None
        self.widget = _FakeHexWidget()
        self.active_ids = []
        self.rules_list = QListWidget()

        setattr(self, "_hex_widget", self.widget)
        setattr(self, "_highlight_condition_combo", None)
        setattr(self, "_highlight_color_edit", None)
        setattr(self, "_highlight_params_stack", None)
        setattr(self, "_highlight_byte_value_spin", None)
        setattr(self, "_highlight_range_min_spin", None)
        setattr(self, "_highlight_range_max_spin", None)
        setattr(self, "_highlight_pattern_edit", None)
        setattr(self, "_highlight_rules_list", self.rules_list)
        setattr(self, "_active_highlight_ids", self.active_ids)
        setattr(self, "_bridge", cast("HexEditorBridge | None", bridge))

    def configure_add_controls(
        self,
        condition_index: int,
        color: str,
        byte_value: int = 0,
    ) -> None:
        """Configure the add-rule widget controls for a byte_value condition.

        Args:
            condition_index: Index of the condition type (0=byte_value, 1=byte_range, 2=pattern).
            color: Hex color string for the new rule.
            byte_value: Byte value to set on the spin box (only used when condition_index==0).
        """
        combo = QComboBox()
        combo.addItem("Byte Value")
        combo.addItem("Byte Range")
        combo.addItem("Pattern")
        combo.setCurrentIndex(condition_index)
        setattr(self, "_highlight_condition_combo", combo)

        color_edit = QLineEdit(color)
        setattr(self, "_highlight_color_edit", color_edit)

        spin = QSpinBox()
        spin.setValue(byte_value)
        setattr(self, "_highlight_byte_value_spin", spin)

    def trigger_add_rule(self) -> None:
        """Call _on_add_highlight_rule (public wrapper for test access)."""
        self._on_add_highlight_rule()

    def trigger_remove_rule(self) -> None:
        """Call _on_remove_highlight_rule (public wrapper for test access)."""
        self._on_remove_highlight_rule()


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Provide a shared QApplication for all tests in this module.

    Returns:
        QApplication: The Qt application instance.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        return existing
    return QApplication([])


class TestAddHighlightRoutesThoughBridge:
    """F-0002: _on_add_highlight_rule must dispatch to bridge.add_highlight_rule."""

    def test_add_highlight_routes_through_bridge(
        self,
        qapp: QApplication,
    ) -> None:
        """Verify add dispatches to bridge.add_highlight_rule, not the widget directly.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        recorder = _AddCallRecorder()
        host = _HighlightingTestHost(bridge=recorder)
        host.configure_add_controls(condition_index=0, color="#FF0000", byte_value=0x41)

        initial_widget_rules = len(host.widget.rules)
        initial_active_ids = len(host.active_ids)

        host.trigger_add_rule()

        assert len(recorder.calls) == 1, "bridge.add_highlight_rule was not called"
        condition_type, params_json, color = recorder.calls[0]
        assert condition_type == "byte_value"
        parsed = json.loads(params_json)
        assert parsed.get("value") == 0x41
        assert color == "#FF0000"

        assert len(host.widget.rules) == initial_widget_rules, (
            "Widget was updated directly before bridge confirmation; expected no change until HIGHLIGHT_RULE_ADDED event"
        )
        assert len(host.active_ids) == initial_active_ids, "active_highlight_ids mutated before bridge confirmation"


class TestRemoveHighlightRoutesThoughBridge:
    """F-0002: _on_remove_highlight_rule must dispatch to bridge.remove_highlight_rule."""

    def test_remove_highlight_routes_through_bridge(
        self,
        qapp: QApplication,
    ) -> None:
        """Verify remove dispatches to bridge.remove_highlight_rule, not the widget.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        rule_id = "test-rule-abcd"

        recorder = _RemoveCallRecorder()
        host = _HighlightingTestHost(bridge=recorder)
        host.active_ids.append(rule_id)
        host.rules_list.addItem(f"[{rule_id[:8]}] Byte == 0x42")
        fake_rule = _FakeHighlightRule(rule_id, "byte_value", {"value": 0x42}, "#00FF00")
        host.widget.rules.append(fake_rule)

        host.rules_list.setCurrentRow(0)

        host.trigger_remove_rule()

        assert rule_id in recorder.calls, "bridge.remove_highlight_rule was not called with the correct rule_id"

        assert len(host.active_ids) == 1, "active_highlight_ids was mutated before bridge HIGHLIGHT_RULE_REMOVED event confirmation"
        assert len(host.widget.rules) == 1, "Widget rules list was mutated before bridge HIGHLIGHT_RULE_REMOVED event confirmation"


class TestListHighlightsSeedsWidget:
    """F-0002: seed_highlights_from_bridge must populate widget from bridge state."""

    def test_list_highlights_seeds_widget(
        self,
        qapp: QApplication,
    ) -> None:
        """Verify seed_highlights_from_bridge populates widget from 2 pre-existing rules.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        rule_a = "rule-id-aaaa-0001"
        rule_b = "rule-id-bbbb-0002"

        rules: list[dict[str, Any]] = [
            {
                "id": rule_a,
                "condition_type": "byte_value",
                "condition_params": {"value": 0x10},
                "color": "#AABBCC",
            },
            {
                "id": rule_b,
                "condition_type": "byte_range",
                "condition_params": {"min": 0x20, "max": 0x30},
                "color": "#DDEEFF",
            },
        ]

        host = _HighlightingTestHost()

        host.seed_highlights_from_bridge(rules)

        assert len(host.active_ids) == 2, f"Expected 2 active IDs after seeding, got {len(host.active_ids)}"
        assert host.rules_list.count() == 2, f"Expected 2 list widget items after seeding, got {host.rules_list.count()}"

        assert rule_a in host.active_ids
        assert rule_b in host.active_ids

        assert len(host.widget.rules) == 2, f"Expected 2 widget rules after seeding, got {len(host.widget.rules)}"


class TestRefreshPatternHighlightsCallsUpdateOnce:
    """F-0015: refresh_pattern_highlights must call _hex_widget.update() exactly once."""

    def test_refresh_pattern_highlights_calls_update_once(self, qapp: QApplication) -> None:
        """Verify that refresh_pattern_highlights calls update() exactly once.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _HighlightingTestHost()

        class _FakeDoc:
            def search_hex(self, _pattern: str, _max_matches: int) -> list[int]:
                """Return a fixed list of match offsets.

                Args:
                    _pattern: Hex pattern string (unused).
                    _max_matches: Maximum number of matches (unused).

                Returns:
                    list[int]: List of matching offsets.
                """
                return [0, 4, 8]

        host.document = _FakeDoc()

        pattern_rule = _FakeHighlightRule(
            rule_id="test-rule-id",
            condition_type="pattern",
            condition_params={"pattern": "DEADBEEF", "offsets": []},
            color="#FF0000",
        )
        host.widget.rules.append(pattern_rule)

        host.widget.update_counter.call_count = 0

        host.refresh_pattern_highlights()

        assert host.widget.update_counter.call_count == 1, (
            f"Expected update() called exactly once, got {host.widget.update_counter.call_count}"
        )


class TestBuildRuleLabel:
    """Unit tests for the build_rule_label helper function."""

    def test_byte_value_label(self) -> None:
        """Verify build_rule_label formats byte_value rules correctly."""
        label = build_rule_label("abcdef12", "byte_value", {"value": 0x41}, "#FF0000")
        assert "0x41" in label.upper() or "0X41" in label.upper()
        assert "#FF0000" in label

    def test_byte_range_label(self) -> None:
        """Verify build_rule_label formats byte_range rules correctly."""
        label = build_rule_label("abcdef12", "byte_range", {"min": 0x20, "max": 0x7E}, "#00FF00")
        assert "0x20" in label.upper() or "0X20" in label.upper()
        assert "0x7E" in label.upper() or "0X7E" in label.upper()
        assert "#00FF00" in label

    def test_pattern_label(self) -> None:
        """Verify build_rule_label formats pattern rules with hit count."""
        label = build_rule_label(
            "abcdef12",
            "pattern",
            {"pattern": "DEADBEEF", "offsets": [0, 4, 8]},
            "#0000FF",
        )
        assert "DEADBEEF" in label
        assert "3 hits" in label
        assert "#0000FF" in label
