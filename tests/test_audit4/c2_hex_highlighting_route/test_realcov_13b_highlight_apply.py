# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Strengthened coverage for highlight rule application to the real widget.

The audit (shard 13, c2 trivial findings) flagged that the existing routing
tests only assert that the bridge was *called*: they do not verify the
highlight is actually applied to the widget with the correct colour, priority
ordering, condition parameters, or pattern hit offsets.

These tests close that gap by driving the real
:meth:`HighlightingMixin._apply_bridge_highlight_rule_added` and
:meth:`seed_highlights_from_bridge` event-confirmation path against a genuine
:class:`HexEditorWidget`. They assert the exact ``HighlightRule`` objects the
widget ends up holding (colour, condition params, priority) and that the
list-widget label encodes the right pattern hit count, rather than merely that
a dispatch happened.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QApplication, QListWidget

from intellicrack.ui.panels.hex_editor.highlighting import HighlightingMixin
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget, HighlightRule


if TYPE_CHECKING:
    from intellicrack.bridges.hex_editor import HexEditorBridge


pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Provide a shared QApplication for the highlight application tests.

    Returns:
        QApplication: The Qt application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        return existing
    return QApplication([])


class _RealWidgetHost(HighlightingMixin):
    """Host wiring the mixin to a real HexEditorWidget and list widget.

    Attributes:
        widget: The real hex editor widget receiving highlight rules.
        rules_list: The list widget mirroring the rules for the UI.
        active_ids: Shared reference to the mixin's active highlight ID list.
    """

    widget: HexEditorWidget
    rules_list: QListWidget
    active_ids: list[str]

    def __init__(self) -> None:
        """Wire the mixin attributes to real widgets."""
        self.widget = HexEditorWidget()
        self.rules_list = QListWidget()
        self.active_ids = []
        setattr(self, "document", None)
        setattr(self, "_hex_widget", self.widget)
        setattr(self, "_highlight_rules_list", self.rules_list)
        setattr(self, "_active_highlight_ids", self.active_ids)
        setattr(self, "_bridge", cast("HexEditorBridge | None", None))

    def apply_added(self, rule: dict[str, Any]) -> None:
        """Apply a bridge-confirmed ADD event to the widget.

        Args:
            rule: Bridge rule dict with ``id``, ``condition_type``,
                ``condition_params``, and ``color`` keys.
        """
        self._apply_bridge_highlight_rule_added(rule)

    def widget_rules(self) -> list[HighlightRule]:
        """Return the rules currently held by the real widget.

        Returns:
            list[HighlightRule]: Rules in the widget's internal store.
        """
        return self.widget.get_highlight_rules()

    def list_label(self, row: int) -> str:
        """Return the list widget item text at ``row``.

        Args:
            row: Zero-based row index in the rules list.

        Returns:
            str: The display text of the item at ``row``.
        """
        item = self.rules_list.item(row)
        assert item is not None
        return item.text()


class TestApplyAddedToRealWidget:
    """Bridge-confirmed ADD events must apply real rules to the real widget."""

    def test_byte_value_rule_applied_with_color(self, qapp: QApplication) -> None:
        """Verify a byte_value rule reaches the widget with the right colour/params.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _RealWidgetHost()
        host.apply_added(
            {
                "id": "rule-bv-0001",
                "condition_type": "byte_value",
                "condition_params": {"value": 0x41},
                "color": "#FF0000",
            },
        )
        rules = host.widget_rules()
        assert len(rules) == 1
        applied = rules[0]
        assert applied.rule_id == "rule-bv-0001"
        assert applied.condition_type == "byte_value"
        assert applied.condition_params == {"value": 0x41}
        assert applied.color == "#FF0000"
        label = host.list_label(0)
        assert "rule-bv-" in label
        assert "0X41" in label.upper()

    def test_priority_ordering_reflects_add_order(self, qapp: QApplication) -> None:
        """Verify later-added rules carry higher priority and sort first.

        The mixin assigns ``priority = len(active_ids)`` at apply time, and
        the real widget sorts highest-priority first. Three sequential adds
        must therefore appear in reverse insertion order in the widget.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _RealWidgetHost()
        for index, colour in enumerate(("#111111", "#222222", "#333333")):
            host.apply_added(
                {
                    "id": f"rule-{index}",
                    "condition_type": "byte_value",
                    "condition_params": {"value": index},
                    "color": colour,
                },
            )
        rules = host.widget_rules()
        assert [r.rule_id for r in rules] == ["rule-2", "rule-1", "rule-0"]
        assert [r.priority for r in rules] == [2, 1, 0]
        assert [r.color for r in rules] == ["#333333", "#222222", "#111111"]

    def test_pattern_rule_label_encodes_hit_count(self, qapp: QApplication) -> None:
        """Verify a pattern rule's label reflects the real offset hit count.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _RealWidgetHost()
        host.apply_added(
            {
                "id": "rule-pat-0001",
                "condition_type": "pattern",
                "condition_params": {"pattern": "DEADBEEF", "offsets": [0, 16, 32, 48]},
                "color": "#00FF00",
            },
        )
        rules = host.widget_rules()
        assert len(rules) == 1
        assert rules[0].condition_params["offsets"] == [0, 16, 32, 48]
        label = host.list_label(0)
        assert "DEADBEEF" in label
        assert "4 hits" in label
        assert "#00FF00" in label


class TestSeedFromBridgePopulatesRealWidget:
    """seed_highlights_from_bridge must mirror bridge state into the widget."""

    def test_seed_applies_all_rules_and_is_idempotent(self, qapp: QApplication) -> None:
        """Verify seeding twice produces exactly the seeded rule set, not duplicates.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _RealWidgetHost()
        seed: list[dict[str, Any]] = [
            {
                "id": "seed-a",
                "condition_type": "byte_value",
                "condition_params": {"value": 0x10},
                "color": "#AABBCC",
            },
            {
                "id": "seed-b",
                "condition_type": "byte_range",
                "condition_params": {"min": 0x20, "max": 0x30},
                "color": "#DDEEFF",
            },
        ]
        host.seed_highlights_from_bridge(seed)
        host.seed_highlights_from_bridge(seed)

        rules = host.widget_rules()
        assert len(rules) == 2
        ids = {r.rule_id for r in rules}
        assert ids == {"seed-a", "seed-b"}
        colours = {r.rule_id: r.color for r in rules}
        assert colours["seed-a"] == "#AABBCC"
        assert colours["seed-b"] == "#DDEEFF"
        assert host.rules_list.count() == 2
        assert host.active_ids == ["seed-a", "seed-b"]
