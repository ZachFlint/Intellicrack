# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real end-to-end tests for the hex-editor highlight-rule bridge route.

F-0002: GUI add/remove operations route through the real ``HexEditorBridge``
(``add_highlight_rule`` / ``remove_highlight_rule``) and the real widget is
updated only via the shared ``HexDocumentState`` ``HIGHLIGHT_RULE_ADDED`` /
``HIGHLIGHT_RULE_REMOVED`` notification path -- never written directly.

F-0015: ``refresh_pattern_highlights`` re-resolves pattern offsets against the
real ``intellicrack_hexcore`` document and calls ``_hex_widget.update()`` once.

Every test drives the genuine ``HighlightingMixin`` against a real
``HexEditorWidget``, a real ``QListWidget``, a real ``HexEditorBridge`` and a
real ``HexDocumentState`` wired exactly the way ``HexEditorPanel.set_state_holder``
wires them.  No bridge, widget, document or state-holder behaviour is mocked,
stubbed, or simulated; the bridge coroutines are awaited directly so the
state-holder notification (which the bridge fires synchronously inside the
coroutine body) drives the mixin's widget mutation on the test thread.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QApplication, QComboBox, QLineEdit, QListWidget, QSpinBox

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.panels.hex_editor.highlighting import HighlightingMixin, build_rule_label
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget, HighlightRule


if TYPE_CHECKING:
    import types


pytestmark = pytest.mark.integration


# The compiled HexDocument lives in the ``intellicrack_hexcore.intellicrack_hexcore``
# extension submodule; importing the namespace parent alone does not bind it.
_HEXCORE_SUBMODULE: str = "intellicrack_hexcore.intellicrack_hexcore"
_HEXCORE_AVAILABLE: bool = importlib.util.find_spec("intellicrack_hexcore") is not None


class _UpdateCountingWidget:
    """Repaint-counting delegate wrapping a real :class:`HexEditorWidget`.

    Every highlight-rule operation is forwarded to the genuine
    ``HexEditorWidget`` so production rule storage, priority sorting, and
    per-byte rule matching (``_get_highlight_color``) run unmodified.  The only
    added behaviour is counting the no-argument ``update()`` repaint requests
    the mixin issues, which lets F-0015 assert an exact repaint count without
    overriding a Qt method or patching the operation under test.

    Attributes:
        widget: The wrapped real hex editor widget.
        update_call_count: Number of ``update()`` calls observed.
    """

    widget: HexEditorWidget
    update_call_count: int

    def __init__(self) -> None:
        """Create the wrapper around a fresh real hex editor widget."""
        self.widget = HexEditorWidget()
        self.update_call_count = 0

    @property
    def _highlight_rules(self) -> list[HighlightRule]:
        """Expose the real widget's rules for the mixin's ``getattr`` lookup.

        The list is a fresh container holding the same live ``HighlightRule``
        instances the real widget stores, so the mixin's in-place mutation of a
        rule's ``condition_params`` during a pattern refresh persists on the
        genuine rule objects.

        Returns:
            list[HighlightRule]: Current rules from the real widget.
        """
        return self.widget.get_highlight_rules()

    def update(self) -> None:
        """Count a repaint request and forward it to the real widget."""
        self.update_call_count += 1
        self.widget.update()

    def add_highlight_rule(self, rule: HighlightRule) -> None:
        """Forward a rule add to the real widget.

        Args:
            rule: The highlight rule to add.
        """
        self.widget.add_highlight_rule(rule)

    def remove_highlight_rule(self, rule_id: str) -> bool:
        """Forward a rule removal to the real widget.

        Args:
            rule_id: Identifier of the rule to remove.

        Returns:
            bool: True if the real widget removed a matching rule.
        """
        return self.widget.remove_highlight_rule(rule_id)

    def clear_highlight_rules(self) -> None:
        """Forward a clear-all to the real widget."""
        self.widget.clear_highlight_rules()

    def get_highlight_rules(self) -> list[HighlightRule]:
        """Return the real widget's current rules.

        Returns:
            list[HighlightRule]: Active rules, priority-ordered, from the real widget.
        """
        return self.widget.get_highlight_rules()


class _HighlightingPanelHost(HighlightingMixin):
    """Concrete host wiring the real mixin to real widget, list, bridge, and state.

    Replicates the exact ``HexEditorPanel.set_state_holder`` wiring: the
    state-holder callback (registered with ``source_id="panel"``) routes
    ``HIGHLIGHT_RULE_ADDED`` / ``HIGHLIGHT_RULE_REMOVED`` events to the mixin's
    ``_apply_bridge_highlight_rule_added`` / ``_apply_bridge_highlight_rule_removed``
    handlers, so a bridge add/remove flows through state to the real widget.

    Attributes:
        document: Optional document backing pattern searches (None unless set).
        hex_widget: The real update-counting hex editor widget.
        rules_list: The real :class:`QListWidget` backing the rule sidebar.
        active_ids: Shared reference to the mixin's active-rule-id list.
        bridge: The real :class:`HexEditorBridge` driving rule lifecycle.
        state: The real :class:`HexDocumentState` relaying bridge events.
    """

    document: Any | None
    hex_widget: _UpdateCountingWidget
    rules_list: QListWidget
    active_ids: list[str]
    bridge: HexEditorBridge
    state: HexDocumentState

    def __init__(self) -> None:
        """Build the host and wire bridge, state holder, and event callback."""
        self.document = None
        self.hex_widget = _UpdateCountingWidget()
        self.rules_list = QListWidget()
        self.active_ids = []
        self.bridge = HexEditorBridge()
        self.state = HexDocumentState()

        setattr(self, "_hex_widget", self.hex_widget)
        setattr(self, "_highlight_condition_combo", None)
        setattr(self, "_highlight_color_edit", None)
        setattr(self, "_highlight_params_stack", None)
        setattr(self, "_highlight_byte_value_spin", None)
        setattr(self, "_highlight_range_min_spin", None)
        setattr(self, "_highlight_range_max_spin", None)
        setattr(self, "_highlight_pattern_edit", None)
        setattr(self, "_highlight_rules_list", self.rules_list)
        setattr(self, "_active_highlight_ids", self.active_ids)
        setattr(self, "_bridge", self.bridge)

        self.bridge.set_state_holder(self.state)
        self.state.register_callback(self.route_state_event, source_id="panel")

    def route_state_event(self, event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
        """Route highlight state events to the mixin apply handlers.

        Mirrors the production ``HexEditorPanel.set_state_holder`` callback so
        the full bridge -> state-holder -> widget confirmation path is exercised.

        Args:
            event_type: The hex-document event type emitted by the state holder.
            data: Event payload dictionary.
        """
        if event_type == HexDocumentEvent.HIGHLIGHT_RULE_ADDED:
            rule = data.get("rule")
            if isinstance(rule, dict):
                self._apply_bridge_highlight_rule_added(cast("dict[str, Any]", rule))
        elif event_type == HexDocumentEvent.HIGHLIGHT_RULE_REMOVED:
            rule_id = data.get("rule_id")
            if isinstance(rule_id, str):
                self._apply_bridge_highlight_rule_removed(rule_id)

    def configure_byte_value_controls(self, color: str, byte_value: int) -> None:
        """Configure the add-rule controls for a ``byte_value`` rule.

        Args:
            color: Hex color string for the new rule.
            byte_value: Byte value (0-255) to place in the spin box.
        """
        combo = QComboBox()
        combo.addItems(["Byte Value", "Byte Range", "Pattern"])
        combo.setCurrentIndex(0)
        setattr(self, "_highlight_condition_combo", combo)

        setattr(self, "_highlight_color_edit", QLineEdit(color))

        spin = QSpinBox()
        spin.setRange(0, 255)
        spin.setValue(byte_value)
        setattr(self, "_highlight_byte_value_spin", spin)

    def trigger_add_rule(self) -> None:
        """Invoke the production add-rule slot (public wrapper for test access)."""
        self._on_add_highlight_rule()

    def widget_rules(self) -> list[HighlightRule]:
        """Return the real widget's current highlight rules.

        Returns:
            list[HighlightRule]: Rules held by the real widget, priority-ordered.
        """
        return self.hex_widget.get_highlight_rules()

    def list_labels(self) -> list[str]:
        """Return the visible text of every sidebar list item.

        Returns:
            list[str]: Label text for each row in the rule list widget, in order.
        """
        labels: list[str] = []
        for row in range(self.rules_list.count()):
            item = self.rules_list.item(row)
            if item is not None:
                labels.append(item.text())
        return labels


def _run(coro: Any) -> Any:  # noqa: ANN401
    """Drive a bridge coroutine to completion on the calling thread.

    The bridge fires its ``HexDocumentState`` notification synchronously inside
    the coroutine body, so awaiting it here makes the mixin's widget mutation
    run on the test thread -- deterministic and Qt-safe.

    Args:
        coro: The bridge coroutine to await.

    Returns:
        Any: The coroutine's result.
    """
    return asyncio.run(coro)


def _wait_for_bridge_rules(bridge: HexEditorBridge, expected: int, timeout_iters: int = 2000) -> list[dict[str, Any]]:
    """Block until the bridge reports ``expected`` rules, draining Qt events.

    ``list_highlight_rules`` is dispatched onto the same persistent bridge event
    loop the slot's worker uses, so the read is serialised after the in-flight
    add rather than racing it.  Qt events are processed each iteration so the
    worker thread can be scheduled.  The wait is bounded and fails loudly when
    the rule never appears, so a broken dispatch surfaces as a failure rather
    than a hang or a silent skip.

    Args:
        bridge: The real bridge whose rule store is polled.
        expected: Required number of rules before returning.
        timeout_iters: Maximum poll iterations before failing.

    Returns:
        list[dict[str, Any]]: The bridge's rule list once it reaches ``expected``.
    """
    rules: list[dict[str, Any]] = []
    for _ in range(timeout_iters):
        QApplication.processEvents()
        polled = run_bridge_coroutine(bridge.list_highlight_rules())
        rules = polled if isinstance(polled, list) else []
        if len(rules) >= expected:
            return rules
    pytest.fail(f"bridge never registered {expected} highlight rule(s); slot dispatch did not reach the bridge")


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Provide a shared QApplication for all widget-backed tests.

    Returns:
        QApplication: The Qt application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        return existing
    return QApplication([])


class TestAddHighlightRoutesThroughBridge:
    """F-0002: adding a rule routes through the bridge and reaches the real widget."""

    def test_add_byte_value_rule_propagates_to_widget(self, qapp: QApplication) -> None:
        """A real bridge add yields the exact rule in widget, list, and active ids.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _HighlightingPanelHost()
        host.configure_byte_value_controls(color="#FF0000", byte_value=0x41)

        assert host.widget_rules() == []
        assert host.active_ids == []
        assert host.rules_list.count() == 0

        rule_id: str = _run(host.bridge.add_highlight_rule("byte_value", json.dumps({"value": 0x41}), "#FF0000"))

        bridge_rules = _run(host.bridge.list_highlight_rules())
        assert len(bridge_rules) == 1
        assert bridge_rules[0]["id"] == rule_id
        assert bridge_rules[0]["condition_type"] == "byte_value"
        assert bridge_rules[0]["condition_params"] == {"value": 0x41}
        assert bridge_rules[0]["color"] == "#FF0000"

        assert host.active_ids == [rule_id]

        widget_rules = host.widget_rules()
        assert len(widget_rules) == 1
        applied = widget_rules[0]
        assert applied.rule_id == rule_id
        assert applied.condition_type == "byte_value"
        assert applied.condition_params == {"value": 0x41}
        assert applied.color == "#FF0000"

        assert host.list_labels() == [f"[{rule_id[:8]}] Byte == 0x41  (#FF0000)"]

    def test_on_add_highlight_rule_dispatches_correct_bridge_call(self, qapp: QApplication) -> None:
        """The real GUI slot reads its controls and dispatches a correct bridge add.

        Drives the production ``_on_add_highlight_rule`` slot end to end through
        its real background-worker dispatch.  The slot reads the byte-value spin
        (0x7E) and colour edit (``#123456``) and must register exactly one
        ``byte_value`` rule on the real bridge.  The state-holder callback is
        detached for this case so the worker thread performs no off-thread Qt
        mutation; correctness is read back from the bridge after the dispatch
        is serialised on the shared bridge event loop.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _HighlightingPanelHost()
        host.state.unregister_callback(host.route_state_event)
        host.configure_byte_value_controls(color="#123456", byte_value=0x7E)

        host.trigger_add_rule()

        stored = _wait_for_bridge_rules(host.bridge, expected=1)
        assert len(stored) == 1
        assert stored[0]["condition_type"] == "byte_value"
        assert stored[0]["condition_params"] == {"value": 0x7E}
        assert stored[0]["color"] == "#123456"
        assert isinstance(stored[0]["id"], str)
        assert len(stored[0]["id"]) > 0

    def test_add_without_bridge_does_not_touch_widget(self, qapp: QApplication) -> None:
        """When no bridge is wired the slot is a no-op: nothing is written.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _HighlightingPanelHost()
        host.configure_byte_value_controls(color="#FF0000", byte_value=0x41)
        setattr(host, "_bridge", None)

        host.trigger_add_rule()

        assert host.widget_rules() == []
        assert host.active_ids == []
        assert host.rules_list.count() == 0


class TestRemoveHighlightRoutesThroughBridge:
    """F-0002: removing a rule routes through the bridge and clears the real widget."""

    def test_remove_rule_clears_widget_list_and_state(self, qapp: QApplication) -> None:
        """A real bridge remove deletes the rule from widget, list, ids, and state.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _HighlightingPanelHost()

        keep_id: str = _run(host.bridge.add_highlight_rule("byte_value", json.dumps({"value": 0x10}), "#AABBCC"))
        drop_id: str = _run(host.bridge.add_highlight_rule("byte_range", json.dumps({"min": 0x20, "max": 0x30}), "#DDEEFF"))

        assert {keep_id, drop_id} == set(host.active_ids)
        assert len(host.widget_rules()) == 2

        removed: bool = _run(host.bridge.remove_highlight_rule(drop_id))
        assert removed is True

        assert host.active_ids == [keep_id]

        remaining_ids = {rule.rule_id for rule in host.widget_rules()}
        assert remaining_ids == {keep_id}
        assert drop_id not in remaining_ids

        bridge_rules = _run(host.bridge.list_highlight_rules())
        assert [rule["id"] for rule in bridge_rules] == [keep_id]

        assert host.list_labels() == [f"[{keep_id[:8]}] Byte == 0x10  (#AABBCC)"]

    def test_remove_unknown_rule_returns_false_and_preserves_state(self, qapp: QApplication) -> None:
        """Removing an id the bridge never issued returns False and changes nothing.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _HighlightingPanelHost()
        keep_id: str = _run(host.bridge.add_highlight_rule("byte_value", json.dumps({"value": 0x55}), "#010203"))

        removed: bool = _run(host.bridge.remove_highlight_rule("nonexistent-rule-id"))
        assert removed is False

        assert host.active_ids == [keep_id]
        assert {rule.rule_id for rule in host.widget_rules()} == {keep_id}
        assert host.rules_list.count() == 1


class TestSeedHighlightsFromBridge:
    """F-0002: ``seed_highlights_from_bridge`` rebuilds widget state from bridge rules."""

    def test_seed_populates_widget_with_exact_rules(self, qapp: QApplication) -> None:
        """Seeding from real bridge ``list_highlight_rules`` output rebuilds every field.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        source = _HighlightingPanelHost()
        rule_a: str = _run(source.bridge.add_highlight_rule("byte_value", json.dumps({"value": 0x10}), "#AABBCC"))
        rule_b: str = _run(source.bridge.add_highlight_rule("byte_range", json.dumps({"min": 0x20, "max": 0x30}), "#DDEEFF"))
        rules = _run(source.bridge.list_highlight_rules())

        host = _HighlightingPanelHost()
        host.seed_highlights_from_bridge(rules)

        assert host.active_ids == [rule_a, rule_b]

        by_id = {rule.rule_id: rule for rule in host.widget_rules()}
        assert set(by_id) == {rule_a, rule_b}
        assert by_id[rule_a].condition_type == "byte_value"
        assert by_id[rule_a].condition_params == {"value": 0x10}
        assert by_id[rule_a].color == "#AABBCC"
        assert by_id[rule_b].condition_type == "byte_range"
        assert by_id[rule_b].condition_params == {"min": 0x20, "max": 0x30}
        assert by_id[rule_b].color == "#DDEEFF"

        assert host.list_labels() == [
            f"[{rule_a[:8]}] Byte == 0x10  (#AABBCC)",
            f"[{rule_b[:8]}] Byte 0x20-0x30  (#DDEEFF)",
        ]

    def test_seed_is_idempotent_and_clears_stale_state(self, qapp: QApplication) -> None:
        """Re-seeding replaces prior state rather than accumulating duplicates.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        source = _HighlightingPanelHost()
        old_id: str = _run(source.bridge.add_highlight_rule("byte_value", json.dumps({"value": 0x01}), "#111111"))
        first_rules = _run(source.bridge.list_highlight_rules())

        host = _HighlightingPanelHost()
        host.seed_highlights_from_bridge(first_rules)
        assert host.active_ids == [old_id]

        replacement = _HighlightingPanelHost()
        new_id: str = _run(replacement.bridge.add_highlight_rule("byte_value", json.dumps({"value": 0x02}), "#222222"))
        second_rules = _run(replacement.bridge.list_highlight_rules())

        host.seed_highlights_from_bridge(second_rules)

        assert host.active_ids == [new_id]
        assert {rule.rule_id for rule in host.widget_rules()} == {new_id}
        assert host.rules_list.count() == 1


@pytest.mark.skipif(not _HEXCORE_AVAILABLE, reason="intellicrack_hexcore backend required for real pattern search")
class TestRefreshPatternHighlights:
    """F-0015: ``refresh_pattern_highlights`` re-resolves offsets and repaints once."""

    def _make_pattern_host(self, hexcore: types.ModuleType, data: bytes, pattern: str) -> _HighlightingPanelHost:
        """Build a host whose document is a real hexcore doc with a pattern rule.

        Args:
            hexcore: The native ``intellicrack_hexcore`` module.
            data: Raw bytes loaded into the real document.
            pattern: Hex pattern string stored on the rule.

        Returns:
            _HighlightingPanelHost: Host with one pattern rule and a real document.
        """
        host = _HighlightingPanelHost()
        host.document = hexcore.HexDocument.open_bytes(data)
        rule = HighlightRule(
            rule_id="pattern-rule-0001",
            condition_type="pattern",
            condition_params={"pattern": pattern, "offsets": []},
            color="#FF0000",
        )
        host.hex_widget.add_highlight_rule(rule)
        return host

    @pytest.fixture
    def hexcore(self) -> types.ModuleType:
        """Import and return the compiled hexcore extension exposing ``HexDocument``.

        Returns:
            types.ModuleType: The native ``intellicrack_hexcore`` extension module.
        """
        module = importlib.import_module(_HEXCORE_SUBMODULE)
        assert hasattr(module, "HexDocument"), "compiled hexcore extension does not expose HexDocument"
        return module

    def test_refresh_resolves_exact_offsets_and_updates_once(
        self,
        qapp: QApplication,
        hexcore: types.ModuleType,
    ) -> None:
        """Offsets become the real match positions and ``update()`` fires once.

        ``DEADBEEF`` occurs at offsets 0 and 5 in the crafted buffer; the
        oracle is the buffer layout, independent of production code.

        Args:
            qapp: Qt application fixture.
            hexcore: The native hexcore module fixture.
        """
        _ = qapp
        data = bytes.fromhex("DEADBEEF") + b"\x00" + bytes.fromhex("DEADBEEF") + b"\x11\x22\x33"
        host = self._make_pattern_host(hexcore, data, "DE AD BE EF")

        host.hex_widget.update_call_count = 0
        host.refresh_pattern_highlights()

        assert host.hex_widget.update_call_count == 1

        rule = host.hex_widget.get_highlight_rules()[0]
        assert rule.condition_params["offsets"] == {0, 5}
        assert rule.color == "#FF0000"
        assert rule.condition_type == "pattern"

    def test_refresh_with_no_match_yields_empty_offsets(
        self,
        qapp: QApplication,
        hexcore: types.ModuleType,
    ) -> None:
        """A pattern absent from the document resolves to an empty offset set.

        Args:
            qapp: Qt application fixture.
            hexcore: The native hexcore module fixture.
        """
        _ = qapp
        data = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        host = self._make_pattern_host(hexcore, data, "CA FE BA BE")

        host.hex_widget.update_call_count = 0
        host.refresh_pattern_highlights()

        assert host.hex_widget.update_call_count == 1
        rule = host.hex_widget.get_highlight_rules()[0]
        assert rule.condition_params["offsets"] == set()

    def test_refresh_without_document_is_noop(self, qapp: QApplication) -> None:
        """With no document attached, refresh neither searches nor repaints.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        host = _HighlightingPanelHost()
        rule = HighlightRule(
            rule_id="pattern-rule-0002",
            condition_type="pattern",
            condition_params={"pattern": "DEADBEEF", "offsets": []},
            color="#FF0000",
        )
        host.hex_widget.add_highlight_rule(rule)

        host.hex_widget.update_call_count = 0
        host.refresh_pattern_highlights()

        assert host.hex_widget.update_call_count == 0
        unchanged = host.hex_widget.get_highlight_rules()[0]
        assert unchanged.condition_params["offsets"] == []


class TestBuildRuleLabel:
    """Unit tests pinning the exact label format produced by ``build_rule_label``."""

    def test_byte_value_label_exact_format(self) -> None:
        """A byte_value rule renders the full documented label verbatim."""
        label = build_rule_label("abcdef1234", "byte_value", {"value": 0x41}, "#FF0000")
        assert label == "[abcdef12] Byte == 0x41  (#FF0000)"

    def test_byte_range_label_exact_format(self) -> None:
        """A byte_range rule renders min/max as two-digit hex in the full label."""
        label = build_rule_label("abcdef1234", "byte_range", {"min": 0x20, "max": 0x7E}, "#00FF00")
        assert label == "[abcdef12] Byte 0x20-0x7E  (#00FF00)"

    def test_pattern_label_exact_format(self) -> None:
        """A pattern rule renders the pattern text and exact hit count."""
        label = build_rule_label(
            "abcdef1234",
            "pattern",
            {"pattern": "DEADBEEF", "offsets": [0, 4, 8]},
            "#0000FF",
        )
        assert label == "[abcdef12] Pattern DEADBEEF  (3 hits, #0000FF)"

    def test_pattern_label_zero_hits(self) -> None:
        """A pattern rule with no offsets reports ``0 hits``."""
        label = build_rule_label("abcdef1234", "pattern", {"pattern": "CAFE", "offsets": []}, "#0000FF")
        assert label == "[abcdef12] Pattern CAFE  (0 hits, #0000FF)"

    def test_unknown_condition_type_fallback_format(self) -> None:
        """An unrecognised condition type falls back to the generic label."""
        label = build_rule_label("abcdef1234", "regex", {}, "#123456")
        assert label == "[abcdef12] regex  (#123456)"
