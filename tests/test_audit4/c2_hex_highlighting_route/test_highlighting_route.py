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
import threading
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QApplication, QComboBox, QLineEdit, QListWidget, QSpinBox

from intellicrack.ui.panels.hex_editor.highlighting import HighlightingMixin, build_rule_label
from intellicrack.ui.panels.hex_editor_widget import HighlightRule


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytestmark = pytest.mark.integration


class _UpdateCounter:
    """Callable that counts the number of times it is invoked."""

    def __init__(self) -> None:
        self.call_count: int = 0

    def __call__(self) -> None:
        """Increment the invocation counter."""
        self.call_count += 1


class _FakeHexWidget:
    """Minimal stand-in for HexEditorWidget with a counter-based update().

    Mirrors the real ``HexEditorWidget`` interface faithfully so that
    ``_apply_bridge_highlight_rule_added`` and
    ``_apply_bridge_highlight_rule_removed`` operate against the same API as
    in production.  ``add_highlight_rule`` accepts real ``HighlightRule``
    dataclass instances because the production mixin constructs them before
    calling the widget.  ``remove_highlight_rule`` filters by
    ``rule_id: str`` matching the real widget (not by integer index).

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
        self._highlight_rules: list[HighlightRule] = []
        self.update_counter = _UpdateCounter()

    @property
    def rules(self) -> list[HighlightRule]:
        """Expose the internal highlight rules list for test assertions.

        Returns:
            list[HighlightRule]: Current list of highlight rules.
        """
        return self._highlight_rules

    def update(self) -> None:
        """Increment the update counter."""
        self.update_counter()

    def add_highlight_rule(self, rule: HighlightRule) -> None:
        """Append a rule to the internal list.

        Mirrors ``HexEditorWidget.add_highlight_rule`` which appends then
        sorts by priority descending.

        Args:
            rule: The highlight rule to add.
        """
        self._highlight_rules.append(rule)
        self._highlight_rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_highlight_rule(self, rule_id: str) -> bool:
        """Remove a rule by its identifier, matching the real widget signature.

        The production ``_apply_bridge_highlight_rule_removed`` passes
        ``rule_id: str`` to this method.  Mirrors the real
        ``HexEditorWidget.remove_highlight_rule`` which filters the list and
        returns a boolean indicating whether a rule was removed.

        Args:
            rule_id: Unique identifier of the rule to remove.

        Returns:
            bool: True if a rule was removed, False if not found.
        """
        before = len(self._highlight_rules)
        self._highlight_rules = [r for r in self._highlight_rules if r.rule_id != rule_id]
        return len(self._highlight_rules) < before

    def clear_highlight_rules(self) -> None:
        """Clear all rules."""
        self._highlight_rules.clear()


async def _noop_add(_condition_type: str, _condition_params: str, _color: str) -> str:
    """Stub coroutine that returns a fixed rule ID without doing anything.

    Args:
        _condition_type: Ignored.
        _condition_params: Ignored.
        _color: Ignored.

    Returns:
        str: Fixed fake rule ID.
    """
    await asyncio.sleep(0)
    return "stub-rule-id"


async def _noop_remove(_rule_id: str) -> bool:
    """Stub coroutine that returns True without doing anything.

    Args:
        _rule_id: Ignored.

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


_WORKER_WAIT_TIMEOUT_S: float = 5.0
"""Seconds to wait for an async bridge worker thread to finish in tests."""


async def _resolving_add(condition_type: str, condition_params: str, color: str, done: threading.Event) -> str:
    """Coroutine that records completion by setting a threading.Event.

    Resolves immediately so the BridgeCallWorker thread completes without delay.
    Sets ``done`` before returning so the calling test can synchronize on the
    background thread completing.

    Args:
        condition_type: Forwarded condition type (unused in resolution).
        condition_params: Forwarded params JSON (unused in resolution).
        color: Forwarded color string (unused in resolution).
        done: Event to set when this coroutine resolves.

    Returns:
        str: Fixed stub rule ID.
    """
    _ = (condition_type, condition_params, color)
    await asyncio.sleep(0)
    done.set()
    return "sync-stub-rule-id"


async def _resolving_remove(rule_id: str, done: threading.Event) -> bool:
    """Coroutine that records completion by setting a threading.Event.

    Args:
        rule_id: Forwarded rule ID (unused in resolution).
        done: Event to set when this coroutine resolves.

    Returns:
        bool: Always True.
    """
    _ = rule_id
    await asyncio.sleep(0)
    done.set()
    return True


class _SynchronizingAddRecorder:
    """Records add_highlight_rule calls and signals when the async coroutine resolves.

    Unlike ``_AddCallRecorder``, this recorder exposes a ``threading.Event``
    (``resolved``) that is set inside the coroutine body, allowing a test to
    call ``resolved.wait(timeout=...)`` after ``trigger_add_rule()`` and
    guarantee the BridgeCallWorker thread has fully completed before making
    post-confirmation assertions.

    Attributes:
        calls: List of (condition_type, condition_params_json, color) tuples recorded.
        resolved: Set by the add coroutine when it completes.
    """

    calls: list[tuple[str, str, str]]
    resolved: threading.Event

    def __init__(self) -> None:
        """Initialise the recorder."""
        self.calls = []
        self.resolved = threading.Event()

    def add_highlight_rule(
        self,
        condition_type: str,
        condition_params: str,
        color: str = "#FFFF00",
    ) -> Coroutine[Any, Any, str]:
        """Record the call and return a synchronizing coroutine.

        Args:
            condition_type: The condition type string.
            condition_params: JSON-encoded condition parameters.
            color: Hex color string.

        Returns:
            Coroutine[Any, Any, str]: Coroutine that sets ``resolved`` when it completes.
        """
        self.calls.append((condition_type, condition_params, color))
        return _resolving_add(condition_type, condition_params, color, self.resolved)

    def remove_highlight_rule(self, rule_id: str) -> Coroutine[Any, Any, bool]:
        """Return a stub coroutine without recording or signalling.

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


class _SynchronizingRemoveRecorder:
    """Records remove_highlight_rule calls and signals when the async coroutine resolves.

    Attributes:
        calls: List of rule IDs passed to remove_highlight_rule.
        resolved: Set by the remove coroutine when it completes.
    """

    calls: list[str]
    resolved: threading.Event

    def __init__(self) -> None:
        """Initialise the recorder."""
        self.calls = []
        self.resolved = threading.Event()

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
        """Record the rule ID and return a synchronizing coroutine.

        Args:
            rule_id: The rule ID to remove.

        Returns:
            Coroutine[Any, Any, bool]: Coroutine that sets ``resolved`` when it completes.
        """
        self.calls.append(rule_id)
        return _resolving_remove(rule_id, self.resolved)

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

    def __init__(
        self,
        bridge: _AddCallRecorder | _RemoveCallRecorder | _SynchronizingAddRecorder | _SynchronizingRemoveRecorder | None = None,
    ) -> None:
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

    def trigger_apply_add(self, rule: dict[str, Any]) -> None:
        """Call _apply_bridge_highlight_rule_added (public wrapper for test access).

        Simulates the HIGHLIGHT_RULE_ADDED event confirmation arriving from the
        state_holder after the bridge coroutine completes, so tests can verify
        the widget and active_ids are updated correctly on confirmation.

        Args:
            rule: Rule dict with keys ``id``, ``condition_type``,
                ``condition_params``, and ``color``.
        """
        self._apply_bridge_highlight_rule_added(rule)

    def trigger_apply_remove(self, rule_id: str) -> None:
        """Call _apply_bridge_highlight_rule_removed (public wrapper for test access).

        Simulates the HIGHLIGHT_RULE_REMOVED event confirmation arriving from the
        state_holder after the bridge coroutine completes, so tests can verify
        the widget and active_ids are updated correctly on confirmation.

        Args:
            rule_id: The rule identifier to remove.
        """
        self._apply_bridge_highlight_rule_removed(rule_id)


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
    """F-0002: _on_add_highlight_rule must dispatch to bridge.add_highlight_rule.

    Two distinct gates are exercised:

    1. ``test_add_highlight_routes_through_bridge`` - the full-route gate:
       ``_on_add_highlight_rule`` must invoke ``bridge.add_highlight_rule``
       with the exact condition type, JSON-encoded params, and color read from
       the UI controls.  The widget must NOT be mutated before the bridge
       confirmation event arrives.  After the async worker completes and the
       confirmation event is applied, ``widget.rules`` must contain exactly
       the rule with exact field values (rule_id, condition_type,
       condition_params, color), ``active_ids`` must list the confirmed ID,
       and ``update()`` must have been called exactly once.

    2. ``test_add_confirmation_updates_widget`` - the confirmation-only gate:
       calling ``_apply_bridge_highlight_rule_added`` with a known rule dict
       must produce a ``HighlightRule`` on the widget with exact field values,
       append the rule_id to ``active_ids``, add a correctly labelled item to
       the ``QListWidget``, and call ``update()`` on the hex widget.  If
       ``_apply_bridge_highlight_rule_added`` were deleted or corrupted, these
       assertions would go red.
    """

    def test_add_highlight_routes_through_bridge(
        self,
        qapp: QApplication,
    ) -> None:
        """Verify add dispatches through bridge then updates widget on confirmation.

        This test covers the full route: dispatch → bridge invoked with exact
        args → confirmation event → widget.rules updated with exact values.

        Falsifiability: deleting the ``run_bridge_coroutine_logged`` call in
        ``_on_add_highlight_rule`` leaves ``recorder.calls`` empty, the
        ``resolved`` event is never set so ``resolved.wait()`` times out, and
        every subsequent assertion fires.  Replacing the dispatch with a direct
        ``widget.add_highlight_rule(...)`` still leaves ``recorder.calls`` empty
        (first assert fires) and updates the widget before confirmation (breaking
        the pre-confirmation assertion).  Corrupting the JSON-encoded params
        passed to the bridge breaks the ``parsed.get("value") == 0x41``
        assertion.  If ``_apply_bridge_highlight_rule_added`` is removed, the
        final widget-state assertions fire because no confirmation arrives.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        recorder = _SynchronizingAddRecorder()
        host = _HighlightingTestHost(bridge=recorder)
        host.configure_add_controls(condition_index=0, color="#FF0000", byte_value=0x41)

        host.trigger_add_rule()

        assert recorder.resolved.wait(timeout=_WORKER_WAIT_TIMEOUT_S), (
            "BridgeCallWorker thread did not complete within timeout — async bridge dispatch stalled; "
            "if bridge dispatch was deleted the coroutine never runs and this event is never set"
        )

        assert len(recorder.calls) == 1, f"bridge.add_highlight_rule was not called; recorder.calls={recorder.calls!r}"
        condition_type, params_json, color = recorder.calls[0]
        assert condition_type == "byte_value", f"Expected condition_type 'byte_value', got {condition_type!r}"
        parsed: dict[str, Any] = json.loads(params_json)
        assert parsed.get("value") == 0x41, f"Expected value 0x41 (65) in dispatched params, got {parsed.get('value')!r}"
        assert color == "#FF0000", f"Expected color '#FF0000', got {color!r}"

        assert len(host.widget.rules) == 0, (
            "Widget was updated directly before bridge confirmation; "
            "expected 0 rules until the state_holder HIGHLIGHT_RULE_ADDED event arrives"
        )
        assert len(host.active_ids) == 0, "active_highlight_ids mutated before bridge confirmation"

        confirmed_rule_id = "route-gate-add-confirmed-0001"
        confirmed_rule: dict[str, Any] = {
            "id": confirmed_rule_id,
            "condition_type": condition_type,
            "condition_params": parsed,
            "color": color,
        }
        host.trigger_apply_add(confirmed_rule)

        assert len(host.widget.rules) == 1, f"Expected widget to have 1 rule after confirmation, got {len(host.widget.rules)}"
        applied = host.widget.rules[0]
        assert applied.rule_id == confirmed_rule_id, f"Expected rule_id {confirmed_rule_id!r}, got {applied.rule_id!r}"
        assert applied.condition_type == "byte_value", f"Expected condition_type 'byte_value', got {applied.condition_type!r}"
        assert applied.condition_params == {"value": 0x41}, f"Expected condition_params {{'value': 0x41}}, got {applied.condition_params!r}"
        assert applied.color == "#FF0000", f"Expected color '#FF0000', got {applied.color!r}"
        assert host.active_ids == [confirmed_rule_id], f"Expected active_ids [{confirmed_rule_id!r}], got {host.active_ids!r}"
        assert host.rules_list.count() == 1, f"Expected 1 item in rules_list after confirmation, got {host.rules_list.count()}"
        first_item = host.rules_list.item(0)
        label_text = first_item.text() if first_item is not None else ""
        expected_label = build_rule_label(confirmed_rule_id, "byte_value", {"value": 0x41}, "#FF0000")
        assert label_text == expected_label, f"List item label mismatch.\n  expected: {expected_label!r}\n  actual:   {label_text!r}"
        assert host.widget.update_counter.call_count == 1, (
            f"Expected widget.update() called exactly once after confirmation, got {host.widget.update_counter.call_count}"
        )

    def test_add_confirmation_updates_widget(
        self,
        qapp: QApplication,
    ) -> None:
        """Verify _apply_bridge_highlight_rule_added writes exact data to the widget.

        This is the confirmation-path gate: when the bridge's
        HIGHLIGHT_RULE_ADDED event fires (simulated here by calling
        ``_apply_bridge_highlight_rule_added`` directly), the widget's
        ``_highlight_rules`` must contain a ``HighlightRule`` whose fields
        exactly match the incoming rule dict.  ``active_ids`` must contain
        the rule_id, ``rules_list`` must show a correctly labelled item, and
        ``update()`` must have been called once.

        Falsifiability: removing the ``add_rule_fn(widget_rule)`` call in
        ``_apply_bridge_highlight_rule_added`` leaves ``host.widget.rules``
        empty and breaks the count and field assertions.  Corrupting the
        ``condition_params`` passed to ``HighlightRule`` breaks the field
        assertion.  Removing the ``_active_highlight_ids.append`` call breaks
        the active_ids assertion.  Removing the ``update_fn()`` call breaks the
        update_counter assertion.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        rule_id = "rule-id-confirm-add-0001"
        rule_dict: dict[str, Any] = {
            "id": rule_id,
            "condition_type": "byte_value",
            "condition_params": {"value": 0xBE},
            "color": "#12AB34",
        }

        host = _HighlightingTestHost()
        host.widget.update_counter.call_count = 0

        host.trigger_apply_add(rule_dict)

        assert len(host.widget.rules) == 1, f"Expected 1 rule in widget after confirmation, got {len(host.widget.rules)}"
        applied_rule = host.widget.rules[0]
        assert applied_rule.rule_id == rule_id, f"Expected rule_id {rule_id!r}, got {applied_rule.rule_id!r}"
        assert applied_rule.condition_type == "byte_value", f"Expected condition_type 'byte_value', got {applied_rule.condition_type!r}"
        assert applied_rule.condition_params == {"value": 0xBE}, (
            f"Expected condition_params {{'value': 0xBE}}, got {applied_rule.condition_params!r}"
        )
        assert applied_rule.color == "#12AB34", f"Expected color '#12AB34', got {applied_rule.color!r}"

        assert host.active_ids == [rule_id], f"Expected active_ids [{rule_id!r}], got {host.active_ids!r}"

        assert host.rules_list.count() == 1, f"Expected 1 item in rules_list, got {host.rules_list.count()}"
        first_item = host.rules_list.item(0)
        label_text = first_item.text() if first_item is not None else ""
        expected_label = build_rule_label(rule_id, "byte_value", {"value": 0xBE}, "#12AB34")
        assert label_text == expected_label, f"List item label mismatch.\n  expected: {expected_label!r}\n  actual:   {label_text!r}"

        assert host.widget.update_counter.call_count == 1, (
            f"Expected widget.update() called once after confirmation, got {host.widget.update_counter.call_count}"
        )


class TestRemoveHighlightRoutesThoughBridge:
    """F-0002: _on_remove_highlight_rule must dispatch to bridge.remove_highlight_rule.

    Two distinct gates are exercised:

    1. ``test_remove_highlight_routes_through_bridge`` - the full-route gate:
       calling ``_on_remove_highlight_rule`` must invoke
       ``bridge.remove_highlight_rule`` with the exact rule_id at the
       selected row in ``active_ids``.  The widget must NOT be mutated before
       the bridge confirmation event arrives.  After the async worker completes
       and the confirmation event is applied, ``widget.rules`` must be empty,
       ``active_ids`` must be empty, and ``update()`` must have been called
       exactly once.

    2. ``test_remove_confirmation_updates_widget`` - the confirmation-only
       gate: calling ``_apply_bridge_highlight_rule_removed`` with a known
       rule_id must remove that rule from the widget's ``_highlight_rules``
       list, pop the rule_id from ``active_ids``, remove the corresponding
       ``QListWidget`` item, and call ``update()`` once.
    """

    def test_remove_highlight_routes_through_bridge(
        self,
        qapp: QApplication,
    ) -> None:
        """Verify remove dispatches through bridge then removes rule from widget on confirmation.

        This test covers the full route: dispatch → bridge.remove_highlight_rule invoked
        with the exact rule_id → confirmation event → widget.rules emptied and active_ids
        cleared.

        Falsifiability: removing the ``run_bridge_coroutine_logged`` call in
        ``_on_remove_highlight_rule`` leaves ``recorder.calls`` empty so the
        ``resolved`` event is never set; the timeout fires and every subsequent
        assertion fires.  Replacing the dispatch with a direct widget mutation would
        remove the rule from ``host.widget.rules`` and ``host.active_ids`` BEFORE
        confirmation, breaking the pre-confirmation assertions (widget still has 1
        rule / active_ids still has 1 entry).  If ``_apply_bridge_highlight_rule_removed``
        is removed, the post-confirmation assertions fire because the rule remains.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        rule_id = "test-rule-remove-gate-ef01"

        recorder = _SynchronizingRemoveRecorder()
        host = _HighlightingTestHost(bridge=recorder)
        host.active_ids.append(rule_id)
        host.rules_list.addItem(f"[{rule_id[:8]}] Byte == 0x42")
        real_rule = HighlightRule(
            rule_id=rule_id,
            condition_type="byte_value",
            condition_params={"value": 0x42},
            color="#00FF00",
        )
        host.widget.add_highlight_rule(real_rule)

        host.rules_list.setCurrentRow(0)

        host.trigger_remove_rule()

        assert recorder.resolved.wait(timeout=_WORKER_WAIT_TIMEOUT_S), (
            "BridgeCallWorker thread did not complete within timeout — async bridge dispatch stalled; "
            "if bridge dispatch was deleted the coroutine never runs and this event is never set"
        )

        assert recorder.calls == [rule_id], f"Expected bridge.remove_highlight_rule called with [{rule_id!r}], got {recorder.calls!r}"

        assert len(host.active_ids) == 1, (
            "active_highlight_ids was mutated before bridge HIGHLIGHT_RULE_REMOVED event confirmation; "
            "expected 1 entry until the state_holder event arrives"
        )
        assert len(host.widget.rules) == 1, (
            "Widget rules list was mutated before bridge HIGHLIGHT_RULE_REMOVED event confirmation; "
            "expected 1 rule until the state_holder event arrives"
        )

        host.widget.update_counter.call_count = 0
        host.trigger_apply_remove(rule_id)

        assert len(host.widget.rules) == 0, f"Expected widget.rules to be empty after remove confirmation, got {len(host.widget.rules)}"
        assert host.active_ids == [], f"Expected active_ids to be empty after remove confirmation, got {host.active_ids!r}"
        assert host.rules_list.count() == 0, f"Expected rules_list to be empty after remove confirmation, got {host.rules_list.count()}"
        assert host.widget.update_counter.call_count == 1, (
            f"Expected widget.update() called once after remove confirmation, got {host.widget.update_counter.call_count}"
        )

    def test_remove_confirmation_updates_widget(
        self,
        qapp: QApplication,
    ) -> None:
        """Verify _apply_bridge_highlight_rule_removed removes exactly the targeted rule.

        Sets up two pre-existing rules on the widget/active_ids, then calls
        ``_apply_bridge_highlight_rule_removed`` for the first rule only.
        After confirmation, the widget must contain exactly the second rule
        (with exact field values preserved), ``active_ids`` must contain only
        the second rule_id, the ``QListWidget`` must have exactly one item
        with the correct label, and ``update()`` must have been called once.

        Falsifiability: removing the ``remove_fn(rule_id)`` call in
        ``_apply_bridge_highlight_rule_removed`` leaves the widget with 2
        rules and breaks the count assertion.  Removing the
        ``_active_highlight_ids.pop(row)`` call leaves active_ids with 2
        items.  Removing ``takeItem(row)`` leaves the QListWidget with 2
        items.  Removing ``update_fn()`` leaves update_counter at 0.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        rule_id_a = "rule-remove-confirm-aaaa"
        rule_id_b = "rule-remove-confirm-bbbb"

        host = _HighlightingTestHost()

        expected_b = HighlightRule(
            rule_id=rule_id_b,
            condition_type="byte_range",
            condition_params={"min": 0x20, "max": 0x7E},
            color="#00FF00",
            priority=0,
        )

        host.trigger_apply_add(
            {
                "id": rule_id_a,
                "condition_type": "byte_value",
                "condition_params": {"value": 0x10},
                "color": "#FF0000",
            },
        )
        host.trigger_apply_add(
            {
                "id": rule_id_b,
                "condition_type": "byte_range",
                "condition_params": {"min": 0x20, "max": 0x7E},
                "color": "#00FF00",
            },
        )

        assert len(host.widget.rules) == 2, "Pre-condition: expected 2 rules before remove"
        assert host.active_ids == [rule_id_a, rule_id_b], "Pre-condition: expected both IDs in active_ids"
        assert host.rules_list.count() == 2, "Pre-condition: expected 2 list items"

        host.widget.update_counter.call_count = 0

        host.trigger_apply_remove(rule_id_a)

        assert len(host.widget.rules) == 1, f"Expected 1 rule after removing rule_a, got {len(host.widget.rules)}"
        remaining = host.widget.rules[0]
        assert remaining.rule_id == rule_id_b, f"Expected remaining rule to be rule_b ({rule_id_b!r}), got {remaining.rule_id!r}"
        assert remaining.condition_type == expected_b.condition_type, (
            f"Expected condition_type {expected_b.condition_type!r}, got {remaining.condition_type!r}"
        )
        assert remaining.condition_params == expected_b.condition_params, (
            f"Expected condition_params {expected_b.condition_params!r}, got {remaining.condition_params!r}"
        )
        assert remaining.color == expected_b.color, f"Expected color {expected_b.color!r}, got {remaining.color!r}"

        assert host.active_ids == [rule_id_b], f"Expected active_ids [{rule_id_b!r}] after remove, got {host.active_ids!r}"

        assert host.rules_list.count() == 1, f"Expected 1 list item after remove, got {host.rules_list.count()}"
        remaining_item = host.rules_list.item(0)
        remaining_label = remaining_item.text() if remaining_item is not None else ""
        expected_label = build_rule_label(rule_id_b, "byte_range", {"min": 0x20, "max": 0x7E}, "#00FF00")
        assert remaining_label == expected_label, (
            f"Remaining list item label mismatch.\n  expected: {expected_label!r}\n  actual:   {remaining_label!r}"
        )

        assert host.widget.update_counter.call_count == 1, (
            f"Expected widget.update() called once after remove confirmation, got {host.widget.update_counter.call_count}"
        )


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

        pattern_rule = HighlightRule(
            rule_id="test-rule-id",
            condition_type="pattern",
            condition_params={"pattern": "DEADBEEF", "offsets": []},
            color="#FF0000",
        )
        host.widget.add_highlight_rule(pattern_rule)

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
