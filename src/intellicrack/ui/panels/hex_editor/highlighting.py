# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Highlight rule management mixin for the hex editor panel.

Every background pattern-highlight ``search_hex`` scan started in this
module disables the entire ``HexEditorPanel`` instance for its duration
(see :meth:`HighlightingMixin._begin_pattern_search_busy`), not just the
embedded :attr:`HighlightingMixin._hex_widget`. ``HexEditorPanel`` mixes in
:class:`HighlightingMixin` alongside every other hex-editor mixin
(``SearchMixin``, ``TransformsMixin``, ``ScriptingMixin``, etc.) as a single
``QWidget``, and Qt's disabled-widget propagation blocks input delivery to
every descendant of a disabled widget. Disabling the panel therefore also
blocks the "Replace All", "Apply Transform", and "Run Script" controls owned
by those sibling mixins -- not only the hex view's own key/mouse handlers --
so no GUI-thread click can start a concurrent ``write_bytes``,
``insert_bytes``, or ``delete_bytes`` call against the same document while a
background pattern search's native borrow is in flight. hexcore's
``search_hex`` holds a PyO3 shared borrow on the ``HexDocument`` for the
entire duration of the call, including the GIL-released whole-document scan;
a concurrent exclusive borrow taken by a document-mutating call while a
background ``search_hex`` is in flight raises ``PyBorrowMutError``, which
pyo3 surfaces to Python as ``RuntimeError``.

The panel-wide disable only blocks *new* GUI-thread-initiated mutations
while a search is in flight; it cannot retroactively serialise a
document-mutating background worker that was already running before the
search started (e.g. a script already executing via
``ScriptingMixin._script_worker``), nor any mutation triggered
programmatically (AI/bridge-driven) rather than through a disabled control.
This module also exposes :data:`DOCUMENT_MUTATION_LOCK` for those
remaining call sites: every native-document-mutating call site elsewhere in
the hex editor (``hex_editor_widget.py``, ``search.py``, ``transforms.py``,
``scripting.py``) must acquire this lock instance around each
``write_bytes``/``insert_bytes``/``delete_bytes`` call, regardless of
whether it is reached via a UI control or a programmatic/bridge call, so
their exclusive borrows never overlap with an in-flight shared-borrow
search on a background thread.
"""

from __future__ import annotations

import json
import threading
from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtWidgets import (
    QColorDialog,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import GenericCallableWorker, run_bridge_coroutine_logged
from intellicrack.ui.panels.hex_editor_widget import HighlightRule


_logger = get_logger(__name__)


_DEFAULT_HIGHLIGHT_COLOR: Final[str] = "#FFFF00"
_BYTE_MAX: Final[int] = 255
_HIGHLIGHT_PATTERN_MAX_MATCHES: Final[int] = 10000

DOCUMENT_MUTATION_LOCK: Final[threading.Lock] = threading.Lock()
"""Serialises native ``HexDocument`` access across mutation and search.

Every background ``search_hex`` dispatch in this module acquires this lock for the duration of the call. Any other module that mutates the
active document's underlying bytes (``write_bytes``, ``insert_bytes``, block operations, etc.) must acquire the same lock instance around
each mutating call so those exclusive borrows never overlap with an in-flight shared- borrow search on a background thread.
"""

if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.bridges.hex_editor import HexEditorBridge


class HighlightingMixin:
    """Mixin providing highlight rule management for the hex editor panel."""

    document: Any | None
    _hex_widget: Any | None
    _highlight_condition_combo: QComboBox | None
    _highlight_color_edit: QLineEdit | None
    _highlight_params_stack: QStackedWidget | None
    _highlight_byte_value_spin: QSpinBox | None
    _highlight_range_min_spin: QSpinBox | None
    _highlight_range_max_spin: QSpinBox | None
    _highlight_pattern_edit: QLineEdit | None
    _highlight_rules_list: QListWidget | None
    _active_highlight_ids: list[str]
    _bridge: HexEditorBridge | None
    _pattern_rule_worker: GenericCallableWorker | None
    _pending_pattern_add_bridge: HexEditorBridge | None
    _pending_pattern_add_pattern: str
    _pending_pattern_add_color: str
    _pattern_refresh_worker: GenericCallableWorker | None
    _pattern_refresh_pending: bool
    _pattern_search_busy_count: int

    def _create_highlighting_controls(self) -> QGroupBox:
        """Create the highlight rules management group box.

        Returns:
            QGroupBox: Container with condition type selector, parameter
                inputs, color picker, rule list, and control buttons.
        """
        box = QGroupBox("Highlight Rules")
        layout = QVBoxLayout(box)
        layout.setSpacing(4)

        cond_row = QHBoxLayout()
        cond_row.addWidget(QLabel("Condition:"))
        self._highlight_condition_combo = QComboBox()
        self._highlight_condition_combo.addItems(["Byte Value", "Byte Range", "Pattern"])
        self._highlight_condition_combo.currentIndexChanged.connect(
            self._on_highlight_condition_changed,
        )
        cond_row.addWidget(self._highlight_condition_combo)
        layout.addLayout(cond_row)

        self._highlight_params_stack = QStackedWidget()

        byte_value_page = QWidget()
        bv_layout = QHBoxLayout(byte_value_page)
        bv_layout.setContentsMargins(0, 0, 0, 0)
        bv_layout.addWidget(QLabel("Value:"))
        self._highlight_byte_value_spin = QSpinBox()
        self._highlight_byte_value_spin.setRange(0, _BYTE_MAX)
        bv_layout.addWidget(self._highlight_byte_value_spin)
        bv_layout.addStretch()
        self._highlight_params_stack.addWidget(byte_value_page)

        byte_range_page = QWidget()
        br_layout = QHBoxLayout(byte_range_page)
        br_layout.setContentsMargins(0, 0, 0, 0)
        br_layout.addWidget(QLabel("Min:"))
        self._highlight_range_min_spin = QSpinBox()
        self._highlight_range_min_spin.setRange(0, _BYTE_MAX)
        br_layout.addWidget(self._highlight_range_min_spin)
        br_layout.addWidget(QLabel("Max:"))
        self._highlight_range_max_spin = QSpinBox()
        self._highlight_range_max_spin.setRange(0, _BYTE_MAX)
        self._highlight_range_max_spin.setValue(_BYTE_MAX)
        br_layout.addWidget(self._highlight_range_max_spin)
        br_layout.addStretch()
        self._highlight_params_stack.addWidget(byte_range_page)

        pattern_page = QWidget()
        pp_layout = QHBoxLayout(pattern_page)
        pp_layout.setContentsMargins(0, 0, 0, 0)
        pp_layout.addWidget(QLabel("Hex:"))
        self._highlight_pattern_edit = QLineEdit()
        self._highlight_pattern_edit.setToolTip("Hex pattern (e.g. 4D5A)")
        pp_layout.addWidget(self._highlight_pattern_edit)
        self._highlight_params_stack.addWidget(pattern_page)

        layout.addWidget(self._highlight_params_stack)

        color_row = QHBoxLayout()
        color_row.addWidget(QLabel("Color:"))
        self._highlight_color_edit = QLineEdit(_DEFAULT_HIGHLIGHT_COLOR)
        self._highlight_color_edit.setMaximumWidth(80)
        color_row.addWidget(self._highlight_color_edit)
        pick_btn = QPushButton("Pick...")
        pick_btn.clicked.connect(self._on_pick_highlight_color)
        color_row.addWidget(pick_btn)
        color_row.addStretch()
        layout.addLayout(color_row)

        add_btn = QPushButton("Add Rule")
        add_btn.clicked.connect(self._on_add_highlight_rule)
        layout.addWidget(add_btn)

        self._highlight_rules_list = QListWidget()
        layout.addWidget(self._highlight_rules_list)

        btn_row = QHBoxLayout()
        rm_btn = QPushButton("Remove Selected")
        rm_btn.clicked.connect(self._on_remove_highlight_rule)
        btn_row.addWidget(rm_btn)
        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self._on_clear_highlight_rules)
        btn_row.addWidget(clear_btn)
        layout.addLayout(btn_row)

        self._active_highlight_ids = []
        self._pattern_rule_worker = None
        self._pending_pattern_add_bridge = None
        self._pending_pattern_add_pattern = ""
        self._pending_pattern_add_color = _DEFAULT_HIGHLIGHT_COLOR
        self._pattern_refresh_worker = None
        self._pattern_refresh_pending = False
        self._pattern_search_busy_count = 0
        return box

    def _begin_pattern_search_busy(self) -> None:
        """Register an in-flight background pattern search and lock out document mutation.

        Increments the shared busy counter and, the first time it moves off zero,
        disables the whole panel widget (``self``, the ``HexEditorPanel`` instance
        that mixes in :class:`HighlightingMixin` alongside every sibling
        document-mutating mixin) so that no descendant control -- the hex view's
        own keyboard/mouse handlers, "Replace All", "Apply Transform", or "Run
        Script" -- can start a document-mutating call while a background
        ``search_hex`` scan holds a native shared borrow on the same document.
        """
        self._pattern_search_busy_count += 1
        if self._pattern_search_busy_count == 1 and isinstance(self, QWidget):
            self.setEnabled(False)

    def _end_pattern_search_busy(self) -> None:
        """Retire an in-flight background pattern search and restore document mutation.

        Decrements the shared busy counter and, only once it returns to zero, re-enables the panel widget so overlapping refresh and add-
        rule searches cannot re-enable mutation while a sibling background search is still running.
        """
        self._pattern_search_busy_count = max(0, self._pattern_search_busy_count - 1)
        if self._pattern_search_busy_count == 0 and isinstance(self, QWidget):
            self.setEnabled(True)

    def _on_highlight_condition_changed(self, index: int) -> None:
        """Switch the parameter input page for the selected condition type.

        Args:
            index: Index of the selected condition type.
        """
        if self._highlight_params_stack is not None:
            self._highlight_params_stack.setCurrentIndex(index)

    def _on_pick_highlight_color(self) -> None:
        """Open a color dialog and set the selected color."""
        parent = self if isinstance(self, QWidget) else None
        color = QColorDialog.getColor(parent=parent)
        if color.isValid() and self._highlight_color_edit is not None:
            self._highlight_color_edit.setText(color.name())

    def _on_add_highlight_rule(self) -> None:
        """Create a highlight rule via the bridge and update the widget on confirmation."""
        if self._highlight_condition_combo is None:
            return

        bridge: HexEditorBridge | None = getattr(self, "_bridge", None)
        if bridge is None:
            _logger.warning("highlight_rule_add_no_bridge")
            return

        condition_idx = self._highlight_condition_combo.currentIndex()
        color = self._highlight_color_edit.text().strip() if self._highlight_color_edit else _DEFAULT_HIGHLIGHT_COLOR

        if condition_idx == 0:
            value = self._highlight_byte_value_spin.value() if self._highlight_byte_value_spin else 0
            self._dispatch_add_highlight_rule(bridge, "byte_value", {"value": value}, color)
            return
        if condition_idx == 1:
            min_val = self._highlight_range_min_spin.value() if self._highlight_range_min_spin else 0
            max_val = self._highlight_range_max_spin.value() if self._highlight_range_max_spin else _BYTE_MAX
            self._dispatch_add_highlight_rule(bridge, "byte_range", {"min": min_val, "max": max_val}, color)
            return

        self._on_add_pattern_highlight_rule(bridge, color)

    def _on_add_pattern_highlight_rule(self, bridge: HexEditorBridge, color: str) -> None:
        """Resolve a ``pattern``-type highlight rule's offsets off the GUI thread, then dispatch it.

        The native ``search_hex`` whole-document scan runs on a background
        :class:`~intellicrack.ui.panels.async_bridge.GenericCallableWorker` thread so the
        'Add Rule' click never blocks the Qt event loop while the pattern is resolved.

        Args:
            bridge: Connected hex editor bridge used to persist the rule.
            color: Hex colour string selected for the new rule.
        """
        pattern = self._highlight_pattern_edit.text().strip() if self._highlight_pattern_edit else ""
        parent = self if isinstance(self, QWidget) else None
        if not pattern:
            QMessageBox.warning(parent, "Highlight", "Pattern cannot be empty.")
            return

        document = getattr(self, "document", None)
        search_fn = getattr(document, "search_hex", None) if document is not None else None
        if not callable(search_fn):
            self._dispatch_add_highlight_rule(bridge, "pattern", {"pattern": pattern, "offsets": []}, color)
            return

        existing_worker = getattr(self, "_pattern_rule_worker", None)
        if existing_worker is not None and existing_worker.isRunning():
            return

        self._pending_pattern_add_bridge = bridge
        self._pending_pattern_add_pattern = pattern
        self._pending_pattern_add_color = color
        self._pattern_rule_worker = GenericCallableWorker(
            _locked_search_hex,
            search_fn,
            pattern,
            _HIGHLIGHT_PATTERN_MAX_MATCHES,
        )
        _ = self._pattern_rule_worker.call_finished.connect(self._on_pattern_rule_search_finished)
        _ = self._pattern_rule_worker.call_error.connect(self._on_pattern_rule_search_error)
        self._begin_pattern_search_busy()
        self._pattern_rule_worker.start()

    def _on_pattern_rule_search_finished(self, matches: object) -> None:
        """Dispatch the pending pattern highlight rule once its offsets resolve.

        Args:
            matches: Raw match list returned by the background ``search_hex`` call.
        """
        self._pattern_rule_worker = None
        self._end_pattern_search_busy()
        bridge = getattr(self, "_pending_pattern_add_bridge", None)
        pattern = getattr(self, "_pending_pattern_add_pattern", "")
        color = getattr(self, "_pending_pattern_add_color", _DEFAULT_HIGHLIGHT_COLOR)
        self._pending_pattern_add_bridge = None
        if bridge is None:
            return
        offsets = _parse_pattern_matches(matches)
        params: dict[str, Any] = {"pattern": pattern, "offsets": sorted(offsets)}
        self._dispatch_add_highlight_rule(bridge, "pattern", params, color)

    def _on_pattern_rule_search_error(self, exc: object) -> None:
        """Handle a background pattern-highlight search failure.

        Args:
            exc: Exception raised by the background ``search_hex`` call.
        """
        self._pattern_rule_worker = None
        self._end_pattern_search_busy()
        pattern = getattr(self, "_pending_pattern_add_pattern", "")
        self._pending_pattern_add_bridge = None
        _logger.warning("highlight_rule_pattern_search_failed", pattern=pattern, error=str(exc), error_type=type(exc).__name__)
        parent = self if isinstance(self, QWidget) else None
        QMessageBox.warning(parent, "Highlight", f"Pattern search failed: {exc}")

    def _dispatch_add_highlight_rule(
        self,
        bridge: HexEditorBridge,
        condition_type: str,
        params: dict[str, Any],
        color: str,
    ) -> None:
        """Send an ``add_highlight_rule`` bridge RPC for a fully-resolved condition.

        Args:
            bridge: Connected hex editor bridge used to persist the rule.
            condition_type: One of ``"byte_value"``, ``"byte_range"``, or ``"pattern"``.
            params: Condition parameters dict for the new rule.
            color: Hex colour string selected for the new rule.
        """
        params_json = json.dumps(params)
        parent_obj = self if isinstance(self, QWidget) else None
        run_bridge_coroutine_logged(
            bridge.add_highlight_rule(condition_type, params_json, color),
            on_success=self._on_bridge_rule_added,
            on_error=self._on_bridge_rule_error,
            parent=parent_obj,
            event="hex_editor_add_highlight_rule",
            logger=_logger,
            level="info",
            condition_type=condition_type,
            color=color,
        )

    @staticmethod
    def _on_bridge_rule_added(result: object) -> None:
        """Handle successful bridge add_highlight_rule response.

        The bridge's state_holder fires HIGHLIGHT_RULE_ADDED, which drives
        widget update via :meth:`_apply_bridge_highlight_rule_added`.  This
        callback is only for logging; the widget is NOT written here to avoid
        double-write.

        Args:
            result: Rule ID string returned by the bridge.
        """
        _logger.debug("highlight_rule_bridge_add_ok", rule_id=result)

    def _on_bridge_rule_error(self, exc: object) -> None:
        """Handle bridge add_highlight_rule failure.

        Args:
            exc: Exception raised by the bridge coroutine.
        """
        _logger.warning("highlight_rule_bridge_add_failed", exc=str(exc))
        parent = self if isinstance(self, QWidget) else None
        QMessageBox.warning(parent, "Highlight", f"Failed to add highlight rule: {exc}")

    def _on_remove_highlight_rule(self) -> None:
        """Remove the selected highlight rule via the bridge."""
        if self._highlight_rules_list is None:
            return

        bridge: HexEditorBridge | None = getattr(self, "_bridge", None)
        if bridge is None:
            _logger.warning("highlight_rule_remove_no_bridge")
            return

        row = self._highlight_rules_list.currentRow()
        if row < 0 or row >= len(self._active_highlight_ids):
            return

        rule_id = self._active_highlight_ids[row]
        parent_obj = self if isinstance(self, QWidget) else None
        run_bridge_coroutine_logged(
            bridge.remove_highlight_rule(rule_id),
            on_success=self._on_bridge_rule_removed,
            on_error=self._on_bridge_rule_remove_error,
            parent=parent_obj,
            event="hex_editor_remove_highlight_rule",
            logger=_logger,
            level="info",
            rule_id=rule_id,
        )

    @staticmethod
    def _on_bridge_rule_removed(result: object) -> None:
        """Handle successful bridge remove_highlight_rule response.

        The bridge fires HIGHLIGHT_RULE_REMOVED through state_holder, which
        drives widget update via :meth:`_apply_bridge_highlight_rule_removed`.

        Args:
            result: Boolean indicating whether the rule was found and removed.
        """
        _logger.info("highlight_rule_bridge_remove_ok", result=result)

    def _on_bridge_rule_remove_error(self, exc: object) -> None:
        """Handle bridge remove_highlight_rule failure.

        Args:
            exc: Exception raised by the bridge coroutine.
        """
        _logger.warning("highlight_rule_bridge_remove_failed", exc=str(exc))
        parent = self if isinstance(self, QWidget) else None
        QMessageBox.warning(parent, "Highlight", f"Failed to remove highlight rule: {exc}")

    def _apply_bridge_highlight_rule_added(self, rule: dict[str, Any]) -> None:
        """Apply a bridge-confirmed highlight rule to the local widget and list.

        Called from the state_holder HIGHLIGHT_RULE_ADDED event handler in
        :meth:`HexEditorPanel.set_state_holder`.  The rule dict originates
        from :meth:`HexEditorBridge.add_highlight_rule` and contains the
        canonical ``id`` assigned by the bridge (a full UUID), not the
        short preview ID generated in :meth:`_on_add_highlight_rule`.

        Args:
            rule: Rule dict with keys ``id``, ``condition_type``,
                ``condition_params``, and ``color``.
        """
        rule_id: str = str(rule.get("id", ""))
        condition_type: str = str(rule.get("condition_type", ""))
        condition_params: Any = rule.get("condition_params", {})
        color: str = str(rule.get("color", _DEFAULT_HIGHLIGHT_COLOR))

        if not isinstance(condition_params, dict):
            condition_params = {}

        if self._hex_widget is not None:
            add_rule_fn = getattr(self._hex_widget, "add_highlight_rule", None)
            if callable(add_rule_fn):
                try:
                    widget_rule = HighlightRule(
                        rule_id=rule_id,
                        condition_type=condition_type,
                        condition_params=cast("dict[str, Any]", condition_params),
                        color=color,
                        priority=len(self._active_highlight_ids),
                    )
                    add_rule_fn(widget_rule)
                except (ImportError, TypeError, AttributeError):
                    _logger.exception("highlight_widget_rule_apply_failed", rule_id=rule_id)

        self._active_highlight_ids.append(rule_id)

        if self._highlight_rules_list is not None:
            label = build_rule_label(rule_id, condition_type, cast("dict[str, Any]", condition_params), color)
            item = QListWidgetItem(label)
            self._highlight_rules_list.addItem(item)

        update_fn = getattr(self._hex_widget, "update", None)
        if callable(update_fn):
            update_fn()

        _logger.info("highlight_rule_applied_to_widget", rule_id=rule_id, condition_type=condition_type)

    def _apply_bridge_highlight_rule_removed(self, rule_id: str) -> None:
        """Remove a bridge-confirmed highlight rule from the local widget and list.

        Called from the state_holder HIGHLIGHT_RULE_REMOVED event handler in
        :meth:`HexEditorPanel.set_state_holder`.

        Args:
            rule_id: Rule ID returned by the bridge coroutine.
        """
        if rule_id not in self._active_highlight_ids:
            return

        row = self._active_highlight_ids.index(rule_id)

        if self._hex_widget is not None:
            remove_fn = getattr(self._hex_widget, "remove_highlight_rule", None)
            if callable(remove_fn):
                try:
                    remove_fn(rule_id)
                except (IndexError, TypeError, AttributeError):
                    _logger.exception("highlight_widget_rule_remove_failed", row=row, rule_id=rule_id)

        self._active_highlight_ids.pop(row)
        if self._highlight_rules_list is not None:
            self._highlight_rules_list.takeItem(row)

        update_fn = getattr(self._hex_widget, "update", None)
        if callable(update_fn):
            update_fn()

        _logger.info("highlight_rule_removed_from_widget", rule_id=rule_id)

    def _on_clear_highlight_rules(self) -> None:
        """Remove all active highlight rules."""
        if self._hex_widget is None:
            return

        clear_fn = getattr(self._hex_widget, "clear_highlight_rules", None)
        if callable(clear_fn):
            clear_fn()
        else:
            rules_attr = getattr(self._hex_widget, "_highlight_rules", None)
            if isinstance(rules_attr, list):
                rules_attr.clear()

        self._active_highlight_ids.clear()
        if self._highlight_rules_list is not None:
            self._highlight_rules_list.clear()

    def seed_highlights_from_bridge(self, rules: object) -> None:
        """Populate the widget and list from the bridge's current highlight rules.

        Called on panel initialisation (after :meth:`set_state_holder` wires
        the callback) to ensure the GUI reflects any rules already registered
        by the bridge or AI before the panel was opened.

        The method clears any stale local state first so it is safe to call
        more than once (e.g. when the bridge is reset).

        Args:
            rules: List of rule dicts from :meth:`HexEditorBridge.list_highlight_rules`.
                Each dict must contain at minimum ``id``, ``condition_type``,
                ``condition_params``, and ``color``.
        """
        if not isinstance(rules, list):
            return

        self._active_highlight_ids.clear()
        if self._highlight_rules_list is not None:
            self._highlight_rules_list.clear()

        clear_fn = getattr(self._hex_widget, "clear_highlight_rules", None) if self._hex_widget is not None else None
        if callable(clear_fn):
            clear_fn()
        elif self._hex_widget is not None:
            rules_attr = getattr(self._hex_widget, "_highlight_rules", None)
            if isinstance(rules_attr, list):
                rules_attr.clear()

        for rule_raw in cast("list[object]", rules):
            if not isinstance(rule_raw, dict):
                continue
            rule: dict[str, Any] = cast("dict[str, Any]", rule_raw)
            self._apply_bridge_highlight_rule_added(rule)

        _logger.debug("highlight_widget_seeded_from_bridge", count=len(self._active_highlight_ids))

    def refresh_pattern_highlights(self) -> None:
        """Re-resolve offsets for every pattern-type highlight rule.

        Called by the hex editor panel whenever the active document's byte content changes (``HexEditorWidget.data_changed``) so that
        pattern-based highlight rules stay consistent with the underlying document.  Byte-value and byte-range rules do not need to be
        refreshed because their match logic is re-evaluated per-paint from the raw byte value.

        The native ``search_hex`` whole-document scan for every active pattern rule runs on a background
        :class:`~intellicrack.ui.panels.async_bridge.GenericCallableWorker` thread so a byte edit never blocks the Qt event loop while
        offsets are recomputed.  A refresh requested while one is already in flight is coalesced into a single follow-up pass once the
        in-flight worker completes, so rapid successive edits never queue an unbounded number of background scans.
        """
        if self._hex_widget is None:
            return
        rules_attr = getattr(self._hex_widget, "_highlight_rules", None)
        if not isinstance(rules_attr, list):
            return
        document = getattr(self, "document", None)
        search_fn = getattr(document, "search_hex", None) if document is not None else None
        if not callable(search_fn):
            return

        specs: list[tuple[str, str]] = []
        for rule in cast("list[Any]", rules_attr):
            if getattr(rule, "condition_type", None) != "pattern":
                continue
            rule_id = getattr(rule, "rule_id", None)
            params_attr: object = getattr(rule, "condition_params", None)
            if not isinstance(rule_id, str) or not isinstance(params_attr, dict):
                continue
            pattern_raw: object = cast("dict[str, Any]", params_attr).get("pattern")
            if isinstance(pattern_raw, str) and pattern_raw:
                specs.append((rule_id, pattern_raw))
        if not specs:
            return

        existing_worker = getattr(self, "_pattern_refresh_worker", None)
        if existing_worker is not None and existing_worker.isRunning():
            self._pattern_refresh_pending = True
            return

        self._pattern_refresh_pending = False
        self._pattern_refresh_worker = GenericCallableWorker(_resolve_pattern_offsets, search_fn, specs)
        _ = self._pattern_refresh_worker.call_finished.connect(self._on_pattern_refresh_finished)
        _ = self._pattern_refresh_worker.call_error.connect(self._on_pattern_refresh_error)
        self._begin_pattern_search_busy()
        self._pattern_refresh_worker.start()

    def _on_pattern_refresh_finished(self, result: object) -> None:
        """Apply resolved pattern-highlight offsets from the background refresh worker.

        Args:
            result: Mapping of rule ID to offset list returned by ``_resolve_pattern_offsets``.
        """
        self._pattern_refresh_worker = None
        self._end_pattern_search_busy()
        if self._hex_widget is not None and isinstance(result, dict):
            resolved = cast("dict[str, list[int]]", result)
            rules_attr = getattr(self._hex_widget, "_highlight_rules", None)
            if isinstance(rules_attr, list):
                for rule in cast("list[Any]", rules_attr):
                    rule_id = getattr(rule, "rule_id", None)
                    if not isinstance(rule_id, str) or rule_id not in resolved:
                        continue
                    params_attr: object = getattr(rule, "condition_params", None)
                    if isinstance(params_attr, dict):
                        cast("dict[str, Any]", params_attr)["offsets"] = set(resolved[rule_id])
            update_fn = getattr(self._hex_widget, "update", None)
            if callable(update_fn):
                update_fn()
        if getattr(self, "_pattern_refresh_pending", False):
            self._pattern_refresh_pending = False
            self.refresh_pattern_highlights()

    def _on_pattern_refresh_error(self, exc: object) -> None:
        """Handle a background pattern-highlight refresh failure.

        Args:
            exc: Exception raised inside the background refresh worker.
        """
        self._pattern_refresh_worker = None
        self._end_pattern_search_busy()
        _logger.warning("highlight_pattern_refresh_batch_failed", error=str(exc), error_type=type(exc).__name__)
        if getattr(self, "_pattern_refresh_pending", False):
            self._pattern_refresh_pending = False
            self.refresh_pattern_highlights()


def _parse_pattern_matches(matches: object) -> set[int]:
    """Extract match offsets from a raw ``search_hex`` result.

    Args:
        matches: Raw return value from ``HexDocument.search_hex``: expected to be a list of
            ``(offset, length)`` tuples or bare integer offsets, but treated defensively since it
            crosses the native FFI boundary.

    Returns:
        set[int]: Set of integer byte offsets extracted from ``matches``.
    """
    offsets: set[int] = set()
    if isinstance(matches, list):
        entries: list[Any] = cast("list[Any]", matches)
        for entry in entries:
            if isinstance(entry, tuple):
                entry_tuple: tuple[Any, ...] = cast("tuple[Any, ...]", entry)
                if entry_tuple and isinstance(entry_tuple[0], int):
                    offsets.add(entry_tuple[0])
            elif isinstance(entry, int):
                offsets.add(entry)
    return offsets


def _locked_search_hex(
    search_fn: Callable[[str, int], object],
    pattern: str,
    max_matches: int,
) -> object:
    """Invoke a document's ``search_hex`` while holding the shared document lock.

    Acquires :data:`DOCUMENT_MUTATION_LOCK` for the duration of the call so
    the shared PyO3 borrow ``search_hex`` holds across its whole-document
    scan never overlaps with a concurrent exclusive borrow taken by a
    document-mutating call elsewhere in the hex editor.

    Args:
        search_fn: The document's bound ``search_hex(pattern, max_matches)`` method.
        pattern: Hex pattern string to search for.
        max_matches: Maximum number of matches to return.

    Returns:
        object: Raw match list returned by ``search_fn``.
    """
    with DOCUMENT_MUTATION_LOCK:
        return search_fn(pattern, max_matches)


def _resolve_pattern_offsets(
    search_fn: Callable[[str, int], object],
    specs: list[tuple[str, str]],
) -> dict[str, list[int]]:
    """Resolve match offsets for a batch of pattern-type highlight rules.

    Intended to run on a background :class:`~intellicrack.ui.panels.async_bridge.GenericCallableWorker`
    thread so the native whole-document ``search_hex`` scan for every active pattern rule never blocks
    the Qt event loop. A search failure for one rule is logged and skipped rather than aborting the
    remaining rules in the batch.

    Args:
        search_fn: The document's bound ``search_hex(pattern, max_matches)`` method.
        specs: List of ``(rule_id, pattern)`` tuples to resolve.

    Returns:
        dict[str, list[int]]: Mapping of rule ID to its sorted list of matching offsets. Rule IDs
        whose search failed are omitted.
    """
    resolved: dict[str, list[int]] = {}
    for rule_id, pattern in specs:
        try:
            matches = _locked_search_hex(search_fn, pattern, _HIGHLIGHT_PATTERN_MAX_MATCHES)
        except (RuntimeError, OSError, ValueError, AttributeError):
            _logger.exception("highlight_pattern_refresh_failed", pattern=pattern, rule_id=rule_id)
            continue
        resolved[rule_id] = sorted(_parse_pattern_matches(matches))
    return resolved


def build_rule_label(rule_id: str, condition_type: str, params: dict[str, Any], color: str) -> str:
    """Build a human-readable display label for a highlight rule.

    Args:
        rule_id: Unique identifier for the rule.
        condition_type: One of ``"byte_value"``, ``"byte_range"``, or ``"pattern"``.
        params: Condition parameters dict.
        color: Hex color string.

    Returns:
        str: Display label string suitable for a list widget item.
    """
    if condition_type == "byte_value":
        value: int = int(params.get("value", 0))
        return f"[{rule_id[:8]}] Byte == 0x{value:02X}  ({color})"
    if condition_type == "byte_range":
        min_val: int = int(params.get("min", 0))
        max_val: int = int(params.get("max", _BYTE_MAX))
        return f"[{rule_id[:8]}] Byte 0x{min_val:02X}-0x{max_val:02X}  ({color})"
    if condition_type == "pattern":
        pattern: str = str(params.get("pattern", ""))
        offsets_raw: object = params.get("offsets", [])
        hit_count: int = len(cast("list[Any]", offsets_raw)) if isinstance(offsets_raw, list) else 0
        return f"[{rule_id[:8]}] Pattern {pattern}  ({hit_count} hits, {color})"
    return f"[{rule_id[:8]}] {condition_type}  ({color})"
