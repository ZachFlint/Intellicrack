# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for GUI audit findings M8, M23, M24, L11 in ``pattern_editor``.

* ``M8`` -- ``PatternEditorMixin._apply_via_interpreter`` used to call
  ``HexPatInterpreter.execute`` directly and synchronously from the "Apply at
  Cursor" click handler, freezing the Qt event loop for the full duration of
  interpretation. The fix dispatches ``execute`` onto a
  ``GenericCallableWorker`` background ``QThread`` and applies the decoded
  fields back on the GUI thread via queued signals.
* ``M23`` -- ``_on_pattern_library_clicked`` treated every non-root tree item
  as a loadable template, including category/folder nodes, so clicking a
  category silently raised (and swallowed) an exception instead of
  expanding/collapsing. The fix special-cases any item with children.
* ``M24`` -- the "User" top-level node in the pattern library tree was built
  but never populated; every template, including ones with no category, was
  bucketed under "Built-in". The fix routes uncategorised
  (``list_templates_detailed`` category == ``""``) templates to "User".
* ``L11`` -- the pattern library tree was hard-capped at 200px with no
  ``ResizeToContents`` header and no tooltip fallback when a HexPat
  community-pattern's description pragma was empty. The fix removes the hard
  cap, resizes the header to contents, and falls back the tooltip to the
  pattern's own name.

All tests drive a real :class:`HexEditorPanel` (which mixes in
``PatternEditorMixin``) against a real ``intellicrack_hexcore.HexDocument``
and/or a real ``HexPatInterpreter`` / ``PatternRegistry``; nothing here is
stubbed or mocked.
"""

from __future__ import annotations

import json
import threading
import time
from typing import TYPE_CHECKING, Any, override

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QHeaderView, QTreeWidget, QTreeWidgetItem

from intellicrack.core.hexpat import HexPatInterpreter, PatternRegistry
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from intellicrack.core.types import HexDocumentLike


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real hex documents",
)


pytestmark = pytest.mark.integration


_DELAY_S: float = 0.4
"""Artificial delay injected into the fake delayed interpreter, in seconds."""

_RETURN_BUDGET_S: float = _DELAY_S / 2
"""Maximum wall-clock time a non-blocking dispatch may take to return."""


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float) -> bool:
    """Pump the Qt event loop until ``predicate()`` is true or the timeout elapses.

    The worker's ``call_finished``/``call_error`` signals are queued
    cross-thread connections and are only delivered to their slots while the
    main-thread event loop is processing events.

    Args:
        qapp: The active QApplication whose event loop is pumped.
        predicate: Zero-argument callable polled after each pump.
        timeout_s: Maximum number of seconds to wait.

    Returns:
        bool: ``True`` if ``predicate()`` became true before the timeout.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(0.02)
    return predicate()


def _find_top_level_item(tree: QTreeWidget, text: str) -> QTreeWidgetItem | None:
    """Find a top-level tree item by its column-0 text.

    Args:
        tree: The tree widget to search.
        text: The exact column-0 text to match.

    Returns:
        QTreeWidgetItem | None: The matching top-level item, or ``None``.
    """
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        if item is not None and item.text(0) == text:
            return item
    return None


def _find_child_item(parent: QTreeWidgetItem, text: str) -> QTreeWidgetItem | None:
    """Find a direct child item by its column-0 text.

    Args:
        parent: The parent tree item whose children are searched.
        text: The exact column-0 text to match.

    Returns:
        QTreeWidgetItem | None: The matching child item, or ``None``.
    """
    for i in range(parent.childCount()):
        child = parent.child(i)
        if child is not None and child.text(0) == text:
            return child
    return None


class _DelayedInterpreter(HexPatInterpreter):
    """``HexPatInterpreter`` whose ``execute`` imposes an artificial delay.

    Lets a test distinguish a non-blocking worker-thread dispatch (the
    caller returns well before ``execute`` finishes) from the pre-fix
    in-line call (the caller only returns once ``execute``, including the
    delay, has completed). Also records the name of the thread ``execute``
    actually ran on, so the test can prove it was not the Qt GUI thread.
    """

    def __init__(self, delay_s: float) -> None:
        """Initialise the delayed interpreter.

        Args:
            delay_s: Number of seconds ``execute`` sleeps for before
                performing the real interpretation.
        """
        super().__init__()
        self._delay_s: float = delay_s
        self.execute_thread_names: list[str] = []

    @override
    def execute(
        self,
        source: str,
        document: HexDocumentLike,
        offset: int = 0,
        file_path: Path | None = None,
    ) -> list[dict[str, Any]]:
        """Record the calling thread, sleep, then perform the real execution.

        Args:
            source: The .hexpat source code to interpret.
            document: A HexDocument PyO3 object or read/length-compatible object.
            offset: Base offset in the binary data to start parsing.
            file_path: Path to the source file for #include resolution and error messages.

        Returns:
            list[dict[str, Any]]: The real ``ParsedField``-compatible dicts produced by
            ``HexPatInterpreter.execute``.
        """
        self.execute_thread_names.append(threading.current_thread().name)
        time.sleep(self._delay_s)
        return super().execute(source, document, offset, file_path)


class TestM8ApplyViaInterpreterRunsOffGuiThread:
    """M8: ``_apply_via_interpreter`` dispatches interpretation to a background worker."""

    def test_m8_apply_via_interpreter_returns_before_delayed_execute_completes(self, qapp: QApplication) -> None:
        """The click-handler path returns almost immediately, well before ``execute`` finishes.

        Pre-fix, ``_apply_via_interpreter`` called
        ``interpreter.execute(source, self.document, offset)`` directly on
        the calling (GUI) thread, so it would not return until the full
        artificial delay plus the real interpretation had elapsed, and the
        status label and templates tree would already reflect the finished
        result by the time the call returned. Post-fix, execution is
        dispatched to a ``GenericCallableWorker`` QThread, so the call
        returns in a small fraction of the delay, the status label reads
        "Executing...", and the templates tree is still empty until the
        queued ``call_finished`` signal is delivered on a later event-loop
        pump.

        Args:
            qapp: The shared QApplication fixture.
        """
        document = hexcore.HexDocument.open_bytes(bytes(range(64)))
        panel = HexEditorPanel()
        panel.document = document
        interpreter = _DelayedInterpreter(_DELAY_S)
        panel._interpreter = interpreter
        try:
            status_label = panel._pattern_status_label
            templates_tree = panel._templates_tree
            assert status_label is not None
            assert templates_tree is not None

            start = time.monotonic()
            panel._apply_via_interpreter("u8 v @ 0;", 0)
            elapsed = time.monotonic() - start

            assert elapsed < _RETURN_BUDGET_S, (
                f"_apply_via_interpreter blocked the calling thread for {elapsed:.3f}s waiting on a "
                f"{_DELAY_S}s HexPatInterpreter.execute call instead of dispatching it to a background worker"
            )
            assert status_label.text() == "Executing...", (
                f"expected an in-flight status of 'Executing...' immediately after the call returned, "
                f"got {status_label.text()!r}; the interpreter must have run synchronously"
            )
            assert templates_tree.topLevelItemCount() == 0, (
                "the templates tree was already populated before the worker could have finished; "
                "execute() ran synchronously on the calling thread"
            )

            completed = _pump_until(
                qapp,
                lambda: status_label.text().startswith("Executed at offset"),
                timeout_s=_DELAY_S + 5.0,
            )
            assert completed, "pattern execution never completed after pumping the Qt event loop"

            assert templates_tree.topLevelItemCount() == 1
            assert templates_tree.topLevelItem(0) is not None
            field_item = templates_tree.topLevelItem(0)
            assert field_item is not None
            assert field_item.text(0) == "v"

            assert interpreter.execute_thread_names, "HexPatInterpreter.execute was never invoked"
            assert interpreter.execute_thread_names[0] != threading.main_thread().name, (
                "HexPatInterpreter.execute ran on the Qt GUI thread instead of a background worker thread"
            )
        finally:
            panel.deleteLater()


class TestM23CategoryNodeTogglesExpansionInsteadOfLoading:
    """M23: clicking a category/folder node toggles expansion instead of loading a template."""

    def test_m23_clicking_category_node_toggles_expansion_not_treated_as_template(self, qapp: QApplication) -> None:
        """Clicking the "PE" category under "Built-in" expands it, not loads it as a template.

        Pre-fix, ``_on_pattern_library_clicked`` only special-cased items
        whose ``parent()`` is ``None``; a category node like "PE" (parent is
        the "Built-in" root) fell through to
        ``self.document.export_template_json("PE")``, which raises because
        no template is literally named "PE", and the exception is logged and
        swallowed -- ``PE.isExpanded()`` is never touched. Post-fix, any item
        with children is expanded/collapsed directly and returns before the
        template-loading branch runs.

        Args:
            qapp: The shared QApplication fixture.
        """
        _ = qapp
        document = hexcore.HexDocument.open_bytes(bytes(64))
        panel = HexEditorPanel()
        panel.document = document
        try:
            panel._populate_pattern_library()
            tree = panel._pattern_library_tree
            status_label = panel._pattern_status_label
            assert tree is not None
            assert status_label is not None

            builtin_root = _find_top_level_item(tree, "Built-in")
            assert builtin_root is not None
            pe_category = _find_child_item(builtin_root, "PE")
            assert pe_category is not None
            assert pe_category.childCount() > 0, "test premise: the PE category has child templates"
            assert not pe_category.isExpanded(), "test premise: PE category starts collapsed"

            panel._on_pattern_library_clicked(pe_category, 0)

            assert pe_category.isExpanded(), (
                "clicking the PE category node did not expand it; it was treated as a loadable "
                "template (export_template_json('PE')) instead of a folder"
            )
            assert not panel._compiled_json, (
                "_compiled_json was mutated by clicking a category node, as though it were a real template name"
            )
            assert status_label.text() != "Loaded: PE", "the category label was loaded as if it were a template"

            panel._on_pattern_library_clicked(pe_category, 0)
            assert not pe_category.isExpanded(), "a second click did not collapse the category back"
        finally:
            panel.deleteLater()

    def test_m23_clicking_leaf_template_still_loads_it(self, qapp: QApplication) -> None:
        """A real leaf template item (no children) is still loaded on click.

        Guards against an overly broad fix that would stop leaf templates
        from loading at all.

        Args:
            qapp: The shared QApplication fixture.
        """
        _ = qapp
        document = hexcore.HexDocument.open_bytes(bytes(64))
        panel = HexEditorPanel()
        panel.document = document
        try:
            panel._populate_pattern_library()
            tree = panel._pattern_library_tree
            assert tree is not None
            builtin_root = _find_top_level_item(tree, "Built-in")
            assert builtin_root is not None
            pe_category = _find_child_item(builtin_root, "PE")
            assert pe_category is not None
            assert pe_category.childCount() > 0

            leaf_item = pe_category.child(0)
            assert leaf_item is not None
            assert leaf_item.childCount() == 0, "test premise: leaf template item has no children"
            leaf_name = leaf_item.text(0)

            panel._on_pattern_library_clicked(leaf_item, 0)

            preview = panel._pattern_json_preview
            status_label = panel._pattern_status_label
            assert preview is not None
            assert status_label is not None
            assert status_label.text() == f"Loaded: {leaf_name}"
            assert preview.toPlainText()
        finally:
            panel.deleteLater()


class TestM24UserRootPopulatedFromUncategorisedTemplates:
    """M24: uncategorised templates are attached to the "User" root, which is no longer dead."""

    def test_m24_imported_template_without_category_appears_under_user_root(self, qapp: QApplication) -> None:
        """A JSON template registered with no ``category`` key lands under "User".

        Pre-fix, ``user_root`` was created and added to the tree but no code
        path ever called ``user_root.addChild(...)``; every template,
        regardless of category, was bucketed into ``builtin_root`` via the
        name-prefix heuristic. Post-fix, ``list_templates_detailed()``'s
        empty category string routes the template to ``user_root``.

        Args:
            qapp: The shared QApplication fixture.
        """
        _ = qapp
        document = hexcore.HexDocument.open_bytes(bytes(64))
        template_json = json.dumps({
            "name": "MY_CUSTOM_STRUCT",
            "description": "A user-imported template with no category",
            "default_endianness": "little",
            "fields": [
                {"name": "a", "field_type": {"type": "UInt8"}, "description": ""},
            ],
        })
        registered_name = document.register_json_template(template_json)
        assert registered_name == "MY_CUSTOM_STRUCT"

        panel = HexEditorPanel()
        panel.document = document
        try:
            panel._populate_pattern_library()
            tree = panel._pattern_library_tree
            assert tree is not None

            user_root = _find_top_level_item(tree, "User")
            assert user_root is not None
            assert user_root.childCount() > 0, (
                "the User root has no children; uncategorised templates are never attached to it and the node is permanently empty"
            )
            child_names = {user_root.child(i).text(0) for i in range(user_root.childCount()) if user_root.child(i) is not None}
            assert "MY_CUSTOM_STRUCT" in child_names

            builtin_root = _find_top_level_item(tree, "Built-in")
            assert builtin_root is not None
            for cat_idx in range(builtin_root.childCount()):
                category_item = builtin_root.child(cat_idx)
                assert category_item is not None
                assert _find_child_item(category_item, "MY_CUSTOM_STRUCT") is None, (
                    "the uncategorised template leaked into a Built-in category instead of User"
                )
        finally:
            panel.deleteLater()


class TestL11PatternLibraryTreeWidthAndTooltipFallback:
    """L11: the library tree is no longer width-capped and tooltips fall back to the pattern name."""

    def test_l11_library_tree_resizes_to_contents_instead_of_hard_capped(self, qapp: QApplication) -> None:
        """The tree's header resizes to contents and its width is no longer hard-capped at 200px.

        Pre-fix, ``setMaximumWidth(200)`` permanently capped the pane
        regardless of content. Post-fix a minimum width replaces the cap and
        the header section resize mode is ``ResizeToContents``.

        Args:
            qapp: The shared QApplication fixture.
        """
        _ = qapp
        panel = HexEditorPanel()
        try:
            tree = panel._pattern_library_tree
            assert tree is not None
            assert tree.minimumWidth() == 150
            assert tree.maximumWidth() > 1000, f"tree.maximumWidth() == {tree.maximumWidth()}; the 200px hard cap is still in effect"
            header = tree.header()
            assert header is not None
            assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.ResizeToContents, (
                "the Templates column is not configured to resize to its contents"
            )
            assert tree.horizontalScrollBarPolicy() == Qt.ScrollBarPolicy.ScrollBarAsNeeded
        finally:
            panel.deleteLater()

    def test_l11_hexpat_entry_tooltip_falls_back_to_name_when_description_empty(
        self,
        qapp: QApplication,
        tmp_path: Path,
    ) -> None:
        """A community pattern with no ``#pragma description`` gets a name-fallback tooltip.

        Pre-fix, ``tooltip = pattern.description or ""`` left the tooltip
        empty for any pattern without a description pragma, so an elided
        long name had no way to be read in full. Post-fix, the tooltip falls
        back to the pattern's own name.

        Args:
            qapp: The shared QApplication fixture.
            tmp_path: Pytest temporary directory fixture.
        """
        _ = qapp
        category_dir = tmp_path / "community"
        category_dir.mkdir()
        (category_dir / "dotnet_binaryformatter.hexpat").write_text(
            "struct S { u8 x; };\n",
            encoding="utf-8",
        )
        (category_dir / "described_pattern.hexpat").write_text(
            '#pragma description "A described pattern"\nstruct S { u8 x; };\n',
            encoding="utf-8",
        )

        registry = PatternRegistry([tmp_path])
        document = hexcore.HexDocument.open_bytes(bytes(16))
        panel = HexEditorPanel()
        panel.document = document
        panel._pattern_registry = registry
        try:
            panel._populate_hexpat_library_entries()
            tree = panel._pattern_library_tree
            assert tree is not None

            hexpat_root = _find_top_level_item(tree, "HexPat Patterns")
            assert hexpat_root is not None
            category_item = _find_child_item(hexpat_root, "community")
            assert category_item is not None

            no_desc_item = _find_child_item(category_item, "dotnet_binaryformatter")
            assert no_desc_item is not None
            assert no_desc_item.toolTip(0) == "dotnet_binaryformatter", (
                f"expected the tooltip to fall back to the pattern name, got {no_desc_item.toolTip(0)!r}"
            )

            described_item = _find_child_item(category_item, "described_pattern")
            assert described_item is not None
            assert described_item.toolTip(0) == "A described pattern"
        finally:
            panel.deleteLater()
