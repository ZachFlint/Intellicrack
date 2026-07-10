# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""GUI-audit regression gate for :mod:`intellicrack.ui.panels.hex_editor.yara`.

Covers the 2026-07-02 audit finding for ``yara.py``:

* M56 -- the YARA results tree's "Rule" column had no resize mode configured,
  so ``QTreeView``'s default (``Interactive`` on every section, with only the
  last section stretched) left the "Rule" column at a fixed, clipped width no
  matter how long the compiled YARA rule's identifier was. Rule names are
  exactly the field an analyst reads first when triaging matches, and real
  rulesets commonly use long, descriptive identifiers. The fix configures the
  results tree header so column 0 ("Rule") stretches to fill available space,
  columns 1-3 size to their content, ``stretchLastSection`` is disabled (so
  "Match Data" no longer eats the freed space), and each rule row also gets a
  tooltip carrying the full, untruncated rule name.

All tests drive a real ``YaraMixin`` instance (via a minimal harness exposing
only the mixin's own bound methods, following the pattern used by the sibling
``test_gui_audit_hexsub_yara_goto.py`` gate file) under an offscreen
``QApplication``, and inspect the real ``QHeaderView``/``QTreeWidgetItem``
state the fix produces.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from PyQt6.QtWidgets import (
    QApplication,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QTreeWidget,
    QWidget,
)

from intellicrack.ui.panels.hex_editor.yara import YaraMixin


if TYPE_CHECKING:
    from intellicrack.bridges.hex_editor import HexEditorBridge


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


_LONG_RULE_NAME = "Suspicious_PE_Packer_UPX_Modified_Header_Anomaly_Long_Descriptive_Rule_Identifier"


class _YaraTabHarness(YaraMixin):
    """Minimal object exposing only the attributes ``YaraMixin`` methods read.

    Instantiating the mixin directly (rather than the full hex-editor panel)
    keeps the gate focused on the mixin's own tab-construction and
    result-rendering logic, following the harness pattern used by
    ``test_gui_audit_hexsub_yara_goto.py``.
    """

    def __init__(self) -> None:
        """Initialise empty/None state matching the panel's declared attributes."""
        self._document: Any | None = None
        self.document: Any | None = None
        self._hex_widget: Any | None = None
        self._yara_rule_files: list[str] = []
        self._yara_file_count_label: QLabel | None = None
        self._yara_inline_editor: QPlainTextEdit | None = None
        self._yara_results_tree: QTreeWidget | None = None
        self._bridge: HexEditorBridge | None = None


def _build_tab(qapp: QApplication) -> tuple[_YaraTabHarness, QWidget]:
    """Construct the real YARA tab widget via the production mixin method.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.

    Returns:
        tuple[_YaraTabHarness, QWidget]: The harness (owning
        ``_yara_results_tree`` and friends) and the container widget
        ``_create_yara_tab`` returned.
    """
    del qapp
    harness = _YaraTabHarness()
    container = harness._create_yara_tab()
    return harness, container


def test_m56_rule_column_uses_stretch_others_resize_to_contents(qapp: QApplication) -> None:
    """M56: the results tree header configures per-column resize modes.

    Pre-fix, ``_create_yara_tab`` never called ``header()`` at all, so every
    column (including "Rule") stayed at Qt's default ``Interactive`` resize
    mode and only the last column ("Match Data") stretched. This asserts the
    fixed configuration: column 0 ("Rule") is ``Stretch``, columns 1-3 are
    ``ResizeToContents``, and ``stretchLastSection`` is disabled so the freed
    space goes to "Rule" instead of "Match Data".

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.
    """
    harness, container = _build_tab(qapp)
    try:
        tree = harness._yara_results_tree
        assert tree is not None
        header = tree.header()
        assert header is not None

        assert header.stretchLastSection() is False, "stretchLastSection must be disabled so 'Match Data' stops absorbing free space"
        assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.Stretch, "the 'Rule' column must stretch to fill available space"
        assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.ResizeToContents
        assert header.sectionResizeMode(2) == QHeaderView.ResizeMode.ResizeToContents
        assert header.sectionResizeMode(3) == QHeaderView.ResizeMode.ResizeToContents
    finally:
        container.deleteLater()


def test_m56_rule_column_actually_widens_with_the_panel_at_runtime(qapp: QApplication) -> None:
    """M56: the "Rule" column's real on-screen width tracks the widget size.

    This exercises the concrete runtime consequence of the ``Stretch`` resize
    mode rather than just the configured enum: with the pre-fix default
    ``Interactive`` mode, a section's pixel width is fixed once computed and
    does not grow when the containing widget is enlarged, so a long rule name
    stays clipped no matter how much room becomes available. Post-fix, the
    "Rule" section is bound to the available header width and must measurably
    widen when the container is enlarged.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.
    """
    harness, container = _build_tab(qapp)
    try:
        tree = harness._yara_results_tree
        assert tree is not None
        harness._on_yara_scan_success([{"rule": _LONG_RULE_NAME, "strings": []}])

        header = tree.header()
        assert header is not None

        container.resize(420, 300)
        container.show()
        QApplication.processEvents()
        narrow_rule_width = header.sectionSize(0)
        other_columns_narrow = tuple(header.sectionSize(i) for i in (1, 2, 3))

        container.resize(1400, 300)
        QApplication.processEvents()
        wide_rule_width = header.sectionSize(0)
        other_columns_wide = tuple(header.sectionSize(i) for i in (1, 2, 3))

        assert wide_rule_width > narrow_rule_width, (
            f"'Rule' column did not widen when the panel grew ({narrow_rule_width} -> {wide_rule_width}); "
            "it is still clipped at a fixed Interactive width"
        )
        assert other_columns_wide == other_columns_narrow, (
            "content-sized columns (Offset/Identifier/Match Data) must not grow with the panel; "
            "only the stretch column should absorb the extra space"
        )
    finally:
        container.deleteLater()


def test_m56_long_rule_name_gets_full_untruncated_tooltip(qapp: QApplication) -> None:
    """M56: a long rule name is recoverable via tooltip even if visually elided.

    Pre-fix, ``_on_yara_scan_success`` built the rule row with
    ``QTreeWidgetItem([rule_name, "", "", ""])`` and set no tooltip, so a
    clipped "Rule" cell gave the analyst no way to read the full identifier
    short of manually widening the column. Post-fix, the row's tooltip on
    column 0 carries the complete rule name regardless of the rendered width.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.
    """
    harness, container = _build_tab(qapp)
    try:
        tree = harness._yara_results_tree
        assert tree is not None
        harness._on_yara_scan_success([{"rule": _LONG_RULE_NAME, "strings": []}])

        rule_item = tree.topLevelItem(0)
        assert rule_item is not None, "scan success must add a top-level row for the match"
        assert rule_item.text(0) == _LONG_RULE_NAME
        assert rule_item.toolTip(0) == _LONG_RULE_NAME, f"expected the full rule name as the column-0 tooltip, got {rule_item.toolTip(0)!r}"
    finally:
        container.deleteLater()
