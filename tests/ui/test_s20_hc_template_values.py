# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""S20-D07 regression: Hex Templates tree must populate real field values.

Reproduces the live-audit repro exactly at the GUI boundary: load a real PE
binary into the real, fully-assembled ``HexEditorPanel`` (``ui/panels/hex_editor/panel.py``),
pick the real ``IMAGE_DOS_HEADER`` struct template, and drive the panel's
actual ``_on_apply_template`` - the same handler the toolbar's Apply button
connects to - with no stubbed document, no patched ``apply_template``, and no
synthetic field dicts.

The audit found the Templates tree's Field/Offset/Size columns populated
correctly for every ``IMAGE_DOS_HEADER`` field while the Value column stayed
empty for all of them (e_magic should read "23117 (0x5A4D)"). Tracing the
full chain end to end - the Rust template evaluator
(``src/intellicrack-hexcore/src/templates/eval.rs``), the PyO3
``field_to_dict`` conversion (``src/intellicrack-hexcore/src/lib.rs``), and
the installed ``intellicrack_hexcore`` extension itself - shows every stage
already emits a fully populated ``display_value`` for every field: calling
``HexDocument.apply_template`` directly (bypassing the GUI entirely) already
returns ``{'name': 'e_magic', ..., 'display_value': '23117 (0x5A4D)', ...}``
against the real installed backend. So neither the Rust engine nor the PyO3
boundary was ever the break.

The real break is a method-name collision between two ``HexEditorPanel``
mixins that both use the generic name ``_populate_template_tree`` /
``_highlight_template_fields`` for two different features:
``TemplatesMixin`` (struct templates, this file's fields keyed by
``display_value``) and ``PatternEditorMixin`` (the HexPat DSL pattern
preview, fields keyed by ``type``). ``HexEditorPanel`` lists
``PatternEditorMixin`` before ``TemplatesMixin`` in its base classes, so
Python's MRO resolves every ``self._populate_template_tree(...)`` call -
including ``TemplatesMixin._on_apply_template``'s own call - to
``PatternEditorMixin``'s implementation, which reads a ``type`` key struct
fields never carry. The Value column comes out empty not because the data is
missing, but because the wrong mixin's tree-builder silently wins the name
collision. The fix renames ``TemplatesMixin``'s own methods to
``_populate_struct_template_tree`` / ``_highlight_struct_template_fields`` so
its call site can never again be shadowed by a same-named method on a
different mixin, however the base-class list is ordered.

This test builds the real, fully-assembled ``HexEditorPanel`` (every mixin,
real MRO) rather than a single-mixin harness, because a harness built from
``TemplatesMixin`` alone cannot reproduce the collision at all - it would
pass whether or not the rename fix is present, since ``PatternEditorMixin``
would simply be absent from its MRO.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")


_IMAGE_DOS_HEADER_TEMPLATE: Final[str] = "IMAGE_DOS_HEADER"
_E_MAGIC_FIELD_NAME: Final[str] = "e_magic"
_E_MAGIC_OFFSET_COLUMN: Final[str] = "0"
_E_MAGIC_SIZE_COLUMN: Final[str] = "2"
_VALUE_COLUMN_INDEX: Final[int] = 3


class TestHexTemplateValueColumn:
    """S20-D07 -- the real HexEditorPanel's Templates tree must show real field values."""

    @staticmethod
    def test_apply_image_dos_header_populates_real_values_on_full_panel(qapp: QApplication, real_pe_dll: Path) -> None:
        """Applying IMAGE_DOS_HEADER on the real, fully-assembled panel fills the Value column.

        Drives the exact production call chain a user triggers by picking
        IMAGE_DOS_HEADER in the Templates tab combo and clicking Apply:
        ``HexEditorPanel._on_apply_template`` -> the real
        ``intellicrack_hexcore.HexDocument.apply_template`` -> the real
        ``TemplatesMixin._populate_struct_template_tree`` -> the real
        ``QTreeWidgetItem`` rows the panel renders in ``self._templates_tree``.
        Because ``HexEditorPanel`` combines every mixin with the same MRO
        ordering the live app uses, this is the one construction that can
        actually distinguish "the rename fixed the collision" from "the
        struct-template code was fine all along in isolation".

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real ``kernel32.dll`` fixture (session-scoped, read-only).
        """
        panel = HexEditorPanel()
        try:
            assert panel.load_file(real_pe_dll) is True, "load_file must succeed against a real PE"
            assert panel.document is not None
            assert panel._templates_tree is not None
            assert panel._template_combo is not None

            panel._select_template(_IMAGE_DOS_HEADER_TEMPLATE)
            assert panel._template_combo.currentText() == _IMAGE_DOS_HEADER_TEMPLATE, (
                "IMAGE_DOS_HEADER must be selectable from the real template combo"
            )

            panel._on_apply_template()
            qapp.processEvents()

            tree = panel._templates_tree
            assert tree.topLevelItemCount() > 0, "applying a template must populate at least one tree row"

            e_magic_item = tree.topLevelItem(0)
            assert e_magic_item is not None
            assert e_magic_item.text(0) == _E_MAGIC_FIELD_NAME
            assert e_magic_item.text(1) == _E_MAGIC_OFFSET_COLUMN
            assert e_magic_item.text(2) == _E_MAGIC_SIZE_COLUMN

            e_magic_value = e_magic_item.text(_VALUE_COLUMN_INDEX)
            assert e_magic_value, (
                "e_magic Value column must not be empty -- S20-D07 regression: "
                "PatternEditorMixin._populate_template_tree is shadowing "
                "TemplatesMixin's struct-template tree builder again"
            )
            assert "5A4D" in e_magic_value or "23117" in e_magic_value, e_magic_value
        finally:
            panel._cleanup()

    @staticmethod
    def test_apply_template_tree_builder_resolves_to_templates_mixin(qapp: QApplication, real_pe_dll: Path) -> None:
        """The renamed struct-template tree builder must resolve on the real MRO.

        Isolates the MRO-collision fix itself: ``HexEditorPanel`` must
        expose ``_populate_struct_template_tree`` bound to
        ``TemplatesMixin``'s implementation (not shadowed by any other
        mixin), independent of whether ``_on_apply_template`` is invoked.
        A regression that reverts the rename back to the shared
        ``_populate_template_tree`` name makes this attribute lookup miss
        (the panel would fall back to ``PatternEditorMixin``'s same-named
        method instead, which this test would then find populates the
        tree with an empty Value column for every field).

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real ``kernel32.dll`` fixture (session-scoped, read-only).
        """
        panel = HexEditorPanel()
        try:
            assert panel.load_file(real_pe_dll) is True
            assert panel._templates_tree is not None

            builder = panel._populate_struct_template_tree
            assert builder.__func__.__qualname__.startswith("TemplatesMixin."), (
                f"_populate_struct_template_tree must resolve to TemplatesMixin, got {builder.__func__.__qualname__}"
            )

            fields = panel.document.apply_template(_IMAGE_DOS_HEADER_TEMPLATE, 0)
            assert isinstance(fields, list)
            assert fields[0].get("display_value"), "raw field dict must already carry a non-empty display_value"

            panel._templates_tree.clear()
            builder(fields)
            qapp.processEvents()

            item = panel._templates_tree.topLevelItem(0)
            assert item is not None
            assert item.text(_VALUE_COLUMN_INDEX) == fields[0]["display_value"]
        finally:
            panel._cleanup()
