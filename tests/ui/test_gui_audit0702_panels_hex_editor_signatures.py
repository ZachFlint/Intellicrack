# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the GUI audit findings M54 and L12 in ``hex_editor.signatures``.

M54: ``_sig_db_path_label`` was created as ``QLabel("(none)")`` with no
``setWordWrap(True)`` and no tooltip. Because ``_on_select_sig_db`` sets the
label's text to an arbitrary, user-controlled filename
(``Path(db_path).name``), a long descriptive signature-database filename
either overflowed the narrow side-panel tab or was clipped, with no way to
recover the full name by hovering. The fix enables word wrap on the label,
seeds an initial tooltip, and updates the tooltip to the full path whenever a
database is selected.

L12: ``_sig_results_tree`` was configured with ``setRootIsDecorated(False)``
and ``setAlternatingRowColors(True)`` but no header resize mode and no
per-item tooltips, even though the "Details" column can hold an arbitrarily
long YARA namespace/meta/tags repr and "Name" holds unbounded
signature/rule names from user-supplied database files. The fix sets every
header section to ``QHeaderView.ResizeMode.ResizeToContents`` (so columns
grow to fit real content instead of clipping at a fixed default width) and
sets a full-text tooltip on every populated cell.

Every test below drives the real ``SignaturesMixin`` implementation (no
mocks standing in for the mixin logic) under an offscreen ``QApplication``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QHeaderView, QWidget

from intellicrack.ui.panels.hex_editor import signatures as signatures_module
from intellicrack.ui.panels.hex_editor.signatures import SignaturesMixin


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.usefixtures("qapp")


class _SignaturesHost(SignaturesMixin):
    """Minimal host exposing only the state ``SignaturesMixin`` touches.

    Mirrors the attribute surface ``HexEditorPanel`` provides to the mixin
    (``document``, ``file_path``, ``_hex_widget``, and the signature-tab
    widget references), without pulling in the rest of the real panel.
    """

    def __init__(self) -> None:
        """Initialise empty document/widget/worker state."""
        self.document = None
        self.file_path = None
        self._hex_widget = None
        self._sig_db_type_combo = None
        self._sig_db_path_label = None
        self._sig_results_tree = None
        self._sig_worker = None
        self._sig_db_path = ""
        self._bridge = None
        self._tab_container: QWidget | None = None

    def build_tab(self) -> QWidget:
        """Create the signatures tab and retain it for the host's lifetime.

        ``_create_signatures_tab`` returns an unparented container ``QWidget``
        that owns the label and results-tree children. Without holding a
        reference to it, Python's garbage collector reclaims the container
        between statements, taking its C++ children with it and leaving the
        ``self._sig_db_path_label`` / ``self._sig_results_tree`` wrappers
        dangling. Storing it here keeps the whole widget tree alive for as
        long as the host object is referenced by the test.

        Returns:
            QWidget: The constructed, retained signatures-tab container.
        """
        self._tab_container = self._create_signatures_tab()
        return self._tab_container


def test_m54_label_has_word_wrap_enabled() -> None:
    """``_sig_db_path_label`` must have word wrap enabled after tab construction.

    Pre-fix the label was built with ``QLabel("(none)")`` and no
    ``setWordWrap(True)`` call, so ``wordWrap()`` reports Qt's default
    ``False`` and long filenames paint on a single, overflowing/clipped line.
    """
    host = _SignaturesHost()
    host.build_tab()
    label = host._sig_db_path_label
    assert label is not None
    assert label.wordWrap() is True, (
        "_sig_db_path_label was not built with setWordWrap(True); long filenames will "
        "overflow or clip instead of wrapping onto multiple lines"
    )


def test_m54_long_filename_grows_taller_at_narrow_width_instead_of_clipping() -> None:
    """A long database display name must wrap to more lines at a narrow width than at a wide one.

    Drives the real ``QLabel.heightForWidth`` layout math on the actual label:
    with ``setWordWrap(True)`` a long, multi-word database name must break onto
    several lines at the narrow side-panel width and so report a greater height
    than at a wide width where it fits on one line. The name carries genuine
    word boundaries because ``QLabel`` word wrap breaks at whitespace; without
    the ``setWordWrap(True)`` fix the height would not grow as the width
    shrinks, so this assertion is falsified by removing the fix.
    """
    host = _SignaturesHost()
    host.build_tab()
    label = host._sig_db_path_label
    assert label is not None
    label.setText("Win32 Trojan Generic Backdoor Signature Database 2026 Extended Variant NDB")

    narrow_height = label.heightForWidth(60)
    wide_height = label.heightForWidth(4000)

    assert narrow_height > wide_height, (
        f"label height at a narrow width ({narrow_height}px) is not taller than at a wide "
        f"width ({wide_height}px); word wrap is not breaking the long name onto multiple lines"
    )


def test_m54_initial_tooltip_matches_placeholder_text() -> None:
    """The label must carry a tooltip from construction, before any selection.

    Pre-fix no tooltip was ever attached, so ``toolTip()`` returns the Qt
    default empty string.
    """
    host = _SignaturesHost()
    host.build_tab()
    label = host._sig_db_path_label
    assert label is not None
    assert label.toolTip() == "(none)", "label was constructed without a tooltip matching its placeholder text"


def test_m54_selecting_database_sets_tooltip_to_full_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Selecting a database must set the tooltip to the full, un-clipped path.

    Reproduces the finding's failure scenario: a long, descriptive signature
    database filename. Post-fix the label text is the short display name
    while the tooltip recovers the full path on hover; pre-fix no tooltip is
    ever set, so ``toolTip()`` stays empty regardless of what was selected.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory fixture.
    """
    host = _SignaturesHost()
    host.build_tab()
    label = host._sig_db_path_label
    assert label is not None

    long_name = "win32_trojan_generic_backdoor_signature_database_2026_extended_variant.ndb"
    db_file = tmp_path / long_name
    db_file.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        signatures_module.QFileDialog,
        "getOpenFileName",
        staticmethod(lambda *_a, **_k: (str(db_file), "All Files (*)")),
    )

    host._on_select_sig_db()

    assert label.text() == long_name
    assert label.toolTip() == str(db_file), (
        "tooltip was not updated to the full database path after selection; a long filename "
        "clipped or wrapped in the label cannot be recovered by hovering"
    )


def test_l12_results_header_resizes_to_contents_and_stretches_last_section() -> None:
    """Every header section must use ``ResizeToContents``, with the last section stretched.

    Pre-fix the header was never touched, so it stayed on Qt's default
    ``Interactive`` resize mode with a fixed default section width,
    regardless of how long the populated cell text is.
    """
    host = _SignaturesHost()
    host.build_tab()
    tree = host._sig_results_tree
    assert tree is not None
    header = tree.header()
    assert header is not None

    for column in range(tree.columnCount()):
        mode = header.sectionResizeMode(column)
        assert mode == QHeaderView.ResizeMode.ResizeToContents, (
            f"column {column} header resize mode is {mode!r}, not ResizeToContents; "
            "long cell content will be clipped at the default fixed section width"
        )
    assert header.stretchLastSection() is True, "last section (Details) does not stretch to fill remaining width"


def test_l12_name_column_width_grows_to_fit_a_long_signature_name() -> None:
    """The Name column must widen past its default width to fit a long, real signature name.

    Populates the tree through the real ``_on_sig_scan_finished`` handler
    with a long rule name (mirroring an unbounded, user-supplied YARA/DIE
    signature name) and asserts the rendered column width is at least as
    wide as the text itself. Pre-fix, with no resize-mode call, the column
    stays at Qt's default fixed section width and clips the name.
    """
    host = _SignaturesHost()
    container = host.build_tab()
    assert isinstance(container, QWidget)
    tree = host._sig_results_tree
    assert tree is not None
    container.resize(320, 240)
    container.show()
    QApplication.processEvents()

    long_name = "SuperLongSignatureRuleName_" + "x" * 60
    matches: list[object] = [
        {"name": long_name, "type": "ndb", "version": "", "offset": 0, "details": "match"},
    ]
    host._on_sig_scan_finished(matches)
    QApplication.processEvents()

    fm = tree.fontMetrics()
    needed_width = fm.horizontalAdvance(long_name)
    actual_width = tree.columnWidth(0)
    container.close()

    assert actual_width >= needed_width, (
        f"Name column width ({actual_width}px) is narrower than the rendered signature name "
        f"({needed_width}px); the column did not resize to fit its content"
    )


def test_l12_scan_results_populate_full_text_tooltips_for_every_column() -> None:
    """Populated rows must carry a full-text tooltip on every column, not just Details.

    Uses a YARA-style match whose ``details`` string embeds a namespace,
    meta dict, and tags list -- exactly the unbounded-length payload
    described by the finding. Pre-fix no tooltip is ever set, so hovering
    over a clipped Name or Details cell reveals nothing.
    """
    host = _SignaturesHost()
    host.build_tab()
    tree = host._sig_results_tree
    assert tree is not None

    long_name = "SuperLongSignatureRuleName_" + "x" * 80
    long_details = (
        "Namespace: default, Meta: {'author': 'vendor', 'threat_family': 'generic_backdoor'}, "
        "Tags: ['packed', 'obfuscated', 'network', 'persistence']"
    )
    matches: list[object] = [
        {
            "name": long_name,
            "type": "YARA",
            "version": "1.0",
            "offset": 0x1000,
            "details": long_details,
        },
    ]

    host._on_sig_scan_finished(matches)

    assert tree.topLevelItemCount() == 1
    item = tree.topLevelItem(0)
    assert item is not None
    assert item.toolTip(0) == long_name, "Name column tooltip does not expose the full, un-clipped signature name"
    assert item.toolTip(3) == "0x00001000", "Offset column tooltip does not match the rendered cell text"
    assert item.toolTip(4) == long_details, "Details column tooltip does not expose the full match details"
