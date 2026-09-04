# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for D36: hardcoded ``Consolas`` fonts replaced by the shared stack.

Pre-fix, five sites constructed a monospace font by hardcoding the literal
family name ``"Consolas"`` directly:

* ``intellicrack.ui.panels.hex_editor.disassembly.DisassemblyMixin._create_disassembly_tab``
  (the disassembly results table)
* ``intellicrack.ui.panels.hex_editor.sandbox.SandboxMixin._create_sandbox_tab``
  (the sandbox output console)
* ``intellicrack.ui.panels.hex_editor.scripting.ScriptingMixin._create_scripting_tab``
  (both the script editor and its output console)
* ``intellicrack.ui.panels.hex_editor.yara.YaraMixin._create_yara_tab``
  (the inline YARA rule editor)
* ``intellicrack.ui.log_viewer.window.LogRecordDetailsDialog._setup_ui``
  (the per-record JSON details view)

A hardcoded family name silently diverges from whatever the rest of the
application actually renders code in (``FontManager`` loads a bundled
JetBrains Mono and only falls back toward ``Consolas``/``monospace`` when no
bundled or configured family is available), and gives users no way to have a
custom monospace preference honoured consistently across the hex editor and
log viewer.

The fix routes every site through the shared
``intellicrack.ui.resources.font_manager.FontManager`` singleton instead.
This module drives each real, unmocked widget-construction method under an
offscreen ``QApplication`` and asserts the constructed widget's font family is
exactly the family the shared ``FontManager`` singleton currently resolves --
not a literal hardcoded in the call site -- and separately scans the fixed
source files themselves so a regression that reintroduces the literal string
``"Consolas"`` is caught even if it happens to resolve to the same family the
manager would have chosen on a given machine.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from intellicrack.ui.log_viewer import LogRecordDetailsDialog, LogRecordDict
from intellicrack.ui.panels.hex_editor.disassembly import DisassemblyMixin
from intellicrack.ui.panels.hex_editor.sandbox import SandboxMixin
from intellicrack.ui.panels.hex_editor.scripting import ScriptingMixin
from intellicrack.ui.panels.hex_editor.yara import YaraMixin
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication, QWidget


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


_REPO_ROOT: Path = Path(__file__).resolve().parents[2]

_TARGET_RELATIVE_PATHS: tuple[str, ...] = (
    "src/intellicrack/ui/panels/hex_editor/disassembly.py",
    "src/intellicrack/ui/panels/hex_editor/sandbox.py",
    "src/intellicrack/ui/panels/hex_editor/scripting.py",
    "src/intellicrack/ui/panels/hex_editor/yara.py",
    "src/intellicrack/ui/log_viewer/window.py",
)


class _DisassemblyHarness(DisassemblyMixin):
    """Minimal object exposing only the attributes ``_create_disassembly_tab`` touches."""

    def __init__(self) -> None:
        """Initialise empty mixin state matching the panel's declared attributes."""
        self._document: Any | None = None
        self.document: Any | None = None
        self._hex_widget: Any | None = None
        self._disasm_arch_combo = None
        self._disasm_mode_combo = None
        self._disasm_count_spin = None
        self._disasm_follow_cursor = None
        self._disasm_table = None
        self._bridge: Any | None = None
        self._disasm_follow_timer = None
        self._disasm_pending_offset: int | None = None
        self._disasm_last_dispatched_offset: int | None = None
        self._disasm_in_flight: bool = False


class _SandboxHarness(SandboxMixin):
    """Minimal object exposing only the attributes ``_create_sandbox_tab`` touches."""

    def __init__(self) -> None:
        """Initialise empty mixin state matching the panel's declared attributes."""
        self.document: Any | None = None
        self.file_path = None
        self._bridge: Any | None = None
        self._sandbox_type_combo = None
        self._sandbox_instance_combo = None
        self._sandbox_dest_input = None
        self._sandbox_args_input = None
        self._sandbox_timeout_spin = None
        self._sandbox_output = None
        self._sandbox_status = None


class _YaraHarness(YaraMixin):
    """Minimal object exposing only the attributes ``_create_yara_tab`` touches."""

    def __init__(self) -> None:
        """Initialise empty mixin state matching the panel's declared attributes."""
        self._document: Any | None = None
        self.document: Any | None = None
        self._hex_widget: Any | None = None
        self._yara_rule_files: list[str] = []
        self._yara_file_count_label = None
        self._yara_inline_editor = None
        self._yara_results_tree = None
        self._bridge: Any | None = None


class _ScriptingHarness(ScriptingMixin):
    """Minimal object exposing only the attributes ``_create_scripting_tab`` touches."""

    def __init__(self) -> None:
        """Initialise empty mixin state matching the panel's declared attributes."""
        self.document: Any | None = None
        self._hex_widget: Any | None = None
        self.file_path = None
        self._side_tabs = None
        self._script_editor = None
        self._script_output = None
        self._script_worker = None
        self._script_status = None
        self._encoding_combo = None


def _resolved_code_font_family() -> str:
    """Return the code-font family the shared ``FontManager`` singleton currently resolves.

    Returns:
        str: The family name the production widgets are expected to carry.
    """
    return FontManager.get_instance().code_font_family


def test_disassembly_table_font_family_sourced_from_font_manager(qapp: QApplication) -> None:
    """The disassembly results table's font family matches the shared ``FontManager`` resolution.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.
    """
    del qapp
    harness = _DisassemblyHarness()
    container: QWidget = harness._create_disassembly_tab()
    try:
        table = harness._disasm_table
        assert table is not None
        assert table.font().family() == _resolved_code_font_family()
    finally:
        container.deleteLater()


def test_sandbox_output_font_family_sourced_from_font_manager(qapp: QApplication) -> None:
    """The sandbox output console's font family matches the shared ``FontManager`` resolution.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.
    """
    del qapp
    harness = _SandboxHarness()
    container: QWidget = harness._create_sandbox_tab()
    try:
        output = harness._sandbox_output
        assert output is not None
        assert output.font().family() == _resolved_code_font_family()
    finally:
        container.deleteLater()


def test_yara_inline_editor_font_family_sourced_from_font_manager(qapp: QApplication) -> None:
    """The YARA inline rule editor's font family matches the shared ``FontManager`` resolution.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.
    """
    del qapp
    harness = _YaraHarness()
    container: QWidget = harness._create_yara_tab()
    try:
        editor = harness._yara_inline_editor
        assert editor is not None
        assert editor.font().family() == _resolved_code_font_family()
    finally:
        container.deleteLater()


def test_scripting_editor_and_output_font_families_sourced_from_font_manager(qapp: QApplication) -> None:
    """Both the script editor and its output console match the shared ``FontManager`` resolution.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.
    """
    del qapp
    harness = _ScriptingHarness()
    container: QWidget = harness._create_scripting_tab()
    try:
        editor = harness._script_editor
        output = harness._script_output
        assert editor is not None
        assert output is not None
        assert editor.font().family() == _resolved_code_font_family()
        assert output.font().family() == _resolved_code_font_family()
    finally:
        container.deleteLater()


def test_log_viewer_details_dialog_font_family_sourced_from_font_manager(qapp: QApplication) -> None:
    """The log-record details dialog's text view matches the shared ``FontManager`` resolution.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.
    """
    del qapp
    record: LogRecordDict = LogRecordDict(
        timestamp="2026-08-29 00:00:00",
        level="INFO",
        logger="intellicrack.tests",
        module="m",
        function="f",
        line_number=1,
        event="monospace_font_sourcing_probe",
        extras={},
    )
    dialog = LogRecordDetailsDialog(record)
    try:
        assert dialog._text.font().family() == _resolved_code_font_family()
    finally:
        dialog.deleteLater()


def test_no_hardcoded_consolas_qfont_remains_in_target_files() -> None:
    """None of the five fixed source files may reference the literal family ``"Consolas"``.

    This is a source-level gate rather than a widget-behavior gate: it fails
    even if a reintroduced ``QFont("Consolas")`` happened to resolve to the
    same family the ``FontManager`` singleton would independently pick on a
    particular test machine, which the widget-family assertions above cannot
    distinguish on their own.
    """
    offenders: dict[str, int] = {}
    for relative_path in _TARGET_RELATIVE_PATHS:
        source = (_REPO_ROOT / relative_path).read_text(encoding="utf-8")
        count = source.count("Consolas")
        if count:
            offenders[relative_path] = count

    assert not offenders, f"hardcoded 'Consolas' literal reintroduced in: {offenders!r}"
