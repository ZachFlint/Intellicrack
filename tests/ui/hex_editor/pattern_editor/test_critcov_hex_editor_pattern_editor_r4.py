# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Fourth-pass critical-coverage tests for the HexPat pattern editor mixin of the hex editor panel.

The Compile slot used to let a ``HexPatError`` escape (PD-023, now fixed), so the branch that reports a compiler error without an error
pane never ran. The test here drives the production mixin through a small widget host with the real panes built by
``_build_pattern_editor`` and calls the slot the Compile button triggers. The source that makes the real HexPat compiler fail is the
comment-only source the existing Compile gating test uses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QFrame, QVBoxLayout, QWidget

from intellicrack.ui.panels.hex_editor.pattern_editor import PatternEditorMixin


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot

    from intellicrack.ui.panels.hex_editor.pattern_code_editor import PatternCodeEditor


pytestmark = pytest.mark.usefixtures("qapp")


_COMMENT_ONLY_SOURCE: str = "// nothing but a comment\n"


class _CompileHost(PatternEditorMixin, QWidget):
    """Concrete widget host that exposes the Compile slot of the pattern editor mixin."""

    def __init__(self) -> None:
        """Create a host with none of the pattern editor panes built yet."""
        super().__init__()
        self._document = None
        self.document = None
        self._hex_widget = None
        self._file_path = None
        self._pattern_frame = None
        self._pattern_dsl_editor = None
        self._pattern_completer = None
        self._pattern_json_preview = None
        self._pattern_library_tree = None
        self._pattern_error_display = None
        self._pattern_print_output = None
        self._pattern_status_label = None
        self._pattern_visible = False
        self._compiled_json = ""
        self._main_vsplit = None
        self._interpreter = None
        self._pattern_registry = None
        self._templates_tree = None
        self._template_combo = None
        self._state_holder = None
        self.state_holder = None
        self._pattern_apply_worker = None
        self._pattern_print_buffer = None

    def build_editor(self) -> None:
        """Build the real pattern editor panes and place them inside the host."""
        frame: QFrame = self._build_pattern_editor()
        self._pattern_frame = frame
        QVBoxLayout(self).addWidget(frame)

    def drop_error_pane(self) -> None:
        """Forget the error pane so the slot sees it as not yet created."""
        self._pattern_error_display = None

    def set_compiled_json(self, text: str) -> None:
        """Seed the compiled JSON the slot is expected to discard on failure.

        Args:
            text: JSON text to hold as the compiled template.
        """
        self._compiled_json = text

    def preview_text(self) -> str:
        """Read the JSON preview pane.

        Returns:
            str: The text shown in the JSON preview pane.
        """
        preview = self._pattern_json_preview
        assert preview is not None
        return preview.toPlainText()

    def status_text(self) -> str:
        """Read the status label.

        Returns:
            str: The text shown in the status label.
        """
        label = self._pattern_status_label
        assert label is not None
        return label.text()

    def dsl_editor(self) -> PatternCodeEditor:
        """Return the DSL editor built by the mixin.

        Returns:
            PatternCodeEditor: The editor widget.
        """
        editor = self._pattern_dsl_editor
        assert editor is not None
        return editor

    @property
    def compiled_json(self) -> str:
        """The JSON text the mixin currently holds as compiled.

        Returns:
            str: The compiled template JSON, empty when nothing is compiled.
        """
        return self._compiled_json

    def do_compile(self) -> None:
        """Invoke the slot the Compile button triggers."""
        self._on_pattern_compile()


@pytest.fixture
def host(qtbot: QtBot) -> _CompileHost:
    """Create a host with every pane built.

    Args:
        qtbot: pytest-qt fixture that owns the host.

    Returns:
        _CompileHost: Host with the pattern editor panes built.
    """
    instance = _CompileHost()
    qtbot.addWidget(instance)
    instance.build_editor()
    return instance


def test_pattern_compile_hexpat_error_without_an_error_pane_still_flags_failure(host: _CompileHost) -> None:
    """A compiler rejection with no error pane to show it discards the old JSON and marks the compile as failed.

    A comment-only source has no struct declaration, so the HexPat compiler raises ``HexPatError("no struct declaration found")``. With
    the error pane forgotten, the slot has nowhere to print the message and must neither raise nor touch the other panes beyond the
    status label and the stored JSON.

    Args:
        host: Host with every pane built.
    """
    host.set_compiled_json("stale-json")
    host.dsl_editor().setPlainText(_COMMENT_ONLY_SOURCE)
    host.drop_error_pane()
    preview_before = host.preview_text()
    host.do_compile()
    assert not host.compiled_json
    assert host.status_text() == "Compilation failed"
    assert host.preview_text() == preview_before
