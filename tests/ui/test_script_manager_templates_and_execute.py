# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for two Scripts Manager defects.

* S16-D14: ``ScriptTypeInfo.get_template`` used ``str.format`` to substitute
  ``{target}``/``{address}`` placeholders, which misparsed the literal
  ``{``/``}`` code braces embedded in the frida, ghidra, and python
  templates and raised ``KeyError``/``ValueError`` instead of returning a
  template. That exception propagated out of ``ScriptManagerPanel._on_new``,
  so View > Scripts Manager > New silently failed to load a template for
  every type except Cutter and x64dbg.
* S15-D13: ``ScriptManagerPanel``'s ``Execute`` button always dispatched
  through ``self._executor``, but both production call sites
  (``ToolOutputPanel.add_script_panel`` and
  ``ToolOutputPanel.wire_script_backend`` in ``intellicrack.ui.tools``)
  constructed ``set_backend`` without an ``executor`` argument, so
  ``self._executor`` stayed ``None`` forever and every Execute click timed
  out after 30s with no script ever actually running.

All tests drive real ``ScriptManagerPanel``/``ToolOutputPanel`` widgets
under an offscreen ``QApplication`` and a real ``ScriptManager`` backend;
the Python execution path runs a genuine subprocess and asserts on its
captured stdout. Nothing here is mocked or stubbed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QMessageBox

from intellicrack.core.script_gen import ScriptManager
from intellicrack.ui.panels.script_manager import ScriptManagerPanel, ScriptTypeInfo
from intellicrack.ui.tools import ToolOutputPanel, _run_python_script


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


_ALL_SCRIPT_TYPES: Final[tuple[str, ...]] = ("frida", "ghidra", "cutter", "x64dbg", "python")


@pytest.fixture(autouse=True)
def _auto_dismiss_blocking_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auto-answer blocking ``QMessageBox`` modals so headless UI tests never hang.

    ``ScriptManagerPanel`` surfaces confirm/error modals (the unsaved-changes
    prompt in ``_on_new`` and the template-failure ``critical`` dialog). Under an
    offscreen ``QApplication`` with no user present, those static modal calls
    block forever; this replaces each with an instant non-blocking return so the
    real handler logic still runs to completion.

    Args:
        monkeypatch: Pytest fixture used to replace the blocking static methods.
    """
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.StandardButton.No)
    monkeypatch.setattr(QMessageBox, "critical", lambda *_a, **_k: QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QMessageBox, "warning", lambda *_a, **_k: QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QMessageBox, "information", lambda *_a, **_k: QMessageBox.StandardButton.Ok)


class TestS16D14ScriptTemplates:
    """Falsifiable gates for S16-D14: ``get_template`` must not crash for any script type."""

    def test_get_template_substitutes_placeholders_without_raising(self) -> None:
        """``get_template`` must return a real template with placeholders substituted for every type.

        Before the fix, ``str.format()`` misparsed the literal ``{`` / ``}``
        code braces embedded in the frida, ghidra, and python templates and
        raised ``KeyError``/``ValueError`` instead of returning a template.
        Not every template references ``{target}``/``{address}`` (ghidra
        uses its own ``currentAddress`` API instead), so only the substring
        checks are unconditional; the substituted value is asserted only for
        types whose template embeds the corresponding placeholder.
        """
        for script_type in _ALL_SCRIPT_TYPES:
            raw_template = ScriptTypeInfo.TYPES[script_type]["template"]
            template = ScriptTypeInfo.get_template(script_type, target="C:/bin/target.exe", address="0x401000")

            assert template.strip(), f"{script_type}: template is empty"
            assert "{target}" not in template, f"{script_type}: target placeholder left unsubstituted"
            assert "{address}" not in template, f"{script_type}: address placeholder left unsubstituted"
            if "{target}" in raw_template:
                assert "C:/bin/target.exe" in template, f"{script_type}: target value missing from rendered template"
            if "{address}" in raw_template:
                assert "0x401000" in template, f"{script_type}: address value missing from rendered template"

    def test_get_template_python_renders_syntactically_valid_source(self) -> None:
        """The Python template must compile as real Python after substitution, not just avoid raising."""
        rendered = ScriptTypeInfo.get_template("python", target="C:/bin/target.exe")
        compile(rendered, "<script_manager_template>", "exec")

    def test_get_template_preserves_literal_code_braces(self) -> None:
        """Frida and Ghidra templates must keep their literal ``{``/``}`` code braces intact."""
        frida_template = ScriptTypeInfo.get_template("frida", target="t.exe", address="0x1")
        assert "onEnter: function(args) {" in frida_template

        ghidra_template = ScriptTypeInfo.get_template("ghidra")
        assert "public class LicenseAnalyzer extends GhidraScript {" in ghidra_template

    def test_new_script_button_loads_template_into_editor_for_every_type(self, qapp: QApplication) -> None:
        """Scripts Manager ``New`` must populate the editor for every script type, not just Cutter/x64dbg.

        Drives the real ``ScriptManagerPanel`` widget end to end: selects
        each type in the type combo and invokes the ``New`` handler exactly
        as the toolbar button does, then asserts the editor actually
        received non-empty content and no error status was raised.

        Args:
            qapp: Session ``QApplication`` fixture required for widget construction.
        """
        panel = ScriptManagerPanel(parent=None)
        try:
            for script_type in _ALL_SCRIPT_TYPES:
                index = panel._type_combo.findData(script_type)
                assert index >= 0, f"{script_type}: not present in type combo"
                panel._type_combo.setCurrentIndex(index)

                panel._on_new()

                content = panel._editor.get_content()
                assert content.strip(), f"{script_type}: New left the editor empty"
                assert panel._status_bar.currentMessage() == "New script created"
        finally:
            panel.deleteLater()
            qapp.processEvents()


class TestS15D13ScriptExecute:
    """Falsifiable gates for S15-D13: Scripts-panel Execute must actually run scripts."""

    def test_run_python_script_captures_real_stdout(self) -> None:
        """``_run_python_script`` must run genuine Python code and capture its stdout."""
        output = _run_python_script('print("AUDIT_PY_OUTPUT:", 6 * 7)')
        assert "AUDIT_PY_OUTPUT: 42" in output

    def test_run_python_script_reports_nonzero_exit_and_stderr(self) -> None:
        """A script that raises must surface a nonzero exit code and its traceback in the captured output."""
        output = _run_python_script("raise RuntimeError('boom')")
        assert "boom" in output
        assert "[exit code 1]" in output

    def test_execute_script_dispatches_python_synchronously(self, qapp: QApplication) -> None:
        """``ToolOutputPanel._execute_script`` must run python scripts and return captured output directly.

        Args:
            qapp: Session ``QApplication`` fixture required for widget construction.
        """
        panel = ToolOutputPanel()
        try:
            result = panel._execute_script("AuditScript", "python", 'print("AUDIT_PY_OUTPUT:", 6 * 7)')
            assert result is not None
            assert "AUDIT_PY_OUTPUT: 42" in result
        finally:
            panel.deleteLater()
            qapp.processEvents()

    def test_add_script_panel_wires_a_real_executor(self, qapp: QApplication, tmp_path: Path) -> None:
        """``add_script_panel`` must wire a non-None executor into a script backend pending before panel creation.

        Before the fix, ``add_script_panel`` called ``set_backend`` without
        an ``executor`` argument, so ``self._executor`` on the panel stayed
        ``None`` forever regardless of script type.

        Args:
            qapp: Session ``QApplication`` fixture required for widget construction.
            tmp_path: Pytest-provided temporary directory for the script manager's storage.
        """
        panel = ToolOutputPanel()
        try:
            manager = ScriptManager(scripts_dir=tmp_path / "scripts")
            panel.wire_script_backend(manager)
            script_panel = panel.add_script_panel()
            assert isinstance(script_panel, ScriptManagerPanel)
            assert script_panel._executor is not None
        finally:
            panel.deleteLater()
            qapp.processEvents()

    def test_wire_script_backend_wires_executor_after_panel_exists(self, qapp: QApplication, tmp_path: Path) -> None:
        """``wire_script_backend`` must wire a non-None executor when the panel already exists.

        Before the fix, ``wire_script_backend`` called ``set_backend``
        without an ``executor`` argument for the immediate-wiring path too.

        Args:
            qapp: Session ``QApplication`` fixture required for widget construction.
            tmp_path: Pytest-provided temporary directory for the script manager's storage.
        """
        panel = ToolOutputPanel()
        try:
            script_panel = panel.add_script_panel()
            manager = ScriptManager(scripts_dir=tmp_path / "scripts")
            panel.wire_script_backend(manager)
            assert isinstance(script_panel, ScriptManagerPanel)
            assert script_panel._executor is not None
        finally:
            panel.deleteLater()
            qapp.processEvents()

    def test_execute_button_runs_python_script_and_shows_output(self, qapp: QApplication, tmp_path: Path) -> None:
        """End-to-end: Scripts tab Execute must run a real Python script and show its output.

        Reproduces the exact audited symptom (Scripts tab -> Execute ->
        "Executing..." then a 30s timeout) and asserts it no longer occurs:
        clicking Execute for a Python script must populate the result pane
        with the script's real stdout, clear the busy state, and never show
        the timeout message.

        Args:
            qapp: Session ``QApplication`` fixture required for widget construction.
            tmp_path: Pytest-provided temporary directory for the script manager's storage.
        """
        panel = ToolOutputPanel()
        try:
            manager = ScriptManager(scripts_dir=tmp_path / "scripts")
            panel.wire_script_backend(manager)
            script_panel = panel.add_script_panel()
            assert isinstance(script_panel, ScriptManagerPanel)

            type_index = script_panel._type_combo.findData("python")
            assert type_index >= 0
            script_panel._type_combo.setCurrentIndex(type_index)
            script_panel._name_edit.setText("AuditScript")
            script_panel._editor.set_content('print("AUDIT_PY_OUTPUT:", 6 * 7)')

            script_panel._on_execute()
            qapp.processEvents()

            assert not script_panel._execution_in_progress
            result_text = script_panel._result_pane.toPlainText()
            assert "AUDIT_PY_OUTPUT: 42" in result_text
            assert "timeout" not in result_text.lower()
        finally:
            panel.deleteLater()
            qapp.processEvents()
