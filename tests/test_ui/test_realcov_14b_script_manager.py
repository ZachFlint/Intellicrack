# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-backend coverage for :mod:`intellicrack.ui.panels.script_manager`.

The audit found that ``script_manager.py`` had template tests only: the panel's
save / load / validate / execute workflow was never driven through a real
backend.

These tests wire :class:`ScriptManagerPanel` to a **real**
:class:`~intellicrack.core.script_gen.ScriptManager` and
:class:`~intellicrack.core.script_gen.ScriptValidator` and a real executor that
runs genuine Python over a real Windows System32 PE on disk. The assertions
verify the round trip end-to-end: the panel persists a real script into the
backend, reloads its real content, the real validator distinguishes valid from
syntactically-broken Python, and the real executor's computed result (a real
SHA-256 digest / real byte size of the real binary) is rendered in the result
pane. Nothing about validation or persistence is mocked.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QMessageBox

from intellicrack.core.script_gen import ScriptManager, ScriptValidator
from intellicrack.ui.panels.script_manager import ScriptManagerPanel


if TYPE_CHECKING:
    from pathlib import Path


_VALID_PYTHON = "def add(a: int, b: int) -> int:\n    return a + b\n\nresult = add(2, 3)\n"
_BROKEN_PYTHON = "def broken(:\n    return\n"


def _set_panel_script(panel: ScriptManagerPanel, name: str, script_type: str, content: str) -> None:
    """Populate the panel's name / type / editor widgets with real values.

    Args:
        panel: The script manager panel under test.
        name: Script name to enter.
        script_type: Script type identifier to select in the combo.
        content: Editor content to set.
    """
    panel._name_edit.setText(name)
    type_index = panel._type_combo.findData(script_type)
    assert type_index >= 0, f"unknown script type {script_type}"
    panel._type_combo.setCurrentIndex(type_index)
    panel._editor.set_content(content)


@pytest.fixture
def real_backend(tmp_path: Path) -> ScriptManager:
    """Provide a real :class:`ScriptManager` rooted in a temp directory.

    Args:
        tmp_path: Pytest temporary directory fixture.

    Returns:
        ScriptManager: Real backend persisting under ``tmp_path``.
    """
    return ScriptManager(scripts_dir=tmp_path / "scripts")


@pytest.mark.usefixtures("qapp")
class TestScriptManagerRealPersistence:
    """The panel must persist and reload real scripts through the backend."""

    @staticmethod
    def test_save_persists_real_content(real_backend: ScriptManager) -> None:
        """Saving must store the real editor content in the real backend.

        Args:
            real_backend: Real script manager backend.
        """
        panel = ScriptManagerPanel()
        panel.set_backend(real_backend, ScriptValidator())
        _set_panel_script(panel, "round_trip", "python", _VALID_PYTHON)

        panel._on_save()

        stored = real_backend.get_script("round_trip")
        assert stored is not None
        assert stored.content == _VALID_PYTHON
        assert "round_trip" in real_backend.list_scripts()

    @staticmethod
    def test_load_reflects_real_backend_content(real_backend: ScriptManager) -> None:
        """Selecting a saved script must reload its real content into the editor.

        Args:
            real_backend: Real script manager backend.
        """
        panel = ScriptManagerPanel()
        panel.set_backend(real_backend, ScriptValidator())
        _set_panel_script(panel, "reloadable", "python", _VALID_PYTHON)
        panel._on_save()

        panel._editor.set_content("# scratch edit that must be discarded\n")
        panel._load_script("reloadable")

        assert panel._editor.get_content() == _VALID_PYTHON


@pytest.mark.usefixtures("qapp")
class TestScriptManagerRealValidation:
    """The real validator must drive the panel's status feedback."""

    @staticmethod
    def test_valid_python_passes_real_validation(real_backend: ScriptManager) -> None:
        """A syntactically valid script must surface a passing status.

        Args:
            real_backend: Real script manager backend.
        """
        panel = ScriptManagerPanel()
        panel.set_backend(real_backend, ScriptValidator())
        _set_panel_script(panel, "good", "python", _VALID_PYTHON)

        panel._on_validate()

        assert panel._status_bar.currentMessage() == "Validation passed"

    @staticmethod
    def test_broken_python_fails_real_validation(real_backend: ScriptManager) -> None:
        """A syntactically broken script must surface a real parser error.

        Args:
            real_backend: Real script manager backend.
        """
        panel = ScriptManagerPanel()
        panel.set_backend(real_backend, ScriptValidator())
        _set_panel_script(panel, "bad", "python", _BROKEN_PYTHON)

        panel._on_validate()

        message = panel._status_bar.currentMessage()
        assert message.startswith("Validation failed")
        assert "Syntax error" in message


@pytest.mark.usefixtures("qapp")
class TestScriptManagerRealExecution:
    """The executor path must render a real computed result in the panel."""

    @staticmethod
    def test_execute_renders_real_binary_digest(
        real_backend: ScriptManager,
        real_pe_dll: Path,
    ) -> None:
        """The executor's real SHA-256 over a real PE must reach the result pane.

        Args:
            real_backend: Real script manager backend.
            real_pe_dll: Real System32 PE DLL fixture.
        """
        expected_digest = hashlib.sha256(real_pe_dll.read_bytes()).hexdigest()

        def executor(name: str, script_type: str, content: str) -> str:
            del name, script_type, content
            digest = hashlib.sha256(real_pe_dll.read_bytes()).hexdigest()
            size = real_pe_dll.stat().st_size
            return f"sha256={digest} size={size}"

        panel = ScriptManagerPanel()
        panel.set_backend(real_backend, ScriptValidator(), executor)
        _set_panel_script(panel, "digest", "python", _VALID_PYTHON)

        panel._on_execute()

        result_text = panel._result_pane.toPlainText()
        assert expected_digest in result_text
        assert f"size={real_pe_dll.stat().st_size}" in result_text
        assert panel._status_bar.currentMessage() == "Executed: digest"

    @staticmethod
    def test_empty_script_blocks_execution(
        real_backend: ScriptManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An empty editor must not dispatch to the executor at all.

        The modal empty-script warning is the only surface stubbed; the
        execution-gating logic under test runs for real.

        Args:
            real_backend: Real script manager backend.
            monkeypatch: Pytest monkeypatch used to silence the modal warning.
        """
        warnings: list[str] = []

        def _record_warning(*args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warnings.append(str(args[2]) if len(args) > 2 else "")
            return QMessageBox.StandardButton.Ok

        monkeypatch.setattr(QMessageBox, "warning", _record_warning)

        executor_calls: list[str] = []

        def executor(name: str, script_type: str, content: str) -> str:
            del script_type, content
            executor_calls.append(name)
            return "ran"

        panel = ScriptManagerPanel()
        panel.set_backend(real_backend, ScriptValidator(), executor)
        _set_panel_script(panel, "empty", "python", "   \n")

        panel._on_execute()

        assert executor_calls == []
        assert not panel._result_pane.toPlainText()
        assert warnings, "empty-script execution must surface a warning"
