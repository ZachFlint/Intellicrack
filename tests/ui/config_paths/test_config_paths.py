# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit5 U8 hardcoded path fix (F-0024).

These tests verify that ``ToolConfigDialog`` and ``SandboxConfigDialog``
no longer rely on the developer-specific ``D:/Intellicrack/...``
hardcoded paths cited in audit5 F-0024. Instead, defaults must derive
from :func:`intellicrack.core.config.get_project_root` so the dialogs
function on any installation root.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.config import get_project_root


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from intellicrack.ui.sandbox_config import SandboxConfigDialog
from intellicrack.ui.tool_config import ToolConfigDialog


class _ProbeToolConfigDialog(ToolConfigDialog):
    """ToolConfigDialog subclass that publishes private state for tests.

    Exposing the resolved tools directory through a class method satisfies
    basedpyright's ``reportPrivateUsage`` check while still allowing the
    regression test to inspect what default the dialog computed.
    """

    def resolved_tools_directory(self) -> Path:
        """Return the dialog's currently resolved tools directory.

        Returns:
            Path: The directory the dialog will hand to per-tool widgets.
        """
        return self._tools_directory


class _ProbeSandboxConfigDialog(SandboxConfigDialog):
    """SandboxConfigDialog subclass that publishes the displayed shared folder."""

    def displayed_shared_folder(self) -> str:
        """Return the text currently shown in the shared-folder line edit.

        Returns:
            str: The widget's textual value.
        """
        return self._shared_folder_input.text()


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Provide a process-wide QApplication for Qt widget construction.

    Yields:
        QApplication: The active Qt application instance for tests.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class TestToolConfigDialogPaths:
    """F-0024: ToolConfigDialog must default tools_directory to project root."""

    def test_default_tools_directory_uses_project_root(
        self,
        qapp: QApplication,
    ) -> None:
        """Default tools_directory must derive from get_project_root().

        Args:
            qapp: Active Qt application fixture.
        """
        del qapp
        dialog = _ProbeToolConfigDialog()
        try:
            assert dialog.resolved_tools_directory() == get_project_root() / "tools"
        finally:
            dialog.deleteLater()

    def test_default_tools_directory_is_not_hardcoded_d_drive(
        self,
        qapp: QApplication,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Default tools_directory must track get_project_root(), not a frozen literal.

        Patches the project-root resolver to a synthetic location and asserts the
        resolved tools directory follows it. A path hardcoded to
        ``D:/Intellicrack/tools`` would ignore the patched root and fail this gate
        regardless of which drive the repository actually lives on.

        Args:
            qapp: Active Qt application fixture.
            tmp_path: Pytest temp directory fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp
        synthetic_root = tmp_path / "elsewhere"
        monkeypatch.setattr("intellicrack.ui.tool_config.get_project_root", lambda: synthetic_root)
        dialog = _ProbeToolConfigDialog()
        try:
            assert dialog.resolved_tools_directory() == synthetic_root / "tools"
        finally:
            dialog.deleteLater()

    def test_explicit_tools_directory_override_respected(
        self,
        qapp: QApplication,
        tmp_path: Path,
    ) -> None:
        """Explicit tools_directory argument must override the default.

        Args:
            qapp: Active Qt application fixture.
            tmp_path: Pytest temp directory fixture.
        """
        del qapp
        custom = tmp_path / "my_tools"
        dialog = _ProbeToolConfigDialog(tools_directory=custom)
        try:
            assert dialog.resolved_tools_directory() == custom
        finally:
            dialog.deleteLater()

    def test_source_has_no_hardcoded_paths(self) -> None:
        """The tool_config source must not contain any 'D:/Intellicrack' literal."""
        source_path = get_project_root() / "src" / "intellicrack" / "ui" / "tool_config.py"
        text = source_path.read_text(encoding="utf-8")
        assert "D:/Intellicrack" not in text
        assert "D:\\Intellicrack" not in text


class TestSandboxConfigDialogPaths:
    """F-0024: SandboxConfigDialog must default shared folder to project root."""

    def test_default_shared_folder_uses_project_root(
        self,
        qapp: QApplication,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When no config file exists, shared folder defaults to project_root/sandbox_shared.

        Args:
            qapp: Active Qt application fixture.
            tmp_path: Pytest temp directory fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp
        missing_config = tmp_path / "no_such_sandbox.json"
        monkeypatch.setattr(SandboxConfigDialog, "CONFIG_FILE", missing_config)

        dialog = _ProbeSandboxConfigDialog()
        try:
            displayed = dialog.displayed_shared_folder()
            expected = str(get_project_root() / "sandbox_shared")
            assert displayed == expected
        finally:
            dialog.deleteLater()

    def test_default_shared_folder_not_hardcoded_d_drive(
        self,
        qapp: QApplication,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Default shared folder must track get_project_root(), not a frozen literal.

        Patches the project-root resolver to a synthetic location and asserts the
        displayed shared folder follows it. A path hardcoded to
        ``D:/Intellicrack/sandbox_shared`` would ignore the patched root and fail
        this gate regardless of which drive the repository actually lives on.

        Args:
            qapp: Active Qt application fixture.
            tmp_path: Pytest temp directory fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp
        missing_config = tmp_path / "no_such_sandbox.json"
        monkeypatch.setattr(SandboxConfigDialog, "CONFIG_FILE", missing_config)
        synthetic_root = tmp_path / "elsewhere"
        monkeypatch.setattr("intellicrack.ui.sandbox_config.get_project_root", lambda: synthetic_root)

        dialog = _ProbeSandboxConfigDialog()
        try:
            displayed = dialog.displayed_shared_folder()
            assert displayed == str(synthetic_root / "sandbox_shared")
        finally:
            dialog.deleteLater()

    def test_default_shared_folder_used_when_config_lacks_key(
        self,
        qapp: QApplication,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A config file missing 'shared_folder' must fall back to the project-root default.

        Args:
            qapp: Active Qt application fixture.
            tmp_path: Pytest temp directory fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp
        config_path = tmp_path / "sandbox.json"
        config_path.write_text(
            json.dumps({"enabled": True, "timeout_seconds": 300}),
            encoding="utf-8",
        )
        monkeypatch.setattr(SandboxConfigDialog, "CONFIG_FILE", config_path)

        dialog = _ProbeSandboxConfigDialog()
        try:
            displayed = dialog.displayed_shared_folder()
            expected = str(get_project_root() / "sandbox_shared")
            assert displayed == expected
        finally:
            dialog.deleteLater()

    def test_source_has_no_hardcoded_paths(self) -> None:
        """The sandbox_config source must not contain any 'D:/Intellicrack' literal."""
        source_path = get_project_root() / "src" / "intellicrack" / "ui" / "sandbox_config.py"
        text = source_path.read_text(encoding="utf-8")
        assert "D:/Intellicrack" not in text
        assert "D:\\Intellicrack" not in text
