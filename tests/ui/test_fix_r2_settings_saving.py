# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 12: the MCP settings dialog never replaces a server by renaming, never lets one draft block a save, and never loses edits.

The gates drive the real settings dialog over a real configuration file. Renaming a server onto another's id is refused and both stay as
they were; a newly added server with no command yet does not stop everything else from being saved; an imported server whose id is taken
is kept beside the existing one; and dismissing the dialog with Escape asks what to do with unsaved changes, doing what the answer says.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QLineEdit, QListView, QMessageBox, QPushButton, QTextEdit, QWidget

from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import McpConfigDocument, McpConfigStore, McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import ApprovalStore, McpConsentGate, TrustStore, deny_all_launches
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.ui.mcp_config import McpConfigDialog
from tests._helpers.mcp_ui_support import DialogWatcher


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


_WAIT_MS: Final[int] = 10_000


def _widget[W: QWidget](root: QWidget, kind: type[W], name: str) -> W:
    """Find one named widget.

    Args:
        root: The widget to search.
        kind: The widget class.
        name: The object name.

    Returns:
        W: The widget.
    """
    found = root.findChild(kind, name)
    assert found is not None, f"no {kind.__name__} named {name!r}"
    return found


def _stdio(server_id: str, command: str) -> McpServerConfig:
    """Build a local server that is never started.

    Args:
        server_id: The id.
        command: The launch command.

    Returns:
        McpServerConfig: The configuration.
    """
    return McpServerConfig(server_id=server_id, kind=McpTransportKind.STDIO, stdio=StdioServerSpec(command=command))


class _Shown:
    """Every message box title the dialog showed, recorded instead of shown.

    Attributes:
        titles: The titles, in order.
    """

    titles: list[str]

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Record warnings, errors and notices from here on.

        Args:
            monkeypatch: Restores the message box functions afterwards.
        """
        self.titles = []
        for name in ("warning", "critical", "information"):
            monkeypatch.setattr(QMessageBox, name, self._record)

    def _record(self, _parent: object, title: str, _message: str, *_rest: object) -> QMessageBox.StandardButton:
        """Record one message box.

        Args:
            _parent: The parent widget.
            title: The box's title.
            _message: The box's text.
            *_rest: Buttons and defaults.

        Returns:
            QMessageBox.StandardButton: ``Ok``.
        """
        self.titles.append(title)
        return QMessageBox.StandardButton.Ok


@pytest.fixture
def parent(qtbot: QtBot) -> QWidget:
    """Provide a parent widget that outlives the dialog.

    Args:
        qtbot: The Qt test driver.

    Returns:
        QWidget: The parent.
    """
    widget = QWidget()
    qtbot.addWidget(widget)
    return widget


def _open(tmp_path: Path, parent: QWidget, servers: tuple[McpServerConfig, ...]) -> tuple[McpConfigDialog, McpConfigStore]:
    """Write a configuration and open the settings dialog over it.

    Args:
        tmp_path: Per-test directory.
        parent: The dialog's parent.
        servers: The configured servers.

    Returns:
        tuple[McpConfigDialog, McpConfigStore]: The dialog and its store.
    """
    store = McpConfigStore(tmp_path / "mcp.json")
    store.save(McpConfigDocument(servers=servers))
    resolver = McpSecretResolver(CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env")))
    manager = McpConnectionManager(store, resolver, McpConsentGate(TrustStore(tmp_path / "trust.json"), deny_all_launches))
    _ = manager.reload()
    dialog = McpConfigDialog(manager, resolver, parent, approvals=ApprovalStore(tmp_path / "approvals.json"))
    dialog.show()
    return dialog, store


def _select(dialog: McpConfigDialog, server_id: str) -> None:
    """Select one server in the list.

    Args:
        dialog: The dialog.
        server_id: The server.
    """
    view = _widget(dialog, QListView, "mcp_server_list")
    model = view.model()
    assert model is not None
    for row in range(model.rowCount()):
        index = model.index(row, 0)
        if str(model.data(index)).startswith(f"{server_id} - "):
            view.setCurrentIndex(index)
            return
    pytest.fail(f"server {server_id!r} is not listed")


def _listed(dialog: McpConfigDialog) -> list[str]:
    """List the server ids the dialog shows.

    Args:
        dialog: The dialog.

    Returns:
        list[str]: The ids, in list order.
    """
    view = _widget(dialog, QListView, "mcp_server_list")
    model = view.model()
    assert model is not None
    return [str(model.data(model.index(row, 0))).split(" - ", 1)[0] for row in range(model.rowCount())]


def _save(dialog: McpConfigDialog) -> None:
    """Press Save.

    Args:
        dialog: The dialog.
    """
    box = dialog.findChild(QDialogButtonBox)
    assert box is not None
    button = box.button(QDialogButtonBox.StandardButton.Save)
    assert button is not None
    button.click()


def _commands(store: McpConfigStore) -> dict[str, str]:
    """Read each saved server's command back from disk.

    Args:
        store: The configuration store.

    Returns:
        dict[str, str]: Id to command.
    """
    return {server.server_id: server.stdio.command for server in store.load().servers if server.stdio is not None}


def test_renaming_onto_an_existing_id_is_refused(tmp_path: Path, parent: QWidget, monkeypatch: pytest.MonkeyPatch) -> None:
    """Giving one server another's id and saving is refused, and both servers stay as they were.

    Args:
        tmp_path: Per-test directory.
        parent: The dialog's parent.
        monkeypatch: Records message boxes.
    """
    shown = _Shown(monkeypatch)
    dialog, store = _open(tmp_path, parent, (_stdio("alpha", "alpha-tool"), _stdio("beta", "beta-tool")))
    _select(dialog, "alpha")

    _widget(dialog, QLineEdit, "mcp_server_id").setText("beta")
    _save(dialog)

    assert shown.titles == ["Server id"]
    assert _commands(store) == {"alpha": "alpha-tool", "beta": "beta-tool"}
    assert sorted(_listed(dialog)) == ["alpha", "beta"]


def test_an_unfinished_new_server_does_not_block_saving_the_rest(tmp_path: Path, parent: QWidget, monkeypatch: pytest.MonkeyPatch) -> None:
    """A server added with no command yet is kept in the dialog unsaved, and the other edits are saved.

    Args:
        tmp_path: Per-test directory.
        parent: The dialog's parent.
        monkeypatch: Records message boxes.
    """
    shown = _Shown(monkeypatch)
    dialog, store = _open(tmp_path, parent, (_stdio("alpha", "alpha-tool"),))
    _widget(dialog, QPushButton, "mcp_add_server").click()
    _select(dialog, "alpha")
    _widget(dialog, QLineEdit, "mcp_stdio_command").setText("alpha-tool-2")

    _save(dialog)

    assert _commands(store) == {"alpha": "alpha-tool-2"}
    assert "server-1" in _listed(dialog)
    assert shown.titles == ["Saved, with servers left unfinished"]


def test_an_imported_server_with_a_taken_id_is_kept_beside_the_existing_one(
    tmp_path: Path,
    parent: QWidget,
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Importing ``GitHub`` next to an existing ``github`` keeps both, and both are saved.

    Args:
        tmp_path: Per-test directory.
        parent: The dialog's parent.
        qtbot: The Qt test driver.
        monkeypatch: Records message boxes.
    """
    _ = _Shown(monkeypatch)
    dialog, store = _open(tmp_path, parent, (_stdio("github", "existing-tool"),))

    def paste(import_dialog: QDialog) -> None:
        editor = import_dialog.findChild(QTextEdit, "mcp_import_text")
        if editor is None:
            return
        editor.setPlainText(json.dumps({"mcpServers": {"GitHub": {"command": "imported-tool"}}}))
        import_dialog.accept()

    watcher = DialogWatcher(QDialog, paste)
    try:
        _widget(dialog, QPushButton, "mcp_import_json").click()
        qtbot.waitUntil(lambda: len(_listed(dialog)) == 2, timeout=_WAIT_MS)
    finally:
        watcher.stop()
    _save(dialog)

    assert _commands(store) == {"github": "existing-tool", "github-2": "imported-tool"}


class TestEscapeAsksAboutUnsavedChanges:
    """Escape with unsaved edits asks first, and does what the operator answers."""

    @staticmethod
    def _escape_answering(
        tmp_path: Path,
        parent: QWidget,
        qtbot: QtBot,
        answer: QMessageBox.StandardButton,
    ) -> tuple[McpConfigDialog, McpConfigStore, list[QDialog]]:
        """Edit a server, press Escape, and give one answer to the question that follows.

        Args:
            tmp_path: Per-test directory.
            parent: The dialog's parent.
            qtbot: The Qt test driver.
            answer: The button to press.

        Returns:
            tuple[McpConfigDialog, McpConfigStore, list[QDialog]]: The dialog, its store, and the questions asked.
        """
        dialog, store = _open(tmp_path, parent, (_stdio("alpha", "alpha-tool"),))
        _select(dialog, "alpha")
        _widget(dialog, QLineEdit, "mcp_stdio_command").setText("edited-tool")

        def respond(box: QDialog) -> None:
            if isinstance(box, QMessageBox) and box.objectName() == "mcp_unsaved_changes":
                button = box.button(answer)
                assert button is not None
                button.click()

        watcher = DialogWatcher(QMessageBox, respond)
        try:
            qtbot.keyClick(dialog, Qt.Key.Key_Escape)
        finally:
            watcher.stop()
        return dialog, store, watcher.seen

    def test_cancel_keeps_the_dialog_and_the_edit(self, tmp_path: Path, parent: QWidget, qtbot: QtBot) -> None:
        """Cancel leaves the dialog open with the edit still in it and nothing saved.

        Args:
            tmp_path: Per-test directory.
            parent: The dialog's parent.
            qtbot: The Qt test driver.
        """
        dialog, store, asked = self._escape_answering(tmp_path, parent, qtbot, QMessageBox.StandardButton.Cancel)

        assert len(asked) == 1
        assert dialog.isVisible()
        assert _widget(dialog, QLineEdit, "mcp_stdio_command").text() == "edited-tool"
        assert _commands(store) == {"alpha": "alpha-tool"}

    def test_discard_closes_without_saving(self, tmp_path: Path, parent: QWidget, qtbot: QtBot) -> None:
        """Discard closes the dialog and leaves the file as it was.

        Args:
            tmp_path: Per-test directory.
            parent: The dialog's parent.
            qtbot: The Qt test driver.
        """
        dialog, store, asked = self._escape_answering(tmp_path, parent, qtbot, QMessageBox.StandardButton.Discard)

        assert len(asked) == 1
        assert not dialog.isVisible()
        assert _commands(store) == {"alpha": "alpha-tool"}

    def test_save_saves_then_closes(self, tmp_path: Path, parent: QWidget, qtbot: QtBot) -> None:
        """Save writes the edit and closes the dialog.

        Args:
            tmp_path: Per-test directory.
            parent: The dialog's parent.
            qtbot: The Qt test driver.
        """
        dialog, store, asked = self._escape_answering(tmp_path, parent, qtbot, QMessageBox.StandardButton.Save)

        assert len(asked) == 1
        assert not dialog.isVisible()
        assert _commands(store) == {"alpha": "edited-tool"}
