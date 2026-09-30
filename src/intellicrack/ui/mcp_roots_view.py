# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The Roots tab of MCP Settings: which folders one server is told it may work in.

The tab edits the selected server's :class:`~intellicrack.mcp.config.McpRootsSpec` -- whether it is offered roots at all, whether the
session's folders are among them and which of those it is not told about, and folders offered to it alone -- and the folders the
operator added to the session, which every server that includes the session's folders is offered. Below the settings it lists exactly
what the server is offered as they stand, each root's ``file://`` URI beside its name, and, for a sandboxed server, whether the sandbox
lets it write there.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from intellicrack.mcp.config import McpRootsSpec
from intellicrack.mcp.roots import root_key
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from collections.abc import Sequence

    from intellicrack.mcp.roots import McpRoot


_CODE_FONT_POINT_SIZE: Final[int] = 9
_FOLDERS_MAX_HEIGHT: Final[int] = 128


def _lines(text: str) -> tuple[str, ...]:
    """Split a one-folder-per-line block into its folders.

    Args:
        text: The block the operator typed.

    Returns:
        tuple[str, ...]: The non-blank lines, stripped, in order.
    """
    return tuple(line.strip() for line in text.splitlines() if line.strip())


def describe_root(root: McpRoot) -> str:
    """Render one offered root for the list of what a server is offered.

    Args:
        root: The root.

    Returns:
        str: Its name and URI, and whether a sandbox lets the server write there.
    """
    access = "" if root.writable is None else (" (sandbox: writable)" if root.writable else " (sandbox: read only)")
    return f"{root.name}{access}\n{root.uri}"


class McpRootsView(QWidget):
    """Edits one server's roots and the session's own folders.

    Emits ``changed()`` whenever the operator changes anything.
    """

    changed = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Build an empty view.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._loading = False
        self._unlisted_exclusions: tuple[str, ...] = ()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._enabled_box = QCheckBox("Offer roots to this server")
        self._enabled_box.setObjectName("mcp_roots_enabled")
        self._enabled_box.setToolTip("Off withdraws the roots capability, so the server is never told which folders you work in.")
        self._enabled_box.toggled.connect(self._on_edited)
        layout.addWidget(self._enabled_box)

        self._include_box = QCheckBox("Include this session's folders")
        self._include_box.setObjectName("mcp_roots_include_session")
        self._include_box.toggled.connect(self._on_edited)
        layout.addWidget(self._include_box)

        layout.addWidget(QLabel("Session folders this server is told about (untick one to hide it from this server):"))
        self._session_list = QListWidget()
        self._session_list.setObjectName("mcp_roots_session_list")
        self._session_list.itemChanged.connect(self._on_session_item_changed)
        layout.addWidget(self._session_list)

        layout.addWidget(QLabel("Folders for this server only:"))
        self._folders_edit = self._folder_editor("mcp_roots_folders", "one absolute folder per line")
        layout.addLayout(self._with_add_button(self._folders_edit, "mcp_roots_add_folder", "Folder this server may work in"))

        layout.addWidget(QLabel("What this server is offered:"))
        self._effective_list = QListWidget()
        self._effective_list.setObjectName("mcp_roots_effective")
        layout.addWidget(self._effective_list)

        layout.addWidget(QLabel("Folders added to this session, offered to every server that includes the session's folders:"))
        self._session_folders_edit = self._folder_editor("mcp_session_folders", "one absolute folder per line")
        layout.addLayout(
            self._with_add_button(self._session_folders_edit, "mcp_session_add_folder", "Folder to add to this session"),
        )

    def _folder_editor(self, name: str, placeholder: str) -> QPlainTextEdit:
        """Build a one-folder-per-line editor.

        Args:
            name: Its object name.
            placeholder: Its placeholder text.

        Returns:
            QPlainTextEdit: The editor.
        """
        editor = QPlainTextEdit()
        editor.setObjectName(name)
        editor.setPlaceholderText(placeholder)
        editor.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        editor.setMaximumHeight(_FOLDERS_MAX_HEIGHT)
        editor.textChanged.connect(self._on_edited)
        return editor

    def _with_add_button(self, editor: QPlainTextEdit, name: str, caption: str) -> QHBoxLayout:
        """Put a folder editor beside a button that appends a chosen folder to it.

        Args:
            editor: The editor.
            name: The button's object name.
            caption: The folder picker's caption.

        Returns:
            QHBoxLayout: The row.
        """
        row = QHBoxLayout()
        row.addWidget(editor)
        button = QPushButton("Add folder...")
        button.setObjectName(name)

        def _add() -> None:
            """Append a folder the operator picks."""
            chosen = QFileDialog.getExistingDirectory(self, caption)
            if chosen:
                current = editor.toPlainText().rstrip("\n")
                editor.setPlainText(f"{current}\n{chosen}" if current else chosen)

        button.clicked.connect(_add)
        row.addWidget(button, alignment=Qt.AlignmentFlag.AlignTop)
        return row

    def load(self, spec: McpRootsSpec, session: Sequence[McpRoot], session_folders: Sequence[str]) -> None:
        """Show one server's roots settings.

        Args:
            spec: The server's roots settings.
            session: The session's roots, as they stand with ``session_folders``.
            session_folders: The folders the operator added to the session.
        """
        self._loading = True
        try:
            self._enabled_box.setChecked(spec.enabled)
            self._include_box.setChecked(spec.include_session)
            self._folders_edit.setPlainText("\n".join(spec.folders))
            self._session_folders_edit.setPlainText("\n".join(session_folders))
            self._fill_session(session, spec.exclude)
        finally:
            self._loading = False
        self._sync_enabled()

    def show_session(self, session: Sequence[McpRoot]) -> None:
        """Replace the session's roots listed, keeping which are hidden from this server.

        Args:
            session: The session's roots.
        """
        exclude = self.spec().exclude
        self._loading = True
        try:
            self._fill_session(session, exclude)
        finally:
            self._loading = False

    def _fill_session(self, session: Sequence[McpRoot], exclude: Sequence[str]) -> None:
        """List the session's roots, ticking those not hidden from this server.

        Exclusions of folders the session does not hold now are kept, so a
        server stays hidden from a folder that comes back later.

        Args:
            session: The session's roots.
            exclude: The folders hidden from this server.
        """
        excluded = {root_key(entry): entry for entry in exclude}
        listed = {root_key(root.path) for root in session}
        self._unlisted_exclusions = tuple(entry for key, entry in excluded.items() if key not in listed)
        self._session_list.clear()
        for root in session:
            item = QListWidgetItem(f"{root.name}\n{root.path}")
            item.setData(Qt.ItemDataRole.UserRole, root.path)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked if root_key(root.path) in excluded else Qt.CheckState.Checked)
            self._session_list.addItem(item)

    def show_effective(self, roots: Sequence[McpRoot]) -> None:
        """List what the server is offered.

        Args:
            roots: The server's roots as they stand.
        """
        self._effective_list.clear()
        if not roots:
            self._effective_list.addItem("Nothing: this server is not told about any folder.")
            return
        for root in roots:
            self._effective_list.addItem(describe_root(root))

    def spec(self) -> McpRootsSpec:
        """Build the roots settings the operator described.

        Returns:
            McpRootsSpec: The settings.
        """
        hidden: list[str] = list(self._unlisted_exclusions)
        for row in range(self._session_list.count()):
            item = self._session_list.item(row)
            if item is not None and item.checkState() is Qt.CheckState.Unchecked:
                path: object = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(path, str):
                    hidden.append(path)
        return McpRootsSpec(
            enabled=self._enabled_box.isChecked(),
            include_session=self._include_box.isChecked(),
            folders=_lines(self._folders_edit.toPlainText()),
            exclude=tuple(hidden),
        )

    def session_folders(self) -> tuple[str, ...]:
        """Read the folders the operator added to the session.

        Returns:
            tuple[str, ...]: The folders.
        """
        return _lines(self._session_folders_edit.toPlainText())

    def _sync_enabled(self) -> None:
        """Grey out the settings that do nothing while roots are off or the session is left out."""
        offered = self._enabled_box.isChecked()
        self._include_box.setEnabled(offered)
        self._session_list.setEnabled(offered and self._include_box.isChecked())
        self._folders_edit.setEnabled(offered)

    def _on_session_item_changed(self, item: QListWidgetItem) -> None:
        """Report a session folder being hidden from, or shown to, this server.

        Args:
            item: The folder whose tick changed.
        """
        del item
        self._on_edited()

    def _on_edited(self) -> None:
        """Report an edit the operator made."""
        if self._loading:
            return
        self._sync_enabled()
        self.changed.emit()
