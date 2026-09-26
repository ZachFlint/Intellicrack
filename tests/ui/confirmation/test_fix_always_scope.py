# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for which tool-call answers may be kept across restarts.

An answer kept "always" is only honest when something invalidates it once the
tool it was about changes. MCP tools carry a tool-listing generation that does
exactly that; built-in bridge tools carry none, so an "always" answer about
one would outlive any change to it. The real dialog and a real approval file
are used throughout.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QPushButton, QRadioButton

from intellicrack.core.types import ToolCall
from intellicrack.mcp.consent import ApprovalScope, ApprovalStore
from intellicrack.ui.confirmation_dialog import ToolConfirmationDialog


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from pytestqt.qtbot import QtBot


_BRIDGE_CALL = ToolCall(id="b1", tool_name="ghidra", function_name="patch_bytes", arguments={"address": 4096})
_MCP_CALL = ToolCall(id="m1", tool_name="mcp-files", function_name="mcp-files.write", arguments={"path": "a.txt"})


@pytest.fixture
def store(tmp_path: Path) -> Iterator[ApprovalStore]:
    """Install a real approval store for the dialog.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Yields:
        ApprovalStore: The installed store.
    """
    installed = ApprovalStore(tmp_path / "approvals.json")
    ToolConfirmationDialog.set_approval_store(installed)
    try:
        yield installed
    finally:
        ToolConfirmationDialog.clear_remembered_decisions()
        ToolConfirmationDialog.set_approval_store(None)


def _always(dialog: ToolConfirmationDialog) -> QRadioButton:
    """Find the dialog's "always" option.

    Args:
        dialog: The dialog.

    Returns:
        QRadioButton: The option.
    """
    button = dialog.findChild(QRadioButton, "confirm_scope_always")
    assert button is not None
    return button


class TestAlwaysIsOfferedOnlyWhereItCanBeInvalidated:
    """The option appears for MCP tools and not for bridge tools."""

    def test_bridge_tool_is_not_offered_always(self, qtbot: QtBot, store: ApprovalStore) -> None:
        """A bridge tool's dialog disables "always"; an MCP tool's enables it.

        Args:
            qtbot: pytest-qt bot.
            store: The installed approval store.
        """
        del store
        bridge = ToolConfirmationDialog(_BRIDGE_CALL)
        mcp = ToolConfirmationDialog(_MCP_CALL, generation="g1", source_label="MCP server 'files'")
        qtbot.addWidget(bridge)
        qtbot.addWidget(mcp)
        assert not _always(bridge).isEnabled(), "'always' was offered for a tool nothing can invalidate"
        assert _always(mcp).isEnabled()

    def test_programmatic_always_is_not_persisted_for_a_bridge_tool(self, qtbot: QtBot, store: ApprovalStore) -> None:
        """Selecting "always" in code and approving a bridge tool persists nothing.

        Args:
            qtbot: pytest-qt bot.
            store: The installed approval store.
        """
        dialog = ToolConfirmationDialog(_BRIDGE_CALL)
        qtbot.addWidget(dialog)
        dialog.set_scope(ApprovalScope.ALWAYS)
        approve = dialog.findChild(QPushButton, "confirm_approve_button")
        assert approve is not None
        approve.click()
        assert dialog.scope is not ApprovalScope.ALWAYS
        assert store.entries() == [], "an 'always' answer about a bridge tool was written to disk"

    def test_store_decision_keeps_a_bridge_answer_for_the_session_only(self, store: ApprovalStore) -> None:
        """An "always" answer about a bridge tool lasts the session and is never written to disk.

        Args:
            store: The installed approval store.
        """
        ToolConfirmationDialog.store_decision(_BRIDGE_CALL, approved=True, scope=ApprovalScope.ALWAYS)
        assert ToolConfirmationDialog.remembered_decision(_BRIDGE_CALL) is True
        assert store.entries() == []
        ToolConfirmationDialog.clear_remembered_decisions()
        assert ToolConfirmationDialog.remembered_decision(_BRIDGE_CALL) is None

    def test_mcp_answer_is_persisted(self, qtbot: QtBot, store: ApprovalStore) -> None:
        """Approving an MCP tool "always" writes the answer under its generation.

        Args:
            qtbot: pytest-qt bot.
            store: The installed approval store.
        """
        dialog = ToolConfirmationDialog(_MCP_CALL, generation="g1")
        qtbot.addWidget(dialog)
        _always(dialog).setChecked(True)
        approve = dialog.findChild(QPushButton, "confirm_approve_button")
        assert approve is not None
        approve.click()
        assert [(entry.function_name, entry.generation, entry.scope) for entry in store.entries()] == [
            ("mcp-files.write", "g1", ApprovalScope.ALWAYS),
        ]


class TestLegacyAnswersAreNotHonoured:
    """An answer persisted earlier for a bridge tool no longer approves anything."""

    def test_persisted_bridge_answer_is_ignored_and_revocable(self, tmp_path: Path) -> None:
        """A stored bridge answer is not replayed, and forgetting it removes it from disk.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        path = tmp_path / "approvals.json"
        _ = path.write_text('{"ghidra|patch_bytes|": true}\n', encoding="utf-8")
        store = ApprovalStore(path)
        ToolConfirmationDialog.set_approval_store(store)
        try:
            assert ToolConfirmationDialog.remembered_decision(_BRIDGE_CALL) is None, "a persisted bridge answer was replayed"
            assert ToolConfirmationDialog.forget_decision("ghidra", "patch_bytes", None)
            assert store.entries() == []
        finally:
            ToolConfirmationDialog.set_approval_store(None)
