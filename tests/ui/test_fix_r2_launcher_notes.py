# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 10: the launch consent dialog tells the operator what a sandboxed launcher needs.

The gates build the real consent dialog for a sandboxed server started by each kind of launcher and read what its sandbox label says.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QLabel

from intellicrack.mcp.config import McpSandboxSpec, McpServerConfig, McpTransportKind, StdioServerSpec, launcher_notes
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


def _sandbox_text(qtbot: QtBot, command: str, *, enabled: bool) -> str:
    """Build the consent dialog for one launcher and read its sandbox label.

    Args:
        qtbot: The Qt test driver.
        command: The launch command.
        enabled: Whether the server is sandboxed.

    Returns:
        str: The label's text.
    """
    config = McpServerConfig(
        server_id="launcher",
        kind=McpTransportKind.STDIO,
        stdio=StdioServerSpec(command=command, args=("server",)),
        enabled=True,
        sandbox=McpSandboxSpec(enabled=enabled, allow_write=("C:\\work",)),
    )
    dialog = McpServerConsentDialog.for_config(config, {})
    qtbot.addWidget(dialog)
    label = dialog.findChild(QLabel, "mcp_consent_sandbox")
    assert label is not None
    return label.text()


@pytest.mark.parametrize("command", ["npx", "uvx", "pipx", "python", "node", "docker"])
def test_sandboxed_launcher_notes_are_shown(qtbot: QtBot, command: str) -> None:
    """Every note for the launcher is in the sandbox label, beside the sandbox's own home.

    Args:
        qtbot: The Qt test driver.
        command: The launcher.
    """
    text = _sandbox_text(qtbot, command, enabled=True)

    assert "its own sandbox home" in text
    for note in launcher_notes(command):
        assert note in text


def test_unsandboxed_launcher_gets_no_sandbox_notes(qtbot: QtBot) -> None:
    """An unconfined server's dialog does not talk about a sandbox it does not have.

    Args:
        qtbot: The Qt test driver.
    """
    text = _sandbox_text(qtbot, "npx", enabled=False)

    assert text.startswith("Sandbox: OFF.")
    assert all(note not in text for note in launcher_notes("npx"))
