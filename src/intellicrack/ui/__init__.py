# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""User interface components for Intellicrack.

This package provides PyQt6-based UI components including the main application window, chat panel, tool output display, and configuration
dialogs.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from intellicrack.ui._hex_format import format_hex_dump
from intellicrack.ui.app import MainWindow
from intellicrack.ui.chat import ChatInput, ChatPanel, MessageBubble
from intellicrack.ui.confirmation_dialog import ToolConfirmationDialog
from intellicrack.ui.dialogs import SplashScreen
from intellicrack.ui.highlighter import (
    AssemblySyntaxHighlighter,
    CSyntaxHighlighter,
    HighlightRule,
    JavaScriptSyntaxHighlighter,
    PythonSyntaxHighlighter,
    get_highlighter_for_language,
)
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from intellicrack.ui.preferences import PreferencesDialog
from intellicrack.ui.provider_config import (
    ModelSelectionDialog,
    ProviderConfigDialog,
    ProviderSettingsWidget,
)
from intellicrack.ui.resources import FontManager, IconManager, ThemeManager, get_assets_path, get_resource_path
from intellicrack.ui.sandbox_config import (
    SandboxConfigDialog,
    SandboxMonitorWidget,
)
from intellicrack.ui.session_manager import (
    NewSessionDialog,
    SessionManagerDialog,
)
from intellicrack.ui.tool_config import (
    ToolConfigDialog,
    ToolSettingsWidget,
    ToolStatusDialog,
)
from intellicrack.ui.tools import (
    CodeDisplay,
    FunctionListPanel,
    ToolOutputPanel,
    ToolTab,
    XRefPanel,
)


if TYPE_CHECKING:
    from intellicrack.ui.mcp_config import McpConfigDialog, McpInputPromptDialog, McpServerEditor, McpServerListModel, McpToolToggleView
    from intellicrack.ui.mcp_elicitation_dialog import McpElicitationDialog
    from intellicrack.ui.mcp_service import McpService


__all__: list[str] = [
    "AssemblySyntaxHighlighter",
    "CSyntaxHighlighter",
    "ChatInput",
    "ChatPanel",
    "CodeDisplay",
    "FontManager",
    "FunctionListPanel",
    "HighlightRule",
    "IconManager",
    "JavaScriptSyntaxHighlighter",
    "MainWindow",
    "McpConfigDialog",
    "McpElicitationDialog",
    "McpInputPromptDialog",
    "McpServerConsentDialog",
    "McpServerEditor",
    "McpServerListModel",
    "McpService",
    "McpToolToggleView",
    "MessageBubble",
    "ModelSelectionDialog",
    "NewSessionDialog",
    "PreferencesDialog",
    "ProviderConfigDialog",
    "ProviderSettingsWidget",
    "PythonSyntaxHighlighter",
    "SandboxConfigDialog",
    "SandboxMonitorWidget",
    "SessionManagerDialog",
    "SplashScreen",
    "ThemeManager",
    "ToolConfigDialog",
    "ToolConfirmationDialog",
    "ToolOutputPanel",
    "ToolSettingsWidget",
    "ToolStatusDialog",
    "ToolTab",
    "XRefPanel",
    "format_hex_dump",
    "get_assets_path",
    "get_highlighter_for_language",
    "get_resource_path",
]


def __getattr__(name: str) -> object:
    """Resolve an MCP user-interface export the first time it is used.

    These classes talk to MCP servers through the ``mcp`` SDK, which is optional. Importing them with the rest of the package would make a
    missing SDK break the whole user interface, where it should only disable the MCP client. The resolved object is cached on the package
    globals so later look-ups bypass this hook.

    Args:
        name: The attribute being looked up.

    Returns:
        object: The exported object.

    Raises:
        AttributeError: If ``name`` is not an export of this package.
    """
    sdk_exports: dict[str, str] = {
        "McpConfigDialog": "intellicrack.ui.mcp_config",
        "McpInputPromptDialog": "intellicrack.ui.mcp_config",
        "McpServerEditor": "intellicrack.ui.mcp_config",
        "McpServerListModel": "intellicrack.ui.mcp_config",
        "McpToolToggleView": "intellicrack.ui.mcp_config",
        "McpElicitationDialog": "intellicrack.ui.mcp_elicitation_dialog",
        "McpService": "intellicrack.ui.mcp_service",
    }
    module_name = sdk_exports.get(name)
    if module_name is None:
        message = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(message)
    value: object = getattr(importlib.import_module(module_name), name)
    globals()[name] = value
    return value
