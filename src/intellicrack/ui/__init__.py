# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""User interface components for Intellicrack.

This package provides PyQt6-based UI components including the main application window, chat panel, tool output display, and configuration
dialogs.
"""

from __future__ import annotations

from intellicrack.ui.app import AsyncWorker, MainWindow
from intellicrack.ui.chat import ChatInput, ChatPanel, MessageBubble
from intellicrack.ui.dialogs import SplashScreen
from intellicrack.ui.highlighter import (
    AssemblySyntaxHighlighter,
    CSyntaxHighlighter,
    HighlightRule,
    JavaScriptSyntaxHighlighter,
    PythonSyntaxHighlighter,
    get_highlighter_for_language,
)
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


__all__: list[str] = [
    "AssemblySyntaxHighlighter",
    "AsyncWorker",
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
    "MessageBubble",
    "ModelSelectionDialog",
    "NewSessionDialog",
    "ProviderConfigDialog",
    "ProviderSettingsWidget",
    "PythonSyntaxHighlighter",
    "SandboxConfigDialog",
    "SandboxMonitorWidget",
    "SessionManagerDialog",
    "SplashScreen",
    "ThemeManager",
    "ToolConfigDialog",
    "ToolOutputPanel",
    "ToolSettingsWidget",
    "ToolStatusDialog",
    "ToolTab",
    "XRefPanel",
    "get_assets_path",
    "get_highlighter_for_language",
    "get_resource_path",
]
