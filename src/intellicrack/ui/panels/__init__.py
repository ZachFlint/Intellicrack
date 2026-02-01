"""UI panels for Intellicrack analysis displays.

This module provides specialized panels for licensing analysis,
stack viewing, script management, Frida instrumentation, process
management, binary hex viewing, and sandbox control within the
main application.
"""

from __future__ import annotations

from intellicrack.ui.panels.binary_panel import BinaryPanel
from intellicrack.ui.panels.frida_panel import FridaPanel
from intellicrack.ui.panels.licensing_panel import LicensingAnalysisPanel
from intellicrack.ui.panels.process_panel import ProcessPanel
from intellicrack.ui.panels.sandbox_panel import SandboxPanel
from intellicrack.ui.panels.script_manager import ScriptManagerPanel, ScriptTypeInfo
from intellicrack.ui.panels.stack_viewer import (
    FridaStackSource,
    StackFrame,
    StackViewerPanel,
    X64DbgStackSource,
)


__all__ = [
    "BinaryPanel",
    "FridaPanel",
    "FridaStackSource",
    "LicensingAnalysisPanel",
    "ProcessPanel",
    "SandboxPanel",
    "ScriptManagerPanel",
    "ScriptTypeInfo",
    "StackFrame",
    "StackViewerPanel",
    "X64DbgStackSource",
]
