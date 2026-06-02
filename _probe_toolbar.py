"""Probe the toolbar overflow state for assertion design."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QApplication, QToolButton

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.ui.app import MainWindow
from intellicrack.ui.overflow_toolbar import OverflowToolBar
from tests.test_ui.conftest import NoOpSandboxManager

import intellicrack.ui.app as appmod


tmp = Path("D:/Intellicrack/_qstmp")
tmp.mkdir(exist_ok=True)
QSettings.setDefaultFormat(QSettings.Format.IniFormat)
QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(tmp))
QSettings("Intellicrack", "MainWindow").clear()

app = QApplication([])
appmod.SandboxManager = NoOpSandboxManager
cfg = Config(tools_directory=tmp / "tools", logs_directory=tmp / "logs", data_directory=tmp / "data")
orch = Orchestrator(
    provider_registry=ProviderRegistry(),
    tool_registry=ToolRegistry(tools_dir=tmp / "tools"),
    session_manager=SessionManager(store=SessionStore(db_path=tmp / "s.db")),
)
win = MainWindow(cfg, orch)
win.resize(640, 600)
win.show()
app.processEvents()

tbs = win.findChildren(OverflowToolBar)
tb = tbs[0]
actions = tb.actions()
hidden = 0
visible = 0
for a in actions:
    w = tb.widgetForAction(a)
    if w is None:
        continue
    if w.isVisible():
        visible += 1
    else:
        hidden += 1
print("toolbar count:", len(tbs))
print("widget actions visible:", visible, "hidden:", hidden)
ext = tb.findChildren(QToolButton, "qt_toolbar_ext_button")
print("ext buttons:", len(ext))
if ext:
    print("ext visible:", ext[0].isVisible())
print("extension_button prop:", tb.extension_button)
win.close()
