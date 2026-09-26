# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for running without the ``mcp`` SDK installed.

MCP is optional. Without the SDK the application must still start, with the
MCP client switched off, rather than failing to import its user interface.
Each gate runs a fresh interpreter whose import system refuses ``mcp`` and
``mcp_types``, exactly as it would behave with neither package installed, and
builds the real main window in it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
_CHILD_TIMEOUT_S = 240.0

_CHILD_SCRIPT = textwrap.dedent(
    """
    import importlib
    import importlib.abc
    import sys
    import tempfile
    from pathlib import Path


    class RefuseMcpSdk(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path, target=None):
            if name.split(".")[0] in {"mcp", "mcp_types"}:
                raise ModuleNotFoundError(f"No module named {name!r}", name=name)
            return None


    sys.meta_path.insert(0, RefuseMcpSdk())

    import intellicrack.ui
    from intellicrack.mcp.config import is_mcp_namespace

    try:
        importlib.import_module("intellicrack.ui.mcp_service")
    except ImportError:
        print("SERVICE-IMPORT-REFUSED")

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator
    from intellicrack.core.session import SessionManager, SessionStore
    from intellicrack.core.tools import ToolRegistry
    from intellicrack.providers.registry import ProviderRegistry
    from intellicrack.ui.app import MainWindow

    app = QApplication([])
    root = Path(tempfile.mkdtemp())
    (root / "tools").mkdir()
    config = Config(tools_directory=root / "tools", logs_directory=root / "logs", data_directory=root / "data")
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=root / "tools"),
        session_manager=SessionManager(store=SessionStore(db_path=root / "sessions.db"), auto_save=False),
    )
    window = MainWindow(config, orchestrator)
    print("MCP-SERVICE", window._mcp_service is None)
    print("NAMESPACE-CHECK", is_mcp_namespace("mcp-files"))
    print("SDK-LOADED", "mcp" in sys.modules or "mcp_types" in sys.modules)
    """,
)


def test_ui_starts_with_mcp_disabled_when_the_sdk_is_missing(tmp_path: Path) -> None:
    """The main window builds, and the MCP client is simply off, without the SDK.

    Args:
        tmp_path: Pytest-provided temporary directory.
    """
    script = tmp_path / "without_mcp_sdk.py"
    _ = script.write_text(_CHILD_SCRIPT, encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(_REPO_ROOT / "src"), str(_REPO_ROOT), env.get("PYTHONPATH", "")]))
    env["QT_QPA_PLATFORM"] = "offscreen"
    completed = subprocess.run(
        [sys.executable, str(script)],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=_CHILD_TIMEOUT_S,
        check=False,
    )
    output = completed.stdout
    assert completed.returncode == 0, f"the UI failed without the mcp SDK:\n{completed.stderr[-4000:]}"
    assert "SERVICE-IMPORT-REFUSED" in output, "the SDK was not actually missing in the child interpreter"
    assert "MCP-SERVICE True" in output, "the window did not fall back to running without MCP"
    assert "NAMESPACE-CHECK True" in output
    assert "SDK-LOADED False" in output
