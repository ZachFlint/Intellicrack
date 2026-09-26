# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate: listing a server's tools in the MCP settings dialog never waits on the network.

``McpToolToggleView.load`` prices every tool on the GUI thread. Pricing used to
call ``tiktoken.get_encoding``, which downloads its BPE file on first use with
no timeout, so on a stalled network the dialog froze. The gate runs the real
widget in a child interpreter whose every HTTPS request goes to a proxy that
never answers, so a regression fails the test instead of hanging the run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from tests._helpers.child_python import run_child_json
from tests._helpers.stalling_http import StallingServer


if TYPE_CHECKING:
    from pathlib import Path


_CHILD_TIMEOUT_S: Final[float] = 240.0

_LOAD_CHILD: Final[str] = """
    import json, time
    from PyQt6.QtWidgets import QApplication, QLabel
    from intellicrack.mcp.catalog import McpToolEntry
    from intellicrack.ui.mcp_config import McpToolToggleView

    app = QApplication([])
    entries = tuple(
        McpToolEntry(
            name=f"tool_{index}",
            canonical_name=f"mcp-demo.tool_{index}",
            title=None,
            description=f"Look up symbol number {index} in the indexed binaries.",
            input_schema={"type": "object", "properties": {"symbol": {"type": "string"}}, "required": ["symbol"]},
            output_schema=None,
            annotations=None,
        )
        for index in range(40)
    )
    view = McpToolToggleView()
    started = time.perf_counter()
    view.load(entries, frozenset({"tool_3"}))
    elapsed = time.perf_counter() - started
    label = view.findChild(QLabel, "mcp_tools_summary")
    print(json.dumps({"elapsed": elapsed, "summary": label.text() if label is not None else "", "disabled": sorted(view.disabled_tools())}))
"""


def test_tool_list_loads_at_once_on_a_stalled_network(tmp_path: Path) -> None:
    """Forty tools are listed and priced without the GUI thread waiting on the download.

    Args:
        tmp_path: Per-test directory.
    """
    with StallingServer() as proxy:
        result = run_child_json(
            _LOAD_CHILD,
            timeout_s=_CHILD_TIMEOUT_S,
            extra_env={
                "HTTPS_PROXY": proxy.url,
                "HTTP_PROXY": proxy.url,
                "NO_PROXY": "",
                "TIKTOKEN_CACHE_DIR": str(tmp_path / "cache"),
                "QT_QPA_PLATFORM": "offscreen",
            },
        )

    assert result["elapsed"] < 1.0
    assert result["summary"].startswith("39 of 40 tools enabled, costing about ")
    assert result["disabled"] == ["tool_3"]
