"""Entry point for running dev-tools MCP server as a module."""
from __future__ import annotations

import sys
from pathlib import Path

# Add parent directory to path for proper imports
parent = Path(__file__).parent.parent
if str(parent) not in sys.path:
    sys.path.insert(0, str(parent))

from dev_tools.dev_tools_server import mcp

if __name__ == "__main__":
    mcp.run()
