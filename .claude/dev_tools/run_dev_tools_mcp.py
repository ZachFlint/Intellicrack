"""Standalone entry point for dev-tools MCP server.

This script adds the .claude directory to the Python path and runs the MCP server.
"""
import sys
from pathlib import Path

# Add .claude directory to path so dev_tools package can be imported
claude_dir = Path(__file__).parent.parent
sys.path.insert(0, str(claude_dir))

from dev_tools.dev_tools_server import mcp

if __name__ == "__main__":
    mcp.run()
