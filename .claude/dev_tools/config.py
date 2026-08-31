"""Configuration for MCP dev-tools server."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "working_dir": "D:/Intellicrack",
    "timeout": 120,
    "long_timeout": 300,
    "max_output_size": 100000,
    "pixi_command": "pixi",
    "git_command": "git",
}


def get_config() -> dict[str, Any]:
    """
    Load configuration from environment or config file.

    Priority:
    1. Environment variables (DEV_TOOLS_WORKING_DIR, DEV_TOOLS_TIMEOUT, etc.)
    2. Config file (.claude/mcp/config.json)
    3. Default values

    Returns:
        Configuration dictionary.
    """
    config = DEFAULT_CONFIG.copy()

    config_path = Path(__file__).parent / "config.json"
    if config_path.exists():
        try:
            with open(config_path, encoding="utf-8") as f:
                file_config = json.load(f)
                config.update(file_config)
        except (json.JSONDecodeError, OSError):
            pass

    env_mappings: dict[str, str | tuple[str, type[int]]] = {
        "DEV_TOOLS_WORKING_DIR": "working_dir",
        "DEV_TOOLS_TIMEOUT": ("timeout", int),
        "DEV_TOOLS_LONG_TIMEOUT": ("long_timeout", int),
        "DEV_TOOLS_PIXI_COMMAND": "pixi_command",
        "DEV_TOOLS_GIT_COMMAND": "git_command",
    }

    for env_var, mapping in env_mappings.items():
        env_value = os.environ.get(env_var)
        if env_value:
            if isinstance(mapping, tuple):
                key, converter = mapping
                try:
                    config[key] = converter(env_value)
                except (ValueError, TypeError):
                    pass
            elif isinstance(mapping, str):
                config[mapping] = env_value

    return config


CONFIG = get_config()
WORKING_DIR = Path(CONFIG["working_dir"])
TIMEOUT = CONFIG["timeout"]
LONG_TIMEOUT = CONFIG["long_timeout"]
PIXI = CONFIG["pixi_command"]
GIT = CONFIG["git_command"]
