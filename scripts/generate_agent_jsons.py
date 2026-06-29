# Copyright (C) 2026 Zachary Flint
"""Script to generate workspace-scoped agent.json files from Claude agent markdown files."""

import json
from pathlib import Path
from typing import Any, cast

import yaml


# Constant for split parsing magic number
FRONTMATTER_SPLIT_PARTS: int = 3


def parse_agent_markdown(agent_file: Path) -> dict[str, object] | None:
    """Parses frontmatter and body from a Claude agent markdown file.

    Args:
        agent_file: Path to the markdown file.

    Returns:
        A dictionary containing parsed metadata and instructions body,
        or None if parsing failed.
    """
    content: str = agent_file.read_text(encoding="utf-8")
    parts: list[str] = content.split("---", 2)
    if len(parts) < FRONTMATTER_SPLIT_PARTS:
        return None

    frontmatter_str: str = parts[1]
    body: str = parts[2].strip()
    metadata_raw: Any = yaml.safe_load(frontmatter_str)

    metadata: dict[str, object] = {}
    if isinstance(metadata_raw, dict):
        raw_dict = cast("dict[object, object]", metadata_raw)
        metadata.update(
            {str(k): v for k, v in raw_dict.items() if isinstance(k, str)},
        )
    metadata["body"] = body
    return metadata


def generate_agent_configs() -> None:
    """Parses Claude agent markdown files and generates Antigravity agent.json files.

    Raises:
        FileNotFoundError: If the source agents directory does not exist.
    """
    agents_dir = Path("D:/Intellicrack/.claude/agents")
    plugin_dir = Path("D:/Intellicrack/.agents/plugins/intellicrack-agents")
    output_dir = plugin_dir / "agents"
    tools: list[str] = [
        "view_file",
        "run_command",
        "replace_file_content",
        "multi_replace_file_content",
        "write_to_file",
        "list_dir",
        "grep_search",
        "search_web",
        "read_url_content",
        "schedule",
        "manage_task",
        "manage_subagents",
        "define_subagent",
        "invoke_subagent",
        "send_message",
        "ask_question",
        "ask_permission",
    ]

    if not agents_dir.exists():
        err_msg: str = "Source agents directory not found"
        raise FileNotFoundError(err_msg)

    # Ensure plugin directory exists
    if not plugin_dir.exists():
        plugin_dir.mkdir(parents=True, exist_ok=True)

    # Write plugin.json
    plugin_spec: dict[str, str] = {
        "$schema": "https://antigravity.google/schemas/v1/plugin.json",
        "name": "intellicrack-agents",
        "version": "1.0.0",
        "description": "Workspace-scoped Intellicrack agents.",
    }
    plugin_json_path: Path = plugin_dir / "plugin.json"
    with plugin_json_path.open("w", encoding="utf-8") as f:
        json.dump(plugin_spec, f, indent=2, ensure_ascii=False)

    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)

    for agent_file in agents_dir.glob("*.md"):
        metadata = parse_agent_markdown(agent_file)
        if metadata is None:
            continue

        agent_name: str = str(metadata.get("name", agent_file.stem)).lower()
        agent_spec: dict[str, Any] = {
            "name": agent_name,
            "displayName": str(metadata.get("name", agent_file.stem)),
            "description": str(metadata.get("description", "")).strip(),
            "hidden": False,
            "customAgentSpec": {
                "customAgent": {
                    "systemPromptSections": [
                        {
                            "title": "Instructions",
                            "content": str(metadata.get("body", "")),
                        },
                    ],
                    "toolNames": tools,
                },
            },
        }

        agent_folder: Path = output_dir / agent_name
        if not agent_folder.exists():
            agent_folder.mkdir(parents=True, exist_ok=True)

        json_path: Path = agent_folder / "agent.json"
        with json_path.open("w", encoding="utf-8") as f:
            json.dump(agent_spec, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    generate_agent_configs()
