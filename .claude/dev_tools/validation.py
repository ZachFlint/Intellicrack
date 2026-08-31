"""Path and argument validation for MCP dev-tools server."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

BLOCKED_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.\.[/\\]"),
    re.compile(r"^[/\\]etc[/\\]", re.IGNORECASE),
    re.compile(r"^[/\\]usr[/\\]", re.IGNORECASE),
    re.compile(r"^C:[/\\]Windows", re.IGNORECASE),
    re.compile(r"^C:[/\\]Program Files", re.IGNORECASE),
    re.compile(r"^C:[/\\]ProgramData", re.IGNORECASE),
    re.compile(r"(^|[/\\])\.git[/\\]objects", re.IGNORECASE),
    re.compile(r"[/\\]\.pixi[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]node_modules[/\\]", re.IGNORECASE),
    re.compile(r"[/\\]__pycache__[/\\]", re.IGNORECASE),
]

SHELL_METACHARACTERS = frozenset(";|&`$(){}[]<>")

ALLOWED_EXTENSIONS: dict[str, frozenset[str]] = {
    "python": frozenset({".py", ".pyi", ".pyx", ".pyw"}),
    "rust": frozenset({".rs", ".toml"}),
    "javascript": frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}),
    "java": frozenset({".java"}),
    "markdown": frozenset({".md", ".markdown"}),
    "yaml": frozenset({".yaml", ".yml"}),
    "json": frozenset({".json", ".jsonc"}),
    "toml": frozenset({".toml"}),
    "shell": frozenset({".sh", ".bash", ".zsh", ".ps1", ".psm1", ".psd1"}),
    "all": frozenset(),
}


def validate_path(
    path: str,
    category: Literal[
        "python", "rust", "javascript", "java", "markdown", "yaml", "json", "toml", "shell", "all"
    ] = "all",
    must_exist: bool = False,
    allow_directory: bool = True,
) -> tuple[bool, str | None]:
    """
    Validate a path for security and appropriateness.

    Args:
        path: The path to validate.
        category: File category for extension validation.
        must_exist: Whether the path must exist.
        allow_directory: Whether directories are allowed.

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is None.
    """
    if not path or not path.strip():
        return False, "Path cannot be empty"

    for pattern in BLOCKED_PATH_PATTERNS:
        if pattern.search(path):
            return False, f"Path blocked: matches security pattern"

    try:
        resolved = Path(path).resolve()
    except (OSError, ValueError) as e:
        return False, f"Invalid path: {e}"

    if must_exist and not resolved.exists():
        return False, f"Path does not exist: {path}"

    if resolved.exists():
        if resolved.is_dir() and not allow_directory:
            return False, "Directory not allowed for this operation"

        if resolved.is_file() and category != "all":
            allowed = ALLOWED_EXTENSIONS.get(category, frozenset())
            if allowed and resolved.suffix.lower() not in allowed:
                return False, f"File extension {resolved.suffix} not allowed for {category}"

    return True, None


def validate_command_arg(arg: str) -> tuple[bool, str | None]:
    """
    Validate a command argument for shell metacharacters.

    Args:
        arg: The argument to validate.

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is None.
    """
    if not arg:
        return True, None

    for char in arg:
        if char in SHELL_METACHARACTERS:
            return False, f"Shell metacharacter '{char}' not allowed in arguments"

    return True, None


def validate_commit_message(message: str) -> tuple[bool, str | None]:
    """
    Validate a git commit message.

    Args:
        message: The commit message to validate.

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is None.
    """
    if not message or len(message.strip()) < 3:
        return False, "Commit message must be at least 3 characters"

    if len(message) > 5000:
        return False, "Commit message too long (max 5000 characters)"

    return True, None


def sanitize_path(path: str) -> str:
    """
    Sanitize a path by normalizing separators.

    Args:
        path: The path to sanitize.

    Returns:
        Sanitized path string.
    """
    return path.replace("\\", "/").strip()
