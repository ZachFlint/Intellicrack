"""Code formatters for MCP dev-tools server."""
from __future__ import annotations

from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

from ..config import PIXI
from ..validation import validate_path


def register_formatter_tools(
    mcp: FastMCP,
    run_command: Callable[..., dict[str, Any]],
    error_result: Callable[[str], dict[str, Any]],
) -> None:
    """Register code formatter tools with the MCP server."""

    @mcp.tool()
    def ruff_format(
        path: str,
        check_only: bool = False,
        diff: bool = False,
        config: str | None = None,
        target_version: str | None = None,
        line_length: int | None = None,
        preview: bool = False,
        exclude: str | None = None,
        extend_exclude: str | None = None,
        force_exclude: bool = False,
        respect_gitignore: bool = True,
        isolated: bool = False,
        stdin_filename: str | None = None,
        range_start: int | None = None,
        range_end: int | None = None,
    ) -> dict[str, Any]:
        """
        Format Python code using ruff formatter.

        Args:
            path: File or directory to format.
            check_only: If True, only check formatting without modifying files.
            diff: Show diff of what would change.
            config: Path to pyproject.toml or ruff.toml config file.
            target_version: Python version to target (e.g., "py312").
            line_length: Maximum line length.
            preview: Enable preview formatting rules.
            exclude: Comma-separated paths to exclude.
            extend_exclude: Additional paths to exclude on top of defaults.
            force_exclude: Force exclusion of files even if explicitly listed.
            respect_gitignore: Respect .gitignore files.
            isolated: Ignore all config files.
            stdin_filename: Filename to use for stdin input.
            range_start: First line to format (1-indexed).
            range_end: Last line to format (1-indexed).

        Returns:
            Dict with success status and formatting output.
        """
        is_valid, err = validate_path(path, category="python")
        if not is_valid:
            return error_result(err or "Invalid path")

        args = [PIXI, "run", "ruff", "format", path]
        if check_only:
            args.append("--check")
        if diff:
            args.append("--diff")
        if config:
            is_valid_cfg, _ = validate_path(config, category="toml")
            if is_valid_cfg:
                args.extend(["--config", config])
        if target_version:
            args.extend(["--target-version", target_version])
        if line_length:
            args.extend(["--line-length", str(line_length)])
        if preview:
            args.append("--preview")
        if exclude:
            args.extend(["--exclude", exclude])
        if extend_exclude:
            args.extend(["--extend-exclude", extend_exclude])
        if force_exclude:
            args.append("--force-exclude")
        if not respect_gitignore:
            args.append("--no-respect-gitignore")
        if isolated:
            args.append("--isolated")
        if stdin_filename:
            args.extend(["--stdin-filename", stdin_filename])
        if range_start is not None:
            args.extend(["--range", f"{range_start}:"])
        if range_end is not None:
            if range_start is not None:
                args[-1] = f"{range_start}:{range_end}"
            else:
                args.extend(["--range", f":{range_end}"])

        return run_command(args)
