#!/usr/bin/env python3
"""Generate requirements.txt from the pixi environment.

Reads the pixi lockfile to extract PyPI dependencies and writes them
to requirements.txt in pip-compatible format.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _parse_pixi_output(stdout: str) -> list[dict[str, str]]:
    """Parse pixi list JSON output into typed package dicts.

    Args:
        stdout: Raw stdout from pixi list --json.

    Returns:
        List of package dictionaries with string keys and values.

    Raises:
        TypeError: If the output is not a JSON array.
    """
    decoded: object = json.loads(stdout)
    if not isinstance(decoded, list):
        msg = "Expected JSON array from pixi list"
        raise TypeError(msg)

    result: list[dict[str, str]] = []
    for raw_item in decoded:
        if not isinstance(raw_item, dict):
            continue
        result.append({str(k): str(v) for k, v in raw_item.items() if isinstance(k, str) and isinstance(v, str)})
    return result


def generate_requirements(output_path: str = "requirements.txt") -> int:
    """Generate requirements.txt from pixi's locked dependency list.

    Args:
        output_path: Path to write the requirements file to.

    Returns:
        Exit code: 0 on success, 1 on failure.
    """
    try:
        result = subprocess.run(
            ["pixi", "list", "--frozen", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print("Error: pixi not found on PATH", file=sys.stderr)
        return 1

    if result.returncode != 0:
        print(f"Error: pixi list failed: {result.stderr}", file=sys.stderr)
        return 1

    try:
        packages = _parse_pixi_output(result.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Error: Failed to parse pixi output: {exc}", file=sys.stderr)
        return 1

    pypi_packages: list[tuple[str, str]] = []
    for pkg in packages:
        if pkg.get("kind") != "pypi":
            continue
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if name:
            pypi_packages.append((name, version))

    pypi_packages.sort(key=lambda p: p[0].lower())

    lines: list[str] = []
    for pkg_name, pkg_version in pypi_packages:
        if pkg_version:
            lines.append(f"{pkg_name}=={pkg_version}")
        else:
            lines.append(pkg_name)

    _ = Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Generated {output_path} with {len(lines)} PyPI packages")
    return 0


if __name__ == "__main__":
    sys.exit(generate_requirements())
