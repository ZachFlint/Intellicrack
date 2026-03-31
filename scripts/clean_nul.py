# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Script to clean Windows reserved 'nul' files from the project directory."""

import os
import sys
from collections.abc import Iterator
from pathlib import Path

SKIP_DIRS: frozenset[str] = frozenset({
    ".pixi",
    ".git",
    ".claude",
    "vendor",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    "target",
    ".venv",
    ".tox",
})

RESERVED_NAMES: frozenset[str] = frozenset({
    "nul", "con", "prn", "aux",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
})


def _walk_filtered(root: str) -> Iterator[str]:
    """Walk directory tree, skipping heavy non-project directories.

    Args:
        root: Root directory path to start walking from.

    Yields:
        Path to each file found outside of skipped directories.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            yield os.path.join(dirpath, fname)


def clean_nul_files() -> None:
    """Recursively find and delete Windows reserved-name files in the cwd.

    This is necessary because some Windows build tools can erroneously create these files,
    and standard command-line tools fail to delete them due to 'nul' being a reserved name.
    """
    print("--- Python NUL File Cleaner ---")
    root_dir = str(Path.cwd())
    print(f"Starting recursive search in: {root_dir}")
    files_deleted = 0

    try:
        for filepath in _walk_filtered(root_dir):
            basename = os.path.basename(filepath).lower()
            stem = basename.rsplit(".", 1)[0] if "." in basename else basename
            if stem in RESERVED_NAMES:
                prefixed_path = "\\\\?\\" + os.path.abspath(filepath)
                try:
                    Path(prefixed_path).unlink()
                    print(f"  [OK] Deleted: {filepath}")
                    files_deleted += 1
                except OSError as e:
                    print(f"  [!!!] FAILED to delete: {filepath}. Reason: {e}")
    except OSError as e:
        print(f"[!!!] The script failed with an unexpected error: {e}")
        sys.exit(1)

    print(f"\nScan complete. {files_deleted} file(s) deleted.")
    sys.exit(0)


if __name__ == "__main__":
    clean_nul_files()
