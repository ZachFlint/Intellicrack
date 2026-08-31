# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Fix PyQt6 QtWidgets.pyi missing ``collections.abc`` import.

PyQt6 6.10.x ships a ``QtWidgets.pyi`` type hint file that references
``collections.abc.Callable`` and ``collections.abc.Iterable`` but only
imports ``collections`` (without the ``abc`` submodule).  This causes
basedpyright to report *partially unknown* type errors when
``useLibraryCodeForTypes`` is disabled.

The script is **idempotent**: it patches the import line only when the
fix is missing and silently exits when PyQt6 is absent or already
correct.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path


def _locate_qtwidgets_pyi() -> Path | None:
    """Return the path to ``PyQt6/QtWidgets.pyi``, or *None* if missing.

    Returns:
        Path | None: Path to the type hint file if found, None otherwise.
    """
    spec = importlib.util.find_spec("PyQt6")
    if spec is None or spec.origin is None:
        return None
    pyi = Path(spec.origin).parent / "QtWidgets.pyi"
    return pyi if pyi.is_file() else None


def _needs_patch(text: str) -> bool:
    """Return *True* when the import line lacks ``collections.abc``.

    Args:
        text: Full text content of the type hint file.

    Returns:
        bool: True if the import line needs patching.
    """
    return bool(
        re.search(
            r"^import\s+collections\s*,\s*(?!collections\.abc)",
            text,
            re.MULTILINE,
        ),
    )


def _apply_patch(text: str) -> str:
    """Insert ``collections.abc`` into the import line.

    Args:
        text: Full text content of the type hint file.

    Returns:
        str: Patched text with ``collections.abc`` added to the import.
    """
    return re.sub(
        r"^(import\s+collections)\s*,",
        r"\1, collections.abc,",
        text,
        count=1,
        flags=re.MULTILINE,
    )


def main() -> int:
    """Patch PyQt6 QtWidgets.pyi if needed.

    Returns:
        int: Exit code (0 = success/no-op, 1 = error).
    """
    pyi = _locate_qtwidgets_pyi()
    if pyi is None:
        print("PyQt6 not installed or QtWidgets.pyi not found -- skipping")
        return 0

    text = pyi.read_text(encoding="utf-8")
    if not _needs_patch(text):
        print(f"QtWidgets.pyi already correct: {pyi}")
        return 0

    patched = _apply_patch(text)
    pyi.write_text(patched, encoding="utf-8")
    print(f"Patched QtWidgets.pyi: added collections.abc import in {pyi}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
