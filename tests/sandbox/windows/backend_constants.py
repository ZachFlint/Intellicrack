# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Read the Windows backend's own timing budgets out of its source.

Gates that assert against a budget have to assert against the budget production
actually uses. Importing one would reach into another module's private
namespace; restating it would leave the gate measuring a number nothing
enforces. Parsing the declaration keeps the value derived, and a rename or a
removal fails loudly here instead of silently.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final


_BACKEND_SOURCE: Final[Path] = Path(__file__).resolve().parents[3] / "src" / "intellicrack" / "sandbox" / "windows.py"
_ERR_NO_CONSTANT: Final[str] = "{name} is not declared as a numeric constant in {path}"


def production_seconds(name: str) -> float:
    """Return the value the Windows backend declares for a timing constant.

    Args:
        name: Module-level constant to read from the backend.

    Returns:
        float: The declared value in seconds.

    Raises:
        AssertionError: If the backend declares no such numeric constant.
    """
    tree = ast.parse(_BACKEND_SOURCE.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.AnnAssign | ast.Assign):
            continue
        targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, int | float):
            return float(value.value)
    raise AssertionError(_ERR_NO_CONSTANT.format(name=name, path=_BACKEND_SOURCE))
