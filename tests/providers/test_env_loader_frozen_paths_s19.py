# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Frozen-application ``.env`` discovery regression test.

``_find_env_file`` searches the current working directory, the project root, and
the user home for a ``.env`` credential file. The project-root candidate must be
resolved through :func:`intellicrack.core.config.get_project_root`, so a frozen
build searches beside the executable rather than an ancestor of the read-only
extraction directory. This gate creates a ``.env`` only in a synthetic frozen
root and asserts the resolver finds it; before the fix the resolver computed the
project root from ``__file__`` and would return the source checkout's ``.env``
instead.
"""

from __future__ import annotations

import importlib
import sys
from typing import TYPE_CHECKING, cast


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest


_find_env_file = cast(
    "Callable[[], Path]",
    getattr(importlib.import_module("intellicrack.credentials.env_loader"), "_find_env_file"),
)
"""Production ``.env`` search helper resolved through ``importlib``.

Accessed via ``getattr`` on the imported module so the underscored helper is
reached without a ``from``-import that the package's lazy ``__getattr__`` could
shadow.
"""


def test_find_env_file_searches_frozen_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A frozen build must discover ``.env`` beside the executable.

    The current working directory is pointed at an empty directory (no ``.env``)
    so the frozen-root candidate is the one that must match.
    """
    exe_dir = tmp_path / "install"
    cwd_dir = tmp_path / "elsewhere"
    exe_dir.mkdir()
    cwd_dir.mkdir()

    frozen_env = exe_dir / ".env"
    _ = frozen_env.write_text("ANTHROPIC_API_KEY=sk-ant-test\n", encoding="utf-8")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe_dir / "Intellicrack.exe"))
    monkeypatch.chdir(cwd_dir)

    assert _find_env_file().resolve() == frozen_env.resolve()
