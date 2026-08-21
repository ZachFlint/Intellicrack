# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Frozen-application path-resolution regression tests.

These gates verify that :func:`intellicrack.core.config.get_project_root`
resolves the deployment root from the executable location when the process is
a PyInstaller frozen build, and from the source tree otherwise, and that every
derived path (``.env`` credential file, ``.intellicrack`` config directory, and
the tools/logs/data directories the bridges discover external engines through)
tracks that root. A build that reverted the frozen branch would resolve these
paths inside the read-only extraction directory or the wrong ancestor of the
bundle, so each assertion below fails loudly on that regression.
"""

from __future__ import annotations

import importlib
import sys
from typing import TYPE_CHECKING, cast

from intellicrack.core.config import (
    Config,
    get_config_dir,
    get_env_file,
    get_project_root,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest


_resolve_env_path = cast(
    "Callable[[], Path]",
    importlib.import_module("intellicrack.main")._resolve_env_path,
)
"""Production ``.env`` resolver resolved through :func:`importlib.import_module`.

Accessed via the module object rather than ``from intellicrack.main import X``
because ``intellicrack.__init__`` ships a lazy ``__getattr__`` that aliases
``intellicrack.main`` to the ``main()`` function during collection-time
``from``-imports, hiding the underscored helpers.
"""


def _freeze(monkeypatch: pytest.MonkeyPatch, exe_dir: Path) -> Path:
    """Simulate a PyInstaller frozen process rooted at ``exe_dir``.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        exe_dir: Directory that should contain the synthetic executable.

    Returns:
        Path: The resolved directory ``get_project_root`` is expected to return.
    """
    exe = exe_dir / "Intellicrack.exe"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    return exe.resolve().parent


def test_get_project_root_dev_is_source_checkout() -> None:
    """In a development checkout the root must contain ``src/intellicrack``."""
    root = get_project_root()
    assert (root / "src" / "intellicrack" / "core" / "config.py").is_file()


def test_get_project_root_frozen_is_executable_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A frozen process must root at the executable directory, not ``parents[3]``."""
    expected = _freeze(monkeypatch, tmp_path)
    assert get_project_root() == expected


def test_get_env_file_frozen_tracks_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The ``.env`` path must resolve beside the frozen executable."""
    expected = _freeze(monkeypatch, tmp_path)
    assert get_env_file() == expected / ".env"


def test_get_config_dir_frozen_tracks_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The ``.intellicrack`` config directory must resolve beside the executable."""
    expected = _freeze(monkeypatch, tmp_path)
    assert get_config_dir() == expected / ".intellicrack"


def test_config_default_dirs_track_frozen_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The tools/logs/data directories must derive from the frozen root.

    The bridges locate external engines (QEMU, Ghidra, Cutter, radare2, x64dbg)
    under ``tools_directory``; if that pointed inside the extraction directory a
    frozen build could never find them.
    """
    expected = _freeze(monkeypatch, tmp_path)
    config = Config.default()
    assert config.tools_directory == expected / "tools"
    assert config.logs_directory == expected / "logs"
    assert config.data_directory == expected / "data"


def test_resolve_env_path_matches_get_env_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``main._resolve_env_path`` must return the frozen-aware ``.env`` path."""
    expected = _freeze(monkeypatch, tmp_path)
    assert _resolve_env_path() == expected / ".env"
