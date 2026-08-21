# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable tests for the installer ML-split top-level entry projection.

``packaging/ml_split.py`` decides which top-level ``site-packages`` entries the
installer stager relocates into ``ml_overlay``. The projection must ignore
``RECORD`` paths that escape ``site-packages`` (console scripts, man pages, and
other data files installed via relative ``../..`` paths), including the real
``sympy`` case that records its man page with OS-native backslashes
(``..\\..\\share\\man\\man1\\isympy.1``). If that path were mistaken for a
top-level entry, the stager would hand ``Move-Item`` a bogus
``ml_overlay\\share\\...`` destination whose parent does not exist and abort the
whole build -- exactly the regression these tests guard.

The module is a standalone build script outside the ``intellicrack`` package, so
it is loaded here directly from its file path.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from types import ModuleType

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ML_SPLIT_PATH = _REPO_ROOT / "packaging" / "ml_split.py"


def _load_ml_split() -> ModuleType:
    """Load ``packaging/ml_split.py`` as a module from its file path.

    Returns:
        ModuleType: The imported ``ml_split`` module.
    """
    spec = importlib.util.spec_from_file_location("ml_split", _ML_SPLIT_PATH)
    if spec is None or spec.loader is None:
        pytest.fail(f"could not load ml_split from {_ML_SPLIT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ml_split = _load_ml_split()


def test_backslash_escaping_data_path_is_not_a_top_level_entry() -> None:
    """The real sympy man-page RECORD path must not project to a top-level entry."""
    assert ml_split.top_level_name("..\\..\\share\\man\\man1\\isympy.1") is None


def test_forward_slash_escaping_data_path_is_not_a_top_level_entry() -> None:
    """A forward-slash console-script RECORD path must be ignored too."""
    assert ml_split.top_level_name("../../Scripts/accelerate.exe") is None


def test_real_package_paths_project_to_their_top_level_name() -> None:
    """Ordinary in-tree RECORD paths yield the importable top-level name."""
    assert ml_split.top_level_name("torch/__init__.py") == "torch"
    assert ml_split.top_level_name("torch/lib/torch_cpu.dll") == "torch"
    assert ml_split.top_level_name("sympy-1.13.3.dist-info/RECORD") == "sympy-1.13.3.dist-info"


def test_top_level_names_excludes_escaping_paths_keeps_real_ones() -> None:
    """The set projection drops escaping data paths and keeps real entries.

    This is the exact mix that crashed ``stage.ps1``: a set of ``sympy`` RECORD
    paths where the man page escapes ``site-packages`` with backslashes.
    """
    record_paths = [
        "sympy/__init__.py",
        "sympy/core/numbers.py",
        "sympy-1.13.3.dist-info/METADATA",
        "..\\..\\share\\man\\man1\\isympy.1",
        "../../Scripts/isympy.exe",
    ]
    names = ml_split.top_level_names(record_paths)
    assert names == {"sympy", "sympy-1.13.3.dist-info"}
    assert not any(entry.startswith("..") for entry in names)


def test_bare_and_empty_paths_yield_no_entry() -> None:
    """Empty or pure-parent paths do not name a top-level entry."""
    assert ml_split.top_level_name("") is None
    assert ml_split.top_level_name("..") is None
    assert ml_split.top_level_name("../..") is None
