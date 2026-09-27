# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for the pixi.lock multi-platform requirements generator.

``pixi.lock`` can resolve a package to different versions per locked
platform, since not every release ships wheels for every platform (this
project hit it for real: ``ast-serialize`` resolved to ``0.11.2`` on
``linux-64`` but only ``0.6.0`` on ``win-64``). ``generate_requirements.py``
must deterministically select the ``win-64`` resolution, since this project
targets Windows as a priority and its CI runs on ``windows-latest`` -- not
whichever platform happens to be listed last in the lockfile.

These tests exercise the real functions against real, on-disk YAML/TOML
fixtures (no mocks) and fail loudly if platform selection regresses to the
old "last one wins" behavior, or if the ambiguous-platform guard stops
raising.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml


if TYPE_CHECKING:
    from types import ModuleType


_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "generate_requirements.py"

_MULTI_PLATFORM_LOCK = """\
version: 7
platforms:
- name: linux-64-glibc234
  subdir: linux-64
- name: win-64
environments:
  default:
    channels: []
    packages:
      linux-64-glibc234:
      - pypi: https://files.pythonhosted.org/packages/lin/ast_serialize-0.11.2-manylinux.whl
      - pypi: https://files.pythonhosted.org/packages/both/onlylib-2.0.0-py3-none-any.whl
      win-64:
      - pypi: https://files.pythonhosted.org/packages/win/ast_serialize-0.6.0-win_amd64.whl
      - pypi: https://files.pythonhosted.org/packages/both/onlylib-2.0.0-py3-none-any.whl
packages:
- pypi: https://files.pythonhosted.org/packages/lin/ast_serialize-0.11.2-manylinux.whl
  name: ast-serialize
  version: 0.11.2
- pypi: https://files.pythonhosted.org/packages/win/ast_serialize-0.6.0-win_amd64.whl
  name: ast-serialize
  version: 0.6.0
- pypi: https://files.pythonhosted.org/packages/both/onlylib-2.0.0-py3-none-any.whl
  name: onlylib
  version: 2.0.0
"""

_AMBIGUOUS_PLATFORM_LOCK = """\
version: 7
platforms:
- name: linux-64
- name: osx-64
environments:
  default:
    channels: []
    packages:
      linux-64: []
      osx-64: []
packages: []
"""

_SINGLE_PLATFORM_LOCK = """\
version: 7
platforms:
- name: win-64
environments:
  default:
    channels: []
    packages:
      win-64:
      - pypi: https://files.pythonhosted.org/packages/only/solo-1.0.0-py3-none-any.whl
packages:
- pypi: https://files.pythonhosted.org/packages/only/solo-1.0.0-py3-none-any.whl
  name: solo
  version: 1.0.0
"""

_NO_ENV_PACKAGES_LOCK = """\
version: 6
platforms:
- name: win-64
- name: linux-64
packages:
- pypi: https://files.pythonhosted.org/packages/legacy/legacypkg-3.0.0-py3-none-any.whl
  name: legacypkg
  version: 3.0.0
"""

_PYPROJECT = """\
[project]
name = "fixture"
version = "0.0.0"

[tool.pixi.dependencies]
condaonly = "*"

[tool.pixi.pypi-dependencies]
ast-serialize = ">=0.1"
onlylib = ">=1.0"
"""


def _load_module() -> ModuleType:
    """Import ``scripts/generate_requirements.py`` as a fresh module.

    Returns:
        ModuleType: The loaded script module.
    """
    spec = importlib.util.spec_from_file_location("generate_requirements_under_test", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


@pytest.fixture(scope="module")
def gr() -> ModuleType:
    """Load the module under test once per test module.

    Returns:
        ModuleType: The loaded ``generate_requirements`` module.
    """
    return _load_module()


def test_select_lock_platform_prefers_win64_among_multiple(gr: ModuleType, tmp_path: Path) -> None:
    """``_select_lock_platform`` must pick win-64 when it is one of several locked platforms."""
    lock_path = tmp_path / "pixi.lock"
    lock_path.write_text(_MULTI_PLATFORM_LOCK, encoding="utf-8")
    with lock_path.open("rb") as fh:
        root = yaml.safe_load(fh)
    assert gr._select_lock_platform(root) == "win-64"


def test_select_lock_platform_falls_back_to_sole_platform(gr: ModuleType, tmp_path: Path) -> None:
    """A single-platform lockfile must select that platform even if it is not win-64."""
    lock_path = tmp_path / "pixi.lock"
    lock_path.write_text(_SINGLE_PLATFORM_LOCK.replace("win-64", "linux-64"), encoding="utf-8")
    with lock_path.open("rb") as fh:
        root = yaml.safe_load(fh)
    assert gr._select_lock_platform(root) == "linux-64"


def test_select_lock_platform_returns_none_when_ambiguous(gr: ModuleType, tmp_path: Path) -> None:
    """Multiple non-win-64 platforms with no way to disambiguate must return None, not guess."""
    lock_path = tmp_path / "pixi.lock"
    lock_path.write_text(_AMBIGUOUS_PLATFORM_LOCK, encoding="utf-8")
    with lock_path.open("rb") as fh:
        root = yaml.safe_load(fh)
    assert gr._select_lock_platform(root) is None


def test_platform_pypi_urls_returns_only_that_platforms_urls(gr: ModuleType, tmp_path: Path) -> None:
    """``_platform_pypi_urls`` must return exactly the URLs listed for the requested platform."""
    lock_path = tmp_path / "pixi.lock"
    lock_path.write_text(_MULTI_PLATFORM_LOCK, encoding="utf-8")
    with lock_path.open("rb") as fh:
        root = yaml.safe_load(fh)
    win_urls = gr._platform_pypi_urls(root, "win-64")
    assert win_urls == {
        "https://files.pythonhosted.org/packages/win/ast_serialize-0.6.0-win_amd64.whl",
        "https://files.pythonhosted.org/packages/both/onlylib-2.0.0-py3-none-any.whl",
    }
    linux_urls = gr._platform_pypi_urls(root, "linux-64-glibc234")
    assert linux_urls == {
        "https://files.pythonhosted.org/packages/lin/ast_serialize-0.11.2-manylinux.whl",
        "https://files.pythonhosted.org/packages/both/onlylib-2.0.0-py3-none-any.whl",
    }
    assert gr._platform_pypi_urls(root, "nonexistent-platform") == set()


def test_package_name_and_version_extracts_and_normalizes(gr: ModuleType) -> None:
    """``_package_name_and_version`` must extract, stringify, and strip name/version."""
    assert gr._package_name_and_version({"name": "foo", "version": "1.2.3"}) == ("foo", "1.2.3")
    assert gr._package_name_and_version({"name": "foo", "version": "  1.2.3  "}) == ("foo", "1.2.3")
    assert gr._package_name_and_version({"name": "foo", "version": 3}) == ("foo", "3")


def test_package_name_and_version_rejects_incomplete_entries(gr: ModuleType) -> None:
    """Entries missing a usable name or version must yield None, never a partial tuple."""
    assert gr._package_name_and_version({"version": "1.0.0"}) is None
    assert gr._package_name_and_version({"name": "foo"}) is None
    assert gr._package_name_and_version({"name": "foo", "version": ""}) is None
    assert gr._package_name_and_version({"name": "foo", "version": None}) is None
    assert gr._package_name_and_version({"name": "", "version": "1.0.0"}) is None


def test_load_lock_pypi_packages_selects_windows_version_not_linux(gr: ModuleType, tmp_path: Path) -> None:
    """The exact regression this fix targets: ast-serialize must resolve to the win-64 version.

    Falsifiable: reverting ``_load_lock_pypi_packages`` to the pre-fix
    behavior (iterate the flat ``packages`` list, last entry wins) would
    make this assert ``0.11.2`` (the Linux entry, which appears last in the
    fixture's ``packages`` list) instead of ``0.6.0`` (the Windows entry).
    """
    lock_path = tmp_path / "pixi.lock"
    lock_path.write_text(_MULTI_PLATFORM_LOCK, encoding="utf-8")

    packages = gr._load_lock_pypi_packages(lock_path)

    assert packages["ast-serialize"] == ("ast-serialize", "0.6.0")
    assert packages["onlylib"] == ("onlylib", "2.0.0")


def test_load_lock_pypi_packages_raises_on_ambiguous_platform(gr: ModuleType, tmp_path: Path) -> None:
    """An ambiguous multi-platform lock with no win-64 entry must raise, never guess."""
    lock_path = tmp_path / "pixi.lock"
    lock_path.write_text(_AMBIGUOUS_PLATFORM_LOCK, encoding="utf-8")

    with pytest.raises(TypeError, match="cannot unambiguously select"):
        gr._load_lock_pypi_packages(lock_path)


def test_load_lock_pypi_packages_falls_back_without_environments_section(gr: ModuleType, tmp_path: Path) -> None:
    """A lockfile with no per-platform package list must fall back to the flat package list."""
    lock_path = tmp_path / "pixi.lock"
    lock_path.write_text(_NO_ENV_PACKAGES_LOCK, encoding="utf-8")

    packages = gr._load_lock_pypi_packages(lock_path)

    assert packages["legacypkg"] == ("legacypkg", "3.0.0")


def test_generate_requirements_writes_windows_resolved_versions(gr: ModuleType, tmp_path: Path) -> None:
    """End-to-end: generate_requirements() must write the win-64 versions to requirements.txt.

    Falsifiable: if platform selection regressed, this would write
    ``ast-serialize==0.11.2`` (the Linux version) instead of ``0.6.0``.
    """
    project_root = tmp_path
    (project_root / "pixi.lock").write_text(_MULTI_PLATFORM_LOCK, encoding="utf-8")
    (project_root / "pyproject.toml").write_text(_PYPROJECT, encoding="utf-8")
    output_path = project_root / "requirements.txt"

    original_root = getattr(gr, "_PROJECT_ROOT")
    setattr(gr, "_PROJECT_ROOT", project_root)
    try:
        exit_code = gr.generate_requirements(str(output_path))
    finally:
        setattr(gr, "_PROJECT_ROOT", original_root)

    assert exit_code == 0
    content = output_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    assert "ast-serialize==0.6.0" in lines
    assert "ast-serialize==0.11.2" not in lines
    assert "onlylib==2.0.0" in lines


def test_generate_requirements_fails_when_declared_dep_missing_from_lock(gr: ModuleType, tmp_path: Path) -> None:
    """A pypi-dependency declared in pyproject.toml but absent from the lock must fail loudly."""
    project_root = tmp_path
    (project_root / "pixi.lock").write_text(_SINGLE_PLATFORM_LOCK, encoding="utf-8")
    (project_root / "pyproject.toml").write_text(
        '[tool.pixi.pypi-dependencies]\nnot-in-lock = ">=1.0"\n',
        encoding="utf-8",
    )
    output_path = project_root / "requirements.txt"

    original_root = getattr(gr, "_PROJECT_ROOT")
    setattr(gr, "_PROJECT_ROOT", project_root)
    try:
        exit_code = gr.generate_requirements(str(output_path))
    finally:
        setattr(gr, "_PROJECT_ROOT", original_root)

    assert exit_code == 1
    assert not output_path.exists()
