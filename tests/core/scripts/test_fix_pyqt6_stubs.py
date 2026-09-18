# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for the PyQt6 stub fixer that keeps CI's type check honest.

PyQt6 6.11.0 ships 35 ``.pyi`` stubs that reference ``collections.abc.*``
while importing only ``collections``. Left unpatched, basedpyright resolves
the slot type of every ``signal.connect`` to Unknown, and a fresh environment
reports over a thousand errors that a hand-patched one does not. The fixer
used to patch only ``QtWidgets.pyi``.

The gate works on copies of the real installed stubs with the import line
restored to the exact form the 6.11.0 wheel ships, so it exercises the real
files without depending on whether the local environment was already patched,
and without modifying it.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from types import ModuleType


_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "fix_pyqt6_stubs.py"
_SHIPPED_IMPORT = "import collections, re, typing, enum"
"""The import line PyQt6 6.11.0 ships in every affected stub."""

_PATCHED_IMPORT = re.compile(r"^import\s+collections\s*,\s*collections\.abc\b", re.MULTILINE)


def _load_script() -> ModuleType:
    """Import ``scripts/fix_pyqt6_stubs.py`` as a module.

    Returns:
        ModuleType: The loaded script module.
    """
    spec = importlib.util.spec_from_file_location("fix_pyqt6_stubs", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def shipped_stubs(tmp_path: Path) -> Path:
    """Copy the installed PyQt6 stubs and restore their shipped import line.

    Args:
        tmp_path: Per-test directory the copies are written to.

    Returns:
        Path: Directory holding stubs byte-identical to the 6.11.0 wheel's
        import line, whatever the installed copies currently say.
    """
    spec = importlib.util.find_spec("PyQt6")
    assert spec is not None
    assert spec.origin is not None
    installed = Path(spec.origin).parent
    target = tmp_path / "PyQt6"
    target.mkdir()
    for pyi in installed.glob("*.pyi"):
        text = pyi.read_text(encoding="utf-8")
        restored = re.sub(r"^import\s+collections\s*,\s*collections\.abc\s*,", "import collections,", text, count=1, flags=re.MULTILINE)
        _ = (target / pyi.name).write_text(restored, encoding="utf-8")
    return target


def _stubs_missing_the_import(directory: Path) -> list[str]:
    """List stubs that use ``collections.abc`` without importing it.

    Args:
        directory: Directory of ``.pyi`` stubs.

    Returns:
        list[str]: Names of the defective stubs, sorted.
    """
    missing: list[str] = []
    for pyi in sorted(directory.glob("*.pyi")):
        text = pyi.read_text(encoding="utf-8")
        if "collections.abc." in text and _PATCHED_IMPORT.search(text) is None:
            missing.append(pyi.name)
    return missing


def test_the_fixture_reproduces_the_shipped_defect(shipped_stubs: Path) -> None:
    """The copied stubs must be defective, or the next gate proves nothing.

    Args:
        shipped_stubs: Stubs carrying the wheel's own import line.
    """
    defective = _stubs_missing_the_import(shipped_stubs)
    assert "QtCore.pyi" in defective
    assert "QtWidgets.pyi" in defective
    assert len(defective) > 2


def test_every_affected_stub_is_patched(shipped_stubs: Path) -> None:
    """Every stub that uses ``collections.abc`` must import it afterwards.

    ``QtCore.pyi`` is named explicitly: it defines ``PYQT_SLOT``, the type of
    every ``connect`` slot, and it is the stub a QtWidgets-only fix missed.

    Args:
        shipped_stubs: Stubs carrying the wheel's own import line.
    """
    script = _load_script()
    before = _stubs_missing_the_import(shipped_stubs)

    patched = script.patch_stub_directory(shipped_stubs)

    assert sorted(path.name for path in patched) == before
    assert _stubs_missing_the_import(shipped_stubs) == []
    core = (shipped_stubs / "QtCore.pyi").read_text(encoding="utf-8")
    assert _PATCHED_IMPORT.search(core) is not None


def test_patching_is_idempotent_and_leaves_other_stubs_alone(shipped_stubs: Path) -> None:
    """A second run changes nothing, and a stub without the defect is untouched.

    Args:
        shipped_stubs: Stubs carrying the wheel's own import line.
    """
    script = _load_script()
    untouched = shipped_stubs / "Unaffected.pyi"
    original = "import typing\n\ndef f() -> typing.Any: ...\n"
    _ = untouched.write_text(original, encoding="utf-8")

    _ = script.patch_stub_directory(shipped_stubs)
    snapshot = {pyi.name: pyi.read_text(encoding="utf-8") for pyi in shipped_stubs.glob("*.pyi")}

    assert script.patch_stub_directory(shipped_stubs) == []
    assert {pyi.name: pyi.read_text(encoding="utf-8") for pyi in shipped_stubs.glob("*.pyi")} == snapshot
    assert untouched.read_text(encoding="utf-8") == original


def test_a_line_damaged_by_repeated_runs_is_repaired(tmp_path: Path) -> None:
    """Repeated ``collections.abc`` entries from the old script collapse to one.

    The previous version reported an already-patched line as unpatched and
    appended another entry on every run; a developer environment had
    accumulated 148 of them in ``QtWidgets.pyi``.

    Args:
        tmp_path: Per-test directory for the damaged stub.
    """
    script = _load_script()
    damaged = tmp_path / "QtWidgets.pyi"
    repeated = ", ".join(["collections.abc"] * 148)
    _ = damaged.write_text(
        f"import collections, {repeated}, re, typing, enum\n\ndef f(x: collections.abc.Callable[..., object]) -> None: ...\n",
        encoding="utf-8",
    )

    assert [path.name for path in script.patch_stub_directory(tmp_path)] == ["QtWidgets.pyi"]
    first_line = damaged.read_text(encoding="utf-8").splitlines()[0]
    assert first_line == "import collections, collections.abc, re, typing, enum"
    assert script.patch_stub_directory(tmp_path) == []


def test_the_restored_line_matches_what_the_wheel_ships(shipped_stubs: Path) -> None:
    """Guard the fixture itself against drifting from the real shipped text.

    Args:
        shipped_stubs: Stubs carrying the wheel's own import line.
    """
    core = (shipped_stubs / "QtCore.pyi").read_text(encoding="utf-8")
    assert _SHIPPED_IMPORT in core
