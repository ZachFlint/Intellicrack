# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Fix two defects PyQt6 ships in its type stubs.

PyQt6 6.11.0 ships 35 ``.pyi`` stubs with the same two mistakes, and with
``useLibraryCodeForTypes`` disabled each one makes basedpyright resolve part
of a type to Unknown:

* The stubs ``import collections, re, typing, enum`` and then use
  ``collections.abc.Callable`` and friends throughout, without ever importing
  the ``abc`` submodule.
* They define the slot type as ``PYQT_SLOT = typing.Union[
  collections.abc.Callable[..., Any], ...]``, but import ``typing`` as a module
  and never import a bare ``Any``, so the slot's return type is undefined.

Between them they give every ``pyqtBoundSignal.connect``, ``disconnect``,
``QTimer.singleShot`` and ``addAction`` a partially unknown slot parameter, and
turn every signal connection in the UI into a basedpyright error. The return
type becomes ``object``: a slot's return value is discarded, so any callable
is acceptable, and ``object`` states that without falling back to ``Any``.

This script used to fix only the import, and only in ``QtWidgets.pyi``. An
environment whose other stubs had been fixed by hand type-checked clean while
a fresh install -- CI's -- reported over a thousand errors. Both defects are
fixed now, in every affected stub.

The script is **idempotent**: a second run changes nothing, and a line an
earlier version damaged with repeated ``collections.abc`` entries is repaired
to a single one. It exits quietly when PyQt6 is absent.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path


_COLLECTIONS_ABC_REFERENCE = "collections.abc."
"""Text a stub contains when it depends on the ``abc`` submodule."""

_COLLECTIONS_IMPORT = re.compile(r"^import[ \t]+collections(?![.\w])(?P<rest>[^\n#]*)$", re.MULTILINE)
"""The ``import collections, ...`` line, excluding ``import collections.abc`` itself."""

_PYQT_SLOT_ANY = re.compile(
    r"^(?P<head>PYQT_SLOT\s*=\s*typing\.Union\[collections\.abc\.Callable\[\.\.\.,\s*)Any(?P<tail>\])",
    re.MULTILINE,
)
"""The module-level ``PYQT_SLOT`` definition whose return type names an undefined ``Any``.

Anchored to that one definition: ``QtGui.pyi`` also declares a class-level
enum member called ``Any``, which must be left alone.
"""


def _pyqt6_package_dir() -> Path | None:
    """Return the installed ``PyQt6`` package directory, or *None* if missing.

    Returns:
        Path | None: The package directory if PyQt6 is importable.
    """
    spec = importlib.util.find_spec("PyQt6")
    if spec is None or spec.origin is None:
        return None
    return Path(spec.origin).parent


def _locate_qtwidgets_pyi() -> Path | None:
    """Return the path to ``PyQt6/QtWidgets.pyi``, or *None* if missing.

    Returns:
        Path | None: Path to the type hint file if found, None otherwise.
    """
    package_dir = _pyqt6_package_dir()
    if package_dir is None:
        return None
    pyi = package_dir / "QtWidgets.pyi"
    return pyi if pyi.is_file() else None


def _canonical_import(rest: str) -> str:
    """Build the ``import collections`` line with ``collections.abc`` exactly once.

    Modules keep their original order, a repeated name is kept once, and
    ``collections.abc`` sits directly after ``collections`` -- the form the
    patch has always produced, so a stub patched by an earlier run keeps its
    line unchanged.

    Args:
        rest: Everything on the import line after ``import collections``.

    Returns:
        str: The canonical import line, without a trailing newline.
    """
    ordered: list[str] = ["collections"]
    for name in (part.strip() for part in rest.split(",")):
        if name and name not in ordered:
            ordered.append(name)
    if "collections.abc" in ordered:
        ordered.remove("collections.abc")
    ordered.insert(1, "collections.abc")
    return "import " + ", ".join(ordered)


def _needs_patch(text: str) -> bool:
    """Return *True* when the stub is not already in its corrected form.

    Defined through :func:`_apply_patch` rather than by a separate pattern, so
    the two can never disagree: a line the patch would leave alone is never
    reported as needing it. The previous pattern backtracked over the space
    after the comma and reported an already-patched line as unpatched, so
    every run added another ``collections.abc`` to the same line.

    Args:
        text: Full text content of the type hint file.

    Returns:
        bool: True if the import line needs patching.
    """
    return _apply_patch(text) != text


def _apply_patch(text: str) -> str:
    """Rewrite a stub's ``import collections`` line and ``PYQT_SLOT`` definition.

    The import gains ``collections.abc`` when it is missing, with the
    duplicate entries a non-idempotent earlier version of this script
    accumulated collapsed to one, and ``PYQT_SLOT``'s undefined ``Any`` return
    type becomes ``object``.

    Args:
        text: Full text content of the type hint file.

    Returns:
        str: The text with both definitions corrected.
    """
    text = _COLLECTIONS_IMPORT.sub(lambda match: _canonical_import(match.group("rest")), text, count=1)
    return _PYQT_SLOT_ANY.sub(r"\g<head>object\g<tail>", text, count=1)


def patch_stub_directory(directory: Path) -> list[Path]:
    """Patch every stub in ``directory`` that carries either shipped defect.

    A stub is rewritten only when it references ``collections.abc.`` and the
    patch would change it, so a stub that never touches ``collections.abc`` is
    left byte-for-byte alone.

    Args:
        directory: Directory holding the ``.pyi`` stubs, typically the
            installed ``PyQt6`` package.

    Returns:
        list[Path]: The stubs that were rewritten, in sorted order.
    """
    patched: list[Path] = []
    for pyi in sorted(directory.glob("*.pyi")):
        text = pyi.read_text(encoding="utf-8")
        if _COLLECTIONS_ABC_REFERENCE not in text or not _needs_patch(text):
            continue
        pyi.write_text(_apply_patch(text), encoding="utf-8")
        patched.append(pyi)
    return patched


def main() -> int:
    """Patch every affected stub in the installed PyQt6 package.

    Returns:
        int: Exit code (0 = success/no-op, 1 = error).
    """
    package_dir = _pyqt6_package_dir()
    if package_dir is None or _locate_qtwidgets_pyi() is None:
        print("PyQt6 not installed or shipped without type stubs -- skipping")
        return 0

    patched = patch_stub_directory(package_dir)
    if not patched:
        print(f"PyQt6 stubs already correct: {package_dir}")
        return 0

    names = ", ".join(pyi.name for pyi in patched)
    print(f"Patched {len(patched)} PyQt6 stub(s) in {package_dir}: {names}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
