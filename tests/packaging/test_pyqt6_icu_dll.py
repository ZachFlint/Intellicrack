# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Falsifiable gates for the PyQt6 QtCore DLL load on Windows.

Qt 6.10+ Windows builds link ``Qt6Core.dll`` against the OS-provided,
unversioned ``icuuc.dll``/``icu.dll`` pair instead of bundling their own ICU
(see doc.qt.io/qt-6/qtwebengine-3rdparty-icu.html), and the PyQt6-Qt6 wheel
does not bundle an ``icuuc.dll`` of its own -- confirmed against the wheel's
``RECORD``, which lists no ``icu*`` file. On a Windows build where
``System32\icuuc.dll``'s export forwards to ``System32\icu.dll`` fail to
resolve at load time (verified here with a ctypes ``GetProcAddress`` probe:
the forwarder loads, but ``ucnv_open`` and friends resolve to nothing through
it even though ``icu.dll`` implements every one of them directly),
``import PyQt6.QtCore`` fails with ``ImportError: DLL load failed while
importing QtCore: The specified procedure could not be found``. That crashes
pytest-qt's plugin bootstrap (``qt_compat._can_import``) before pytest can
collect a single test.

``scripts/fix-pyqt6-icu.ps1`` (``just fix-pyqt6-icu``) fixes this by copying
the local machine's own ``System32\icu.dll`` -- which holds direct,
non-forwarded implementations of every symbol ``Qt6Core.dll`` imports -- to
``PyQt6\Qt6\bin\icuuc.dll``, right next to ``Qt6Core.dll``. Windows always
searches the directory containing the importing DLL before System32, so this
local copy resolves first and the broken System32 forwarder chain is never
consulted. The copy lives only under the gitignored ``.pixi\envs`` tree; it
is a per-machine environment fix, not a repo change.

These gates import PyQt6 through ``importlib.import_module`` rather than a
module-level ``import`` statement, so a DLL load failure surfaces as one
isolated, clearly-attributed test failure instead of a collection error for
the whole file.
"""

from __future__ import annotations

import importlib
import os
import re
from pathlib import Path
from typing import Final


_VERSION_RE: Final[re.Pattern[str]] = re.compile(r"^\d+\.\d+\.\d+$")


def test_pyqt6_qtcore_imports_and_reports_a_real_version() -> None:
    """``PyQt6.QtCore`` must import cleanly and report a well-formed Qt version.

    This is the exact statement the DLL load failure broke: an
    ``ImportError: DLL load failed while importing QtCore`` here means
    ``Qt6Core.dll`` could not resolve one of its imports, and would redden
    every test that needs PyQt6 -- starting with pytest-qt's own plugin
    bootstrap, which crashes pytest before any test is even collected.
    """
    qtcore = importlib.import_module("PyQt6.QtCore")

    version = qtcore.QT_VERSION_STR
    assert _VERSION_RE.match(version), f"QT_VERSION_STR is not a well-formed version: {version!r}"


def test_pyqt6_qtwidgets_constructs_a_real_application_and_widget() -> None:
    """A real ``QApplication`` and widget must construct end-to-end.

    Importing ``QtCore`` alone only proves ``Qt6Core.dll`` resolved its
    imports. Constructing a ``QApplication`` and a widget pulls in
    ``Qt6Gui.dll`` and ``Qt6Widgets.dll`` too, so this catches a break
    anywhere in that chain, not only the ICU symbol ``Qt6Core.dll`` needs.
    """
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    widgets = importlib.import_module("PyQt6.QtWidgets")

    app = widgets.QApplication.instance()
    if app is None:
        app = widgets.QApplication([])

    label = widgets.QLabel("intellicrack")
    assert label.text() == "intellicrack"


def test_qt6core_dll_resolves_icuuc_next_to_itself() -> None:
    r"""``Qt6Core.dll``'s own directory must carry a working ``icuuc.dll``.

    Structural companion to the two import gates above: pins the fix's actual
    mechanism (an ``icuuc.dll`` placed next to ``Qt6Core.dll`` in
    ``PyQt6\Qt6\bin``) so a regression that silently drops just that one
    file gets a message pointing straight at the fix, instead of only a bare
    ``ImportError`` that sends the next person back through the whole
    diagnosis. A regenerated pixi environment that never re-ran the fix
    reddens this the same way it reddens the two import gates above.
    """
    qtcore = importlib.import_module("PyQt6.QtCore")
    qtcore_file = qtcore.__file__
    assert qtcore_file is not None, "PyQt6.QtCore has no __file__; it did not load from a compiled extension module"

    qt6_bin = Path(qtcore_file).resolve().parent / "Qt6" / "bin"
    icuuc = qt6_bin / "icuuc.dll"
    assert icuuc.is_file(), f"{icuuc} is missing; run 'just fix-pyqt6-icu' (or 'pixi run fix-pyqt6-icu') to restore it"
