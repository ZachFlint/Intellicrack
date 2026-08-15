# -*- mode: python ; coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
#
# Build description for the Hexbench executable. Run it through the justfile
# recipe rather than by hand:
#
#     just build-hexbench
#
# Three things have to be carried in deliberately, because nothing in the
# import graph reveals them:
#
#   * The static tree. It is read from disk at request time, never imported.
#   * The engine's type stub. hexbench.catalog parses __init__.pyi beside the
#     compiled extension to recover the annotations PyO3 does not expose at
#     runtime, so a build without it starts and then fails to build a
#     catalogue at all. Its neighbours are collected by name rather than by
#     scanning the directory, which would also sweep in the debug symbols and
#     any superseded .pyd the build system left behind.
#   * The window toolkit. hexbench.window imports it through importlib so that
#     the modes opening no window still work without it, and an import the
#     analysis cannot see is an import it cannot follow.
#
# The console is kept and hidden early rather than dropped. A windowed build
# leaves sys.stderr as None, which turns every diagnostic this program writes
# into an AttributeError; keeping it means a session started from a terminal
# still reports, while one started from Explorer shows no console window.

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

import intellicrack_hexcore


PACKAGE_ROOT = Path(SPECPATH)
SOURCE_ROOT = PACKAGE_ROOT.parent
ENGINE_ROOT = Path(intellicrack_hexcore.__file__).parent
ENGINE_FILES = ("__init__.pyi", "py.typed")
TOOLKIT = "webview"

datas = [(str(PACKAGE_ROOT / "static"), "hexbench/static")]
datas += [(str(ENGINE_ROOT / name), "intellicrack_hexcore") for name in ENGINE_FILES]

hiddenimports = [TOOLKIT, *collect_submodules(TOOLKIT)]

analysis = Analysis(
    [str(PACKAGE_ROOT / "launch.py")],
    pathex=[str(SOURCE_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PyQt6", "PySide6", "matplotlib", "numpy", "pytest", "tkinter"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="Hexbench",
    icon=str(PACKAGE_ROOT / "hexbench.ico"),
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    hide_console="hide-early",
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
