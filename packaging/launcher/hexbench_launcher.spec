# -*- mode: python ; coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
#
# Build description for the installed Hexbench shortcut target. It is invoked
# from the repository root by the staging script:
#
#     pixi run pyinstaller packaging/launcher/hexbench_launcher.spec
#
# This is not the standalone Hexbench build. src/hexbench/hexbench.spec freezes
# the editor itself, interpreter and all, for distribution on its own. This one
# carries no editor code at all: it is a small, stdlib-only bootstrapper that
# resolves the runtime and the hexbench package the installer laid down beside
# it and spawns runtime/python.exe -m hexbench. Shipping the standalone build
# inside the installer instead would embed a second interpreter, webview and
# hexcore alongside the ones the runtime already provides.
#
# The result is windowed. The launcher never writes to a stream on its normal
# path, and reports a failure it cannot recover from in a dialog instead, so it
# needs no console of its own -- while the child it spawns is started under
# CREATE_NO_WINDOW precisely so that the child keeps one.

from pathlib import Path


REPO_ROOT = Path(SPECPATH).resolve().parents[1]
LAUNCHER_SCRIPT = REPO_ROOT / "packaging" / "launcher" / "hexbench_launcher.py"
ICON_FILE = REPO_ROOT / "src" / "hexbench" / "hexbench.ico"


a = Analysis(
    [str(LAUNCHER_SCRIPT)],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Hexbench",
    icon=str(ICON_FILE),
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
