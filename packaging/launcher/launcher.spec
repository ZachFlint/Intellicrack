# -*- mode: python ; coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
#
# Build description for the Intellicrack installer launcher. It is invoked from
# the repository root by the staging script:
#
#     pixi run pyinstaller packaging/launcher/launcher.spec
#
# The launcher is a small, stdlib-only bootstrapper. It carries no application
# code: it resolves the bundled runtime and application source that the
# installer lays down beside it and spawns runtime/pythonw.exe -m intellicrack.
# The result is a single, windowed executable named Intellicrack.
#
# The Win32 version resource is generated into the build directory rather than
# tracked, because every field in it is derived from src/intellicrack/_metadata.py
# by version_resource.py beside this file. See that module for how the version
# stays tied to the one the installer stamps.

import sys
from pathlib import Path


SPEC_DIR = Path(SPECPATH).resolve()
if str(SPEC_DIR) not in sys.path:
    sys.path.insert(0, str(SPEC_DIR))

from version_resource import write_version_resource

REPO_ROOT = SPEC_DIR.parents[1]
LAUNCHER_SCRIPT = REPO_ROOT / "packaging" / "launcher" / "launcher.py"
ICON_FILE = REPO_ROOT / "src" / "intellicrack" / "assets" / "icon.ico"
VERSION_FILE = write_version_resource(
    destination=Path(workpath) / "Intellicrack.version.txt",
    repo_root=REPO_ROOT,
    executable_name="Intellicrack",
)


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
    name="Intellicrack",
    icon=str(ICON_FILE),
    version=str(VERSION_FILE),
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
