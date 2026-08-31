# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the Ghidra bridge PyGhidra migration (F15).

Ghidra 11.3+/12.x dropped the bundled Jython interpreter, so the bridge was
migrated to launch ``analyzeHeadless`` through PyGhidra (CPython/jpype). These
gates pin the migration-specific invariants that cannot regress silently:

  1. :meth:`GhidraBridge._discover_jdk` must prefer a valid ``JAVA_HOME`` and
     otherwise select the highest-versioned bundled ``jdk-*`` that actually
     contains a ``bin`` directory, so the PyGhidra JVM launch resolves a real
     runtime. Exercised against a real temporary Ghidra tree.

  2. :meth:`GhidraBridge.decompile` must build its remote script around an
     explicitly constructed ``DecompileOptions()`` (never ``ifc.getOptions()``,
     which returns ``null`` in headless and yields a decompiler
     ``NullPointerException``), and must apply the simplification style on the
     ``DecompInterface`` where that setter actually lives. The generated script
     is captured and asserted directly.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


_discover_jdk = cast("Callable[[Path], Path | None]", getattr(GhidraBridge, "_discover_jdk"))


def _write_jdk_release(java_home: Path, java_version: str) -> None:
    """Write a Temurin-style ``release`` file into a JDK home.

    Args:
        java_home: The JDK home directory to populate.
        java_version: Value written for the ``JAVA_VERSION`` release key, for
            example ``"25.0.3"``.
    """
    (java_home / "release").write_text(
        f'JAVA_VERSION="{java_version}"\n',
        encoding="utf-8",
    )


def _make_jdk(root: Path, name: str, *, with_bin: bool) -> Path:
    """Create a fake bundled JDK directory inside a Ghidra tree.

    The directory name (``jdk-<version>``) determines the ``JAVA_VERSION`` value
    written into a ``release`` file, so the discovery version gate resolves a
    real major version for the JDK.

    Args:
        root: The Ghidra installation root to create the JDK under.
        name: The JDK directory name (e.g. ``"jdk-25.0.3"``).
        with_bin: Whether to create a ``bin`` subdirectory, marking the JDK as
            usable for the discovery filter.

    Returns:
        Path: The created JDK directory.
    """
    jdk = root / name
    jdk.mkdir(parents=True, exist_ok=True)
    _write_jdk_release(jdk, name.removeprefix("jdk-"))
    if with_bin:
        (jdk / "bin").mkdir(exist_ok=True)
    return jdk


def test_discover_jdk_prefers_valid_java_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``JAVA_HOME`` that contains a ``bin`` directory must win over bundled JDKs.

    Fails if the environment preference is dropped or the ``bin`` validity check
    is removed.

    Args:
        tmp_path: Pytest temp dir root.
        monkeypatch: Fixture used to set ``JAVA_HOME``.
    """
    java_home = tmp_path / "system_jdk"
    (java_home / "bin").mkdir(parents=True)
    _write_jdk_release(java_home, "21.0.8")

    ghidra_root = tmp_path / "ghidra"
    _make_jdk(ghidra_root, "jdk-25.0.3", with_bin=True)

    monkeypatch.setenv("JAVA_HOME", str(java_home))

    resolved = _discover_jdk(ghidra_root)
    assert resolved == java_home


def test_discover_jdk_ignores_java_home_without_bin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``JAVA_HOME`` lacking ``bin`` must be rejected in favour of a bundled JDK.

    Fails if the ``bin`` validity check on ``JAVA_HOME`` is removed (a bogus
    ``JAVA_HOME`` would then be returned and break the JVM launch).

    Args:
        tmp_path: Pytest temp dir root.
        monkeypatch: Fixture used to set ``JAVA_HOME``.
    """
    bogus_home = tmp_path / "not_a_jdk"
    bogus_home.mkdir()

    ghidra_root = tmp_path / "ghidra"
    bundled = _make_jdk(ghidra_root, "jdk-25.0.3", with_bin=True)

    monkeypatch.setenv("JAVA_HOME", str(bogus_home))

    resolved = _discover_jdk(ghidra_root)
    assert resolved == bundled


def test_discover_jdk_selects_highest_bundled_with_bin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovery must select the highest bundled ``jdk-*`` that has a ``bin`` dir.

    A newer-named JDK missing ``bin`` must be skipped in favour of the highest
    complete one. Fails if the ``bin`` filter is dropped (the incomplete
    ``jdk-99`` would then be selected) or the highest-version ordering regresses.

    Args:
        tmp_path: Pytest temp dir root.
        monkeypatch: Fixture used to clear ``JAVA_HOME``.
    """
    monkeypatch.delenv("JAVA_HOME", raising=False)

    ghidra_root = tmp_path / "ghidra"
    _make_jdk(ghidra_root, "jdk-21.0.2", with_bin=True)
    _make_jdk(ghidra_root, "jdk-23.0.9", with_bin=True)
    complete_high = _make_jdk(ghidra_root, "jdk-25.0.3", with_bin=True)
    _make_jdk(ghidra_root, "jdk-99.0.0", with_bin=False)

    resolved = _discover_jdk(ghidra_root)
    assert resolved == complete_high


def test_discover_jdk_returns_none_when_nothing_usable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovery must return ``None`` when neither env nor a bundled JDK is usable.

    Fails if a non-existent ``JAVA_HOME`` or a bin-less bundled JDK is returned
    instead of ``None`` (which would suppress PyGhidra's own JVM discovery).

    Args:
        tmp_path: Pytest temp dir root.
        monkeypatch: Fixture used to clear ``JAVA_HOME``.
    """
    monkeypatch.delenv("JAVA_HOME", raising=False)

    ghidra_root = tmp_path / "ghidra"
    _make_jdk(ghidra_root, "jdk-25.0.3", with_bin=False)

    resolved = _discover_jdk(ghidra_root)
    assert resolved is None


@pytest.mark.asyncio
async def test_decompile_script_constructs_decompile_options_explicitly() -> None:
    """Decompile must build the remote script with an explicit ``DecompileOptions()``.

    In headless mode ``ifc.getOptions()`` returns ``null`` and the decompiler
    later raises ``NullPointerException`` on ``options.getNameTransformer()``.
    The generated script must therefore import and construct ``DecompileOptions``
    directly and never call ``ifc.getOptions()``. The real script is captured by
    intercepting ``_execute_remote`` (which returns a success outcome so
    ``decompile`` completes). Fails if the script regresses to ``getOptions()``.
    """
    bridge = GhidraBridge()
    setattr(bridge, "_bridge", object())

    captured: list[str] = []

    async def _capture(code: str) -> object:
        await asyncio.sleep(0)
        captured.append(code)
        return {"status": "ok", "code": "undefined8 FUN_140001010(void)\n{\n  return 0;\n}\n", "error": None}

    setattr(bridge, "_execute_remote", _capture)

    result = await bridge.decompile(0x140001010)
    assert result.startswith("undefined8 FUN_140001010")

    assert len(captured) == 1
    script = captured[0]
    assert "from ghidra.app.decompiler import DecompInterface, DecompileOptions" in script
    assert "opts = DecompileOptions()" in script
    assert "ifc.getOptions()" not in script
    assert "ifc.openProgram(currentProgram)" in script


@pytest.mark.asyncio
async def test_decompile_script_applies_simplification_on_interface() -> None:
    """A configured simplification style must be applied on the ``DecompInterface``.

    ``setSimplificationStyle`` lives on ``DecompInterface``, not on
    ``DecompileOptions``; the migrated script must call it on ``ifc`` with the
    configured style. Fails if the setter is dropped or applied to the options
    object (which has no such method).
    """
    bridge = GhidraBridge()
    setattr(bridge, "_bridge", object())
    setattr(bridge, "_decompiler_simplification", "normalize")

    captured: list[str] = []

    async def _capture(code: str) -> object:
        await asyncio.sleep(0)
        captured.append(code)
        return {"status": "ok", "code": "void f(void){return;}", "error": None}

    setattr(bridge, "_execute_remote", _capture)

    await bridge.decompile(0x401000)

    script = captured[0]
    assert 'simp = "normalize"' in script
    assert "ifc.setSimplificationStyle(simp)" in script


@pytest.mark.asyncio
async def test_decompile_raises_on_null_options_regression_marker() -> None:
    """A remote decompile failure must surface as a ToolError with detail.

    Models the exact headless failure the F15 fix eliminates: the remote script
    reporting a decompiler failure. ``decompile`` must raise ``ToolError``
    carrying the error detail rather than returning an opaque sentinel. Fails if
    the failure branch is swallowed.
    """
    bridge = GhidraBridge()
    setattr(bridge, "_bridge", object())

    async def _capture(_code: str) -> object:
        await asyncio.sleep(0)
        return {
            "status": "decompile_failed",
            "code": None,
            "error": 'Cannot invoke "DecompileOptions.getNameTransformer()" because "options" is null',
        }

    setattr(bridge, "_execute_remote", _capture)

    with pytest.raises(ToolError) as exc_info:
        await bridge.decompile(0x401000)

    message = str(exc_info.value)
    assert "options" in message
