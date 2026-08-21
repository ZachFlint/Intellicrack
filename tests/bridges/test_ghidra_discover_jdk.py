# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the Ghidra JDK discovery version check.

Ghidra 11.4.x declares ``application.java.min=21`` and its JVM refuses to
launch against an older runtime. Before the version gate,
:meth:`GhidraBridge._discover_jdk` returned any ``JAVA_HOME`` that merely
contained a ``bin`` directory, so a host whose ``JAVA_HOME`` pointed at a JRE 8
was handed straight to PyGhidra, which then failed deep inside the JVM launch.

These tests build a real on-disk Ghidra installation layout and JDK ``release``
files in a temporary directory and assert that discovery skips the too-old
``JAVA_HOME`` in favour of a bundled JDK 21, accepts a ``JAVA_HOME`` that is a
valid JDK 21, and that :meth:`GhidraBridge._read_jdk_major` normalises both the
legacy ``1.8.0_x`` and modern ``21.0.8`` version schemes. No external tools are
touched; the fixtures are pure filesystem, so the suite runs in the sandbox.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from intellicrack.bridges.ghidra import GhidraBridge


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest


_discover_jdk = cast("Callable[[Path], Path | None]", getattr(GhidraBridge, "_discover_jdk"))
_read_jdk_major = cast("Callable[[Path], int | None]", getattr(GhidraBridge, "_read_jdk_major"))


def _write_release(java_home: Path, java_version: str) -> None:
    """Create a JDK layout with a ``bin`` dir and a Temurin ``release`` file.

    Args:
        java_home: Directory to populate as a JDK home.
        java_version: Value written for the ``JAVA_VERSION`` release key, for
            example ``"21.0.8"`` or ``"1.8.0_502"``.
    """
    bin_dir = java_home / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / "java.exe").write_bytes(b"MZ")
    (java_home / "release").write_text(
        f'IMPLEMENTOR="Eclipse Adoptium"\nJAVA_VERSION="{java_version}"\n',
        encoding="utf-8",
    )


def _build_ghidra_install(root: Path, min_jdk: int) -> Path:
    """Create a Ghidra installation directory declaring a minimum JDK.

    Args:
        root: Parent directory in which to create the installation.
        min_jdk: Value written for ``application.java.min``.

    Returns:
        Path: The root of the created Ghidra installation.
    """
    ghidra_path = root / "ghidra"
    props = ghidra_path / "Ghidra"
    props.mkdir(parents=True, exist_ok=True)
    (props / "application.properties").write_text(
        f"application.java.compiler={min_jdk}\napplication.java.max=\napplication.java.min={min_jdk}\n",
        encoding="utf-8",
    )
    return ghidra_path


def test_discover_jdk_skips_old_java_home_for_bundled_jdk21(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A JRE-8 ``JAVA_HOME`` is rejected in favour of a bundled JDK 21.

    Args:
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest environment-patching fixture.
    """
    ghidra_path = _build_ghidra_install(tmp_path, 21)
    bundled = ghidra_path / "jdk-21.0.8"
    _write_release(bundled, "21.0.8")

    jre8 = tmp_path / "jre8"
    _write_release(jre8, "1.8.0_502")
    monkeypatch.setenv("JAVA_HOME", str(jre8))

    result = _discover_jdk(ghidra_path)

    assert result == bundled


def test_discover_jdk_accepts_valid_jdk21_java_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``JAVA_HOME`` that is a valid JDK 21 is returned directly.

    Args:
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest environment-patching fixture.
    """
    ghidra_path = _build_ghidra_install(tmp_path, 21)
    bundled = ghidra_path / "jdk-21.0.8"
    _write_release(bundled, "21.0.8")

    java_home = tmp_path / "jdk21_home"
    _write_release(java_home, "21.0.8")
    monkeypatch.setenv("JAVA_HOME", str(java_home))

    result = _discover_jdk(ghidra_path)

    assert result == java_home


def test_read_jdk_major_normalises_legacy_and_modern_schemes(tmp_path: Path) -> None:
    """``1.8.0_502`` maps to 8 and ``21.0.8`` maps to 21.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    legacy = tmp_path / "legacy"
    _write_release(legacy, "1.8.0_502")
    modern = tmp_path / "modern"
    _write_release(modern, "21.0.8")

    assert _read_jdk_major(legacy) == 8
    assert _read_jdk_major(modern) == 21
