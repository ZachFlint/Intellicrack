# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for bundled QEMU guest-image discovery.

The installer stages an ~800 MB ready-to-run guest at
``<install_root>/qemu-guest``, but the sandbox settings left ``qemu_image_path``
unset, so the QEMU backend reported "no image configured" and could not start
from a fresh install. ``default_qemu_image()`` closes that gap by discovering a
bundled ``*.qcow2`` under the deployment root (and, for a dev checkout, under
``tools/qemu/images``); ``build_qemu_config`` falls back to it when the user has
configured no explicit image.

These gates pin that discovery and fallback, and the hard-won constraint that
image discovery must not make backend availability image-dependent -- it only
supplies a default disk image.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from intellicrack.sandbox import settings as settings_module
from intellicrack.sandbox.settings import (
    QEMU_IMAGE_PATH_KEY,
    build_qemu_config,
    default_qemu_image,
)


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _make_guest_image(root: Path, *segments: str) -> Path:
    """Create a stub ``guest.qcow2`` under ``root`` joined with ``segments``.

    Args:
        root: The deployment-root stand-in to populate.
        *segments: Directory segments under ``root`` in which to place the image.

    Returns:
        Path: The path to the created stub image.
    """
    directory = root.joinpath(*segments)
    directory.mkdir(parents=True, exist_ok=True)
    image = directory / "guest.qcow2"
    image.write_bytes(b"QFI\xfb")
    return image


def test_default_image_discovers_installed_guest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The installed ``<install_root>/qemu-guest`` image is discovered automatically.

    Args:
        tmp_path: Pytest temporary directory used as the deployment root.
        monkeypatch: Pytest patching fixture.
    """
    install_root = tmp_path / "install"
    install_root.mkdir()
    image = _make_guest_image(install_root, "qemu-guest")
    monkeypatch.setattr(settings_module, "get_project_root", lambda: install_root)

    assert default_qemu_image() == image


def test_default_image_discovers_dev_checkout_guest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A development checkout's ``tools/qemu/images`` guest is discovered.

    Args:
        tmp_path: Pytest temporary directory used as the deployment root.
        monkeypatch: Pytest patching fixture.
    """
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    image = _make_guest_image(repo_root, "tools", "qemu", "images")
    monkeypatch.setattr(settings_module, "get_project_root", lambda: repo_root)

    assert default_qemu_image() == image


def test_default_image_is_none_without_a_bundled_guest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no bundled ``*.qcow2`` present, discovery returns ``None`` (no crash).

    Args:
        tmp_path: Pytest temporary directory used as an empty deployment root.
        monkeypatch: Pytest patching fixture.
    """
    empty_root = tmp_path / "empty" / "app"
    empty_root.mkdir(parents=True)
    monkeypatch.setattr(settings_module, "get_project_root", lambda: empty_root)

    assert default_qemu_image() is None


def test_build_config_falls_back_to_bundled_guest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no configured image, ``build_qemu_config`` adopts the bundled guest.

    Args:
        tmp_path: Pytest temporary directory used as the deployment root.
        monkeypatch: Pytest patching fixture.
    """
    install_root = tmp_path / "install"
    install_root.mkdir()
    image = _make_guest_image(install_root, "qemu-guest")
    monkeypatch.setattr(settings_module, "get_project_root", lambda: install_root)

    config = build_qemu_config({})
    assert config.image_path == image


def test_configured_image_wins_over_bundled_guest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicitly configured image is honoured over the discovered bundled one.

    Args:
        tmp_path: Pytest temporary directory used as the deployment root.
        monkeypatch: Pytest patching fixture.
    """
    install_root = tmp_path / "install"
    install_root.mkdir()
    _make_guest_image(install_root, "qemu-guest")
    monkeypatch.setattr(settings_module, "get_project_root", lambda: install_root)

    chosen = tmp_path / "chosen" / "win10.qcow2"
    chosen.parent.mkdir(parents=True)
    chosen.write_bytes(b"QFI\xfb")

    config = build_qemu_config({QEMU_IMAGE_PATH_KEY: str(chosen)})
    assert config.image_path == chosen


def test_discovery_returns_the_first_image_deterministically(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Discovery is deterministic: the lexicographically first ``*.qcow2`` is chosen.

    Args:
        tmp_path: Pytest temporary directory used as the deployment root.
        monkeypatch: Pytest patching fixture.
    """
    install_root = tmp_path / "install"
    guest_dir = install_root / "qemu-guest"
    guest_dir.mkdir(parents=True)
    for name in ("zeta.qcow2", "alpha.qcow2", "middle.qcow2"):
        (guest_dir / name).write_bytes(b"QFI\xfb")
    monkeypatch.setattr(settings_module, "get_project_root", lambda: install_root)

    discovered = default_qemu_image()
    assert discovered is not None
    assert discovered.name == "alpha.qcow2"


def test_default_image_resolves_install_root_from_bundled_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The install root is anchored on the bundled runtime, not on package depth.

    Simulates the installed layout where the launcher spawns
    ``<install_root>/runtime/pythonw.exe`` while the ``intellicrack`` package
    resolves somewhere entirely unrelated (a wheel / ``site-packages`` install).
    The bundled guest at ``<install_root>/qemu-guest`` must still be discovered
    via the runtime-derived install root, even though neither the package-relative
    root nor its parent contains a guest. Falsifiable: the pre-fix code, which
    only probed ``get_project_root()`` and its parent, returns ``None`` here.

    Args:
        tmp_path: Pytest temporary directory used to build the layout.
        monkeypatch: Pytest patching fixture.
    """
    install_root = tmp_path / "Program Files" / "Intellicrack"
    runtime_dir = install_root / "runtime"
    runtime_dir.mkdir(parents=True)
    fake_interpreter = runtime_dir / "pythonw.exe"
    fake_interpreter.write_bytes(b"MZ")
    image = _make_guest_image(install_root, "qemu-guest")

    stray_root = tmp_path / "unrelated" / "site-packages" / "intellicrack"
    stray_root.mkdir(parents=True)
    monkeypatch.setattr(settings_module, "get_project_root", lambda: stray_root)
    monkeypatch.setattr(settings_module.sys, "executable", str(fake_interpreter))

    assert default_qemu_image() == image


def test_non_runtime_interpreter_is_not_used_as_install_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A development interpreter's grandparent is never treated as an install root.

    The runtime anchor is gated on the interpreter living inside a ``runtime``
    directory, which is the contract the frozen launcher guarantees. A dev
    interpreter (here under ``.pixi/envs/default``) must not have its grandparent
    adopted as a deployment root, so an unrelated ``*.qcow2`` sitting beside it is
    never mistaken for a bundled guest. Falsifiable: dropping the ``runtime``
    gate and using the interpreter grandparent unconditionally discovers the
    stray image and this gate reddens.

    Args:
        tmp_path: Pytest temporary directory used to build the layout.
        monkeypatch: Pytest patching fixture.
    """
    envs_dir = tmp_path / ".pixi" / "envs"
    default_env = envs_dir / "default"
    default_env.mkdir(parents=True)
    fake_interpreter = default_env / "python.exe"
    fake_interpreter.write_bytes(b"MZ")
    _make_guest_image(envs_dir, "qemu-guest")

    clean_root = tmp_path / "clean"
    clean_root.mkdir()
    monkeypatch.setattr(settings_module, "get_project_root", lambda: clean_root)
    monkeypatch.setattr(settings_module.sys, "executable", str(fake_interpreter))

    assert default_qemu_image() is None
