# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D06: the GUI must be able to configure and launch QEMU.

Before this fix the sandbox configuration dialog had no QEMU controls at all,
so there was no way to tell the application which qcow2 disk image to boot, and
the sandbox panel never built a ``QEMUConfig`` to pass to the bridge. The QEMU
backend was therefore unreachable from the GUI on every host.

These tests drive the real dialog and the real panel helper against a real
settings file on disk: the dialog writes the settings document, and the panel
reads that same document back into the configuration it hands to the bridge.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from intellicrack.sandbox.qemu import GuestOS, QEMUConfig
from intellicrack.sandbox.settings import (
    QEMU_CPU_CORES_KEY,
    QEMU_GUEST_OS_KEY,
    QEMU_IMAGE_PATH_KEY,
    QEMU_MEMORY_MB_KEY,
)
from intellicrack.ui.panels.sandbox_panel import SandboxPanel
from intellicrack.ui.sandbox_config import SandboxConfigDialog


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import pytest
    from PyQt6.QtWidgets import QApplication, QLineEdit


_CONFIGURED_CPU_CORES = 4
_CONFIGURED_MEMORY_MB = 6144


def _fixed_config_file(target: Path) -> Callable[[str], Path]:
    """Build a ``get_config_file`` replacement resolving to a fixed path.

    Args:
        target: Path every lookup should resolve to.

    Returns:
        Callable[[str], Path]: Resolver returning ``target`` for any filename.
    """

    def _resolve(filename: str) -> Path:
        """Resolve any configuration filename to the fixed target.

        Args:
            filename: Requested configuration filename, ignored.

        Returns:
            Path: The fixed target path.
        """
        del filename
        return target

    return _resolve


def _make_disk_image(tmp_path: Path) -> Path:
    """Create a real qcow2 file for the dialog to point at.

    Args:
        tmp_path: Per-test temporary directory.

    Returns:
        Path: Path to the created qcow2 image file.
    """
    header = b"QFI\xfb" + (3).to_bytes(4, "big") + bytes(64)
    image = tmp_path / "guest.qcow2"
    image.write_bytes(header)
    return image


def _image_input(dialog: SandboxConfigDialog) -> QLineEdit:
    """Return the dialog's QEMU disk-image entry widget.

    Args:
        dialog: Sandbox configuration dialog under test.

    Returns:
        QLineEdit: The QEMU disk-image line edit.
    """
    widget = getattr(dialog, "_qemu_image_input", None)
    assert widget is not None, "dialog has no QEMU disk-image control"
    return cast("QLineEdit", widget)


def _save(dialog: SandboxConfigDialog) -> None:
    """Persist the dialog's current widget state to disk.

    Args:
        dialog: Sandbox configuration dialog under test.
    """
    save = getattr(dialog, "_save_settings", None)
    assert save is not None, "dialog exposes no settings-save routine"
    cast("Callable[[], None]", save)()


def _panel_qemu_config(sandbox_type: str) -> QEMUConfig | None:
    """Build the QEMU creation config the panel would send to the bridge.

    Args:
        sandbox_type: Sandbox type selected in the panel toolbar.

    Returns:
        QEMUConfig | None: The configuration the panel builds for that type.
    """
    builder = getattr(SandboxPanel, "_qemu_create_config", None)
    assert builder is not None, "panel exposes no QEMU creation config builder"
    return cast("Callable[[str], QEMUConfig | None]", builder)(sandbox_type)


def _relocate_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point both the dialog and the settings loader at a temporary file.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Fixture used to relocate the settings file.

    Returns:
        Path: The relocated settings file path.
    """
    settings_file = tmp_path / "sandbox.json"
    monkeypatch.setattr(SandboxConfigDialog, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(SandboxConfigDialog, "CONFIG_FILE", settings_file)
    monkeypatch.setattr(
        "intellicrack.sandbox.settings.get_config_file",
        _fixed_config_file(settings_file),
    )
    return settings_file


class TestDialogPersistsQemuSettings:
    """The configuration dialog must expose and persist the QEMU settings."""

    def test_image_chosen_in_the_dialog_is_written_to_disk(
        self,
        qapp: QApplication,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A disk image entered in the dialog lands in the settings document.

        Args:
            qapp: Live QApplication required for widget construction.
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to relocate the settings file.
        """
        del qapp
        image = _make_disk_image(tmp_path)
        settings_file = _relocate_config(tmp_path, monkeypatch)

        dialog = SandboxConfigDialog()
        try:
            _image_input(dialog).setText(str(image))
            _save(dialog)
        finally:
            dialog.deleteLater()

        assert settings_file.exists(), "dialog wrote no settings document"
        written: dict[str, Any] = json.loads(settings_file.read_text(encoding="utf-8"))
        assert written[QEMU_IMAGE_PATH_KEY] == str(image)

    def test_saved_settings_are_restored_on_the_next_open(
        self,
        qapp: QApplication,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """QEMU settings saved by the dialog are restored when it reopens.

        Args:
            qapp: Live QApplication required for widget construction.
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to relocate the settings file.
        """
        del qapp
        image = _make_disk_image(tmp_path)
        settings_file = _relocate_config(tmp_path, monkeypatch)
        settings_file.write_text(
            json.dumps({
                QEMU_IMAGE_PATH_KEY: str(image),
                QEMU_GUEST_OS_KEY: GuestOS.LINUX.value,
                QEMU_CPU_CORES_KEY: _CONFIGURED_CPU_CORES,
                QEMU_MEMORY_MB_KEY: _CONFIGURED_MEMORY_MB,
            }),
            encoding="utf-8",
        )

        dialog = SandboxConfigDialog()
        try:
            restored: dict[str, Any] = dialog.get_settings()
        finally:
            dialog.deleteLater()

        assert restored[QEMU_IMAGE_PATH_KEY] == str(image), "saved disk image was not restored into the dialog"
        assert restored[QEMU_GUEST_OS_KEY] == GuestOS.LINUX.value
        assert restored[QEMU_CPU_CORES_KEY] == _CONFIGURED_CPU_CORES
        assert restored[QEMU_MEMORY_MB_KEY] == _CONFIGURED_MEMORY_MB

    def test_dialog_round_trip_survives_a_reopen(
        self,
        qapp: QApplication,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An image saved by one dialog instance reappears in the next one.

        Args:
            qapp: Live QApplication required for widget construction.
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to relocate the settings file.
        """
        del qapp
        image = _make_disk_image(tmp_path)
        _relocate_config(tmp_path, monkeypatch)

        first = SandboxConfigDialog()
        try:
            _image_input(first).setText(str(image))
            _save(first)
        finally:
            first.deleteLater()

        second = SandboxConfigDialog()
        try:
            reopened = _image_input(second).text()
        finally:
            second.deleteLater()

        assert reopened == str(image)


class TestPanelBuildsQemuConfig:
    """The panel must turn persisted settings into a config for the bridge."""

    def test_qemu_create_config_loads_the_configured_image(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Creating a QEMU sandbox carries the configured image to the bridge.

        Args:
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to relocate the settings file.
        """
        image = _make_disk_image(tmp_path)
        settings_file = _relocate_config(tmp_path, monkeypatch)
        settings_file.write_text(
            json.dumps({
                QEMU_IMAGE_PATH_KEY: str(image),
                QEMU_GUEST_OS_KEY: GuestOS.LINUX.value,
            }),
            encoding="utf-8",
        )

        qemu_config = _panel_qemu_config("qemu")

        assert qemu_config is not None, "panel built no QEMU config for a QEMU sandbox"
        assert qemu_config.image_path == image
        assert qemu_config.guest_os is GuestOS.LINUX

    def test_windows_sandbox_gets_no_qemu_config(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A Windows sandbox must not be handed QEMU settings.

        Args:
            tmp_path: Per-test temporary directory.
            monkeypatch: Fixture used to relocate the settings file.
        """
        image = _make_disk_image(tmp_path)
        settings_file = _relocate_config(tmp_path, monkeypatch)
        settings_file.write_text(json.dumps({QEMU_IMAGE_PATH_KEY: str(image)}), encoding="utf-8")

        assert _panel_qemu_config("windows") is None
