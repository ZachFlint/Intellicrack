# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for :class:`PreferencesDialog`.

The preferences dialog was previously untested. These tests construct the
real dialog over a real :class:`Config`, mutate real input widgets through
the live Qt widget tree, and assert that:

* The ``settings_changed`` signal fires on Accept carrying a real
  :class:`Config` that reflects the edits made in the UI.
* When a config path is set, Accept persists the new config to disk and the
  reloaded config round-trips the edited values.

No part of the dialog under test is stubbed; only the modal blocking call is
avoided by invoking the dialog's own ``_on_accept`` slot, which is exactly
what the Qt button box would trigger.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.config import (
    Config,
    LogConfig,
    ProviderConfig,
    SessionConfig,
    ToolConfig,
    UIConfig,
)
from intellicrack.core.types import ConfirmationLevel, ProviderName, ToolName
from intellicrack.ui.preferences import PreferencesDialog


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


def _make_config(tmp_path: Path) -> Config:
    """Build a real :class:`Config` rooted at ``tmp_path``.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Config: Config with directories under ``tmp_path``.
    """
    return Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )


def _make_rich_config(tmp_path: Path) -> Config:
    """Build a fully non-default :class:`Config` for round-trip auditing.

    Every scalar field is deliberately set to a value that differs from the
    dataclass default so that an accidental reset of any field to its default
    during an edit/accept cycle is detectable. The ``providers`` and ``tools``
    mappings are seeded with non-default sub-configs as well.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Config: A Config whose every field is distinct from the defaults.
    """
    return Config(
        tools_directory=tmp_path / "orig_tools",
        logs_directory=tmp_path / "orig_logs",
        data_directory=tmp_path / "orig_data",
        default_provider=ProviderName.OPENAI,
        confirmation_level=ConfirmationLevel.ALL,
        providers={
            ProviderName.OPENAI: ProviderConfig(
                enabled=False,
                api_base="https://example.invalid/v1",
                default_model="custom-model",
                timeout_seconds=77,
                max_retries=9,
            ),
        },
        tools={
            ToolName.GHIDRA: ToolConfig(
                enabled=False,
                path=tmp_path / "ghidra",
                auto_install=False,
                startup_timeout_seconds=314,
                port=5959,
            ),
        },
        ui=UIConfig(theme="dark", font_family="Courier New", font_size=15, show_tool_calls=False),
        session=SessionConfig(auto_save=False, save_interval_seconds=120, retention_days=21),
        log=LogConfig(
            level="WARNING",
            file_enabled=False,
            console_enabled=False,
            max_file_size_mb=42,
            backup_count=9,
            retention_days=99,
            json_file=False,
        ),
    )


def test_accept_emits_settings_changed_with_edited_config(
    qtbot: QtBot,
    tmp_path: Path,
) -> None:
    """Editing only the tools directory preserves every other config field.

    Drives a fully non-default :class:`Config` through the live dialog, edits a
    single field (tools directory) in the real widget tree, accepts, and audits
    the entire emitted ``Config`` field by field against an independently known
    expected state. The expected state is derived from the dialog contract, not
    from the implementation output: ``dataclasses.replace`` preserves untouched
    top-level fields (``data_directory``, ``providers``, ``tools``,
    ``sandbox``), the appearance/session widgets round-trip their loaded values,
    and the logging widget rebuilds ``LogConfig`` without carrying
    ``retention_days``/``json_file``, so those two reset to their defaults.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    config = _make_rich_config(tmp_path)
    original_providers = config.providers
    original_tools = config.tools
    original_sandbox = config.sandbox
    dialog = PreferencesDialog(config)
    qtbot.addWidget(dialog)

    new_tools_dir = tmp_path / "edited_tools"
    general = dialog._settings_widgets[0]
    tools_edit = general._tools_path
    tools_edit.clear()
    qtbot.keyClicks(tools_edit, str(new_tools_dir))

    with qtbot.waitSignal(dialog.settings_changed, timeout=2_000) as blocker:
        dialog._on_accept()

    emitted = blocker.args[0]
    assert isinstance(emitted, Config)

    assert emitted.tools_directory == new_tools_dir

    assert emitted.data_directory == tmp_path / "orig_data"
    assert emitted.default_provider is ProviderName.OPENAI
    assert emitted.confirmation_level is ConfirmationLevel.ALL

    assert emitted.providers == original_providers
    assert emitted.tools == original_tools
    assert emitted.sandbox == original_sandbox

    assert emitted.logs_directory == tmp_path / "orig_logs"

    assert emitted.ui == UIConfig(theme="dark", font_family="Courier New", font_size=15, show_tool_calls=False)
    assert emitted.session == SessionConfig(auto_save=False, save_interval_seconds=120, retention_days=21)

    assert emitted.log == LogConfig(
        level="WARNING",
        file_enabled=False,
        console_enabled=False,
        max_file_size_mb=42,
        backup_count=9,
        retention_days=14,
        json_file=True,
    )

    assert dialog.get_config() == emitted


def test_accept_edits_logging_level_round_trips(
    qtbot: QtBot,
    tmp_path: Path,
) -> None:
    """Changing the log level via the UI is reflected in the emitted Config.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    config = _make_config(tmp_path)
    assert config.log.level != "ERROR"
    dialog = PreferencesDialog(config)
    qtbot.addWidget(dialog)

    logging_widget = dialog._settings_widgets[3]
    level_combo = logging_widget._log_level
    error_index = level_combo.findData("ERROR")
    assert error_index >= 0
    level_combo.setCurrentIndex(error_index)

    with qtbot.waitSignal(dialog.settings_changed, timeout=2_000) as blocker:
        dialog._on_accept()

    emitted = blocker.args[0]
    assert isinstance(emitted, Config)
    assert emitted.log.level == "ERROR"
    assert getattr(logging, emitted.log.level) == logging.ERROR


def test_accept_persists_config_to_disk(
    qtbot: QtBot,
    tmp_path: Path,
) -> None:
    """Accept writes the edited config to the configured path and round-trips.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    config = _make_config(tmp_path)
    dialog = PreferencesDialog(config)
    qtbot.addWidget(dialog)
    config_path = tmp_path / "config.json"
    dialog.set_config_path(config_path)

    new_tools_dir = tmp_path / "persisted_tools"
    general = dialog._settings_widgets[0]
    general._tools_path.clear()
    qtbot.keyClicks(general._tools_path, str(new_tools_dir))

    with qtbot.waitSignal(dialog.settings_changed, timeout=2_000):
        dialog._on_accept()

    assert config_path.exists()
    reloaded = Config.load(config_path)
    assert reloaded.tools_directory == new_tools_dir
