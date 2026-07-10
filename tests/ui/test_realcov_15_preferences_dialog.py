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

from intellicrack.core.config import Config
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


def test_accept_emits_settings_changed_with_edited_config(
    qtbot: QtBot,
    tmp_path: Path,
) -> None:
    """Editing the tools directory and accepting emits an updated Config.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    config = _make_config(tmp_path)
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
    assert dialog.get_config().tools_directory == new_tools_dir


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
