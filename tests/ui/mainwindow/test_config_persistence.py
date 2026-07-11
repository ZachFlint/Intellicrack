# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for Preferences persistence targeting the load path.

``main.py`` loads configuration from ``get_config_dir() / "config.toml"`` at
startup. The Preferences dialog therefore has to be pointed at that exact file;
if it saves anywhere else, the user's saved preferences land in a file nothing
ever reads. ``MainWindow._on_preferences`` historically pointed the dialog at
``config.json`` (a file the loader ignores), so these gates fail if that path
regresses to any filename other than ``config.toml``.

Each test drives the real :class:`MainWindow` slot with only the blocking modal
``exec`` isolated, and redirects the config directory under ``tmp_path`` so the
real project configuration is never written.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.core.config import Config, get_config_file
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui import preferences as preferences_module
from intellicrack.ui.app import MainWindow


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

    from PyQt6.QtCore import QCoreApplication


def _no_exec(_self: object) -> int:
    """Stand in for a modal ``exec`` so the dialog never blocks.

    Args:
        _self: The dialog instance (ignored).

    Returns:
        int: ``0`` (``QDialog.DialogCode.Rejected``).
    """
    return 0


@pytest.fixture
def window(qapp: QCoreApplication, tmp_path: Path) -> Generator[MainWindow]:
    """Construct a real :class:`MainWindow` on temporary registries.

    Args:
        qapp: Qt application fixture.
        tmp_path: Pytest temporary directory.

    Yields:
        MainWindow: The window under test, closed on teardown.
    """
    del qapp
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    config = Config(
        tools_directory=tools_dir,
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    orch = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db")),
    )
    win = MainWindow(config, orch)
    try:
        yield win
    finally:
        win.close()


class TestPreferencesConfigPathMatchesLoadPath:
    """Preferences must save to the exact file the app loads at startup."""

    @staticmethod
    def test_preferences_dialog_targets_config_toml(
        window: MainWindow,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_on_preferences`` points the dialog at ``config.toml``.

        The config directory is redirected under ``tmp_path`` so the real
        project config is never touched, then ``_on_preferences`` is driven with
        only the blocking modal ``exec`` isolated. The path handed to the dialog
        must equal the load path ``get_config_file("config.toml")``; the
        ``config.json`` bug makes these differ and fails the assertion.

        Args:
            window: Real MainWindow fixture.
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch fixture.
        """
        cfg_dir = tmp_path / "cfgdir" / ".intellicrack"
        monkeypatch.setattr("intellicrack.core.config.get_config_dir", lambda: cfg_dir)
        monkeypatch.setattr(preferences_module.PreferencesDialog, "exec", _no_exec)

        cast("Callable[[], None]", getattr(window, "_on_preferences"))()

        dialogs = window.findChildren(preferences_module.PreferencesDialog)
        assert dialogs, "PreferencesDialog was not constructed as a child of the window"
        config_path = cast("Path", getattr(dialogs[0], "_config_path"))
        assert config_path == get_config_file("config.toml")
        assert config_path.name == "config.toml"

    @staticmethod
    def test_preferences_apply_round_trips_through_load_path(
        window: MainWindow,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Applying preferences writes a file that ``Config.load`` reads back.

        Drives the real Apply path so the dialog serializes to the redirected
        ``config.toml``, then loads that exact file the way ``main.py`` does and
        asserts the persisted UI theme survives the round-trip. If Apply wrote to
        a different filename than the load path, the load would miss the written
        data and the theme would not match.

        Args:
            window: Real MainWindow fixture.
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch fixture.
        """
        cfg_dir = tmp_path / "cfgdir" / ".intellicrack"
        monkeypatch.setattr("intellicrack.core.config.get_config_dir", lambda: cfg_dir)
        monkeypatch.setattr(preferences_module.PreferencesDialog, "exec", _no_exec)

        cast("Callable[[], None]", getattr(window, "_on_preferences"))()
        dialog = window.findChildren(preferences_module.PreferencesDialog)[0]

        cast("Callable[[], None]", getattr(dialog, "_on_apply"))()

        load_path = get_config_file("config.toml")
        assert load_path.exists(), "Apply did not write to the file main.py loads"
        reloaded = Config.load(load_path)
        assert reloaded.ui.theme == cast("Config", getattr(dialog, "get_config")()).ui.theme
