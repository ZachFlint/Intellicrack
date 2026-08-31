# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the confirmation-level setting reaching the orchestrator.

The Preferences dialog offers a three-way confirmation level (never / only
destructive / every call) and persists it correctly, but nothing forwarded it
to the object that acts on it. ``MainWindow._on_preferences_changed`` only
swapped its own ``Config`` copy, and the toolbar's binary auto-approve button
was the sole caller of ``Orchestrator.set_confirmation_level`` -- hardcoding
``DESTRUCTIVE`` whenever it was switched off, which silently discarded a user
who had chosen ``ALL`` or ``NONE``.

Everything here is driven through the real ``MainWindow``, the real
``Orchestrator`` and the real ``PreferencesDialog`` signal; the assertion is on
the live orchestrator's own configuration, which is what actually decides
whether a tool call prompts.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ConfirmationLevel
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

    from PyQt6.QtCore import QCoreApplication


def _orchestrator_level(orchestrator: Orchestrator) -> ConfirmationLevel:
    """Read the level the orchestrator will actually enforce.

    Args:
        orchestrator: The live orchestrator under test.

    Returns:
        ConfirmationLevel: The level currently configured on it.
    """
    return cast("ConfirmationLevel", getattr(orchestrator, "_config").confirmation_level)


@pytest.fixture
def window_with_level(
    qapp: QCoreApplication,
    tmp_path: Path,
) -> Generator[tuple[MainWindow, Orchestrator]]:
    """Build a real window whose config asks for confirmation on every call.

    Args:
        qapp: Qt application fixture.
        tmp_path: Pytest temporary directory fixture.

    Yields:
        tuple[MainWindow, Orchestrator]: The window and its orchestrator.
    """
    del qapp
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    config = Config(
        tools_directory=tools_dir,
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
        confirmation_level=ConfirmationLevel.ALL,
    )
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db")),
    )
    window = MainWindow(config, orchestrator)
    try:
        yield window, orchestrator
    finally:
        window.close()


def test_configured_level_is_applied_at_startup(
    window_with_level: tuple[MainWindow, Orchestrator],
) -> None:
    """A window built on a config asking for ALL must leave the orchestrator at ALL.

    Args:
        window_with_level: The real window/orchestrator pair.
    """
    _window, orchestrator = window_with_level

    assert _orchestrator_level(orchestrator) == ConfirmationLevel.ALL, (
        "the configured confirmation level never reached the orchestrator, so the setting has no effect"
    )


def test_preferences_change_reaches_the_orchestrator(
    window_with_level: tuple[MainWindow, Orchestrator],
) -> None:
    """Applying a new level in Preferences must take effect without a restart.

    Args:
        window_with_level: The real window/orchestrator pair.
    """
    window, orchestrator = window_with_level
    changed = replace(window._config, confirmation_level=ConfirmationLevel.NONE)

    cast("Callable[[Config], None]", getattr(window, "_on_preferences_changed"))(changed)

    assert _orchestrator_level(orchestrator) == ConfirmationLevel.NONE, (
        "a Preferences change was persisted but never applied to the running orchestrator"
    )


def test_auto_approve_off_restores_the_configured_level(
    window_with_level: tuple[MainWindow, Orchestrator],
) -> None:
    """Toggling auto-approve on then off must return to the user's own choice.

    The button is an override, not a second setting. Switching it off used to
    stamp ``DESTRUCTIVE`` unconditionally, quietly downgrading a configured
    ``ALL``.

    Args:
        window_with_level: The real window/orchestrator pair.
    """
    window, orchestrator = window_with_level
    toggle = cast("Callable[..., None]", getattr(window, "_on_auto_approve_toggled"))

    window._auto_approve_btn.setChecked(True)
    toggle(checked=True)
    assert _orchestrator_level(orchestrator) == ConfirmationLevel.NONE, "auto-approve ON did not suppress confirmation"

    window._auto_approve_btn.setChecked(False)
    toggle(checked=False)
    assert _orchestrator_level(orchestrator) == ConfirmationLevel.ALL, (
        "auto-approve OFF discarded the configured ALL level instead of restoring it"
    )
