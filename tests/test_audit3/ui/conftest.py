# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Shared fixtures for audit3 UI panel tests.

Provides a session-scoped QApplication required for Qt widget testing under
the offscreen Qt platform plugin, plus the ``real_config`` and
``real_orchestrator`` fixtures used by panel-construction tests.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qapp() -> Iterator[QApplication]:
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process. This fixture
    creates one for the entire test session and yields any pre-existing
    instance if present.

    Yields:
        QApplication: A live QApplication for widget construction.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return

    yield QApplication([])


@pytest.fixture
def real_config(tmp_path: Path) -> Config:
    """Create a real Config instance with tmp_path directories.

    Args:
        tmp_path: Pytest temporary directory fixture.

    Returns:
        Config: Config instance using temporary directories.
    """
    return Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )


@pytest.fixture
def real_orchestrator(tmp_path: Path) -> Orchestrator:
    """Create a real Orchestrator with empty registries.

    Args:
        tmp_path: Pytest temporary directory fixture.

    Returns:
        Orchestrator: Orchestrator instance.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "sessions.db"
    return Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=db_path)),
    )
