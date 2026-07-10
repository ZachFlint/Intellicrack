# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""pytest-qt tests for the F-0008 ``TagChipsWidget`` UI.

Verifies that adding a tag through the inline editor mutates the wired
session's tags list, that clicking a chip removes the tag, and that the
``orchestrator.tag_current_session`` CLI parity API delegates correctly.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ProviderName
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.session_manager import TagChipsWidget


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


def _build_session() -> Session:
    """Build a throw-away in-memory session.

    Returns:
        Session: A fresh ``Session`` instance.
    """
    return Session.create(provider=ProviderName.OPENAI, model="gpt-4")


def test_widget_adds_tag_via_input(qapp: QApplication) -> None:
    """Typing a tag and pressing Add must add it to the session.

    Args:
        qapp: QApplication fixture from ``tests/test_ui/conftest.py``.
    """
    del qapp
    session = _build_session()
    widget = TagChipsWidget(session=session)

    widget._tag_input.setText("triage")
    widget._on_add_clicked()

    assert "triage" in session.tags
    assert widget._chip_buttons.get("triage") is not None


def test_widget_renders_initial_tags(qapp: QApplication) -> None:
    """Constructing with a tagged session must render those chips.

    Args:
        qapp: QApplication fixture from ``tests/test_ui/conftest.py``.
    """
    del qapp
    session = _build_session()
    session.add_tag("alpha")
    session.add_tag("beta")
    widget = TagChipsWidget(session=session)

    assert set(widget._chip_buttons.keys()) == {"alpha", "beta"}


def test_widget_removes_tag_when_chip_clicked(qapp: QApplication) -> None:
    """Clicking a chip must remove the tag from the session.

    Args:
        qapp: QApplication fixture from ``tests/test_ui/conftest.py``.
    """
    del qapp
    session = _build_session()
    session.add_tag("delta")
    widget = TagChipsWidget(session=session)

    chip = widget._chip_buttons["delta"]
    chip.click()

    assert "delta" not in session.tags
    assert "delta" not in widget._chip_buttons


def test_widget_rejects_empty_tag(qapp: QApplication) -> None:
    """An empty tag string must not be added to the session.

    Args:
        qapp: QApplication fixture from ``tests/test_ui/conftest.py``.
    """
    del qapp
    session = _build_session()
    widget = TagChipsWidget(session=session)

    widget._tag_input.setText("   ")
    widget._on_add_clicked()

    assert session.tags == []


def test_widget_disabled_without_session(qapp: QApplication) -> None:
    """Without a wired session the add controls must be disabled.

    Args:
        qapp: QApplication fixture from ``tests/test_ui/conftest.py``.
    """
    del qapp
    widget = TagChipsWidget()
    assert widget._add_btn.isEnabled() is False
    assert widget._tag_input.isEnabled() is False


def test_widget_set_session_rehydrates_chips(qapp: QApplication) -> None:
    """``set_session`` must rebuild chips for the new session's tags.

    Args:
        qapp: QApplication fixture from ``tests/test_ui/conftest.py``.
    """
    del qapp
    first = _build_session()
    first.add_tag("first")
    second = _build_session()
    second.add_tag("second")

    widget = TagChipsWidget(session=first)
    assert "first" in widget._chip_buttons

    widget.set_session(second)
    assert "first" not in widget._chip_buttons
    assert "second" in widget._chip_buttons


def test_widget_emits_signals_on_change(qapp: QApplication) -> None:
    """Adding and removing tags must emit ``tag_added``/``tag_removed``.

    Args:
        qapp: QApplication fixture from ``tests/test_ui/conftest.py``.
    """
    del qapp
    session = _build_session()
    widget = TagChipsWidget(session=session)
    added: list[str] = []
    removed: list[str] = []

    widget.tag_added.connect(added.append)
    widget.tag_removed.connect(removed.append)

    widget._tag_input.setText("signal-add")
    widget._on_add_clicked()
    widget._chip_buttons["signal-add"].click()

    assert added == ["signal-add"]
    assert removed == ["signal-add"]


def test_orchestrator_tag_current_session_api(tmp_path: Path) -> None:
    """The orchestrator CLI parity API must mutate the live session.

    Args:
        tmp_path: Pytest-managed temporary directory for the session
            store.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    store = SessionStore(db_path=tmp_path / "sessions.db")
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=store),
    )

    session = asyncio.run(orchestrator._sessions.create(provider=ProviderName.OPENAI, model="gpt-4"))
    orchestrator._current_session = session

    assert orchestrator.tag_current_session("important") is True
    assert "important" in session.tags
    assert orchestrator.tag_current_session("important") is False  # already present

    assert orchestrator.untag_current_session("important") is True
    assert "important" not in session.tags


def test_orchestrator_tag_current_session_requires_session(tmp_path: Path) -> None:
    """The CLI API must raise ``RuntimeError`` when no session is active.

    Args:
        tmp_path: Pytest-managed temporary directory for the session
            store.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    store = SessionStore(db_path=tmp_path / "sessions.db")
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=store),
    )

    with pytest.raises(RuntimeError):
        orchestrator.tag_current_session("never")
    with pytest.raises(RuntimeError):
        orchestrator.untag_current_session("never")
