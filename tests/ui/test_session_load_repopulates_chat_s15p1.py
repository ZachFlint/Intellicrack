# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the S15 P1 audit defect in ``MainWindow``'s session load.

Pre-fix, ``MainWindow._on_session_load_requested`` cleared the chat panel and
the tool panel *before* dispatching the load, and attached no success handler
to the coroutine -- so the loaded session's messages were never rendered. The
defect was self-inflicted twice over: ``SessionManagerDialog`` already restores
the history through ``_restore_session_to_ui`` and only then emits
``session_loaded``, which is wired to this very slot, so the window wiped the
bubbles the dialog had just drawn. A failed load blanked the panel too.

Unlike the sibling gate ``test_session_load_restores_state_s16d12``, which
drives the dialog against a ``_FakeMainWindow``, this one drives the **real**
``MainWindow`` slot both entry points reach, which is the only place the defect
lives. Everything here is real: a real SQLite-backed ``SessionStore``, a real
``SessionManager``, a real ``Orchestrator``, a real ``MainWindow`` and its real
``ChatPanel`` widgets. The assertions read the bubbles actually laid out in the
panel, in layout order, so a bookkeeping list that disagrees with the rendered
widgets cannot pass.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

import pytest
from PyQt6.QtCore import QEvent
from PyQt6.QtWidgets import QApplication, QMessageBox

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import BinaryInfo, Message, ProviderName
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow
from intellicrack.ui.chat import MessageBubble
from intellicrack.ui.panels.async_bridge import drain_bridge_workers_for, run_bridge_coroutine


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from PyQt6.QtCore import QCoreApplication


pytestmark = pytest.mark.usefixtures("qapp")

_MessageRole = Literal["user", "assistant", "system", "tool"]

_SAVED_TURNS: tuple[tuple[_MessageRole, str], ...] = (
    ("user", "What does this binary do?"),
    ("assistant", "It reaches a license check at 0x140001704."),
    ("user", "Patch the branch."),
)


@pytest.fixture
def loaded_window(qapp: QCoreApplication, tmp_path: Path) -> Generator[MainWindow]:
    """Construct a real ``MainWindow`` over temporary registries and a temp session store.

    Args:
        qapp: Qt application fixture.
        tmp_path: Pytest temporary directory fixture.

    Yields:
        MainWindow: The window under test.
    """
    del qapp
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    config = Config(
        tools_directory=tools_dir,
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db")),
    )
    window = MainWindow(config, orchestrator)
    try:
        yield window
    finally:
        drain_bridge_workers_for(window)
        window.close()


def _build_saved_session(window: MainWindow, tmp_path: Path) -> Session:
    """Persist a session carrying the known chat history and an active binary.

    Args:
        window: The window whose orchestrator owns the session manager.
        tmp_path: Pytest temporary directory fixture, used for the binary path.

    Returns:
        Session: The persisted session.
    """
    manager = window._orchestrator._sessions
    session = run_bridge_coroutine(manager.create(ProviderName.OLLAMA, "test-model", "S15P1 Session"))
    assert isinstance(session, Session)

    for role, content in _SAVED_TURNS:
        session.add_message(Message(role=role, content=content))

    binary_path = tmp_path / "target.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 60)
    session.add_binary(
        BinaryInfo(
            path=binary_path,
            name="target.exe",
            size=binary_path.stat().st_size,
            sha256="b" * 64,
            file_type="PE",
            architecture="x86_64",
            is_64bit=True,
            entry_point=0x1000,
            sections=[],
            imports=[],
            exports=[],
        ),
    )

    run_bridge_coroutine(manager.save())
    return session


def _settle(window: MainWindow) -> None:
    """Join the load worker and deliver its queued result on the GUI thread.

    Args:
        window: The window whose bridge workers should be drained.
    """
    drain_bridge_workers_for(window)
    app = QApplication.instance()
    if app is not None:
        app.processEvents()
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def _rendered_turns(window: MainWindow) -> list[tuple[str, str]]:
    """Read the chat bubbles actually laid out in the panel, in layout order.

    Args:
        window: The window whose chat panel should be read.

    Returns:
        list[tuple[str, str]]: ``(role, content)`` per rendered bubble.
    """
    layout = window._chat_panel._messages_layout
    turns: list[tuple[str, str]] = []
    for index in range(layout.count()):
        item = layout.itemAt(index)
        widget = item.widget() if item is not None else None
        if isinstance(widget, MessageBubble):
            turns.append((widget._message.role, widget._message.content))
    return turns


def test_load_session_repopulates_the_chat_panel_and_binary(
    loaded_window: MainWindow,
    tmp_path: Path,
) -> None:
    """Loading a saved session renders its history and re-adopts its binary.

    Args:
        loaded_window: Real MainWindow fixture.
        tmp_path: Pytest temporary directory fixture.
    """
    saved = _build_saved_session(loaded_window, tmp_path)

    loaded_window._chat_panel.clear_messages()
    run_bridge_coroutine(loaded_window._orchestrator._sessions.close())
    assert _rendered_turns(loaded_window) == [], "precondition: the chat panel must start empty"

    loaded_window._on_session_load_requested(saved.id)
    _settle(loaded_window)

    assert loaded_window._orchestrator.current_session is not None, "the orchestrator never adopted the session"
    assert _rendered_turns(loaded_window) == list(_SAVED_TURNS), (
        f"the loaded session's messages were not rendered; panel holds {_rendered_turns(loaded_window)}"
    )
    assert [(m.role, m.content) for m in loaded_window._chat_panel.get_messages()] == list(_SAVED_TURNS)
    assert loaded_window.current_binary == saved.binaries[0].path, (
        f"binary context was not re-adopted; current_binary={loaded_window.current_binary}"
    )


def test_failed_session_load_leaves_the_chat_panel_intact(
    loaded_window: MainWindow,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A load that fails must not blank a conversation that is already on screen.

    Args:
        loaded_window: Real MainWindow fixture.
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    saved = _build_saved_session(loaded_window, tmp_path)
    loaded_window._on_session_load_requested(saved.id)
    _settle(loaded_window)
    assert _rendered_turns(loaded_window) == list(_SAVED_TURNS), "precondition: the good load must render first"

    warnings: list[str] = []

    def _record_warning(*args: object, **kwargs: object) -> QMessageBox.StandardButton:
        """Record a warning dialog instead of blocking on it.

        Args:
            *args: Positional arguments passed by the production call site.
            **kwargs: Keyword arguments passed by the production call site.

        Returns:
            QMessageBox.StandardButton: The button a user would have pressed.
        """
        del kwargs
        warnings.append(" | ".join(str(arg) for arg in args))
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "warning", _record_warning)

    loaded_window._on_session_load_requested("no-such-session-id")
    _settle(loaded_window)

    assert warnings, "a failed session load reported nothing to the user"
    assert _rendered_turns(loaded_window) == list(_SAVED_TURNS), "a failed session load blanked the conversation that was already on screen"
