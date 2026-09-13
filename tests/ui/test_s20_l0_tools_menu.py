# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S20-D19: Frida/Process/Sandbox-panel must be reachable from the Tools menu.

Before the fix, ``_frida_btn``/``process_btn``/``_sandbox_tool_btn`` existed
only on the toolbar -- with ``_frida_btn`` additionally disabled until a
binary loads -- while the Tools -> Embedded Tools menu exposed only
x64dbg/Cutter/Hex. Separately, the Sandbox menu's "Open Sandbox" action
created a VM (``_on_open_sandbox``) rather than opening the Sandbox panel
(``_on_open_sandbox_panel``), which had no menu entry at all (S20-D19).
This test drives the real ``MainWindow`` menu construction and asserts the
three missing entries now exist, are enabled with no binary loaded (matching
the existing x64dbg/Cutter/Hex entries), and that the Sandbox-panel entry is
wired to the panel opener rather than the VM-creating handler.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.app import MainWindow

from .conftest import CallRecorder, NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtGui import QAction
    from PyQt6.QtWidgets import QApplication, QMenu

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator

_EXPECTED_NEW_ENTRIES: tuple[str, ...] = (
    "Open Frida Instrumentation",
    "Open Process Manager",
    "Open Sandbox Panel",
)


def _embedded_tools_menu(window: MainWindow) -> QMenu:
    """Resolve the Tools -> Embedded Tools submenu from a real ``MainWindow``.

    Args:
        window: The ``MainWindow`` instance to inspect.

    Returns:
        QMenu: The Embedded Tools submenu.
    """
    menubar = window.menuBar()
    assert menubar is not None, "menu bar not found"
    tools_menu = next((action.menu() for action in menubar.actions() if action.text() == "&Tools"), None)
    assert tools_menu is not None, "Tools menu not found"
    embedded_menu = next((action.menu() for action in tools_menu.actions() if action.text() == "&Embedded Tools"), None)
    assert embedded_menu is not None, "Embedded Tools submenu not found"
    return embedded_menu


def _find_action(menu: QMenu, text: str) -> QAction:
    """Find a menu action by its exact visible text.

    Args:
        menu: The menu to search.
        text: The action's label text.

    Returns:
        QAction: The matching action.

    Raises:
        AssertionError: If no action with ``text`` exists in ``menu``.
    """
    for action in menu.actions():
        if action.text() == text:
            return action
    message = f"action {text!r} not found in menu"
    raise AssertionError(message)


@pytest.fixture
def shell_window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Construct a real ``MainWindow`` with no binary loaded.

    Args:
        qapp: Shared QApplication fixture required for Qt widget construction.
        real_config: Real Config fixture.
        real_orchestrator: Real Orchestrator fixture.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        MainWindow: A constructed ``MainWindow`` instance.
    """
    _ = qapp
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    window = MainWindow(real_config, real_orchestrator)
    yield window
    window.close()


def test_embedded_tools_menu_exposes_frida_process_sandbox_panel(shell_window: MainWindow) -> None:
    """Tools -> Embedded Tools must list Frida, Process, and Sandbox-panel entries.

    Args:
        shell_window: A real, constructed ``MainWindow``.
    """
    embedded_menu = _embedded_tools_menu(shell_window)
    action_texts = [a.text() for a in embedded_menu.actions() if not a.isSeparator()]

    for expected in _EXPECTED_NEW_ENTRIES:
        assert expected in action_texts, f"Tools -> Embedded Tools is missing '{expected}' (D19); has {action_texts}"


def test_frida_process_sandbox_panel_menu_actions_are_not_binary_gated(shell_window: MainWindow) -> None:
    """The three new menu entries must be enabled with no binary loaded.

    The toolbar's Frida button is disabled until a binary loads
    (``_binary_dependent_buttons``); the menu entries must not inherit that
    gating, matching the existing x64dbg/Cutter/Hex menu items.

    Args:
        shell_window: A real, constructed ``MainWindow``.
    """
    window = shell_window
    assert window.current_binary is None, "test premise: no binary loaded"
    embedded_menu = _embedded_tools_menu(window)

    for label in _EXPECTED_NEW_ENTRIES:
        action = _find_action(embedded_menu, label)
        assert action.isEnabled(), f"'{label}' must not be gated on a loaded binary (D19)"


def test_sandbox_panel_menu_action_opens_panel_not_vm(
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
    qapp: QApplication,
) -> None:
    """The Sandbox-panel menu entry must call the panel opener, never the VM-creating handler.

    ``MainWindow._on_open_sandbox_panel``/``_on_open_sandbox`` are replaced
    at the class level *before* ``MainWindow`` is constructed, since the
    menu action's Qt connection captures the bound method that existed at
    ``_setup_menus()`` time -- patching the instance afterward would not
    affect an already-established signal/slot connection.

    Args:
        real_config: Real Config fixture.
        real_orchestrator: Real Orchestrator fixture.
        monkeypatch: Pytest monkeypatch fixture.
        qapp: Shared QApplication fixture required for Qt widget construction.
    """
    _ = qapp
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    panel_opener = CallRecorder()
    vm_creator = CallRecorder()
    monkeypatch.setattr(MainWindow, "_on_open_sandbox_panel", lambda _self: panel_opener())
    monkeypatch.setattr(MainWindow, "_on_open_sandbox", lambda _self: vm_creator())

    window = MainWindow(real_config, real_orchestrator)
    try:
        embedded_menu = _embedded_tools_menu(window)
        action = _find_action(embedded_menu, "Open Sandbox Panel")

        action.trigger()

        assert panel_opener.times_called == 1, "Open Sandbox Panel menu action must call _on_open_sandbox_panel exactly once"
        assert vm_creator.times_called == 0, "Open Sandbox Panel menu action must NOT call the VM-creating _on_open_sandbox"
    finally:
        window.close()
