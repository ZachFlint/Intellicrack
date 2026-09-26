# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S20-D13 (VM Display pop-out) and the S20-D11 header state-reporting fix.

S20-D13: the VM Display tab scaled a live guest framebuffer into a small
docked sliver with no way to enlarge it - no fullscreen, pop-out, or detach
control existed anywhere in ``vnc_widget.py`` or ``sandbox_panel.py``.
:class:`VNCWidget` now carries its own "Pop Out" control that reparents the
*same* live widget instance into a resizable, maximized top-level window and
back again, and :class:`SandboxPanel` wires it to the real ``QTabWidget`` the
"VM Display" tab lives in.

These gates drive real ``QTabWidget``/``QWidget`` reparenting - the widget
really is removed from and reinserted into the tab widget's page list, and
its real top-level ``window()`` really changes - not a stand-in for Qt's
widget tree.

S20-D11 (header half): the header showed "Inactive" the entire time a real
Windows Sandbox session process was alive during a slow create, because the
indicator was only ever updated on the two extremes (never created / fully
created). ``SandboxPanel._on_create`` now sets an intermediate "Starting..."
state as soon as the create request is dispatched.
"""

from __future__ import annotations

import inspect
import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QPushButton, QTabWidget, QWidget

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.ui.panels import sandbox_panel as sandbox_panel_module
from intellicrack.ui.panels.sandbox_panel import SandboxPanel
from intellicrack.ui.panels.vnc_widget import VNCWidget


if TYPE_CHECKING:
    from collections.abc import Iterator

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_BEFORE_TAB_LABEL = "Before"
_AFTER_TAB_LABEL = "After"
_VM_DISPLAY_LABEL = "VM Display"
_ORIGINAL_TAB_INDEX = 1


@pytest.fixture(scope="session")
def qapp() -> Iterator[QApplication]:
    """Provide a session-scoped QApplication.

    Qt requires exactly one QApplication per process.

    Yields:
        QApplication: A live QApplication for widget construction.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


def _host_tab_widget(vnc: VNCWidget) -> QTabWidget:
    """Build a tab widget with the VNC widget docked at a non-zero index.

    Args:
        vnc: The widget to dock, so a redock at the wrong index is caught.

    Returns:
        QTabWidget: A real tab widget with ``vnc`` at index
        :data:`_ORIGINAL_TAB_INDEX`, flanked by two other real tabs.
    """
    tabs = QTabWidget()
    tabs.addTab(QWidget(), _BEFORE_TAB_LABEL)
    tabs.addTab(vnc, _VM_DISPLAY_LABEL)
    tabs.addTab(QWidget(), _AFTER_TAB_LABEL)
    vnc.configure_dock_host(tabs, _VM_DISPLAY_LABEL)
    return tabs


class TestVncWidgetPopoutAndRedock:
    """The VM Display widget must genuinely leave and rejoin its host tab widget."""

    @staticmethod
    def test_popout_removes_the_widget_from_its_host_tab_widget(qapp: QApplication) -> None:
        """Popping out must really remove the page from the tab widget, not just visually.

        Args:
            qapp: Session QApplication fixture.
        """
        assert isinstance(qapp, QApplication)
        vnc = VNCWidget()
        tabs = _host_tab_widget(vnc)
        assert tabs.indexOf(vnc) == _ORIGINAL_TAB_INDEX

        vnc.popout()

        assert tabs.indexOf(vnc) == -1, "the widget must be a real top-level window's child, not still a tab page"
        assert tabs.count() == 2, "the tab widget must genuinely have one fewer page while popped out"

    @staticmethod
    def test_popout_gives_the_widget_a_new_top_level_window(qapp: QApplication) -> None:
        """The widget's real top-level ancestor must change once popped out.

        Args:
            qapp: Session QApplication fixture.
        """
        assert isinstance(qapp, QApplication)
        vnc = VNCWidget()
        tabs = _host_tab_widget(vnc)
        original_window = vnc.window()
        assert original_window is tabs

        vnc.popout()

        assert vnc.window() is not original_window, "popped-out content must live under its own top-level window"
        assert vnc.window() is not tabs

    @staticmethod
    def test_redock_restores_the_widget_at_its_original_tab_index(qapp: QApplication) -> None:
        """Closing the popout must put the widget back exactly where it came from.

        Args:
            qapp: Session QApplication fixture.
        """
        assert isinstance(qapp, QApplication)
        vnc = VNCWidget()
        tabs = _host_tab_widget(vnc)

        vnc.popout()
        vnc.redock()

        assert tabs.indexOf(vnc) == _ORIGINAL_TAB_INDEX, "re-docking must restore the exact original tab position"
        assert tabs.tabText(_ORIGINAL_TAB_INDEX) == _VM_DISPLAY_LABEL
        assert vnc.window() is tabs, "after redocking, the widget's top-level window must be the host again"

    @staticmethod
    def test_popout_is_idempotent_and_redock_is_a_no_op_when_already_docked(qapp: QApplication) -> None:
        """A second pop-out or a redundant redock must never raise or duplicate state.

        Args:
            qapp: Session QApplication fixture.
        """
        assert isinstance(qapp, QApplication)
        vnc = VNCWidget()
        tabs = _host_tab_widget(vnc)

        vnc.redock()  # already docked: must be a harmless no-op
        assert tabs.indexOf(vnc) == _ORIGINAL_TAB_INDEX

        vnc.popout()
        vnc.popout()  # already popped out: must not create a second window or raise
        assert tabs.indexOf(vnc) == -1

        vnc.redock()
        vnc.redock()  # already docked again: must be a harmless no-op
        assert tabs.indexOf(vnc) == _ORIGINAL_TAB_INDEX

    @staticmethod
    def test_clicking_the_widgets_own_popout_button_drives_the_real_popout(qapp: QApplication) -> None:
        """The widget's self-contained button must be wired to the real pop-out/redock toggle.

        Args:
            qapp: Session QApplication fixture.
        """
        assert isinstance(qapp, QApplication)
        vnc = VNCWidget()
        tabs = _host_tab_widget(vnc)
        button = vnc.findChild(QPushButton, "vnc_popout_button")
        assert isinstance(button, QPushButton), "the widget must expose its pop-out control under a stable object name"

        button.click()
        assert tabs.indexOf(vnc) == -1, "clicking the button must pop the widget out for real"

        button.click()
        assert tabs.indexOf(vnc) == _ORIGINAL_TAB_INDEX, "clicking it again while popped out must redock"


def _no_op_dispatch(*args: object, **_kwargs: object) -> None:
    """Stand in for ``run_bridge_coroutine_logged`` without dispatching anything real.

    The bridge coroutine handed in is closed unstarted, so the real
    ``SandboxBridge.create`` body never runs and no un-awaited coroutine
    warning is emitted.

    Args:
        *args: Positional arguments (the coroutine and callbacks); coroutines are closed.
        **_kwargs: Ignored keyword arguments (event name, logger, context).
    """
    for arg in args:
        if inspect.iscoroutine(arg):
            arg.close()


def _no_op_show_error(*_args: object, **_kwargs: object) -> None:
    """Stand in for ``show_error`` so the modal failure dialog never blocks the test.

    Args:
        *_args: Ignored positional arguments (parent, title, message).
        **_kwargs: Ignored keyword arguments (the reported exception).
    """


class _ExposedSandboxPanel(SandboxPanel):
    """Exposes ``SandboxPanel``'s private create/status internals for testing.

    ``basedpyright`` reports ``reportPrivateUsage`` for a test reaching a
    private member directly, so the members under test are forwarded through
    public methods - the same pattern the sibling ``windows.py``/``qemu.py``
    gates use.
    """

    def status_text(self) -> str:
        """Read the current header status-indicator text.

        Returns:
            str: The status indicator's current label.
        """
        return self._status_indicator.text()

    def trigger_create(self) -> None:
        """Forward to :meth:`SandboxPanel._on_create`."""
        self._on_create()

    def trigger_create_error(self, exc: BaseException) -> None:
        """Forward to :meth:`SandboxPanel._on_create_error`.

        Args:
            exc: Exception standing in for the failed create's real error.
        """
        self._on_create_error(exc)


class TestSandboxCreateHeaderState:
    """The header must reflect that a create is genuinely in progress, not just its two extremes."""

    @staticmethod
    def _make_panel(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> _ExposedSandboxPanel:
        """Build a panel whose create dispatch never actually reaches a real backend.

        ``run_bridge_coroutine_logged`` is replaced with a no-op so the test
        observes only the synchronous status-label update ``_on_create``
        makes before dispatching - exactly what a slow or hung create leaves
        the header showing - without needing a real sandbox backend, a real
        coroutine, or the shared bridge event loop thread.

        Args:
            qapp: Session QApplication fixture, required to construct Qt widgets.
            monkeypatch: Pytest fixture used to stub the dispatch call.

        Returns:
            _ExposedSandboxPanel: A panel ready to have create/status driven directly.
        """
        assert isinstance(qapp, QApplication)
        monkeypatch.setattr(sandbox_panel_module, "run_bridge_coroutine_logged", _no_op_dispatch)
        panel = _ExposedSandboxPanel()
        panel.set_bridge(SandboxBridge())
        return panel

    @staticmethod
    def test_starting_a_create_shows_an_intermediate_status_before_the_bridge_answers(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Create must move the header off "Inactive" immediately, not just on success.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Pytest fixture used to stub the dispatch call.
        """
        panel = TestSandboxCreateHeaderState._make_panel(qapp, monkeypatch)
        assert panel.status_text() == "Inactive"

        panel.trigger_create()

        assert panel.status_text() not in {"", "Inactive"}, (
            "the header must show an intermediate state as soon as create is dispatched, "
            "instead of staying on Inactive for the whole (possibly slow) create"
        )
        assert panel.status_text() == "Starting..."

    @staticmethod
    def test_a_failed_create_resets_the_header_back_to_inactive(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failed create must not leave the header stuck on the intermediate state.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: Pytest fixture used to stub the dispatch call and make
                ``show_error`` a no-op so the modal failure dialog never blocks this test.
        """
        panel = TestSandboxCreateHeaderState._make_panel(qapp, monkeypatch)
        monkeypatch.setattr(sandbox_panel_module, "show_error", _no_op_show_error)

        panel.trigger_create()
        assert panel.status_text() == "Starting..."

        panel.trigger_create_error(RuntimeError("dispatcher did not signal ready"))

        assert panel.status_text() == "Inactive"
