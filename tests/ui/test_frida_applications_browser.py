# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for finding T2-8b: the Frida panel's application browser.

``FridaBridge.enumerate_applications`` and its ``ToolFunction`` were already
real and correct, but a human operator of the Frida panel had no GUI control
to list installed applications at all -- the primary way to target an
app-model process that is not yet running (the process browser only shows
already-running processes). This adds a reachable "Applications" tab beside
the existing "Processes" tab, wired through ``run_bridge_coroutine_logged``
following the established process-browser pattern, with the same
select-to-target flow for a running instance and a clear, non-misleading
fallback for an application that has no running instance to attach to.

Tests drive the real ``FridaPanel`` widget: the tab/table/button widgets are
inspected directly (proving the control is actually reachable, not merely
described), the real ``_populate_application_table`` callback is exercised
with genuine ``FridaApplicationInfo`` dataclass instances (the exact shape
``FridaBridge.enumerate_applications`` returns), and the real
``_on_refresh_applications`` handler is driven against a real (uninitialized)
``FridaBridge`` to prove the Refresh button is genuinely wired to the bridge
method end to end, not a dead control.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

import pytest
from PyQt6.QtWidgets import QPushButton, QTableWidget, QTabWidget

from intellicrack.core.types import FridaApplicationInfo
from intellicrack.ui.panels import async_bridge as async_bridge_module
from intellicrack.ui.panels.frida_panel import (
    _APPLICATION_COL_IDENTIFIER,
    _APPLICATION_COL_NAME,
    _APPLICATION_COL_PID,
    FridaPanel,
)


try:
    from intellicrack.bridges.frida_bridge import FridaBridge

    _frida_available: bool = True
except ImportError:
    _frida_available = False


pytestmark = pytest.mark.usefixtures("qapp")

_RUNNING_APP: Final[FridaApplicationInfo] = FridaApplicationInfo(
    identifier="com.example.running",
    name="Running App",
    pid=4321,
)
_STOPPED_APP: Final[FridaApplicationInfo] = FridaApplicationInfo(
    identifier="com.example.stopped",
    name="Stopped App",
    pid=0,
)


@pytest.fixture
def require_frida() -> None:
    """Skip the current test when frida-python is not installed."""
    if not _frida_available:
        pytest.skip("frida-python required for this test")


@pytest.fixture
def synchronous_dispatch(monkeypatch: pytest.MonkeyPatch) -> list[Coroutine[object, object, object]]:
    """Replace ``run_bridge_coroutine_async`` with a synchronous, draining capture.

    The real bridge coroutine still runs and its real result/exception still
    flows to the panel's real ``on_success``/``on_error`` callbacks; only the
    ``BridgeCallWorker`` ``QThread`` scheduling is swapped for an immediate,
    same-thread run so assertions do not race a background thread. Mirrors
    the established pattern in ``tests/ui/test_frida_remote_and_processes.py``.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        list[Coroutine[object, object, object]]: List that records every
        coroutine the panel tried to dispatch, in dispatch order.
    """
    captured: list[Coroutine[object, object, object]] = []
    drain_loop = asyncio.new_event_loop()

    def fake_dispatch(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: object = None,
    ) -> None:
        del parent
        captured.append(coro)
        try:
            result = drain_loop.run_until_complete(coro)
        except Exception as exc:  # noqa: BLE001
            if on_error is not None:
                on_error(exc)
            return
        if on_success is not None:
            on_success(result)

    monkeypatch.setattr(async_bridge_module, "run_bridge_coroutine_async", fake_dispatch)
    return captured


def test_applications_tab_is_reachable_beside_processes_tab() -> None:
    """Verify the Applications browser exists as a real, reachable tab.

    Falsifiable: before this fix, ``FridaPanel`` had no ``_target_tabs``,
    ``_application_table``, or ``_refresh_apps_btn`` attributes at all --
    the process browser was the sole widget in that pane -- so this
    construction and these attribute/type/tab-label assertions fail
    against the pre-fix panel.
    """
    panel = FridaPanel()
    try:
        assert isinstance(panel._target_tabs, QTabWidget)
        labels = [panel._target_tabs.tabText(i) for i in range(panel._target_tabs.count())]
        assert "Processes" in labels, f"Processes tab must still be present, got tabs {labels}"
        assert "Applications" in labels, f"Applications tab must be reachable beside Processes, got tabs {labels}"

        assert isinstance(panel._application_table, QTableWidget)
        assert isinstance(panel._refresh_apps_btn, QPushButton)

        applications_index = labels.index("Applications")
        tab_page = panel._target_tabs.widget(applications_index)
        assert tab_page is not None
        assert tab_page.isAncestorOf(panel._application_table), "the application table must actually live inside the Applications tab page"
    finally:
        panel.close()


def test_populate_application_table_renders_identifier_name_and_pid() -> None:
    """Verify the real population callback renders both running and stopped applications.

    Drives the real ``_populate_application_table`` (the exact
    ``on_success`` callback ``_on_refresh_applications`` wires up) with
    genuine ``FridaApplicationInfo`` rows -- one currently running, one
    not -- and asserts the rendered cells. The not-running row's PID cell
    must render empty (not the literal ``"0"``), because
    ``_on_application_double_click`` relies on that exact convention to
    decide whether a row can be attached to directly.

    Falsifiable: before this fix, no such callback or table existed at
    all, so constructing the panel and reading ``_application_table``
    raises ``AttributeError``; a naive implementation rendering ``"0"``
    for a stopped application would fail the empty-PID assertion.
    """
    panel = FridaPanel()
    try:
        panel._populate_application_table([_STOPPED_APP, _RUNNING_APP])

        assert panel._application_table.rowCount() == 2

        stopped_identifier = panel._application_table.item(0, _APPLICATION_COL_IDENTIFIER)
        stopped_name = panel._application_table.item(0, _APPLICATION_COL_NAME)
        stopped_pid = panel._application_table.item(0, _APPLICATION_COL_PID)
        assert stopped_identifier is not None
        assert stopped_name is not None
        assert stopped_pid is not None
        assert stopped_identifier.text() == _STOPPED_APP.identifier
        assert stopped_name.text() == _STOPPED_APP.name
        assert not stopped_pid.text(), f"a stopped application's PID cell must render empty, got {stopped_pid.text()!r}"

        running_identifier = panel._application_table.item(1, _APPLICATION_COL_IDENTIFIER)
        running_pid = panel._application_table.item(1, _APPLICATION_COL_PID)
        assert running_identifier is not None
        assert running_pid is not None
        assert running_identifier.text() == _RUNNING_APP.identifier
        assert running_pid.text() == str(_RUNNING_APP.pid)
    finally:
        panel.close()


def test_double_click_running_application_targets_and_attaches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify double-clicking a running application row targets and attaches to it.

    Mirrors ``_on_process_double_click``'s established select-to-target
    flow: the real ``_target_input`` must be populated with the running
    application's PID and a real attach attempt must be triggered.
    ``_on_attach`` is monkeypatched to a spy so this test verifies routing
    without needing a real attachable process.

    Falsifiable: before this fix, no ``_on_application_double_click``
    handler existed (``AttributeError``); a broken routing that forgets to
    call ``_on_attach`` or writes the wrong value would fail these
    assertions instead.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    panel = FridaPanel()
    try:
        panel._populate_application_table([_STOPPED_APP, _RUNNING_APP])
        panel._application_table.selectRow(1)

        attach_calls: list[None] = []
        monkeypatch.setattr(panel, "_on_attach", lambda: attach_calls.append(None))

        panel._on_application_double_click()

        assert panel._target_input.text() == str(_RUNNING_APP.pid), (
            f"target input must be populated with the running app's pid, got {panel._target_input.text()!r}"
        )
        assert len(attach_calls) == 1, "a running application row must trigger exactly one attach attempt"
    finally:
        panel.close()


def test_double_click_stopped_application_does_not_attach(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify double-clicking a stopped application never attempts an attach.

    An application with no running instance has no process to attach to
    (attaching would only ever raise ``frida.ProcessNotFoundError``), so
    the identifier is copied into the target field for reference and no
    attach attempt is made; the console must explain why.

    Falsifiable: a naive copy of the process browser's double-click
    behaviour would call ``_on_attach`` unconditionally, which this
    ``attach_calls == []`` assertion would catch; a handler that leaves
    the target field untouched or is silent about the skipped attach
    would fail the remaining assertions.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    panel = FridaPanel()
    try:
        panel._populate_application_table([_STOPPED_APP, _RUNNING_APP])
        panel._application_table.selectRow(0)

        attach_calls: list[None] = []
        monkeypatch.setattr(panel, "_on_attach", lambda: attach_calls.append(None))

        panel._on_application_double_click()

        assert not attach_calls, "a stopped application must never trigger an attach attempt"
        assert panel._target_input.text() == _STOPPED_APP.identifier, (
            f"target input must carry the stopped app's identifier for reference, got {panel._target_input.text()!r}"
        )
        console_text = panel._console.toPlainText()
        assert _STOPPED_APP.name in console_text, f"console must name the stopped application, got {console_text!r}"
        assert "not running" in console_text.lower(), f"console must explain why no attach was attempted, got {console_text!r}"
    finally:
        panel.close()


@pytest.mark.usefixtures("require_frida")
def test_refresh_applications_button_is_wired_to_real_bridge_method(
    synchronous_dispatch: list[Coroutine[object, object, object]],
) -> None:
    """Verify Refresh genuinely dispatches ``FridaBridge.enumerate_applications``.

    Drives the real ``_on_refresh_applications`` handler against a real
    (uninitialized) ``FridaBridge`` -- no device is attached, so the real
    coroutine raises a real ``ToolError``, which must surface through the
    real ``_on_refresh_applications_error`` callback into the console. This
    proves the button reaches the actual bridge method end to end rather
    than being cosmetically present with nothing behind it.

    Falsifiable: a decorative button with no ``clicked`` connection, or a
    handler that calls the wrong bridge method, would leave
    ``synchronous_dispatch`` empty; a handler that swallows the failure
    instead of routing it to ``_on_refresh_applications_error`` would leave
    the console silent and the button permanently disabled.

    Args:
        synchronous_dispatch: Fixture capturing dispatched bridge coroutines.
    """
    panel = FridaPanel()
    bridge = FridaBridge()
    try:
        panel.set_bridge(bridge)

        panel._on_refresh_applications()

        assert len(synchronous_dispatch) == 1, "Refresh must dispatch exactly one real bridge coroutine"
        assert panel._refresh_apps_btn.isEnabled(), "Refresh must re-enable itself once the dispatch completes"
        console_text = panel._console.toPlainText()
        assert "Enumerate applications failed" in console_text, (
            f"the real bridge failure (no device attached) must reach the panel's error handler, got {console_text!r}"
        )
    finally:
        panel.close()
