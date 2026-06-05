# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for SystemTab audit4 F-0020/F-0021/F-0022/F-0023 remediations.

Every test here exercises the production async dispatch path end to end. The
``SystemTab`` slots call ``run_bridge_coroutine_logged`` -> ``run_bridge_coroutine_async``
-> a real ``BridgeCallWorker`` ``QThread`` that runs the bridge coroutine on the
shared persistent asyncio loop and delivers the result (or the raised exception)
back to the Qt main thread via real queued signals. No test patches, mocks, or
otherwise replaces that dispatcher; the only doubles are the awaitable bridge
methods themselves (the external "tool" the bridge wraps), and those return
genuine coroutines that the real worker awaits.

Synchronisation is explicit and observable: ``_pump_until`` spins the real Qt
event loop until the production success/error callback has mutated an observable
piece of state (a table row, a tree population, a recorded warning dialog) or a
bounded monotonic deadline elapses. A timeout fails the test rather than passing
silently, so the gates cannot go green without the real worker completing.

Covers:
- F-0020: _on_pipe_close dispatches before removing the row; on error the row is kept.
- F-0021: _on_job_info clears _res_tree before populating (double-click yields one set).
- F-0022: privileges/debug/services/PEB actions gate on _attached_pid; None -> no dispatch.
- F-0023: all queries pass an _on_error callback that surfaces bridge errors to the user.
"""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtCore import QEventLoop
from PyQt6.QtWidgets import QApplication, QPlainTextEdit, QTableWidget, QTableWidgetItem, QTreeWidget

from intellicrack.ui.panels.async_bridge import shutdown_bridge_loop
from intellicrack.ui.panels.process_panel.system_tab import SystemTab


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator

    from intellicrack.bridges.process import ProcessBridge
    from tests.test_audit4.b6_system_tab.conftest import WarningRecorder

_NOT_ATTACHED_MSG = "Not attached to any process"
_PUMP_TIMEOUT_S = 5.0
_PUMP_SLICE_MS = 10

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qapp() -> Iterator[QApplication]:
    """Provide a session-scoped QApplication and tear down the bridge loop.

    The persistent background asyncio loop used by the real bridge worker is
    shut down on session teardown so the daemon thread does not outlive the
    test session.

    Yields:
        QApplication: A live QApplication for widget construction.
    """
    existing = QApplication.instance()
    app = existing if isinstance(existing, QApplication) else QApplication([])
    try:
        yield app
    finally:
        shutdown_bridge_loop()


def _pump_until(app: QApplication, predicate: Callable[[], bool], timeout_s: float = _PUMP_TIMEOUT_S) -> bool:
    """Spin the real Qt event loop until ``predicate`` holds or a deadline elapses.

    Delivers the queued ``call_finished`` / ``call_error`` signals emitted by the
    background ``BridgeCallWorker`` to the main thread so the production callbacks
    run. The loop exits the instant ``predicate`` becomes true; the bounded
    deadline only guards against a never-completing worker (which fails the test).

    Args:
        app: Live ``QApplication`` whose event queue is pumped.
        predicate: Observable post-condition the production callback establishes.
        timeout_s: Hard upper bound in seconds before giving up.

    Returns:
        bool: True if ``predicate`` became true within the deadline, else False.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        app.processEvents(QEventLoop.ProcessEventsFlag.WaitForMoreEvents, _PUMP_SLICE_MS)
        app.processEvents()
    return predicate()


class _RecordingAsyncMethod:
    """A genuine awaitable bridge method that records each invocation.

    The instance is callable like a real ``ProcessBridge`` coroutine method:
    calling it returns a fresh coroutine the production worker awaits. It records
    the positional/keyword arguments it was invoked with so tests can assert,
    through the real dispatch path, whether the bridge was reached at all and
    with what arguments.

    Args:
        result: Value the coroutine resolves to when no exception is set.
        exc: Exception the coroutine raises instead of returning ``result``.

    Attributes:
        calls: Ordered list of ``(args, kwargs)`` for every invocation.
    """

    calls: list[tuple[tuple[object, ...], dict[str, object]]]

    def __init__(self, result: object = None, exc: Exception | None = None) -> None:
        self._result = result
        self._exc = exc
        self.calls = []

    def __call__(self, *args: object, **kwargs: object) -> Coroutine[Any, Any, object]:
        """Record the call and return a fresh awaiting coroutine.

        Args:
            *args: Positional arguments forwarded by the production slot.
            **kwargs: Keyword arguments forwarded by the production slot.

        Returns:
            Coroutine[Any, Any, object]: Coroutine resolving to the configured
            result or raising the configured exception.
        """
        self.calls.append((args, kwargs))
        return self._coro()

    async def _coro(self) -> object:
        """Resolve to the configured result or raise the configured exception.

        Returns:
            object: The configured result value.

        Raises:
            self._exc: The configured exception instance, re-raised unchanged so
                the production worker observes the scripted failure. The literal
                raise target is used so static analysis correlates body and docstring.
        """
        if self._exc is not None:
            raise self._exc
        return self._result


class _StubBridge:
    """Bridge stub exposing real awaitable methods that record invocations.

    Each method is a :class:`_RecordingAsyncMethod`, so the production
    ``SystemTab`` slots reach genuine coroutines through the real async worker.
    Default results are valid, well-typed payloads matching the real
    ``ProcessBridge`` return contracts; individual tests override a method to
    inject a specific result or a raising coroutine.
    """

    def __init__(self) -> None:
        self.get_token_privileges = _RecordingAsyncMethod(result=[])
        self.adjust_token_privilege = _RecordingAsyncMethod(result=None)
        self.list_services = _RecordingAsyncMethod(result=[])
        self.read_peb = _RecordingAsyncMethod(result={})
        self.read_teb = _RecordingAsyncMethod(result={})
        self.get_windows = _RecordingAsyncMethod(result=[])
        self.get_job_info = _RecordingAsyncMethod(result={})
        self.get_gui_resources = _RecordingAsyncMethod(result={})
        self.get_mitigation_policies = _RecordingAsyncMethod(result={})
        self.pipe_connect = _RecordingAsyncMethod(result=0xDEAD)
        self.pipe_close = _RecordingAsyncMethod(result=True)


def _make_tab_with_bridge(*, pid: int | None = 1234) -> tuple[SystemTab, _StubBridge]:
    """Create a SystemTab with an attached _StubBridge.

    Args:
        pid: Initial attached PID; pass None to leave unattached.

    Returns:
        tuple[SystemTab, _StubBridge]: Configured tab and its bridge stub.
    """
    tab = SystemTab()
    bridge = _StubBridge()
    tab.set_bridge(cast("ProcessBridge", bridge))
    if pid is not None:
        tab.set_attached_pid(pid)
    return tab, bridge


def _add_pipe_row(tab: SystemTab, pipe_name: str, handle: int) -> None:
    """Insert a pipe row directly into the tab's pipe_table and pipe_handles.

    Args:
        tab: The SystemTab under test.
        pipe_name: Name to write into column 0.
        handle: Integer handle to store in the handles map.
    """
    pipe_table = getattr(tab, "_pipe_table")
    assert isinstance(pipe_table, QTableWidget)
    row = pipe_table.rowCount()
    pipe_table.insertRow(row)
    pipe_table.setItem(row, 0, QTableWidgetItem(pipe_name))
    pipe_table.setItem(row, 1, QTableWidgetItem(f"0x{handle:X}"))
    pipe_handles: dict[str, int] = getattr(tab, "_pipe_handles")
    pipe_handles[pipe_name] = handle


def _select_pipe_row(tab: SystemTab, row: int) -> None:
    """Programmatically select a row in the pipe table.

    Args:
        tab: The SystemTab under test.
        row: Row index to select.
    """
    pipe_table = getattr(tab, "_pipe_table")
    assert isinstance(pipe_table, QTableWidget)
    pipe_table.selectRow(row)


def _pipe_table_row_count(tab: SystemTab) -> int:
    """Return the number of rows in the pipe table.

    Args:
        tab: The SystemTab under test.

    Returns:
        int: Number of rows in the pipe table.
    """
    pipe_table = getattr(tab, "_pipe_table")
    assert isinstance(pipe_table, QTableWidget)
    return pipe_table.rowCount()


def _pipe_handles(tab: SystemTab) -> dict[str, int]:
    """Return the pipe handles dict from the tab.

    Args:
        tab: The SystemTab under test.

    Returns:
        dict[str, int]: The pipe handles mapping.
    """
    result: dict[str, int] = getattr(tab, "_pipe_handles")
    return result


def _res_tree(tab: SystemTab) -> QTreeWidget:
    """Return the resources tree widget from the tab.

    Args:
        tab: The SystemTab under test.

    Returns:
        QTreeWidget: The resources tree widget.
    """
    tree = getattr(tab, "_res_tree")
    assert isinstance(tree, QTreeWidget)
    return tree


def _res_tree_pairs(tab: SystemTab) -> list[tuple[str, str]]:
    """Return the (field, value) text pairs of every top-level resources row.

    Args:
        tab: The SystemTab under test.

    Returns:
        list[tuple[str, str]]: Field/value text for each top-level item, in order.
    """
    tree = _res_tree(tab)
    pairs: list[tuple[str, str]] = []
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        assert item is not None
        pairs.append((item.text(0), item.text(1)))
    return pairs


def _attached_pid(tab: SystemTab) -> int | None:
    """Return the currently attached PID from the tab.

    Args:
        tab: The SystemTab under test.

    Returns:
        int | None: Attached PID or None.
    """
    return cast("int | None", getattr(tab, "_attached_pid"))


def _raw_output_text(tab: SystemTab) -> str:
    """Return the plain text content of the raw output widget.

    Args:
        tab: The SystemTab under test.

    Returns:
        str: Plain text from the raw output.
    """
    raw_output = getattr(tab, "_raw_output")
    assert isinstance(raw_output, QPlainTextEdit)
    return raw_output.toPlainText()


@pytest.mark.usefixtures("qapp")
class TestPipeCloseKeepsRowOnFailure:
    """F-0020: row must not be removed before a real close coroutine succeeds."""

    def test_pipe_close_keeps_row_on_failure(self, qapp: QApplication, warning_recorder: WarningRecorder) -> None:
        """Row stays when the real pipe_close coroutine raises through the worker.

        The terminal observable of the error path is the genuine ``Close Pipe
        Error`` warning dialog the production ``_on_error`` callback shows. Once
        that dialog has fired, the error path has fully run, so asserting the row
        persists afterwards is a real gate: removing the production guard (closing
        the row before the coroutine resolves) would drop the row before this
        point and turn the assertion red.

        Args:
            qapp: Live QApplication used to pump the real worker's signals.
            warning_recorder: Autouse recorder capturing the real error dialog.
        """
        tab, bridge = _make_tab_with_bridge()
        bridge.pipe_close = _RecordingAsyncMethod(exc=OSError("access denied"))

        _add_pipe_row(tab, r"\\.\pipe\TestPipe", 0xABC)
        _select_pipe_row(tab, 0)

        getattr(tab, "_on_pipe_close")()

        failed = _pump_until(qapp, lambda: warning_recorder.titles == ["Close Pipe Error"])
        assert failed, "the real pipe_close worker must have raised and surfaced the error dialog"

        assert bridge.pipe_close.calls == [((0xABC,), {})], "the real handle must be forwarded to the bridge"
        assert warning_recorder.messages == [r"\\.\pipe\TestPipe: access denied"]
        assert _pipe_table_row_count(tab) == 1, "row must remain after the close coroutine raised"
        assert _pipe_handles(tab) == {r"\\.\pipe\TestPipe": 0xABC}, "handle must remain after failure"

    def test_pipe_close_removes_row_on_success(self, qapp: QApplication) -> None:
        """Row is removed only after the real close coroutine resolves successfully.

        Args:
            qapp: Live QApplication used to pump the real worker's signals.
        """
        tab, bridge = _make_tab_with_bridge()

        _add_pipe_row(tab, r"\\.\pipe\TestPipe", 0xABC)
        _select_pipe_row(tab, 0)

        getattr(tab, "_on_pipe_close")()

        removed = _pump_until(qapp, lambda: _pipe_table_row_count(tab) == 0)
        assert removed, "row must be removed after the successful close coroutine"
        assert bridge.pipe_close.calls == [((0xABC,), {})]
        assert r"\\.\pipe\TestPipe" not in _pipe_handles(tab)


@pytest.mark.usefixtures("qapp")
class TestJobInfoClearsBeforePopulate:
    """F-0021: _on_job_info must clear _res_tree before each real populate."""

    def test_job_info_clears_before_populate(self, qapp: QApplication) -> None:
        """Two real Get Job Info dispatches leave exactly one set of entries.

        Args:
            qapp: Live QApplication used to pump the real worker's signals.
        """
        tab, bridge = _make_tab_with_bridge()
        payload: dict[str, object] = {"active_processes": 2, "total_page_file_usage": 4096}
        bridge.get_job_info = _RecordingAsyncMethod(result=payload)
        expected_pairs = [("active_processes", "2"), ("total_page_file_usage", "4096")]

        getattr(tab, "_on_job_info")()
        first = _pump_until(qapp, lambda: _res_tree_pairs(tab) == expected_pairs)
        assert first, "first job-info dispatch must populate the resources tree"

        getattr(tab, "_on_job_info")()
        second = _pump_until(qapp, lambda: len(bridge.get_job_info.calls) == 2 and _res_tree_pairs(tab) == expected_pairs)
        assert second, "second dispatch must clear then repopulate, not append"

        assert bridge.get_job_info.calls == [((1234,), {}), ((1234,), {})], "real pid forwarded on both dispatches"
        assert _res_tree_pairs(tab) == expected_pairs, "exactly one set of entries, in field order, after two dispatches"

    def test_job_info_repopulates_with_new_payload(self, qapp: QApplication) -> None:
        """A second dispatch with different data replaces the first, never merges.

        Args:
            qapp: Live QApplication used to pump the real worker's signals.
        """
        tab, bridge = _make_tab_with_bridge()
        bridge.get_job_info = _RecordingAsyncMethod(result={"active_processes": 9})
        first_pairs = [("active_processes", "9")]
        getattr(tab, "_on_job_info")()
        assert _pump_until(qapp, lambda: _res_tree_pairs(tab) == first_pairs)

        bridge.get_job_info = _RecordingAsyncMethod(result={"total_processes": 1, "active_processes": 3})
        second_pairs = [("total_processes", "1"), ("active_processes", "3")]
        getattr(tab, "_on_job_info")()
        assert _pump_until(qapp, lambda: _res_tree_pairs(tab) == second_pairs)
        assert _res_tree_pairs(tab) == second_pairs, "stale first-dispatch rows must not survive the clear"


@pytest.mark.usefixtures("qapp")
class TestUnattachedDoesNotDispatch:
    """F-0022: pid-gated actions must not reach the real bridge when unattached."""

    def test_unattached_does_not_dispatch_privileges(self, qapp: QApplication) -> None:
        """Get Privileges with no attached pid must not call the real bridge method.

        Args:
            qapp: Live QApplication used to confirm no deferred dispatch occurs.
        """
        tab, bridge = _make_tab_with_bridge(pid=None)
        assert _attached_pid(tab) is None

        getattr(tab, "_refresh_privileges")()

        qapp.processEvents()
        assert bridge.get_token_privileges.calls == [], "no bridge call when _attached_pid is None"

    def test_unattached_does_not_dispatch_enable_debug(self, qapp: QApplication) -> None:
        """Enable Debug Privilege with no attached pid must not call the bridge.

        Args:
            qapp: Live QApplication used to confirm no deferred dispatch occurs.
        """
        tab, bridge = _make_tab_with_bridge(pid=None)
        assert _attached_pid(tab) is None

        getattr(tab, "_on_enable_debug")()

        qapp.processEvents()
        assert bridge.adjust_token_privilege.calls == [], "no bridge call when _attached_pid is None"

    def test_unattached_does_not_dispatch_services(self, qapp: QApplication) -> None:
        """Enumerate Services with no attached pid must not call the bridge.

        Args:
            qapp: Live QApplication used to confirm no deferred dispatch occurs.
        """
        tab, bridge = _make_tab_with_bridge(pid=None)
        assert _attached_pid(tab) is None

        getattr(tab, "_refresh_services")()

        qapp.processEvents()
        assert bridge.list_services.calls == [], "no bridge call when _attached_pid is None"

    def test_unattached_does_not_dispatch_read_peb(self, qapp: QApplication) -> None:
        """Read PEB with no attached pid must not call the bridge.

        Args:
            qapp: Live QApplication used to confirm no deferred dispatch occurs.
        """
        tab, bridge = _make_tab_with_bridge(pid=None)
        assert _attached_pid(tab) is None

        getattr(tab, "_on_read_peb")()

        qapp.processEvents()
        assert bridge.read_peb.calls == [], "no bridge call when _attached_pid is None"

    def test_attached_privileges_does_dispatch_to_real_bridge(self, qapp: QApplication) -> None:
        """When attached, Get Privileges reaches the bridge and renders the rows.

        This complements the negative gate: it proves the gate guards the *real*
        dispatch path rather than an always-dead one, so the unattached asserts
        above are meaningful.

        Args:
            qapp: Live QApplication used to pump the real worker's signals.
        """
        tab, bridge = _make_tab_with_bridge(pid=4321)
        privs: list[dict[str, object]] = [
            {"name": "SeDebugPrivilege", "luid_high": 0, "luid_low": 20, "enabled": True, "attributes": 3},
        ]
        bridge.get_token_privileges = _RecordingAsyncMethod(result=privs)

        getattr(tab, "_refresh_privileges")()

        priv_table = getattr(tab, "_priv_table")
        assert isinstance(priv_table, QTableWidget)
        populated = _pump_until(qapp, lambda: priv_table.rowCount() == 1)
        assert populated, "attached privileges dispatch must populate the table via the real worker"
        assert bridge.get_token_privileges.calls == [((4321,), {})], "real attached pid forwarded to the bridge"

        name_item = priv_table.item(0, 0)
        luid_item = priv_table.item(0, 1)
        enabled_item = priv_table.item(0, 2)
        attr_item = priv_table.item(0, 3)
        assert name_item is not None
        assert luid_item is not None
        assert enabled_item is not None
        assert attr_item is not None
        assert name_item.text() == "SeDebugPrivilege"
        assert luid_item.text() == "00000000:00000014"
        assert enabled_item.text() == "Yes"
        assert attr_item.text() == "3"


@pytest.mark.usefixtures("qapp")
class TestSetAttachedPidNoneSurfacesStatus:
    """F-0022: clearing the pid surfaces the not-attached status without dispatch."""

    def test_set_attached_pid_none_surfaces_not_attached_status(self, qapp: QApplication) -> None:
        """_refresh_privileges with no pid writes Not Attached and never dispatches.

        Args:
            qapp: Live QApplication used to confirm no deferred dispatch occurs.
        """
        tab, bridge = _make_tab_with_bridge()
        tab.set_attached_pid(None)

        getattr(tab, "_refresh_privileges")()

        qapp.processEvents()
        assert bridge.get_token_privileges.calls == [], "no bridge call when pid was cleared to None"
        assert _raw_output_text(tab) == _NOT_ATTACHED_MSG


@pytest.mark.usefixtures("qapp")
class TestQueryErrorSurfacesToUser:
    """F-0023: a real raising bridge coroutine must surface via QMessageBox.warning."""

    def test_privileges_error_surfaces_warning(self, qapp: QApplication, warning_recorder: WarningRecorder) -> None:
        """A raising get_token_privileges coroutine renders the real error dialog.

        Args:
            qapp: Live QApplication used to pump the real worker's signals.
            warning_recorder: Autouse recorder capturing real warning dialogs.
        """
        tab, bridge = _make_tab_with_bridge()
        bridge.get_token_privileges = _RecordingAsyncMethod(exc=RuntimeError("bridge call failed"))

        getattr(tab, "_refresh_privileges")()

        shown = _pump_until(qapp, lambda: warning_recorder.titles == ["Query Privileges Error"])
        assert shown, "the real error coroutine must drive QMessageBox.warning"
        assert bridge.get_token_privileges.calls == [((1234,), {})]
        assert warning_recorder.messages == ["bridge call failed"], "exact exception text must reach the user"

    def test_pipe_close_error_surfaces_warning_and_keeps_row(self, qapp: QApplication, warning_recorder: WarningRecorder) -> None:
        """A raising pipe_close coroutine warns the user and preserves the row.

        Args:
            qapp: Live QApplication used to pump the real worker's signals.
            warning_recorder: Autouse recorder capturing real warning dialogs.
        """
        tab, bridge = _make_tab_with_bridge()
        bridge.pipe_close = _RecordingAsyncMethod(exc=OSError("pipe closed unexpectedly"))

        _add_pipe_row(tab, r"\\.\pipe\ErrPipe", 0x111)
        _select_pipe_row(tab, 0)

        getattr(tab, "_on_pipe_close")()

        shown = _pump_until(qapp, lambda: warning_recorder.titles == ["Close Pipe Error"])
        assert shown, "the real error coroutine must drive QMessageBox.warning"
        assert bridge.pipe_close.calls == [((0x111,), {})]
        assert warning_recorder.messages == [r"\\.\pipe\ErrPipe: pipe closed unexpectedly"]
        assert _pipe_table_row_count(tab) == 1, "row must persist after the close failure"

    def test_job_info_error_surfaces_warning(self, qapp: QApplication, warning_recorder: WarningRecorder) -> None:
        """A raising get_job_info coroutine renders the real error dialog.

        Args:
            qapp: Live QApplication used to pump the real worker's signals.
            warning_recorder: Autouse recorder capturing real warning dialogs.
        """
        tab, bridge = _make_tab_with_bridge()
        bridge.get_job_info = _RecordingAsyncMethod(exc=RuntimeError("job query failed"))

        getattr(tab, "_on_job_info")()

        shown = _pump_until(qapp, lambda: warning_recorder.titles == ["Get Job Info Error"])
        assert shown, "the real error coroutine must drive QMessageBox.warning"
        assert bridge.get_job_info.calls == [((1234,), {})]
        assert warning_recorder.messages == ["job query failed"]

    def test_services_error_surfaces_warning(self, qapp: QApplication, warning_recorder: WarningRecorder) -> None:
        """A raising list_services coroutine renders the real error dialog.

        Args:
            qapp: Live QApplication used to pump the real worker's signals.
            warning_recorder: Autouse recorder capturing real warning dialogs.
        """
        tab, bridge = _make_tab_with_bridge()
        bridge.list_services = _RecordingAsyncMethod(exc=RuntimeError("services enum failed"))

        getattr(tab, "_refresh_services")()

        shown = _pump_until(qapp, lambda: warning_recorder.titles == ["Enumerate Services Error"])
        assert shown, "the real error coroutine must drive QMessageBox.warning"
        assert bridge.list_services.calls == [((1234,), {})]
        assert warning_recorder.messages == ["services enum failed"]


@pytest.mark.usefixtures("qapp")
class TestUserVisibleWarningDialogIsShown:
    """F-0022/F-0023: production code must display the real ``QMessageBox.warning`` modal.

    These tests use no bridge double at all on the gated path: every warning is
    raised entirely by production ``SystemTab`` code and rendered by the genuine
    static ``QMessageBox.warning``. The autouse ``warning_recorder`` captures the
    real modal Qt creates, records its actual ``windowTitle()``/``text()``, and
    dismisses it. Asserting on the recorded title/text proves the real warning
    mechanism fired with the exact content production specifies.
    """

    def test_pid_gate_shows_real_not_attached_warning(self, warning_recorder: WarningRecorder) -> None:
        """An unattached privileges query renders the genuine not-attached dialog.

        Args:
            warning_recorder: Autouse recorder capturing real warning dialogs.
        """
        tab, bridge = _make_tab_with_bridge(pid=None)
        assert _attached_pid(tab) is None

        getattr(tab, "_refresh_privileges")()

        assert bridge.get_token_privileges.calls == [], "no bridge dispatch may occur when unattached"
        assert warning_recorder.titles == ["Query Privileges"], (
            f"expected exactly one warning titled 'Query Privileges', got {warning_recorder.titles}"
        )
        assert warning_recorder.messages == [_NOT_ATTACHED_MSG]
        assert _raw_output_text(tab) == _NOT_ATTACHED_MSG

    def test_read_teb_without_selection_shows_real_warning(self, warning_recorder: WarningRecorder) -> None:
        """Reading TEB with no selected thread renders the genuine warning dialog.

        Args:
            warning_recorder: Autouse recorder capturing real warning dialogs.
        """
        tab, bridge = _make_tab_with_bridge()

        getattr(tab, "_on_read_teb")()

        assert bridge.read_teb.calls == [], "no bridge dispatch may occur when no thread is selected"
        assert warning_recorder.titles == ["Read TEB"]
        assert warning_recorder.messages == ["No thread selected"]

    def test_distinct_actions_record_distinct_real_dialogs_in_order(self, warning_recorder: WarningRecorder) -> None:
        """Two distinct unattached actions each fire their own correctly-titled dialog.

        Args:
            warning_recorder: Autouse recorder capturing real warning dialogs.
        """
        tab, bridge = _make_tab_with_bridge(pid=None)

        getattr(tab, "_refresh_privileges")()
        getattr(tab, "_refresh_services")()

        assert bridge.get_token_privileges.calls == [], "no bridge dispatch may occur when unattached"
        assert bridge.list_services.calls == [], "no bridge dispatch may occur when unattached"
        assert warning_recorder.titles == ["Query Privileges", "Enumerate Services"]
        assert warning_recorder.messages == [_NOT_ATTACHED_MSG, _NOT_ATTACHED_MSG]
