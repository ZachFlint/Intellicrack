# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for SystemTab audit4 F-0020/F-0021/F-0022/F-0023 remediations.

Covers:
- F-0020: _on_pipe_close dispatches before removing the row; on error the row is kept.
- F-0021: _on_job_info clears _res_tree before populating (double-click yields one set).
- F-0022: privileges/debug/services/PEB actions gate on _attached_pid; None -> no dispatch.
- F-0023: all queries pass an _on_error callback that surfaces bridge errors via warning log.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch

import pytest
from PyQt6.QtWidgets import QApplication, QPlainTextEdit, QTableWidget, QTableWidgetItem, QTreeWidget

from intellicrack.ui.panels.process_panel.system_tab import SystemTab


if TYPE_CHECKING:
    from intellicrack.bridges.process import ProcessBridge

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_WORKER_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ArithmeticError,
    AttributeError,
    LookupError,
    OSError,
    PermissionError,
    RuntimeError,
    SyntaxError,
    TimeoutError,
    TypeError,
    ValueError,
)


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Provide a session-scoped QApplication for Qt widget tests.

    Returns:
        QApplication: A live QApplication for widget construction.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        return existing
    return QApplication([])


class _AsyncSuccess:
    """Minimal awaitable bridge method stub that resolves to a fixed value."""

    def __init__(self, value: object) -> None:
        """Initialise with the value the coroutine will return.

        Args:
            value: Return value yielded by the coroutine.
        """
        self._value = value

    async def __call__(self, *_args: object, **_kwargs: object) -> object:
        """Execute the stub and return the configured value.

        Args:
            *_args: Ignored positional arguments.
            **_kwargs: Ignored keyword arguments.

        Returns:
            object: The configured return value.
        """
        return self._value


class _AsyncError:
    """Minimal awaitable bridge method stub that raises a fixed exception."""

    def __init__(self, exc: Exception) -> None:
        """Initialise with the exception the coroutine will raise.

        Args:
            exc: Exception raised by the coroutine.
        """
        self._exc = exc

    async def __call__(self, *_args: object, **_kwargs: object) -> object:
        """Execute the stub and raise the configured exception.

        Args:
            *_args: Ignored positional arguments.
            **_kwargs: Ignored keyword arguments.

        Returns:
            object: Never returns; the coroutine always raises the exception
            supplied at construction.

        Raises:
            self._exc: The exception instance supplied at construction is
                re-raised unchanged so callers observe the scripted failure.
                The Raises entry uses the literal raise target so static
                analysis can correlate the body with the docstring.
        """
        raise self._exc


_CallRecord = tuple[Coroutine[Any, Any, Any], object, object]


def _make_sync_runner(
    calls: list[_CallRecord],
    *,
    error_exc: Exception | None = None,
) -> Callable[..., None]:
    """Build a synchronous replacement for run_bridge_coroutine_async.

    Drives the coroutine to completion synchronously, then invokes either
    on_success or on_error based on whether the coroutine raises.

    Args:
        calls: List that receives (coro, on_success, on_error) per invocation.
        error_exc: If set, the synthetic exception injected into on_error instead
            of running the coroutine.

    Returns:
        Callable[..., None]: A callable that mimics run_bridge_coroutine_async.
    """

    def _run(
        coro: Coroutine[Any, Any, Any],
        on_success: object = None,
        on_error: object = None,
        _parent: object = None,
    ) -> None:
        calls.append((coro, on_success, on_error))
        if error_exc is not None:
            coro.close()
            if callable(on_error):
                on_error(error_exc)
            return
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(coro)
        except _WORKER_EXCEPTIONS as exc:
            if callable(on_error):
                on_error(exc)
        else:
            if callable(on_success):
                on_success(result)
        finally:
            loop.close()

    return _run


def _make_error_capture_runner(
    errors_received: list[object],
    error_exc: Exception,
) -> Callable[..., None]:
    """Build a runner that injects error_exc into on_error and records it.

    Args:
        errors_received: List that receives each on_error invocation's argument.
        error_exc: Exception to inject into every on_error callback.

    Returns:
        Callable[..., None]: A callable that mimics run_bridge_coroutine_async.
    """

    def _run(
        coro: Coroutine[Any, Any, Any],
        _on_success: object = None,
        on_error: object = None,
        _parent: object = None,
    ) -> None:
        coro.close()
        if callable(on_error):
            errors_received.append(error_exc)
            on_error(error_exc)

    return _run


class _StubBridge:
    """Bridge stub with configurable per-method coroutine factories."""

    def __init__(self) -> None:
        """Initialise with default no-op stubs for all relevant methods."""
        self.pipe_close_exc: Exception | None = None
        self.job_info_result: dict[str, object] = {}
        self.privileges_result: list[object] = []

    def get_token_privileges(self, _pid: int | None) -> Coroutine[Any, Any, Any]:
        """Stub for get_token_privileges.

        Args:
            _pid: Process ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding the configured privileges list.
        """
        return _AsyncSuccess(self.privileges_result)()

    def adjust_token_privilege(self, _name: str, *, enable: bool, pid: int | None) -> Coroutine[Any, Any, Any]:
        """Stub for adjust_token_privilege.

        Args:
            _name: Privilege name.
            enable: Whether to enable.
            pid: Process ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding None.
        """
        del enable, pid
        return _AsyncSuccess(None)()

    def list_services(self, _pid: int | None) -> Coroutine[Any, Any, Any]:
        """Stub for list_services.

        Args:
            _pid: Process ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty list.
        """
        return _AsyncSuccess([])()

    def read_peb(self, _pid: int | None) -> Coroutine[Any, Any, Any]:
        """Stub for read_peb.

        Args:
            _pid: Process ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty dict.
        """
        return _AsyncSuccess({})()

    def get_job_info(self, _pid: int | None) -> Coroutine[Any, Any, Any]:
        """Stub for get_job_info.

        Args:
            _pid: Process ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding the configured result dict.
        """
        return _AsyncSuccess(self.job_info_result)()

    def get_gui_resources(self, _pid: int | None) -> Coroutine[Any, Any, Any]:
        """Stub for get_gui_resources.

        Args:
            _pid: Process ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty dict.
        """
        return _AsyncSuccess({})()

    def pipe_close(self, _handle: int) -> Coroutine[Any, Any, Any]:
        """Stub for pipe_close.

        Args:
            _handle: Pipe handle to close.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine that raises or succeeds per configuration.
        """
        if self.pipe_close_exc is not None:
            return _AsyncError(self.pipe_close_exc)()
        return _AsyncSuccess(None)()

    def pipe_connect(self, _name: str) -> Coroutine[Any, Any, Any]:
        """Stub for pipe_connect.

        Args:
            _name: Pipe name to connect to.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding a fake handle integer.
        """
        return _AsyncSuccess(0xDEAD)()

    def get_mitigation_policies(self, _pid: int | None) -> Coroutine[Any, Any, Any]:
        """Stub for get_mitigation_policies.

        Args:
            _pid: Process ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty dict.
        """
        return _AsyncSuccess({})()

    def reg_read_value(self, _key: str, _name: str) -> Coroutine[Any, Any, Any]:
        """Stub for reg_read_value.

        Args:
            _key: Registry key path.
            _name: Value name.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty dict.
        """
        return _AsyncSuccess({})()

    def reg_enum_keys(self, _key: str) -> Coroutine[Any, Any, Any]:
        """Stub for reg_enum_keys.

        Args:
            _key: Registry key path.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty list.
        """
        return _AsyncSuccess([])()

    def reg_enum_values(self, _key: str) -> Coroutine[Any, Any, Any]:
        """Stub for reg_enum_values.

        Args:
            _key: Registry key path.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty list.
        """
        return _AsyncSuccess([])()

    def query_system_info(self, _info_class: int, _buf_size: int) -> Coroutine[Any, Any, Any]:
        """Stub for query_system_info.

        Args:
            _info_class: Information class integer.
            _buf_size: Buffer size in bytes.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding empty bytes.
        """
        return _AsyncSuccess(b"")()

    def get_windows(self, _pid: int) -> Coroutine[Any, Any, Any]:
        """Stub for get_windows.

        Args:
            _pid: Process ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty list.
        """
        return _AsyncSuccess([])()

    def read_teb(self, _tid: int) -> Coroutine[Any, Any, Any]:
        """Stub for read_teb.

        Args:
            _tid: Thread ID.

        Returns:
            Coroutine[Any, Any, Any]: Coroutine yielding an empty dict.
        """
        return _AsyncSuccess({})()


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


def _res_tree_item_count(tab: SystemTab) -> int:
    """Return the number of top-level items in the resources tree.

    Args:
        tab: The SystemTab under test.

    Returns:
        int: Top-level item count.
    """
    res_tree = getattr(tab, "_res_tree")
    assert isinstance(res_tree, QTreeWidget)
    return res_tree.topLevelItemCount()


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


def _attached_pid(tab: SystemTab) -> int | None:
    """Return the currently attached PID from the tab.

    Args:
        tab: The SystemTab under test.

    Returns:
        int | None: Attached PID or None.
    """
    return cast("int | None", getattr(tab, "_attached_pid"))


_MOD = "intellicrack.ui.panels.async_bridge.run_bridge_coroutine_async"


@pytest.mark.usefixtures("qapp")
class TestPipeCloseKeepsRowOnFailure:
    """F-0020: row must not be removed before close succeeds."""

    def test_pipe_close_keeps_row_on_failure(self) -> None:
        """Row stays in the table when the bridge returns an error."""
        tab, bridge = _make_tab_with_bridge()
        exc = OSError("access denied")
        bridge.pipe_close_exc = exc

        _add_pipe_row(tab, r"\\.\pipe\TestPipe", 0xABC)
        _select_pipe_row(tab, 0)

        calls: list[_CallRecord] = []
        runner = _make_sync_runner(calls, error_exc=exc)

        with patch(_MOD, runner):
            getattr(tab, "_on_pipe_close")()

        assert len(calls) == 1, "bridge must have been called exactly once"
        assert _pipe_table_row_count(tab) == 1, "row must remain after close failure"
        assert r"\\.\pipe\TestPipe" in _pipe_handles(tab), "handle must remain after failure"

    def test_pipe_close_removes_row_on_success(self) -> None:
        """Row is removed only after the bridge reports success."""
        tab, _bridge = _make_tab_with_bridge()

        _add_pipe_row(tab, r"\\.\pipe\TestPipe", 0xABC)
        _select_pipe_row(tab, 0)

        calls: list[_CallRecord] = []
        runner = _make_sync_runner(calls)

        with patch(_MOD, runner):
            getattr(tab, "_on_pipe_close")()

        assert len(calls) == 1
        assert _pipe_table_row_count(tab) == 0, "row must be removed after successful close"
        assert r"\\.\pipe\TestPipe" not in _pipe_handles(tab)


@pytest.mark.usefixtures("qapp")
class TestJobInfoClearsBeforePopulate:
    """F-0021: _on_job_info must clear _res_tree before each populate."""

    def test_job_info_clears_before_populate(self) -> None:
        """Double-clicking Get Job Info yields exactly one set of entries."""
        tab, bridge = _make_tab_with_bridge()
        bridge.job_info_result = {"active_processes": 2, "total_page_file_usage": 4096}

        calls: list[_CallRecord] = []
        runner = _make_sync_runner(calls)

        with patch(_MOD, runner):
            getattr(tab, "_on_job_info")()
            getattr(tab, "_on_job_info")()

        assert len(calls) == 2, "bridge must have been called twice"
        count = _res_tree_item_count(tab)
        expected = len(bridge.job_info_result)
        assert count == expected, f"_res_tree must contain {expected} items after two calls, got {count}"


@pytest.mark.usefixtures("qapp")
class TestUnattachedDoesNotDispatchPrivileges:
    """F-0022: pid-gated actions must not dispatch when _attached_pid is None."""

    def test_unattached_does_not_dispatch_privileges(self) -> None:
        """Get Privileges with no attached pid must not invoke the bridge."""
        tab, _bridge = _make_tab_with_bridge(pid=None)
        assert _attached_pid(tab) is None

        calls: list[_CallRecord] = []
        runner = _make_sync_runner(calls)

        with patch(_MOD, runner):
            getattr(tab, "_refresh_privileges")()

        assert calls == [], "no bridge call must occur when _attached_pid is None"

    def test_unattached_does_not_dispatch_enable_debug(self) -> None:
        """Enable Debug Privilege with no attached pid must not invoke the bridge."""
        tab, _bridge = _make_tab_with_bridge(pid=None)
        assert _attached_pid(tab) is None

        calls: list[_CallRecord] = []
        runner = _make_sync_runner(calls)

        with patch(_MOD, runner):
            getattr(tab, "_on_enable_debug")()

        assert calls == [], "no bridge call must occur when _attached_pid is None"

    def test_unattached_does_not_dispatch_services(self) -> None:
        """Enumerate Services with no attached pid must not invoke the bridge."""
        tab, _bridge = _make_tab_with_bridge(pid=None)
        assert _attached_pid(tab) is None

        calls: list[_CallRecord] = []
        runner = _make_sync_runner(calls)

        with patch(_MOD, runner):
            getattr(tab, "_refresh_services")()

        assert calls == [], "no bridge call must occur when _attached_pid is None"

    def test_unattached_does_not_dispatch_read_peb(self) -> None:
        """Read PEB with no attached pid must not invoke the bridge."""
        tab, _bridge = _make_tab_with_bridge(pid=None)
        assert _attached_pid(tab) is None

        calls: list[_CallRecord] = []
        runner = _make_sync_runner(calls)

        with patch(_MOD, runner):
            getattr(tab, "_on_read_peb")()

        assert calls == [], "no bridge call must occur when _attached_pid is None"

    def test_set_attached_pid_none_surfaces_not_attached_status(self) -> None:
        """_refresh_privileges with no pid writes Not Attached into raw output."""
        tab, _bridge = _make_tab_with_bridge()
        tab.set_attached_pid(None)

        calls: list[_CallRecord] = []
        runner = _make_sync_runner(calls)

        with patch(_MOD, runner):
            getattr(tab, "_refresh_privileges")()

        assert calls == []
        assert "Not attached" in _raw_output_text(tab)


@pytest.mark.usefixtures("qapp")
class TestQueryErrorSurfacesToUser:
    """F-0023: bridge errors must not be swallowed — on_error must be wired."""

    def test_query_error_surfaces_to_user(self) -> None:
        """A bridge error on get_token_privileges must invoke on_error, not silently drop."""
        tab, _bridge = _make_tab_with_bridge()

        error_exc = RuntimeError("bridge call failed")
        errors_received: list[object] = []
        runner = _make_error_capture_runner(errors_received, error_exc)

        with patch(_MOD, runner):
            getattr(tab, "_refresh_privileges")()

        assert errors_received, "on_error must have been wired and called"

    def test_pipe_close_error_wired(self) -> None:
        """A bridge error on pipe_close must invoke on_error and be passed the exception."""
        tab, _bridge = _make_tab_with_bridge()

        _add_pipe_row(tab, r"\\.\pipe\ErrPipe", 0x111)
        _select_pipe_row(tab, 0)

        error_exc = OSError("pipe closed unexpectedly")
        errors_received: list[object] = []
        runner = _make_error_capture_runner(errors_received, error_exc)

        with patch(_MOD, runner):
            getattr(tab, "_on_pipe_close")()

        assert errors_received, "on_error must have been wired and invoked"

    def test_job_info_error_wired(self) -> None:
        """A bridge error on get_job_info must invoke on_error."""
        tab, _bridge = _make_tab_with_bridge()

        error_exc = RuntimeError("job query failed")
        errors_received: list[object] = []
        runner = _make_error_capture_runner(errors_received, error_exc)

        with patch(_MOD, runner):
            getattr(tab, "_on_job_info")()

        assert errors_received, "on_error must have been wired and invoked"

    def test_services_error_wired(self) -> None:
        """A bridge error on list_services must invoke on_error."""
        tab, _bridge = _make_tab_with_bridge()

        error_exc = RuntimeError("services enum failed")
        errors_received: list[object] = []
        runner = _make_error_capture_runner(errors_received, error_exc)

        with patch(_MOD, runner):
            getattr(tab, "_refresh_services")()

        assert errors_received, "on_error must have been wired and invoked"
