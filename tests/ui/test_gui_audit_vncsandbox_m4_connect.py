# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for GUI audit finding M4 (VNC connect blocks the GUI thread).

Finding M4: ``VNCWidget.connect_to_server`` ran ``run_bridge_coroutine`` (the
blocking bridge runner) on the Qt main thread, freezing the UI for up to the
connect timeout when the VNC port is unreachable.

These tests assert the fix: the connect handshake is dispatched onto the async
worker path via ``run_bridge_coroutine_logged`` (never the blocking runner) and
the outcome is delivered back on the GUI thread, starting the pump/timer on
success and surfacing failure via ``connection_status_changed``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import intellicrack.ui.panels.vnc_widget as vnc_widget_mod
from intellicrack.ui.panels.vnc_widget import VNCWidget


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    import pytest


class TestConnectDispatch:
    """M4: connect must dispatch via the async worker, not block the GUI thread."""

    @staticmethod
    def test_connect_uses_async_logged_runner_not_blocking(
        qapp: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """connect_to_server must call run_bridge_coroutine_logged, never the blocking runner.

        Args:
            qapp: Session QApplication fixture (ensures a Qt app exists).
            monkeypatch: Fixture used to patch both bridge runners.
        """
        _ = qapp
        widget = VNCWidget()

        logged_calls: list[Coroutine[object, object, object]] = []
        blocking_calls: list[object] = []

        def _fake_logged(
            coro: Coroutine[object, object, object],
            on_success: Callable[[object], None] | None,
            on_error: Callable[[object], None] | None,
            parent: object,
            **_kwargs: object,
        ) -> None:
            """Record the dispatched coroutine and close it without awaiting.

            Args:
                coro: Bridge coroutine that would run on the worker.
                on_success: Success callback (unused here).
                on_error: Error callback (unused here).
                parent: Qt parent (unused here).
                **_kwargs: Structured logging context (ignored).
            """
            _ = (on_success, on_error, parent)
            logged_calls.append(coro)
            coro.close()

        def _fake_blocking(*args: object, **kwargs: object) -> None:
            """Record any (forbidden) blocking-runner invocation.

            Args:
                *args: Positional arguments (ignored).
                **kwargs: Keyword arguments (ignored).
            """
            _ = (args, kwargs)
            blocking_calls.append(True)

        monkeypatch.setattr(vnc_widget_mod, "run_bridge_coroutine_logged", _fake_logged)
        monkeypatch.setattr(vnc_widget_mod, "run_bridge_coroutine", _fake_blocking)

        widget.connect_to_server("127.0.0.1", 5900, password=None)

        assert len(logged_calls) == 1
        assert not blocking_calls

    @staticmethod
    def test_connect_success_starts_pump_and_emits_true(
        qapp: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A successful handshake must start the pump/timer and emit True on the GUI thread.

        Args:
            qapp: Session QApplication fixture (ensures a Qt app exists).
            monkeypatch: Fixture used to patch the async runner and pump start.
        """
        _ = qapp
        widget = VNCWidget()

        pump_started: list[bool] = []
        monkeypatch.setattr(widget, "_start_pump_task", lambda: pump_started.append(True))

        def _immediate_success(
            coro: Coroutine[object, object, object],
            on_success: Callable[[object], None] | None,
            on_error: Callable[[object], None] | None,
            parent: object,
            **_kwargs: object,
        ) -> None:
            """Invoke on_success synchronously as though the handshake succeeded.

            Args:
                coro: Bridge coroutine that would run on the worker.
                on_success: Success callback invoked with a truthy result.
                on_error: Error callback (unused here).
                parent: Qt parent (unused here).
                **_kwargs: Structured logging context (ignored).
            """
            _ = (on_error, parent)
            coro.close()
            if on_success is not None:
                success_result = True
                on_success(success_result)

        monkeypatch.setattr(vnc_widget_mod, "run_bridge_coroutine_logged", _immediate_success)

        statuses: list[bool] = []
        widget.connection_status_changed.connect(statuses.append)

        widget.connect_to_server("127.0.0.1", 5900, password=None)

        assert pump_started == [True]
        assert widget.update_timer.isActive()
        assert statuses == [True]

    @staticmethod
    def test_connect_failure_emits_false_without_pump(
        qapp: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failed handshake must emit False and never start the pump/timer.

        Args:
            qapp: Session QApplication fixture (ensures a Qt app exists).
            monkeypatch: Fixture used to patch the async runner and pump start.
        """
        _ = qapp
        widget = VNCWidget()

        pump_started: list[bool] = []
        monkeypatch.setattr(widget, "_start_pump_task", lambda: pump_started.append(True))

        def _immediate_error(
            coro: Coroutine[object, object, object],
            on_success: Callable[[object], None] | None,
            on_error: Callable[[object], None] | None,
            parent: object,
            **_kwargs: object,
        ) -> None:
            """Invoke on_error synchronously as though the connection failed.

            Args:
                coro: Bridge coroutine that would run on the worker.
                on_success: Success callback (unused here).
                on_error: Error callback invoked with an exception.
                parent: Qt parent (unused here).
                **_kwargs: Structured logging context (ignored).
            """
            _ = (on_success, parent)
            coro.close()
            if on_error is not None:
                on_error(OSError("connection refused"))

        monkeypatch.setattr(vnc_widget_mod, "run_bridge_coroutine_logged", _immediate_error)

        statuses: list[bool] = []
        widget.connection_status_changed.connect(statuses.append)

        widget.connect_to_server("127.0.0.1", 5900, password=None)

        assert statuses == [False]
        assert not pump_started
        assert not widget.update_timer.isActive()


class TestConnectDoesNotBlock:
    """M4: connect_to_server must return without awaiting the coroutine."""

    @staticmethod
    def test_connect_returns_before_coroutine_completes(
        qapp: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """connect_to_server must return synchronously even if the coroutine never completes.

        The fake async runner never invokes the callbacks (mirroring a stalled
        unreachable-port connect). A blocking implementation would wait here and
        the call would not return; the async dispatch returns immediately.

        Args:
            qapp: Session QApplication fixture (ensures a Qt app exists).
            monkeypatch: Fixture used to patch the async runner.
        """
        _ = qapp
        widget = VNCWidget()

        def _never_completes(
            coro: Coroutine[object, object, object],
            on_success: Callable[[object], None] | None,
            on_error: Callable[[object], None] | None,
            parent: object,
            **_kwargs: object,
        ) -> None:
            """Drop the coroutine without ever signalling completion.

            Args:
                coro: Bridge coroutine that would run on the worker.
                on_success: Success callback (never invoked).
                on_error: Error callback (never invoked).
                parent: Qt parent (unused here).
                **_kwargs: Structured logging context (ignored).
            """
            _ = (on_success, on_error, parent)
            coro.close()

        monkeypatch.setattr(vnc_widget_mod, "run_bridge_coroutine_logged", _never_completes)

        statuses: list[bool] = []
        widget.connection_status_changed.connect(statuses.append)

        returned: list[object] = [widget.connect_to_server("10.255.255.1", 5900, password=None)]

        assert returned == [None]
        assert not statuses
        assert not widget.update_timer.isActive()
