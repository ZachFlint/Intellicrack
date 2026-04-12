# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the async bridge infrastructure.

Validates BridgeCallWorker, run_bridge_coroutine (blocking),
run_bridge_coroutine_async (non-blocking), and shutdown_bridge_loop.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.panels import async_bridge as async_bridge_mod
from intellicrack.ui.panels.async_bridge import (
    BridgeCallWorker,
    run_bridge_coroutine,
    shutdown_bridge_loop,
)


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication


ASYNC_RETURN_VALUE = 42
ASYNC_WAIT_MS = 50
POLL_INTERVAL_MS = 10
MAX_WAIT_MS = 3000


@pytest.fixture(autouse=True, scope="session")
def _cleanup_bridge_loop() -> Generator[None]:
    """Shut down the persistent bridge event loop after all async bridge tests.

    Yields:
        None: Nothing (fixture exists for cleanup only).
    """
    yield
    shutdown_bridge_loop()
    time.sleep(0.1)


@pytest.mark.usefixtures("qapp")
class TestRunBridgeCoroutineBlocking:
    """Tests for the blocking run_bridge_coroutine variant."""

    @staticmethod
    def test_returns_coroutine_result() -> None:
        """Verify blocking call returns the coroutine's result."""

        async def simple_coro() -> int:
            await asyncio.sleep(0)
            return ASYNC_RETURN_VALUE

        result = run_bridge_coroutine(simple_coro())
        assert result == ASYNC_RETURN_VALUE

    @staticmethod
    def test_returns_none_result() -> None:
        """Verify blocking call propagates None return correctly."""

        async def none_coro() -> None:
            await asyncio.sleep(0)

        result = run_bridge_coroutine(none_coro())
        assert result is None

    @staticmethod
    def test_raises_on_coroutine_exception() -> None:
        """Verify blocking call propagates coroutine exceptions."""

        async def failing_coro() -> None:
            await asyncio.sleep(0)
            msg = "bridge failure"
            raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="bridge failure"):
            run_bridge_coroutine(failing_coro())

    @staticmethod
    def test_returns_string_result() -> None:
        """Verify blocking call handles string results."""
        expected = "disassembly output"

        async def string_coro() -> str:
            await asyncio.sleep(0)
            return expected

        result = run_bridge_coroutine(string_coro())
        assert result == expected

    @staticmethod
    def test_returns_dict_result() -> None:
        """Verify blocking call handles dict results."""
        expected: dict[str, int] = {"rax": 0x1234, "rbx": 0x5678}

        async def dict_coro() -> dict[str, int]:
            await asyncio.sleep(0)
            return expected

        result = run_bridge_coroutine(dict_coro())
        assert result == expected


@pytest.mark.usefixtures("qapp")
class TestRunBridgeCoroutineAsync:
    """Tests for the non-blocking run_bridge_coroutine_async variant.

    Uses BridgeCallWorker directly to hold references and avoid
    premature garbage collection of QThread objects.
    """

    @staticmethod
    def test_success_callback_invoked(qapp: QApplication) -> None:
        """Verify call_finished signal delivers the coroutine result.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        received: list[object] = []

        async def simple_coro() -> int:
            await asyncio.sleep(0)
            return ASYNC_RETURN_VALUE

        worker = BridgeCallWorker(simple_coro())
        _ = worker.call_finished.connect(received.append)
        worker.start()

        deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while not received and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_INTERVAL_MS / 1000)

        assert len(received) == 1
        assert received[0] == ASYNC_RETURN_VALUE

    @staticmethod
    def test_error_callback_invoked(qapp: QApplication) -> None:
        """Verify call_error signal delivers the exception on failure.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        errors: list[object] = []

        async def failing_coro() -> None:
            await asyncio.sleep(0)
            msg = "async bridge error"
            raise ValueError(msg)

        worker = BridgeCallWorker(failing_coro())
        _ = worker.call_error.connect(errors.append)
        worker.start()

        deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while not errors and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_INTERVAL_MS / 1000)

        assert len(errors) == 1
        assert isinstance(errors[0], ValueError)
        assert str(errors[0]) == "async bridge error"

    @staticmethod
    def test_worker_completes_without_callbacks(qapp: QApplication) -> None:
        """Verify a worker completes even without connected callbacks.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """

        async def noop_coro() -> int:
            await asyncio.sleep(0)
            return 1

        worker = BridgeCallWorker(noop_coro())
        worker.start()

        deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while worker.isRunning() and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_INTERVAL_MS / 1000)

        assert not worker.isRunning()


@pytest.mark.usefixtures("qapp")
class TestBridgeCallWorker:
    """Tests for BridgeCallWorker QThread."""

    @staticmethod
    def test_emits_call_finished_signal(qapp: QApplication) -> None:
        """Verify call_finished signal emits the coroutine result.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        results: list[object] = []

        async def coro() -> str:
            await asyncio.sleep(0)
            return "worker_result"

        worker = BridgeCallWorker(coro())
        worker.call_finished.connect(results.append)
        worker.start()

        deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while not results and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_INTERVAL_MS / 1000)

        assert results == ["worker_result"]

    @staticmethod
    def test_emits_call_error_signal(qapp: QApplication) -> None:
        """Verify call_error signal emits the exception on failure.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        errors: list[object] = []

        async def bad_coro() -> None:
            await asyncio.sleep(0)
            msg = "worker error"
            raise RuntimeError(msg)

        worker = BridgeCallWorker(bad_coro())
        worker.call_error.connect(errors.append)
        worker.start()

        deadline = time.monotonic() + MAX_WAIT_MS / 1000
        while not errors and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(POLL_INTERVAL_MS / 1000)

        assert len(errors) == 1
        assert isinstance(errors[0], RuntimeError)


class TestEnsureLoop:
    """Tests for the persistent event loop management."""

    @staticmethod
    def test_returns_running_loop() -> None:
        """Verify _ensure_loop returns a running event loop."""
        loop = async_bridge_mod.ensure_loop()
        assert loop.is_running()

    @staticmethod
    def test_returns_same_loop_on_repeated_calls() -> None:
        """Verify _ensure_loop returns the same loop instance."""
        loop1 = async_bridge_mod.ensure_loop()
        loop2 = async_bridge_mod.ensure_loop()
        assert loop1 is loop2


class TestShutdownBridgeLoop:
    """Tests for shutdown_bridge_loop cleanup."""

    @staticmethod
    def test_shutdown_is_idempotent() -> None:
        """Verify shutdown_bridge_loop can be called multiple times safely."""
        shutdown_bridge_loop()
        shutdown_bridge_loop()
