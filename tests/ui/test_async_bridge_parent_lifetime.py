# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates: a bridge call must outlive the widget that dispatched it.

``run_bridge_coroutine_async`` used to parent its ``BridgeCallWorker`` to the calling widget. Closing a panel or dialog while a call was
in flight therefore had Qt delete a running ``QThread`` along with its parent, and Qt answers that with a native access violation that
takes the whole process down: no Python traceback, exit 255, nothing reported. Provider Settings' own workers were fixed the same way in
``ui/provider_config.py``; these gates cover the shared dispatch helper that every panel in the application funnels through.

The worker is now dispatched unparented, carries the calling widget as its recorded owner so :func:`drain_bridge_workers_for` still finds
it, and its result is dropped when that owner's C++ object has been deleted.

Every gate drives the real helpers against a real coroutine -- an HTTP request over a loopback socket the server holds open until the test
releases it -- so the worker is genuinely blocked mid-call when the widget is deleted. The set covers:

* the dispatched worker must not be a Qt child of its delivery context (re-parent it and the widget is its parent again),
* a live delivery context must still receive its result, on the main thread (a guard that dropped everything, or delivery that moved off
  the GUI thread, fails here),
* :func:`drain_bridge_workers_for` must still find and join an unparented worker (drop the recorded owner and it finds nothing to join),
* a result that arrives after the widget is deleted must be dropped instead of delivered into a destroyed C++ object, for both the plain
  and the logged dispatch helper,
* and the worker must survive that deletion at all -- the gate that aborts the interpreter when the worker is parented again.
"""

from __future__ import annotations

import json
import socket
import threading
from typing import TYPE_CHECKING, Final

import httpx
import pytest
from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication, QEvent, QThread
from PyQt6.QtWidgets import QWidget

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import (
    BridgeCallWorker,
    bridge_workers_for,
    drain_bridge_workers_for,
    run_bridge_coroutine_async,
    run_bridge_coroutine_logged,
    worker_is_running,
)


if TYPE_CHECKING:
    from collections.abc import Iterator

    from PyQt6.QtWidgets import QApplication
    from pytestqt.qtbot import QtBot


_SERVED_MARKER: Final[str] = "held-bridge-call"
_ACCEPT_BACKLOG: Final[int] = 4
_ACCEPT_POLL_S: Final[float] = 0.2
_RECV_CHUNK: Final[int] = 65_536
_HTTP_TIMEOUT_S: Final[float] = 60.0
_HOLD_LIMIT_S: Final[float] = 60.0
_CONNECT_WAIT_MS: Final[int] = 20_000
_DELETE_WAIT_MS: Final[int] = 5_000
_WORKER_JOIN_MS: Final[int] = 30_000
_RELEASE_DELAY_S: Final[float] = 0.5
_RESPONDED_WAIT_S: Final[float] = 10.0
_EXPECTED_WORKERS: Final[int] = 1
_EXPECTED_DELIVERIES: Final[int] = 1
_LOG_EVENT: Final[str] = "async_bridge_parent_lifetime_probe"


class _HeldResponseServer:
    """Loopback HTTP server that holds every request open until released.

    Attributes:
        connected: Set once a client has connected and sent its request.
        release: Set by the test to let the held response go out.
        responded: Set once a held response has actually been written back, proving the coroutine under test received a real result.
    """

    connected: threading.Event
    release: threading.Event
    responded: threading.Event

    def __init__(self) -> None:
        """Bind an ephemeral loopback port and start accepting connections."""
        self.connected = threading.Event()
        self.release = threading.Event()
        self.responded = threading.Event()
        self._listener: socket.socket = socket.create_server(("127.0.0.1", 0), backlog=_ACCEPT_BACKLOG)
        self._stop: threading.Event = threading.Event()
        self._thread: threading.Thread = threading.Thread(target=self._serve, name="held-bridge-response-server", daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        """The URL this server answers, held open until :attr:`release` is set.

        Returns:
            str: ``http://127.0.0.1:<port>/held``.
        """
        port: int = self._listener.getsockname()[1]
        return f"http://127.0.0.1:{port}/held"

    def _serve(self) -> None:
        """Accept connections and answer each one only after ``release`` is set."""
        self._listener.settimeout(_ACCEPT_POLL_S)
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._answer, args=(client,), daemon=True).start()

    def _answer(self, client: socket.socket) -> None:
        """Read one request, signal the test, wait for release, then respond.

        Args:
            client: The accepted connection.
        """
        with client:
            client.settimeout(_HOLD_LIMIT_S)
            try:
                _ = client.recv(_RECV_CHUNK)
            except OSError:
                return
            self.connected.set()
            _ = self.release.wait(timeout=_HOLD_LIMIT_S)
            body = json.dumps({"marker": _SERVED_MARKER}).encode()
            head = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            try:
                client.sendall(head.encode() + body)
            except OSError:
                return
            self.responded.set()

    def close(self) -> None:
        """Release any held request and stop accepting connections."""
        self.release.set()
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=5)


class _Delivery:
    """Bridge callback that records its payload and touches the widget it belongs to.

    Panel callbacks update their own widgets, so this one does too: reaching a deleted widget raises ``RuntimeError: wrapped C/C++ object
    ... has been deleted`` out of a Qt slot, which pytest-qt turns into a test failure. A guard that stops delivering is therefore visible
    twice over -- in the empty payload list and in the absence of that raise.

    Attributes:
        payloads: Every payload delivered to this callback, in arrival order.
        threads: The thread each delivery ran on, captured at delivery time. Qt reports the current thread as optional, so a
            delivery whose thread cannot be identified is recorded as ``None`` rather than silently passing a thread assertion.
    """

    payloads: list[object]
    threads: list[QThread | None]

    def __init__(self, widget: QWidget) -> None:
        """Bind the callback to the widget its deliveries update.

        Args:
            widget: Widget the callback writes to, exactly as a panel handler would.
        """
        self.payloads = []
        self.threads = []
        self._widget: QWidget = widget

    def __call__(self, payload: object) -> None:
        """Record one delivery and write it to the bound widget.

        Args:
            payload: Result object or exception emitted by the bridge worker.
        """
        self.payloads.append(payload)
        self.threads.append(QThread.currentThread())
        self._widget.setWindowTitle(f"delivered-{len(self.payloads)}")


async def _fetch(url: str) -> str:
    """Fetch ``url`` over a real HTTP connection and return the response body.

    Args:
        url: Loopback URL served by :class:`_HeldResponseServer`.

    Returns:
        str: The response body, which the server withholds until released.
    """
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S) as client:
        response = await client.get(url)
        return response.text


@pytest.fixture
def held_server() -> Iterator[_HeldResponseServer]:
    """Provide a loopback server that holds its response until released.

    Yields:
        _HeldResponseServer: The running server.
    """
    server = _HeldResponseServer()
    try:
        yield server
    finally:
        server.close()


def _single_worker(widget: QWidget) -> BridgeCallWorker:
    """Return the one retained bridge worker that ``widget`` owns.

    Args:
        widget: The dispatching widget whose worker is wanted.

    Returns:
        BridgeCallWorker: The single worker owned by ``widget``.
    """
    workers = bridge_workers_for(widget)
    assert len(workers) == _EXPECTED_WORKERS, f"expected one retained worker for the dispatching widget, found {len(workers)}"
    worker = workers[0]
    assert isinstance(worker, BridgeCallWorker), f"the retained worker is a {type(worker).__name__}, not a BridgeCallWorker"
    return worker


def _delete(widget: QWidget, qtbot: QtBot) -> None:
    """Destroy ``widget``'s C++ object, as closing a panel or dialog does.

    Args:
        widget: The widget to delete.
        qtbot: pytest-qt bot used to pump the deferred-delete event.
    """
    widget.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    qtbot.waitUntil(lambda: sip.isdeleted(widget), timeout=_DELETE_WAIT_MS)


@pytest.mark.usefixtures("qapp")
def test_the_dispatched_worker_is_not_parented_to_its_delivery_context(qtbot: QtBot, held_server: _HeldResponseServer) -> None:
    """The worker must be unparented, with the widget recorded as its owner instead.

    This is the structural half of the crash fix, and the one gate that reports a clean failure rather than an aborted interpreter: a
    worker parented to the widget is destroyed with it, and Qt answers the destruction of a running ``QThread`` with an access violation.

    Args:
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
        held_server: Loopback endpoint holding the request open mid-call.
    """
    widget = QWidget()
    delivery = _Delivery(widget)

    run_bridge_coroutine_async(_fetch(held_server.url), delivery, delivery, parent=widget)
    qtbot.waitUntil(held_server.connected.is_set, timeout=_CONNECT_WAIT_MS)

    worker = _single_worker(widget)
    assert worker.isRunning(), "the call finished before the worker's parentage could be inspected mid-flight"
    assert worker.parent() is None, "the bridge worker is a Qt child of the dispatching widget, which destroys it mid-flight"
    assert worker.owner() is widget, "the dispatching widget was not recorded as the worker's owner"

    held_server.release.set()
    assert drain_bridge_workers_for(widget, _WORKER_JOIN_MS) == _EXPECTED_WORKERS


@pytest.mark.usefixtures("qapp")
def test_a_live_delivery_context_receives_the_result_on_the_main_thread(
    qapp: QApplication,
    qtbot: QtBot,
    held_server: _HeldResponseServer,
) -> None:
    """A result must still reach a live widget, and reach it on the GUI thread.

    The delivery guard wraps the caller's callback, so this gate holds it honest in both directions: the wrapper must pass a real result
    through to a live widget, and it must not move that delivery off the thread the widget lives on.

    Args:
        qapp: The running QApplication, whose thread the delivery must run on.
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
        held_server: Loopback endpoint, released up front so the request completes.
    """
    held_server.release.set()
    widget = QWidget()
    delivery = _Delivery(widget)

    run_bridge_coroutine_async(_fetch(held_server.url), delivery, delivery, parent=widget)
    qtbot.waitUntil(lambda: bool(delivery.payloads), timeout=_CONNECT_WAIT_MS)

    assert len(delivery.payloads) == _EXPECTED_DELIVERIES, f"the result was delivered {len(delivery.payloads)} times"
    payload = delivery.payloads[0]
    assert isinstance(payload, str), f"the bridge delivered a {type(payload).__name__} instead of the response body"
    assert _SERVED_MARKER in payload, f"the delivered body is not the served response: {payload!r}"
    delivered_thread = delivery.threads[0]
    assert delivered_thread is not None, "the delivering thread could not be identified"
    assert delivered_thread is qapp.thread(), "the result was delivered off the GUI thread"
    assert widget.windowTitle() == "delivered-1", "the callback did not run against the live widget"


@pytest.mark.usefixtures("qapp")
def test_drain_bridge_workers_for_joins_an_unparented_worker(qtbot: QtBot, held_server: _HeldResponseServer) -> None:
    """A widget's scoped drain must still find and join the worker it dispatched.

    Unparenting the worker removes it from the widget's Qt subtree, so the scoped drain can only find it through the owner recorded on the
    worker. The request is released from a timer while the drain is blocked, so the drain has to do a real join: dropping the recorded
    owner leaves it nothing to wait for and it returns zero.

    Args:
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
        held_server: Loopback endpoint holding the request open mid-call.
    """
    widget = QWidget()
    delivery = _Delivery(widget)

    run_bridge_coroutine_async(_fetch(held_server.url), delivery, delivery, parent=widget)
    qtbot.waitUntil(held_server.connected.is_set, timeout=_CONNECT_WAIT_MS)
    worker = _single_worker(widget)

    releaser = threading.Timer(_RELEASE_DELAY_S, held_server.release.set)
    releaser.start()
    try:
        drained = drain_bridge_workers_for(widget, _WORKER_JOIN_MS)
    finally:
        releaser.cancel()

    assert drained == _EXPECTED_WORKERS, "the scoped drain did not find the worker its widget dispatched"
    assert not worker_is_running(worker), "the scoped drain returned before the worker had finished"


@pytest.mark.usefixtures("qapp")
def test_a_logged_dispatch_drops_its_result_when_the_context_dies(qtbot: QtBot, held_server: _HeldResponseServer) -> None:
    """``run_bridge_coroutine_logged`` must drop a result for a deleted widget.

    The logged helper is what most panels call, and it wraps the caller's callbacks in its own logging closures before dispatch. This gate
    proves the guard sits outside those closures, where it covers every logged call site at once.

    Args:
        qtbot: pytest-qt bot, which fails the test on an exception raised inside the Qt event loop -- including a late delivery reaching a
            destroyed widget.
        held_server: Loopback endpoint holding the request open until the widget is gone.
    """
    widget = QWidget()
    delivery = _Delivery(widget)

    run_bridge_coroutine_logged(
        _fetch(held_server.url),
        delivery,
        delivery,
        widget,
        event=_LOG_EVENT,
        logger=get_logger(__name__),
    )
    qtbot.waitUntil(held_server.connected.is_set, timeout=_CONNECT_WAIT_MS)
    worker = _single_worker(widget)

    _delete(widget, qtbot)
    held_server.release.set()
    assert worker.wait(_WORKER_JOIN_MS), "the worker never finished after its request was released"
    assert held_server.responded.wait(timeout=_RESPONDED_WAIT_S), "the server never answered, so no late result was ever there to drop"
    QCoreApplication.processEvents()
    QCoreApplication.sendPostedEvents()

    assert delivery.payloads == [], f"a logged result was delivered to a destroyed widget: {delivery.payloads!r}"


@pytest.mark.usefixtures("qapp")
def test_deleting_the_delivery_context_mid_call_leaves_the_worker_running(qtbot: QtBot, held_server: _HeldResponseServer) -> None:
    """Deleting the widget mid-call must not touch the worker, and must drop its result.

    The crash gate. With the worker parented to the widget again, the ``deleteLater`` below destroys a ``QThread`` that is still blocked
    inside its request and the interpreter dies on a native access violation -- exit 255, no traceback, nothing collected. With the fix,
    the worker runs on, finishes normally once released, and its result is dropped instead of being delivered into freed memory.

    Args:
        qtbot: pytest-qt bot, which fails the test on an exception raised inside the Qt event loop -- including a late delivery reaching a
            destroyed widget.
        held_server: Loopback endpoint holding the request open until the widget is gone.
    """
    widget = QWidget()
    delivery = _Delivery(widget)

    run_bridge_coroutine_async(_fetch(held_server.url), delivery, delivery, parent=widget)
    qtbot.waitUntil(held_server.connected.is_set, timeout=_CONNECT_WAIT_MS)
    worker = _single_worker(widget)
    assert worker.isRunning(), "the call finished before the widget could be deleted mid-request"

    _delete(widget, qtbot)

    assert not sip.isdeleted(worker), "deleting the widget destroyed its running worker thread"
    assert worker.isRunning(), "the worker stopped when its delivery context was deleted"
    assert bridge_workers_for(widget), "the deleted widget's in-flight worker can no longer be found for draining"

    held_server.release.set()
    assert worker.wait(_WORKER_JOIN_MS), "the worker never finished after its request was released"
    assert held_server.responded.wait(timeout=_RESPONDED_WAIT_S), "the server never answered, so no late result was ever there to drop"
    QCoreApplication.processEvents()
    QCoreApplication.sendPostedEvents()

    assert delivery.payloads == [], f"a result was delivered to a destroyed widget: {delivery.payloads!r}"
