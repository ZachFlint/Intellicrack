# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Closing Provider Settings mid-request must not destroy the running worker.

The settings widget refreshes its model list on a background ``QThread``. That
thread used to be parented to the widget, so closing the widget while a
refresh was in flight -- against a slow or unreachable endpoint, for up to the
request's 15-second timeout -- had Qt delete a running thread together with its
parent. Qt answers that with an access violation that takes the whole
application down.

The gate holds a real model-list request open on a loopback socket, deletes
the widget while the worker is blocked inside it, and requires the thread to
survive its former owner. It then lets the request finish and requires the
late result to be dropped rather than delivered to the deleted widget.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication, QEvent

from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.ui.provider_config import ModelRefreshWorker, ProviderSettingsWidget
from tests._helpers.provider_state import isolate_provider_environment


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from pytestqt.qtbot import QtBot


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_HELD_MODEL_ID: Final[str] = "held-request-model"
_CONNECT_WAIT_S: Final[float] = 20.0
_WORKER_JOIN_MS: Final[int] = 30_000
_ACCEPT_BACKLOG: Final[int] = 4
_RECV_CHUNK: Final[int] = 65_536


class _HeldResponseServer:
    """Loopback HTTP server that holds every request open until released.

    Attributes:
        connected: Set once a client has connected and sent its request.
        release: Set by the test to let the held responses go out.
    """

    connected: threading.Event
    release: threading.Event

    def __init__(self) -> None:
        """Bind an ephemeral loopback port and start accepting connections."""
        self.connected = threading.Event()
        self.release = threading.Event()
        self._listener = socket.create_server(("127.0.0.1", 0), backlog=_ACCEPT_BACKLOG)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="held-response-server", daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        """The OpenAI-compatible base URL this server answers under.

        Returns:
            str: ``http://127.0.0.1:<port>/v1``.
        """
        port: int = self._listener.getsockname()[1]
        return f"http://127.0.0.1:{port}/v1"

    def _serve(self) -> None:
        """Accept connections and answer each one only after ``release`` is set."""
        self._listener.settimeout(0.2)
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
            client.settimeout(_CONNECT_WAIT_S)
            _ = client.recv(_RECV_CHUNK)
            self.connected.set()
            self.release.wait(timeout=_CONNECT_WAIT_S * 2)
            body = json.dumps({"object": "list", "data": [{"id": _HELD_MODEL_ID, "object": "model"}]}).encode()
            head = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            try:
                client.sendall(head.encode() + body)
            except OSError:
                return

    def close(self) -> None:
        """Release any held request and stop accepting connections."""
        self.release.set()
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=5)


@pytest.fixture
def held_server() -> Iterator[_HeldResponseServer]:
    """Provide a loopback server that holds requests until released.

    Yields:
        _HeldResponseServer: The running server.
    """
    server = _HeldResponseServer()
    try:
        yield server
    finally:
        server.close()


def test_closing_the_widget_mid_refresh_leaves_the_worker_running(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    held_server: _HeldResponseServer,
) -> None:
    """A model refresh in flight must outlive the widget that started it.

    Args:
        qtbot: pytest-qt bot, which fails the test on any exception raised in
            the Qt event loop -- including a late result reaching a deleted
            widget.
        tmp_path: Per-test directory for ``.env`` and ``providers.json``.
        monkeypatch: Isolates the process environment from real provider keys.
        held_server: Loopback endpoint that holds the model-list request open.
    """
    isolate_provider_environment(monkeypatch)
    env_path = tmp_path / ".env"
    probe_key = "held-request-probe-key"
    _ = env_path.write_text(
        f'OPENAI_API_KEY={probe_key}\nOPENAI_API_BASE="{held_server.base_url}"\n',
        encoding="utf-8",
    )

    widget = ProviderSettingsWidget(
        "openai",
        config_path=tmp_path / "providers.json",
        credential_loader=CredentialLoader(env_path),
    )

    qtbot.waitUntil(held_server.connected.is_set, timeout=int(_CONNECT_WAIT_S * 1000))
    worker = getattr(widget, "_refresh_worker", None)
    assert isinstance(worker, ModelRefreshWorker)
    assert worker.isRunning(), "the refresh finished before the widget could be closed mid-request"

    widget.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    qtbot.waitUntil(lambda: sip.isdeleted(widget), timeout=5_000)

    assert not sip.isdeleted(worker), "deleting the widget destroyed its running worker thread"
    assert worker.isRunning(), "the worker stopped when its widget was deleted"

    held_server.release.set()
    assert worker.wait(_WORKER_JOIN_MS), "the worker never finished after its request was released"
    QCoreApplication.processEvents()
    QCoreApplication.sendPostedEvents()
