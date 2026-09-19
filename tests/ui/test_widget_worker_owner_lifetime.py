# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates: a hand-rolled worker thread must outlive the widget that started it.

The workers that do not go through the async-bridge dispatch helpers each belong to one widget: the tool installer and status check, the
sandbox test, the XPU requirements probe, the tracked-process refresh, the log-tail load, and the provider model refresh and connection
test. Every one of them used to take that widget as its Qt parent. Qt destroys a parent's children along with it, and destroying a
``QThread`` whose OS thread is still running aborts the process with a native access violation and no Python traceback: exit 255 with
nothing reported. A tool download, a Windows Sandbox launch and a model list from an unreachable endpoint all run long enough for a user
to close the window first.

All of them now derive from :class:`RetainedWorker`, which pins the thread in the shared worker registry until its OS thread finishes, and
none of them accepts a Qt parent any more: they take ``owner``, which :func:`drain_bridge_workers_for` matches on and
:func:`guarded_delivery` checks before delivering. Their call sites wrap the closure slots, which is where the guard is load-bearing: Qt
breaks a connection itself when the slot is a bound method of a destroyed ``QObject``, but a closure has no receiver object to detect, so
Qt delivers into it and the call raises out of the slot. Bound-method connections are therefore left alone, not least because some
teardown paths disconnect them by identity.

The gates below cover the class contract for every one of these workers, the guard on a real multi-argument signal while its owner is
destroyed mid-run, and three real widgets driving their real work: a tool status check over a real filesystem path, the XPU requirements
probe, and the log viewer's historical tail load over a real file.
"""

from __future__ import annotations

import ast
import inspect
import json
import socket
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Final

import httpx
import pytest
from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication, QEvent, pyqtSignal
from PyQt6.QtWidgets import QWidget

from intellicrack.ui import xpu_status
from intellicrack.ui.log_viewer._tail_reader import InitialLoadWorker, LogFileTailReader
from intellicrack.ui.panels.async_bridge import RetainedWorker, bridge_workers_for, guarded_delivery
from intellicrack.ui.panels.process_panel.workers import TrackedRefreshWorker
from intellicrack.ui.provider_config import ConnectionTestWorker, ModelRefreshWorker
from intellicrack.ui.sandbox_config import SandboxTestWorker
from intellicrack.ui.tool_config import ToolInstallWorker, ToolSettingsWidget, ToolStatusCheckWorker
from intellicrack.ui.xpu_status import XPUStatusDialog


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

    from pytestqt.qtbot import QtBot


_SERVED_MARKER: Final[str] = "held-widget-worker"
_ACCEPT_BACKLOG: Final[int] = 4
_ACCEPT_POLL_S: Final[float] = 0.2
_RECV_CHUNK: Final[int] = 65_536
_HTTP_TIMEOUT_S: Final[float] = 60.0
_HOLD_LIMIT_S: Final[float] = 60.0
_CONNECT_WAIT_MS: Final[int] = 20_000
_DELETE_WAIT_MS: Final[int] = 5_000
_WORKER_JOIN_MS: Final[int] = 60_000
_RESPONDED_WAIT_S: Final[float] = 10.0
_EXPECTED_WORKERS: Final[int] = 1
_PROBE_LABEL: Final[str] = "probe"
_PROBE_CODE: Final[int] = 1
_TAIL_BYTES: Final[int] = 64 * 1024
_CHECKING_TEXT: Final[str] = "Checking..."
_SANDBOX_MEMORY_MB: Final[int] = 2048
_PROBE_KEY: Final[str] = "gate-probe-key"
_LOG_RECORDS: Final[int] = 8


class _HeldResponseServer:
    """Loopback HTTP server that holds every request open until released.

    Attributes:
        connected: Set once a client has connected and sent its request.
        release: Set by the test to let the held response go out.
        responded: Set once a held response has actually been written back, proving the worker received a real result.
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
        self._thread: threading.Thread = threading.Thread(target=self._serve, name="held-widget-worker-server", daemon=True)
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


class _HeldProbeWorker(RetainedWorker):
    """Widget-owned worker whose real work is an HTTP request the server holds open.

    The production workers differ only in what their ``run`` does: the lifetime contract under test - retained in the shared registry,
    owned by a widget, never its child - comes from :class:`RetainedWorker` itself. Blocking inside a real socket read is what makes the
    mid-run deletion deterministic instead of a race against a fast probe, and the three-argument signal matches the shape the tool and
    provider workers emit.

    Attributes:
        probed: Emitted with a label, a status code and the response body.
    """

    probed: pyqtSignal = pyqtSignal(str, int, str)

    def __init__(self, url: str, *, owner: QWidget | None = None) -> None:
        """Initialise the worker with the URL it will fetch.

        Args:
            url: Loopback URL served by :class:`_HeldResponseServer`.
            owner: Widget that started this probe, recorded rather than used as a Qt parent.
        """
        super().__init__(owner=owner)
        self._url = url

    def run(self) -> None:
        """Fetch the held URL and emit the response body."""
        response = httpx.get(self._url, timeout=_HTTP_TIMEOUT_S)
        self.probed.emit(_PROBE_LABEL, _PROBE_CODE, response.text)


class _Delivery:
    """Worker callback that records its arguments and touches the widget it belongs to.

    Panel slots update their own widgets, so this one does too: reaching a deleted widget raises ``RuntimeError: wrapped C/C++ object ...
    has been deleted`` out of a Qt slot, which pytest-qt turns into a test failure. A guard that stops delivering is visible twice over, in
    the empty call list and in the absence of that raise.

    Attributes:
        calls: The argument tuples delivered to this callback, in arrival order.
    """

    calls: list[tuple[object, ...]]

    def __init__(self, widget: QWidget) -> None:
        """Bind the callback to the widget its deliveries update.

        Args:
            widget: Widget the callback writes to, exactly as a panel slot would.
        """
        self.calls = []
        self._widget: QWidget = widget

    def __call__(self, *payload: object) -> None:
        """Record one delivery and write it to the bound widget.

        Args:
            *payload: Arguments carried by the worker's signal.
        """
        self.calls.append(payload)
        self._widget.setWindowTitle(f"delivered-{len(self.calls)}")


_REQUIREMENTS_WORKER: Final[type[RetainedWorker]] = getattr(xpu_status, "_RequirementsCheckWorker")


def _build_requirements_worker(_tmp_path: Path, owner: QWidget) -> RetainedWorker:
    """Build the XPU requirements probe worker.

    Args:
        _tmp_path: Unused per-test directory.
        owner: Widget to record as the worker's owner.

    Returns:
        RetainedWorker: The constructed, unstarted worker.
    """
    return _REQUIREMENTS_WORKER(owner=owner)


def _build_sandbox_test_worker(_tmp_path: Path, owner: QWidget) -> RetainedWorker:
    """Build the Windows Sandbox test worker.

    Args:
        _tmp_path: Unused per-test directory.
        owner: Widget to record as the worker's owner.

    Returns:
        RetainedWorker: The constructed, unstarted worker.
    """
    return SandboxTestWorker(network_enabled=False, memory_limit_mb=_SANDBOX_MEMORY_MB, owner=owner)


def _build_tool_install_worker(tmp_path: Path, owner: QWidget) -> RetainedWorker:
    """Build the tool install worker.

    Args:
        tmp_path: Per-test directory used as the install target.
        owner: Widget to record as the worker's owner.

    Returns:
        RetainedWorker: The constructed, unstarted worker.
    """
    return ToolInstallWorker("ghidra", tmp_path / "tools" / "ghidra", owner=owner)


def _build_tool_status_worker(tmp_path: Path, owner: QWidget) -> RetainedWorker:
    """Build the tool status-check worker.

    Args:
        tmp_path: Per-test directory used to form a tool path.
        owner: Widget to record as the worker's owner.

    Returns:
        RetainedWorker: The constructed, unstarted worker.
    """
    return ToolStatusCheckWorker("ghidra", str(tmp_path / "ghidra.exe"), owner=owner)


def _build_tracked_refresh_worker(_tmp_path: Path, owner: QWidget) -> RetainedWorker:
    """Build the tracked-process refresh worker.

    Args:
        _tmp_path: Unused per-test directory.
        owner: Widget to record as the worker's owner.

    Returns:
        RetainedWorker: The constructed, unstarted worker.
    """
    return TrackedRefreshWorker(owner=owner)


def _build_initial_load_worker(tmp_path: Path, owner: QWidget) -> RetainedWorker:
    """Build the log viewer's historical-load worker.

    Args:
        tmp_path: Per-test directory holding the log file path.
        owner: Widget to record as the worker's owner.

    Returns:
        RetainedWorker: The constructed, unstarted worker.
    """
    return InitialLoadWorker(tmp_path / "intellicrack.jsonl", _TAIL_BYTES, owner=owner)


def _build_connection_test_worker(_tmp_path: Path, owner: QWidget) -> RetainedWorker:
    """Build the provider connection-test worker.

    Args:
        _tmp_path: Unused per-test directory.
        owner: Widget to record as the worker's owner.

    Returns:
        RetainedWorker: The constructed, unstarted worker.
    """
    return ConnectionTestWorker("openai", _PROBE_KEY, None, owner=owner)


def _build_model_refresh_worker(_tmp_path: Path, owner: QWidget) -> RetainedWorker:
    """Build the provider model-refresh worker.

    Args:
        _tmp_path: Unused per-test directory.
        owner: Widget to record as the worker's owner.

    Returns:
        RetainedWorker: The constructed, unstarted worker.
    """
    return ModelRefreshWorker("openai", _PROBE_KEY, None, None, owner=owner)


_WIDGET_WORKERS: Final[tuple[tuple[str, type[RetainedWorker], Callable[[Path, QWidget], RetainedWorker]], ...]] = (
    ("requirements_check", _REQUIREMENTS_WORKER, _build_requirements_worker),
    ("sandbox_test", SandboxTestWorker, _build_sandbox_test_worker),
    ("tool_install", ToolInstallWorker, _build_tool_install_worker),
    ("tool_status_check", ToolStatusCheckWorker, _build_tool_status_worker),
    ("tracked_refresh", TrackedRefreshWorker, _build_tracked_refresh_worker),
    ("initial_log_load", InitialLoadWorker, _build_initial_load_worker),
    ("connection_test", ConnectionTestWorker, _build_connection_test_worker),
    ("model_refresh", ModelRefreshWorker, _build_model_refresh_worker),
)

_WORKER_CONSTRUCTORS: Final[tuple[tuple[str, type[RetainedWorker]], ...]] = tuple(
    (label, worker_cls) for label, worker_cls, _ in _WIDGET_WORKERS
)


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
@pytest.mark.parametrize(("label", "worker_cls", "build"), _WIDGET_WORKERS, ids=[name for name, _, _ in _WIDGET_WORKERS])
def test_every_widget_worker_records_its_owner_without_a_qt_parent(
    label: str,
    worker_cls: type[RetainedWorker],
    build: Callable[[Path, QWidget], RetainedWorker],
    tmp_path: Path,
) -> None:
    """Each widget-owned worker must record its owner and stay out of the widget's Qt subtree.

    Args:
        label: Identifier of the worker under test, used in the failure message.
        worker_cls: The worker class, checked for the retained base.
        build: Factory constructing that worker with an owner.
        tmp_path: Per-test directory for the workers that need a path.
    """
    widget = QWidget()
    worker = build(tmp_path, widget)

    assert issubclass(worker_cls, RetainedWorker), f"the {label} worker is not retained, so its thread can be collected mid-flight"
    assert worker.parent() is None, f"the {label} worker is a Qt child of its widget, which destroys it mid-flight"
    assert worker.owner() is widget, f"the {label} worker did not record the widget that built it"


@pytest.mark.parametrize(("label", "worker_cls"), _WORKER_CONSTRUCTORS, ids=[name for name, _ in _WORKER_CONSTRUCTORS])
def test_no_widget_worker_accepts_a_qt_parent(label: str, worker_cls: type[RetainedWorker]) -> None:
    """None of these workers may offer a Qt parent for a caller to pass.

    Removing the parameter is what stops the crash from coming back one constructor argument at a time: a call site cannot re-parent a
    worker it has no way to hand a parent to. Restoring ``parent`` on any of these classes turns this red, as does inheriting the base's
    constructor instead of declaring one.

    Args:
        label: Identifier of the worker under test, used in the failure message.
        worker_cls: The worker class whose constructor is inspected.
    """
    parameters = inspect.signature(worker_cls.__init__).parameters

    assert "parent" not in parameters, f"the {label} worker still offers a Qt parent: {sorted(parameters)}"
    assert "owner" in parameters, f"the {label} worker has no owner to record: {sorted(parameters)}"


@pytest.mark.usefixtures("qapp")
def test_a_worker_outliving_its_owner_keeps_running_and_drops_its_result(qtbot: QtBot, held_server: _HeldResponseServer) -> None:
    """A retained, widget-owned worker must survive its owner's deletion and drop its late result.

    The crash gate for the hand-rolled workers' shared machinery, driven against a real HTTP request the server holds open so the thread
    is genuinely blocked when the widget is deleted. With the worker parented again, the ``deleteLater`` below destroys a running
    ``QThread`` and the interpreter dies on a native access violation. The delivery is a three-argument signal, the shape the tool and
    provider workers emit, so this also holds the guard honest about forwarding everything a signal carries.

    Args:
        qtbot: pytest-qt bot, which fails the test on an exception raised inside the Qt event loop.
        held_server: Loopback endpoint holding the request open until the widget is gone.
    """
    widget = QWidget()
    delivery = _Delivery(widget)
    worker = _HeldProbeWorker(held_server.url, owner=widget)
    worker.probed.connect(guarded_delivery(delivery, widget, "success"))
    worker.start()

    qtbot.waitUntil(held_server.connected.is_set, timeout=_CONNECT_WAIT_MS)
    assert worker.isRunning(), "the probe finished before the widget could be deleted mid-request"
    assert bridge_workers_for(widget) == [worker], "the widget's own worker is not discoverable for scoped draining"

    _delete(widget, qtbot)

    assert not sip.isdeleted(worker), "deleting the widget destroyed its running worker thread"
    assert worker.isRunning(), "the worker stopped when its owner was deleted"

    held_server.release.set()
    assert worker.wait(_WORKER_JOIN_MS), "the worker never finished after its request was released"
    assert held_server.responded.wait(timeout=_RESPONDED_WAIT_S), "the server never answered, so no late result was there to drop"
    QCoreApplication.processEvents()
    QCoreApplication.sendPostedEvents()

    assert delivery.calls == [], f"a result was delivered to a destroyed widget: {delivery.calls!r}"


@pytest.mark.usefixtures("qapp")
def test_a_live_owner_receives_every_argument_of_its_workers_signal(qtbot: QtBot, held_server: _HeldResponseServer) -> None:
    """A live owner must receive the full signal payload through the guard.

    The positive control for the gate above: the same worker and the same guard, delivering to a widget that is still alive, must pass all
    three signal arguments through untouched. Without it, a guard that dropped everything would look correct.

    Args:
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
        held_server: Loopback endpoint, released up front so the request completes.
    """
    held_server.release.set()
    widget = QWidget()
    delivery = _Delivery(widget)
    worker = _HeldProbeWorker(held_server.url, owner=widget)
    worker.probed.connect(guarded_delivery(delivery, widget, "success"))
    worker.start()

    qtbot.waitUntil(lambda: bool(delivery.calls), timeout=_CONNECT_WAIT_MS)

    assert len(delivery.calls) == _EXPECTED_WORKERS, f"the result was delivered {len(delivery.calls)} times"
    label, code, body = delivery.calls[0]
    assert label == _PROBE_LABEL
    assert code == _PROBE_CODE
    assert isinstance(body, str), f"the worker delivered a {type(body).__name__} instead of the response body"
    assert _SERVED_MARKER in body, f"the delivered body is not the served response: {body!r}"
    assert widget.windowTitle() == "delivered-1", "the callback did not run against the live widget"


@pytest.mark.usefixtures("qapp")
def test_the_real_tool_status_check_is_owned_by_its_row_and_delivers(qtbot: QtBot, tmp_path: Path) -> None:
    """The real tool row must own its status worker and still receive the probe result.

    Drives the real ``ToolSettingsWidget`` slot against a real filesystem path (this interpreter's own executable), so the availability
    probe, the worker dispatch and the label update are all production code.

    Args:
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
        tmp_path: Per-test directory for the row's tools directory and config file.
    """
    widget = ToolSettingsWidget("ghidra", "Ghidra", "Reverse engineering suite", tmp_path, config_path=tmp_path / "tools.json")
    try:
        widget._path_input.setText(sys.executable)
        widget._check_status()

        workers = bridge_workers_for(widget)
        assert len(workers) == _EXPECTED_WORKERS, f"expected one status worker for the tool row, found {len(workers)}"
        worker = workers[0]
        assert isinstance(worker, ToolStatusCheckWorker)
        assert worker.parent() is None, "the status worker is a Qt child of the tool row and dies with it"
        assert worker.owner() is widget, "the tool row is not the status worker's recorded owner"

        assert worker.wait(_WORKER_JOIN_MS), "the status check never finished"
        qtbot.waitUntil(lambda: widget.status_label.text() != _CHECKING_TEXT, timeout=_DELETE_WAIT_MS)

        assert widget.status_label.text() != _CHECKING_TEXT, "the status result never reached the tool row"
    finally:
        widget.deleteLater()


@pytest.mark.usefixtures("qapp")
def test_a_real_tool_status_result_is_dropped_when_the_row_is_deleted(qtbot: QtBot, tmp_path: Path) -> None:
    """A finished status check must not be delivered into a destroyed tool row.

    The row connects a closure to ``status_checked``, which is exactly the case Qt cannot clean up by itself: it delivers into the closure
    whatever happened to the widget. The check is joined first, so its result is sitting in the event queue, and only then is the row
    deleted. Delivering it would run ``_on_status_checked`` against freed labels and raise out of a Qt slot, which pytest-qt turns into a
    failure; the guard drops it instead. The gate above is the positive control that the same path does fire for a live row.

    Args:
        qtbot: pytest-qt bot, which fails the test on an exception raised inside the Qt event loop.
        tmp_path: Per-test directory for the row's tools directory and config file.
    """
    widget = ToolSettingsWidget("ghidra", "Ghidra", "Reverse engineering suite", tmp_path, config_path=tmp_path / "tools.json")
    widget._path_input.setText(sys.executable)
    widget._check_status()

    workers = bridge_workers_for(widget)
    assert len(workers) == _EXPECTED_WORKERS, f"expected one status worker for the tool row, found {len(workers)}"
    worker = workers[0]
    assert worker.wait(_WORKER_JOIN_MS), "the status check never finished"
    assert widget.status_label.text() == _CHECKING_TEXT, "the result was applied before the row could be deleted"

    _delete(widget, qtbot)
    QCoreApplication.processEvents()
    QCoreApplication.sendPostedEvents()

    assert not sip.isdeleted(worker), "deleting the tool row destroyed its worker"


@pytest.mark.usefixtures("qapp")
def test_the_real_requirements_probe_is_owned_by_its_dialog(qtbot: QtBot) -> None:
    """The XPU dialog's requirements probe must be owned by the dialog, not parented to it.

    Constructing the dialog dispatches the real probe, which walks this machine's actual accelerator and package state.

    Args:
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
    """
    dialog = XPUStatusDialog()
    try:
        workers = bridge_workers_for(dialog)
        assert len(workers) == _EXPECTED_WORKERS, f"expected one requirements worker for the dialog, found {len(workers)}"
        worker = workers[0]
        assert isinstance(worker, RetainedWorker)
        assert worker.parent() is None, "the requirements worker is a Qt child of the dialog and dies with it"
        assert worker.owner() is dialog, "the dialog is not the requirements worker's recorded owner"

        assert worker.wait(_WORKER_JOIN_MS), "the requirements probe never finished"
        qtbot.waitUntil(lambda: dialog._requirements_worker is None, timeout=_DELETE_WAIT_MS)
    finally:
        dialog.deleteLater()


@pytest.mark.usefixtures("qapp")
def test_the_real_log_tail_load_is_owned_by_its_reader(qtbot: QtBot, tmp_path: Path) -> None:
    """The log viewer's historical load must be owned by its reader and deliver the real records.

    Args:
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
        tmp_path: Per-test directory holding the real JSON-Lines log file.
    """
    log_path = tmp_path / "intellicrack.jsonl"
    lines = [json.dumps({"event": f"gate_record_{index}", "level": "info"}) for index in range(_LOG_RECORDS)]
    _ = log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reader = LogFileTailReader(log_path, max_initial_bytes=_TAIL_BYTES)
    loaded: list[int] = []
    reader.initial_load_complete.connect(loaded.append)
    try:
        reader.start()

        workers = bridge_workers_for(reader)
        assert len(workers) == _EXPECTED_WORKERS, f"expected one initial-load worker for the reader, found {len(workers)}"
        worker = workers[0]
        assert isinstance(worker, InitialLoadWorker)
        assert worker.parent() is None, "the initial-load worker is a Qt child of the reader"
        assert worker.owner() is reader, "the reader is not the initial-load worker's recorded owner"

        assert worker.wait(_WORKER_JOIN_MS), "the historical load never finished"
        qtbot.waitUntil(lambda: bool(loaded), timeout=_DELETE_WAIT_MS)

        assert loaded, "the historical load never reported an offset to the reader"
    finally:
        reader.stop()


_TESTS_ROOT: Final[Path] = Path(__file__).resolve().parents[1]


def _worker_positional_limits() -> dict[str, int | None]:
    """Return how many positional arguments each converted worker still accepts.

    Returns:
        dict[str, int | None]: Class name mapped to its positional limit, or ``None`` when the constructor takes ``*args``.
    """
    limits: dict[str, int | None] = {}
    positional = {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD}
    for _label, worker_cls in _WORKER_CONSTRUCTORS:
        parameters = list(inspect.signature(worker_cls.__init__).parameters.values())[1:]
        if any(parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters):
            limits[worker_cls.__name__] = None
        else:
            limits[worker_cls.__name__] = sum(1 for parameter in parameters if parameter.kind in positional)
    return limits


def _declared_arity(node: ast.ClassDef, inherited: int | None) -> int | None:
    """Return the positional limit a subclass imposes, falling back to the one it inherits.

    Args:
        node: Class definition of a test-local worker subclass.
        inherited: Positional limit of the base class.

    Returns:
        int | None: The subclass's own limit when it declares ``__init__``, otherwise ``inherited``; ``None`` means ``*args``.
    """
    for statement in node.body:
        if isinstance(statement, ast.FunctionDef) and statement.name == "__init__":
            if statement.args.vararg is not None:
                return None
            return len(statement.args.posonlyargs) + len(statement.args.args) - 1
    return inherited


def _overlong_worker_constructions(root: Path, limits: Mapping[str, int | None]) -> list[str]:
    """Find test call sites handing a converted worker more positional arguments than it accepts.

    Args:
        root: Directory scanned recursively for test modules.
        limits: Positional limit per worker class name, as :func:`_worker_positional_limits` reports it.

    Returns:
        list[str]: One ``<path>:<line> <class> ...`` description per offending call, empty when every call fits.
    """
    offenders: list[str] = []
    for path in sorted(root.rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        local: dict[str, int | None] = dict(limits)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for base in node.bases:
                    if isinstance(base, ast.Name) and base.id in local:
                        local[node.name] = _declared_arity(node, local[base.id])
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id not in local:
                continue
            limit = local[node.func.id]
            if limit is None or len(node.args) <= limit:
                continue
            root_parent = _TESTS_ROOT.parent
            location = path.relative_to(root_parent) if path.is_relative_to(root_parent) else path
            offenders.append(f"{location}:{node.lineno} {node.func.id} takes {limit} positional arguments, {len(node.args)} given")
    return offenders


def test_no_test_hands_a_converted_worker_a_positional_parent() -> None:
    """No test may construct a converted worker with more positional arguments than it declares.

    Removing ``parent`` from these constructors left every caller that passed a widget as the trailing positional argument raising
    ``TypeError`` on construction. Two such call sites reached CI and failed there; two more sat in files the suite aborts before
    reaching, so nothing reported them. The production side is already gated, and this is the mirror of it for the tests: restore a
    trailing positional widget at any of those call sites and this turns red, naming the file, the line and the arity.
    """
    offenders = _overlong_worker_constructions(_TESTS_ROOT, _worker_positional_limits())

    assert offenders == [], "tests construct workers with more positional arguments than the constructors accept:\n" + "\n".join(
        offenders,
    )
