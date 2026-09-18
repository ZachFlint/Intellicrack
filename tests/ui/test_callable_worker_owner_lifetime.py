# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates: a callable worker must outlive the widget that dispatched it.

Every ``GenericCallableWorker`` dispatch site used to hand the calling widget to the worker as its Qt parent. Qt destroys a parent's
children along with it, and destroying a ``QThread`` whose OS thread is still running aborts the process with a native access violation and
no Python traceback: exit 255 with nothing reported. Closing the hex editor during a full-file entropy scan, a signature scan or a long
pattern search did exactly that, as did closing the sandbox dialog while its ``taskkill`` was still running.

Dispatch now goes through :func:`run_callable_async`, which creates the worker unparented, records the widget as its owner so
:func:`drain_bridge_workers_for` still finds it, and wraps both callbacks in :func:`guarded_delivery` so a result arriving after the widget
is gone is dropped instead of raising out of a Qt slot. The same treatment reached the two sites that build their own worker (the strings
extractor and the process-region lister), whose callbacks capture the worker instance and so cannot be handed to the helper.

The gates below come in three layers:

* the dispatch helper, driven against a real HTTP request over a loopback socket the server holds open, so the worker is genuinely blocked
  mid-call when the widget is deleted,
* a source gate over the whole package, so no present or future site can quietly re-parent a worker,
* and the real widgets behind the longest-running scans - the hex editor's entropy scan, the statistics mixin's byte statistics and the
  strings extractor - driven against a real ``intellicrack_hexcore`` document.

The drop half is gated where it bites. PyQt breaks a connection itself when the slot is a bound method of a destroyed ``QObject``, so the
entropy scan's own handler would never have been called either way; the strings extractor connects a ``functools.partial`` that captures
its worker, which Qt happily delivers into, and that is the site whose late result the guard has to stop.
"""

from __future__ import annotations

import ast
import json
import socket
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

import httpx
import pytest
from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication, QEvent, QThread
from PyQt6.QtWidgets import QLabel, QTreeWidget, QWidget

import intellicrack
from intellicrack.ui.panels.async_bridge import (
    WORKER_DEFAULT_EXCEPTIONS,
    GenericCallableWorker,
    bridge_workers_for,
    drain_bridge_workers_for,
    run_callable_async,
    worker_is_running,
)
from intellicrack.ui.panels.hex_editor.sections import SectionsMixin, execute_strings_extraction
from intellicrack.ui.panels.hex_editor.statistics import StatisticsMixin
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget


if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import ModuleType

    from PyQt6.QtWidgets import QApplication
    from pytestqt.qtbot import QtBot


_SERVED_MARKER: Final[str] = "held-callable-call"
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
_DOCUMENT_BYTES: Final[bytes] = bytes(range(256)) * 4096
_CALL_EXCEPTIONS: Final[tuple[type[BaseException], ...]] = (*WORKER_DEFAULT_EXCEPTIONS, httpx.HTTPError)
_QTHREAD: Final[str] = "QThread"
_COMPUTING_TEXT: Final[str] = "Computing..."
_ENTROPY_UNITS: Final[str] = "bits/byte"
_UNIFORM_ENTROPY: Final[float] = 8.0
_ENTROPY_TOLERANCE: Final[float] = 0.01
_SCANNING_ROWS: Final[int] = 1
_STRINGS_MIN_LENGTH: Final[int] = 4
_STRINGS_MAX_RESULTS: Final[int] = 512


class _HeldResponseServer:
    """Loopback HTTP server that holds every request open until released.

    Attributes:
        connected: Set once a client has connected and sent its request.
        release: Set by the test to let the held response go out.
        responded: Set once a held response has actually been written back, proving the callable under test received a real result.
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
        self._thread: threading.Thread = threading.Thread(target=self._serve, name="held-callable-response-server", daemon=True)
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
    """Worker callback that records its payload and touches the widget it belongs to.

    Panel callbacks update their own widgets, so this one does too: reaching a deleted widget raises ``RuntimeError: wrapped C/C++ object
    ... has been deleted`` out of a Qt slot, which pytest-qt turns into a test failure. A guard that stops delivering is therefore visible
    twice over, in the empty payload list and in the absence of that raise.

    Attributes:
        payloads: Every payload delivered to this callback, in arrival order.
        threads: The thread each delivery ran on, captured at delivery time. Qt reports the current thread as optional, so a delivery
            whose thread cannot be identified is recorded as ``None`` rather than silently passing a thread assertion.
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
            payload: Result object or exception emitted by the worker.
        """
        self.payloads.append(payload)
        self.threads.append(QThread.currentThread())
        self._widget.setWindowTitle(f"delivered-{len(self.payloads)}")


class _StatisticsHarness(QWidget, StatisticsMixin):
    """Real ``StatisticsMixin`` consumer with the label surface its result path writes to.

    The mixin reads its optional widgets through ``getattr``, so only the entropy label is materialised: it is a real ``QLabel``, which is
    what makes a late delivery against a destroyed harness observable as a ``RuntimeError`` rather than a silent attribute write.
    """

    def __init__(self, document: object) -> None:
        """Wire the mixin's required attribute slots around a real document.

        Args:
            document: Real ``intellicrack_hexcore`` document the statistics path computes over.
        """
        QWidget.__init__(self)
        self._document = document
        self.document = document
        self._statistics_tree: QTreeWidget | None = None
        self._entropy_graph = None
        self._byte_dist_widget = None
        self._entropy_label: QLabel | None = QLabel(_COMPUTING_TEXT, self)
        self._null_pct_label: QLabel | None = None
        self._printable_pct_label: QLabel | None = None
        self._control_pct_label: QLabel | None = None
        self._high_pct_label: QLabel | None = None
        self._classification_label: QLabel | None = None
        self._statistics_worker: GenericCallableWorker | None = None
        self._digram_worker: GenericCallableWorker | None = None

    def update_statistics(self) -> None:
        """Invoke the mixin's statistics-update slot as a public test entry point."""
        self._update_statistics()

    def entropy_label(self) -> QLabel:
        """Return the entropy label the mixin's result path writes to.

        Returns:
            QLabel: The real label wired into the mixin's attribute slot.
        """
        label = self._entropy_label
        assert label is not None, "the harness must expose a real entropy label"
        return label


class _StringsHarness(QWidget, SectionsMixin):
    """Real ``SectionsMixin`` consumer with the strings tree its result path writes to.

    The tree is a real ``QTreeWidget`` child, so it dies with the harness: a late delivery that reaches ``_on_strings_ready`` raises
    ``RuntimeError`` on the first ``clear()`` instead of failing an assertion quietly.
    """

    def __init__(self, document: object) -> None:
        """Wire the mixin's strings slots around a real document.

        Args:
            document: Real ``intellicrack_hexcore`` document the extraction runs over.
        """
        QWidget.__init__(self)
        self._document = document
        self.document = document
        self._strings_tree: QTreeWidget | None = QTreeWidget(self)
        self._strings_worker: GenericCallableWorker | None = None

    def populate_strings(self) -> None:
        """Invoke the mixin's strings-population slot as a public test entry point."""
        self._populate_strings()

    def row_count(self) -> int:
        """Return the number of rows currently in the strings tree.

        Returns:
            int: Top-level row count, which is the single "(scanning...)" placeholder until a result is applied.
        """
        tree = self._strings_tree
        assert tree is not None, "the harness must expose a real strings tree"
        return tree.topLevelItemCount()


def _fetch_held(url: str) -> str:
    """Fetch ``url`` over a real HTTP connection and return the response body.

    This is the synchronous callable under dispatch: it blocks inside a real socket read for as long as the server withholds its response,
    which is what keeps the worker genuinely in flight while the test deletes its owner.

    Args:
        url: Loopback URL served by :class:`_HeldResponseServer`.

    Returns:
        str: The response body, which the server withholds until released.
    """
    response = httpx.get(url, timeout=_HTTP_TIMEOUT_S)
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


@pytest.fixture
def hexcore() -> ModuleType:
    """Provide the native hex-document backend the real-widget gates compute over.

    Returns:
        ModuleType: The imported ``intellicrack_hexcore`` extension module.
    """
    return pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")


def _single_worker(widget: QWidget) -> GenericCallableWorker:
    """Return the one retained callable worker that ``widget`` owns.

    Args:
        widget: The dispatching widget whose worker is wanted.

    Returns:
        GenericCallableWorker: The single worker owned by ``widget``.
    """
    workers = bridge_workers_for(widget)
    assert len(workers) == _EXPECTED_WORKERS, f"expected one retained worker for the dispatching widget, found {len(workers)}"
    worker = workers[0]
    assert isinstance(worker, GenericCallableWorker), f"the retained worker is a {type(worker).__name__}, not a GenericCallableWorker"
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


@dataclass(frozen=True)
class _WorkerClass:
    """One ``QThread``-derived class as the source gate sees it.

    Attributes:
        bases: Names of the class's immediate bases, as written.
        positional: Names of its ``__init__``'s positional parameters without ``self``, or ``None`` when it declares no ``__init__`` and
            therefore inherits one.
    """

    bases: tuple[str, ...]
    positional: tuple[str, ...] | None


def _base_names(node: ast.ClassDef) -> tuple[str, ...]:
    """Return the written names of a class's immediate bases.

    Args:
        node: Class definition from a parsed source file.

    Returns:
        tuple[str, ...]: Base names, with dotted bases reduced to their attribute (``QtCore.QThread`` becomes ``QThread``).
    """
    names: list[str] = []
    for base in node.bases:
        if isinstance(base, ast.Name):
            names.append(base.id)
        elif isinstance(base, ast.Attribute):
            names.append(base.attr)
    return tuple(names)


def _worker_classes(root: Path) -> dict[str, _WorkerClass]:
    """Collect every class under ``root`` that reaches ``QThread`` through its bases.

    Discovering the classes instead of listing them is what makes the gate cover workers that do not exist yet: a new ``QThread``
    subclass is picked up by the next run with no change here.

    Args:
        root: Package directory whose Python sources are parsed.

    Returns:
        dict[str, _WorkerClass]: Worker class names mapped to what the gate needs to know about their constructors.
    """
    found: dict[str, _WorkerClass] = {}
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            init = next((item for item in node.body if isinstance(item, ast.FunctionDef) and item.name == "__init__"), None)
            positional = tuple(arg.arg for arg in [*init.args.posonlyargs, *init.args.args][1:]) if init is not None else None
            found[node.name] = _WorkerClass(_base_names(node), positional)

    def _derives(name: str, seen: tuple[str, ...] = ()) -> bool:
        """Report whether ``name`` reaches ``QThread`` through the collected class graph.

        Args:
            name: Class name to resolve.
            seen: Names already visited on this path, guarding against a cycle.

        Returns:
            bool: True when the chain of bases ends at ``QThread``.
        """
        if name == _QTHREAD:
            return True
        if name in seen or name not in found:
            return False
        return any(_derives(base, (*seen, name)) for base in found[name].bases)

    return {name: info for name, info in found.items() if name != _QTHREAD and _derives(name)}


def _parent_slot(name: str, classes: dict[str, _WorkerClass]) -> int | None:
    """Return the positional index at which ``name``'s constructor takes a Qt parent.

    A class that declares its own ``__init__`` either names ``parent`` among its positional parameters or has no positional parent at
    all. A class that declares none inherits one, so the search walks its bases; falling off the end of the package means it inherits
    ``QThread.__init__``, whose first positional argument is the parent.

    Args:
        name: Worker class name.
        classes: The collected worker classes.

    Returns:
        int | None: Index of the parent argument, or ``None`` when the constructor cannot take one positionally.
    """
    seen: set[str] = set()
    current = name
    while current in classes and current not in seen:
        seen.add(current)
        positional = classes[current].positional
        if positional is not None:
            return positional.index("parent") if "parent" in positional else None
        current = next((base for base in classes[current].bases if base in classes), "")
    return 0


def _parented_worker_sites(root: Path) -> list[str]:
    """Find every worker construction under ``root`` that hands over a Qt parent.

    Args:
        root: Package directory whose Python sources are parsed.

    Returns:
        list[str]: One ``<path>:<line>`` description per offending construction, empty when every site is unparented.
    """
    classes = _worker_classes(root)
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
            if name is None or name not in classes:
                continue
            if any(keyword.arg == "parent" for keyword in node.keywords):
                offenders.append(f"{path}:{node.lineno} passes parent= to {name}")
            slot = _parent_slot(name, classes)
            if slot is not None and len(node.args) > slot:
                offenders.append(f"{path}:{node.lineno} passes a positional Qt parent to {name}")
    return offenders


@pytest.mark.usefixtures("qapp")
def test_the_dispatched_worker_is_not_parented_to_its_owner(qtbot: QtBot, held_server: _HeldResponseServer) -> None:
    """The dispatched worker must be unparented, with the widget recorded as its owner.

    This is the structural half of the crash fix, and the one behavioural gate that reports a clean failure rather than an aborted
    interpreter: a worker parented to the widget is destroyed with it, and Qt answers the destruction of a running ``QThread`` with an
    access violation.

    Args:
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
        held_server: Loopback endpoint holding the request open mid-call.
    """
    widget = QWidget()
    delivery = _Delivery(widget)

    run_callable_async(
        _fetch_held,
        held_server.url,
        on_success=delivery,
        on_error=delivery,
        parent=widget,
        exceptions=_CALL_EXCEPTIONS,
    )
    qtbot.waitUntil(held_server.connected.is_set, timeout=_CONNECT_WAIT_MS)

    worker = _single_worker(widget)
    assert worker.isRunning(), "the call finished before the worker's parentage could be inspected mid-flight"
    assert worker.parent() is None, "the callable worker is a Qt child of the dispatching widget, which destroys it mid-flight"
    assert worker.owner() is widget, "the dispatching widget was not recorded as the worker's owner"

    held_server.release.set()
    assert drain_bridge_workers_for(widget, _WORKER_JOIN_MS) == _EXPECTED_WORKERS


@pytest.mark.usefixtures("qapp")
def test_a_live_owner_receives_the_result_on_the_main_thread(
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

    run_callable_async(
        _fetch_held,
        held_server.url,
        on_success=delivery,
        on_error=delivery,
        parent=widget,
        exceptions=_CALL_EXCEPTIONS,
    )
    qtbot.waitUntil(lambda: bool(delivery.payloads), timeout=_CONNECT_WAIT_MS)

    assert len(delivery.payloads) == _EXPECTED_DELIVERIES, f"the result was delivered {len(delivery.payloads)} times"
    payload = delivery.payloads[0]
    assert isinstance(payload, str), f"the worker delivered a {type(payload).__name__} instead of the response body"
    assert _SERVED_MARKER in payload, f"the delivered body is not the served response: {payload!r}"
    delivered_thread = delivery.threads[0]
    assert delivered_thread is not None, "the delivering thread could not be identified"
    assert delivered_thread is qapp.thread(), "the result was delivered off the GUI thread"
    assert widget.windowTitle() == "delivered-1", "the callback did not run against the live widget"


@pytest.mark.usefixtures("qapp")
def test_drain_bridge_workers_for_joins_an_unparented_callable_worker(qtbot: QtBot, held_server: _HeldResponseServer) -> None:
    """A widget's scoped drain must still find and join the callable worker it dispatched.

    Unparenting the worker removes it from the widget's Qt subtree, so the scoped drain can only find it through the owner recorded on the
    worker. The request is released from a timer while the drain is blocked, so the drain has to do a real join: dropping the recorded
    owner leaves it nothing to wait for and it returns zero.

    Args:
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
        held_server: Loopback endpoint holding the request open mid-call.
    """
    widget = QWidget()
    delivery = _Delivery(widget)

    run_callable_async(
        _fetch_held,
        held_server.url,
        on_success=delivery,
        on_error=delivery,
        parent=widget,
        exceptions=_CALL_EXCEPTIONS,
    )
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


def test_no_dispatch_site_parents_its_worker_to_a_widget() -> None:
    """No worker construction anywhere in the package may take a Qt parent.

    The behavioural gates cover individual workers; this one covers every site at once. The gate discovers each class that reaches
    ``QThread`` through its bases - the two dispatch workers, the hand-rolled ones behind the tool installer, the sandbox test, the
    requirements probe, the tracked-process refresh, the log tail load and the provider model refresh and connection test - and requires
    every construction of them to leave the Qt parent unset and pass the widget as ``owner`` instead. A parented worker is destroyed with
    its widget and takes the process down with it when its thread is still running.

    Both ways of handing one over are covered: the ``parent=`` keyword, and a positional argument landing in a constructor's parent slot.
    Re-parenting any single site turns this red and names the file and line, and a worker class added later is covered without touching
    this test.
    """
    root = Path(str(intellicrack.__file__)).parent
    offenders = _parented_worker_sites(root)

    assert offenders == [], "worker dispatch sites still hand a Qt parent to a thread that can outlive it:\n" + "\n".join(offenders)


@pytest.mark.usefixtures("qapp")
def test_deleting_the_owner_mid_run_leaves_the_worker_running(qtbot: QtBot, held_server: _HeldResponseServer) -> None:
    """Deleting the widget mid-call must not touch the worker, and must drop its result.

    The crash gate. With the worker parented to the widget again, the ``deleteLater`` below destroys a ``QThread`` that is still blocked
    inside its request and the interpreter dies on a native access violation: exit 255, no traceback, nothing collected. With the fix the
    worker runs on, finishes normally once released, and its result is dropped instead of being delivered into freed memory.

    Args:
        qtbot: pytest-qt bot, which fails the test on an exception raised inside the Qt event loop -- including a late delivery reaching a
            destroyed widget.
        held_server: Loopback endpoint holding the request open until the widget is gone.
    """
    widget = QWidget()
    delivery = _Delivery(widget)

    run_callable_async(
        _fetch_held,
        held_server.url,
        on_success=delivery,
        on_error=delivery,
        parent=widget,
        exceptions=_CALL_EXCEPTIONS,
    )
    qtbot.waitUntil(held_server.connected.is_set, timeout=_CONNECT_WAIT_MS)
    worker = _single_worker(widget)
    assert worker.isRunning(), "the call finished before the widget could be deleted mid-request"

    _delete(widget, qtbot)

    assert not sip.isdeleted(worker), "deleting the widget destroyed its running worker thread"
    assert worker.isRunning(), "the worker stopped when its owner was deleted"
    assert bridge_workers_for(widget), "the deleted widget's in-flight worker can no longer be found for draining"

    held_server.release.set()
    assert worker.wait(_WORKER_JOIN_MS), "the worker never finished after its request was released"
    assert held_server.responded.wait(timeout=_RESPONDED_WAIT_S), "the server never answered, so no late result was ever there to drop"
    QCoreApplication.processEvents()
    QCoreApplication.sendPostedEvents()

    assert delivery.payloads == [], f"a result was delivered to a destroyed widget: {delivery.payloads!r}"


@pytest.mark.usefixtures("qapp")
def test_the_real_entropy_scan_is_owned_but_not_parented(qtbot: QtBot, hexcore: ModuleType) -> None:
    """The hex editor's entropy scan must be owned by the widget and deliver to it.

    Drives the real widget over a real ``intellicrack_hexcore`` document: the entropy cache is filled by a background scan of real bytes,
    dispatched from the widget's own minimap path. The worker must belong to the widget without being its child, and its result must still
    land in the widget's cache.

    Args:
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
        hexcore: The native hex-document backend.
    """
    document = hexcore.HexDocument.open_bytes(_DOCUMENT_BYTES)
    widget = HexEditorWidget()
    widget.set_document(document)

    _ = widget._ensure_entropy_cache()

    worker = _single_worker(widget)
    assert worker.owner() is widget, "the hex editor is not the entropy worker's recorded owner"
    assert worker.parent() is None, "the entropy worker is a Qt child of the hex editor; closing the editor mid-scan would destroy it"

    assert worker.wait(_WORKER_JOIN_MS), "the entropy scan never finished"
    qtbot.waitUntil(lambda: bool(widget._entropy_cache), timeout=_DELETE_WAIT_MS)

    assert widget._entropy_cache, "the entropy scan's result never reached the widget"
    widget.deleteLater()


@pytest.mark.usefixtures("qapp")
def test_a_real_strings_result_is_dropped_when_the_panel_is_deleted(qtbot: QtBot, hexcore: ModuleType) -> None:
    """A finished strings extraction must not be delivered into a destroyed panel.

    The strings extractor is the site the guard exists for: its callbacks are ``functools.partial`` objects capturing the worker, which Qt
    delivers into no matter what happened to the widget. The extraction is joined first, so its result is sitting in the event queue, and
    only then is the panel deleted. Delivering it would run ``_on_strings_ready`` against a freed ``QTreeWidget`` and raise out of a Qt
    slot, which pytest-qt turns into a failure; the guard drops it instead and the tree is never touched.

    Args:
        qtbot: pytest-qt bot, which fails the test on an exception raised inside the Qt event loop.
        hexcore: The native hex-document backend.
    """
    document = hexcore.HexDocument.open_bytes(_DOCUMENT_BYTES)
    extracted = execute_strings_extraction(document, _STRINGS_MIN_LENGTH, _STRINGS_MAX_RESULTS)
    assert isinstance(extracted, list), f"the real extractor returned a {type(extracted).__name__} instead of a list of records"
    assert extracted, "the document yields no strings, so a dropped delivery would have carried nothing"

    harness = _StringsHarness(document)
    harness.populate_strings()
    worker = _single_worker(harness)
    assert worker.owner() is harness, "the panel widget is not the strings worker's recorded owner"
    assert worker.parent() is None, "the strings worker is a Qt child of the panel widget and dies with it"
    assert worker.wait(_WORKER_JOIN_MS), "the strings extraction never finished"
    assert harness.row_count() == _SCANNING_ROWS, "the result was applied before the panel could be deleted, so nothing was left to drop"

    _delete(harness, qtbot)
    QCoreApplication.processEvents()
    QCoreApplication.sendPostedEvents()


@pytest.mark.usefixtures("qapp")
def test_a_real_strings_result_reaches_a_live_panel(qtbot: QtBot, hexcore: ModuleType) -> None:
    """A live panel must receive the strings extraction the guard would otherwise drop.

    The positive control for the gate above: the same real extraction over the same real document, delivered to a panel that is still
    alive, must replace the "(scanning...)" placeholder with real rows. Without it, a guard that dropped every delivery would look correct.

    Args:
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
        hexcore: The native hex-document backend.
    """
    document = hexcore.HexDocument.open_bytes(_DOCUMENT_BYTES)
    harness = _StringsHarness(document)
    try:
        harness.populate_strings()
        worker = _single_worker(harness)
        assert worker.wait(_WORKER_JOIN_MS), "the strings extraction never finished"
        qtbot.waitUntil(lambda: harness.row_count() != _SCANNING_ROWS, timeout=_DELETE_WAIT_MS)

        assert harness.row_count() > _SCANNING_ROWS, "the extracted strings never reached the panel's tree"
    finally:
        harness.deleteLater()


@pytest.mark.usefixtures("qapp")
def test_the_real_statistics_worker_is_owned_but_not_parented(qtbot: QtBot, hexcore: ModuleType) -> None:
    """The statistics mixin's worker must be owned by the panel widget and deliver to it.

    Drives the real ``StatisticsMixin`` slot over a real document, so the byte-statistics computation, the worker dispatch and the label
    update all run production code. The worker must belong to the harness widget without being its child, and the entropy label must leave
    its "Computing..." placeholder once the real result arrives.

    Args:
        qtbot: pytest-qt bot used to pump the Qt event loop while waiting.
        hexcore: The native hex-document backend.
    """
    document = hexcore.HexDocument.open_bytes(_DOCUMENT_BYTES)
    harness = _StatisticsHarness(document)
    try:
        harness.update_statistics()

        worker = _single_worker(harness)
        assert worker.owner() is harness, "the panel widget is not the statistics worker's recorded owner"
        assert worker.parent() is None, "the statistics worker is a Qt child of the panel widget and dies with it"

        assert worker.wait(_WORKER_JOIN_MS), "the statistics computation never finished"
        label = harness.entropy_label()
        qtbot.waitUntil(lambda: label.text() != _COMPUTING_TEXT, timeout=_DELETE_WAIT_MS)

        text = label.text()
        assert text.endswith(_ENTROPY_UNITS), f"the statistics result never reached the panel's labels: {text!r}"
        measured = float(text.removesuffix(_ENTROPY_UNITS).strip())
        assert abs(measured - _UNIFORM_ENTROPY) < _ENTROPY_TOLERANCE, (
            f"the label carries {measured} bits/byte for a uniform byte distribution, so the delivered result is not the real computation"
        )
    finally:
        harness.deleteLater()
