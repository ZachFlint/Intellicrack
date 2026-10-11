# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the analysis, transfer, VM-control, command, refresh and VNC handlers of ``SandboxPanel``.

Every end-to-end test drives a real ``SandboxPanel`` wired to a real ``SandboxBridge`` whose manager owns a real ``QEMUSandbox`` subclass
that never starts QEMU. The only scripted parts are the wire exchanges of the monitor and guest-agent clients, as in the QEMU sandbox
tests. Results come back through the shipped worker path, so the handlers receive exactly what the bridge produces. The shapes the
handlers must tolerate beyond that are fed to them directly. Expected values are written out by hand from the report fields, the dialog
answers and the RFB protocol, never recomputed with the code under test.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NamedTuple, cast, override

import pytest
from PyQt6.QtWidgets import QFileDialog, QInputDialog, QMessageBox, QTreeWidgetItem

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.sandbox.base import ExecutionReport, SandboxConfig
from intellicrack.sandbox.manager import AvailabilityCacheEntry
from intellicrack.sandbox.qemu import GuestAgentClient, GuestAgentMessage, QEMUConfig, QEMUSandbox, QMPClient, QMPResponse
from intellicrack.ui.panels.async_bridge import bridge_workers_for, drain_bridge_workers_for
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication, QPlainTextEdit, QTreeWidget
    from pytestqt.qtbot import QtBot

    from intellicrack.sandbox.base import FileChange, NetworkActivity, RegistryChange
    from intellicrack.sandbox.manager import SandboxInstance


pytestmark = pytest.mark.usefixtures("qapp")


_Dynamic = Any
_WAIT_MS: int = 20_000
_SERVER_TIMEOUT_S: float = 10.0
_RFB_GREETING: bytes = b"RFB 003.008\n"
_RFB_SECURITY_VNC_AUTH: int = 2
_RFB_CHALLENGE_LENGTH: int = 16
_RFB_AUTH_FAILED: bytes = b"\x00\x00\x00\x01"

_RUN_KEY: str = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
_GUARDED_SLOTS: list[str] = [
    "_on_detect_behaviors",
    "_on_copy_in",
    "_on_copy_out",
    "_on_continue_vm",
    "_on_pause_vm",
    "_on_delete_snapshot",
    "_on_execute_command",
]


class _Rig(NamedTuple):
    """A panel wired to a real bridge that owns one real, never-started QEMU sandbox.

    Attributes:
        panel: Panel with the sandbox controls active and QEMU selected.
        bridge: Real bridge attached to the panel.
        box: The registered sandbox.
        instance: The manager's record of the registered sandbox.
        shared: Host shared folder attached to the sandbox.
    """

    panel: SandboxPanel
    bridge: SandboxBridge
    box: _QemuBox
    instance: SandboxInstance
    shared: Path


def _arguments(command: dict[str, object]) -> dict[str, object]:
    """Return the ``arguments`` member of a monitor command as a mapping.

    Args:
        command: Command dictionary as the product built it.

    Returns:
        dict[str, object]: The arguments, or an empty mapping when there are none.
    """
    raw = command.get("arguments")
    return cast("dict[str, object]", raw) if isinstance(raw, dict) else {}


def _ok(data: object = None) -> QMPResponse:
    """Build a successful monitor reply.

    Args:
        data: The reply's ``return`` member.

    Returns:
        QMPResponse: A successful response carrying ``data``.
    """
    return QMPResponse(success=True, data=data)


def _refused(error: str | None) -> QMPResponse:
    """Build a failed monitor reply.

    Args:
        error: The monitor's error description, or None when it gave none.

    Returns:
        QMPResponse: A failed response carrying ``error``.
    """
    return QMPResponse(success=False, error=error)


def _run_state(*, running: bool) -> QMPResponse:
    """Build a ``query-status`` reply.

    Args:
        running: Whether the processors are executing.

    Returns:
        QMPResponse: A ``query-status`` answer.
    """
    return _ok({"running": running, "status": "running" if running else "restore-vm"})


def _block_report(*snapshot_names: str) -> list[object]:
    """Build a ``query-block`` reply with one writable qcow2 disk and one read-only CD.

    Args:
        *snapshot_names: Names of the internal snapshots the disk holds.

    Returns:
        list[object]: The ``return`` member of a ``query-block`` reply.
    """
    disk: dict[str, object] = {
        "device": "drive0",
        "inserted": {
            "drv": "qcow2",
            "ro": False,
            "node-name": "disk0",
            "image": {"snapshots": [{"name": name} for name in snapshot_names]},
        },
    }
    install_media: dict[str, object] = {
        "device": "cd0",
        "inserted": {"drv": "raw", "ro": True, "node-name": "cd0", "image": {"filename": "install.iso"}},
    }
    return [disk, install_media]


class _ScriptedQMP(QMPClient):
    """Real ``QMPClient`` whose wire exchange answers from a per-command script.

    Only ``_send_command`` is replaced. Each command name maps to a queue of replies; the last reply of a queue repeats once the queue is
    down to it. A ``query-jobs`` reply has its records stamped with the job id the most recent snapshot command carried, because the
    sandbox mints that id at random.
    """

    def __init__(self, script: Mapping[str, Sequence[QMPResponse]]) -> None:
        """Initialise the scripted monitor.

        Args:
            script: Replies per command name.
        """
        super().__init__()
        self._script: dict[str, list[QMPResponse]] = {name: list(replies) for name, replies in script.items()}
        self._job_id = ""
        self.sent: list[dict[str, object]] = []

    @property
    def commands(self) -> list[str]:
        """Names of the commands received so far, in order.

        Returns:
            list[str]: The ``execute`` value of every command sent.
        """
        return [str(command["execute"]) for command in self.sent]

    @override
    async def _send_command(self, command: dict[str, object], time_limit: float = 10.0) -> QMPResponse:
        """Record a command and answer it from the script.

        Args:
            command: Command dictionary with an ``execute`` key.
            time_limit: Ignored; the scripted exchange is immediate.

        Returns:
            QMPResponse: The next scripted reply for this command name.
        """
        del time_limit
        self.sent.append(command)
        name = str(command["execute"])
        job_id = _arguments(command).get("job-id")
        if isinstance(job_id, str):
            self._job_id = job_id
        queue = self._script[name]
        reply = queue.pop(0) if len(queue) > 1 else queue[0]
        if name == "query-jobs" and reply.success and isinstance(reply.data, list):
            records = cast("list[object]", reply.data)
            return _ok([{"id": self._job_id, **cast("dict[str, object]", record)} for record in records])
        return reply


class _ScriptedAgent(GuestAgentClient):
    """Real ``GuestAgentClient`` that reports itself connected and replies from a list."""

    def __init__(self, replies: Sequence[tuple[int, str, str]]) -> None:
        """Initialise the scripted agent.

        Args:
            replies: ``(exit_code, stdout, stderr)`` answers, the last one repeating.
        """
        super().__init__()
        self._replies = list(replies)
        self.calls: list[tuple[str, list[str]]] = []

    @property
    @override
    def is_connected(self) -> bool:
        """Report the agent as connected.

        Returns:
            bool: Always True.
        """
        return True

    @override
    async def send_command(
        self,
        command: str,
        args: Sequence[str] | None = None,
        time_limit: float = 30.0,
    ) -> tuple[int, str, str]:
        """Record a command and answer it from the list.

        Args:
            command: Executable the sandbox asked the guest to run.
            args: Its arguments.
            time_limit: Ignored; the scripted exchange is immediate.

        Returns:
            tuple[int, str, str]: The next scripted ``(exit_code, stdout, stderr)``.
        """
        del time_limit
        self.calls.append((command, list(args or [])))
        return self._replies.pop(0) if len(self._replies) > 1 else self._replies[0]


class _MessageAgent(GuestAgentClient):
    """Real ``GuestAgentClient`` whose pending-message queue can be filled without a guest."""

    def enqueue(self, message: GuestAgentMessage) -> None:
        """Queue a message the way the reader would after decoding a line from the guest.

        Args:
            message: Message to queue.
        """
        self._message_queue.put_nowait(message)


class _QemuBox(QEMUSandbox):
    """Real ``QEMUSandbox`` that accepts its monitor, agent, share and VNC port without starting QEMU."""

    def attach_qmp(self, qmp: QMPClient | None) -> None:
        """Set the monitor client.

        Args:
            qmp: Monitor client to install, or None for none.
        """
        self._qmp = qmp

    def attach_agent(self, agent: GuestAgentClient | None) -> None:
        """Set the Intellicrack guest-agent client.

        Args:
            agent: Agent client to install, or None for none.
        """
        self._agent = agent

    def attach_shared_folder(self, folder: Path | None) -> None:
        """Set the host shared folder.

        Args:
            folder: Host shared folder, or None for none.
        """
        self._shared_folder = folder

    def attach_vnc_port(self, port: int | None) -> None:
        """Set the VNC port the sandbox reports.

        Args:
            port: VNC port, or None for none.
        """
        self._vnc_port = port


class _AuthProbeServer:
    """Loopback RFB server that records whether a client answers with VNC Authentication.

    It greets with the RFB 3.8 version string, offers exactly one security type (VNC Authentication), and then reports what the client
    chose and how many response bytes followed a 16-byte challenge. It rejects the response so the client's handshake ends.

    Attributes:
        port: Loopback port the server listens on.
        selected: The byte the client sent to pick a security type, empty when none arrived.
        response_length: Number of bytes the client sent in answer to the challenge.
        finished: Set once the single connection has been served or abandoned.
    """

    port: int
    selected: bytes
    response_length: int
    finished: threading.Event

    def __init__(self) -> None:
        """Bind a loopback listener on a free port and start serving one connection."""
        self.selected = b""
        self.response_length = 0
        self.finished = threading.Event()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(_SERVER_TIMEOUT_S)
        self.port = int(self._listener.getsockname()[1])
        self._thread = threading.Thread(target=self._serve, name="rfb-auth-probe", daemon=True)
        self._thread.start()

    @staticmethod
    def _read_exactly(connection: socket.socket, count: int) -> bytes:
        """Read exactly ``count`` bytes from a connection.

        Args:
            connection: Connected socket.
            count: Number of bytes to read.

        Returns:
            bytes: The bytes read.

        Raises:
            ConnectionError: If the peer closes before ``count`` bytes arrive.
        """
        received = b""
        while len(received) < count:
            chunk = connection.recv(count - len(received))
            if not chunk:
                message = "peer closed the connection early"
                raise ConnectionError(message)
            received += chunk
        return received

    def _serve(self) -> None:
        """Serve one connection and record what the client sent."""
        try:
            connection, _ = self._listener.accept()
        except OSError:
            self.finished.set()
            return
        try:
            with connection, contextlib.suppress(OSError):
                connection.settimeout(_SERVER_TIMEOUT_S)
                connection.sendall(_RFB_GREETING)
                self._read_exactly(connection, len(_RFB_GREETING))
                connection.sendall(bytes([1, _RFB_SECURITY_VNC_AUTH]))
                self.selected = connection.recv(1)
                if self.selected == bytes([_RFB_SECURITY_VNC_AUTH]):
                    connection.sendall(bytes(range(_RFB_CHALLENGE_LENGTH)))
                    self.response_length = len(self._read_exactly(connection, _RFB_CHALLENGE_LENGTH))
                    connection.sendall(_RFB_AUTH_FAILED)
        finally:
            self.finished.set()

    def close(self) -> None:
        """Close the listener and join the serving thread."""
        self._listener.close()
        self._thread.join(timeout=_SERVER_TIMEOUT_S)


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _set_priv(obj: object, name: str, value: object) -> None:
    """Assign a private data attribute on a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        value: Value to store.
    """
    setattr(obj, name, value)


def _call(panel: SandboxPanel, name: str, *args: object, **kwargs: object) -> None:
    """Call a panel slot or handler by name.

    Args:
        panel: Panel that owns the method.
        name: Method name.
        *args: Positional arguments for the method.
        **kwargs: Keyword arguments for the method.
    """
    method: Callable[..., object] = getattr(panel, name)
    method(*args, **kwargs)


def _console(panel: SandboxPanel) -> str:
    """Return the panel's console text.

    Args:
        panel: Panel to read.

    Returns:
        str: The whole console contents.
    """
    console: QPlainTextEdit = _priv(panel, "_console_output")
    return console.toPlainText()


def _tree(panel: SandboxPanel, name: str) -> QTreeWidget:
    """Return one of the panel's result trees.

    Args:
        panel: Panel to read.
        name: Attribute name of the tree.

    Returns:
        QTreeWidget: The tree.
    """
    tree: QTreeWidget = _priv(panel, name)
    return tree


def _rows(tree: QTreeWidget) -> list[list[str]]:
    """Read every top-level row of a tree as a list of column texts.

    Args:
        tree: Tree to read.

    Returns:
        list[list[str]]: One list of column texts per top-level row.
    """
    rows: list[list[str]] = []
    for index in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(index)
        assert item is not None
        rows.append([item.text(column) for column in range(tree.columnCount())])
    return rows


def _wait_console(qtbot: QtBot, panel: SandboxPanel, text: str) -> None:
    """Wait until the console shows a line.

    Args:
        qtbot: Qt test helper that pumps events while waiting.
        panel: Panel whose console is watched.
        text: Text that must appear.
    """
    qtbot.waitUntil(lambda: text in _console(panel), timeout=_WAIT_MS)


def _instance_by_id(bridge: SandboxBridge, instance_id: str) -> SandboxInstance:
    """Look an instance up in the bridge's manager.

    Args:
        bridge: Bridge whose manager owns the instance.
        instance_id: Identifier to find.

    Returns:
        SandboxInstance: The matching instance.
    """
    manager = bridge.manager
    assert manager is not None
    return next(instance for instance in manager.instances if instance.id == instance_id)


def _report(
    *,
    exit_code: int = 0,
    duration: float = 1.0,
    file_changes: list[FileChange] | None = None,
    registry_changes: list[RegistryChange] | None = None,
    network_activity: list[NetworkActivity] | None = None,
) -> ExecutionReport:
    """Build an execution report with only the streams a test names.

    Args:
        exit_code: Process exit code.
        duration: Run time in seconds.
        file_changes: File changes to record.
        registry_changes: Registry changes to record.
        network_activity: Network activity to record.

    Returns:
        ExecutionReport: A successful report.
    """
    return ExecutionReport(
        result="success",
        exit_code=exit_code,
        stdout="",
        stderr="",
        duration_seconds=duration,
        file_changes=file_changes or [],
        registry_changes=registry_changes or [],
        network_activity=network_activity or [],
    )


def _answer_open(path: str) -> Callable[..., tuple[str, str]]:
    """Build a replacement for ``QFileDialog.getOpenFileName`` that picks a fixed path.

    Args:
        path: Path the user picks, or an empty string for cancel.

    Returns:
        Callable[..., tuple[str, str]]: A function with the static method's call shape.
    """

    def _answer(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Return the chosen path and an empty filter.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, str]: The path and an empty selected filter.
        """
        return (path, "")

    return _answer


def _answer_text(text: str, *, accepted: bool) -> Callable[..., tuple[str, bool]]:
    """Build a replacement for ``QInputDialog.getText`` that answers fixed text.

    Args:
        text: Text the user types.
        accepted: Whether the user confirms the dialog.

    Returns:
        Callable[..., tuple[str, bool]]: A function with the static method's call shape.
    """

    def _answer(*_args: object, **_kwargs: object) -> tuple[str, bool]:
        """Return the typed text and the confirmation flag.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, bool]: The text and whether the dialog was accepted.
        """
        return (text, accepted)

    return _answer


@pytest.fixture
def error_dialogs(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Record the error dialogs the panel raises instead of opening them.

    Args:
        monkeypatch: Fixture that swaps Qt's static critical-message function for a recorder.

    Returns:
        list[tuple[str, str]]: ``(title, text)`` pairs in the order the dialogs were requested.
    """
    shown: list[tuple[str, str]] = []

    def _record(_parent: object, title: str, text: str, *_rest: object, **_kwargs: object) -> QMessageBox.StandardButton:
        """Record one requested dialog and answer it.

        Args:
            _parent: Ignored dialog parent.
            title: Dialog window title.
            text: Dialog body text.
            *_rest: Ignored extra arguments.
            **_kwargs: Ignored extra keyword arguments.

        Returns:
            QMessageBox.StandardButton: The OK button.
        """
        shown.append((title, text))
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "critical", _record)
    return shown


@pytest.fixture
def rig(qapp: QApplication, tmp_path: Path) -> Iterator[_Rig]:
    """Wire a panel to a real bridge that owns a real, never-started QEMU sandbox.

    Args:
        qapp: Session application, which must exist before a panel is built.
        tmp_path: Pytest temporary directory that holds the sandbox's shared folder.

    Yields:
        _Rig: The panel, bridge, sandbox, instance record and shared folder.
    """
    del qapp
    shared = tmp_path / "shared"
    (shared / "input").mkdir(parents=True)
    (shared / "output").mkdir()
    box = _QemuBox(SandboxConfig(), QEMUConfig())
    box.attach_shared_folder(shared)
    panel = SandboxPanel()
    panel.sandbox_type_combo.setCurrentText("QEMU")
    panel.set_sandbox(box)
    bridge = panel.get_bridge()
    assert bridge is not None
    manager = bridge.manager
    assert manager is not None
    manager.availability_cache["windows"] = AvailabilityCacheEntry(available=False)
    manager.availability_cache["qemu"] = AvailabilityCacheEntry(available=False)
    assert panel.sandbox_id is not None
    instance = _instance_by_id(bridge, panel.sandbox_id)
    _call(panel, "_set_sandbox_controls_active", active=True)
    try:
        yield _Rig(panel=panel, bridge=bridge, box=box, instance=instance, shared=shared)
    finally:
        drain_bridge_workers_for(panel)
        panel.close()


@pytest.mark.parametrize("slot", _GUARDED_SLOTS)
@pytest.mark.parametrize(("has_bridge", "has_instance"), [(False, False), (True, False), (False, True)])
def test_slot_without_bridge_or_instance_does_nothing(*, slot: str, has_bridge: bool, has_instance: bool) -> None:
    """A slot reached without a bridge or without an instance must return before doing any work.

    Args:
        slot: Name of the panel slot a toolbar button triggers.
        has_bridge: Whether a real bridge is attached.
        has_instance: Whether the panel holds a sandbox id.
    """
    panel = SandboxPanel()
    if has_bridge:
        panel.set_bridge(SandboxBridge())
    if has_instance:
        panel.sandbox_id = "sbx-none"
    _priv(panel, "_cmd_input").setText("echo hi")
    before = _console(panel)

    _call(panel, slot)

    assert _console(panel) == before
    assert bridge_workers_for(panel) == []


def test_diff_without_a_bridge_reports_it(error_dialogs: list[tuple[str, str]]) -> None:
    """Comparing instances with no bridge attached must say so on the console and raise no dialog.

    Args:
        error_dialogs: Recorder for any error dialog the panel would raise.
    """
    panel = SandboxPanel()

    _call(panel, "_on_diff")

    assert "[!] No sandbox bridge configured" in _console(panel)
    assert error_dialogs == []
    assert not _priv(panel, "_diff_btn").isEnabled()


def test_timeline_slot_fills_the_tree_from_the_bridge_report(rig: _Rig, qtbot: QtBot) -> None:
    """The Timeline slot must show the bridge's merged, time-ordered events and drop stale rows.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    rig.instance.last_report = _report(
        file_changes=[
            {
                "path": "C:\\drop\\late.bin",
                "operation": "created",
                "old_path": None,
                "timestamp": "2026-07-01T00:00:02",
                "size": 10,
            },
        ],
        registry_changes=[
            {
                "key": "HKCU\\Software\\Demo",
                "value_name": "Flag",
                "operation": "modified",
                "value_type": "REG_SZ",
                "value_data": "1",
                "timestamp": "2026-07-01T00:00:01",
            },
        ],
    )
    tree = _tree(rig.panel, "_timeline_tree")
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "stale", "stale"]))
    button = _priv(rig.panel, "timeline_btn")
    assert button.isEnabled()

    _call(rig.panel, "_on_timeline")

    assert not button.isEnabled()
    _wait_console(qtbot, rig.panel, "[+] Timeline generated: 2 events")
    assert _rows(tree) == [
        ["2026-07-01T00:00:01", "registry", "Registry modified: HKCU\\Software\\Demo\\Flag"],
        ["2026-07-01T00:00:02", "file", "File created: C:\\drop\\late.bin"],
    ]
    assert button.isEnabled()


def test_timeline_failure_raises_a_dialog_and_restores_the_button(
    rig: _Rig,
    qtbot: QtBot,
    error_dialogs: list[tuple[str, str]],
) -> None:
    """A timeline requested before any report exists must surface the bridge's error and re-enable the button.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
        error_dialogs: Recorder for the error dialog.
    """
    _call(rig.panel, "_on_timeline")

    _wait_console(qtbot, rig.panel, "[-] Timeline generation failed: ")
    assert "No execution report available for this instance" in _console(rig.panel)
    assert len(error_dialogs) == 1
    title, text = error_dialogs[0]
    assert title == "Timeline Generation Failed"
    assert text.startswith("Timeline generation failed:\n\n")
    assert "No execution report available for this instance" in text
    assert _priv(rig.panel, "timeline_btn").isEnabled()


@pytest.mark.parametrize(
    ("payload", "expected_rows"),
    [
        ("not a dict", []),
        ({"events": "not a list"}, []),
        (
            {"events": [{"timestamp": "t1", "category": "file", "summary": "wrote x"}, "skipped", 7, {"timestamp": "t2"}]},
            [["t1", "file", "wrote x"], ["t2", "", ""]],
        ),
    ],
    ids=["non-dict-result", "events-not-a-list", "non-dict-events-skipped"],
)
def test_timeline_success_tolerates_unexpected_payload_shapes(payload: object, expected_rows: list[list[str]]) -> None:
    """The timeline handler must ignore what is not an event record and still report the count of rows it built.

    Args:
        payload: Result handed to the success handler.
        expected_rows: Rows the tree must hold afterwards.
    """
    panel = SandboxPanel()
    tree = _tree(panel, "_timeline_tree")
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "stale", "stale"]))

    _call(panel, "_on_timeline_success", payload)

    assert _rows(tree) == expected_rows
    assert f"[+] Timeline generated: {len(expected_rows)} events" in _console(panel)


def _run_behavior_detection(rig: _Rig, qtbot: QtBot) -> list[list[str]]:
    """Run the Behaviors slot against a report with one registry Run-key write and return the rows it produced.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.

    Returns:
        list[list[str]]: The Behaviors tree rows after detection finished.
    """
    rig.instance.last_report = _report(
        registry_changes=[
            {
                "key": _RUN_KEY,
                "value_name": "Updater",
                "operation": "created",
                "value_type": "REG_SZ",
                "value_data": "C:\\drop\\late.bin",
                "timestamp": "2026-07-01T00:00:01",
            },
        ],
    )
    button = _priv(rig.panel, "behaviors_btn")
    assert button.isEnabled()

    _call(rig.panel, "_on_detect_behaviors")

    assert not button.isEnabled()
    _wait_console(qtbot, rig.panel, "[+] Behavior detection complete: ")
    assert button.isEnabled()
    return _rows(_tree(rig.panel, "_behaviors_tree"))


def test_behavior_detection_fills_category_severity_and_description(rig: _Rig, qtbot: QtBot) -> None:
    """A Run-key write must appear in the Behaviors tab with its category, severity and description.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    rows = _run_behavior_detection(rig, qtbot)

    matching = [row for row in rows if row[4] == f"Registry Run key modification: {_RUN_KEY}"]
    assert len(matching) == 1
    assert matching[0][1] == "Persistence"
    assert matching[0][2] == "high"
    assert f"[+] Behavior detection complete: {len(rows)} signatures matched" in _console(rig.panel)


def test_behavior_detection_shows_signature_name_and_mitre_id(rig: _Rig, qtbot: QtBot) -> None:
    """The Signature and MITRE columns must carry the bridge's signature name and ATT&CK id.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    rows = _run_behavior_detection(rig, qtbot)

    matching = [row for row in rows if row[4] == f"Registry Run key modification: {_RUN_KEY}"]
    assert len(matching) == 1
    assert matching[0][0] == "Run Key Persistence"
    assert matching[0][3] == "T1547"


def test_behavior_detection_failure_raises_a_dialog(rig: _Rig, qtbot: QtBot, error_dialogs: list[tuple[str, str]]) -> None:
    """Detection requested before any report exists must surface the bridge's error and re-enable the button.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
        error_dialogs: Recorder for the error dialog.
    """
    _call(rig.panel, "_on_detect_behaviors")

    _wait_console(qtbot, rig.panel, "[-] Behavior detection failed: ")
    assert [title for title, _ in error_dialogs] == ["Behavior Detection Failed"]
    assert "No execution report available for this instance" in error_dialogs[0][1]
    assert _priv(rig.panel, "behaviors_btn").isEnabled()


@pytest.mark.parametrize(
    ("payload", "expected_rows"),
    [
        (None, []),
        ({"matches": "not a list"}, []),
        (
            {"matches": [{"category": "Persistence", "severity": "low", "description": "d"}, "skipped", 3]},
            [["", "Persistence", "low", "", "d"]],
        ),
    ],
    ids=["non-dict-result", "matches-not-a-list", "non-dict-matches-skipped"],
)
def test_behavior_success_tolerates_unexpected_payload_shapes(payload: object, expected_rows: list[list[str]]) -> None:
    """The behavior handler must skip what is not a match record and report how many rows it built.

    Args:
        payload: Result handed to the success handler.
        expected_rows: Rows the tree must hold afterwards.
    """
    panel = SandboxPanel()
    tree = _tree(panel, "_behaviors_tree")
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "", "", "", ""]))

    _call(panel, "_on_detect_behaviors_success", payload)

    assert _rows(tree) == expected_rows
    assert f"[+] Behavior detection complete: {len(expected_rows)} signatures matched" in _console(panel)


@pytest.mark.parametrize(
    ("source", "destination", "accepted"),
    [
        ("", "C:\\guest\\a.bin", True),
        ("C:\\host\\sample.bin", "", False),
        ("C:\\host\\sample.bin", "C:\\guest\\a.bin", False),
        ("C:\\host\\sample.bin", "", True),
    ],
    ids=["no-source", "dest-cancelled-empty", "dest-cancelled-with-text", "dest-accepted-empty"],
)
def test_copy_in_cancelled_dialogs_dispatch_nothing(
    *,
    rig: _Rig,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    destination: str,
    accepted: bool,
) -> None:
    """Cancelling either prompt of Copy Into Sandbox must leave the panel untouched and start no transfer.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        monkeypatch: Fixture that swaps the Qt dialogs for fixed answers.
        source: Path the file dialog answers.
        destination: Text the input dialog answers.
        accepted: Whether the input dialog is confirmed.
    """
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _answer_open(source))
    monkeypatch.setattr(QInputDialog, "getText", _answer_text(destination, accepted=accepted))
    before = _console(rig.panel)

    _call(rig.panel, "_on_copy_in")

    assert _console(rig.panel) == before
    assert not _priv(rig.panel, "_pending_copy_in_source")
    assert not _priv(rig.panel, "_pending_copy_in_dest")
    assert _priv(rig.panel, "copy_in_btn").isEnabled()
    assert bridge_workers_for(rig.panel) == []


def test_copy_in_stages_the_file_in_the_shared_folder(rig: _Rig, qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Copy Into Sandbox must send the chosen file to the chosen path and report both on the console.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
        tmp_path: Pytest temporary directory that holds the host file.
        monkeypatch: Fixture that swaps the Qt dialogs for fixed answers.
    """
    payload = b"MZ\x90\x00 sample bytes"
    host_file = tmp_path / "sample.bin"
    host_file.write_bytes(payload)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _answer_open(str(host_file)))
    monkeypatch.setattr(QInputDialog, "getText", _answer_text("input/sample.bin", accepted=True))
    button = _priv(rig.panel, "copy_in_btn")

    _call(rig.panel, "_on_copy_in")

    assert not button.isEnabled()
    assert _priv(rig.panel, "_pending_copy_in_source") == str(host_file)
    assert _priv(rig.panel, "_pending_copy_in_dest") == "input/sample.bin"
    _wait_console(qtbot, rig.panel, f"[+] Copied into sandbox: {host_file} -> input/sample.bin")
    assert (rig.shared / "input" / "sample.bin").read_bytes() == payload
    assert button.isEnabled()


@pytest.mark.parametrize(
    ("sandbox_path", "accepted", "destination"),
    [
        ("", True, "C:\\host\\out.bin"),
        ("output/result.bin", False, "C:\\host\\out.bin"),
        ("output/result.bin", True, ""),
    ],
    ids=["empty-path", "path-cancelled", "no-destination"],
)
def test_copy_out_cancelled_dialogs_dispatch_nothing(
    *,
    rig: _Rig,
    monkeypatch: pytest.MonkeyPatch,
    sandbox_path: str,
    accepted: bool,
    destination: str,
) -> None:
    """Cancelling either prompt of Copy From Sandbox must leave the panel untouched and start no transfer.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        monkeypatch: Fixture that swaps the Qt dialogs for fixed answers.
        sandbox_path: Text the input dialog answers.
        accepted: Whether the input dialog is confirmed.
        destination: Path the save dialog answers.
    """
    monkeypatch.setattr(QInputDialog, "getText", _answer_text(sandbox_path, accepted=accepted))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _answer_open(destination))
    before = _console(rig.panel)

    _call(rig.panel, "_on_copy_out")

    assert _console(rig.panel) == before
    assert not _priv(rig.panel, "_pending_copy_out_source")
    assert not _priv(rig.panel, "_pending_copy_out_dest")
    assert _priv(rig.panel, "copy_out_btn").isEnabled()
    assert bridge_workers_for(rig.panel) == []


def test_copy_out_fetches_the_file_from_the_shared_folder(rig: _Rig, qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Copy From Sandbox must write the chosen sandbox file to the chosen host path and report both on the console.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
        tmp_path: Pytest temporary directory that receives the file.
        monkeypatch: Fixture that swaps the Qt dialogs for fixed answers.
    """
    payload = b"result bytes \x00\x01\x02"
    (rig.shared / "output" / "result.bin").write_bytes(payload)
    destination = tmp_path / "fetched" / "result.bin"
    monkeypatch.setattr(QInputDialog, "getText", _answer_text("output/result.bin", accepted=True))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _answer_open(str(destination)))
    button = _priv(rig.panel, "copy_out_btn")

    _call(rig.panel, "_on_copy_out")

    assert not button.isEnabled()
    assert _priv(rig.panel, "_pending_copy_out_source") == "output/result.bin"
    assert _priv(rig.panel, "_pending_copy_out_dest") == str(destination)
    _wait_console(qtbot, rig.panel, f"[+] Copied from sandbox: output/result.bin -> {destination}")
    assert destination.read_bytes() == payload
    assert button.isEnabled()


def test_copy_out_of_a_missing_file_raises_a_dialog(
    rig: _Rig,
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_dialogs: list[tuple[str, str]],
) -> None:
    """A sandbox path that does not exist must come back as an error dialog and leave the button usable.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
        tmp_path: Pytest temporary directory named as the destination.
        monkeypatch: Fixture that swaps the Qt dialogs for fixed answers.
        error_dialogs: Recorder for the error dialog.
    """
    destination = tmp_path / "never.bin"
    monkeypatch.setattr(QInputDialog, "getText", _answer_text("output/missing.bin", accepted=True))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", _answer_open(str(destination)))

    _call(rig.panel, "_on_copy_out")

    _wait_console(qtbot, rig.panel, "[-] Copy from sandbox failed: ")
    assert [title for title, _ in error_dialogs] == ["Copy From Sandbox Failed"]
    assert not destination.exists()
    assert _priv(rig.panel, "copy_out_btn").isEnabled()


def test_continue_resumes_the_vm_through_the_monitor(rig: _Rig, qtbot: QtBot) -> None:
    """Continue must send the monitor's ``cont`` command and report the resumed VM.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    qmp = _ScriptedQMP({"cont": [_ok({})]})
    rig.box.attach_qmp(qmp)
    button = _priv(rig.panel, "continue_btn")
    assert button.isEnabled()

    _call(rig.panel, "_on_continue_vm")

    assert not button.isEnabled()
    _wait_console(qtbot, rig.panel, "[+] VM execution resumed")
    assert qmp.commands == ["cont"]
    assert button.isEnabled()


def test_continue_without_a_monitor_raises_a_dialog(rig: _Rig, qtbot: QtBot, error_dialogs: list[tuple[str, str]]) -> None:
    """Continue on a sandbox with no monitor connection must surface the bridge's error and re-enable the button.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
        error_dialogs: Recorder for the error dialog.
    """
    _call(rig.panel, "_on_continue_vm")

    _wait_console(qtbot, rig.panel, "[-] VM continue failed: ")
    assert [title for title, _ in error_dialogs] == ["VM Continue Failed"]
    assert "Failed to resume VM execution: QMP client not connected" in error_dialogs[0][1]
    assert _priv(rig.panel, "continue_btn").isEnabled()


def test_pause_stops_the_vm_through_the_monitor(rig: _Rig, qtbot: QtBot) -> None:
    """Pause must send the monitor's ``stop`` command and report the paused VM.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    qmp = _ScriptedQMP({"stop": [_ok({})]})
    rig.box.attach_qmp(qmp)
    button = _priv(rig.panel, "pause_btn")
    assert button.isEnabled()

    _call(rig.panel, "_on_pause_vm")

    assert not button.isEnabled()
    _wait_console(qtbot, rig.panel, "[+] VM execution paused")
    assert qmp.commands == ["stop"]
    assert button.isEnabled()


def test_delete_snapshot_without_a_selection_logs_and_dispatches_nothing(rig: _Rig) -> None:
    """Delete Snapshot with no row selected must say so and send nothing to the sandbox.

    Args:
        rig: Panel wired to a real bridge and sandbox.
    """
    _call(rig.panel, "_on_delete_snapshot")

    assert "[!] No snapshot selected for deletion" in _console(rig.panel)
    assert bridge_workers_for(rig.panel) == []
    assert _priv(rig.panel, "delete_snap_btn").isEnabled()


def test_delete_snapshot_removes_the_selected_row_after_the_job_finishes(rig: _Rig, qtbot: QtBot) -> None:
    """Delete Snapshot must run the sandbox's delete job for the selected tag and drop only that row.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    qmp = _ScriptedQMP({
        "query-block": [_ok(_block_report("clean")), _ok(_block_report("clean")), _ok(_block_report())],
        "query-status": [_run_state(running=True)],
        "snapshot-delete": [_ok({})],
        "query-jobs": [_ok([{"status": "concluded"}])],
        "job-dismiss": [_ok({})],
    })
    rig.box.attach_qmp(qmp)
    tree = _tree(rig.panel, "_snapshots_tree")
    other = QTreeWidgetItem(["other", "other", ""])
    clean = QTreeWidgetItem(["clean", "clean", ""])
    tree.addTopLevelItem(other)
    tree.addTopLevelItem(clean)
    tree.setCurrentItem(clean)
    button = _priv(rig.panel, "delete_snap_btn")
    assert button.isEnabled()

    _call(rig.panel, "_on_delete_snapshot")

    assert not button.isEnabled()
    assert _priv(rig.panel, "_pending_snapshot_id") == "clean"
    _wait_console(qtbot, rig.panel, "[+] Snapshot deleted: clean")
    assert _rows(tree) == [["other", "other", ""]]
    assert qmp.commands == ["query-block", "query-block", "query-status", "snapshot-delete", "query-jobs", "job-dismiss", "query-block"]
    assert button.isEnabled()


def test_delete_snapshot_success_for_a_row_that_is_gone_leaves_the_tree_alone() -> None:
    """A completed delete whose row is no longer listed must report the deletion and keep every other row."""
    panel = SandboxPanel()
    tree = _tree(panel, "_snapshots_tree")
    tree.addTopLevelItem(QTreeWidgetItem(["keep", "keep", ""]))
    _set_priv(panel, "_pending_snapshot_id", "gone")

    _call(panel, "_on_delete_snapshot_success", None)

    assert _rows(tree) == [["keep", "keep", ""]]
    assert "[+] Snapshot deleted: gone" in _console(panel)


def test_execute_with_a_blank_command_logs_and_dispatches_nothing(rig: _Rig) -> None:
    """Execute with only whitespace typed must say no command was given and send nothing.

    Args:
        rig: Panel wired to a real bridge and sandbox.
    """
    _priv(rig.panel, "_cmd_input").setText("   ")

    _call(rig.panel, "_on_execute_command")

    assert "[!] No command specified" in _console(rig.panel)
    assert bridge_workers_for(rig.panel) == []
    assert _priv(rig.panel, "_exec_cmd_btn").isEnabled()


def test_execute_runs_the_trimmed_command_and_shows_its_output(rig: _Rig, qtbot: QtBot) -> None:
    """Execute must forward the trimmed command to the guest and print its exit code, stdout and stderr.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    agent = _ScriptedAgent([(3, "hello", "oops")])
    rig.box.attach_agent(agent)
    rig.box.state.status = "running"
    _priv(rig.panel, "_cmd_input").setText("  echo hi  ")
    button = _priv(rig.panel, "_exec_cmd_btn")
    assert button.isEnabled()

    _call(rig.panel, "_on_execute_command")

    assert not button.isEnabled()
    _wait_console(qtbot, rig.panel, "[stderr] oops")
    console = _console(rig.panel)
    assert "[*] Executing command: echo hi" in console
    assert "[+] Command exited with code 3" in console
    assert "[stdout] hello" in console
    assert agent.calls[0][1][-1] == "echo hi"
    assert button.isEnabled()


def test_execute_with_silent_output_prints_only_the_exit_code(rig: _Rig, qtbot: QtBot) -> None:
    """A command that wrote nothing must add neither a stdout nor a stderr line.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    rig.box.attach_agent(_ScriptedAgent([(0, "", "")]))
    rig.box.state.status = "running"
    _priv(rig.panel, "_cmd_input").setText("true")

    _call(rig.panel, "_on_execute_command")

    _wait_console(qtbot, rig.panel, "[+] Command exited with code 0")
    console = _console(rig.panel)
    assert "[stdout]" not in console
    assert "[stderr]" not in console


def test_execute_success_with_a_non_mapping_result_reports_plain_success() -> None:
    """A result that is not the exit-code mapping must be reported as a plain success and re-enable the button."""
    panel = SandboxPanel()
    _call(panel, "_set_sandbox_controls_active", active=True)
    _priv(panel, "_exec_cmd_btn").setEnabled(False)

    _call(panel, "_on_execute_command_success", "done")

    assert "[+] Command executed" in _console(panel)
    assert "exited with code" not in _console(panel)
    assert _priv(panel, "_exec_cmd_btn").isEnabled()


def test_refresh_instances_success_with_a_non_list_result_reports_plain_success() -> None:
    """A refresh result that is not a list must be reported without touching the Instances tree."""
    panel = SandboxPanel()
    tree = _tree(panel, "_instances_tree")
    tree.addTopLevelItem(QTreeWidgetItem(["kept", "", "", "", "", ""]))
    _priv(panel, "_refresh_instances_btn").setEnabled(False)

    _call(panel, "_on_refresh_instances_success", {"unexpected": True})

    assert "[+] Instances refreshed" in _console(panel)
    assert "[+] Instances refreshed: " not in _console(panel)
    assert _rows(tree) == [["kept", "", "", "", "", ""]]
    assert _priv(panel, "_refresh_instances_btn").isEnabled()


def test_refresh_instances_error_raises_a_dialog_and_re_enables_the_button(error_dialogs: list[tuple[str, str]]) -> None:
    """A failed instance refresh must raise a dialog with the error text and re-enable Refresh.

    Args:
        error_dialogs: Recorder for the error dialog.
    """
    panel = SandboxPanel()
    _priv(panel, "_refresh_instances_btn").setEnabled(False)

    _call(panel, "_on_refresh_instances_error", RuntimeError("list broke"))

    assert error_dialogs == [("Instance Refresh Failed", "Instance refresh failed:\n\nlist broke")]
    assert "[-] Instance refresh failed: list broke" in _console(panel)
    assert _priv(panel, "_refresh_instances_btn").isEnabled()


def test_refresh_snapshots_lists_the_names_the_disk_holds(rig: _Rig, qtbot: QtBot) -> None:
    """Refresh Snapshots must show one row per snapshot the sandbox's disk holds and drop stale rows.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    rig.box.attach_qmp(_ScriptedQMP({"query-block": [_ok(_block_report("clean", "dirty"))]}))
    tree = _tree(rig.panel, "_snapshots_tree")
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "stale", ""]))
    button = _priv(rig.panel, "_refresh_snapshots_btn")
    assert button.isEnabled()

    _call(rig.panel, "_on_refresh_snapshots")

    assert not button.isEnabled()
    _wait_console(qtbot, rig.panel, "[+] Snapshots refreshed: 2")
    assert _rows(tree) == [["clean", "clean", ""], ["dirty", "dirty", ""]]
    assert button.isEnabled()


def test_refresh_snapshots_failure_raises_a_dialog(rig: _Rig, qtbot: QtBot, error_dialogs: list[tuple[str, str]]) -> None:
    """A monitor that refuses the block query must come back as an error dialog and leave Refresh usable.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
        error_dialogs: Recorder for the error dialog.
    """
    rig.box.attach_qmp(_ScriptedQMP({"query-block": [_refused("monitor busy")]}))

    _call(rig.panel, "_on_refresh_snapshots")

    _wait_console(qtbot, rig.panel, "[-] Snapshot list failed: ")
    assert [title for title, _ in error_dialogs] == ["Snapshot List Failed"]
    assert "Snapshot listing failed" in error_dialogs[0][1]
    assert _priv(rig.panel, "_refresh_snapshots_btn").isEnabled()


@pytest.mark.parametrize(
    ("payload", "expected_rows"),
    [
        ("not a dict", []),
        ({"snapshots": "not a list"}, []),
        ({"snapshots": ["alpha", 5]}, [["alpha", "alpha", ""], ["5", "5", ""]]),
    ],
    ids=["non-dict-result", "snapshots-not-a-list", "names-stringified"],
)
def test_refresh_snapshots_success_tolerates_unexpected_payload_shapes(payload: object, expected_rows: list[list[str]]) -> None:
    """The snapshot handler must build one row per listed name and report the count it built.

    Args:
        payload: Result handed to the success handler.
        expected_rows: Rows the tree must hold afterwards.
    """
    panel = SandboxPanel()
    tree = _tree(panel, "_snapshots_tree")
    tree.addTopLevelItem(QTreeWidgetItem(["stale", "stale", ""]))

    _call(panel, "_on_refresh_snapshots_success", payload)

    assert _rows(tree) == expected_rows
    assert f"[+] Snapshots refreshed: {len(expected_rows)}" in _console(panel)


def test_pending_messages_prints_what_the_guest_agent_queued(rig: _Rig, qtbot: QtBot) -> None:
    """Pending Messages must print each queued guest-agent message with its type and payload.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    agent = _MessageAgent()
    now = datetime.now(UTC)
    agent.enqueue(GuestAgentMessage(message_type="status", timestamp=now, data={"k": "v"}))
    agent.enqueue(GuestAgentMessage(message_type="heartbeat", timestamp=now))
    rig.box.attach_agent(agent)
    button = _priv(rig.panel, "_pending_messages_btn")
    assert button.isEnabled()

    _call(rig.panel, "_on_pending_messages")

    assert not button.isEnabled()
    _wait_console(qtbot, rig.panel, "[+] Pending messages retrieved: 2")
    console = _console(rig.panel)
    assert "[guest-agent] status: {'k': 'v'}" in console
    assert "[guest-agent] heartbeat: {}" in console
    assert button.isEnabled()


def test_pending_messages_without_an_agent_raises_a_dialog(rig: _Rig, qtbot: QtBot, error_dialogs: list[tuple[str, str]]) -> None:
    """A sandbox whose guest-agent channel is not connected must come back as an error dialog.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
        error_dialogs: Recorder for the error dialog.
    """
    _call(rig.panel, "_on_pending_messages")

    _wait_console(qtbot, rig.panel, "[-] Pending messages retrieval failed: ")
    assert [title for title, _ in error_dialogs] == ["Pending Messages Failed"]
    assert "guest agent channel not connected" in error_dialogs[0][1]
    assert _priv(rig.panel, "_pending_messages_btn").isEnabled()


@pytest.mark.parametrize(
    ("payload", "expected_lines", "expected_count"),
    [
        (None, [], 0),
        ({"messages": "not a list"}, [], 0),
        (
            {"messages": ["plain text", {"type": "note", "data": {"a": 1}}, {}]},
            ["[guest-agent] plain text", "[guest-agent] note: {'a': 1}", "[guest-agent] unknown: {}"],
            3,
        ),
    ],
    ids=["non-dict-result", "messages-not-a-list", "mixed-entries"],
)
def test_pending_messages_success_tolerates_unexpected_payload_shapes(
    payload: object,
    expected_lines: list[str],
    expected_count: int,
) -> None:
    """The message handler must print each entry in its own shape and report the length of the message list.

    Args:
        payload: Result handed to the success handler.
        expected_lines: Console lines that must appear, in order.
        expected_count: Count the summary line must report.
    """
    panel = SandboxPanel()

    _call(panel, "_on_pending_messages_success", payload)

    console_lines = _console(panel).splitlines()
    printed = [line for line in console_lines if line.startswith("[guest-agent] ")]
    assert printed == expected_lines
    assert f"[+] Pending messages retrieved: {expected_count}" in console_lines


def test_anti_evasion_on_a_stopped_sandbox_raises_a_dialog(rig: _Rig, qtbot: QtBot, error_dialogs: list[tuple[str, str]]) -> None:
    """Applying anti-evasion to a sandbox that is not running must surface the bridge's error and re-enable the button.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
        error_dialogs: Recorder for the error dialog.
    """
    button = _priv(rig.panel, "_anti_evasion_btn")
    assert button.isEnabled()

    _call(rig.panel, "_on_anti_evasion")

    assert not button.isEnabled()
    _wait_console(qtbot, rig.panel, "[-] Anti-evasion failed: ")
    assert [title for title, _ in error_dialogs] == ["Anti-Evasion Failed"]
    assert "Failed to apply anti-evasion" in error_dialogs[0][1]
    assert button.isEnabled()


@pytest.mark.parametrize(
    ("payload", "expected_log", "expected_lines"),
    [
        ("applied", "[+] Anti-evasion applied", []),
        ({"profile": "stealth", "techniques": None}, "[+] Anti-evasion applied (profile: stealth)", []),
        (
            {"profile": "stealth", "techniques": ["cpuid mask", 7]},
            "[+] Anti-evasion applied (profile: stealth)",
            ["[anti-evasion] cpuid mask", "[anti-evasion] 7"],
        ),
        (
            {"profile": "default", "techniques": {"smbios": "patched", "count": 2}},
            "[+] Anti-evasion applied (profile: default)",
            ["[anti-evasion] smbios: patched", "[anti-evasion] count: 2"],
        ),
        ({"techniques": "text"}, "[+] Anti-evasion applied (profile: )", []),
    ],
    ids=["non-dict-result", "no-techniques", "technique-list", "technique-mapping", "technique-text"],
)
def test_anti_evasion_success_renders_the_techniques_it_is_given(payload: object, expected_log: str, expected_lines: list[str]) -> None:
    """The anti-evasion handler must log the profile and print list or mapping techniques, one console line each.

    Args:
        payload: Result handed to the success handler.
        expected_log: Summary line that must appear.
        expected_lines: Technique lines that must appear, in order.
    """
    panel = SandboxPanel()
    panel.sandbox_type_combo.setCurrentText("QEMU")
    _call(panel, "_set_sandbox_controls_active", active=True)
    _priv(panel, "_anti_evasion_btn").setEnabled(False)

    _call(panel, "_on_anti_evasion_success", payload)

    console_lines = _console(panel).splitlines()
    assert expected_log in console_lines
    assert [line for line in console_lines if line.startswith("[anti-evasion] ")] == expected_lines
    assert _priv(panel, "_anti_evasion_btn").isEnabled()


def test_detect_c2_lists_the_patterns_the_bridge_found(rig: _Rig, qtbot: QtBot) -> None:
    """Detect C2 must print a line per pattern for traffic to a well-known C2 port and report the count.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    rig.instance.last_report = _report(
        network_activity=[
            {
                "protocol": "tcp",
                "direction": "outbound",
                "local_address": "10.0.0.5",
                "local_port": 50000,
                "remote_address": "203.0.113.9",
                "remote_port": 4444,
                "timestamp": "2026-07-01T00:00:00",
                "bytes_sent": 10,
                "bytes_received": 20,
            },
        ],
    )
    button = _priv(rig.panel, "_detect_c2_btn")
    assert button.isEnabled()

    _call(rig.panel, "_on_detect_c2")

    assert not button.isEnabled()
    _wait_console(qtbot, rig.panel, "[+] C2 detection complete: ")
    lines = _console(rig.panel).splitlines()
    pattern_lines = [line for line in lines if line.startswith("[C2] ")]
    assert any(line.startswith("[C2] pattern_type=known_c2_port, ") for line in pattern_lines)
    assert any("description=Connections on known C2 port 4444 (1 connection(s))" in line for line in pattern_lines)
    assert f"[+] C2 detection complete: {len(pattern_lines)} patterns" in lines
    assert button.isEnabled()


def test_detect_c2_failure_raises_a_dialog(rig: _Rig, qtbot: QtBot, error_dialogs: list[tuple[str, str]]) -> None:
    """Detection requested before any report exists must surface the bridge's error and re-enable the button.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
        error_dialogs: Recorder for the error dialog.
    """
    _call(rig.panel, "_on_detect_c2")

    _wait_console(qtbot, rig.panel, "[-] C2 detection failed: ")
    assert [title for title, _ in error_dialogs] == ["C2 Detection Failed"]
    assert "No execution report available for this instance" in error_dialogs[0][1]
    assert _priv(rig.panel, "_detect_c2_btn").isEnabled()


@pytest.mark.parametrize(
    ("payload", "expected_lines"),
    [
        (None, []),
        ({"patterns": "not a list"}, []),
        ({"patterns": [{"kind": "beacon", "hosts": 2}, "raw note"]}, ["[C2] kind=beacon, hosts=2", "[C2] raw note"]),
    ],
    ids=["non-dict-result", "patterns-not-a-list", "mapping-and-text"],
)
def test_detect_c2_success_tolerates_unexpected_payload_shapes(payload: object, expected_lines: list[str]) -> None:
    """The C2 handler must print mapping patterns as key=value pairs, other entries verbatim, and report the length.

    Args:
        payload: Result handed to the success handler.
        expected_lines: Pattern lines that must appear, in order.
    """
    panel = SandboxPanel()

    _call(panel, "_on_detect_c2_success", payload)

    lines = _console(panel).splitlines()
    assert [line for line in lines if line.startswith("[C2] ")] == expected_lines
    assert f"[+] C2 detection complete: {len(expected_lines)} patterns" in lines


def test_diff_compares_two_instances_reports(rig: _Rig, qtbot: QtBot) -> None:
    """Diff must compare the panel's instance with the named one and print each field's comparison.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    other_box = _QemuBox(SandboxConfig(), QEMUConfig())
    other_id = rig.bridge.register_existing_sandbox(other_box, "qemu")
    rig.instance.last_report = _report(exit_code=0, duration=1.0)
    _instance_by_id(rig.bridge, other_id).last_report = _report(exit_code=3, duration=2.5)
    _priv(rig.panel, "_diff_instance_b_input").setText(other_id)
    assert rig.panel.sandbox_id is not None
    first_id = rig.panel.sandbox_id
    button = _priv(rig.panel, "_diff_btn")
    assert button.isEnabled()

    _call(rig.panel, "_on_diff")

    assert not button.isEnabled()
    _wait_console(qtbot, rig.panel, f"[+] Diff complete: {first_id} vs {other_id}")
    console = _console(rig.panel)
    assert f"[*] Comparing instances: {first_id} vs {other_id}" in console
    assert "[diff] scalars:" in console
    assert "    exit_code: {'a': 0, 'b': 3}" in console
    assert "    duration_seconds: {'a': 1.0, 'b': 2.5}" in console
    assert "[diff] file_changes:\n    unique_to_a: []\n    unique_to_b: []\n    common: []" in console
    assert button.isEnabled()


def test_diff_against_an_unknown_instance_raises_a_dialog(rig: _Rig, qtbot: QtBot, error_dialogs: list[tuple[str, str]]) -> None:
    """Diffing against an instance the manager does not know must surface the bridge's error.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
        error_dialogs: Recorder for the error dialog.
    """
    _priv(rig.panel, "_diff_instance_b_input").setText("no-such-instance")

    _call(rig.panel, "_on_diff")

    _wait_console(qtbot, rig.panel, "[-] Diff failed: ")
    assert [title for title, _ in error_dialogs] == ["Diff Failed"]
    assert "Sandbox instance not found: no-such-instance" in error_dialogs[0][1]
    assert _priv(rig.panel, "_diff_btn").isEnabled()


@pytest.mark.parametrize(
    ("payload", "expected_log", "expected_lines"),
    [
        ("plain", "[+] Diff complete", []),
        ({"instance_id_a": "a1", "instance_id_b": "b2", "diff": None}, "[+] Diff complete: a1 vs b2", []),
        ({"diff": {}}, "[+] Diff complete:  vs ", []),
        (
            {"instance_id_a": "a1", "instance_id_b": "b2", "diff": {"scalars": {"exit_code": 1}, "note": "same", "count": 4}},
            "[+] Diff complete: a1 vs b2",
            ["[diff] scalars:", "    exit_code: 1", "[diff] note:", "    same", "[diff] count:", "    4"],
        ),
    ],
    ids=["non-dict-result", "diff-not-a-mapping", "empty-diff", "mapping-and-scalar-fields"],
)
def test_diff_success_renders_each_field_in_its_own_shape(payload: object, expected_log: str, expected_lines: list[str]) -> None:
    """The diff handler must print mapping fields as indented sub-keys and scalar fields as one indented value.

    Args:
        payload: Result handed to the success handler.
        expected_log: Summary line that must appear.
        expected_lines: Rendered diff lines that must appear, in order.
    """
    panel = SandboxPanel()
    _call(panel, "_set_sandbox_controls_active", active=True)
    _priv(panel, "_diff_btn").setEnabled(False)

    _call(panel, "_on_diff_success", payload)

    lines = _console(panel).splitlines()
    assert expected_log.rstrip() in [line.rstrip() for line in lines]
    assert [line for line in lines if line.startswith(("[diff] ", "    "))] == expected_lines
    assert _priv(panel, "_diff_btn").isEnabled()


def test_status_poll_shows_the_active_count_and_the_instance_row(rig: _Rig, qtbot: QtBot) -> None:
    """A status poll must report the manager's active count and list the registered instance in the Instances tab.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    rig.box.state.status = "running"
    status_label = _priv(rig.panel, "_status_indicator")

    _call(rig.panel, "_poll_status")

    qtbot.waitUntil(lambda: status_label.text() == "Active (1 instances)", timeout=_WAIT_MS)
    rows = _rows(_tree(rig.panel, "_instances_tree"))
    assert len(rows) == 1
    row = rows[0]
    assert row[0] == rig.instance.id
    assert row[1] == "qemu"
    assert row[2] == "running"
    assert row[3] == rig.instance.created_at.isoformat()
    assert row[4] == rig.instance.last_used.isoformat()
    assert not row[5]


def test_status_poll_without_a_bridge_does_nothing() -> None:
    """A poll tick with no bridge attached must leave the status label and console alone."""
    panel = SandboxPanel()
    before = _console(panel)
    label = _priv(panel, "_status_indicator").text()

    _call(panel, "_poll_status")

    assert _priv(panel, "_status_indicator").text() == label
    assert _console(panel) == before
    assert bridge_workers_for(panel) == []


@pytest.mark.parametrize(
    ("payload", "expected_label"),
    [
        ("not a dict", "Active"),
        ({"active_count": 2}, "Active (2 instances)"),
        ({"active_count": 3, "instances": "not a list"}, "Active (3 instances)"),
    ],
    ids=["non-dict-result", "no-instance-list", "instances-not-a-list"],
)
def test_status_success_without_an_instance_list_leaves_the_tree_alone(payload: object, expected_label: str) -> None:
    """A status result with no usable instance list must update the label and keep the Instances rows.

    Args:
        payload: Result handed to the success handler.
        expected_label: Text the status label must show.
    """
    panel = SandboxPanel()
    tree = _tree(panel, "_instances_tree")
    tree.addTopLevelItem(QTreeWidgetItem(["kept", "", "", "", "", ""]))
    _set_priv(panel, "_last_poll_error", "earlier failure")

    _call(panel, "_on_poll_status_success", payload)

    assert _priv(panel, "_status_indicator").text() == expected_label
    assert _rows(tree) == [["kept", "", "", "", "", ""]]
    assert _priv(panel, "_last_poll_error") is None


def test_instances_tree_updates_known_rows_skips_bad_entries_and_drops_stale_rows() -> None:
    """The Instances tab must update rows in place by id, ignore unusable entries, and remove rows the poll no longer lists."""
    panel = SandboxPanel()

    _call(
        panel,
        "_populate_instances_tree",
        [
            {"id": "a", "type": "qemu", "status": "running", "created_at": "c1", "last_used": "u1", "binary": "x.exe"},
            "not a mapping",
            {"status": "running"},
            {"instance_id": "b", "isolation_level": "windows", "updated_at": "u2", "binary_path": "y.exe"},
        ],
    )

    tree = _tree(panel, "_instances_tree")
    assert _rows(tree) == [
        ["a", "qemu", "running", "c1", "u1", "x.exe"],
        ["b", "windows", "", "", "u2", "y.exe"],
    ]
    first_row = tree.topLevelItem(0)
    assert first_row is not None

    _call(panel, "_populate_instances_tree", [{"id": "a", "type": "qemu", "status": "stopped", "created_at": "c1", "last_used": "u3"}])

    assert _rows(tree) == [["a", "qemu", "stopped", "c1", "u3", ""]]
    assert tree.topLevelItem(0) is first_row


def test_vnc_status_connected_is_logged() -> None:
    """A connected VNC status must be written to the console."""
    panel = SandboxPanel()

    _call(panel, "_on_vnc_status_changed", connected=True)

    assert "[+] VNC display connected" in _console(panel)
    assert "disconnected" not in _console(panel)


@pytest.mark.parametrize(
    ("has_widget", "has_bridge", "has_instance"),
    [(False, True, True), (True, False, True), (True, True, False)],
    ids=["no-widget", "no-bridge", "no-instance"],
)
def test_connect_vnc_display_without_a_prerequisite_dispatches_nothing(
    *,
    has_widget: bool,
    has_bridge: bool,
    has_instance: bool,
) -> None:
    """The VNC connect must return without a port query when the widget, bridge or instance is missing.

    Args:
        has_widget: Whether the panel keeps its VNC widget.
        has_bridge: Whether a real bridge is attached.
        has_instance: Whether the panel holds a sandbox id.
    """
    panel = SandboxPanel()
    panel.sandbox_type_combo.setCurrentText("QEMU")
    if has_bridge:
        panel.set_bridge(SandboxBridge())
    if has_instance:
        panel.sandbox_id = "sbx-vnc"
    if not has_widget:
        _set_priv(panel, "_vnc_widget", None)
    before = _console(panel)

    _call(panel, "_connect_vnc_display")

    assert _console(panel) == before
    assert bridge_workers_for(panel) == []


def test_connect_vnc_display_is_skipped_for_the_windows_backend() -> None:
    """A Windows sandbox has no VNC server, so the port query must not be dispatched."""
    panel = SandboxPanel()
    panel.sandbox_type_combo.setCurrentText("Windows Sandbox")
    panel.set_bridge(SandboxBridge())
    panel.sandbox_id = "sbx-win"
    before = _console(panel)

    _call(panel, "_connect_vnc_display")

    assert _console(panel) == before
    assert bridge_workers_for(panel) == []


@pytest.mark.parametrize("result", [None, "5900", 5900.0], ids=["none", "text", "float"])
def test_vnc_port_that_is_not_an_integer_does_not_start_a_connection(result: object) -> None:
    """A port query result that is not an integer must not start a VNC connection.

    Args:
        result: Value handed to the port handler.
    """
    panel = SandboxPanel()
    panel.set_bridge(SandboxBridge())
    panel.sandbox_id = "sbx-vnc"
    vnc = _priv(panel, "_vnc_widget")
    before = _console(panel)

    _call(panel, "_on_vnc_port_received", result)

    assert _priv(vnc, "_pending_connect") == ("", 0)
    assert _console(panel) == before
    assert bridge_workers_for(panel) == []


def test_vnc_port_with_no_widget_does_nothing() -> None:
    """A port result that arrives after the VNC widget is gone must not start a connection."""
    panel = SandboxPanel()
    panel.set_bridge(SandboxBridge())
    panel.sandbox_id = "sbx-vnc"
    _set_priv(panel, "_vnc_widget", None)
    before = _console(panel)

    _call(panel, "_on_vnc_port_received", 5900)

    assert _console(panel) == before
    assert bridge_workers_for(panel) == []


def test_connect_vnc_with_password_without_a_bridge_does_nothing() -> None:
    """Connecting with a password needs a bridge to read it from, so without one nothing is started."""
    panel = SandboxPanel()
    panel.sandbox_id = "sbx-vnc"
    vnc = _priv(panel, "_vnc_widget")
    before = _console(panel)

    _call(panel, "_connect_vnc_with_password", 5900)

    assert _priv(vnc, "_pending_connect") == ("", 0)
    assert _console(panel) == before


def test_disconnect_vnc_display_without_a_widget_is_a_no_op() -> None:
    """Disconnecting after the VNC widget is gone must not raise."""
    panel = SandboxPanel()
    _set_priv(panel, "_vnc_widget", None)

    _call(panel, "_disconnect_vnc_display")

    assert _priv(panel, "_vnc_widget") is None


def test_vnc_display_connects_with_the_registered_password(rig: _Rig, qtbot: QtBot) -> None:
    """The VM Display must query the sandbox's VNC port and answer the server's VNC Authentication with the registered password.

    A server that offers only VNC Authentication sees the client select that type and send a 16-byte response only when the password
    reached the VNC client. Without a password the client abandons the handshake before sending either.

    Args:
        rig: Panel wired to a real bridge and sandbox.
        qtbot: Qt test helper that pumps events while waiting.
    """
    server = _AuthProbeServer()
    try:
        rig.box.attach_vnc_port(server.port)
        rig.bridge.set_vnc_password(rig.instance.id, "vnc" + "pw")
        vnc = _priv(rig.panel, "_vnc_widget")

        _call(rig.panel, "_connect_vnc_display")

        _wait_console(qtbot, rig.panel, f"[*] Connecting VNC display on port {server.port}...")
        assert _priv(vnc, "_pending_connect") == ("127.0.0.1", server.port)
        qtbot.waitUntil(server.finished.is_set, timeout=_WAIT_MS)
        assert server.selected == bytes([_RFB_SECURITY_VNC_AUTH])
        assert server.response_length == _RFB_CHALLENGE_LENGTH
        _wait_console(qtbot, rig.panel, "[*] VNC display disconnected")
    finally:
        _call(rig.panel, "_disconnect_vnc_display")
        server.close()
