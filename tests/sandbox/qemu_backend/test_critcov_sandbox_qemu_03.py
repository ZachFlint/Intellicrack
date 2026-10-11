# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage for the QEMU snapshot, capture, memory-dump and dropped-file operations.

None of these operations needs a running QEMU to be exercised honestly: they
build monitor commands, read what the monitor answered, move files in the shared
folder and decide what to report. The monitor and guest-agent clients used here
are subclasses of the real production clients whose wire exchange answers from a
script, so every convenience method (``query_block``, ``snapshot_save``,
``job_dismiss`` ...) and every decision in ``QEMUSandbox`` is the shipped code.
Failure paths that QEMU's absence produces naturally use an unconnected real
``QMPClient``, which answers every command with ``Not connected``.
"""

from __future__ import annotations

import base64
import re
import struct
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestAgentClient,
    QEMUConfig,
    QemuGuestAgentClient,
    QEMUSandbox,
    QMPClient,
    QMPResponse,
)


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
GUEST_DROP_DIR = "C:\\drop"


def _arguments(command: dict[str, object]) -> dict[str, object]:
    """Return the ``arguments`` member of a monitor command as a mapping.

    Args:
        command: Command dictionary as the product built it.

    Returns:
        dict[str, object]: The arguments, or an empty mapping when there are none.
    """
    raw = command.get("arguments")
    return cast("dict[str, object]", raw) if isinstance(raw, dict) else {}


def _deposit(arguments: dict[str, object], payload: bytes) -> None:
    """Write bytes where QEMU was told to put its output file.

    QMP's ``screendump`` names its target in ``filename`` and
    ``dump-guest-memory`` names it in ``protocol`` as ``file:<path>``.

    Args:
        arguments: Arguments of the command that asked QEMU to write a file.
        payload: Bytes QEMU would have written.
    """
    target = str(arguments.get("filename") or arguments.get("protocol"))
    Path(target.removeprefix("file:")).write_bytes(payload)


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
        QMPResponse: A ``query-status`` answer. A stopped machine reports the
        ``restore-vm`` state QEMU 10.1.0 was measured leaving it in.
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

    Only ``_send_command`` is replaced. Each command name maps to a queue of
    replies; the last reply of a queue repeats once the queue is down to it. A
    ``query-jobs`` reply has its records stamped with the job id the most recent
    snapshot command carried, because the sandbox mints that id at random.
    """

    def __init__(self, script: Mapping[str, Sequence[QMPResponse]], writes: Mapping[str, bytes] | None = None) -> None:
        """Initialise the scripted monitor.

        Args:
            script: Replies per command name.
            writes: Bytes QEMU would write to the file a command names, per command name.
        """
        super().__init__()
        self._script: dict[str, list[QMPResponse]] = {name: list(replies) for name, replies in script.items()}
        self._writes: dict[str, bytes] = dict(writes or {})
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
        arguments = _arguments(command)
        job_id = arguments.get("job-id")
        if isinstance(job_id, str):
            self._job_id = job_id
        payload = self._writes.get(name)
        if payload is not None:
            _deposit(arguments, payload)
        queue = self._script[name]
        reply = queue.pop(0) if len(queue) > 1 else queue[0]
        if name == "query-jobs" and reply.success and isinstance(reply.data, list):
            records = cast("list[object]", reply.data)
            return _ok([{"id": self._job_id, **cast("dict[str, object]", record)} for record in records])
        return reply


class _ScriptedQGA(QemuGuestAgentClient):
    """Real ``QemuGuestAgentClient`` serving guest file reads from a dictionary.

    Replies follow the qemu-guest-agent schema: ``guest-file-open`` returns an
    integer handle, ``guest-file-read`` returns ``buf-b64`` and ``eof``, and
    ``guest-file-close`` returns an empty object.
    """

    def __init__(self, contents: Mapping[str, bytes], refuse_open: frozenset[str] = frozenset()) -> None:
        """Initialise the scripted guest agent.

        Args:
            contents: File bytes per guest path. A path not listed reads as ``b"x"``.
            refuse_open: Guest paths whose ``guest-file-open`` the agent refuses.
        """
        super().__init__()
        self._contents: dict[str, bytes] = dict(contents)
        self._refuse_open = refuse_open
        self._open_handles: dict[int, str] = {}
        self._next_handle = 1
        self.opened: list[str] = []

    @override
    async def _send_command(self, command: dict[str, object], time_limit: float = 10.0) -> QMPResponse:
        """Answer one guest-file command.

        Args:
            command: Command dictionary with an ``execute`` key.
            time_limit: Ignored; the scripted exchange is immediate.

        Returns:
            QMPResponse: The agent's reply for the command.
        """
        del time_limit
        name = str(command["execute"])
        arguments = _arguments(command)
        if name == "guest-file-open":
            path = str(arguments["path"])
            self.opened.append(path)
            if path in self._refuse_open:
                return _refused("Permission denied")
            handle = self._next_handle
            self._next_handle += 1
            self._open_handles[handle] = path
            return _ok(handle)
        handle = cast("int", arguments["handle"])
        if name == "guest-file-read":
            payload = self._contents.get(self._open_handles[handle], b"x")
            return _ok({"buf-b64": base64.b64encode(payload).decode("ascii"), "eof": True})
        del self._open_handles[handle]
        return _ok({})


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


class _TestableQEMUSandbox(QEMUSandbox):
    """``QEMUSandbox`` exposing the private state and helpers these tests drive."""

    def attach_qmp(self, qmp: QMPClient | None) -> None:
        """Set the monitor client without starting QEMU.

        Args:
            qmp: Monitor client to install, or None for none.
        """
        self._qmp = qmp

    def attach_qga(self, qga: QemuGuestAgentClient | None) -> None:
        """Set the qemu-guest-agent client without starting QEMU.

        Args:
            qga: Guest-agent client to install, or None for none.
        """
        self._qga = qga

    def attach_agent(self, agent: GuestAgentClient | None) -> None:
        """Set the Intellicrack guest-agent client without starting QEMU.

        Args:
            agent: Agent client to install, or None for none.
        """
        self._agent = agent

    def attach_shared_folder(self, folder: Path | None) -> None:
        """Set the shared folder without starting QEMU.

        Args:
            folder: Host shared folder, or None for none.
        """
        self._shared_folder = folder

    def attach_accelerator(self, accelerator: AcceleratorType) -> None:
        """Set the detected accelerator without probing the host.

        Args:
            accelerator: Accelerator to report.
        """
        self._accelerator = accelerator

    @property
    def active_captures(self) -> dict[str, Path]:
        """Packet captures currently recorded as running.

        Returns:
            dict[str, Path]: Capture id mapped to its pcap path.
        """
        return self._active_captures

    def staging_root_for(self, extract_id: str) -> Path:
        """Forward to the private staging-directory resolver.

        Args:
            extract_id: Identifier of the extraction.

        Returns:
            Path: Host directory the extraction stages into.
        """
        return self._staging_root_for(extract_id)

    async def list_guest_directory(self, guest_dir: str) -> list[str]:
        """Forward to the private guest directory lister.

        Args:
            guest_dir: Absolute in-guest directory.

        Returns:
            list[str]: Files found beneath it.
        """
        return await self._list_guest_directory(guest_dir)

    async def pull_guest_directory(self, guest_dir: str, destination: Path) -> int:
        """Forward to the private guest directory puller.

        Args:
            guest_dir: Absolute in-guest directory.
            destination: Host directory to reproduce the tree under.

        Returns:
            int: Number of files written to the host.
        """
        return await self._pull_guest_directory(guest_dir, destination)

    async def host_collect_dropped_files(self, staging_dir: Path) -> None:
        """Forward to the private host-side dropped-file collector.

        Args:
            staging_dir: Directory the files would be copied into.
        """
        await self._host_collect_dropped_files(staging_dir)

    async def await_memory_dump(self, dump_path: Path) -> None:
        """Forward to the private memory-dump waiter.

        Args:
            dump_path: File the dump is being written to.
        """
        await self._await_memory_dump(dump_path)

    @staticmethod
    def count_files_recursive(directory: Path) -> int:
        """Forward to the private recursive file counter.

        Args:
            directory: Root directory to scan.

        Returns:
            int: Number of regular files beneath it.
        """
        return QEMUSandbox._count_files_recursive(directory)

    @staticmethod
    async def wait_for_ppm_stable(ppm_path: Path) -> None:
        """Forward to the private PPM stability poll.

        Args:
            ppm_path: PPM file whose size is polled.
        """
        await QEMUSandbox._wait_for_ppm_stable(ppm_path)


def _sandbox(shared: Path | None, *, qemu_config: QEMUConfig | None = None) -> _TestableQEMUSandbox:
    """Build a sandbox that has not started anything.

    Args:
        shared: Host shared folder to install, or None for none.
        qemu_config: QEMU configuration, or None for the defaults.

    Returns:
        _TestableQEMUSandbox: A sandbox with no process and no monitor.
    """
    box = _TestableQEMUSandbox(SandboxConfig(), qemu_config or QEMUConfig())
    box.attach_shared_folder(shared)
    return box


@pytest.fixture
def shared_folder(tmp_path: Path) -> Path:
    """Create a shared folder with the ``output`` directory QEMU writes into.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: The shared folder.
    """
    folder = tmp_path / "shared"
    (folder / "output").mkdir(parents=True)
    return folder


_NO_MONITOR_CALLS: dict[str, Callable[[_TestableQEMUSandbox], Awaitable[object]]] = {
    "take_snapshot": lambda box: box.take_snapshot("baseline"),
    "restore_snapshot": lambda box: box.restore_snapshot("baseline"),
    "delete_snapshot": lambda box: box.delete_snapshot("baseline"),
    "start_pcap_capture": lambda box: box.start_pcap_capture(),
    "stop_pcap_capture": lambda box: box.stop_pcap_capture("pcap_0123456789abcdef"),
    "capture_screenshot": lambda box: box.capture_screenshot(),
    "dump_memory": lambda box: box.dump_memory(),
    "await_memory_dump": lambda box: box.await_memory_dump(Path("memdump.raw")),
}

_NO_SHARE_CALLS: dict[str, Callable[[_TestableQEMUSandbox], Awaitable[object]]] = {
    "start_pcap_capture": lambda box: box.start_pcap_capture(),
    "capture_screenshot": lambda box: box.capture_screenshot(),
    "dump_memory": lambda box: box.dump_memory(),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", sorted(_NO_MONITOR_CALLS))
async def test_operation_refuses_without_a_monitor(shared_folder: Path, operation: str) -> None:
    """Every monitor-driven operation reports a missing monitor instead of acting.

    Args:
        shared_folder: Shared folder, present so only the monitor is missing.
        operation: Name of the operation under test.
    """
    box = _sandbox(shared_folder)

    with pytest.raises(SandboxError, match="QMP not connected"):
        await _NO_MONITOR_CALLS[operation](box)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", sorted(_NO_SHARE_CALLS))
async def test_operation_refuses_without_a_shared_folder(operation: str) -> None:
    """Capture operations that write into the shared folder refuse when there is none.

    Args:
        operation: Name of the operation under test.
    """
    box = _sandbox(None)
    box.attach_qmp(QMPClient())

    with pytest.raises(SandboxError, match="shared folder not init"):
        await _NO_SHARE_CALLS[operation](box)


@pytest.mark.asyncio
async def test_list_snapshots_is_empty_without_a_monitor() -> None:
    """Without a monitor there are no snapshots to list, and that is not an error."""
    box = _sandbox(None)

    assert await box.list_snapshots() == []


@pytest.mark.asyncio
async def test_list_snapshots_collects_unique_names_across_disks() -> None:
    """Names come from the block records, once each, skipping records that carry none."""
    blocks: list[object] = [
        {"device": "drive0", "inserted": {"image": {"snapshots": [{"name": "clean"}, "junk", {"name": "dirty"}, {"name": 7}]}}},
        {"device": "drive1", "inserted": {"drv": "raw"}},
        {"device": "drive2", "inserted": {"image": {"snapshots": [{"name": "dirty"}, {"name": "extra"}]}}},
        {"device": "drive3"},
    ]
    box = _sandbox(None)
    box.attach_qmp(_ScriptedQMP({"query-block": [_ok(blocks)]}))

    assert await box.list_snapshots() == ["clean", "dirty", "extra"]


@pytest.mark.asyncio
async def test_take_snapshot_under_whpx_writes_a_disk_only_snapshot() -> None:
    """Under WHPX a snapshot is taken on the writable disk's device id, not as a machine-state job."""
    qmp = _ScriptedQMP({
        "query-block": [_ok(_block_report())],
        "blockdev-snapshot-internal-sync": [_ok({})],
    })
    box = _sandbox(None)
    box.attach_qmp(qmp)
    box.attach_accelerator(AcceleratorType.WHPX)

    assert await box.take_snapshot("baseline") == "baseline"

    assert qmp.commands == ["query-block", "blockdev-snapshot-internal-sync"]
    assert qmp.sent[-1] == {
        "execute": "blockdev-snapshot-internal-sync",
        "arguments": {"device": "drive0", "name": "baseline"},
    }


@pytest.mark.asyncio
async def test_take_snapshot_runs_a_full_snapshot_job_and_dismisses_it() -> None:
    """Without WHPX the snapshot is a job over the writable qcow2 node, dismissed once concluded."""
    qmp = _ScriptedQMP({
        "query-block": [_ok(_block_report())],
        "query-status": [_run_state(running=True)],
        "snapshot-save": [_ok({})],
        "query-jobs": [_ok([{"status": "concluded"}])],
        "job-dismiss": [_ok({})],
    })
    box = _sandbox(None)
    box.attach_qmp(qmp)

    assert await box.take_snapshot("baseline") == "baseline"

    assert qmp.commands == ["query-block", "query-status", "snapshot-save", "query-jobs", "job-dismiss"]
    save = _arguments(qmp.sent[2])
    job_id = cast("str", save["job-id"])
    assert job_id.startswith("intellicrack-save-")
    assert save == {"job-id": job_id, "tag": "baseline", "vmstate": "disk0", "devices": ["disk0"]}
    assert _arguments(qmp.sent[4]) == {"id": job_id}


@pytest.mark.asyncio
async def test_take_snapshot_job_failure_resumes_the_machine_and_reports_its_state() -> None:
    """A job that concludes with an error leaves the machine running again, and the error says so."""
    qmp = _ScriptedQMP({
        "query-block": [_ok(_block_report())],
        "query-status": [_run_state(running=True), _run_state(running=False), _run_state(running=True)],
        "snapshot-save": [_ok({})],
        "query-jobs": [_ok([{"status": "concluded", "error": "Failed to save snapshot"}])],
        "job-dismiss": [_ok({})],
        "cont": [_ok({})],
    })
    box = _sandbox(None)
    box.attach_qmp(qmp)

    with pytest.raises(SandboxError) as raised:
        await box.take_snapshot("baseline")

    assert raised.value.message.startswith("snapshot create failed: Failed to save snapshot")
    assert raised.value.message.endswith("has been resumed")
    assert raised.value.vm_state == "running"
    cause = raised.value.__cause__
    assert isinstance(cause, SandboxError)
    assert cause.message == "snapshot create failed: Failed to save snapshot"
    assert "cont" in qmp.commands


@pytest.mark.asyncio
async def test_restore_snapshot_loads_the_tag_over_the_writable_node() -> None:
    """Restoring starts a ``snapshot-load`` job for the named tag and waits for it."""
    qmp = _ScriptedQMP({
        "query-block": [_ok(_block_report("clean"))],
        "query-status": [_run_state(running=True)],
        "snapshot-load": [_ok({})],
        "query-jobs": [_ok([{"status": "concluded"}])],
        "job-dismiss": [_ok({})],
    })
    box = _sandbox(None)
    box.attach_qmp(qmp)

    await box.restore_snapshot("clean")

    assert qmp.commands == ["query-block", "query-status", "snapshot-load", "query-jobs", "job-dismiss"]
    load = _arguments(qmp.sent[2])
    job_id = cast("str", load["job-id"])
    assert job_id.startswith("intellicrack-load-")
    assert load == {"job-id": job_id, "tag": "clean", "vmstate": "disk0", "devices": ["disk0"]}


@pytest.mark.asyncio
async def test_restore_snapshot_refusal_resumes_a_machine_the_job_stopped() -> None:
    """A refused restore that left a running machine stopped starts it again and reports it running."""
    qmp = _ScriptedQMP({
        "query-block": [_ok(_block_report("clean"))],
        "query-status": [_run_state(running=True), _run_state(running=False), _run_state(running=True)],
        "snapshot-load": [_refused("Snapshot 'clean' does not exist")],
        "cont": [_ok({})],
    })
    box = _sandbox(None)
    box.attach_qmp(qmp)

    with pytest.raises(SandboxError) as raised:
        await box.restore_snapshot("clean")

    assert raised.value.message.startswith("snapshot restore failed: Snapshot 'clean' does not exist")
    assert raised.value.message.endswith("has been resumed")
    assert raised.value.vm_state == "running"
    assert "cont" in qmp.commands
    assert "query-jobs" not in qmp.commands


@pytest.mark.asyncio
async def test_restore_snapshot_refusal_leaves_a_machine_that_was_already_stopped() -> None:
    """A machine that was stopped before the job is not started by the failure handler."""
    qmp = _ScriptedQMP({
        "query-block": [_ok(_block_report("clean"))],
        "query-status": [_run_state(running=False)],
        "snapshot-load": [_refused(None)],
    })
    box = _sandbox(None)
    box.attach_qmp(qmp)

    with pytest.raises(SandboxError) as raised:
        await box.restore_snapshot("clean")

    assert raised.value.message == "snapshot restore failed: QEMU refused the request"
    assert raised.value.vm_state == "stopped"
    assert "cont" not in qmp.commands


@pytest.mark.asyncio
async def test_delete_snapshot_refuses_a_tag_no_disk_holds() -> None:
    """Deleting a misspelled tag is refused before any job is started."""
    qmp = _ScriptedQMP({"query-block": [_ok(_block_report("clean"))]})
    box = _sandbox(None)
    box.attach_qmp(qmp)

    with pytest.raises(SandboxError, match=r"no snapshot named 'ghost' exists on this sandbox's disks"):
        await box.delete_snapshot("ghost")

    assert qmp.commands == ["query-block"]


@pytest.mark.asyncio
async def test_delete_snapshot_runs_the_job_and_confirms_the_tag_is_gone() -> None:
    """A delete job is started for the tag and the disks are re-read to confirm it vanished."""
    qmp = _ScriptedQMP({
        "query-block": [_ok(_block_report("clean")), _ok(_block_report("clean")), _ok(_block_report())],
        "query-status": [_run_state(running=True)],
        "snapshot-delete": [_ok({})],
        "query-jobs": [_ok([{"status": "concluded"}])],
        "job-dismiss": [_ok({})],
    })
    box = _sandbox(None)
    box.attach_qmp(qmp)

    await box.delete_snapshot("clean")

    assert qmp.commands == [
        "query-block",
        "query-block",
        "query-status",
        "snapshot-delete",
        "query-jobs",
        "job-dismiss",
        "query-block",
    ]
    removal = _arguments(qmp.sent[3])
    job_id = cast("str", removal["job-id"])
    assert job_id.startswith("intellicrack-delete-")
    assert removal == {"job-id": job_id, "tag": "clean", "devices": ["disk0"]}


@pytest.mark.asyncio
async def test_delete_snapshot_reports_a_tag_that_outlives_its_job() -> None:
    """A job that finishes while the tag is still on the disk is reported as a failure."""
    qmp = _ScriptedQMP({
        "query-block": [_ok(_block_report("clean"))],
        "query-status": [_run_state(running=True)],
        "snapshot-delete": [_ok({})],
        "query-jobs": [_ok([{"status": "concluded"}])],
        "job-dismiss": [_ok({})],
    })
    box = _sandbox(None)
    box.attach_qmp(qmp)

    with pytest.raises(SandboxError, match=r"deletion of 'clean' as finished, but the tag is still on the disk"):
        await box.delete_snapshot("clean")


@pytest.mark.asyncio
async def test_start_pcap_capture_adds_a_filter_dump_for_the_shared_output(shared_folder: Path) -> None:
    """Starting a capture adds a ``filter-dump`` object writing into the shared output directory.

    Args:
        shared_folder: Shared folder the capture file belongs under.
    """
    qmp = _ScriptedQMP({"object-add": [_ok({})]})
    box = _sandbox(shared_folder)
    box.attach_qmp(qmp)

    capture_id = await box.start_pcap_capture()

    assert re.fullmatch(r"pcap_[0-9a-f]{16}", capture_id)
    pcap_path = shared_folder / "output" / f"{capture_id}.pcap"
    assert box.active_captures == {capture_id: pcap_path}
    assert qmp.sent == [
        {
            "execute": "object-add",
            "arguments": {"qom-type": "filter-dump", "id": capture_id, "netdev": "net0", "filename": str(pcap_path)},
        },
    ]


@pytest.mark.asyncio
async def test_start_pcap_capture_failure_records_no_capture(shared_folder: Path) -> None:
    """A monitor that cannot add the filter leaves no capture recorded as running.

    Args:
        shared_folder: Shared folder the capture would write into.
    """
    box = _sandbox(shared_folder)
    box.attach_qmp(QMPClient())

    with pytest.raises(SandboxError, match="packet capture start failed"):
        await box.start_pcap_capture()

    assert box.active_captures == {}


@pytest.mark.asyncio
async def test_stop_pcap_capture_refuses_an_unknown_capture(shared_folder: Path) -> None:
    """Stopping a capture that was never started is refused without touching the monitor.

    Args:
        shared_folder: Shared folder, so only the capture id is wrong.
    """
    qmp = _ScriptedQMP({})
    box = _sandbox(shared_folder)
    box.attach_qmp(qmp)

    with pytest.raises(SandboxError, match="no active packet capture with this ID"):
        await box.stop_pcap_capture("pcap_0123456789abcdef")

    assert qmp.sent == []


@pytest.mark.asyncio
async def test_stop_pcap_capture_failure_keeps_the_capture_active(shared_folder: Path) -> None:
    """A monitor that cannot delete the filter leaves the capture recorded as running.

    Args:
        shared_folder: Shared folder the capture was started in.
    """
    box = _sandbox(shared_folder)
    box.attach_qmp(_ScriptedQMP({"object-add": [_ok({})]}))
    capture_id = await box.start_pcap_capture()
    box.attach_qmp(QMPClient())

    with pytest.raises(SandboxError, match="packet capture stop failed"):
        await box.stop_pcap_capture(capture_id)

    assert capture_id in box.active_captures


@pytest.mark.asyncio
async def test_stop_pcap_capture_returns_the_capture_path_and_forgets_it(shared_folder: Path) -> None:
    """Stopping deletes the filter object and returns the pcap path the capture wrote to.

    Args:
        shared_folder: Shared folder the capture was started in.
    """
    qmp = _ScriptedQMP({"object-add": [_ok({})], "object-del": [_ok({})]})
    box = _sandbox(shared_folder)
    box.attach_qmp(qmp)
    capture_id = await box.start_pcap_capture()

    result = await box.stop_pcap_capture(capture_id)

    assert result == shared_folder / "output" / f"{capture_id}.pcap"
    assert qmp.sent[-1] == {"execute": "object-del", "arguments": {"id": capture_id}}
    assert capture_id not in box.active_captures


@pytest.mark.asyncio
async def test_stop_pcap_capture_copies_the_capture_to_the_requested_path(shared_folder: Path, tmp_path: Path) -> None:
    """With an output path the capture file is copied there, creating missing parent directories.

    Args:
        shared_folder: Shared folder the capture was started in.
        tmp_path: Pytest temporary directory holding the export location.
    """
    qmp = _ScriptedQMP({"object-add": [_ok({})], "object-del": [_ok({})]})
    box = _sandbox(shared_folder)
    box.attach_qmp(qmp)
    capture_id = await box.start_pcap_capture()
    capture_bytes = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20
    (shared_folder / "output" / f"{capture_id}.pcap").write_bytes(capture_bytes)
    export = tmp_path / "export" / "nested" / "capture.pcap"

    result = await box.stop_pcap_capture(capture_id, export)

    assert result == export
    assert export.read_bytes() == capture_bytes
    assert capture_id not in box.active_captures


@pytest.mark.asyncio
async def test_wait_for_ppm_stable_returns_once_the_size_stops_changing(tmp_path: Path) -> None:
    """A PPM whose size is the same on two consecutive polls is considered finished.

    Args:
        tmp_path: Pytest temporary directory.
    """
    ppm = tmp_path / "screen.ppm"
    ppm.write_bytes(b"P6\n1 1\n255\n\x01\x02\x03")

    assert await _TestableQEMUSandbox.wait_for_ppm_stable(ppm) is None


@pytest.mark.asyncio
async def test_wait_for_ppm_stable_gives_up_on_a_file_that_never_appears(tmp_path: Path) -> None:
    """A PPM that QEMU never writes exhausts the poll budget and is reported as unstable.

    Args:
        tmp_path: Pytest temporary directory.
    """
    with pytest.raises(SandboxError, match="PPM file did not stabilize before timeout"):
        await _TestableQEMUSandbox.wait_for_ppm_stable(tmp_path / "never_written.ppm")


@pytest.mark.asyncio
async def test_capture_screenshot_failure_reports_the_refused_screendump(shared_folder: Path) -> None:
    """A monitor that cannot take the screendump yields a screenshot failure.

    Args:
        shared_folder: Shared folder the screendump would be written into.
    """
    box = _sandbox(shared_folder)
    box.attach_qmp(QMPClient())

    with pytest.raises(SandboxError, match="screenshot capture failed"):
        await box.capture_screenshot()


@pytest.mark.asyncio
async def test_capture_screenshot_converts_the_screendump_to_png(shared_folder: Path) -> None:
    """The PPM QEMU writes becomes a PNG of the same size beside it, and the PPM is removed.

    Args:
        shared_folder: Shared folder the screendump is written into.
    """
    ppm = b"P6\n2 1\n255\n" + bytes([255, 0, 0, 0, 0, 255])
    qmp = _ScriptedQMP({"screendump": [_ok({})]}, writes={"screendump": ppm})
    box = _sandbox(shared_folder)
    box.attach_qmp(qmp)

    result = await box.capture_screenshot()

    output = shared_folder / "output"
    assert result.parent == output
    assert re.fullmatch(r"screenshot_[0-9a-f]{16}\.png", result.name)
    png = result.read_bytes()
    assert png[:8] == PNG_SIGNATURE
    assert struct.unpack(">II", png[16:24]) == (2, 1)
    assert list(output.glob("*.ppm")) == []
    assert _arguments(qmp.sent[0]) == {"filename": str(output / result.name.replace(".png", ".ppm"))}


@pytest.mark.asyncio
async def test_capture_screenshot_copies_the_png_to_the_requested_path(shared_folder: Path, tmp_path: Path) -> None:
    """With an output path the PNG is copied there, creating missing parent directories.

    Args:
        shared_folder: Shared folder the screendump is written into.
        tmp_path: Pytest temporary directory holding the export location.
    """
    ppm = b"P6\n1 1\n255\n\x10\x20\x30"
    qmp = _ScriptedQMP({"screendump": [_ok({})]}, writes={"screendump": ppm})
    box = _sandbox(shared_folder)
    box.attach_qmp(qmp)
    export = tmp_path / "export" / "nested" / "screen.png"

    result = await box.capture_screenshot(export)

    assert result == export
    exported = export.read_bytes()
    assert exported[:8] == PNG_SIGNATURE
    assert struct.unpack(">II", exported[16:24]) == (1, 1)


@pytest.mark.asyncio
async def test_capture_screenshot_reports_a_malformed_ppm_as_a_conversion_failure(shared_folder: Path) -> None:
    """A screendump that is not a P6 PPM is reported as a failed conversion, not returned as an image.

    Args:
        shared_folder: Shared folder the screendump is written into.
    """
    qmp = _ScriptedQMP({"screendump": [_ok({})]}, writes={"screendump": b"P3\n1 1\n255\n0 0 0\n"})
    box = _sandbox(shared_folder)
    box.attach_qmp(qmp)

    with pytest.raises(SandboxError, match="PPM to PNG conversion failed") as raised:
        await box.capture_screenshot()

    assert isinstance(raised.value.__cause__, ValueError)
    assert list((shared_folder / "output").glob("*.png")) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("refusal", "expected"),
    [
        ("Dump already in progress", "memory dump failed: Dump already in progress"),
        (None, "memory dump failed: QEMU refused the request"),
    ],
    ids=["monitor-error", "no-error-text"],
)
async def test_dump_memory_reports_a_refused_request(shared_folder: Path, refusal: str | None, expected: str) -> None:
    """A dump the monitor refuses is reported with the monitor's reason, or a default when it gave none.

    Args:
        shared_folder: Shared folder the dump would be written into.
        refusal: Error text the monitor answers with.
        expected: Message the caller must see.
    """
    box = _sandbox(shared_folder)
    box.attach_qmp(_ScriptedQMP({"dump-guest-memory": [_refused(refusal)]}))

    with pytest.raises(SandboxError) as raised:
        await box.dump_memory(target_pid=4321)

    assert raised.value.message == expected


@pytest.mark.asyncio
async def test_dump_memory_waits_for_the_dump_and_returns_the_file(shared_folder: Path) -> None:
    """A detached dump is polled until it completes, then its file in the shared output is returned.

    Args:
        shared_folder: Shared folder the dump is written into.
    """
    memory = b"RAM-PAGE" * 8
    qmp = _ScriptedQMP(
        {
            "dump-guest-memory": [_ok({})],
            "query-dump": [
                _ok({"status": "active", "completed": 10, "total": 64}),
                _ok({"status": "completed", "completed": 64, "total": 64}),
            ],
        },
        writes={"dump-guest-memory": memory},
    )
    box = _sandbox(shared_folder)
    box.attach_qmp(qmp)

    result = await box.dump_memory(target_pid=77)

    assert result.parent == shared_folder / "output"
    assert re.fullmatch(r"memdump_[0-9a-f]{16}\.raw", result.name)
    assert result.read_bytes() == memory
    assert qmp.sent[0] == {
        "execute": "dump-guest-memory",
        "arguments": {"paging": False, "protocol": f"file:{result}", "detach": True},
    }
    assert qmp.commands == ["dump-guest-memory", "query-dump", "query-dump"]


@pytest.mark.asyncio
async def test_dump_memory_copies_the_dump_to_the_requested_path(shared_folder: Path, tmp_path: Path) -> None:
    """With an output path the dump is copied there, creating missing parent directories.

    Args:
        shared_folder: Shared folder the dump is written into.
        tmp_path: Pytest temporary directory holding the export location.
    """
    memory = b"\x00\x01\x02\x03" * 16
    qmp = _ScriptedQMP(
        {"dump-guest-memory": [_ok({})], "query-dump": [_ok({"status": "completed", "completed": 64})]},
        writes={"dump-guest-memory": memory},
    )
    box = _sandbox(shared_folder)
    box.attach_qmp(qmp)
    export = tmp_path / "export" / "nested" / "guest.raw"

    result = await box.dump_memory(export)

    assert result == export
    assert export.read_bytes() == memory


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_reply", "expected"),
    [
        (_refused("Command not supported"), "memory dump failed: Command not supported"),
        (_ok("not a mapping"), "memory dump failed: the dump status could not be read, so the outcome is unknown"),
    ],
    ids=["status-query-refused", "status-not-a-mapping"],
)
async def test_dump_memory_reports_an_unreadable_dump_status(
    shared_folder: Path,
    status_reply: QMPResponse,
    expected: str,
) -> None:
    """A dump whose progress cannot be read is reported instead of being assumed complete.

    Args:
        shared_folder: Shared folder the dump is written into.
        status_reply: What the monitor answers to ``query-dump``.
        expected: Message the caller must see.
    """
    box = _sandbox(shared_folder)
    box.attach_qmp(_ScriptedQMP({"dump-guest-memory": [_ok({})], "query-dump": [status_reply]}))

    with pytest.raises(SandboxError) as raised:
        await box.dump_memory()

    assert raised.value.message == expected


@pytest.mark.asyncio
async def test_dump_memory_reports_a_dump_qemu_says_failed(shared_folder: Path) -> None:
    """A status other than active, none or completed is reported with the status QEMU gave.

    Args:
        shared_folder: Shared folder the dump is written into.
    """
    box = _sandbox(shared_folder)
    box.attach_qmp(_ScriptedQMP({"dump-guest-memory": [_ok({})], "query-dump": [_ok({"status": "failed"})]}))

    with pytest.raises(SandboxError) as raised:
        await box.dump_memory()

    assert raised.value.message == "memory dump failed: QEMU reported the dump as failed"


@pytest.mark.asyncio
async def test_dump_memory_reports_a_completed_dump_that_wrote_nothing(shared_folder: Path) -> None:
    """A dump QEMU calls complete but whose file is empty is a failure, not a success.

    Args:
        shared_folder: Shared folder the dump is written into.
    """
    qmp = _ScriptedQMP(
        {"dump-guest-memory": [_ok({})], "query-dump": [_ok({"status": "completed", "completed": 0})]},
        writes={"dump-guest-memory": b""},
    )
    box = _sandbox(shared_folder)
    box.attach_qmp(qmp)

    with pytest.raises(SandboxError) as raised:
        await box.dump_memory()

    prefix = "memory dump failed: QEMU reported the dump as complete but wrote nothing to "
    assert raised.value.message.startswith(prefix)
    assert re.fullmatch(r".*memdump_[0-9a-f]{16}\.raw", raised.value.message.removeprefix(prefix))


@pytest.mark.asyncio
async def test_dump_memory_times_out_and_reports_the_progress_made(shared_folder: Path) -> None:
    """A dump still running when the budget ends is reported with how much it had written.

    Args:
        shared_folder: Shared folder the dump is written into.
    """
    box = _sandbox(shared_folder, qemu_config=QEMUConfig(memory_dump_timeout=1.0))
    box.attach_qmp(_ScriptedQMP({"dump-guest-memory": [_ok({})], "query-dump": [_ok({"status": "active", "completed": 7})]}))

    with pytest.raises(SandboxError) as raised:
        await box.dump_memory()

    assert raised.value.message == "memory dump failed: the dump had written 7 bytes and was still running after 1s"


@pytest.mark.asyncio
async def test_extract_dropped_files_refuses_when_the_sandbox_is_not_running(shared_folder: Path) -> None:
    """A sandbox that never started has nothing to extract from.

    Args:
        shared_folder: Shared folder, so only the run state is wrong.
    """
    box = _sandbox(shared_folder)

    with pytest.raises(SandboxError, match="not running"):
        await box.extract_dropped_files()


@pytest.mark.asyncio
async def test_extract_dropped_files_refuses_without_a_shared_folder() -> None:
    """A running sandbox with no shared folder cannot stage extracted files."""
    box = _sandbox(None)
    box.state.status = "running"

    with pytest.raises(SandboxError, match="shared folder not init"):
        await box.extract_dropped_files()


def test_staging_root_needs_somewhere_on_the_host() -> None:
    """With neither a working directory nor a shared folder there is nowhere to stage into."""
    box = _sandbox(None)

    with pytest.raises(SandboxError, match="shared folder not init"):
        box.staging_root_for("0123456789abcdef")


@pytest.mark.asyncio
async def test_list_guest_directory_is_empty_when_the_listing_command_fails() -> None:
    """A guest listing that exits non-zero is how both listers say the directory holds nothing."""
    agent = _ScriptedAgent([(1, "", "File Not Found")])
    box = _sandbox(None)
    box.state.status = "running"
    box.attach_agent(agent)

    assert await box.list_guest_directory(GUEST_DROP_DIR) == []

    assert agent.calls[0][1][-1] == f'dir /b /s /a-d "{GUEST_DROP_DIR}"'


@pytest.mark.asyncio
async def test_pull_guest_directory_stops_at_the_file_cap(tmp_path: Path) -> None:
    """A listing longer than the per-extraction file cap is truncated, not pulled whole.

    Args:
        tmp_path: Pytest temporary directory the files are pulled into.
    """
    listing = "\r\n".join(f"{GUEST_DROP_DIR}\\f{index:03d}.bin" for index in range(513))
    box = _sandbox(None)
    box.state.status = "running"
    box.attach_agent(_ScriptedAgent([(0, listing, "")]))
    box.attach_qga(_ScriptedQGA({}))
    destination = tmp_path / "pulled"

    pulled = await box.pull_guest_directory(GUEST_DROP_DIR, destination)

    assert pulled == 512
    assert len(list(destination.iterdir())) == 512
    assert (destination / "f511.bin").read_bytes() == b"x"
    assert not (destination / "f512.bin").exists()


@pytest.mark.asyncio
async def test_pull_guest_directory_skips_the_root_entry_and_unreadable_files(tmp_path: Path) -> None:
    """The directory's own entry and a file the agent refuses to open are skipped, not fatal.

    Args:
        tmp_path: Pytest temporary directory the files are pulled into.
    """
    locked = f"{GUEST_DROP_DIR}\\locked.bin"
    readable = f"{GUEST_DROP_DIR}\\sub\\ok.bin"
    listing = "\r\n".join([f"{GUEST_DROP_DIR}\\", locked, readable])
    qga = _ScriptedQGA({readable: b"payload"}, refuse_open=frozenset({locked}))
    box = _sandbox(None)
    box.state.status = "running"
    box.attach_agent(_ScriptedAgent([(0, listing, "")]))
    box.attach_qga(qga)
    destination = tmp_path / "pulled"

    pulled = await box.pull_guest_directory(GUEST_DROP_DIR, destination)

    assert pulled == 1
    assert (destination / "sub" / "ok.bin").read_bytes() == b"payload"
    assert not (destination / "locked.bin").exists()
    assert qga.opened == [locked, readable]


@pytest.mark.asyncio
async def test_host_collect_dropped_files_without_a_shared_folder_copies_nothing(tmp_path: Path) -> None:
    """With no shared folder there is no mirror to copy from, and the staging directory stays empty.

    Args:
        tmp_path: Pytest temporary directory holding the staging directory.
    """
    staging = tmp_path / "staging"
    staging.mkdir()
    box = _sandbox(None)

    await box.host_collect_dropped_files(staging)

    assert list(staging.iterdir()) == []


def test_count_files_recursive_is_zero_for_a_missing_directory(tmp_path: Path) -> None:
    """A directory that does not exist holds no files, while a populated one counts only files.

    Args:
        tmp_path: Pytest temporary directory.
    """
    populated = tmp_path / "populated"
    (populated / "sub").mkdir(parents=True)
    (populated / "a.bin").write_bytes(b"1")
    (populated / "sub" / "b.bin").write_bytes(b"2")

    assert _TestableQEMUSandbox.count_files_recursive(tmp_path / "missing") == 0
    assert _TestableQEMUSandbox.count_files_recursive(populated) == 2


@pytest.mark.asyncio
async def test_yara_scan_refuses_without_a_shared_folder() -> None:
    """A scan needs the shared folder's output directory, so without one it is refused."""
    box = _sandbox(None)

    with pytest.raises(SandboxError, match="shared folder not init"):
        await box.yara_scan()
