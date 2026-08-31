# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S17-D31 and S17-D32: the Linux guest must fill two report tabs.

The Sandbox panel renders seventeen report tabs from the monitor logs the
in-guest agent leaves in the shared folder. Two of them were permanently empty
whenever the QEMU guest ran Linux:

* **S17-D31, Network Activity.** :meth:`QEMUSandbox._collect_monitoring_logs`
  only ever reads ``network_activity.log``, and that file was written
  exclusively by the Windows PowerShell agent. The generated Linux agent wrote
  ``file_changes.log`` and ``process_activity.log`` and nothing else, so the tab
  had no rows to draw however much the guest talked to the network.
* **S17-D32, Resources.** The same shape, for ``resource_monitor.log``: the
  bundled ``resource_monitor.ps1`` produced it on Windows and no Linux
  equivalent existed.

Neither gap is a Linux limitation - ``/proc`` carries every field both schemas
need - so both are gated here against the real thing rather than declared not
applicable.

Nothing in this module restates what the agent should do. The collection code
under test is lifted verbatim out of the ``agent.py`` source the application
itself generates (:meth:`QEMUSandbox._create_guest_agent_script`) with
:func:`ast.get_source_segment` and imported as a real module, following
:mod:`tests.sandbox.qemu.test_guest_agent_readiness_s17d25`. It is then run
against real ``/proc``-shaped trees - real files, and real ``socket:[inode]``
symlinks in the per-process descriptor directories - and the records it emits
are read back through the real host-side reader,
:meth:`QEMUSandbox._collect_monitoring_logs`, which is the exact path both tabs
are populated from. Because the guest's own log name is what the record is
written under and the host's own reader is what parses it back, a name or a
field the agent renders wrongly cannot survive the round trip.

The expected values are derived from the two log schemas, which are not this
module's to invent: ten pipe-delimited fields for
:func:`intellicrack.sandbox.log_parsers.parse_network_log`
(``timestamp|operation|local|remote|state|protocol|bytes_sent|bytes_received|pid|process_name``)
and seven for :func:`intellicrack.sandbox.log_parsers.parse_resource_log`
(``timestamp|cpu_percent|memory_mb|disk_read|disk_write|net_sent|net_recv``),
with the state vocabulary and the two unavailable byte columns taken from the
canonical Windows monitors in ``sandbox/scripts``.
"""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import logging
import math
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.log_helpers import split_addr_port
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

    from intellicrack.sandbox.base import NetworkActivity, ResourceSample


_MONITOR_DIRECTORY: Final[str] = "monitor"
_LINUX_AGENT_NAME: Final[str] = "agent.py"
_LOGS_DIRECTORY: Final[str] = "logs"
_COLLECTED_DIRECTORY: Final[str] = "collected"
_SHARE_DIRECTORY: Final[str] = "share"

_LOGGER_NAME: Final[str] = "_logger"
_LOG_DIR_NAME: Final[str] = "LOG_DIR"
_NETWORK_LOG_CONSTANT: Final[str] = "NETWORK_LOG_NAME"
_RESOURCE_LOG_CONSTANT: Final[str] = "RESOURCE_LOG_NAME"
_POLL_INTERVAL_CONSTANT: Final[str] = "MONITOR_POLL_INTERVAL"
_SAMPLE_INTERVAL_CONSTANT: Final[str] = "RESOURCE_SAMPLE_INTERVAL"
_COLLECT_NETWORK_NAME: Final[str] = "collect_network_records"
_APPEND_LOG_NAME: Final[str] = "_append_log"
_READ_COUNTERS_NAME: Final[str] = "read_resource_counters"
_READ_MEMORY_NAME: Final[str] = "read_memory_used_mb"
_READ_DISK_NAME: Final[str] = "read_disk_totals"
_FORMAT_SAMPLE_NAME: Final[str] = "format_resource_sample"
_NETWORK_MONITOR_NAME: Final[str] = "network_monitor"
_RESOURCE_MONITOR_NAME: Final[str] = "resource_monitor"
_FILE_MONITOR_NAME: Final[str] = "file_monitor"
_PROCESS_MONITOR_NAME: Final[str] = "process_monitor"
_MAIN_NAME: Final[str] = "main"
_RESOURCE_STARTED_MESSAGE: Final[str] = "resource_monitoring_started"

_ERR_NO_DEFINITION: Final[str] = "the generated Linux agent defines no {name}"
_ERR_NOT_IMPORTABLE: Final[str] = "the generated Linux agent source could not be imported"

_NETWORK_FIELD_COUNT: Final[int] = 10
_RESOURCE_FIELD_COUNT: Final[int] = 7
_OPERATION_FIELD_INDEX: Final[int] = 1
_LOCAL_FIELD_INDEX: Final[int] = 2
_REMOTE_FIELD_INDEX: Final[int] = 3
_STATE_FIELD_INDEX: Final[int] = 4
_BYTES_SENT_FIELD_INDEX: Final[int] = 6
_BYTES_RECEIVED_FIELD_INDEX: Final[int] = 7
_PID_FIELD_INDEX: Final[int] = 8
_PROCESS_NAME_FIELD_INDEX: Final[int] = 9

_UDP_BIND_ENDPOINT: Final[str] = "0.0.0.0:53"
_TIMESTAMP: Final[str] = "2026-08-06 12:00:00"
_ELAPSED_SECONDS: Final[float] = 2.0
_EXPECTED_CONNECTION_COUNT: Final[int] = 5

# Every expectation below is derived by hand from the two /proc snapshots in
# this module, never from the agent's own output: 600 busy of 1400 elapsed
# ticks, 2048000 minus 1024000 kibibytes, and the counter deltas over the two
# seconds between readings.
_EXPECTED_CPU_PERCENT: Final[float] = 42.86
_EXPECTED_MEMORY_MB: Final[float] = 1000.0
_EXPECTED_DISK_READ_RATE: Final[int] = 256000
_EXPECTED_DISK_WRITE_RATE: Final[int] = 256000
_EXPECTED_NET_SENT_RATE: Final[int] = 50000
_EXPECTED_NET_RECV_RATE: Final[int] = 100000
_EXPECTED_DISK_READ_TOTAL: Final[int] = 1024000
_EXPECTED_DISK_WRITE_TOTAL: Final[int] = 2048000
_RAW_CPU_TICK_DELTA: Final[float] = 1400.0
_CPU_PERCENT_CEILING: Final[float] = 100.0

_FALLBACK_READ_BYTES: Final[int] = 40960
_FALLBACK_WRITE_BYTES: Final[int] = 12288

_LOOP_POLL_INTERVAL_S: Final[float] = 0.05
_LOOP_SAMPLE_INTERVAL_S: Final[float] = 0.5
_LOOP_PARKED_INTERVAL_S: Final[float] = 3600.0
_LOOP_DEADLINE_S: Final[float] = 30.0
_LOOP_WAIT_STEP_S: Final[float] = 0.05
_REAL_PROC_SAMPLE_GAP_S: Final[float] = 0.5

_REAL_PROC_STAT: Final[Path] = Path("/proc/stat")

_PROC_NET_TCP: Final[str] = (
    "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n"
    "   0: 0A01A8C0:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100001 1 ffff8f0b1c2d3e4f 100 0 0 10 0\n"
    "   1: 0A01A8C0:C000 057100CB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 100002 1 ffff8f0b1c2d3e50 20 4 30 10 -1\n"
)

_PROC_NET_TCP6: Final[str] = (
    "  sl  local_address                         remote_address                        st tx_queue:rx_queue"
    " tr:tm->when retrnsmt   uid  timeout inode\n"
    "   0: B80D0120000000000000000005000000:A1D6 B80D0120000000000000000001000000:0050 01 00000000:00000000"
    " 00:00000000 00000000  1000        0 100004 1 ffff8f0b1c2d3e51 20 4 30 10 -1\n"
)

_PROC_NET_UDP: Final[str] = (
    "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
    "  100: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 100003 2 ffff8f0b1c2d3e52 0\n"
)

_PROC_NET_UDP6: Final[str] = (
    "  sl  local_address                         remote_address                        st tx_queue:rx_queue"
    " tr:tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
    "    5: 00000000000000000000000000000000:14E9 B80D0120000000000000000001000000:0043 01 00000000:00000000"
    " 00:00000000 00000000     0        0 100005 2 ffff8f0b1c2d3e53 0\n"
)

_PROC_STAT_FIRST: Final[str] = "cpu  1000 0 500 8000 500 0 0 0 0 0\ncpu0 500 0 250 4000 250 0 0 0 0 0\nintr 12345 0 0\nctxt 987654\n"

_PROC_STAT_SECOND: Final[str] = "cpu  1400 0 700 8600 700 0 0 0 0 0\ncpu0 700 0 350 4300 350 0 0 0 0 0\nintr 22345 0 0\nctxt 1187654\n"

_PROC_MEMINFO: Final[str] = "MemTotal:        2048000 kB\nMemFree:          512000 kB\nMemAvailable:    1024000 kB\nBuffers:  16000 kB\n"

_PROC_DISKSTATS_FIRST: Final[str] = (
    "   8       0 sda 100 0 2000 50 200 0 4000 60 0 100 110 0 0 0 0 0 0\n"
    "   8       1 sda1 50 0 1000 25 100 0 2000 30 0 50 55 0 0 0 0 0 0\n"
    "   7       0 loop0 10 0 100 5 0 0 0 0 0 5 5 0 0 0 0 0 0\n"
)

_PROC_DISKSTATS_SECOND: Final[str] = (
    "   8       0 sda 150 0 3000 70 260 0 5000 90 0 140 160 0 0 0 0 0 0\n"
    "   8       1 sda1 70 0 1500 35 130 0 2500 45 0 70 80 0 0 0 0 0 0\n"
    "   7       0 loop0 10 0 100 5 0 0 0 0 0 5 5 0 0 0 0 0 0\n"
)

_PROC_NET_DEV_FIRST: Final[str] = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "    lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0\n"
    "  eth0:  500000     400    0    0    0     0          0         0   250000     300    0    0    0     0       0          0\n"
)

_PROC_NET_DEV_SECOND: Final[str] = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "    lo:    9000      90    0    0    0     0          0         0     9000      90    0    0    0     0       0          0\n"
    "  eth0:  700000     600    0    0    0     0          0         0   350000     420    0    0    0     0       0          0\n"
)

_PROC_IO_FIRST: Final[str] = "rchar: 90000\nwchar: 30000\nread_bytes: 32768\nwrite_bytes: 8192\ncancelled_write_bytes: 0\n"

_PROC_IO_SECOND: Final[str] = "rchar: 20000\nwchar: 9000\nread_bytes: 8192\nwrite_bytes: 4096\ncancelled_write_bytes: 0\n"

_SOCKET_OWNERS: Final[tuple[tuple[str, str, tuple[str, ...]], ...]] = (
    ("1234", "payload.elf", ("100001", "100002")),
    ("1500", "resolver", ("100003",)),
)


class _LinuxAgentSandbox(QEMUSandbox):
    """``QEMUSandbox`` used only to generate the real Linux guest agent."""

    async def generate_linux_agent(self, share: Path) -> str:
        """Write the production Linux agent into ``share`` and read it back.

        Args:
            share: Host directory standing in for the guest's shared folder.

        Returns:
            str: Full source of the generated ``agent.py``.
        """
        self._shared_folder = share
        await asyncio.to_thread((share / _MONITOR_DIRECTORY).mkdir, parents=True, exist_ok=True)
        await self._create_guest_agent_script()
        return await asyncio.to_thread(
            (share / _MONITOR_DIRECTORY / _LINUX_AGENT_NAME).read_text,
            encoding="utf-8",
        )


class _ReportReadingSandbox(QEMUSandbox):
    """``QEMUSandbox`` that reads monitor logs from a chosen shared folder."""

    def use_workspace(self, temp_dir: Path, share: Path) -> None:
        """Point the sandbox at its working directory and its shared folder.

        Since S17-D69 the guest writes its logs to its own disk - the share is
        read-only to it, because vvfat's write-back path aborts the machine -
        and the host pulls them into the working directory's ``collected``
        tree, which is where the reader looks.

        Args:
            temp_dir: Working directory whose ``collected`` tree holds the
                logs pulled back from the guest.
            share: Shared folder root the agent scripts were staged into.
        """
        self._temp_dir = temp_dir
        self._shared_folder = share

    async def collect_network_activity(self) -> list[NetworkActivity]:
        """Parse the guest's network log through the real host-side reader.

        Returns:
            list[NetworkActivity]: Records the report's Network Activity tab draws.
        """
        return (await self._collect_monitoring_logs()).network_activity

    async def collect_resource_samples(self) -> list[ResourceSample]:
        """Parse the guest's resource log through the real host-side reader.

        Returns:
            list[ResourceSample]: Samples the report's Resources tab draws.
        """
        return (await self._collect_monitoring_logs()).resource_samples


class _MonitorStartSignal(logging.Handler):
    """Handler that signals when the agent reports a monitor has started."""

    def __init__(self, message: str) -> None:
        """Watch the agent's logger for one startup message.

        Args:
            message: Message the monitor emits once its first reading is taken.
        """
        super().__init__(level=logging.INFO)
        self._message = message
        self.started = threading.Event()

    def emit(self, record: logging.LogRecord) -> None:
        """Set the event when the awaited message arrives.

        Args:
            record: Log record the agent emitted.
        """
        if record.getMessage() == self._message:
            self.started.set()


def _lift_agent_module(script: str, module_path: Path) -> ModuleType:
    """Import every definition the generated Linux agent makes, verbatim.

    Each import, module constant and function of the generated ``agent.py`` is
    copied out with :func:`ast.get_source_segment` in its original order and
    imported as a real module. Only two statements are left behind: the
    ``logging.basicConfig`` call, which opens a handler on the guest's own log
    directory, and the ``__main__`` guard, which would bind the guest's port.
    Nothing else is rewritten, so collection code that is missing or broken in
    the generated source is missing or broken here.

    Args:
        script: Full source of the generated ``agent.py``.
        module_path: File the lifted source is written to before import.

    Returns:
        ModuleType: The imported agent module.

    Raises:
        AssertionError: If a lifted statement has no recoverable source, or the
            lifted module cannot be imported.
    """
    kept: list[str] = []
    for node in ast.parse(script).body:
        if isinstance(node, ast.Expr | ast.If):
            continue
        segment = ast.get_source_segment(script, node)
        if segment is None:
            raise AssertionError(_ERR_NOT_IMPORTABLE)
        kept.append(segment)
    module_path.write_text("\n".join(kept), encoding="utf-8")
    spec = importlib.util.spec_from_file_location(module_path.stem, module_path)
    if spec is None or spec.loader is None:
        raise AssertionError(_ERR_NOT_IMPORTABLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _agent_attribute(module: ModuleType, name: str) -> object:
    """Return one attribute the generated agent defines.

    Args:
        module: Imported agent module.
        name: Attribute the caller needs.

    Returns:
        object: The attribute value.

    Raises:
        AssertionError: If the generated agent defines no such name.
    """
    if not hasattr(module, name):
        raise AssertionError(_ERR_NO_DEFINITION.format(name=name))
    return getattr(module, name)


def _thread_targets(script: str) -> set[str]:
    """Collect the names the generated agent's ``main`` starts threads on.

    Args:
        script: Full source of the generated ``agent.py``.

    Returns:
        set[str]: Every name passed as a ``threading.Thread`` target.

    Raises:
        AssertionError: If the generated agent defines no ``main``.
    """
    for node in ast.parse(script).body:
        if not (isinstance(node, ast.FunctionDef) and node.name == _MAIN_NAME):
            continue
        targets: set[str] = set()
        for inner in ast.walk(node):
            if not (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute) and inner.func.attr == "Thread"):
                continue
            for keyword in inner.keywords:
                if keyword.arg == "target" and isinstance(keyword.value, ast.Name):
                    targets.add(keyword.value.id)
        return targets
    raise AssertionError(_ERR_NO_DEFINITION.format(name=_MAIN_NAME))


def _write_proc_files(root: Path, files: dict[str, str]) -> None:
    """Write a set of relative paths under a ``/proc``-shaped tree.

    Args:
        root: Root of the tree standing in for the proc filesystem.
        files: Mapping of relative path to file contents.
    """
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _write_socket_owners(root: Path) -> None:
    """Create real per-process descriptor links for the fixture sockets.

    The links are genuine symlinks whose targets are the ``socket:[inode]``
    strings the kernel publishes, so the agent's own ``readlink`` walk is what
    resolves them.

    Args:
        root: Root of the tree standing in for the proc filesystem.
    """
    descriptor = 3
    for pid, name, inodes in _SOCKET_OWNERS:
        fd_dir = root / pid / "fd"
        fd_dir.mkdir(parents=True, exist_ok=True)
        (root / pid / "comm").write_text(name + "\n", encoding="utf-8")
        for inode in inodes:
            (fd_dir / str(descriptor)).symlink_to("socket:[" + inode + "]")
            descriptor += 1


def _network_proc_tree(root: Path) -> Path:
    """Build a proc tree carrying the four kernel socket tables.

    Args:
        root: Directory the tree is created in.

    Returns:
        Path: Root of the created tree.
    """
    _write_proc_files(
        root,
        {
            "net/tcp": _PROC_NET_TCP,
            "net/tcp6": _PROC_NET_TCP6,
            "net/udp": _PROC_NET_UDP,
            "net/udp6": _PROC_NET_UDP6,
        },
    )
    (root / "self").mkdir(parents=True, exist_ok=True)
    _write_socket_owners(root)
    return root


def _resource_proc_tree(root: Path, *, second_sample: bool) -> Path:
    """Build a proc tree carrying one resource-counter snapshot.

    Args:
        root: Directory the tree is created in.
        second_sample: Whether to write the later of the two snapshots.

    Returns:
        Path: Root of the created tree.
    """
    _write_proc_files(
        root,
        {
            "stat": _PROC_STAT_SECOND if second_sample else _PROC_STAT_FIRST,
            "meminfo": _PROC_MEMINFO,
            "diskstats": _PROC_DISKSTATS_SECOND if second_sample else _PROC_DISKSTATS_FIRST,
            "net/dev": _PROC_NET_DEV_SECOND if second_sample else _PROC_NET_DEV_FIRST,
        },
    )
    return root


def _host_reader(tmp_path: Path) -> _ReportReadingSandbox:
    """Build the sandbox whose host-side reader parses the guest's logs.

    Args:
        tmp_path: Directory the shared folder lives under.

    Returns:
        _ReportReadingSandbox: Sandbox pointed at that shared folder.
    """
    sandbox = _ReportReadingSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.LINUX))
    sandbox.use_workspace(tmp_path, tmp_path / _SHARE_DIRECTORY)
    return sandbox


async def _agent_module_for(tmp_path: Path) -> ModuleType:
    """Generate the Linux agent and import its definitions.

    Args:
        tmp_path: Directory the shared folder and lifted module live under.

    Returns:
        ModuleType: The imported agent module, logging into the directory the
        host collects the guest's logs into.
    """
    sandbox = _LinuxAgentSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.LINUX))
    share = tmp_path / _SHARE_DIRECTORY
    script = await sandbox.generate_linux_agent(share)
    module = _lift_agent_module(script, tmp_path / "lifted_agent.py")
    # The real agent's own LOG_DIR is on the guest's disk, which this host
    # cannot be; it is redirected to where the host's collection deposits what
    # it pulled back out of the guest, which is where the reader looks.
    logs = tmp_path / _COLLECTED_DIRECTORY / _LOGS_DIRECTORY
    logs.mkdir(parents=True, exist_ok=True)
    setattr(module, _LOG_DIR_NAME, logs)
    return module


def _collector(module: ModuleType) -> Callable[[str, dict[str, bool], Path], list[str]]:
    """Return the generated agent's own network collection function.

    Args:
        module: Imported agent module.

    Returns:
        Callable[[str, dict[str, bool], Path], list[str]]: The collector.
    """
    return cast("Callable[[str, dict[str, bool], Path], list[str]]", _agent_attribute(module, _COLLECT_NETWORK_NAME))


def _appender(module: ModuleType) -> Callable[[str, str], None]:
    """Return the generated agent's own monitor-log append function.

    Args:
        module: Imported agent module.

    Returns:
        Callable[[str, str], None]: The append function.
    """
    return cast("Callable[[str, str], None]", _agent_attribute(module, _APPEND_LOG_NAME))


def _log_path(module: ModuleType, log_constant: str) -> Path:
    """Return the file the generated agent appends one monitor log to.

    Args:
        module: Imported agent module.
        log_constant: Name of the agent constant holding the log file name.

    Returns:
        Path: Full path of the log file inside the shared folder.
    """
    log_dir = cast("Path", _agent_attribute(module, _LOG_DIR_NAME))
    return log_dir / cast("str", _agent_attribute(module, log_constant))


def _wait_for_lines(path: Path, minimum: int, deadline: float) -> list[str]:
    """Wait until a log file holds at least ``minimum`` non-empty lines.

    Returning fewer lines than asked for is not an error here; the caller's
    assertion on the result is the gate.

    Args:
        path: Log file the monitor loop appends to.
        minimum: Number of lines the caller is waiting for.
        deadline: Maximum seconds to wait.

    Returns:
        list[str]: The lines present when the wait ended.
    """
    started = time.monotonic()
    lines: list[str] = []
    while time.monotonic() - started < deadline:
        if path.exists():
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if len(lines) >= minimum:
                return lines
        time.sleep(_LOOP_WAIT_STEP_S)
    return lines


def _watch_for_start(module: ModuleType, message: str) -> _MonitorStartSignal:
    """Attach a signal to the agent's own logger for one startup message.

    Args:
        module: Imported agent module.
        message: Startup message to wait for.

    Returns:
        _MonitorStartSignal: Handler whose event fires when the message arrives.
    """
    logger = cast("logging.Logger", _agent_attribute(module, _LOGGER_NAME))
    signal = _MonitorStartSignal(message)
    logger.addHandler(signal)
    logger.setLevel(logging.INFO)
    return signal


def _park_monitor_loop(module: ModuleType, interval_constant: str) -> None:
    """Stretch a monitor loop's interval so it stops polling after a test.

    The generated loops read their interval from a module constant on every
    iteration, so raising it leaves the daemon thread idle rather than spinning
    on a temporary directory for the rest of the session.

    Args:
        module: Imported agent module.
        interval_constant: Name of the interval constant to raise.
    """
    setattr(module, interval_constant, _LOOP_PARKED_INTERVAL_S)


def _by_endpoint(records: list[NetworkActivity]) -> dict[tuple[str, str, int], NetworkActivity]:
    """Index parsed network records by protocol and local endpoint.

    Args:
        records: Records the host-side parser produced.

    Returns:
        dict[tuple[str, str, int], NetworkActivity]: Mapping of protocol, local
        address and local port to the record describing that socket.
    """
    return {(record["protocol"], record["local_address"], record["local_port"]): record for record in records}


class TestNetworkActivityIsCollectedOnLinux:
    """S17-D31: the Linux agent must fill the Network Activity tab."""

    @pytest.mark.asyncio
    async def test_kernel_socket_tables_reach_the_host_report(self, tmp_path: Path) -> None:
        """Sockets in ``/proc`` must arrive as parsed network activity records.

        The whole defect path runs: the generated agent's own collection code
        reads real socket tables, its own append writes the shared log, and the
        real :meth:`QEMUSandbox._collect_monitoring_logs` - the reader the tab is
        drawn from - parses it back. Addresses, ports, protocol and direction are
        checked against the values the fixture's hexadecimal columns encode, so a
        byte order or a state decode that is wrong cannot pass.

        Args:
            tmp_path: Directory the fixtures are created under.
        """
        module = await _agent_module_for(tmp_path)
        log_name = cast("str", _agent_attribute(module, _NETWORK_LOG_CONSTANT))
        proc_root = _network_proc_tree(tmp_path / "proc")

        for record in _collector(module)(_TIMESTAMP, {}, proc_root):
            _appender(module)(log_name, record)
        activity = await _host_reader(tmp_path).collect_network_activity()
        parsed = _by_endpoint(activity)

        assert len(activity) == _EXPECTED_CONNECTION_COUNT, f"the five fixture sockets did not survive the round trip: {activity}"

        listening = parsed["tcp", "192.168.1.10", 8080]
        assert listening["direction"] == "inbound", "a listening socket must be reported inbound"
        assert listening["remote_port"] == 0

        outbound = parsed["tcp", "192.168.1.10", 49152]
        assert outbound["direction"] == "outbound"
        assert outbound["remote_address"] == "203.0.113.5", f"the remote address decoded wrongly: {outbound['remote_address']!r}"
        assert outbound["remote_port"] == 443

        v6 = parsed["tcp", "2001:db8::5", 41430]
        assert v6["remote_address"] == "2001:db8::1", f"the IPv6 remote address decoded wrongly: {v6['remote_address']!r}"
        assert v6["remote_port"] == 80

        bind_address, bind_port = split_addr_port(_UDP_BIND_ENDPOINT)
        bound_udp = parsed["udp", bind_address, bind_port]
        assert bound_udp["direction"] == "inbound", "an unconnected datagram socket must be reported inbound"

        connected_udp = parsed["udp", "::", 5353]
        assert connected_udp["direction"] == "outbound", "a connected datagram socket must not be reported as listening"
        assert connected_udp["remote_address"] == "2001:db8::1"

    @pytest.mark.asyncio
    async def test_socket_inodes_are_attributed_to_their_owning_process(self, tmp_path: Path) -> None:
        """Each record must name the process holding the socket, or nothing.

        The owner is resolved by reading real ``socket:[inode]`` descriptor
        links, so a record naming ``payload.elf`` can only come from the walk
        having found that process. The unowned socket proves the unknown case is
        reported as an empty field rather than guessed or dropped.

        Args:
            tmp_path: Directory the fixtures are created under.
        """
        module = await _agent_module_for(tmp_path)
        proc_root = _network_proc_tree(tmp_path / "proc")

        rows = [record.split("|") for record in _collector(module)(_TIMESTAMP, {}, proc_root)]
        owners = {
            (row[_LOCAL_FIELD_INDEX], row[_REMOTE_FIELD_INDEX]): (row[_PID_FIELD_INDEX], row[_PROCESS_NAME_FIELD_INDEX]) for row in rows
        }

        for row in rows:
            assert len(row) == _NETWORK_FIELD_COUNT, f"the schema needs ten fields, this record has {len(row)}: {row}"
            assert row[_BYTES_SENT_FIELD_INDEX] == "0", "the kernel exposes no per-socket byte counters; the column must not be invented"
            assert row[_BYTES_RECEIVED_FIELD_INDEX] == "0"

        assert owners["192.168.1.10:8080", "0.0.0.0:0"] == ("1234", "payload.elf"), f"the listening socket was misattributed: {owners}"
        assert owners["192.168.1.10:49152", "203.0.113.5:443"] == ("1234", "payload.elf")
        assert owners["0.0.0.0:53", "0.0.0.0:0"] == ("1500", "resolver")
        assert owners["[2001:db8::5]:41430", "[2001:db8::1]:80"] == ("", ""), (
            f"an unattributable socket must leave both owner fields empty: {owners}"
        )

    @pytest.mark.asyncio
    async def test_operation_and_state_use_the_windows_vocabulary(self, tmp_path: Path) -> None:
        """The state column must carry the names the Windows monitor emits.

        ``infer_direction`` keys off that vocabulary and the report is rendered
        from one schema whichever guest produced it, so a Linux-only spelling
        would silently turn every listener into an outbound connection.

        Args:
            tmp_path: Directory the fixtures are created under.
        """
        module = await _agent_module_for(tmp_path)
        proc_root = _network_proc_tree(tmp_path / "proc")

        rows = [record.split("|") for record in _collector(module)(_TIMESTAMP, {}, proc_root)]
        by_local = {row[_LOCAL_FIELD_INDEX]: row for row in rows}

        assert by_local["192.168.1.10:8080"][_STATE_FIELD_INDEX] == "Listen", f"state 0A is a listener: {by_local['192.168.1.10:8080']}"
        assert by_local["192.168.1.10:8080"][_OPERATION_FIELD_INDEX] == "connection"
        assert by_local["192.168.1.10:49152"][_STATE_FIELD_INDEX] == "Established", (
            f"state 01 is an established connection: {by_local['192.168.1.10:49152']}"
        )
        assert by_local["0.0.0.0:53"][_STATE_FIELD_INDEX] == "Listen", "an unconnected datagram socket is a bound listener"
        assert by_local["0.0.0.0:53"][_OPERATION_FIELD_INDEX] == "bind"
        assert by_local["[::]:5353"][_OPERATION_FIELD_INDEX] == "connection"
        assert by_local["[::]:5353"][_STATE_FIELD_INDEX] == "Established"

    @pytest.mark.asyncio
    async def test_a_socket_already_reported_is_not_reported_again(self, tmp_path: Path) -> None:
        """Polling must report each socket once, not once per poll.

        Args:
            tmp_path: Directory the fixtures are created under.
        """
        module = await _agent_module_for(tmp_path)
        proc_root = _network_proc_tree(tmp_path / "proc")
        seen: dict[str, bool] = {}

        first = _collector(module)(_TIMESTAMP, seen, proc_root)
        second = _collector(module)(_TIMESTAMP, seen, proc_root)

        assert len(first) == _EXPECTED_CONNECTION_COUNT, f"the first poll reported {len(first)} of five sockets"
        assert second == [], f"the second poll re-reported {len(second)} unchanged sockets"


class TestResourceUsageIsCollectedOnLinux:
    """S17-D32: the Linux agent must fill the Resources tab."""

    @pytest.mark.asyncio
    async def test_two_proc_snapshots_become_a_parsed_resource_sample(self, tmp_path: Path) -> None:
        """Counter deltas must arrive as a parsed sample in the host report.

        Reporting raw counters instead of deltas, or kernel ticks instead of a
        percentage, cannot produce the values derived from the two snapshots.

        Args:
            tmp_path: Directory the fixtures are created under.
        """
        module = await _agent_module_for(tmp_path)
        read_counters = cast("Callable[[Path], tuple[int, int, int, int, int, int]]", _agent_attribute(module, _READ_COUNTERS_NAME))
        read_memory = cast("Callable[[Path], float]", _agent_attribute(module, _READ_MEMORY_NAME))
        format_sample = cast(
            "Callable[[str, tuple[int, int, int, int, int, int], tuple[int, int, int, int, int, int], float, float], str]",
            _agent_attribute(module, _FORMAT_SAMPLE_NAME),
        )
        log_name = cast("str", _agent_attribute(module, _RESOURCE_LOG_CONSTANT))
        first = _resource_proc_tree(tmp_path / "proc_first", second_sample=False)
        second = _resource_proc_tree(tmp_path / "proc_second", second_sample=True)

        record = format_sample(_TIMESTAMP, read_counters(first), read_counters(second), _ELAPSED_SECONDS, read_memory(second))
        _appender(module)(log_name, record)
        samples = await _host_reader(tmp_path).collect_resource_samples()

        assert len(record.split("|")) == _RESOURCE_FIELD_COUNT, f"the schema needs seven fields, this record has {record!r}"
        assert len(samples) == 1, f"the sample did not survive the round trip: {samples}"

        sample = samples[0]
        assert math.isclose(sample["cpu_percent"], _EXPECTED_CPU_PERCENT), f"cpu_percent was {sample['cpu_percent']}"
        assert sample["cpu_percent"] <= _CPU_PERCENT_CEILING, "cpu_percent is not a percentage"
        assert not math.isclose(sample["cpu_percent"], _RAW_CPU_TICK_DELTA), "cpu_percent is the raw tick delta, not a percentage"
        assert math.isclose(sample["memory_mb"], _EXPECTED_MEMORY_MB), f"memory_mb was {sample['memory_mb']}"
        assert sample["disk_read_bytes"] == _EXPECTED_DISK_READ_RATE
        assert sample["disk_write_bytes"] == _EXPECTED_DISK_WRITE_RATE
        assert sample["net_sent_bytes"] == _EXPECTED_NET_SENT_RATE
        assert sample["net_recv_bytes"] == _EXPECTED_NET_RECV_RATE

    @pytest.mark.asyncio
    async def test_partitions_and_virtual_devices_are_not_double_counted(self, tmp_path: Path) -> None:
        """Only whole block devices may contribute to the disk totals.

        The fixture's ``sda1`` repeats part of ``sda`` and ``loop0`` is backed by
        a file on it, so counting either would inflate the totals.

        Args:
            tmp_path: Directory the fixtures are created under.
        """
        module = await _agent_module_for(tmp_path)
        read_disk = cast("Callable[[Path], tuple[int, int]]", _agent_attribute(module, _READ_DISK_NAME))
        proc_root = _resource_proc_tree(tmp_path / "proc", second_sample=False)

        read_bytes, write_bytes = read_disk(proc_root)

        assert read_bytes == _EXPECTED_DISK_READ_TOTAL, f"disk reads counted more than the whole device: {read_bytes}"
        assert write_bytes == _EXPECTED_DISK_WRITE_TOTAL, f"disk writes counted more than the whole device: {write_bytes}"

    @pytest.mark.asyncio
    async def test_per_process_io_covers_a_guest_without_block_statistics(self, tmp_path: Path) -> None:
        """With no block statistics the totals must come from per-process I/O.

        Args:
            tmp_path: Directory the fixtures are created under.
        """
        module = await _agent_module_for(tmp_path)
        read_disk = cast("Callable[[Path], tuple[int, int]]", _agent_attribute(module, _READ_DISK_NAME))
        proc_root = tmp_path / "proc"
        _write_proc_files(
            proc_root,
            {
                "stat": _PROC_STAT_FIRST,
                "meminfo": _PROC_MEMINFO,
                "net/dev": _PROC_NET_DEV_FIRST,
                "1234/io": _PROC_IO_FIRST,
                "1500/io": _PROC_IO_SECOND,
            },
        )

        read_bytes, write_bytes = read_disk(proc_root)

        assert read_bytes == _FALLBACK_READ_BYTES, f"the per-process fallback read total was {read_bytes}"
        assert write_bytes == _FALLBACK_WRITE_BYTES, f"the per-process fallback write total was {write_bytes}"

    @pytest.mark.skipif(not _REAL_PROC_STAT.exists(), reason="requires a running Linux kernel exposing /proc")
    @pytest.mark.asyncio
    async def test_real_proc_yields_a_live_sample(self, tmp_path: Path) -> None:
        """On a Linux runner the same code must sample the real kernel.

        Args:
            tmp_path: Directory the fixtures are created under.
        """
        module = await _agent_module_for(tmp_path)
        read_counters = cast("Callable[[Path], tuple[int, int, int, int, int, int]]", _agent_attribute(module, _READ_COUNTERS_NAME))
        read_memory = cast("Callable[[Path], float]", _agent_attribute(module, _READ_MEMORY_NAME))
        real_proc = _REAL_PROC_STAT.parent

        first = read_counters(real_proc)
        await asyncio.sleep(_REAL_PROC_SAMPLE_GAP_S)
        second = read_counters(real_proc)

        assert second[0] > first[0], "the real kernel tick counter did not advance between samples"
        assert read_memory(real_proc) > 0.0, "the real kernel reported no memory in use"


class TestBothMonitorsRunOnTheAgentLoop:
    """The collection must be wired into the agent the guest actually runs."""

    @pytest.mark.asyncio
    async def test_main_starts_the_network_and_resource_monitors(self, tmp_path: Path) -> None:
        """Both new monitors must be started beside the existing two.

        Collection code the agent never runs would leave both tabs exactly as
        empty as the defect left them.

        Args:
            tmp_path: Directory the shared folder is created under.
        """
        sandbox = _LinuxAgentSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.LINUX))
        script = await sandbox.generate_linux_agent(tmp_path / _SHARE_DIRECTORY)

        targets = _thread_targets(script)

        expected = {_FILE_MONITOR_NAME, _PROCESS_MONITOR_NAME, _NETWORK_MONITOR_NAME, _RESOURCE_MONITOR_NAME}
        assert expected <= targets, f"the generated agent starts only {sorted(targets)}"

    @pytest.mark.asyncio
    async def test_the_network_monitor_loop_writes_the_shared_log(self, tmp_path: Path) -> None:
        """The polling loop itself must append to ``network_activity.log``.

        The loop the guest runs is executed here against a real proc tree, and
        the file it leaves behind is parsed by the real host-side reader.

        Args:
            tmp_path: Directory the fixtures are created under.
        """
        module = await _agent_module_for(tmp_path)
        monitor = cast("Callable[[Path], None]", _agent_attribute(module, _NETWORK_MONITOR_NAME))
        setattr(module, _POLL_INTERVAL_CONSTANT, _LOOP_POLL_INTERVAL_S)
        proc_root = _network_proc_tree(tmp_path / "proc")
        log_path = _log_path(module, _NETWORK_LOG_CONSTANT)

        threading.Thread(target=monitor, args=(proc_root,), daemon=True).start()
        lines = _wait_for_lines(log_path, _EXPECTED_CONNECTION_COUNT, _LOOP_DEADLINE_S)
        _park_monitor_loop(module, _POLL_INTERVAL_CONSTANT)
        activity = await _host_reader(tmp_path).collect_network_activity()

        assert len(lines) == _EXPECTED_CONNECTION_COUNT, f"the loop wrote {len(lines)} records to {log_path} in {_LOOP_DEADLINE_S}s"
        assert len(activity) == _EXPECTED_CONNECTION_COUNT, "the loop's own output did not parse into network activity records"

    @pytest.mark.asyncio
    async def test_the_resource_monitor_loop_writes_the_shared_log(self, tmp_path: Path) -> None:
        """The sampling loop itself must append to ``resource_monitor.log``.

        The proc tree is advanced to its second snapshot only after the agent's
        own logger reports the loop has taken its first reading, so the sample
        that appears can only be the difference between two real readings.

        Args:
            tmp_path: Directory the fixtures are created under.
        """
        module = await _agent_module_for(tmp_path)
        monitor = cast("Callable[[Path], None]", _agent_attribute(module, _RESOURCE_MONITOR_NAME))
        setattr(module, _SAMPLE_INTERVAL_CONSTANT, _LOOP_SAMPLE_INTERVAL_S)
        proc_root = _resource_proc_tree(tmp_path / "proc", second_sample=False)
        log_path = _log_path(module, _RESOURCE_LOG_CONSTANT)
        signal = _watch_for_start(module, _RESOURCE_STARTED_MESSAGE)

        threading.Thread(target=monitor, args=(proc_root,), daemon=True).start()
        first_reading_taken = signal.started.wait(_LOOP_DEADLINE_S)
        _resource_proc_tree(proc_root, second_sample=True)
        lines = _wait_for_lines(log_path, 1, _LOOP_DEADLINE_S)
        _park_monitor_loop(module, _SAMPLE_INTERVAL_CONSTANT)
        samples = await _host_reader(tmp_path).collect_resource_samples()

        assert first_reading_taken, "the resource monitor never reported taking its first reading"
        assert lines, f"the resource monitor loop wrote nothing to {log_path} within {_LOOP_DEADLINE_S}s"
        assert samples, "the loop's own output did not parse into resource samples"
        assert math.isclose(samples[0]["cpu_percent"], _EXPECTED_CPU_PERCENT), (
            f"the loop did not compute the busy percentage between its two readings: {samples[0]}"
        )
