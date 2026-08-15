# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared sandbox monitor-log parsers.

The Windows Sandbox and QEMU sandbox both consume the same pipe-delimited log
files emitted by the in-guest monitor scripts under ``sandbox/scripts/``.
This module consolidates the line-level parsing into a single set of pure
async helpers so the two sandbox implementations stay in lock-step with the
guest agent log schemas.

Each parser accepts:
    * ``shared_folder``: optional path to the shared sandbox folder. When
      ``None`` (sandbox not yet initialised) the parser returns an empty list.
    * ``log_name``: file name of the log under ``<shared_folder>/logs/``.
      Both sandboxes use slightly different file names for the same schema
      (e.g. ``file_monitor.log`` vs ``file_changes.log``); the caller selects
      the right name.

All parsers are tolerant of malformed input: lines that fail length checks
are skipped silently while file-level errors are logged and an empty list is
returned. This matches the prior behaviour of both call sites and avoids
abandoning a partial report on a single bad line.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Final

from intellicrack.core.logging import get_logger
from intellicrack.sandbox.base import (
    ApiCall,
    ClipboardEvent,
    CollectorOutage,
    DllLoadEvent,
    FileChange,
    InjectionEvent,
    KernelObjectActivity,
    NetworkActivity,
    ProcessActivity,
    RegistryChange,
    ResourceSample,
    ServiceChange,
    validate_file_operation,
    validate_process_operation,
    validate_registry_operation,
)
from intellicrack.sandbox.log_helpers import (
    coerce_protocol,
    infer_direction,
    safe_float,
    safe_int,
    split_addr_port,
)


if TYPE_CHECKING:
    from pathlib import Path


_logger = get_logger(__name__)

# PowerShell's default Out-File/Add-Content encoding stamps a UTF-8
# byte-order-mark onto every in-guest monitor log. Decoding with
# "utf-8-sig" removes it from the file, and stripping it per line covers
# the logs this app did not write.
_BOM: Final[str] = "\ufeff"

FILE_LOG_MIN_PARTS: int = 3
REGISTRY_LOG_MIN_PARTS: int = 3
NETWORK_LOG_MIN_PARTS: int = 10
PROCESS_LOG_MIN_PARTS: int = 4
SERVICE_LOG_MIN_PARTS: int = 6
KERNEL_LOG_MIN_PARTS: int = 6
DLL_LOG_MIN_PARTS: int = 6
INJECTION_LOG_MIN_PARTS: int = 7
RESOURCE_LOG_MIN_PARTS: int = 7
CLIPBOARD_LOG_MIN_PARTS: int = 7
API_LOG_MIN_PARTS: int = 7
LIFECYCLE_LOG_MIN_PARTS: int = 4

_LIFECYCLE_STATE_IDX: Final[int] = 2
_LIFECYCLE_DETAIL_IDX: Final[int] = 3
_LIFECYCLE_STATE_STARTED: Final[str] = "started"
_LIFECYCLE_STATE_STOPPED: Final[str] = "stopped"
_LIFECYCLE_EXIT_CODE_RE: Final[re.Pattern[str]] = re.compile(r"exit_code=(-?\d+)")
_ERR_COLLECTOR_NEVER_STARTED: Final[str] = "never reported starting"

# The injection monitor has no channel but its own data log in which to report
# that its trace session died, so it writes the failure as a record whose type
# is this marker (``injection_monitor.ps1``, the catch around the session). It
# is telemetry about the collector, not about the sample, and reading it as an
# injection turns a dead collector into a critical finding against whatever
# happened to be running. The outage itself is not lost by skipping it here -
# it is reported through :func:`parse_collector_lifecycle`, which is the
# channel built for it.
_INJECTION_TYPE_COLLECTOR_ERROR: Final[str] = "ERROR"
_INJECTION_LOG_TYPE_IDX: Final[int] = 5

# ``api_trace.ps1`` is in exactly the position the injection monitor is above:
# its own data log is the only channel it has, so it writes its start marker,
# its stop marker and every fatal into ``api_trace.log`` as records. They carry
# the collector's marker in the process-name field and one of these names in
# the API-name field, and none of them is an API call. Read as data they turn a
# collector that captured nothing at all into a tab reporting API activity -
# live, a session that died before processing a single event still presented
# two "API calls" named ERROR and STOP. The outage is not lost by skipping them
# here; it is reported through :func:`parse_collector_lifecycle`.
_API_TRACE_COLLECTOR_MARKER: Final[str] = "tracer"
_API_TRACE_COLLECTOR_ERROR: Final[str] = "ERROR"
_API_TRACE_COLLECTOR_RECORDS: Final[frozenset[str]] = frozenset({"START", "STOP", _API_TRACE_COLLECTOR_ERROR})
_API_LOG_PROCESS_IDX: Final[int] = 1
_API_LOG_NAME_IDX: Final[int] = 3
_API_LOG_STAGE_IDX: Final[int] = 4
_API_LOG_DETAIL_IDX: Final[int] = 5

# Every collector the Windows agent stages that reports its own lifecycle, and
# so is the only kind that can be told apart from a sample that did nothing.
# All four are absent on a Linux guest, which is why the caller gates on the
# guest OS rather than this list. Measured live: the guest's launcher does not
# always get every monitor running - across six runs it started different
# subsets, once none at all - and while only the first two were listed here, a
# dll_monitor or kernel_object_monitor that never started produced an empty tab
# with nothing anywhere in the report to distinguish it from a clean run.
_API_TRACE_COLLECTOR: Final[str] = "api_trace"
_LIFECYCLE_LOG_SUFFIX: Final[str] = ".lifecycle.log"
_LIFECYCLE_COLLECTORS: Final[tuple[str, ...]] = (
    _API_TRACE_COLLECTOR,
    "injection_monitor",
    "dll_monitor",
    "kernel_object_monitor",
)

# The guest's monitor launcher records one line per collector it was asked to
# start, in the same pipe-delimited shape the collectors themselves use. It is
# the only account of why a collector never started: the collector cannot
# report a failure that happened before its first line of execution ran, so
# without this a launcher that skipped it and a collector that died at line one
# are indistinguishable from the host.
_LAUNCHER_LOG_NAME: Final[str] = "monitor_launcher.log"
# ``timestamp|monitor_launcher|<script>|<state>|<detail>`` - one field wider
# than a collector's own lifecycle line, because the launcher speaks about a
# collector rather than for itself.
_LAUNCHER_LOG_MIN_PARTS: Final[int] = 5
_LAUNCHER_NAME_IDX: Final[int] = 2
_LAUNCHER_STATE_IDX: Final[int] = 3
_LAUNCHER_DETAIL_IDX: Final[int] = 4
_LAUNCHER_SCRIPT_SUFFIX: Final[str] = ".ps1"
_LAUNCHER_STATE_MISSING: Final[str] = "missing"
_LAUNCHER_STATE_FAILED: Final[str] = "launch_failed"
_LAUNCHER_FAILURE_REASONS: Final[dict[str, str]] = {
    _LAUNCHER_STATE_MISSING: "the guest's monitor launcher found no script for it at",
    _LAUNCHER_STATE_FAILED: "the guest's monitor launcher could not start it:",
}

_FILE_LOG_OLD_PATH_IDX = 3
_FILE_LOG_SIZE_IDX = 4
_REGISTRY_LOG_VALUE_NAME_IDX = 3
_REGISTRY_LOG_VALUE_TYPE_IDX = 4
_REGISTRY_LOG_VALUE_DATA_IDX = 5
_PROCESS_LOG_PATH_IDX = 4
_PROCESS_LOG_CMD_IDX = 5
_PROCESS_LOG_PPID_IDX = 6
_PROCESS_LOG_EXIT_IDX = 7
_DLL_LOG_EVENT_ID_IDX = 6
_DLL_LOG_PAYLOAD_SCHEMA_IDX = 7


async def read_log_lines(shared_folder: Path | None, name: str) -> list[str]:
    """Read a log file under ``<shared_folder>/logs/<name>`` into stripped lines.

    Returns an empty list when ``shared_folder`` is ``None``, the log file does
    not exist, or the read fails. Read failures are logged at ``warning`` level.

    Args:
        shared_folder: Sandbox shared folder root, or ``None`` if not yet
            initialised.
        name: Log file name relative to ``<shared_folder>/logs/``.

    Returns:
        list[str]: Non-empty stripped lines from the log file.
    """
    if shared_folder is None:
        return []
    log_path = shared_folder / "logs" / name
    if not await asyncio.to_thread(log_path.exists):
        return []
    _logger.debug("sandbox_log_read_started", log=name, path=str(log_path))
    try:
        raw = await asyncio.to_thread(
            log_path.read_text,
            encoding="utf-8-sig",
            errors="ignore",
        )
    except OSError as err:
        _logger.warning("log_read_failed", log=name, error=str(err))
        return []
    return [line for line in (ln.strip().lstrip(_BOM) for ln in raw.splitlines()) if line]


async def parse_file_log(
    shared_folder: Path | None,
    log_name: str = "file_monitor.log",
) -> list[FileChange]:
    """Parse a file-monitor log into :class:`FileChange` records.

    Log format: ``timestamp|operation|path|old_path|size``. The ``old_path``
    and ``size`` fields are optional.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[FileChange]: Parsed file-system change records.
    """
    out: list[FileChange] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < FILE_LOG_MIN_PARTS:
            continue
        old_path: str | None = None
        if len(parts) > _FILE_LOG_OLD_PATH_IDX and parts[_FILE_LOG_OLD_PATH_IDX]:
            old_path = parts[_FILE_LOG_OLD_PATH_IDX]
        size: int | None = None
        if len(parts) > _FILE_LOG_SIZE_IDX and parts[_FILE_LOG_SIZE_IDX].isdigit():
            size = int(parts[_FILE_LOG_SIZE_IDX])
        out.append(
            FileChange(
                path=parts[2],
                operation=validate_file_operation(parts[1]),
                old_path=old_path,
                timestamp=parts[0],
                size=size,
            ),
        )
    return out


async def parse_registry_log(
    shared_folder: Path | None,
    log_name: str = "registry_monitor.log",
) -> list[RegistryChange]:
    """Parse a registry-monitor log into :class:`RegistryChange` records.

    Log format: ``timestamp|operation|key|value_name|value_type|value_data``.
    The trailing ``value_*`` fields are optional.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[RegistryChange]: Parsed registry change records.
    """
    out: list[RegistryChange] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < REGISTRY_LOG_MIN_PARTS:
            continue
        value_name: str | None = None
        if len(parts) > _REGISTRY_LOG_VALUE_NAME_IDX and parts[_REGISTRY_LOG_VALUE_NAME_IDX]:
            value_name = parts[_REGISTRY_LOG_VALUE_NAME_IDX]
        value_type: str | None = None
        if len(parts) > _REGISTRY_LOG_VALUE_TYPE_IDX and parts[_REGISTRY_LOG_VALUE_TYPE_IDX]:
            value_type = parts[_REGISTRY_LOG_VALUE_TYPE_IDX]
        value_data: str | None = None
        if len(parts) > _REGISTRY_LOG_VALUE_DATA_IDX and parts[_REGISTRY_LOG_VALUE_DATA_IDX]:
            value_data = parts[_REGISTRY_LOG_VALUE_DATA_IDX]
        out.append(
            RegistryChange(
                key=parts[2],
                value_name=value_name,
                operation=validate_registry_operation(parts[1]),
                value_type=value_type,
                value_data=value_data,
                timestamp=parts[0],
            ),
        )
    return out


async def parse_network_log(
    shared_folder: Path | None,
    log_name: str = "network_monitor.log",
) -> list[NetworkActivity]:
    """Parse a network-monitor log into :class:`NetworkActivity` records.

    Log format (10 fields):
    ``timestamp|operation|local_addr:port|remote_addr:port|state|protocol|
    bytes_sent|bytes_received|pid|process_name``.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[NetworkActivity]: Parsed network activity records.
    """
    out: list[NetworkActivity] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < NETWORK_LOG_MIN_PARTS:
            continue
        local_addr, local_port = split_addr_port(parts[2])
        remote_addr, remote_port = split_addr_port(parts[3])
        state = parts[4]
        protocol = coerce_protocol(parts[5])
        direction = infer_direction(state)
        out.append(
            NetworkActivity(
                protocol=protocol,
                direction=direction,
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                timestamp=parts[0],
                bytes_sent=safe_int(parts[6]),
                bytes_received=safe_int(parts[7]),
            ),
        )
    return out


async def parse_process_log(
    shared_folder: Path | None,
    log_name: str = "process_monitor.log",
) -> list[ProcessActivity]:
    """Parse a process-monitor log into :class:`ProcessActivity` records.

    Log format:
    ``timestamp|operation|pid|name|path|command_line|parent_pid|exit_code``.
    The trailing fields after ``name`` are optional.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[ProcessActivity]: Parsed process activity records.
    """
    out: list[ProcessActivity] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < PROCESS_LOG_MIN_PARTS:
            continue
        pid = safe_int(parts[2])
        path: str | None = None
        if len(parts) > _PROCESS_LOG_PATH_IDX and parts[_PROCESS_LOG_PATH_IDX]:
            path = parts[_PROCESS_LOG_PATH_IDX]
        cmd_line: str | None = None
        if len(parts) > _PROCESS_LOG_CMD_IDX and parts[_PROCESS_LOG_CMD_IDX]:
            cmd_line = parts[_PROCESS_LOG_CMD_IDX]
        parent_pid: int | None = None
        if len(parts) > _PROCESS_LOG_PPID_IDX and parts[_PROCESS_LOG_PPID_IDX]:
            parent_pid = safe_int(parts[_PROCESS_LOG_PPID_IDX])
        exit_code: int | None = None
        if len(parts) > _PROCESS_LOG_EXIT_IDX and parts[_PROCESS_LOG_EXIT_IDX] and parts[_PROCESS_LOG_EXIT_IDX].lstrip("-").isdigit():
            exit_code = int(parts[_PROCESS_LOG_EXIT_IDX])
        out.append(
            ProcessActivity(
                pid=pid,
                name=parts[3],
                path=path,
                command_line=cmd_line,
                parent_pid=parent_pid,
                operation=validate_process_operation(parts[1]),
                exit_code=exit_code,
                timestamp=parts[0],
            ),
        )
    return out


async def parse_service_log(
    shared_folder: Path | None,
    log_name: str = "service_monitor.log",
) -> list[ServiceChange]:
    """Parse a service-monitor log into :class:`ServiceChange` records.

    Log format:
    ``timestamp|operation|service_name|display_name|binary_path|start_type``.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[ServiceChange]: Parsed Windows service change records.
    """
    out: list[ServiceChange] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < SERVICE_LOG_MIN_PARTS:
            continue
        out.append(
            ServiceChange(
                service_name=parts[2],
                display_name=parts[3],
                binary_path=parts[4],
                start_type=parts[5],
                operation=parts[1],
                timestamp=parts[0],
            ),
        )
    return out


async def parse_kernel_object_log(
    shared_folder: Path | None,
    log_name: str = "kernel_object_monitor.log",
) -> list[KernelObjectActivity]:
    """Parse a kernel-object monitor log into :class:`KernelObjectActivity` records.

    Log format:
    ``timestamp|object_type|name|pid|process_name|operation``.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[KernelObjectActivity]: Parsed kernel-object activity records.
    """
    out: list[KernelObjectActivity] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < KERNEL_LOG_MIN_PARTS:
            continue
        out.append(
            KernelObjectActivity(
                object_type=parts[1],
                name=parts[2],
                pid=safe_int(parts[3]),
                process_name=parts[4],
                operation=parts[5],
                timestamp=parts[0],
            ),
        )
    return out


async def parse_dll_log(
    shared_folder: Path | None,
    log_name: str = "dll_monitor.log",
) -> list[DllLoadEvent]:
    """Parse a DLL-monitor log into :class:`DllLoadEvent` records.

    Log format (legacy 6-column): ``timestamp|pid|process_name|dll_path|base_address|size``.

    Log format (extended 8-column): ``timestamp|pid|process_name|dll_path|base_address|size|event_id|payload_schema``.

    The trailing ``event_id`` and ``payload_schema`` columns are populated by
    F-0019: when the image-load handler cannot resolve an image path from the
    payload field set, it emits a record with ``dll_path`` empty, the raw
    ETW event id, and the observed payload field names. Older monitor builds
    emit only the legacy 6 columns and both extension fields default to 0 /
    empty string.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[DllLoadEvent]: Parsed DLL-load events.
    """
    out: list[DllLoadEvent] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < DLL_LOG_MIN_PARTS:
            continue
        event_id_raw = parts[_DLL_LOG_EVENT_ID_IDX] if len(parts) > _DLL_LOG_EVENT_ID_IDX else ""
        payload_schema = parts[_DLL_LOG_PAYLOAD_SCHEMA_IDX] if len(parts) > _DLL_LOG_PAYLOAD_SCHEMA_IDX else ""
        event: DllLoadEvent = {
            "timestamp": parts[0],
            "pid": safe_int(parts[1]),
            "process_name": parts[2],
            "dll_path": parts[3],
            "base_address": parts[4],
            "size": safe_int(parts[5]),
            "event_id": safe_int(event_id_raw),
            "payload_schema": payload_schema,
        }
        out.append(event)
    return out


async def parse_injection_log(
    shared_folder: Path | None,
    log_name: str = "injection_monitor.log",
) -> list[InjectionEvent]:
    """Parse an injection-monitor log into :class:`InjectionEvent` records.

    Log format:
    ``timestamp|source_pid|source_name|target_pid|target_name|injection_type|api_calls``.
    The ``api_calls`` field is a comma-separated list of API names.

    Records the monitor wrote about *itself* are not injections and are left
    out: see :data:`_INJECTION_TYPE_COLLECTOR_ERROR`.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[InjectionEvent]: Parsed process-injection events.
    """
    out: list[InjectionEvent] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < INJECTION_LOG_MIN_PARTS:
            continue
        if parts[_INJECTION_LOG_TYPE_IDX] == _INJECTION_TYPE_COLLECTOR_ERROR:
            continue
        api_calls = [c.strip() for c in parts[6].split(",") if c.strip()]
        out.append(
            InjectionEvent(
                timestamp=parts[0],
                source_pid=safe_int(parts[1]),
                source_name=parts[2],
                target_pid=safe_int(parts[3]),
                target_name=parts[4],
                injection_type=parts[5],
                api_calls=api_calls,
            ),
        )
    return out


async def parse_resource_log(
    shared_folder: Path | None,
    log_name: str = "resource_monitor.log",
) -> list[ResourceSample]:
    """Parse a resource-monitor log into :class:`ResourceSample` records.

    Log format:
    ``timestamp|cpu_percent|memory_mb|disk_read_bytes|disk_write_bytes|net_sent|net_recv``.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[ResourceSample]: Parsed resource usage samples.
    """
    out: list[ResourceSample] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < RESOURCE_LOG_MIN_PARTS:
            continue
        out.append(
            ResourceSample(
                timestamp=parts[0],
                cpu_percent=safe_float(parts[1]),
                memory_mb=safe_float(parts[2]),
                disk_read_bytes=safe_int(parts[3]),
                disk_write_bytes=safe_int(parts[4]),
                net_sent_bytes=safe_int(parts[5]),
                net_recv_bytes=safe_int(parts[6]),
            ),
        )
    return out


async def parse_clipboard_log(
    shared_folder: Path | None,
    log_name: str = "clipboard_monitor.log",
) -> list[ClipboardEvent]:
    """Parse a clipboard-monitor log into :class:`ClipboardEvent` records.

    Log format:
    ``timestamp|operation|format|content_preview|size_bytes|pid|process_name``.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[ClipboardEvent]: Parsed clipboard events.
    """
    out: list[ClipboardEvent] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < CLIPBOARD_LOG_MIN_PARTS:
            continue
        out.append(
            ClipboardEvent(
                timestamp=parts[0],
                operation=parts[1],
                format=parts[2],
                content_preview=parts[3],
                size_bytes=safe_int(parts[4]),
                pid=safe_int(parts[5]),
                process_name=parts[6],
            ),
        )
    return out


async def parse_api_trace_log(
    shared_folder: Path | None,
    log_name: str = "api_trace.log",
) -> list[ApiCall]:
    """Parse an API-trace log into :class:`ApiCall` records.

    Log format:
    ``timestamp|process_name|pid|api_name|module|arguments|return_value``.
    The ``arguments`` field is a semicolon-separated list of stringified args.

    The collector's own lifecycle and failure rows are skipped: they are
    telemetry about the collector, not observations of the sample.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[ApiCall]: Parsed API-call records.
    """
    out: list[ApiCall] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < API_LOG_MIN_PARTS:
            continue
        if parts[_API_LOG_PROCESS_IDX] == _API_TRACE_COLLECTOR_MARKER and parts[_API_LOG_NAME_IDX] in _API_TRACE_COLLECTOR_RECORDS:
            continue
        arguments = [a for a in parts[5].split(";") if a] if parts[5] else []
        out.append(
            ApiCall(
                timestamp=parts[0],
                process_name=parts[1],
                pid=safe_int(parts[2]),
                api_name=parts[3],
                module=parts[4],
                arguments=arguments,
                return_value=parts[6],
            ),
        )
    return out


async def collect_collector_outages(shared_folder: Path | None) -> list[CollectorOutage]:
    """Report every collector that did not observe for the whole run.

    Covers every collector that reports its own lifecycle, which the
    Windows agent alone stages, so this returns nothing for a guest that
    ran none of them.

    The API tracer's outage carries the collector's own failure text as
    well as its lifecycle detail. That text is written into the tracer's
    data log for want of any other channel and
    :func:`parse_api_trace_log` skips it, since a dead collector's
    complaint is not an API call; folding it in here is what keeps it
    from being lost with the row.

    Args:
        shared_folder: Sandbox shared folder root.

    Returns:
        list[CollectorOutage]: One entry per collector that never
        reported starting or reported stopping before the run finished.
    """
    launch_failures = await parse_monitor_launch_failures(shared_folder)
    outages: list[CollectorOutage] = []
    for collector in _LIFECYCLE_COLLECTORS:
        outage = await parse_collector_lifecycle(shared_folder, collector, f"{collector}{_LIFECYCLE_LOG_SUFFIX}")
        if outage is None:
            continue
        if collector == _API_TRACE_COLLECTOR:
            details = await parse_api_trace_collector_errors(shared_folder)
            if details:
                outage["reason"] = f"{outage['reason']}; it reported {'; '.join(details)}"
        launch_failure = launch_failures.get(collector)
        if launch_failure is not None:
            outage["reason"] = f"{outage['reason']}; {launch_failure}"
        outages.append(outage)
    return outages


async def parse_monitor_launch_failures(shared_folder: Path | None) -> dict[str, str]:
    """Read why the guest's launcher did not start each collector.

    A collector that never ran cannot report anything about itself, so
    :func:`parse_collector_lifecycle` can only say that it never started.
    The launcher writes the missing half - whether the script was not
    there to launch, or launching it threw - and this reads it back so
    the outage can carry the cause rather than only the symptom.

    Args:
        shared_folder: Sandbox shared folder root.

    Returns:
        dict[str, str]: Collector name mapped to a phrase explaining why
        the launcher did not start it. Collectors the launcher started,
        and every collector at all when the launcher wrote no log, are
        absent.
    """
    failures: dict[str, str] = {}
    for line in await read_log_lines(shared_folder, _LAUNCHER_LOG_NAME):
        parts = line.split("|", _LAUNCHER_DETAIL_IDX)
        if len(parts) < _LAUNCHER_LOG_MIN_PARTS:
            continue
        prefix = _LAUNCHER_FAILURE_REASONS.get(parts[_LAUNCHER_STATE_IDX])
        if prefix is None:
            continue
        collector = parts[_LAUNCHER_NAME_IDX].removesuffix(_LAUNCHER_SCRIPT_SUFFIX)
        failures[collector] = f"{prefix} {parts[_LAUNCHER_DETAIL_IDX]}".strip()
    return failures


async def parse_api_trace_collector_errors(
    shared_folder: Path | None,
    log_name: str = "api_trace.log",
) -> list[str]:
    """Extract the API tracer's own failure reports from its data log.

    ``api_trace.ps1`` has no channel but its own data log in which to
    report that it failed, so it writes an ``ERROR`` record naming the
    stage and carrying the message. :func:`parse_api_trace_log` skips
    those rows because they are not API calls; this reads them back out
    so the failure can be carried on the collector's outage instead of
    being lost with the row.

    Args:
        shared_folder: Sandbox shared folder root.
        log_name: Log file name under ``<shared_folder>/logs/``.

    Returns:
        list[str]: One ``"<stage>: <detail>"`` string per failure the
        collector reported, in the order it reported them.
    """
    out: list[str] = []
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|")
        if len(parts) < API_LOG_MIN_PARTS:
            continue
        if parts[_API_LOG_PROCESS_IDX] != _API_TRACE_COLLECTOR_MARKER:
            continue
        if parts[_API_LOG_NAME_IDX] != _API_TRACE_COLLECTOR_ERROR:
            continue
        out.append(f"{parts[_API_LOG_STAGE_IDX]}: {parts[_API_LOG_DETAIL_IDX]}")
    return out


async def parse_collector_lifecycle(
    shared_folder: Path | None,
    collector: str,
    log_name: str,
) -> CollectorOutage | None:
    """Detect whether a monitoring collector suffered an outage during a run.

    Log format: ``timestamp|collector|state|detail``, written by the collector
    itself once when it begins (``state`` is ``started``) and once more, from
    a ``finally`` block, whenever it terminates for any reason (``state`` is
    ``stopped``). Nothing in this application's run orchestration signals a
    collector to stop mid-run - collectors run for the guest's whole
    lifetime - so a ``stopped`` line observed while collecting a run's logs
    means the collector exited on its own before the run finished, and a
    missing or empty lifecycle log means the collector process never reached
    its first line of execution. Either case means the collector's data log
    for this run holds no trustworthy observations, even if it contains
    lines: a collector that fails after opening its log can, and does, write
    its own failure as a data record for lack of any other channel.

    Args:
        shared_folder: Sandbox shared folder root.
        collector: Human-readable collector name recorded on the outage, for
            example ``"api_trace"``.
        log_name: Lifecycle log file name under ``<shared_folder>/logs/``.

    Returns:
        CollectorOutage | None: An outage record if the collector never
        reported starting or reported stopping before the run finished, with
        ``exit_code`` parsed from the stop detail when the collector recorded
        one; ``None`` if the collector reported starting and has not since
        reported stopping.
    """
    started = False
    stop_detail: str | None = None
    for line in await read_log_lines(shared_folder, log_name):
        parts = line.split("|", 3)
        if len(parts) < LIFECYCLE_LOG_MIN_PARTS:
            continue
        state = parts[_LIFECYCLE_STATE_IDX]
        if state == _LIFECYCLE_STATE_STARTED:
            started = True
        elif state == _LIFECYCLE_STATE_STOPPED:
            stop_detail = parts[_LIFECYCLE_DETAIL_IDX]

    if not started:
        return CollectorOutage(collector=collector, reason=_ERR_COLLECTOR_NEVER_STARTED, exit_code=None)
    if stop_detail is None:
        return None

    exit_code: int | None = None
    match = _LIFECYCLE_EXIT_CODE_RE.search(stop_detail)
    if match:
        exit_code = int(match.group(1))
    return CollectorOutage(
        collector=collector,
        reason=f"stopped before the run finished ({stop_detail})",
        exit_code=exit_code,
    )
