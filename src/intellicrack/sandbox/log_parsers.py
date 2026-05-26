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
from typing import TYPE_CHECKING

from intellicrack.core.logging import get_logger
from intellicrack.sandbox.base import (
    ApiCall,
    ClipboardEvent,
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
            encoding="utf-8",
            errors="ignore",
        )
    except OSError as err:
        _logger.warning("log_read_failed", log=name, error=str(err))
        return []
    return [line for line in (ln.strip() for ln in raw.splitlines()) if line]


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
