# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""QEMU sandbox implementation for isolated binary analysis.

This module provides cross-platform sandbox functionality using QEMU virtualization for safe execution and behavioral monitoring of
binaries.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import platform
import secrets
import shlex
import shutil
import socket
import struct
import tempfile
import threading
import time
import zipfile
import zlib
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Any, ClassVar, Final, Literal, cast

import psutil

from intellicrack.core._optional_imports import require_yara
from intellicrack.core.config import get_project_root
from intellicrack.core.logging import get_logger, log_sandbox_operation
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.subprocess_compat import (
    TimeoutExpired as _SubprocessTimeoutExpired,
    run as _subprocess_run,
)
from intellicrack.sandbox.base import (
    ApiCall,
    ClipboardEvent,
    CollectorOutage,
    DllLoadEvent,
    ExecutionReport,
    ExecutionResult,
    FileChange,
    InjectionEvent,
    KernelObjectActivity,
    NetworkActivity,
    ProcessActivity,
    RegistryChange,
    ResourceSample,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxTimeoutError,
    ServiceChange,
)
from intellicrack.sandbox.log_helpers import (
    ERR_YARA_NO_ARTIFACTS,
    ERR_YARA_NO_MEMORY_DUMP,
    ERR_YARA_UNKNOWN_TARGET,
    YARA_SCAN_TARGETS,
    YARA_TARGET_MEMORY,
    format_yara_match as _format_yara_match,
    scannable_output_files,
)
from intellicrack.sandbox.log_parsers import (
    parse_api_trace_log,
    parse_clipboard_log,
    parse_collector_lifecycle,
    parse_dll_log,
    parse_file_log,
    parse_injection_log,
    parse_kernel_object_log,
    parse_network_log,
    parse_process_log,
    parse_registry_log,
    parse_resource_log,
    parse_service_log,
)


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

_logger = get_logger(__name__)

_QMP_READ_TIMEOUT = 5.0
_QMP_CONNECT_TIMEOUT = 60.0
_AGENT_POLL_TIMEOUT = 1.0
_ACCEL_DETECT_TIMEOUT = 10
_ACCEL_TEST_TIMEOUT = 5
_PROCESS_COMMUNICATE_TIMEOUT = 30
_SNAPSHOT_JOB_POLL_INTERVAL_S = 0.5
_SNAPSHOT_DISK_FORMAT = "qcow2"
_JOB_STATUS_CONCLUDED = "concluded"
_QMP_COMMAND_ID_PREFIX = "intellicrack-"
_ERR_NOT_CONNECTED = "Not connected"
_DUMP_POLL_INTERVAL_S = 0.5
_DUMP_STATUS_NONE = "none"
_DUMP_STATUS_ACTIVE = "active"
_DUMP_STATUS_COMPLETED = "completed"
_SCREENSHOT_STABILITY_POLL_DELAY_S = 0.05
_SCREENSHOT_STABILITY_MAX_POLLS = 100
_SCREENSHOT_INITIAL_DELAY_S = 0.05
_ERR_SCREENSHOT_NOT_STABLE = "PPM file did not stabilize before timeout"
_ERR_SCREENSHOT_CONVERSION_FAILED = "PPM to PNG conversion failed"
# Public because which collectors a guest receives is part of what this backend
# promises a caller, not an implementation detail: a report tab can only ever
# have content if the collector feeding it is in this list.
MONITOR_SCRIPT_NAMES: Final[tuple[str, ...]] = (
    "api_trace.ps1",
    "clipboard_monitor.ps1",
    "dll_monitor.ps1",
    "injection_monitor.ps1",
    "kernel_object_monitor.ps1",
    "registry_monitor.ps1",
    "resource_monitor.ps1",
    "service_monitor.ps1",
)
# api_trace.ps1 and injection_monitor.ps1 both load this assembly by
# searching $PSScriptRoot among other locations - staging it beside them
# under the same name they already search for is what lets S17-D50(a) work
# without editing either script. Every other file under vendor/traceevent/
# is staged alongside it (see enumerate_traceevent_assembly_files) because
# TraceEvent 3.2.5 ships no net4x build: it depends on the whole .NET
# Standard 2.0 support-pack closure to load under the Desktop CLR, and both
# scripts pre-load that closure and install an AssemblyResolve handler
# before Add-Type. KernelTraceControl.dll keeps its amd64/ subdirectory
# because TraceEvent resolves that native dependency relative to its own
# assembly directory by architecture, the same layout the NuGet package
# ships it in. PROVENANCE.md is the only vendored file excluded from
# staging - it documents the assemblies, it is not one of them.
_TRACE_EVENT_STAGING_EXCLUDED_NAMES: Final[frozenset[str]] = frozenset({"PROVENANCE.md"})
_MONITORING_LOG_NAMES: Final[tuple[str, ...]] = (
    "file_changes.log",
    "registry_monitor.log",
    "network_activity.log",
    "process_activity.log",
    "api_trace.log",
    "service_monitor.log",
    "kernel_object_monitor.log",
    "dll_monitor.log",
    "injection_monitor.log",
    "resource_monitor.log",
    "clipboard_monitor.log",
)
# Written by the two ETW-based Windows collectors alongside their data logs and
# read by parse_collector_lifecycle, so they are collected from the guest with
# the rest rather than being the one set the host never fetches.
_COLLECTOR_LIFECYCLE_LOG_NAMES: Final[tuple[str, ...]] = (
    "api_trace.lifecycle.log",
    "injection_monitor.lifecycle.log",
)
_LOGS_STABLE_POLL_DELAY_S: Final[float] = 0.25
_LOGS_STABLE_REQUIRED_POLLS: Final[int] = 4
_LOGS_STABLE_MAX_WAIT_S: Final[float] = 30.0
_ERR_LOGS_STABLE_POLL_DELAY = "poll_delay must be positive"
_ERR_LOGS_STABLE_STABLE_POLLS = "stable_polls must be at least 1"
_ERR_LOGS_STABLE_MAX_WAIT = "max_wait must be non-negative"
_RETURNCODE_SUCCESS = 0
_VNC_PORT_BASE: Final[int] = 5900
_VNC_PORT_MAX: Final[int] = 5999

# Windows QEMU builds implement neither -daemonize nor -pidfile, so the VM runs
# as a foreground child for its whole lifetime. A launch that survives this
# window is treated as started; one that exits inside it failed.
_IS_WINDOWS: Final[bool] = platform.system() == "Windows"
_WINDOWS_LAUNCH_GRACE_S: Final[float] = 3.0
_ERR_QEMU_EXITED_EARLY = "QEMU exited immediately after launch"
_ERR_QEMU_PROCESS_GONE = "the QEMU process is no longer running, so the guest it hosted no longer exists: {detail}"
_QEMU_EXIT_UNKNOWN_OUTPUT = "QEMU produced no output before it stopped"
_QEMU_OUTPUT_TAIL_LINES = 200
_QEMU_OUTPUT_READ_SIZE = 4096

_ERR_NO_FREE_PORTS = "no free ports"
_ERR_QEMU_HOST_PORT = (
    "QEMU could not bind one of its host ports. On Windows a port can be unusable while nothing is listening on it, because "
    "Hyper-V reserves ranges that are redrawn at every boot; run 'netsh int ipv4 show excludedportrange protocol=tcp' to see "
    "them. Leave the QEMU port settings at 0 to have Intellicrack allocate ports it has verified it can bind."
)
_ERR_QEMU_PATH = "path not set"
_ERR_QEMU_IMG_MISSING = (
    "qemu-img was not found next to the QEMU binary, so no per-instance disk overlay could be created. Intellicrack will not "
    "attach the configured disk image directly, because QEMU does not lock it and a second sandbox would corrupt it."
)
_ERR_OVERLAY_CREATE = "could not create the per-instance disk overlay"
_ERR_NO_IMAGE_UNSET = (
    "No QEMU disk image is configured. Set a qcow2 disk image under Sandbox Settings -> QEMU Backend before creating a QEMU sandbox."
)
_ERR_NO_IMAGE_MISSING = "Configured QEMU disk image does not exist"
_ERR_QEMU_NA = "QEMU not available"
_ERR_QMP_CONNECT = "QMP connect failed"
_ERR_NOT_RUNNING = "not running"
_ERR_NO_SHARED_FOLDER = "shared folder not init"
_ERR_QMP_NOT_CONNECTED = "QMP not connected"
_ERR_QEMU_START = "QEMU start failed"
_ERR_VM_STATUS = "VM status query failed"
_ERR_SANDBOX_START = "sandbox start failed"
_ERR_SANDBOX_STOP = "sandbox stop failed"
_ERR_CMD_TIMEOUT = "command timed out"
_ERR_PIDFILE_UNREADABLE = "QEMU pidfile unreadable after retries - daemon may be orphaned"
_ERR_BINARY_NOT_FOUND = "binary not found"
_ERR_SOURCE_NOT_FOUND = "source not found"
_ERR_COPY_TO_SANDBOX = "copy to sandbox failed"
_ERR_COPY_FROM_SANDBOX = "copy from sandbox failed"
_ERR_SNAPSHOT_CREATE = "snapshot create failed"
_ERR_SNAPSHOT_RESTORE = "snapshot restore failed"
_ERR_SNAPSHOT_DELETE = "snapshot delete failed"
_ERR_SNAPSHOT_NO_DISK = "the running guest exposes no writable qcow2 disk, so there is nothing that can hold a snapshot"
_ERR_SNAPSHOT_DISK_ONLY_FAILED = "disk-only snapshot of device {device!r} failed: {error}"
_ERR_SNAPSHOT_ABSENT = "no snapshot named {name!r} exists on this sandbox's disks"
_ERR_SNAPSHOT_SURVIVED = "QEMU reported the deletion of {name!r} as finished, but the tag is still on the disk"
_ERR_SNAPSHOT_JOB_GONE = "QEMU stopped reporting job {job_id} before it finished"
_ERR_SNAPSHOT_JOB_TIMEOUT = "job {job_id} had not finished after {budget:.0f}s"
_ERR_SNAPSHOT_JOB_UNREADABLE = "the job list could not be read, so the outcome is unknown"
_ERR_SNAPSHOT_JOB_REFUSED = "QEMU refused the request"
_SNAPSHOT_MACHINE_RESUMED = "; the machine was left stopped by the failed job and has been resumed"
_SNAPSHOT_MACHINE_STUCK = "; the machine was left stopped by the failed job and could not be resumed: {reason}"
_VM_STATE_RUNNING = "running"
_VM_STATE_STOPPED = "stopped"
_PIDFILE_MAX_RETRIES = 3
_PIDFILE_RETRY_DELAY = 2.0
PIDFILE_MAX_RETRIES: int = _PIDFILE_MAX_RETRIES
PIDFILE_RETRY_DELAY: float = _PIDFILE_RETRY_DELAY
_ERR_UNSUPPORTED_GUEST_OS = "unsupported guest OS"
_ERR_PCAP_START_FAILED = "packet capture start failed"
_ERR_PCAP_STOP_FAILED = "packet capture stop failed"
_ERR_PCAP_NOT_ACTIVE = "no active packet capture with this ID"
_ERR_SCREENSHOT_FAILED = "screenshot capture failed"
_ERR_ANTI_EVASION_FAILED = "anti-evasion application failed"
_ERR_ANTI_EVASION_PROFILE_MISMATCH = (
    "Cannot apply anti-evasion profile {requested!r} on a sandbox launched with profile "
    "{current!r}. SMBIOS/CPUID masking is fixed at QEMU launch; set "
    "QEMUConfig.anti_evasion_profile before launching to use a different profile."
)
_ERR_ANTI_EVASION_AGENT_ABSENT = "the guest agent is not connected, so no guest-side hardening could be attempted"
_ERR_ANTI_EVASION_COMMAND_FAILED = "{name} exited {exit_code}"
_ERR_ANTI_EVASION_GUEST_SIDE_FAILED = "guest-side anti-evasion for profile {profile!r} did not succeed: {reasons}"
_ERR_MEMORY_DUMP_FAILED = "memory dump failed"
_ERR_MEMORY_DUMP_REFUSED = "QEMU refused the request"
_ERR_MEMORY_DUMP_UNREADABLE = "the dump status could not be read, so the outcome is unknown"
_ERR_MEMORY_DUMP_EMPTY = "QEMU reported the dump as complete but wrote nothing to {path}"
_ERR_MEMORY_DUMP_TIMEOUT = "the dump had written {completed} bytes and was still running after {budget:.0f}s"
_ERR_EXTRACT_FILES_FAILED = "dropped file extraction failed"
_ERR_YARA_SCAN_FAILED = "YARA scan failed"
_ERR_YARA_NOT_AVAILABLE = "yara-python not installed"
_ERR_GUEST_AGENT_NOT_CONNECTED = "Guest agent not connected"
_ERR_GUEST_SCAN_FAILED = "guest YARA scan failed"
_ERR_AGENT_CONNECT_FAILED = "guest agent failed to connect within {timeout}s"
_ERR_AGENT_BOOTSTRAP_DIED = (
    "the monitor agent exited {exit_code} while the host was waiting for it to listen, so nothing was ever going "
    "to answer on the agent port; the guest recorded: {diagnostic}"
)
_BOOTSTRAP_LOG_ABSENT = "this guest OS keeps no bootstrap log"
_BOOTSTRAP_LOG_EMPTY = "nothing - the bootstrap log is empty"
_ERR_QEMU_GA_UNREACHABLE = (
    "qemu-guest-agent did not respond to guest-ping within the configured timeout; "
    "ensure the guest disk image has qemu-guest-agent installed and enabled at boot"
)
_ERR_QEMU_GA_EXEC_FAILED = "qemu-guest-agent guest-exec failed to launch the monitor agent script"
_ERR_QEMU_GA_EXEC_NO_PID = "qemu-guest-agent guest-exec reply did not include a process id"
_ERR_QEMU_GA_SOCKET_UNREACHABLE = (
    "qemu-guest-agent channel socket on 127.0.0.1:{port} refused the connection; "
    "the QEMU chardev backing org.qemu.guest_agent.0 is not listening"
)
_ERR_QEMU_GA_SYNC_FAILED = "qemu-guest-agent echoed no sync id for any supported sync command; the channel could not be resynchronised"
_ERR_QEMU_GA_DESYNCHRONISED = (
    "qemu-guest-agent channel is still carrying the unread reply to a command that timed out; "
    "no reply can be attributed to a new command until the stream is resynchronised"
)
_ERR_QEMU_GA_EXEC_STATUS_FAILED = "qemu-guest-agent guest-exec-status reply could not be read"
_ERR_QEMU_GA_NOT_CONNECTED = "qemu-guest-agent channel not connected"
_ERR_GUEST_FILE_OPEN_FAILED = "qemu-guest-agent could not open {path} inside the guest for writing: {error}"
_ERR_GUEST_FILE_NO_HANDLE = "qemu-guest-agent opened {path} inside the guest but returned no file handle"
_ERR_GUEST_FILE_WRITE_FAILED = "qemu-guest-agent could not write {path} inside the guest: {error}"
_ERR_GUEST_FILE_SHORT_WRITE = "qemu-guest-agent wrote {written} of {expected} bytes to {path} inside the guest"
_ERR_GUEST_FILE_READ_OPEN_FAILED = "qemu-guest-agent could not open {path} inside the guest for reading: {error}"
_ERR_GUEST_FILE_READ_FAILED = "qemu-guest-agent could not read {path} inside the guest: {error}"
_ERR_GUEST_FILE_READ_MALFORMED = "qemu-guest-agent returned an unreadable answer while reading {path} inside the guest"
_ERR_GUEST_FILE_TOO_LARGE = "{path} inside the guest is larger than the {limit} bytes the host will collect in one read"
_ERR_GUEST_EXEC_NO_EXIT_CODE = "qemu-guest-agent reported {command} as finished inside the guest but gave it no exit status"
_ERR_GUEST_COMMAND_TIMEOUT = "guest command {command} did not exit within {timeout}s"
_ERR_QEMU_GA_EXEC_NOT_READY = (
    "qemu-guest-agent answered guest-ping but ran no command inside the guest within {budget:.0f}s; last failure: {reason}"
)
_ERR_QEMU_GA_EXEC_NOT_ATTEMPTED = "the readiness budget was already spent before a command could be tried"
_ERR_GUEST_SHARED_MOUNT_POINT = "could not create the shared-folder mount point {path} inside the guest"
_ERR_GUEST_SHARED_DEVICE_ENUM = "could not enumerate guest block devices while locating the shared volume"
_ERR_GUEST_SHARED_DEVICE_NOT_FOUND = (
    "no unmounted {fs_type} block device labelled {label!r} is present in the guest; the FAT-backed shared volume never appeared"
)
_ERR_GUEST_SHARED_MOUNT_FAILED = "mounting the shared volume {source} at {mount_point} inside the guest failed"
_ERR_GUEST_SHARED_LAUNCHER_MISSING = "the shared volume is mounted but the monitor launch script {path} is not present inside the guest"
_ERR_GUEST_SHARED_DRIVE_ENUM = "could not enumerate guest drive letters while locating the shared volume"
_ERR_GUEST_SHARED_DRIVE_NOT_FOUND = "no guest drive letter carries {relative}; the FAT-backed shared volume is not visible to the guest"
_AGENT_CONNECT_TIMEOUT = 30.0
_AGENT_CONNECT_RETRY_INTERVAL = 15.0
_AGENT_CONNECT_BACKOFF_INTERVAL = 2.0

_ERR_AGENT_HANDSHAKE_NO_SOCKET = "guest agent handshake attempted without an open socket"
_ERR_AGENT_HANDSHAKE_CLOSED = "guest agent channel closed before answering the readiness handshake"
_ERR_AGENT_HANDSHAKE_TIMEOUT = "guest agent did not answer the readiness handshake within {timeout}s"
_ERR_AGENT_HANDSHAKE_UNFRAMED = "guest agent readiness handshake could not be framed: {error}"
_ERR_AGENT_CHANNEL_CLOSED = "guest agent closed the channel"
_ERR_AGENT_NOT_CONNECTED = "Not connected to guest agent"
_ERR_AGENT_COMMAND_TIMED_OUT = "Command timed out"
_ERR_AGENT_LOST_AFTER_DISPATCH = (
    "the guest agent channel was lost after the command was dispatched, so the guest may already be running it; "
    "it was not sent again ({reason})"
)
_ERR_AGENT_LOST_VM_GONE = (
    "the guest agent channel was lost because the virtual machine stopped, so nothing is running in the guest any more: {detail}"
)
_ERR_AGENT_RECONNECT_FAILED = "the guest agent channel could not be re-established after it failed ({reason})"
_ERR_AGENT_DISPATCH_EXHAUSTED = "the guest agent channel failed on all {attempts} dispatch attempts ({reason})"
_AGENT_RESULT_MESSAGE_TYPE = "result"
_AGENT_RECONNECT_TIME_LIMIT = 30.0
_AGENT_RECONNECT_RETRY_INTERVAL = 1.0
_AGENT_DISPATCH_ATTEMPTS = 2
_READINESS_POLL_INTERVAL = 0.5
_READINESS_POLL_TIMEOUT = 60.0
_RESULT_PAYLOAD_SEPARATOR = "|IC_RESULT|"
_QEMU_GA_PING_TIMEOUT = 90.0
_QEMU_GA_PING_INTERVAL = 1.0
# Reply deadline for one guest-agent request. Public because it is the contract
# a caller has to reason about: a guest that has not answered within it is a
# guest whose command was lost, not a guest that failed.
#
# Sized for the slowest reply the agent is asked for rather than the typical
# one. The first guest-exec on a cold Windows guest has to reach a process
# creation path whose image is still being faulted in off the qcow2 overlay,
# and under WHPX that was measured past ten seconds on
# windows11-intellicrack-v4. Such a command is slow, not lost, and abandoning
# it is not free: the reply still arrives, and until it has been accounted for
# every subsequent read is offset by one.
QEMU_GA_EXEC_TIMEOUT: Final[float] = 45.0
_QEMU_GA_CONNECT_TIMEOUT = 30.0
# Default whole-handshake budget: opening the channel, syncing it, answering a
# ping, and running one command to completion. It has to be a multiple of the
# worst single attempt rather than a round number, because an attempt that is
# abandoned costs its own reply deadline plus the resync that follows it
# (QEMU_GA_EXEC_TIMEOUT + _QEMU_GA_RESYNC_TIMEOUT), and a budget that cannot
# hold two of those has no retry left in it at all - which is how a guest that
# was one slow command away from ready came to fail its whole start.
_QEMU_GA_READY_TIMEOUT: Final[float] = 300.0
_QEMU_GA_CONNECT_RETRY_INTERVAL: Final[float] = 1.0
_QEMU_GA_EXEC_PROBE_INTERVAL: Final[float] = 2.0
# Payload bytes per guest-file-write. The buffer travels base64-encoded inside
# one JSON line, so this is about 88 KiB on the wire - comfortably inside the
# agent's own line limit while keeping the number of round trips low.
_QGA_FILE_WRITE_CHUNK: Final[int] = 65536
# Payload bytes requested per guest-file-read. The agent answers with base64,
# so the same size keeps a read reply the same order as a write request.
_QGA_FILE_READ_CHUNK: Final[int] = 65536
# A guest file the host is willing to pull in one go. Monitor logs are the
# reason this exists: a runaway collector can produce an unbounded log, and a
# host that read it without limit would trade one hang for another.
_QGA_FILE_READ_LIMIT: Final[int] = 64 * 1024 * 1024
_QGA_FILE_COMMAND_TIMEOUT: Final[float] = 30.0
# Budget for the resync that follows a command timeout. This is the same
# negotiation against the same agent that opening the connection performs, so it
# is given the same budget rather than a shorter one of its own. A shorter one
# made a slow guest permanently unusable: the budget ran out before the fallback
# sync command had ever been sent, so the abandoned reply was never consumed and
# every command after it read the previous command's answer.
_QEMU_GA_RESYNC_TIMEOUT: Final[float] = _QEMU_GA_CONNECT_TIMEOUT

# The guest-shutdown mode that powers the guest off rather than rebooting or
# halting it. qemu-guest-agent sends no reply to this command, so the real
# evidence of compliance is QEMU exiting.
_QGA_SHUTDOWN_MODE: Final[str] = "powerdown"

# Seconds given to a QMP quit before the foreground child handle is reaped.
_QEMU_QUIT_SETTLE_S: Final[float] = 2.0

# Windows releases a dead process's file handles asynchronously, so QEMU's disk
# overlay can stay open for a moment after the process itself is gone. These
# bound how long removing an instance's temporary tree keeps retrying before the
# failure is reported rather than discarded.
_TEMP_TREE_REMOVE_ATTEMPTS: Final[int] = 5
_TEMP_TREE_REMOVE_BACKOFF_S: Final[float] = 0.5

# QEMU exposes the guest-agent virtio-serial chardev one port above the
# Intellicrack agent's hostfwd port; see the -chardev argument built by
# _build_qemu_command.
_QGA_CHANNEL_PORT_OFFSET: Final[int] = 1

# Host port allocation. The range sits above the ephemeral ports most services
# take and below the top of the dynamic range, and every candidate drawn from it
# is confirmed bindable before it is used, so a range Windows has reserved is
# skipped rather than handed to QEMU to fail on.
_HOST_PORT_RANGE_START: Final[int] = 10000
_HOST_PORT_RANGE_END: Final[int] = 60000
_HOST_PORT_SEARCH_ATTEMPTS: Final[int] = 100

# QEMU's SLIRP hostfwd binds the wildcard address, so a probe that is to predict
# whether QEMU can bind a port has to bind the same address. Derived from the
# platform's own INADDR_ANY rather than written out.
_WILDCARD_BIND_ADDRESS: Final[str] = socket.inet_ntoa(struct.pack("!I", socket.INADDR_ANY))

# QEMU's wording when a host-side bind fails, for the two sockets it binds by
# way of a command-line argument rather than a listening service.
_QEMU_BIND_FAILURE_MARKERS: Final[tuple[str, ...]] = (
    "Could not set up host forwarding rule",
    "Failed to bind socket",
    "address already in use",
)

# A lone 0xFF byte is the qemu-guest-agent parser reset marker: it cannot occur
# inside valid JSON, so the agent discards whatever partial object a previous
# client left behind when it sees one.
_QGA_PARSER_FLUSH_BYTE: Final[bytes] = b"\xff"
_QGA_SYNC_ID_BITS: Final[int] = 31

# The agent exposes two sync commands and not every build carries both, so the
# handshake tries them in order. ``guest-sync-delimited`` prefixes its reply with
# the parser reset marker, which is what lets a client discard a partial line a
# previous client left in the output stream; ``guest-sync`` echoes the id with no
# marker. Verified against qemu-guest-agent 10.0.11, whose ``guest-info`` command
# table lists both under exactly these names.
_QGA_SYNC_COMMANDS: Final[tuple[str, ...]] = ("guest-sync-delimited", "guest-sync")

# Error class the agent reports for a command its build does not implement. It
# is answered immediately, so treating it as definitive is what stops an
# unsupported sync command from consuming the whole connection budget in silence.
_QGA_COMMAND_NOT_FOUND_CLASS: Final[str] = "CommandNotFound"

# Per-command slice of the sync budget. A reply can be lost outright when a
# previous client left a partial line in the agent's output stream, since only
# the delimited command's reply carries the sentinel that reframes it, so no
# single command may consume the whole budget waiting for an answer that was
# already swallowed.
_QGA_SYNC_ATTEMPT_TIMEOUT: Final[float] = 5.0

# qemu-guest-agent caps each captured stream at GUEST_EXEC_MAX_OUTPUT
# (16 MiB, ``qga/commands.c``) and base64-encodes stdout and stderr into the
# same single-line ``guest-exec-status`` reply, so a reply the agent itself
# considers legal is bounded by two base64 expansions of that cap plus the JSON
# envelope. asyncio's StreamReader defaults to a 64 KiB line limit, which
# ordinary captured guest output passes long before the agent's own cap does,
# and a reader whose limit is exceeded raises a bare ValueError out of
# readline(). The same limit is applied to the QMP monitor: QMP replies are not
# bounded either - ``human-monitor-command`` returns whatever text the HMP
# command produced and ``query-block`` grows with the block topology - and QEMU
# imposes no line length of its own, so a 64 KiB ceiling would be just as
# arbitrary there.
_QGA_STREAM_CAPTURE_LIMIT: Final[int] = 16 * 1024 * 1024
_JSON_LINE_ENVELOPE_ALLOWANCE: Final[int] = 64 * 1024
_BASE64_INPUT_GROUP: Final[int] = 3
_BASE64_OUTPUT_GROUP: Final[int] = 4
_JSON_CAPTURED_STREAM_COUNT: Final[int] = 2
_JSON_LINE_LIMIT: Final[int] = (
    _JSON_CAPTURED_STREAM_COUNT * (((_QGA_STREAM_CAPTURE_LIMIT + _BASE64_INPUT_GROUP - 1) // _BASE64_INPUT_GROUP) * _BASE64_OUTPUT_GROUP)
    + _JSON_LINE_ENVELOPE_ALLOWANCE
)
_ERR_JSON_LINE_TOO_LONG = "peer sent a JSON frame longer than the {limit}-byte channel limit; the stream can no longer be framed"

_GUEST_SHARED_ROOT_WINDOWS: Final[str] = "Z:\\"
_GUEST_SHARED_ROOT_LINUX: Final[str] = "/mnt/shared"

# Everything the guest writes goes here, on the guest's own disk, and never to
# the share. QEMU's vvfat driver aborts the whole virtual machine when it tries
# to commit a guest's directory changes back to the host directory - measured as
# exit code 3 preceded by ``cluster 0 used more than once`` and ``Error handling
# renames (-5)`` - and the append-heavy monitor logs plus the write-then-rename
# used to publish a result are exactly what provokes it. The share is mounted
# read-only instead, so that commit path is never entered, and the host collects
# what the guest produced over the guest-agent file commands.
_GUEST_WORK_ROOT_WINDOWS_RELATIVE: Final[str] = "intellicrack"
_GUEST_WORK_ROOT_LINUX: Final[str] = "/var/lib/intellicrack"
_MONITOR_LAUNCH_RELATIVE_WINDOWS: Final[str] = "monitor\\start_agent.cmd"
_MONITOR_LAUNCH_RELATIVE_LINUX: Final[str] = "monitor/start_agent.sh"
_MONITOR_AGENT_RELATIVE_LINUX: Final[str] = "monitor/agent.py"

# Where the Linux launcher records what happened while it started the agent, and
# how long the agent is given to still be running afterwards. The agent runs for
# as long as the sandbox does, so a launcher process that has already exited can
# only mean it never reached its accept loop.
_GUEST_AGENT_LOG_DIR_RELATIVE: Final[str] = "logs"
_GUEST_BOOTSTRAP_LOG_NAME: Final[str] = "agent_bootstrap.log"
_BOOTSTRAP_LOG_LINES: Final[int] = 40

# The guest-side command interpreters a shell command line has to be handed
# to. The in-guest agents take an executable plus an argument vector and launch
# it directly - PowerShell's ``& $cmd @cmdArgs`` on Windows, ``subprocess.run``
# without a shell on Linux - so a line carrying redirections, ``&&`` or a
# quoted path is only a shell line once one of these runs it.
_WINDOWS_SHELL: Final[str] = "cmd.exe"
_WINDOWS_SHELL_COMMAND_FLAG: Final[str] = "/c"
_LINUX_SHELL: Final[str] = "/bin/bash"
_LINUX_SHELL_COMMAND_FLAG: Final[str] = "-c"

# Identifier for the xHCI controller that carries the guest's absolute pointing
# device. q35 provides no USB bus of its own, so the controller has to be added
# before a tablet has anywhere to attach.
_USB_CONTROLLER_ID: Final[str] = "icusb"

_SHARED_MOUNT_TAG: Final[str] = "shared"
_GUEST_VFAT_FS_TYPE: Final[str] = "vfat"
_GUEST_9P_FS_TYPE: Final[str] = "9p"
_GUEST_VFAT_MOUNT_OPTIONS: Final[str] = "ro"
_GUEST_9P_MOUNT_OPTIONS: Final[str] = "trans=virtio,version=9p2000.L,rw"
_GUEST_BLOCK_DEVICE_COLUMNS: Final[str] = "PATH,FSTYPE,LABEL,MOUNTPOINT"
_GUEST_BLOCK_DEVICE_MIN_FIELDS: Final[int] = 2
_GUEST_BLOCK_DEVICE_LABEL_FIELD: Final[int] = 2
_GUEST_BLOCK_DEVICE_MOUNTPOINT_FIELD: Final[int] = 3

# QEMU's vvfat driver writes this exact 11-byte FAT volume label into both the
# synthesised boot sector and the root-directory volume-label entry. The driver
# does accept a ``label`` option in its full block-device form
# (``-drive driver=vvfat,label=...``), but the ``file=fat:rw:<dir>`` shorthand
# emitted by _shared_folder_args cannot carry one - everything after the
# ``fat:rw:`` prefix is taken as the directory path - so every drive built here
# ends up with vvfat's built-in default. It is what distinguishes the share
# from the guest's own vfat partitions - a Debian cloud image's EFI System
# Partition is vfat too, and is enumerated first - but it does not distinguish
# the share from a second ``file=fat:`` drive, which carries the very same
# label; only the guest's live mount table tells those two apart.
_QEMU_VVFAT_VOLUME_LABEL: Final[str] = "QEMU VVFAT"

# ``lsblk --raw`` separates columns with a single space and hex-escapes any
# character that could be mistaken for that separator.
_LSBLK_ESCAPE_PREFIX: Final[str] = "\\x"
_LSBLK_ESCAPE_LENGTH: Final[int] = 4
_LSBLK_ESCAPE_BASE: Final[int] = 16

_GUEST_COMMAND_TIMEOUT: Final[float] = 60.0
_GUEST_COMMAND_POLL_INTERVAL: Final[float] = 0.25
# What every POSIX shell adds to a terminating signal number to express it as
# an exit code, used when the guest agent reports a signal instead of a code.
_SIGNAL_EXIT_CODE_BASE: Final[int] = 128
_DROPPED_COPY_TIMEOUT: Final[int] = 30
_DROPPED_LIST_TIMEOUT: Final[int] = 30
_LOG_SIZE_PROBE_TIMEOUT: Final[int] = 20
# Bounds on what one extraction pulls back over the guest agent, which carries
# every byte base64-encoded through the monitor socket. A run that filled the
# watched directories would otherwise stall the whole extraction; the trim is
# logged with its counts rather than passed off as a complete collection.
_DROPPED_PULL_MAX_FILES: Final[int] = 512
_DROPPED_PULL_MAX_BYTES: Final[int] = 256 * 1024 * 1024
# The smallest command each guest family can run: it spawns a process, exits
# immediately and touches nothing, so completing it proves the agent's spawn
# path works without depending on anything the sandbox has not set up yet.
_GUEST_EXEC_PROBE_WINDOWS: Final[tuple[str, tuple[str, ...]]] = ("cmd.exe", ("/c", "exit", "0"))
_GUEST_EXEC_PROBE_LINUX: Final[tuple[str, tuple[str, ...]]] = ("/bin/sh", ("-c", "exit 0"))
_WINDOWS_SYSTEM_DRIVE: Final[str] = "C:"
_WINDOWS_SYSTEM_ROOT: Final[str] = "C:\\Windows"
_WINDOWS_DRIVE_SUFFIX: Final[str] = ":"
_WINDOWS_SYSTEM_DRIVE_VARIABLE: Final[str] = "SystemDrive"
_WINDOWS_SYSTEM_ROOT_VARIABLE: Final[str] = "SystemRoot"
# Directories below %SystemDrive% and %SystemRoot% whose newly created files
# the in-guest monitor mirrors into ``<share>\output\dropped``. The agent
# script builds the same three paths from the same two variables, so the host
# scan and the guest mirror always name one set of directories.
_WINDOWS_DROP_WATCH_BELOW_SYSTEM_DRIVE: Final[tuple[str, ...]] = (
    "Users\\Public\\Downloads",
    "Users\\Default\\AppData\\Local\\Temp",
)
_WINDOWS_DROP_WATCH_BELOW_SYSTEM_ROOT: Final[tuple[str, ...]] = ("Temp",)
# ``reg.exe`` below ``%SystemRoot%``. The in-guest agent's allowlist accepts an
# executable only under ``System32``/``SysWOW64`` of the ``%SystemRoot%`` the
# guest itself reports, so :meth:`QEMUSandbox._guest_reg_exe_path` joins this
# suffix onto the probed system root per sandbox; the constants below give the
# documented default for a guest whose Windows lives at ``C:\Windows``.
_WINDOWS_REG_EXE_RELATIVE: Final[str] = "System32\\reg.exe"
_WINDOWS_REG_EXE_PATH: str = f"{_WINDOWS_SYSTEM_ROOT}\\{_WINDOWS_REG_EXE_RELATIVE}"
WINDOWS_REG_EXE_PATH: str = _WINDOWS_REG_EXE_PATH

_ERR_PPM_INVALID_MAGIC = "invalid PPM magic; expected P6"
_ERR_PPM_UNSUPPORTED_MAXVAL = "unsupported PPM maxval; only 8-bit (255) is supported"
_ERR_PPM_TRUNCATED = "PPM pixel data is truncated"
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PPM_EXPECTED_MAXVAL = 255
_PPM_WHITESPACE: frozenset[int] = frozenset(b" \t\r\n")


def _as_mapping(value: object) -> dict[str, object] | None:
    """Narrow a decoded JSON value to a string-keyed mapping.

    A bare ``isinstance(value, dict)`` on an ``object`` leaves the key and value
    types unknown, which is not usable. Everything this module narrows came out
    of :func:`json.loads`, where an object's keys are strings by definition.

    Args:
        value: Decoded JSON value.

    Returns:
        dict[str, object] | None: The mapping, or None when the value is not
        one.
    """
    if isinstance(value, dict):
        return cast("dict[str, object]", value)
    return None


def _file_size_or_zero(path: Path) -> int:
    """Report a file's size, treating an absent file as empty.

    Args:
        path: File to measure.

    Returns:
        int: Size in bytes, or 0 when the file does not exist.
    """
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _as_sequence(value: object) -> list[object] | None:
    """Narrow a decoded JSON value to a list.

    Args:
        value: Decoded JSON value.

    Returns:
        list[object] | None: The list, or None when the value is not one.
    """
    if isinstance(value, list):
        return cast("list[object]", value)
    return None


def _read_ppm_token(data: bytes, pos: int) -> tuple[str, int]:
    """Read the next whitespace-delimited token from PPM header.

    Skips ASCII whitespace and `#`-prefixed comment lines per the
    Netpbm PPM specification, then returns the next token.

    Args:
        data: Raw PPM file bytes.
        pos: Current read position into ``data``.

    Returns:
        tuple[str, int]: Parsed token and updated position pointing at the
        byte immediately after the token.
    """
    while pos < len(data):
        byte = data[pos]
        if byte in _PPM_WHITESPACE:
            pos += 1
            continue
        if byte == ord("#"):
            newline = data.find(b"\n", pos)
            pos = len(data) if newline == -1 else newline + 1
            continue
        break
    start = pos
    while pos < len(data) and data[pos] not in _PPM_WHITESPACE:
        pos += 1
    return data[start:pos].decode("ascii"), pos


def _encode_png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    """Encode a single PNG chunk with length and CRC32 framing.

    Args:
        chunk_type: 4-byte PNG chunk type identifier.
        payload: Chunk data (may be empty).

    Returns:
        bytes: Full PNG chunk including length header and trailing CRC.
    """
    length = struct.pack(">I", len(payload))
    crc = struct.pack(">I", zlib.crc32(chunk_type + payload) & 0xFFFFFFFF)
    return length + chunk_type + payload + crc


def _parse_ppm_p6(data: bytes) -> tuple[int, int, bytes]:
    """Parse a Netpbm P6 PPM payload into ``(width, height, rgb_pixels)``.

    Args:
        data: Raw bytes of the PPM file.

    Returns:
        tuple[int, int, bytes]: Tuple ``(width, height, pixels)`` where ``pixels`` is raw RGB bytes.

    Raises:
        ValueError: If the PPM magic is not ``P6``, the maxval is not 255, or
            the pixel payload is truncated.
    """
    magic, pos = _read_ppm_token(data, 0)
    if magic != "P6":
        _logger.warning("ppm_invalid_magic", magic=magic, payload_size=len(data))
        raise ValueError(_ERR_PPM_INVALID_MAGIC)
    width_str, pos = _read_ppm_token(data, pos)
    height_str, pos = _read_ppm_token(data, pos)
    maxval_str, pos = _read_ppm_token(data, pos)
    if int(maxval_str) != _PPM_EXPECTED_MAXVAL:
        _logger.warning("ppm_unsupported_maxval", maxval=maxval_str)
        raise ValueError(_ERR_PPM_UNSUPPORTED_MAXVAL)
    if pos < len(data) and data[pos] in _PPM_WHITESPACE:
        pos += 1
    width = int(width_str)
    height = int(height_str)
    expected_bytes = width * height * 3
    pixels = data[pos : pos + expected_bytes]
    if len(pixels) < expected_bytes:
        _logger.warning(
            "ppm_truncated",
            expected_size=expected_bytes,
            actual_size=len(pixels),
        )
        raise ValueError(_ERR_PPM_TRUNCATED)
    return width, height, pixels


def _ppm_p6_to_png(ppm_path: Path, png_path: Path) -> None:
    """Convert a Netpbm P6 PPM image to PNG using only the stdlib.

    Reads an 8-bit RGB PPM (binary P6) produced by QEMU's ``screendump``
    and writes a compressed true-color PNG. PPM parsing errors bubble up
    from :func:`_parse_ppm_p6` as ``ValueError``.

    Args:
        ppm_path: Path to the source PPM image.
        png_path: Destination path for the PNG output.
    """
    width, height, pixels = _parse_ppm_p6(ppm_path.read_bytes())
    stride = width * 3
    raw_scanlines = b"".join(b"\x00" + pixels[row * stride : (row + 1) * stride] for row in range(height))
    png_bytes = (
        _PNG_SIGNATURE
        + _encode_png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _encode_png_chunk(b"IDAT", zlib.compress(raw_scanlines, level=9))
        + _encode_png_chunk(b"IEND", b"")
    )
    png_path.write_bytes(png_bytes)
    _logger.info(
        "screenshot_png_written",
        png_path=str(png_path),
        size=len(png_bytes),
        width=width,
        height=height,
    )


def enumerate_traceevent_assembly_files(vendor_dir: Path) -> tuple[str, ...]:
    """Enumerate every vendored TraceEvent assembly that must reach the guest.

    Walking the vendored directory rather than naming each file in a
    hand-maintained list means a newly vendored assembly is staged
    automatically the next time a guest boots, and none can silently be
    left behind by a list that drifted out of sync with what
    ``vendor/traceevent/`` actually contains.

    Args:
        vendor_dir: Root of the vendored ``vendor/traceevent`` directory.

    Returns:
        tuple[str, ...]: Every file under ``vendor_dir`` except documentation,
        as paths relative to ``vendor_dir`` using forward slashes, sorted for
        deterministic staging order. Empty if ``vendor_dir`` does not exist.
    """
    if not vendor_dir.is_dir():
        return ()
    return tuple(
        sorted(
            path.relative_to(vendor_dir).as_posix()
            for path in vendor_dir.rglob("*")
            if path.is_file() and path.name not in _TRACE_EVENT_STAGING_EXCLUDED_NAMES
        ),
    )


class GuestOS(Enum):
    """Guest operating system type."""

    WINDOWS = "windows"
    LINUX = "linux"


class AcceleratorType(Enum):
    """QEMU acceleration types."""

    WHPX = "whpx"
    KVM = "kvm"
    TCG = "tcg"


@dataclass
class _MonitoringLogs:
    """Aggregated monitoring log parse results.

    Attributes:
        file_changes: Parsed file-change records.
        registry_changes: Parsed registry-change records.
        network_activity: Parsed network activity records.
        process_activity: Parsed process activity records.
        api_calls: Parsed API call records.
        service_changes: Parsed service change records.
        kernel_objects: Parsed kernel-object activity records.
        dll_loads: Parsed DLL-load event records.
        injection_events: Parsed injection event records.
        resource_samples: Parsed resource usage samples.
        clipboard_events: Parsed clipboard event records.
        collector_outages: Monitoring collectors that did not observe for
            the full run, per :func:`intellicrack.sandbox.log_parsers.parse_collector_lifecycle`.
    """

    file_changes: list[FileChange] = field(default_factory=list)
    registry_changes: list[RegistryChange] = field(default_factory=list)
    network_activity: list[NetworkActivity] = field(default_factory=list)
    process_activity: list[ProcessActivity] = field(default_factory=list)
    api_calls: list[ApiCall] = field(default_factory=list)
    service_changes: list[ServiceChange] = field(default_factory=list)
    kernel_objects: list[KernelObjectActivity] = field(default_factory=list)
    dll_loads: list[DllLoadEvent] = field(default_factory=list)
    injection_events: list[InjectionEvent] = field(default_factory=list)
    resource_samples: list[ResourceSample] = field(default_factory=list)
    clipboard_events: list[ClipboardEvent] = field(default_factory=list)
    collector_outages: list[CollectorOutage] = field(default_factory=list)


@dataclass
class QEMUConfig:
    """Configuration for QEMU sandbox.

    Attributes:
        guest_os: Guest operating system type.
        image_path: Path to the qcow2 disk image.
        cpu_cores: Number of CPU cores.
        memory_mb: Memory in megabytes.
        display: Display output mode.
        ssh_port: Host port forwarded to the guest's SSH port. Zero - the
            default - allocates one that the host has been confirmed able to
            bind, which is the only safe choice on Windows: Hyper-V reserves
            port ranges that are redrawn at every boot, so a fixed port works
            or does not work depending on where the reservations landed that
            morning, and no two sandboxes could run at once. Set it non-zero
            only to pin a port deliberately; a pinned port is used as given.
        monitor_port: Host port for the QMP monitor. Zero allocates one, as
            for ``ssh_port``.
        agent_port: Host port forwarded to the in-guest Intellicrack agent.
            The qemu-guest-agent channel is bound one port above it, so zero
            allocates an adjacent pair that are both bindable.
        enable_acceleration: Whether to use hardware acceleration.
        snapshot_name: Snapshot to restore on start.
        disk_overlay: Whether each sandbox gets its own copy-on-write overlay
            over ``image_path`` instead of writing to it directly. On by
            default, and the only safe setting when more than one sandbox can
            exist: QEMU does not lock the image on Windows, so two guests
            attached to one file write over each other and corrupt it. Turning
            this off makes a sandbox's changes persist into the configured
            image, which is destructive and is only appropriate when a single
            sandbox is deliberately being used to modify that image.
        shared_folder: Path to shared folder on host.
        anti_evasion_profile: Anti-evasion profile applied at launch via
            ``-smbios`` / ``-cpu`` command-line arguments. One of
            ``default``, ``workstation``, or ``laptop``.
        agent_connect_timeout: Total timeout in seconds that ``start()`` will
            wait for the in-guest agent TCP socket to become reachable before
            failing the sandbox launch.
        guest_agent_ready_timeout: Total timeout in seconds allowed for
            qemu-guest-agent to become usable: opening the
            ``org.qemu.guest_agent.0`` channel, resynchronising it, getting an
            answer to ``guest-ping``, and then getting a command to run. The
            whole budget is available to a guest that is still booting, because
            QEMU binds the channel socket before the guest runs.
        guest_shutdown_timeout: Total time in seconds ``stop()`` allows the
            guest to power itself off before QEMU is terminated outright. The
            budget is split evenly across the shutdown channels that are open,
            so a dead qemu-guest-agent cannot consume the whole of it and leave
            nothing for the ACPI power button. Set it to zero to skip the
            request entirely and yank the power, which loses whatever the
            in-guest monitors had not yet flushed.
        snapshot_timeout: Total time in seconds a snapshot job may run before
            the operation is reported as failed. Saving a snapshot writes the
            guest's whole RAM image, so this budget scales with ``memory_mb``
            rather than being an interactive timeout.
        memory_dump_timeout: Total time in seconds a guest memory dump may run
            before the operation is reported as failed. Like a snapshot this
            writes the guest's whole RAM, and measured against QEMU 10.1.0 a
            1024 MB guest took 3.6 s, so the budget scales with ``memory_mb``.
    """

    guest_os: GuestOS = GuestOS.WINDOWS
    image_path: Path | None = None
    cpu_cores: int = 2
    memory_mb: int = 4096
    display: Literal["none", "vnc", "sdl", "spice"] = "none"
    ssh_port: int = 0
    monitor_port: int = 0
    agent_port: int = 0
    enable_acceleration: bool = True
    snapshot_name: str | None = None
    disk_overlay: bool = True
    shared_folder: Path | None = None
    anti_evasion_profile: Literal["default", "workstation", "laptop"] = "default"
    agent_connect_timeout: float = 60.0
    guest_agent_ready_timeout: float = _QEMU_GA_READY_TIMEOUT
    guest_shutdown_timeout: float = 120.0
    snapshot_timeout: float = 600.0
    memory_dump_timeout: float = 1800.0


@dataclass
class QMPResponse:
    """Response from QMP command.

    Attributes:
        success: Whether the command succeeded.
        data: The reply's ``return`` member verbatim. QMP defines its shape per
            command, so this is not always a mapping: ``query-block`` answers
            with a list and ``human-monitor-command`` with the monitor's output
            text. Callers must narrow it before use.
        error: Error message if failed.
    """

    success: bool
    data: object | None = None
    error: str | None = None


@dataclass
class GuestAgentMessage:
    """Message from the guest agent.

    Attributes:
        message_type: Type of the guest agent message.
        timestamp: When the message was received.
        data: Message payload.
    """

    message_type: str
    timestamp: datetime
    data: dict[str, object] = field(default_factory=dict)


@dataclass
class GuestExecStatus:
    """Outcome of a qemu-guest-agent ``guest-exec-status`` query.

    Attributes:
        exited: Whether the guest-side process has terminated.
        exit_code: Process exit code, or None while it is still running or
            when it was terminated by a signal.
        signal: Terminating signal number, or None when the process was not
            killed by a signal.
        stdout: Decoded standard output captured by the agent.
        stderr: Decoded standard error captured by the agent.
        stdout_truncated: Whether the agent truncated the captured stdout.
        stderr_truncated: Whether the agent truncated the captured stderr.
    """

    exited: bool
    exit_code: int | None = None
    signal: int | None = None
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass(frozen=True)
class _GuestBlockDevice:
    """One row of the guest's ``lsblk --raw`` block-device listing.

    Attributes:
        path: Device node path such as ``/dev/vdb1``.
        fs_type: Filesystem type blkid detected, empty when there is none.
        label: Filesystem volume label with lsblk's escaping undone, empty
            when the volume carries no label.
        mountpoint: Where the device is currently mounted, empty when it is
            not mounted anywhere.
    """

    path: str
    fs_type: str
    label: str
    mountpoint: str


@dataclass(frozen=True)
class _SyncOutcome:
    """Result of waiting for one qemu-guest-agent sync reply.

    Attributes:
        matched: Whether the agent echoed the sync id that was sent.
        unsupported: Whether the agent rejected the command as one this build
            does not implement, which means another sync command may still
            work and no time should be spent waiting on this one.
        agent_error: Description the agent gave for the rejection, when it
            gave one.
    """

    matched: bool
    unsupported: bool = False
    agent_error: str | None = None


@dataclass(frozen=True)
class _DispatchAttempt:
    """What became of one attempt to run a request over the guest agent channel.

    The distinction ``dispatched`` draws is the whole reason this type exists.
    A request the host never managed to write is a request the guest cannot
    have run, so sending it again is free. A request that did leave the host
    and then lost its channel may already be executing inside the guest, and
    re-sending it would run the analysis target a second time.

    Attributes:
        result: Process triple to report to the caller, or None when the
            attempt produced no reply at all.
        dispatched: Whether the request reached the agent before the channel
            failed.
        reason: Why the channel failed, when it did.
    """

    result: tuple[int, str, str] | None
    dispatched: bool
    reason: str


class _JsonLineTooLongError(ConnectionError):
    """Raised when a peer sent a JSON frame longer than the channel's limit.

    ``StreamReader.readline`` reports the overrun as a bare :class:`ValueError`
    and drops what it had buffered, while the remainder of the oversized frame
    is still arriving on the socket: the stream can no longer be framed on
    newlines, so the connection is finished. Subclassing
    :class:`ConnectionError` is what says that, and lets every caller that
    already handles a broken connection handle this too.
    """


class QemuJsonProtocolClient:
    """Line-oriented JSON transport shared by QEMU's QMP and guest-agent sockets.

    Both protocols carry one JSON object per line and shape their replies
    identically (``{"return": ...}`` on success, ``{"error": {"class", "desc"}}``
    on failure); they differ only in the handshake performed once the socket is
    open and in how much of the incoming stream belongs to other conversations.
    This class owns the socket, the serialisation lock, the request/response
    exchange and the reply decoding. Subclasses override :meth:`_handshake` to
    add protocol negotiation and :meth:`_read_reply` to change how a reply is
    picked out of the stream.

    Attributes:
        connected: Whether a socket session is currently open.
    """

    connected: bool
    _log_prefix: ClassVar[str] = "qemu_json"
    _read_limit: ClassVar[int] = _JSON_LINE_LIMIT

    # Whether a socket whose handshake failed is worth keeping. A QMP monitor
    # re-listens after every disconnect, so dropping the socket costs nothing
    # and leaves no half-open connection behind. A chardev socket does not: it
    # is accepted once for the life of the VM, so closing it forfeits the only
    # channel there is.
    _retain_socket_on_handshake_failure: ClassVar[bool] = False

    def __init__(self, host: str = "127.0.0.1", port: int = 4444) -> None:
        """Initialize the protocol client.

        Args:
            host: Host address where the server is listening.
            port: TCP port for the server.
        """
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.connected = False
        self._resync_pending = False
        self._lock = asyncio.Lock()
        _logger.debug(self._event("client_initialized"), host=host, port=port)

    @classmethod
    def _event(cls, suffix: str) -> str:
        """Build a protocol-scoped structured-logging event name.

        Args:
            suffix: Event suffix appended to the protocol prefix.

        Returns:
            str: Fully qualified event name.
        """
        return f"{cls._log_prefix}_{suffix}"

    @property
    def host(self) -> str:
        """Host address this client is bound to.

        Returns:
            str: Configured host address.
        """
        return self._host

    @property
    def port(self) -> int:
        """TCP port this client is bound to.

        Returns:
            int: Configured TCP port.
        """
        return self._port

    async def _handshake(self, time_limit: float) -> None:
        """Negotiate the protocol once the socket is open.

        The base transport needs no negotiation; subclasses override this to
        read a greeting, exchange capabilities, or resynchronise the stream.

        Args:
            time_limit: Handshake timeout in seconds.
        """

    async def _open_session(self, time_limit: float) -> None:
        """Open the socket and complete the protocol handshake.

        The reader is given an explicit line limit sized for the largest reply
        the peer is allowed to produce, because asyncio's 64 KiB default is far
        below it and turns an ordinary large reply into a read failure.

        Args:
            time_limit: Connection timeout in seconds.
        """
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self._host, self._port, limit=self._read_limit),
            timeout=time_limit,
        )
        await self._handshake(time_limit)
        self.connected = True
        self._resync_pending = False
        _logger.info(self._event("connected"), host=self._host, port=self._port)

    @property
    def socket_open(self) -> bool:
        """Whether the transport socket is still open.

        This is weaker than :attr:`connected`, which additionally requires the
        protocol handshake to have completed. A socket that is open but not yet
        synchronised is the normal state of a guest-agent channel opened while
        the guest is still booting.

        Returns:
            bool: True when a writer is attached.
        """
        return self._writer is not None

    async def connect(self, time_limit: float = 30.0) -> bool:
        """Connect to the server.

        A socket that opened but whose handshake failed is closed again before
        the failure is reported, so no half-open connection is left behind for
        a retry to leak - unless the peer will only ever accept one connection,
        in which case closing it forfeits the channel and
        :attr:`_retain_socket_on_handshake_failure` keeps it open instead.

        Args:
            time_limit: Connection timeout in seconds.

        Returns:
            bool: True if connected successfully, False if the socket could not
            be opened within ``time_limit``.

        Raises:
            SandboxError: If the socket opened but the protocol handshake
                failed.
        """
        try:
            await self._open_session(time_limit)
        except (OSError, TimeoutError, ConnectionError) as e:
            _logger.warning(self._event("connection_failed"), error=str(e))
            await self.disconnect()
            return False
        except SandboxError:
            if not self._retain_socket_on_handshake_failure:
                await self.disconnect()
            raise
        return True

    async def disconnect(self) -> None:
        """Disconnect from the server.

        A peer that has already gone - the guest powering off, or a forwarded
        connection that was reset - makes the close itself fail, which is the
        expected ending for this socket rather than a fault a caller could do
        anything about. It is recorded at debug level for that reason.
        """
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except OSError as e:
                _logger.debug(self._event("disconnect_error"), error=str(e))
        self._reader = None
        self._writer = None
        self.connected = False
        self._resync_pending = False

    async def _send_command(
        self,
        command: dict[str, object],
        time_limit: float = 10.0,
    ) -> QMPResponse:
        """Send a command and get response.

        A channel a previous timeout left offset is realigned before anything is
        written to it, and refused outright when it cannot be: a reply read off
        an offset stream belongs to the previous command, and returning it as
        this command's answer is worse than reporting no answer at all.

        Args:
            command: Command dictionary with an ``execute`` key.
            time_limit: Response timeout in seconds.

        Returns:
            QMPResponse: Decoded response, or a failure carrying
            :data:`_ERR_QEMU_GA_DESYNCHRONISED` when the stream is still offset.
        """
        _logger.debug(self._event("command_send_called"), command=command.get("execute"))
        if self._reader is None or self._writer is None:
            return QMPResponse(success=False, error=_ERR_NOT_CONNECTED)

        async with self._lock:
            if self._resync_pending and not await self._clear_pending_resync():
                return QMPResponse(success=False, error=_ERR_QEMU_GA_DESYNCHRONISED)
            try:
                return await self._exchange_command(command, time_limit)
            except TimeoutError:
                _logger.warning(self._event("command_timeout"))
                await self._recover_from_command_timeout()
                return QMPResponse(success=False, error="Command timed out")
            except _JsonLineTooLongError as e:
                _logger.warning(self._event("reply_line_too_long"), error=str(e), read_limit=self._read_limit)
                await self.disconnect()
                return QMPResponse(success=False, error=str(e))
            except (OSError, json.JSONDecodeError, ConnectionError) as e:
                _logger.warning(self._event("command_failed"), error=str(e), exc_info=True)
                return QMPResponse(success=False, error=str(e))

    async def _recover_from_command_timeout(self) -> None:
        """Run the protocol's timeout reaction without letting it escape.

        :meth:`_on_command_timeout` talks to the peer, so it can fail for every
        reason the timed-out command itself could - a reset channel, a closed
        socket, an unanswerable resync. It runs from inside the caller's
        ``except TimeoutError`` handler, where a sibling ``except`` clause
        cannot catch anything it raises, so any such failure would escape
        :meth:`_send_command` as an exception its callers do not expect.

        A broken socket is closed, so the next call opens a fresh one. An
        unanswered resync is a different thing: the peer is still reachable and
        merely slow, and on a channel the peer hands out only once - see
        :attr:`_retain_socket_on_handshake_failure` - closing it would turn a
        slow guest into a permanently unreachable one. Such a channel is kept,
        but it is kept *marked*: the timed-out command's reply is still on its
        way, so the stream is known to be offset by one until some later resync
        consumes it. :meth:`_clear_pending_resync` is what retries that, and
        :meth:`_send_command` refuses to attribute a reply to a new command
        until it has succeeded.
        """
        try:
            await self._on_command_timeout()
        except (OSError, ConnectionError) as e:
            _logger.warning(self._event("command_timeout_recovery_failed"), error=str(e), port=self._port)
            await self.disconnect()
        except SandboxError as e:
            _logger.warning(self._event("command_timeout_resync_unanswered"), error=str(e), port=self._port)
            if self._retain_socket_on_handshake_failure:
                self._resync_pending = True
            else:
                await self.disconnect()
        else:
            self._resync_pending = False

    async def _clear_pending_resync(self) -> bool:
        """Retry the resync a previous command timeout could not complete.

        Runs with the command lock already held, and reaches the peer only
        through :meth:`_recover_from_command_timeout`, so a resync that fails
        again re-arms the mark rather than escaping to the caller. Each attempt
        gets the protocol's whole resync budget: the reason the first one failed
        is that the guest was slower than the budget it was given, and a guest
        that is still busy needs the full budget again, not the remainder of it.

        Returns:
            bool: True when the stream is framed again and a reply may be
            attributed to a new command, False while it is still offset.
        """
        _logger.debug(self._event("resync_pending_retry"), port=self._port)
        await self._recover_from_command_timeout()
        if self._resync_pending:
            _logger.warning(self._event("resync_pending_unresolved"), port=self._port)
            return False
        return self._reader is not None and self._writer is not None

    async def _on_command_timeout(self) -> None:
        """React to a command whose reply did not arrive in time.

        The base transport has no way to realign a stream, so it does nothing; subclasses whose protocol provides one override this.
        """

    async def _exchange_command(
        self,
        command: dict[str, object],
        time_limit: float,
    ) -> QMPResponse:
        """Write a command over the open connection and decode its reply.

        Args:
            command: Command dictionary.
            time_limit: Response timeout in seconds.

        Returns:
            QMPResponse: Parsed response from the server.
        """
        if self._reader is None or self._writer is None:
            return QMPResponse(success=False, error=_ERR_NOT_CONNECTED)

        cmd_json = json.dumps(command) + "\n"
        self._writer.write(cmd_json.encode())
        await self._writer.drain()

        return self._decode_reply(await self._read_reply(time_limit))

    async def _read_line(self, time_limit: float) -> bytes:
        """Read one newline-terminated frame within the channel's line limit.

        Args:
            time_limit: Read timeout in seconds.

        Returns:
            bytes: The raw frame, including its newline, or empty bytes when
            the peer closed the connection.

        Raises:
            ConnectionError: If the socket is not open.
            _JsonLineTooLongError: If the peer sent more than
                :attr:`_read_limit` bytes without a newline.
        """
        if self._reader is None:
            msg = "socket is not open"
            raise ConnectionError(msg)

        try:
            return await asyncio.wait_for(self._reader.readline(), timeout=time_limit)
        except ValueError as e:
            raise _JsonLineTooLongError(_ERR_JSON_LINE_TOO_LONG.format(limit=self._read_limit)) from e

    async def _read_reply(self, time_limit: float) -> dict[str, Any]:
        """Read the reply to the command just written.

        Args:
            time_limit: Read timeout in seconds.

        Returns:
            dict[str, Any]: Decoded reply object.
        """
        return self._decode_line(await self._read_line(time_limit))

    @classmethod
    def _decode_line(cls, line: bytes) -> dict[str, Any]:
        """Decode one newline-terminated JSON object.

        Args:
            line: Raw bytes read from the socket.

        Returns:
            dict[str, Any]: Decoded mapping, or an empty mapping when the line
            holds a JSON value that is not an object.

        Raises:
            ConnectionError: If the peer closed the connection.
        """
        if not line:
            msg = "connection closed by peer"
            raise ConnectionError(msg)

        decoded: object = json.loads(cls._decode_text(line))
        if not isinstance(decoded, dict):
            return {}
        return cast("dict[str, Any]", decoded)

    @staticmethod
    def _decode_text(line: bytes) -> str:
        """Extract the JSON text carried by one raw line.

        QMP frames are strict UTF-8 and carry nothing but the object itself.
        Protocols that prefix their frames override this.

        Args:
            line: Raw bytes read from the socket, including the newline.

        Returns:
            str: JSON text ready for :func:`json.loads`.
        """
        return line.decode()

    @staticmethod
    def _decode_reply(payload: dict[str, Any]) -> QMPResponse:
        """Convert a decoded reply object into a :class:`QMPResponse`.

        Args:
            payload: Decoded reply mapping.

        Returns:
            QMPResponse: Response carrying either the ``return`` member or the
            ``error`` description.
        """
        error: Any = payload.get("error")
        if error is None:
            return QMPResponse(success=True, data=payload.get("return"))

        desc: Any = error
        if isinstance(error, dict):
            desc = cast("dict[str, Any]", error).get("desc", "Unknown error")
        return QMPResponse(success=False, error=str(desc))

    async def execute_command(
        self,
        command: dict[str, object],
        time_limit: float = 10.0,
    ) -> QMPResponse:
        """Execute an arbitrary command on this protocol channel.

        Public wrapper around the internal command dispatch for use by
        the sandbox implementation when operations are needed that
        do not have a dedicated convenience method.

        Args:
            command: Command dictionary with 'execute' key.
            time_limit: Response timeout in seconds.

        Returns:
            QMPResponse: Response with success status and data.
        """
        return await self._send_command(command, time_limit)


class QMPClient(QemuJsonProtocolClient):
    """QEMU Machine Protocol client for VM control.

    Provides asynchronous communication with QEMU via QMP for VM control, snapshot management, and status queries.
    """

    _log_prefix: ClassVar[str] = "qmp"

    def __init__(self, host: str = "127.0.0.1", port: int = 4444) -> None:
        """Initialize the monitor client and its command-id counter.

        Args:
            host: Host address where the monitor is listening.
            port: TCP port for the monitor.
        """
        super().__init__(host=host, port=port)
        self._command_serial = 0

    async def _exchange_command(
        self,
        command: dict[str, object],
        time_limit: float,
    ) -> QMPResponse:
        """Write a command tagged with a unique id and read back its own reply.

        QMP is not a request/response protocol on its own: QEMU pushes
        asynchronous events onto the same socket whenever the machine changes
        state, so the next line after a command is frequently not that
        command's reply. Reading it as one is what made a ``snapshot-save``
        report ``{"return": None}`` and success - the frame actually read was
        ``JOB_STATUS_CHANGE`` - and it left every later command reading the
        previous command's answer for the life of the connection.

        The protocol's own remedy is the optional ``id`` member, which QEMU
        echoes verbatim on the reply and never puts on an event. Tagging every
        command lets its reply be picked out of the stream positively rather
        than positionally, which also discards the late reply to a command that
        already timed out instead of handing it to the next caller.

        Args:
            command: Command dictionary with an ``execute`` key.
            time_limit: Response timeout in seconds.

        Returns:
            QMPResponse: Parsed reply to this command.
        """
        if self._reader is None or self._writer is None:
            return QMPResponse(success=False, error=_ERR_NOT_CONNECTED)

        self._command_serial += 1
        token = f"{_QMP_COMMAND_ID_PREFIX}{self._command_serial}"
        tagged: dict[str, object] = {**command, "id": token}
        self._writer.write((json.dumps(tagged) + "\n").encode())
        await self._writer.drain()

        return self._decode_reply(await self._read_tagged_reply(token, time_limit))

    async def _read_tagged_reply(self, token: str, time_limit: float) -> dict[str, Any]:
        """Read frames until the one carrying this command's id arrives.

        Args:
            token: Command id to match on.
            time_limit: Total time allowed for the reply to arrive, shared
                across however many events precede it.

        Returns:
            dict[str, Any]: The decoded reply frame.

        Raises:
            TimeoutError: If no frame carrying ``token`` arrived in time.
        """
        deadline = time.monotonic() + time_limit
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError

            frame = self._decode_line(await self._read_line(remaining))
            name = frame.get("event")
            if name is not None:
                _logger.debug(self._event("async_event"), qmp_event=str(name), data=frame.get("data"))
                continue

            reply_id = frame.get("id")
            if reply_id == token:
                return frame

            _logger.warning(self._event("unmatched_reply_discarded"), expected=token, received=str(reply_id))

    async def _handshake(self, time_limit: float) -> None:
        """Read the QMP greeting banner and negotiate capabilities.

        Args:
            time_limit: Connection timeout in seconds. The greeting read and
                the capability exchange use the protocol's own fixed timeouts,
                so this value is not applied here.
        """
        del time_limit
        if self._reader is None:
            return

        greeting = await asyncio.wait_for(
            self._reader.readline(),
            timeout=_QMP_READ_TIMEOUT,
        )
        _logger.debug("qmp_greeting_received", greeting=greeting.decode().strip())

        await self._send_command({"execute": "qmp_capabilities"})

    async def query_status(self) -> QMPResponse:
        """Query VM status.

        Returns:
            QMPResponse: VM status response.
        """
        return await self._send_command({"execute": "query-status"})

    async def stop(self) -> QMPResponse:
        """Pause the VM.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({"execute": "stop"})

    async def cont(self) -> QMPResponse:
        """Resume the VM.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({"execute": "cont"})

    async def quit(self) -> QMPResponse:
        """Quit QEMU.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({"execute": "quit"})

    async def savevm(self, name: str) -> QMPResponse:
        """Save a VM snapshot.

        Args:
            name: Snapshot name.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": f"savevm {name}"},
        })

    async def loadvm(self, name: str) -> QMPResponse:
        """Load a VM snapshot.

        Args:
            name: Snapshot name.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": f"loadvm {name}"},
        })

    async def delvm(self, name: str) -> QMPResponse:
        """Delete a VM snapshot.

        Args:
            name: Snapshot name.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": f"delvm {name}"},
        })

    async def info_snapshots(self) -> QMPResponse:
        """Get list of snapshots.

        Returns:
            QMPResponse: Snapshot list response.
        """
        return await self._send_command({
            "execute": "human-monitor-command",
            "arguments": {"command-line": "info snapshots"},
        })

    async def query_block(self) -> QMPResponse:
        """List the guest-visible block devices and what each currently holds.

        This is the only query that distinguishes the disk the guest writes to
        from the images behind it. ``query-named-block-nodes`` reports every
        layer, so on the copy-on-write chain each instance now runs on it
        offers the read-only backing image as an equally plausible qcow2 node -
        and writing a snapshot there would put state back into the image
        S17-D58 stopped sharing.

        Returns:
            QMPResponse: A list of device records, each carrying an
            ``inserted`` member describing its topmost node.
        """
        return await self._send_command({"execute": "query-block"})

    async def query_jobs(self) -> QMPResponse:
        """Report the state of every background job QEMU is tracking.

        Returns:
            QMPResponse: A list of job records. A finished job has
            ``status: "concluded"`` and carries an ``error`` member only when
            it failed.
        """
        return await self._send_command({"execute": "query-jobs"})

    async def job_dismiss(self, job_id: str) -> QMPResponse:
        """Drop a concluded job so it stops being reported.

        Args:
            job_id: Identifier the job was created with.

        Returns:
            QMPResponse: Command response.
        """
        return await self._send_command({"execute": "job-dismiss", "arguments": {"id": job_id}})

    async def snapshot_save(self, job_id: str, tag: str, vmstate: str, devices: list[str]) -> QMPResponse:
        """Start a job that saves an internal snapshot.

        Unlike the ``savevm`` monitor command this replaces, the outcome is
        reported through :meth:`query_jobs` rather than as monitor text inside
        a successful reply.

        Args:
            job_id: Identifier to track the job by.
            tag: Snapshot name.
            vmstate: Node name the RAM state is written to.
            devices: Node names to snapshot.

        Returns:
            QMPResponse: Whether QEMU accepted the request. Completion is a
            separate question, answered by :meth:`query_jobs`.
        """
        return await self._send_command({
            "execute": "snapshot-save",
            "arguments": {"job-id": job_id, "tag": tag, "vmstate": vmstate, "devices": devices},
        })

    async def snapshot_load(self, job_id: str, tag: str, vmstate: str, devices: list[str]) -> QMPResponse:
        """Start a job that restores an internal snapshot.

        Args:
            job_id: Identifier to track the job by.
            tag: Snapshot name.
            vmstate: Node name the RAM state is read from.
            devices: Node names to restore.

        Returns:
            QMPResponse: Whether QEMU accepted the request.
        """
        return await self._send_command({
            "execute": "snapshot-load",
            "arguments": {"job-id": job_id, "tag": tag, "vmstate": vmstate, "devices": devices},
        })

    async def snapshot_delete(self, job_id: str, tag: str, devices: list[str]) -> QMPResponse:
        """Start a job that deletes an internal snapshot.

        Args:
            job_id: Identifier to track the job by.
            tag: Snapshot name.
            devices: Node names to delete it from.

        Returns:
            QMPResponse: Whether QEMU accepted the request.
        """
        return await self._send_command({
            "execute": "snapshot-delete",
            "arguments": {"job-id": job_id, "tag": tag, "devices": devices},
        })

    async def blockdev_snapshot_internal_sync(self, device: str, name: str) -> QMPResponse:
        """Take a disk-only internal snapshot of one block device, synchronously.

        Unlike ``snapshot-save`` this stores no CPU or RAM state, only the qcow2
        contents, so an accelerator that blocks machine-state migration - WHPX -
        permits it. The command is not a job: its outcome is on this reply, not
        in :meth:`query_jobs`. It takes ``device``, the id from
        :meth:`query_block`, not a node name (a node name is refused with
        ``Parameter 'device' is missing``).

        Args:
            device: Block device id, as reported by ``query-block``.
            name: Snapshot name to write into the qcow2.

        Returns:
            QMPResponse: Whether the snapshot was taken.
        """
        return await self._send_command({
            "execute": "blockdev-snapshot-internal-sync",
            "arguments": {"device": device, "name": name},
        })


class QemuGuestAgentClient(QemuJsonProtocolClient):
    r"""Client for the qemu-guest-agent (QGA) virtio-serial channel.

    QGA is reached through the chardev socket QEMU exposes for the
    ``org.qemu.guest_agent.0`` virtserialport, never through the QMP monitor:
    the monitor rejects every ``guest-*`` command with ``CommandNotFound``.
    The channel sends no greeting and negotiates no capabilities, so a client
    starts issuing commands as soon as the socket is open.

    Because the agent's JSON parser retains whatever a previous client left
    behind - and because a guest reboot can leave a half-written object in
    flight - a freshly attached client must resynchronise before its first
    command, and again after any client-side timeout. Both halves of that
    exchange matter:

    * outbound, the client writes a lone ``0xFF`` byte, which cannot occur
      inside valid JSON and makes the agent drop its partial input, then issues
      ``guest-sync-delimited`` with a unique id;
    * inbound, the agent prepends the same ``0xFF`` sentinel to the reply that
      carries the id (``qga/main.c`` ``send_response``). Everything received up
      to and including that byte belongs to the previous conversation - a stale
      reply, a line cut off mid-write, arbitrary non-UTF-8 noise - and is
      discarded, which is what re-frames the stream. The client then reads
      until the reply carrying its id arrives.

    QGA carries no request ids and emits no asynchronous events, so a stale
    reply is indistinguishable from a fresh one on its contents alone; the
    sentinel resync is the only mechanism that realigns the stream.
    """

    _log_prefix: ClassVar[str] = "qemu_ga"

    # QEMU accepts this chardev socket once. Reconnecting is not a retry, it is
    # a forfeit: every later connect is refused for the life of the VM, as an
    # independent client outside the app confirms. See :meth:`resynchronise`.
    _retain_socket_on_handshake_failure: ClassVar[bool] = True

    def __init__(self, host: str = "127.0.0.1", port: int = 4446) -> None:
        """Initialize the qemu-guest-agent client.

        Args:
            host: Host address where the guest-agent chardev socket listens.
            port: TCP port of the guest-agent chardev socket.
        """
        super().__init__(host=host, port=port)

    @staticmethod
    def _decode_text(line: bytes) -> str:
        """Re-frame one raw agent line on the parser-flush sentinel.

        The sentinel is the agent's own marker for "everything before this
        belongs to a previous client", so the bytes ahead of the last one in
        the line are dropped rather than parsed. Whatever survives may still be
        a fragment of somebody else's object, so it is decoded leniently and
        left for the caller to reject as malformed JSON.

        Args:
            line: Raw bytes read from the channel, including the newline.

        Returns:
            str: JSON text of the line that follows the last sentinel byte.
        """
        marker = line.rfind(_QGA_PARSER_FLUSH_BYTE)
        payload = line if marker < 0 else line[marker + 1 :]
        return payload.decode("utf-8", errors="replace")

    async def _handshake(self, time_limit: float) -> None:
        """Resynchronise the agent's parser and reply stream.

        Args:
            time_limit: Deadline in seconds for the sync reply.
        """
        await self._synchronise(time_limit)

    async def resynchronise(self, time_limit: float) -> bool:
        """Retry the handshake on the channel that is already open.

        An unanswered ``guest-sync-delimited`` says the guest has not started
        qemu-guest-agent yet, which is the ordinary state of a Windows guest
        for the first minutes of a cold boot. It says nothing about the host
        side of the channel, which QEMU bound before the guest left firmware -
        so the retry belongs on the open socket. Opening a new one is not
        merely wasteful: QEMU accepts this socket once, and the second connect
        is refused for the life of the VM.

        Only a socket that has genuinely broken is closed here, which lets the
        caller open a fresh one for the case where that can still work.

        Args:
            time_limit: Deadline in seconds for the sync reply.

        Returns:
            bool: True when the agent echoed the sync id and the channel is
            usable.
        """
        if self._reader is None or self._writer is None:
            return False

        try:
            await self._synchronise(time_limit)
        except SandboxError as error:
            _logger.debug(self._event("resync_retry"), port=self._port, error=str(error))
            return False
        except (OSError, ConnectionError) as error:
            _logger.warning(self._event("resync_channel_lost"), port=self._port, error=str(error))
            await self.disconnect()
            return False

        self.connected = True
        _logger.info(self._event("connected"), host=self._host, port=self._port)
        return True

    async def _on_command_timeout(self) -> None:
        """Re-issue the sync so a late reply cannot offset the stream.

        The QGA schema requires ``guest-sync-delimited`` "upon initial
        connection, and after any client-side timeouts": the agent answers a
        slow command eventually, and with no request id to match on, that reply
        would be read as the answer to whatever command comes next. The resync
        discards it.

        Propagates the ``SandboxError`` raised by :meth:`_synchronise` when the
        agent does not echo the fresh sync id, and whatever socket error the
        exchange hits when the channel broke meanwhile.
        :meth:`_recover_from_command_timeout` contains both, and treats them
        differently: a broken socket is closed, an unanswered resync leaves the
        channel open because QEMU will not hand this one out a second time.
        """
        if self._reader is None or self._writer is None:
            return
        await self._synchronise(_QEMU_GA_RESYNC_TIMEOUT)

    async def _synchronise(self, time_limit: float) -> None:
        """Flush the agent parser and align the reply stream with this client.

        Tries each command in :data:`_QGA_SYNC_COMMANDS` in turn. An agent that
        does not implement one answers ``CommandNotFound`` straight away, which
        moves on to the next name rather than waiting out the deadline. An agent
        that is merely slow does not answer at all, so the attempts are sized to
        divide the budget rather than each claim a fixed share of it - see
        :meth:`_sync_attempt_slice`, without which a budget no larger than one
        attempt is spent entirely on the first command and the rest are never
        sent.

        Args:
            time_limit: Deadline in seconds for the sync reply.

        Raises:
            SandboxError: If the socket is not open, if no sync command the
                agent implements echoes its id before the deadline, or if the
                agent implements none of them.
        """
        if self._reader is None or self._writer is None:
            raise SandboxError(_ERR_QEMU_GA_SYNC_FAILED)

        deadline = time.monotonic() + time_limit
        pending = list(_QGA_SYNC_COMMANDS)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            for command in list(pending):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                outcome = await self._attempt_sync(command, self._sync_attempt_slice(remaining, len(pending)))
                if outcome.matched:
                    return
                if outcome.unsupported:
                    pending.remove(command)
                    _logger.debug(
                        self._event("sync_command_unsupported"),
                        command=command,
                        error=outcome.agent_error,
                        port=self._port,
                    )

        _logger.warning(
            self._event("sync_failed"),
            commands=list(_QGA_SYNC_COMMANDS),
            host=self._host,
            port=self._port,
        )
        raise SandboxError(_ERR_QEMU_GA_SYNC_FAILED)

    @staticmethod
    def _sync_attempt_slice(remaining: float, pending_commands: int) -> float:
        """Size one sync attempt so every command still pending gets a turn.

        Trying the sync commands "in order" only holds if the budget outlives
        the first of them. A fixed per-attempt share does not guarantee that:
        once the budget is no larger than that share, the first command consumes
        all of it and the fallback is never sent - which is how a resync against
        a slow guest came to fail without ever trying the command that guest
        answers. Dividing what is left keeps the ordering meaningful at any
        budget, while the fixed share still caps an attempt when the budget is
        generous enough to allow several rounds.

        Args:
            remaining: Seconds left in the whole sync budget.
            pending_commands: Number of sync commands still to be tried.

        Returns:
            float: Deadline in seconds for the next single attempt.
        """
        return min(_QGA_SYNC_ATTEMPT_TIMEOUT, remaining / max(pending_commands, 1))

    async def _attempt_sync(self, command: str, time_limit: float) -> _SyncOutcome:
        """Send one sync command and wait a bounded slice for its reply.

        Each command gets a slice rather than the whole budget because a reply
        can be lost before it is ever decodable: a partial line left in the
        agent's output stream by a previous client swallows the reply appended
        after it, and only the delimited command's reply carries the sentinel
        that would let the stream be reframed. Bounding the wait lets the next
        command have its turn, by which point the leftover has been consumed.

        Args:
            command: Sync command name to negotiate.
            time_limit: Deadline in seconds for this attempt alone.

        Returns:
            _SyncOutcome: Result of this single attempt.
        """
        if self._writer is None:
            return _SyncOutcome(matched=False)

        sync_id = secrets.randbits(_QGA_SYNC_ID_BITS)
        request = json.dumps({"execute": command, "arguments": {"id": sync_id}})
        self._writer.write(_QGA_PARSER_FLUSH_BYTE + request.encode() + b"\n")
        await self._writer.drain()

        outcome = await self._await_sync_id(sync_id, time_limit)
        if outcome.matched:
            _logger.debug(
                self._event("sync_complete"),
                command=command,
                sync_id=sync_id,
                port=self._port,
            )
        return outcome

    async def _await_sync_id(self, sync_id: int, time_limit: float) -> _SyncOutcome:
        """Discard incoming lines until the sync reply for ``sync_id`` arrives.

        The parser reset marker written ahead of the request makes the agent
        report the marker itself as a JSON parse error, so an error line is not
        on its own a rejection of the sync. Only ``CommandNotFound`` is, and it
        identifies a command this agent build does not implement.

        Args:
            sync_id: Sync id sent with the command being negotiated.
            time_limit: Deadline in seconds for the sync reply.

        Returns:
            _SyncOutcome: Matched when the agent echoed ``sync_id``; unsupported
            when the agent rejected the command outright; otherwise a plain
            failure, meaning the deadline elapsed, the channel closed, or the
            agent sent a frame too long to be read at all.
        """
        if self._reader is None:
            return _SyncOutcome(matched=False)

        deadline = time.monotonic() + time_limit
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _SyncOutcome(matched=False)
            try:
                line = await self._read_line(remaining)
            except TimeoutError:
                return _SyncOutcome(matched=False)
            except ConnectionError as e:
                _logger.warning(self._event("sync_read_failed"), error=str(e), port=self._port)
                return _SyncOutcome(matched=False)
            if not line:
                return _SyncOutcome(matched=False)
            try:
                payload = self._decode_line(line)
            except (json.JSONDecodeError, ConnectionError):
                _logger.debug(self._event("sync_line_discarded"), exc_info=True)
                continue
            if payload.get("return") == sync_id:
                return _SyncOutcome(matched=True)

            error_class, description = self._sync_error_fields(payload)
            if error_class == _QGA_COMMAND_NOT_FOUND_CLASS:
                return _SyncOutcome(matched=False, unsupported=True, agent_error=description)
            _logger.debug(
                self._event("sync_line_skipped"),
                keys=sorted(payload),
                agent_error=description,
            )

    @staticmethod
    def _sync_error_fields(payload: dict[str, Any]) -> tuple[str | None, str | None]:
        """Extract the error class and description from a decoded agent reply.

        Args:
            payload: One decoded reply object from the agent.

        Returns:
            tuple[str | None, str | None]: Error class and human-readable
            description, each None when the reply carries no error or the
            member is not a string.
        """
        error = payload.get("error")
        if not isinstance(error, dict):
            return (None, None)
        error_map = cast("dict[str, Any]", error)
        error_class = error_map.get("class")
        description = error_map.get("desc")
        return (
            error_class if isinstance(error_class, str) else None,
            description if isinstance(description, str) else None,
        )

    async def _read_reply(self, time_limit: float) -> dict[str, Any]:
        """Read the next command reply, skipping leftover stream noise.

        A line is skipped when it does not decode to an object carrying a
        ``return`` or an ``error`` member: a fragment left by a previous client
        parses as malformed JSON or as a bare JSON value. Skipping cannot
        separate a stale reply from a fresh one - QGA echoes no request id -
        so a reply that arrives after its command timed out is discarded by the
        resync :meth:`_on_command_timeout` performs, not here.

        Args:
            time_limit: Deadline in seconds for a usable reply.

        Returns:
            dict[str, Any]: First line that carries a ``return`` or ``error``
            member.

        Raises:
            ConnectionError: If the channel is not open, if the agent closed
                it, or if the agent sent a frame longer than the channel limit.
            TimeoutError: If no usable reply arrives before the deadline.
        """
        if self._reader is None:
            msg = "qemu-guest-agent channel is not open"
            raise ConnectionError(msg)

        deadline = time.monotonic() + time_limit
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            line = await self._read_line(remaining)
            try:
                payload = self._decode_line(line)
            except json.JSONDecodeError:
                _logger.debug(self._event("reply_invalid_json_skipped"), exc_info=True)
                continue
            if "return" in payload or "error" in payload:
                return payload
            _logger.debug(self._event("reply_event_skipped"), keys=sorted(payload))

    async def ping(self, time_limit: float = QEMU_GA_EXEC_TIMEOUT) -> QMPResponse:
        """Send ``guest-ping`` to verify the agent is answering.

        Args:
            time_limit: Response timeout in seconds.

        Returns:
            QMPResponse: Successful response when the agent replied.
        """
        return await self.execute_command({"execute": "guest-ping"}, time_limit)

    async def guest_shutdown(self, mode: str = _QGA_SHUTDOWN_MODE) -> bool:
        """Ask the guest operating system to power itself off.

        ``guest-shutdown`` is the one agent command that has no reply: the
        agent hands the request to the guest's own shutdown path and the
        channel dies with the guest. Reading for an answer would therefore
        always spend the full reply timeout and then drive this client into a
        resync against a guest that is already going down, so the request is
        written and not read back. Whether the guest obeyed is decided by
        watching QEMU exit, which it does once its guest powers off.

        Args:
            mode: Shutdown mode - ``powerdown``, ``reboot`` or ``halt``.

        Returns:
            bool: True when the request reached the wire.
        """
        if self._writer is None:
            return False

        payload = json.dumps({"execute": "guest-shutdown", "arguments": {"mode": mode}}) + "\n"
        async with self._lock:
            try:
                self._writer.write(payload.encode())
                await self._writer.drain()
            except (OSError, ConnectionError) as error:
                _logger.warning(self._event("guest_shutdown_write_failed"), error=str(error))
                return False
        return True

    async def guest_exec(
        self,
        path: str,
        args: Sequence[str],
        *,
        capture_output: bool = False,
        time_limit: float = QEMU_GA_EXEC_TIMEOUT,
    ) -> QMPResponse:
        """Launch a program inside the guest via ``guest-exec``.

        Args:
            path: Absolute executable path inside the guest.
            args: Argument list passed to the executable.
            capture_output: Whether the agent should buffer stdout/stderr for
                later retrieval through :meth:`guest_exec_status`.
            time_limit: Response timeout in seconds.

        Returns:
            QMPResponse: Response whose ``data`` carries the guest-side pid.
        """
        command: dict[str, object] = {
            "execute": "guest-exec",
            "arguments": {
                "path": path,
                "arg": list(args),
                "capture-output": capture_output,
            },
        }
        return await self.execute_command(command, time_limit)

    async def guest_exec_status(
        self,
        pid: int,
        time_limit: float = QEMU_GA_EXEC_TIMEOUT,
    ) -> GuestExecStatus:
        """Query the state and captured output of a ``guest-exec`` process.

        Args:
            pid: Guest-side process id returned by :meth:`guest_exec`.
            time_limit: Response timeout in seconds.

        Returns:
            GuestExecStatus: Exit state plus decoded stdout/stderr.

        Raises:
            SandboxError: If the agent reports an error or returns a payload
                that is not a status object.
        """
        response = await self.execute_command(
            {"execute": "guest-exec-status", "arguments": {"pid": pid}},
            time_limit,
        )
        payload = _as_mapping(response.data)
        if not response.success or payload is None:
            _logger.warning(
                self._event("exec_status_unreadable"),
                pid=pid,
                error=response.error,
            )
            raise SandboxError(_ERR_QEMU_GA_EXEC_STATUS_FAILED)

        return self._decode_exec_status(payload)

    @classmethod
    def _decode_exec_status(cls, payload: dict[str, object]) -> GuestExecStatus:
        """Decode a ``guest-exec-status`` return payload.

        Args:
            payload: ``return`` mapping from the agent reply.

        Returns:
            GuestExecStatus: Structured status with base64 output decoded.
        """
        exit_code = payload.get("exitcode")
        signal_number = payload.get("signal")
        return GuestExecStatus(
            exited=bool(payload.get("exited")),
            exit_code=exit_code if isinstance(exit_code, int) else None,
            signal=signal_number if isinstance(signal_number, int) else None,
            stdout=cls._decode_stream(payload, "out-data"),
            stderr=cls._decode_stream(payload, "err-data"),
            stdout_truncated=bool(payload.get("out-truncated")),
            stderr_truncated=bool(payload.get("err-truncated")),
        )

    @classmethod
    def _decode_stream(cls, payload: dict[str, object], key: str) -> str:
        """Decode one base64-encoded output stream from a status payload.

        Args:
            payload: ``return`` mapping from the agent reply.
            key: Member holding the base64 text (``out-data`` or ``err-data``).

        Returns:
            str: Decoded text, or an empty string when the member is absent,
            empty, or not valid base64.
        """
        raw = payload.get(key)
        if not isinstance(raw, str) or not raw:
            return ""
        try:
            return base64.b64decode(raw, validate=True).decode("utf-8", errors="replace")
        except ValueError as e:
            _logger.warning(cls._event("exec_status_stream_undecodable"), stream=key, error=str(e))
            return ""


class GuestAgentClient:
    """Client for communicating with the QEMU guest agent.

    Provides bidirectional communication with the guest OS for command execution, file transfer, and behavioral monitoring.

    Attributes:
        PING_REQUEST_TYPE: Request type of the readiness handshake this client
            sends the moment a socket opens. The agent is reached through a
            QEMU SLIRP ``hostfwd``, which accepts the host-side TCP connection
            unconditionally and only afterwards tries to reach a listener
            inside the guest, so a successful ``connect`` proves nothing about
            the guest; this exchange is the smallest one that does, because the
            agent must have read a framed request and written a framed reply
            for the answer to arrive at all.
        PONG_MESSAGE_TYPE: Message type the agent answers
            :attr:`PING_REQUEST_TYPE` with. Public because anything modelling
            the in-guest agent - the generated agent scripts, and the test
            servers that stand in for them - has to speak exactly these two
            words.
        RECONNECT_TIME_LIMIT: Total seconds one attempt to re-establish a
            failed channel may spend before the command that triggered it is
            reported failed. Public because it bounds how long a caller can be
            held by a channel that is never coming back.
        RECONNECT_RETRY_INTERVAL: Seconds between connect attempts while the
            channel is being re-established.
        MAX_DISPATCH_ATTEMPTS: How many times one command may be written to the
            channel. Only a request that provably never reached the agent is
            written again, so this bounds recovery rather than enabling a
            retry.
    """

    PING_REQUEST_TYPE: ClassVar[str] = "ping"
    PONG_MESSAGE_TYPE: ClassVar[str] = "pong"
    RECONNECT_TIME_LIMIT: ClassVar[float] = _AGENT_RECONNECT_TIME_LIMIT
    RECONNECT_RETRY_INTERVAL: ClassVar[float] = _AGENT_RECONNECT_RETRY_INTERVAL
    MAX_DISPATCH_ATTEMPTS: ClassVar[int] = _AGENT_DISPATCH_ATTEMPTS

    _read_limit: ClassVar[int] = _JSON_LINE_LIMIT

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 4445,
        vm_terminated: Callable[[], QemuTermination | None] | None = None,
    ) -> None:
        """Initialize the guest agent client.

        Args:
            host: Host address where the guest agent is reachable.
            port: TCP port for the guest agent server.
            vm_terminated: Optional probe answering whether the virtual machine
                hosting the agent has stopped. A channel failure means
                something very different depending on the answer, so the client
                consults it before deciding what a failure was.
        """
        self._host = host
        self._port = port
        self._vm_terminated = vm_terminated
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.connected = False
        self._lock = asyncio.Lock()
        self._message_queue: asyncio.Queue[GuestAgentMessage] = asyncio.Queue()
        self._reader_task: asyncio.Task[None] | None = None
        self._read_failure: str | None = None
        _logger.debug("guest_agent_client_initialized", host=host, port=port)

    @property
    def is_connected(self) -> bool:
        """Whether the client is currently connected.

        Returns:
            bool: True if the guest agent connection is active.
        """
        return self.connected

    @classmethod
    def _is_pong_line(cls, line: bytes) -> bool:
        """Report whether one received line is the agent's readiness reply.

        Args:
            line: Newline-terminated bytes read from the agent socket.

        Returns:
            bool: True if the line is a well-formed pong message.
        """
        try:
            parsed: object = json.loads(line.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False
        if not isinstance(parsed, dict):
            return False
        return cast("dict[str, object]", parsed).get("type") == cls.PONG_MESSAGE_TYPE

    async def _await_readiness_reply(self, reader: asyncio.StreamReader, time_limit: float) -> None:
        """Read agent lines until the readiness reply arrives or the budget ends.

        Any other message the agent volunteers while the handshake is in flight
        is queued rather than dropped, so telemetry the caller is owed does not
        disappear into the handshake.

        Args:
            reader: Stream reader for the freshly opened agent socket.
            time_limit: Total seconds the handshake may take.

        Raises:
            ConnectionError: If the peer closes the channel, sends a frame the
                stream can no longer be framed around, or does not answer in
                time.
        """
        deadline = time.monotonic() + time_limit
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConnectionError(_ERR_AGENT_HANDSHAKE_TIMEOUT.format(timeout=time_limit))
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=remaining)
            except TimeoutError as e:
                raise ConnectionError(_ERR_AGENT_HANDSHAKE_TIMEOUT.format(timeout=time_limit)) from e
            except ValueError as e:
                raise ConnectionError(_ERR_AGENT_HANDSHAKE_UNFRAMED.format(error=str(e))) from e

            if not line:
                raise ConnectionError(_ERR_AGENT_HANDSHAKE_CLOSED)
            if self._is_pong_line(line):
                return
            await self._enqueue_agent_line(line)

    async def _handshake(self, time_limit: float) -> None:
        """Prove the in-guest agent is really answering on the open socket.

        Args:
            time_limit: Total seconds the handshake may take.

        Raises:
            ConnectionError: If no socket is open or the agent does not answer.
        """
        reader, writer = self._reader, self._writer
        if reader is None or writer is None:
            raise ConnectionError(_ERR_AGENT_HANDSHAKE_NO_SOCKET)

        writer.write((json.dumps({"type": self.PING_REQUEST_TYPE}) + "\n").encode())
        await writer.drain()
        await self._await_readiness_reply(reader, time_limit)

    async def _abandon_socket(self) -> None:
        """Drop a socket that failed its handshake, leaving nothing connected."""
        writer = self._writer
        self._reader = None
        self._writer = None
        self.connected = False
        if writer is None:
            return
        try:
            writer.close()
            await writer.wait_closed()
        except OSError as e:
            _logger.debug("guest_agent_abandon_socket_error", error=str(e))

    async def _open_agent_socket(self, retry_interval: float) -> None:
        """Open one connection attempt to the guest agent and prove it is live.

        The reader is given the same explicit line limit as the guest-agent
        channel: a ``result`` message carries the whole stdout of an in-guest
        command, which passes asyncio's 64 KiB default long before it reaches
        any size the agent itself would refuse to send.

        A connect to the QEMU hostfwd succeeds whether or not anything listens
        inside the guest, so the socket is only reported connected once the
        agent has answered the readiness handshake on it. An attempt that fails
        that handshake is closed here and raised, which returns the caller to
        :meth:`connect`'s retry loop rather than leaving a dead socket behind
        that every later command would fail on.

        Args:
            retry_interval: Per-attempt connect and handshake timeout in
                seconds.

        Raises:
            BaseException: Whatever the connect or the handshake raised, after
                the half-open socket has been closed.
        """
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self._host, self._port, limit=self._read_limit),
            timeout=retry_interval,
        )
        try:
            await self._handshake(retry_interval)
        except BaseException:
            await self._abandon_socket()
            raise

        self._read_failure = None
        self.connected = True
        self._reader_task = asyncio.create_task(self._read_messages())
        _logger.info("guest_agent_connected", host=self._host, port=self._port)

    async def connect(
        self,
        time_limit: float = 60.0,
        retry_interval: float = 2.0,
        backoff_interval: float | None = None,
    ) -> bool:
        """Connect to guest agent with retry.

        How long one attempt may take and how long to wait before the next one
        are separate questions, and a caller that widens the first does not
        mean to widen the second. Waiting out a slow in-guest agent needs a
        generous per-attempt budget; noticing the moment an agent finally
        reaches ``listen`` needs frequent attempts. Tying the two together
        would spend a whole handshake budget sleeping after every refused
        connection, which inside a 30 s total budget is the difference between
        a dozen chances to catch the agent coming up and two.

        Both are clamped to what is left of ``time_limit``, so no combination
        of the two can overrun the deadline the caller asked for.

        Args:
            time_limit: Total timeout in seconds for connection attempts.
            retry_interval: Per-attempt budget for the connect and the
                readiness handshake.
            backoff_interval: Seconds to wait between attempts. Defaults to
                ``retry_interval``, which is the historical behaviour.

        Returns:
            bool: True if connected successfully.
        """
        backoff_interval = retry_interval if backoff_interval is None else backoff_interval
        deadline = time.monotonic() + time_limit

        connected = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                break
            try:
                await self._open_agent_socket(min(retry_interval, remaining))
                connected = True
                break
            except (TimeoutError, OSError):
                _logger.warning("guest_agent_connect_retry", host=self._host, port=self._port)
                backoff = min(backoff_interval, deadline - time.monotonic())
                if backoff <= 0.0:
                    break
                await asyncio.sleep(backoff)

        if not connected:
            _logger.warning("guest_agent_connection_failed", timeout_seconds=time_limit)
        return connected

    async def disconnect(self) -> None:
        """Disconnect from guest agent.

        A socket the peer has already reset cannot be closed cleanly, and that
        is the ordinary state of this channel at teardown: the guest is on its
        way down, or the forwarded connection died and is what brought the
        caller here. Failing to close it changes nothing a caller can act on,
        so it is recorded at debug level rather than reported as a fault.

        The reader stopping is likewise not a fault: the cancellation it raises
        is this method's own, and rendering its traceback would put a stack
        trace in the log of every clean teardown.
        """
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                _logger.debug("guest_agent_disconnect_cancelled")
            self._reader_task = None

        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except OSError as e:
                _logger.debug("agent_disconnect_error", error=str(e))

        self._reader = None
        self._writer = None
        self.connected = False

    async def _enqueue_agent_line(self, line: bytes) -> None:
        """Decode a raw agent line and enqueue a parsed message.

        A line whose bytes are not valid UTF-8 and a line that is not valid
        JSON are each one unreadable message, not a broken stream: the newline
        framing around them is intact, so both are logged and dropped and the
        reader goes on to the next line.

        Args:
            line: Newline-terminated bytes received from the agent socket.
        """
        try:
            text = line.decode()
        except UnicodeDecodeError as e:
            _logger.warning("agent_invalid_utf8", line=line.decode(errors="replace"), error=str(e))
            return

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            _logger.warning("agent_invalid_json", line=text)
            return

        msg = GuestAgentMessage(
            message_type=data.get("type", "unknown"),
            timestamp=datetime.now(UTC),
            data=data.get("data", {}),
        )
        await self._message_queue.put(msg)

    def _stop_reading(self, reason: str) -> None:
        """Mark the channel unusable and record why the reader stopped.

        A command already waiting for a reply would otherwise sit out its whole
        deadline on a channel that can no longer deliver one, and report a
        timeout instead of the failure that really happened.

        Args:
            reason: Cause reported to a waiting command.
        """
        self._read_failure = reason
        self.connected = False

    async def _read_messages(self) -> None:
        """Background task to read messages from agent.

        Only the read itself is guarded against :class:`ValueError`: that is how
        ``StreamReader.readline`` reports a frame longer than the reader's
        limit, and it leaves the rest of that frame unread, so the stream can no
        longer be framed on newlines and the channel is finished. Decoding the
        line that was read is not covered by that guard - a line the reader
        delivered whole is a message-level problem, which
        :meth:`_enqueue_agent_line` handles without ending the reader.
        """
        if self._reader is None:
            return

        while self.connected:
            try:
                line = await self._reader.readline()
            except asyncio.CancelledError:
                _logger.debug("agent_read_cancelled")
                break
            except ValueError as e:
                _logger.warning("agent_read_line_too_long", error=str(e), read_limit=self._read_limit)
                self._stop_reading(_ERR_JSON_LINE_TOO_LONG.format(limit=self._read_limit))
                break
            except (OSError, ConnectionError) as e:
                _logger.warning("agent_read_error", error=str(e), exc_info=True)
                self._stop_reading(str(e))
                break

            if not line:
                _logger.warning("agent_channel_closed_by_peer", host=self._host, port=self._port)
                self._stop_reading(_ERR_AGENT_CHANNEL_CLOSED)
                break

            await self._enqueue_agent_line(line)

    async def send_command(
        self,
        command: str,
        args: Sequence[str] | None = None,
        time_limit: float = 30.0,
    ) -> tuple[int, str, str]:
        """Send a command to execute in the guest.

        A channel that has died since the last command is re-established here
        rather than ending the session: the forwarded socket this travels over
        can be reset while the guest itself is perfectly healthy, and every
        later command would otherwise fail on a connection nothing reopens.
        What is never repeated is a command that already reached the agent -
        see :meth:`_run_with_channel_recovery`.

        Args:
            command: Command to execute.
            args: Command arguments.
            time_limit: Execution timeout in seconds.

        Returns:
            tuple[int, str, str]: Tuple of (exit_code, stdout, stderr).
        """
        _logger.debug(
            "guest_send_command_called",
            command=command,
            args_count=len(args) if args else 0,
            time_limit=time_limit,
        )
        request = {
            "type": "execute",
            "command": command,
            "args": list(args) if args else [],
            "timeout": time_limit,
        }

        async with self._lock:
            return await self._run_with_channel_recovery(request, time_limit)

    async def _run_with_channel_recovery(
        self,
        request: Mapping[str, object],
        time_limit: float,
    ) -> tuple[int, str, str]:
        """Run one request, re-opening the channel around a failure of it.

        Recovery is deliberately asymmetric. A request that never left the host
        cannot have run inside the guest, so a fresh channel is opened and it is
        written again. A request that did leave the host may already be
        executing - the sandbox's whole purpose is to run an analysis target,
        and running one twice is worse than reporting that a run's outcome is
        unknown - so the channel is re-opened for the commands that follow but
        this one is reported failed and never repeated.

        Both of those presume there is still a guest on the other end. When the
        virtual machine itself has stopped, no reconnection can succeed and
        nothing is still executing, so that is reported as what it is rather
        than spending the reconnect budget dialling a socket that no longer has
        a listener.

        Args:
            request: Serializable request payload to send.
            time_limit: Total wall-clock deadline for the response.

        Returns:
            tuple[int, str, str]: ``(exit_code, stdout, stderr)`` from the
            guest agent's reply, or a failure triple explaining what became of
            the channel.
        """
        reason = _ERR_AGENT_NOT_CONNECTED
        for attempt in range(self.MAX_DISPATCH_ATTEMPTS):
            outcome = await self._attempt_dispatch(request, time_limit)
            if outcome.result is not None:
                return outcome.result
            reason = outcome.reason
            stopped = self._vm_termination_detail()
            if stopped is not None:
                _logger.warning("guest_agent_channel_lost_with_vm", reason=reason, detail=stopped)
                return (-1, "", _ERR_AGENT_LOST_VM_GONE.format(detail=stopped))
            if outcome.dispatched:
                await self._reestablish_channel(reason)
                return (-1, "", _ERR_AGENT_LOST_AFTER_DISPATCH.format(reason=reason))
            if attempt + 1 >= self.MAX_DISPATCH_ATTEMPTS:
                break
            if not await self._reestablish_channel(reason):
                return (-1, "", _ERR_AGENT_RECONNECT_FAILED.format(reason=reason))
        return (
            -1,
            "",
            _ERR_AGENT_DISPATCH_EXHAUSTED.format(attempts=self.MAX_DISPATCH_ATTEMPTS, reason=reason),
        )

    async def _attempt_dispatch(
        self,
        request: Mapping[str, object],
        time_limit: float,
    ) -> _DispatchAttempt:
        """Write one request to the open channel and wait for its reply.

        The dispatch boundary is the drain that follows the write: until it
        returns, the request is still the host's, and every failure up to that
        point leaves the guest untouched. Once it has returned the bytes are on
        their way and nothing the host can observe afterwards distinguishes a
        request the agent never saw from one it is running right now.

        Args:
            request: Serializable request payload to send.
            time_limit: Total wall-clock deadline for the response.

        Returns:
            _DispatchAttempt: The reply, or why no reply arrived and whether
            the request had already been dispatched when the channel failed.
        """
        writer = self._writer
        if writer is None or not self.connected:
            return _DispatchAttempt(None, dispatched=False, reason=self._read_failure or _ERR_AGENT_NOT_CONNECTED)

        try:
            writer.write((json.dumps(request) + "\n").encode())
            await writer.drain()
        except (OSError, ConnectionError) as e:
            _logger.warning("guest_command_dispatch_failed", error=str(e), exc_info=True)
            return _DispatchAttempt(None, dispatched=False, reason=str(e))

        msg = await self._await_guest_result(time_limit)
        if msg is not None:
            return _DispatchAttempt(self._decode_guest_result(msg), dispatched=True, reason="")
        if self.connected:
            return _DispatchAttempt((-1, "", _ERR_AGENT_COMMAND_TIMED_OUT), dispatched=True, reason="")
        return _DispatchAttempt(None, dispatched=True, reason=self._read_failure or _ERR_AGENT_CHANNEL_CLOSED)

    def _vm_termination_detail(self) -> str | None:
        """Describe the hosting virtual machine's death, if it has died.

        Returns:
            str | None: A one-line account of how the virtual machine stopped,
            or ``None`` when it is still running or cannot be observed.
        """
        if self._vm_terminated is None:
            return None
        termination = self._vm_terminated()
        return termination.describe() if termination is not None else None

    async def _reestablish_channel(self, reason: str) -> bool:
        """Replace a failed channel with a freshly handshaken one.

        The existing :meth:`connect` path is what runs here, so a re-opened
        channel is proven live by the same readiness handshake a first connect
        is, and is bounded by the same retry loop.

        Args:
            reason: Why the previous channel failed, for the log record.

        Returns:
            bool: True if a live channel is open again.
        """
        _logger.warning(
            "guest_agent_channel_reconnecting",
            host=self._host,
            port=self._port,
            reason=reason,
        )
        await self.disconnect()
        self._read_failure = None
        self._discard_orphaned_results()

        reconnected = await self.connect(
            time_limit=self.RECONNECT_TIME_LIMIT,
            retry_interval=self.RECONNECT_RETRY_INTERVAL,
        )
        if not reconnected:
            _logger.warning("guest_agent_channel_reconnect_failed", host=self._host, port=self._port, reason=reason)
        return reconnected

    def _discard_orphaned_results(self) -> int:
        """Drop queued results belonging to a channel that no longer exists.

        A reply left in the queue by a dead channel answers a command that has
        already returned. Handing it to the next command would report one
        command's outcome as another's, so results are dropped while every
        other message the agent volunteered is put back in arrival order.

        Returns:
            int: How many orphaned result messages were discarded.
        """
        retained: list[GuestAgentMessage] = []
        discarded = 0
        while not self._message_queue.empty():
            try:
                msg = self._message_queue.get_nowait()
            except asyncio.QueueEmpty:
                _logger.debug("message_queue_empty")
                break
            if msg.message_type == _AGENT_RESULT_MESSAGE_TYPE:
                discarded += 1
                continue
            retained.append(msg)

        for msg in retained:
            self._message_queue.put_nowait(msg)
        if discarded:
            _logger.debug("guest_agent_orphaned_results_discarded", count=discarded)
        return discarded

    @staticmethod
    def _decode_guest_result(msg: GuestAgentMessage) -> tuple[int, str, str]:
        """Decode a ``result`` message from the guest agent into a process triple.

        Args:
            msg: Message whose ``data`` payload contains the result fields.

        Returns:
            tuple[int, str, str]: ``(exit_code, stdout, stderr)`` extracted from
            ``msg``.
        """
        exit_code_raw = msg.data.get("exit_code")
        exit_code_val = int(exit_code_raw) if exit_code_raw is not None and isinstance(exit_code_raw, (int, str)) else -1
        return (
            exit_code_val,
            str(msg.data.get("stdout", "")),
            str(msg.data.get("stderr", "")),
        )

    async def _await_guest_result(self, time_limit: float) -> GuestAgentMessage | None:
        """Poll the message queue until a result message arrives or the deadline elapses.

        A reply that reached the queue before the channel died is still that
        command's answer, so the queue is swept once more after the loop ends
        rather than discarding a result because the socket failed immediately
        behind it.

        The queue is read in short slices so a channel that dies under a
        waiting command is noticed within a slice rather than at the deadline.
        A slice that expires empty is this loop's ordinary continue path - the
        guest is still working on the command - and carries no diagnostic
        value, so it is counted rather than logged. What is reported is the
        wait ending with nothing, once, naming which of the two ways it ended.

        Args:
            time_limit: Total wall-clock deadline in seconds.

        Returns:
            GuestAgentMessage | None: The result message, or None when the
            deadline elapsed or the channel failed with no reply queued.
        """
        start_time = time.time()
        idle_polls = 0
        while self.connected and time.time() - start_time < time_limit:
            try:
                msg = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=_AGENT_POLL_TIMEOUT,
                )
            except TimeoutError:
                idle_polls += 1
                continue
            if msg.message_type == _AGENT_RESULT_MESSAGE_TYPE:
                return msg

        queued = self._take_queued_result()
        if queued is None:
            self._report_absent_result(time.time() - start_time, idle_polls, time_limit)
        return queued

    def _report_absent_result(self, waited: float, idle_polls: int, time_limit: float) -> None:
        """Report a wait that ended without the command's reply.

        The two ways that happens are worth telling apart. A channel still open
        means the guest did not answer inside the budget it was given, and the
        command is what failed. A closed one means the answer can no longer
        arrive at all, and the reason the reader recorded is the real fault -
        the exception behind it was already logged with its traceback where it
        was raised, so it is named here rather than re-rendered.

        Args:
            waited: Seconds spent waiting for the reply.
            idle_polls: How many poll slices expired with nothing queued.
            time_limit: Deadline the wait was given, in seconds.
        """
        if self.connected:
            _logger.warning(
                "guest_command_result_timeout",
                waited_seconds=round(waited, 3),
                time_limit=time_limit,
                idle_polls=idle_polls,
            )
            return
        _logger.warning(
            "guest_command_channel_closed_before_result",
            waited_seconds=round(waited, 3),
            idle_polls=idle_polls,
            reason=self._read_failure or _ERR_AGENT_CHANNEL_CLOSED,
        )

    def _take_queued_result(self) -> GuestAgentMessage | None:
        """Remove and return the first result message already sitting in the queue.

        Returns:
            GuestAgentMessage | None: The queued result, or None if there is
            none. Every message ahead of it is put back in arrival order.
        """
        retained: list[GuestAgentMessage] = []
        found: GuestAgentMessage | None = None
        while not self._message_queue.empty():
            try:
                msg = self._message_queue.get_nowait()
            except asyncio.QueueEmpty:
                _logger.debug("message_queue_empty")
                break
            if found is None and msg.message_type == _AGENT_RESULT_MESSAGE_TYPE:
                found = msg
                continue
            retained.append(msg)

        for msg in retained:
            self._message_queue.put_nowait(msg)
        return found

    async def get_pending_messages(self) -> list[GuestAgentMessage]:
        """Get all pending messages from the agent.

        Returns:
            list[GuestAgentMessage]: List of pending messages.
        """
        messages: list[GuestAgentMessage] = []
        while not self._message_queue.empty():
            try:
                msg = self._message_queue.get_nowait()
                messages.append(msg)
            except asyncio.QueueEmpty:
                _logger.debug("message_queue_empty")
                break
        return messages


@dataclass(frozen=True)
class QemuTermination:
    """How the QEMU process stopped and what it said on the way out.

    Attributes:
        returncode: Exit status QEMU reported.
        output_tail: The last lines QEMU wrote to stdout or stderr, oldest
            first, each already tagged with the stream it came from.
    """

    returncode: int
    output_tail: tuple[str, ...]

    def describe(self) -> str:
        """Render the termination as one line fit for an error message.

        Returns:
            str: The exit status followed by QEMU's parting output.
        """
        tail = " | ".join(self.output_tail) if self.output_tail else _QEMU_EXIT_UNKNOWN_OUTPUT
        return f"QEMU exited with code {self.returncode}; {tail}"


class QemuOutputRecorder:
    """Drain a running QEMU's output streams and remember how it ended.

    A foreground QEMU child is spawned with piped stdout and stderr, and
    nothing else in the sandbox reads them for the life of the guest. Two
    things follow from leaving them unread. The operating system's pipe buffer
    is a fixed size, so a QEMU that keeps writing eventually blocks inside
    ``write`` and the guest freezes with no record of why. And when QEMU dies
    on its own - a rejected instruction, an accelerator fault, a guest triple
    fault - the exit status and the message explaining it are discarded, which
    is exactly the evidence needed to explain the death.

    Draining continuously fixes both: the pipes never fill, every line reaches
    the log as QEMU emits it, and a bounded tail is retained so the last thing
    QEMU said survives the process that said it.
    """

    def __init__(self, process: asyncio.subprocess.Process, tail_lines: int = _QEMU_OUTPUT_TAIL_LINES) -> None:
        """Prepare a recorder for one QEMU process.

        Args:
            process: The spawned QEMU child whose streams are drained.
            tail_lines: How many of the most recent output lines to retain.
        """
        self._process = process
        self._tail: deque[str] = deque(maxlen=tail_lines)
        self._task: asyncio.Task[None] | None = None
        self._termination: QemuTermination | None = None
        self._exit_expected = False

    @property
    def termination(self) -> QemuTermination | None:
        """The recorded termination, or ``None`` while QEMU is still running.

        Returns:
            QemuTermination | None: How QEMU ended, once it has ended.
        """
        return self._termination

    def start(self) -> None:
        """Begin draining both output streams in the background."""
        if self._task is None:
            self._task = asyncio.create_task(self._record())

    def expect_exit(self) -> None:
        """Note that an upcoming exit is a deliberate shutdown, not a failure."""
        self._exit_expected = True

    async def aclose(self) -> None:
        """Stop draining, waiting briefly for the reader to finish on its own."""
        task = self._task
        self._task = None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            _logger.debug("qemu_output_recorder_cancelled")
        except (OSError, ConnectionError, ValueError) as error:
            # Reported rather than raised: draining QEMU's output is a
            # diagnostic aid, and a fault in it must not turn tearing the
            # sandbox down into a failure of its own.
            _logger.warning("qemu_output_recorder_failed", error=str(error), exc_info=True)

    async def _record(self) -> None:
        """Drain both streams to exhaustion, then record how QEMU ended."""
        await asyncio.gather(
            self._pump(self._process.stdout, "stdout"),
            self._pump(self._process.stderr, "stderr"),
        )
        returncode = await self._process.wait()
        self._termination = QemuTermination(returncode=returncode, output_tail=tuple(self._tail))
        if self._exit_expected:
            _logger.info("qemu_process_exited", returncode=returncode)
            return
        _logger.warning(
            "qemu_process_exited_unexpectedly",
            returncode=returncode,
            output_tail=list(self._tail),
        )

    async def _pump(self, stream: asyncio.StreamReader | None, channel: str) -> None:
        """Read one stream to EOF, logging and retaining whole lines.

        Fixed-size reads are used rather than ``readline`` because QEMU is free
        to emit a line longer than the stream reader's buffer limit, and a
        recorder that raises on unusually long output would defeat its own
        purpose at exactly the moment the output matters.

        Args:
            stream: The stream to drain; ``None`` when it was never piped.
            channel: Stream name recorded alongside each line.
        """
        if stream is None:
            return
        pending = ""
        while True:
            try:
                chunk = await stream.read(_QEMU_OUTPUT_READ_SIZE)
            except (OSError, ConnectionError) as error:
                _logger.debug("qemu_output_read_failed", channel=channel, error=str(error))
                return
            if not chunk:
                break
            pending += chunk.decode(errors="replace")
            *lines, pending = pending.split("\n")
            for line in lines:
                self._retain(line, channel)
        if pending.strip():
            self._retain(pending, channel)

    def _retain(self, line: str, channel: str) -> None:
        """Log one output line and keep it in the bounded tail.

        Args:
            line: The line QEMU emitted, without its terminator.
            channel: Stream name the line arrived on.
        """
        text = line.strip()
        if not text:
            return
        _logger.debug("qemu_output", channel=channel, line=text)
        self._tail.append(f"{channel}: {text}")


class QEMUSandbox(SandboxBase):
    """QEMU-based sandbox for cross-platform binary analysis.

    Uses QEMU virtualization with hardware acceleration (WHPX on Windows,
    KVM on Linux) or software emulation (TCG) for isolated binary execution.

    Attributes:
        QEMU_EXE: QEMU executable name.
        QEMU_IMG_EXE: qemu-img executable name, used to build the per-instance
            disk overlay.
        TOOLS_PATH: Bundled QEMU installation directory, resolved from the
            installed project root rather than a fixed absolute location.
        GUEST_SHARED_PATH_WINDOWS: Default shared-volume root on a Windows
            guest, used until :meth:`_mount_guest_shared_volume` has probed the
            drive letter the guest really assigned.
        GUEST_SHARED_PATH_LINUX: Default shared-volume mount point on a Linux
            guest.
    """

    QEMU_EXE: Final[str] = "qemu-system-x86_64"
    QEMU_IMG_EXE: Final[str] = "qemu-img"
    TOOLS_PATH: Final[Path] = get_project_root() / "tools" / "qemu"
    GUEST_SHARED_PATH_WINDOWS: Final[str] = _GUEST_SHARED_ROOT_WINDOWS
    GUEST_SHARED_PATH_LINUX: Final[str] = _GUEST_SHARED_ROOT_LINUX

    _reserved_host_ports: ClassVar[set[int]] = set()
    _port_reservation_lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(
        self,
        config: SandboxConfig | None = None,
        qemu_config: QEMUConfig | None = None,
    ) -> None:
        """Initialize the QEMU sandbox.

        Args:
            config: General sandbox configuration shared across backends.
            qemu_config: QEMU-specific configuration such as memory and disk image.
        """
        super().__init__(config)
        self._qemu_config = qemu_config or QEMUConfig()
        self.process: asyncio.subprocess.Process | None = None
        self._output_recorder: QemuOutputRecorder | None = None
        self._qmp: QMPClient | None = None
        self._qga: QemuGuestAgentClient | None = None
        self._agent: GuestAgentClient | None = None
        self._temp_dir: Path | None = None
        self._shared_folder: Path | None = None
        self._accelerator: AcceleratorType = AcceleratorType.TCG
        self._qemu_path: Path | None = None
        self._pidfile_path: Path | None = None
        self._qemu_pid: int | None = None
        self._vnc_port: int | None = None
        self._claimed_host_ports: set[int] = set()
        self._active_captures: dict[str, Path] = {}
        self._accelerator_cached: bool = False
        self._agent_guest_pid: int | None = None
        self._guest_shared_root: str | None = None
        self._guest_system_drive_value: str | None = None
        self._guest_system_root_value: str | None = None
        self._guest_exec_ready: bool = False
        _logger.info(
            "qemu_sandbox_initialized",
            guest_os=self._qemu_config.guest_os.value,
            memory_mb=self._qemu_config.memory_mb,
            cpu_cores=self._qemu_config.cpu_cores,
        )

    @property
    def qemu_config(self) -> QEMUConfig:
        """QEMU configuration backing this sandbox.

        Returns:
            QEMUConfig: Current QEMU configuration.
        """
        return self._qemu_config

    @property
    def vnc_port(self) -> int | None:
        """VNC port when the VNC display is active.

        Returns:
            int | None: VNC port number, or None if VNC is not enabled.
        """
        return self._vnc_port

    @property
    def qmp(self) -> QMPClient | None:
        """QMP client, or None if not connected.

        Returns:
            QMPClient | None: Active QMP client, or None if the VM is not running.
        """
        return self._qmp

    @property
    def agent(self) -> GuestAgentClient | None:
        """Guest agent client, or None if not connected.

        Returns:
            GuestAgentClient | None: Active guest agent client, or None if the agent is not connected.
        """
        return self._agent

    @property
    def qemu_guest_agent(self) -> QemuGuestAgentClient | None:
        """Qemu-guest-agent channel client, or None if not connected.

        Returns:
            QemuGuestAgentClient | None: Active qemu-guest-agent client, or
            None while the guest-agent channel has not been opened.
        """
        return self._qga

    def enable_vnc_display(self) -> None:
        """Switch display mode to VNC for GUI embedding.

        This must be called before ``start()`` to take effect. If the sandbox is already running, restart is required. A free VNC port is
        chosen immediately so :attr:`vnc_port` is usable before the guest boots, and ``start()`` launches QEMU on that same port whenever it
        is still free. Nothing binds the port in the meantime, so ``start()`` re-probes it and draws a replacement if something else claimed
        it first.
        """
        self._qemu_config = QEMUConfig(
            guest_os=self._qemu_config.guest_os,
            image_path=self._qemu_config.image_path,
            cpu_cores=self._qemu_config.cpu_cores,
            memory_mb=self._qemu_config.memory_mb,
            display="vnc",
            ssh_port=self._qemu_config.ssh_port,
            monitor_port=self._qemu_config.monitor_port,
            agent_port=self._qemu_config.agent_port,
            enable_acceleration=self._qemu_config.enable_acceleration,
            snapshot_name=self._qemu_config.snapshot_name,
            shared_folder=self._qemu_config.shared_folder,
            anti_evasion_profile=self._qemu_config.anti_evasion_profile,
            agent_connect_timeout=self._qemu_config.agent_connect_timeout,
            guest_agent_ready_timeout=self._qemu_config.guest_agent_ready_timeout,
        )
        self._vnc_port = self._get_free_port(_VNC_PORT_BASE, _VNC_PORT_MAX)
        _logger.info("vnc_display_enabled", vnc_port=self.vnc_port)

    def invalidate_accelerator_cache(self) -> None:
        """Invalidate the cached accelerator detection result.

        Forces the next call to ``is_available`` to re-probe the host for hardware virtualisation support. Useful after a system
        configuration change (e.g. enabling Hyper-V Platform) without restarting the application.
        """
        self._accelerator_cached = False
        _logger.debug("accelerator_cache_invalidated")

    async def is_available(self) -> bool:
        """Check if QEMU is available.

        Checks for QEMU executable and determines available acceleration.
        The accelerator detection result is cached after the first successful
        probe; call :meth:`invalidate_accelerator_cache` to force re-detection.

        Returns:
            bool: True if QEMU can be used.
        """
        qemu_path = await self._find_qemu()
        if qemu_path is None:
            _logger.debug("qemu_executable_not_found", search_names=["qemu-system-x86_64"])
            return False

        self._qemu_path = qemu_path

        if not self._accelerator_cached:
            self._accelerator = await self._detect_accelerator()
            self._accelerator_cached = True
            _logger.info(
                "qemu_available",
                path=str(qemu_path),
                accelerator=self._accelerator.value,
            )
        else:
            _logger.debug(
                "qemu_available_cached_accelerator",
                path=str(qemu_path),
                accelerator=self._accelerator.value,
            )
        return True

    async def _find_qemu(self) -> Path | None:
        """Find QEMU executable.

        Returns:
            Path | None: Path to QEMU executable or None if not found.
        """
        search_paths: list[Path] = []

        if await asyncio.to_thread(self.TOOLS_PATH.exists):
            search_paths.append(self.TOOLS_PATH / f"{self.QEMU_EXE}.exe")

        if qemu_in_path := shutil.which(self.QEMU_EXE):
            search_paths.append(Path(qemu_in_path))

        common_paths = [
            Path("C:/Program Files/qemu"),
            Path("C:/Program Files (x86)/qemu"),
            Path("/usr/bin"),
            Path("/usr/local/bin"),
        ]
        for base in common_paths:
            exe_name = f"{self.QEMU_EXE}.exe" if base.drive else self.QEMU_EXE
            search_paths.append(base / exe_name)

        def _find_existing() -> Path | None:
            """Return the first existing QEMU executable path on disk.

            Returns:
                Path | None: First ``search_paths`` entry that is a real file, or
                ``None`` when none exist.
            """
            return next(
                (path for path in search_paths if path.exists() and path.is_file()),
                None,
            )

        return await asyncio.to_thread(_find_existing)

    @staticmethod
    def _hypervisor_present_unelevated() -> bool | None:
        """Report whether a hypervisor is running, without requiring elevation.

        ``Win32_ComputerSystem.HypervisorPresent`` is readable by an ordinary
        user, unlike ``Get-WindowsOptionalFeature -Online`` and
        ``bcdedit /enum``, both of which require an elevated token. It answers
        the question that actually matters for WHPX - is the hypervisor
        running right now - rather than whether an optional feature is
        installed.

        Returns:
            bool | None: The hypervisor-present flag, or ``None`` when the
            query could not be answered so the caller can fall back.
        """
        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if pwsh is None:
            _logger.debug("whpx_probe_no_powershell")
            return None

        try:
            cim_result = _subprocess_run(
                [
                    pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "(Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent",
                ],
                capture_output=True,
                text=True,
                timeout=_ACCEL_DETECT_TIMEOUT,
                check=False,
            )
        except (OSError, _SubprocessTimeoutExpired) as e:
            _logger.debug("whpx_hypervisor_present_probe_failed", error=str(e))
            return None

        answer = cim_result.stdout.strip().lower()
        if answer == "true":
            return True
        if answer == "false":
            return False
        _logger.debug("whpx_hypervisor_present_unparsable", output=answer)
        return None

    @staticmethod
    def _probe_whpx_host_prerequisites() -> bool:
        """Verify that the host OS has Hyper-V Platform (WHPX) actually enabled.

        QEMU reports ``whpx`` in ``-accel help`` output whenever the binary was
        compiled with WHPX support, but the feature is useless unless the
        Hyper-V hypervisor is *running*.

        The primary signal is ``Win32_ComputerSystem.HypervisorPresent``, which
        needs no elevation. The original checks -
        ``Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform``
        and ``bcdedit /enum {current}`` - both require an elevated token, so on
        the ordinary unelevated run they failed, left stdout empty, and made
        this method report "not enabled" on hosts where WHPX works perfectly.
        They are retained only as a fallback for when the unelevated query
        cannot answer.

        Returns:
            bool: ``True`` when the host is confirmed able to run WHPX.
        """
        if platform.system() != "Windows":
            return False

        hypervisor_present = QEMUSandbox._hypervisor_present_unelevated()
        if hypervisor_present is not None:
            if not hypervisor_present:
                _logger.debug("whpx_hypervisor_not_running")
            return hypervisor_present

        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if pwsh is None:
            _logger.debug("whpx_probe_no_powershell")
            return False

        _logger.debug("whpx_feature_probe_started", pwsh=pwsh)
        try:
            ps_result = _subprocess_run(
                [
                    pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "(Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction Stop).State",
                ],
                capture_output=True,
                text=True,
                timeout=_ACCEL_DETECT_TIMEOUT,
                check=False,
            )
            feature_state = ps_result.stdout.strip().lower()
            if feature_state != "enabled":
                _logger.debug("whpx_hypervisor_platform_not_enabled", state=feature_state)
                return False
        except (OSError, _SubprocessTimeoutExpired) as e:
            _logger.warning("whpx_feature_probe_failed", error=str(e))
            return False

        bcdedit_path = shutil.which("bcdedit.exe") or shutil.which("bcdedit")
        if bcdedit_path is None:
            _logger.debug("whpx_probe_no_bcdedit")
            return False
        _logger.debug("whpx_bcdedit_probe_started", bcdedit=bcdedit_path)
        try:
            if not QEMUSandbox._bcdedit_reports_hypervisor_auto(bcdedit_path):
                return False
        except (OSError, _SubprocessTimeoutExpired) as e:
            _logger.warning("whpx_bcdedit_probe_failed", error=str(e))
            return False

        _logger.debug("whpx_host_prerequisites_satisfied")
        return True

    @staticmethod
    def _bcdedit_reports_hypervisor_auto(bcdedit_path: str) -> bool:
        """Invoke ``bcdedit /enum {current}`` and check the hypervisor launch type.

        Args:
            bcdedit_path: Absolute path to the ``bcdedit`` executable.

        Returns:
            bool: True when ``hypervisorlaunchtype`` is present and set to
            ``auto``; False otherwise.
        """
        bcdedit_result = _subprocess_run(
            [bcdedit_path, "/enum", "{current}"],
            capture_output=True,
            text=True,
            timeout=_ACCEL_DETECT_TIMEOUT,
            check=False,
        )
        bcd_output = bcdedit_result.stdout.lower()
        if "hypervisorlaunchtype" not in bcd_output:
            _logger.debug("whpx_bcdedit_no_hypervisorlaunchtype")
            return False
        if "hypervisorlaunchtype    auto" not in bcd_output and "hypervisorlaunchtype  auto" not in bcd_output:
            _logger.debug("whpx_bcdedit_hypervisorlaunchtype_not_auto", bcd_output=bcd_output)
            return False
        return True

    async def _try_whpx_accelerator(
        self,
        process_manager: ProcessManager,
        output_lower: str,
    ) -> AcceleratorType | None:
        """Probe WHPX support and return :attr:`AcceleratorType.WHPX` when usable.

        Args:
            process_manager: Active :class:`ProcessManager` used for tracked
                subprocess invocations.
            output_lower: Lower-cased ``-accel help`` output to scan for WHPX
                advertisement.

        Returns:
            AcceleratorType | None: :attr:`AcceleratorType.WHPX` if WHPX is
            advertised, prerequisites are satisfied, and the smoke test
            succeeds; ``None`` otherwise.
        """
        if "whpx" not in output_lower:
            return None

        whpx_prereqs = await asyncio.to_thread(self._probe_whpx_host_prerequisites)
        if not whpx_prereqs:
            _logger.info("whpx_skipped_host_prerequisites_not_met")
            return None

        whpx_test = await process_manager.run_tracked_async(
            [
                str(self._qemu_path),
                "-accel",
                "whpx",
                "-machine",
                "q35",
                "-m",
                "64",
                "-display",
                "none",
                "-device",
                "?",
            ],
            name="qemu-whpx-test",
            text=False,
            process_timeout=_ACCEL_TEST_TIMEOUT,
        )
        stderr_bytes = whpx_test.stderr if isinstance(whpx_test.stderr, bytes) else whpx_test.stderr.encode()
        if whpx_test.returncode == _RETURNCODE_SUCCESS or b"whpx" not in stderr_bytes.lower():
            _logger.info("whpx_acceleration_available", accelerator="whpx")
            return AcceleratorType.WHPX
        return None

    async def _try_kvm_accelerator(
        self,
        process_manager: ProcessManager,
        output_lower: str,
    ) -> AcceleratorType | None:
        """Probe KVM support and return :attr:`AcceleratorType.KVM` when usable.

        Args:
            process_manager: Active :class:`ProcessManager` used for tracked
                subprocess invocations.
            output_lower: Lower-cased ``-accel help`` output to scan for KVM
                advertisement.

        Returns:
            AcceleratorType | None: :attr:`AcceleratorType.KVM` if the KVM
            smoke test exits successfully; ``None`` otherwise.
        """
        if "kvm" not in output_lower:
            return None

        kvm_test = await process_manager.run_tracked_async(
            [
                str(self._qemu_path),
                "-accel",
                "kvm",
                "-machine",
                "q35",
                "-m",
                "64",
                "-display",
                "none",
                "-device",
                "?",
            ],
            name="qemu-kvm-test",
            text=False,
            process_timeout=_ACCEL_TEST_TIMEOUT,
        )
        if kvm_test.returncode == _RETURNCODE_SUCCESS:
            _logger.info("kvm_acceleration_available", accelerator="kvm")
            return AcceleratorType.KVM
        return None

    async def _detect_accelerator_impl(self, process_manager: ProcessManager) -> AcceleratorType | None:
        """Run the WHPX and KVM detection probes for :meth:`_detect_accelerator`.

        Args:
            process_manager: Active :class:`ProcessManager` used for tracked
                subprocess invocations.

        Returns:
            AcceleratorType | None: The first accelerator that passes its
            smoke test, or ``None`` if no hardware accelerator is usable.
        """
        result = await process_manager.run_tracked_async(
            [str(self._qemu_path), "-accel", "help"],
            name="qemu-accel-help",
            process_timeout=_ACCEL_DETECT_TIMEOUT,
        )
        output_lower = (result.stdout + result.stderr).lower()

        whpx = await self._try_whpx_accelerator(process_manager, output_lower)
        if whpx is not None:
            return whpx

        return await self._try_kvm_accelerator(process_manager, output_lower)

    async def _detect_accelerator(self) -> AcceleratorType:
        """Detect available hardware acceleration.

        On Windows hosts the WHPX path additionally requires that the
        ``HypervisorPlatform`` optional feature is enabled and that
        ``bcdedit /enum {current}`` reports ``hypervisorlaunchtype Auto``.
        When either check fails the candidate is rejected and detection
        falls through to KVM (Linux) or TCG.

        Returns:
            AcceleratorType: Best available accelerator type.
        """
        if self._qemu_path is None:
            return AcceleratorType.TCG

        process_manager = ProcessManager.get_instance()

        try:
            detected = await self._detect_accelerator_impl(process_manager)
        except (OSError, RuntimeError, TimeoutError) as e:
            _logger.warning("acceleration_detection_failed", error=str(e))
            detected = None

        if detected is not None:
            return detected

        _logger.info("using_tcg_software_emulation", accelerator="tcg")
        return AcceleratorType.TCG

    def _resolve_vnc_port(self) -> int:
        """Resolve the VNC port QEMU should bind, re-probing any earlier choice.

        :meth:`enable_vnc_display` picks a port so :attr:`vnc_port` is readable
        before the guest boots, but nothing binds it in the meantime and the
        whole ``start()`` prologue runs in between. The earlier choice is
        therefore re-probed here and replaced if something else took it, rather
        than handed to QEMU to fail on.

        Returns:
            int: A port that was free at the moment the command line was built.
        """
        reserved = self._vnc_port
        if reserved is not None and self._port_is_free(reserved):
            with self._port_reservation_lock:
                self._reserved_host_ports.add(reserved)
            self._claimed_host_ports.add(reserved)
            return reserved
        replacement = self._get_free_port(_VNC_PORT_BASE, _VNC_PORT_MAX)
        if reserved is not None:
            self._claimed_host_ports.discard(reserved)
            self._release_host_ports({reserved})
            _logger.warning(
                "vnc_port_reassigned",
                previous_vnc_port=reserved,
                vnc_port=replacement,
            )
        return replacement

    @staticmethod
    def _port_is_free(port: int) -> bool:
        """Probe whether a TCP port can actually be bound on this host.

        The question that matters is "can QEMU bind this", not "is anyone
        listening on it", and on Windows the two answers differ. Hyper-V
        reserves port ranges that carry no listener at all yet refuse a bind
        with ``WSAEACCES``, and those ranges are redrawn at every boot. A
        connect probe reports every one of them as free, so this binds the port
        for real and immediately releases it. The wildcard address is used
        because that is what a SLIRP ``hostfwd`` binds, and it is the stricter
        test: a port held on the loopback address alone would still fail here.

        Args:
            port: TCP port to probe.

        Returns:
            bool: True when the port was bindable at the moment of the probe.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((_WILDCARD_BIND_ADDRESS, port))
            except OSError:
                return False
        return True

    @classmethod
    def _claim_free_port(cls, span: int = 1, start: int = _HOST_PORT_RANGE_START, end: int = _HOST_PORT_RANGE_END) -> int:
        """Reserve a run of consecutive host ports that are all bindable.

        Reservations are held process-wide because nothing binds an allocated
        port between the probe and QEMU's own bind, so two sandboxes started
        back to back would otherwise draw the same number and the second one
        would fail to launch.

        Args:
            span: How many consecutive ports to claim, starting at the returned
                one. The guest-agent channel sits one above the agent port, so
                that pair is claimed as a span of two.
            start: First port of the search range.
            end: One past the last port of the search range.

        Returns:
            int: The first port of the claimed run.

        Raises:
            SandboxError: If no suitable run was found within the attempt
                budget.
        """
        width = end - start - span
        for _ in range(_HOST_PORT_SEARCH_ATTEMPTS):
            port = secrets.randbelow(width) + start
            wanted = set(range(port, port + span))
            with cls._port_reservation_lock:
                if wanted & cls._reserved_host_ports:
                    continue
                if not all(cls._port_is_free(candidate) for candidate in wanted):
                    continue
                cls._reserved_host_ports |= wanted
                return port
        _logger.error("free_port_search_exhausted", port_start=start, port_end=end, span=span)
        raise SandboxError(_ERR_NO_FREE_PORTS)

    @classmethod
    def _release_host_ports(cls, ports: set[int]) -> None:
        """Give reserved host ports back to the allocator.

        Args:
            ports: Ports previously returned by :meth:`_claim_free_port`.
        """
        with cls._port_reservation_lock:
            cls._reserved_host_ports -= ports

    def _allocate_host_port(self, span: int = 1) -> int:
        """Claim a host port for this sandbox and remember it for release.

        Args:
            span: How many consecutive ports to claim.

        Returns:
            int: The first port of the claimed run.
        """
        port = self._claim_free_port(span)
        self._claimed_host_ports |= set(range(port, port + span))
        return port

    def _get_free_port(self, start: int = _HOST_PORT_RANGE_START, end: int = _HOST_PORT_RANGE_END) -> int:
        """Claim a single free host port for this sandbox.

        Args:
            start: First port of the search range.
            end: One past the last port of the search range.

        Returns:
            int: An allocated, reserved port.
        """
        port = self._claim_free_port(1, start, end)
        self._claimed_host_ports.add(port)
        return port

    def _resolve_qemu_img(self) -> Path:
        """Locate the ``qemu-img`` that belongs to the QEMU being launched.

        It is looked for beside the QEMU binary rather than on ``PATH``, so a
        bundled QEMU cannot end up paired with an unrelated qemu-img.

        Returns:
            Path: Path to the qemu-img executable.

        Raises:
            SandboxError: If qemu-img is not present beside the QEMU binary.
        """
        if self._qemu_path is None:
            raise SandboxError(_ERR_QEMU_PATH)

        suffix = self._qemu_path.suffix
        candidate = self._qemu_path.with_name(f"{self.QEMU_IMG_EXE}{suffix}")
        if candidate.exists():
            return candidate

        _logger.error("qemu_img_missing", searched=str(candidate))
        raise SandboxError(_ERR_QEMU_IMG_MISSING)

    async def _create_disk_overlay(self, image_path: Path) -> Path:
        """Build a copy-on-write overlay over the configured disk image.

        The sandbox writes to the overlay and the configured image is only
        ever read, which is what keeps two concurrent sandboxes from writing
        over each other. QEMU does not take an image lock on Windows, so
        nothing else stops that from happening, and the damage is silent: both
        guests appear to run normally and the corruption only surfaces later.

        The overlay lives in this instance's temporary directory, so it is
        removed with the rest of the instance's state.

        Args:
            image_path: The configured backing image, which is not modified.

        Returns:
            Path: Path to the newly created overlay.

        Raises:
            SandboxError: If qemu-img could not create the overlay.
        """
        if self._temp_dir is None:
            # start() normally creates this first, but the command can also be
            # built on its own; the directory is recorded either way, so
            # _cleanup removes the overlay with the rest of the instance.
            self._temp_dir = Path(await asyncio.to_thread(tempfile.mkdtemp, prefix="intellicrack_qemu_"))

        qemu_img = self._resolve_qemu_img()
        overlay = self._temp_dir / "disk-overlay.qcow2"
        # qemu-img records the backing path as given, and the guest resolves it
        # relative to the overlay's own directory, so it has to be absolute.
        backing = await asyncio.to_thread(image_path.resolve)
        argv = [
            str(qemu_img),
            "create",
            *["-f", "qcow2"],
            *["-b", str(backing)],
            *["-F", "qcow2"],
            str(overlay),
        ]

        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != _RETURNCODE_SUCCESS:
            detail = stderr.decode(errors="replace").strip() if stderr else "no output"
            _logger.error("disk_overlay_create_failed", image_path=str(image_path), error=detail)
            message = f"{_ERR_OVERLAY_CREATE}: {detail}"
            raise SandboxError(message)

        _logger.info("disk_overlay_created", backing_image=str(image_path), overlay=str(overlay))
        return overlay

    @staticmethod
    def _check_qemu_started(returncode: int | None, stderr: bytes | None) -> None:
        """Check if QEMU process started successfully.

        Args:
            returncode: Process return code.
            stderr: Standard error output.

        Raises:
            SandboxError: If process failed to start.
        """
        if returncode != _RETURNCODE_SUCCESS:
            error_msg = stderr.decode() if stderr else "Unknown error"
            _logger.warning("qemu_start_failed", error=error_msg)
            lowered = error_msg.lower()
            if any(marker.lower() in lowered for marker in _QEMU_BIND_FAILURE_MARKERS):
                _logger.warning("qemu_host_port_bind_failed", error=error_msg)
                bind_message = f"{_ERR_QEMU_HOST_PORT} QEMU reported: {error_msg.strip()}"
                raise SandboxError(bind_message)
            raise SandboxError(_ERR_QEMU_START)

    async def _verify_qemu_pid(self, qemu_pid: int | None) -> None:
        """Verify that the QEMU process started and its PID was read successfully.

        Args:
            qemu_pid: The PID read from the pidfile, or None if unreadable.

        Raises:
            SandboxError: If the PID could not be read from the pidfile.
        """
        if qemu_pid is None:
            _logger.warning("qemu_pidfile_unreadable", pidfile=str(self._pidfile_path))
            await self._cleanup()
            raise SandboxError(_ERR_PIDFILE_UNREADABLE)

    async def _connect_and_verify_qmp(self) -> None:
        """Connect to QMP and verify VM status.

        Raises:
            SandboxError: If connection or status check fails.
        """
        self._qmp = QMPClient(port=self._qemu_config.monitor_port)
        if not await self._qmp.connect(time_limit=_QMP_CONNECT_TIMEOUT):
            raise SandboxError(_ERR_QMP_CONNECT)

        status = await self._qmp.query_status()
        if not status.success:
            _logger.warning("vm_status_query_failed", error=status.error)
            raise SandboxError(_ERR_VM_STATUS)

    def _guest_agent_channel_port(self) -> int:
        """Return the host TCP port QEMU exposes for the guest-agent channel.

        Returns:
            int: The resolved ``agent_port`` plus the channel offset used by
            the ``-chardev`` argument built in :meth:`_build_qemu_command`.
        """
        return self._qemu_config.agent_port + _QGA_CHANNEL_PORT_OFFSET

    async def _connect_guest_agent_channel(
        self,
        time_limit: float | None = None,
        attempt_timeout: float = _QEMU_GA_CONNECT_TIMEOUT,
        retry_interval: float = _QEMU_GA_CONNECT_RETRY_INTERVAL,
    ) -> None:
        """Open the qemu-guest-agent channel used for in-guest command dispatch.

        The channel is the ``org.qemu.guest_agent.0`` chardev socket, which is
        a different endpoint from the QMP monitor: QMP rejects every
        ``guest-*`` command outright. QEMU binds that socket with
        ``server,nowait`` while the VM is still in firmware, so a refused
        connection or an unanswered ``guest-sync-delimited`` means the guest
        has not started qemu-guest-agent yet, not that it never will. Attempts
        are therefore repeated until ``time_limit`` is spent - but on the socket
        already open, never on a new one. QEMU accepts that socket once for the
        life of the VM, so a retry that reconnects is refused, and so is every
        retry after it.

        Args:
            time_limit: Total seconds to keep retrying before giving up;
                defaults to ``QEMUConfig.guest_agent_ready_timeout``.
            attempt_timeout: Per-attempt deadline covering the socket connect
                and the ``guest-sync-delimited`` handshake.
            retry_interval: Delay in seconds between attempts.

        Raises:
            SandboxError: If the channel socket is still refusing connections
                when the budget is spent, or if the agent never echoed the
                sync id on any attempt.
        """
        if self._qga is not None and self._qga.connected:
            return

        budget = self._qemu_config.guest_agent_ready_timeout if time_limit is None else time_limit
        channel_port = self._guest_agent_channel_port()
        deadline = time.monotonic() + budget
        sync_failed = False
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            sync_failed = await self._attempt_guest_agent_connect(channel_port, min(attempt_timeout, remaining))
            if self._qga is not None and self._qga.connected:
                return
            await asyncio.sleep(min(retry_interval, max(deadline - time.monotonic(), 0.0)))

        if sync_failed:
            _logger.warning("qemu_ga_channel_sync_failed", channel_port=channel_port, time_limit=budget)
            raise SandboxError(_ERR_QEMU_GA_SYNC_FAILED)
        _logger.warning("qemu_ga_channel_unreachable", channel_port=channel_port, time_limit=budget)
        raise SandboxError(_ERR_QEMU_GA_SOCKET_UNREACHABLE.format(port=channel_port))

    async def _attempt_guest_agent_connect(self, channel_port: int, attempt_timeout: float) -> bool:
        """Make one connect-and-resynchronise attempt on the guest-agent channel.

        Args:
            channel_port: Host TCP port of the guest-agent chardev socket.
            attempt_timeout: Deadline in seconds for this attempt.

        Returns:
            bool: True when the socket opened but the agent did not complete
            the ``guest-sync-delimited`` handshake; False when the socket
            itself could not be opened or the attempt succeeded.
        """
        client = self._qga
        if client is not None and client.socket_open:
            # The channel is up; only the guest is not ready. Retry there.
            if await client.resynchronise(attempt_timeout):
                return False
            _logger.debug("qemu_ga_channel_sync_retry", channel_port=channel_port, error=_ERR_QEMU_GA_SYNC_FAILED)
            return True

        if client is None:
            client = QemuGuestAgentClient(port=channel_port)
            self._qga = client
        else:
            await client.disconnect()

        try:
            connected = await client.connect(time_limit=attempt_timeout)
        except SandboxError as e:
            _logger.debug("qemu_ga_channel_sync_retry", channel_port=channel_port, error=str(e))
            return True

        if not connected:
            _logger.debug("qemu_ga_channel_connect_retry", channel_port=channel_port)
        return False

    async def _wait_for_qemu_ga(
        self,
        ping_timeout: float = _QEMU_GA_PING_TIMEOUT,
        poll_interval: float = _QEMU_GA_PING_INTERVAL,
    ) -> None:
        """Poll ``guest-ping`` until qemu-guest-agent responds or timeout.

        Args:
            ping_timeout: Maximum total time in seconds to wait for the
                qemu-guest-agent to become reachable.
            poll_interval: Delay in seconds between successive
                ``guest-ping`` attempts.

        Raises:
            SandboxError: If the guest-agent channel is not connected, or if
                ``guest-ping`` never succeeds within ``ping_timeout``.
        """
        if self._qga is None:
            raise SandboxError(_ERR_QEMU_GA_NOT_CONNECTED)

        deadline = time.monotonic() + ping_timeout
        last_error: str | None = None
        while time.monotonic() < deadline:
            response = await self._qga.ping(time_limit=QEMU_GA_EXEC_TIMEOUT)
            if response.success:
                _logger.debug(
                    "qemu_ga_ping_ok",
                    channel_port=self._guest_agent_channel_port(),
                )
                return
            last_error = response.error
            _logger.debug(
                "qemu_ga_ping_retry",
                error=last_error,
                interval=poll_interval,
            )
            await asyncio.sleep(poll_interval)

        _logger.warning(
            "qemu_ga_unreachable",
            ping_timeout=ping_timeout,
            last_error=last_error,
        )
        raise SandboxError(_ERR_QEMU_GA_UNREACHABLE)

    async def _guest_agent_exec(
        self,
        path: str,
        args: list[str],
        *,
        capture_output: bool = False,
        reply_time_limit: float = QEMU_GA_EXEC_TIMEOUT,
    ) -> int:
        """Invoke ``guest-exec`` on the guest-agent channel and return the guest PID.

        Args:
            path: Absolute executable path inside the guest.
            args: Argument list passed to the executable.
            capture_output: Whether qemu-guest-agent should buffer
                stdout/stderr for later retrieval. The monitor bootstrap
                does not need output capture.
            reply_time_limit: Seconds to wait for the agent's reply to the
                launch itself, as distinct from how long the launched process
                may then run. A caller working to a deadline of its own passes
                what is left of it, so abandoning one launch cannot consume the
                budget that was meant to cover the retry.

        Returns:
            int: Guest-side process identifier returned by
            qemu-guest-agent.

        Raises:
            SandboxError: If the guest-agent channel is not connected, if the
                ``guest-exec`` invocation fails, or if the reply does not
                include a PID.
        """
        if self._qga is None:
            raise SandboxError(_ERR_QEMU_GA_NOT_CONNECTED)

        response = await self._qga.guest_exec(
            path,
            args,
            capture_output=capture_output,
            time_limit=reply_time_limit,
        )
        if not response.success:
            _logger.warning(
                "qemu_ga_exec_failed",
                path=path,
                arg=list(args),
                error=response.error,
            )
            raise SandboxError(_ERR_QEMU_GA_EXEC_FAILED)

        data = _as_mapping(response.data)
        if data is None or "pid" not in data:
            _logger.warning(
                "qemu_ga_exec_no_pid",
                path=path,
                arg=list(args),
                response_payload=response.data,
            )
            raise SandboxError(_ERR_QEMU_GA_EXEC_NO_PID)

        pid_raw = data["pid"]
        if not isinstance(pid_raw, int):
            _logger.warning(
                "qemu_ga_exec_invalid_pid_type",
                path=path,
                arg=list(args),
                pid_type=type(pid_raw).__name__,
            )
            raise SandboxError(_ERR_QEMU_GA_EXEC_NO_PID)

        return pid_raw

    async def _ensure_guest_agent_ready(self) -> None:
        """Open the guest-agent channel and wait until the agent runs commands.

        ``QEMUConfig.guest_agent_ready_timeout`` is the whole budget for a
        booting guest: whatever the channel spends connecting and
        resynchronising is taken off the time left for ``guest-ping``, and
        whatever is left after that is what the guest gets to prove it can run
        a command, so the total wait is the configured one rather than a
        multiple of it.

        Propagates the ``SandboxError`` raised by
        :meth:`_connect_guest_agent_channel` when the channel never opens, by
        :meth:`_wait_for_qemu_ga` when the agent never answers ``guest-ping``
        within what is left of the budget, and by
        :meth:`_wait_for_guest_exec` when it answers pings but never runs
        anything.
        """
        deadline = time.monotonic() + self._qemu_config.guest_agent_ready_timeout
        await self._connect_guest_agent_channel()
        await self._wait_for_qemu_ga(
            ping_timeout=max(deadline - time.monotonic(), 0.0),
            poll_interval=_QEMU_GA_PING_INTERVAL,
        )
        await self._wait_for_guest_exec(deadline)

    def _guest_exec_probe(self) -> tuple[str, list[str]]:
        """Return the smallest command that proves the agent can spawn a process.

        Returns:
            tuple[str, list[str]]: Executable and argument list for the
            configured guest family.

        Raises:
            SandboxError: If the configured guest family is not supported.
        """
        guest_os = self._qemu_config.guest_os
        if guest_os == GuestOS.WINDOWS:
            path, args = _GUEST_EXEC_PROBE_WINDOWS
        elif guest_os == GuestOS.LINUX:
            path, args = _GUEST_EXEC_PROBE_LINUX
        else:
            _logger.warning("guest_exec_probe_unsupported_guest_os", guest_os=str(guest_os))
            raise SandboxError(_ERR_UNSUPPORTED_GUEST_OS)
        return path, list(args)

    async def _wait_for_guest_exec(self, deadline: float) -> None:
        """Wait until the guest agent really runs a command, not just answers pings.

        ``guest-ping`` is answered by the agent's dispatch loop and proves
        nothing about ``guest-exec``, which has to reach the guest's process
        creation path. On a Windows guest those two become usable minutes
        apart: measured on a cold ``windows11-intellicrack-v4`` boot the agent
        answered ping twelve seconds in and left the next ``guest-exec``
        unanswered past its ten-second reply deadline, which aborted the whole
        start with almost the entire readiness budget unspent. Since the
        backend's very next act is always to run something inside the guest,
        readiness has to mean a command completed, and a command that times out
        while the budget still has room is a retry rather than a failure.

        Args:
            deadline: Monotonic clock value at which the readiness budget for
                the whole agent handshake expires.

        Raises:
            SandboxError: If no command completed before ``deadline``.
        """
        if self._guest_exec_ready:
            return

        path, args = self._guest_exec_probe()
        reason = _ERR_QEMU_GA_EXEC_NOT_ATTEMPTED
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                status = await self._guest_run(
                    path,
                    args,
                    time_limit=min(remaining, _GUEST_COMMAND_TIMEOUT),
                    reply_time_limit=min(remaining, QEMU_GA_EXEC_TIMEOUT),
                )
            except SandboxError as e:
                reason = str(e)
                _logger.debug("guest_exec_probe_retry", path=path, arg=list(args), error=reason)
            else:
                _logger.info("guest_exec_probe_completed", path=path, exit_code=status.exit_code)
                self._guest_exec_ready = True
                return
            await asyncio.sleep(min(_QEMU_GA_EXEC_PROBE_INTERVAL, max(deadline - time.monotonic(), 0.0)))

        budget = self._qemu_config.guest_agent_ready_timeout
        _logger.warning("guest_exec_probe_failed", time_limit=budget, error=reason)
        raise SandboxError(_ERR_QEMU_GA_EXEC_NOT_READY.format(budget=budget, reason=reason))

    async def _guest_run(
        self,
        path: str,
        args: list[str],
        time_limit: float = _GUEST_COMMAND_TIMEOUT,
        reply_time_limit: float = QEMU_GA_EXEC_TIMEOUT,
    ) -> GuestExecStatus:
        """Run a command inside the guest and wait for its exit status.

        Args:
            path: Executable name or absolute path inside the guest.
            args: Argument list passed to the executable.
            time_limit: Maximum time in seconds to wait for the guest-side
                process to terminate.
            reply_time_limit: Maximum time in seconds to wait for the agent to
                acknowledge the launch. Separate from ``time_limit`` because a
                command that runs for a minute and an agent that takes a minute
                to answer are different conditions with different remedies.

        Returns:
            GuestExecStatus: Terminal status including captured output.

        Raises:
            SandboxError: If the guest-agent channel is not connected, if
                ``guest-exec`` fails, or if the process does not exit within
                ``time_limit``.
        """
        if self._qga is None:
            raise SandboxError(_ERR_QEMU_GA_NOT_CONNECTED)

        pid = await self._guest_agent_exec(
            path,
            args,
            capture_output=True,
            reply_time_limit=reply_time_limit,
        )
        deadline = time.monotonic() + time_limit
        while time.monotonic() < deadline:
            status = await self._qga.guest_exec_status(pid)
            if status.exited:
                _logger.debug(
                    "guest_command_completed",
                    path=path,
                    arg=list(args),
                    exit_code=status.exit_code,
                )
                return status
            await asyncio.sleep(_GUEST_COMMAND_POLL_INTERVAL)

        _logger.warning("guest_command_timeout", path=path, arg=list(args), timeout=time_limit)
        raise SandboxError(
            _ERR_GUEST_COMMAND_TIMEOUT.format(command=" ".join([path, *args]), timeout=time_limit),
        )

    @staticmethod
    def _guest_exit_code(status: GuestExecStatus, command: str) -> int:
        """Reduce a terminal guest-exec status to a single exit code.

        ``guest-exec-status`` reports either an exit code or a terminating
        signal, never both, so a process the guest killed carries no code of
        its own. It is reported the way every POSIX shell reports one, as
        ``128 + signal``, which keeps a killed command distinguishable from
        one that chose to fail. A status that carries neither is the agent
        contradicting itself and is refused rather than smoothed over into a
        success.

        Args:
            status: Terminal status returned by :meth:`_guest_run`.
            command: Command line the status belongs to, used in the error.

        Returns:
            int: Exit code, or ``128 + signal`` for a signalled process.

        Raises:
            SandboxError: If the status reports neither an exit code nor a
                terminating signal.
        """
        if status.exit_code is not None:
            return status.exit_code
        if status.signal is not None:
            return _SIGNAL_EXIT_CODE_BASE + status.signal
        raise SandboxError(_ERR_GUEST_EXEC_NO_EXIT_CODE.format(command=command))

    @staticmethod
    def _windows_launch_path(guest_root: str) -> str:
        r"""Build the Windows monitor launcher path under a guest share root.

        Args:
            guest_root: Guest-side root of the shared volume, including the
                trailing backslash (for example ``E:\``).

        Returns:
            str: Absolute in-guest path of ``start_agent.cmd``.
        """
        return guest_root + _MONITOR_LAUNCH_RELATIVE_WINDOWS

    @staticmethod
    def _linux_launch_path(guest_root: str) -> str:
        """Build the Linux monitor launcher path under a guest share root.

        Args:
            guest_root: Guest-side mount point of the shared volume, without
                a trailing slash.

        Returns:
            str: Absolute in-guest path of ``start_agent.sh``.
        """
        return f"{guest_root}/{_MONITOR_LAUNCH_RELATIVE_LINUX}"

    @staticmethod
    def _decode_lsblk_value(raw: str) -> str:
        r"""Undo the ``\xNN`` escaping ``lsblk --raw`` applies to a column value.

        Args:
            raw: One escaped column value as it appeared on the wire.

        Returns:
            str: The value with every well-formed escape expanded; a malformed
            escape is kept verbatim rather than dropped.
        """
        decoded: list[str] = []
        index = 0
        while index < len(raw):
            if not raw.startswith(_LSBLK_ESCAPE_PREFIX, index) or index + _LSBLK_ESCAPE_LENGTH > len(raw):
                decoded.append(raw[index])
                index += 1
                continue
            digits = raw[index + len(_LSBLK_ESCAPE_PREFIX) : index + _LSBLK_ESCAPE_LENGTH]
            try:
                code_point = int(digits, _LSBLK_ESCAPE_BASE)
            except ValueError:
                decoded.append(raw[index])
                index += 1
                continue
            decoded.append(chr(code_point))
            index += _LSBLK_ESCAPE_LENGTH
        return "".join(decoded)

    @classmethod
    def _parse_guest_block_devices(cls, listing: str) -> list[_GuestBlockDevice]:
        """Parse ``lsblk --raw`` output into structured rows.

        Columns are separated by exactly one space and never contain one
        themselves, so a row is split on the literal separator instead of on
        runs of whitespace: that keeps an empty column empty rather than
        shifting every column after it one position to the left.

        Args:
            listing: Standard output of the guest's ``lsblk`` invocation.

        Returns:
            list[_GuestBlockDevice]: One entry per device node reported.
        """
        devices: list[_GuestBlockDevice] = []
        for line in listing.splitlines():
            fields = line.rstrip("\r").split(" ")
            if len(fields) < _GUEST_BLOCK_DEVICE_MIN_FIELDS or not fields[0].startswith("/"):
                continue
            devices.append(
                _GuestBlockDevice(
                    path=fields[0],
                    fs_type=fields[1],
                    label=cls._lsblk_field(fields, _GUEST_BLOCK_DEVICE_LABEL_FIELD),
                    mountpoint=cls._lsblk_field(fields, _GUEST_BLOCK_DEVICE_MOUNTPOINT_FIELD),
                ),
            )
        return devices

    @classmethod
    def _lsblk_field(cls, fields: list[str], index: int) -> str:
        """Return one decoded optional column from a split ``lsblk`` row.

        Args:
            fields: Column values of one row, already split on the separator.
            index: Zero-based column position to read.

        Returns:
            str: Decoded value, or an empty string when the row is shorter.
        """
        if index >= len(fields):
            return ""
        return cls._decode_lsblk_value(fields[index])

    @classmethod
    def _select_guest_block_device(cls, listing: str, fs_type: str, label: str) -> str | None:
        """Pick the block device that carries the host shared folder.

        Neither half of the test identifies the volume on its own, so both are
        required:

        * filesystem type and mount state are not enough, because an unmounted
          ``vfat`` volume is an ordinary thing for a guest to own - a spare
          data partition is one - and it does not carry vvfat's label;
        * label and filesystem type are not enough either, because vvfat writes
          the same label into every ``file=fat:`` drive, and because the share
          has not been mounted yet at this point while any volume the guest
          mounted itself already is.

        Args:
            listing: ``lsblk`` output with one ``PATH FSTYPE LABEL MOUNTPOINT``
                row per device.
            fs_type: Filesystem type the share is formatted with.
            label: Volume label the share carries.

        Returns:
            str | None: Device path of the matching row, or None when the guest
            reports no such volume.
        """
        for device in cls._parse_guest_block_devices(listing):
            if device.fs_type != fs_type or device.mountpoint:
                continue
            if device.label == label:
                return device.path
        return None

    @staticmethod
    def _parse_windows_drive_letters(listing: str, system_drive: str) -> list[str]:
        r"""Extract candidate drive letters from ``fsutil fsinfo drives`` output.

        The guest's own system drive is skipped: the shared volume is always an
        additional FAT drive, never the boot volume. Which drive that is comes
        from the guest itself rather than from an assumption that Windows was
        installed on ``C:``.

        Args:
            listing: Raw ``fsutil fsinfo drives`` standard output, of the form
                ``Drives: C:\ D:\ E:\``.
            system_drive: Designator of the guest's system drive, as reported
                by ``%SystemDrive%``.

        Returns:
            list[str]: Drive designators such as ``["D:", "E:"]``, in the order
            the guest reported them.
        """
        excluded = system_drive.rstrip("\\").upper()
        letters: list[str] = []
        for token in listing.split():
            designator = token.rstrip("\\").upper()
            if not designator.endswith(_WINDOWS_DRIVE_SUFFIX) or len(designator) != len(_WINDOWS_SYSTEM_DRIVE):
                continue
            if designator == excluded or designator in letters:
                continue
            letters.append(designator)
        return letters

    async def _guest_launcher_present(self, launch_path: str) -> bool:
        """Report whether the monitor launcher exists inside the Linux guest.

        Propagates the ``SandboxError`` raised by :meth:`_guest_run` when the
        probe itself cannot be executed in the guest.

        Args:
            launch_path: Absolute in-guest path of ``start_agent.sh``.

        Returns:
            bool: True when ``test -f`` reports the file exists.
        """
        status = await self._guest_run("test", ["-f", launch_path])
        return status.exit_code == 0

    async def _discover_guest_vfat_device(self) -> str:
        """Locate the FAT-backed shared volume among the guest's block devices.

        The device node is discovered rather than assumed: the root image is
        attached with ``if=virtio`` as well, so the shared drive's position in
        the ``/dev/vd*`` ordering is not a contract. Neither is its filesystem
        type on its own - the guest's EFI System Partition is ``vfat`` too and
        is enumerated ahead of the share - so the volume label vvfat writes and
        the guest's live mount table both take part in the decision.

        Returns:
            str: Device path of the guest's shared ``vfat`` volume.

        Raises:
            SandboxError: If the block devices cannot be enumerated or no
                unmounted volume carries the vvfat label.
        """
        status = await self._guest_run(
            "lsblk",
            ["--noheadings", "--raw", "--output", _GUEST_BLOCK_DEVICE_COLUMNS],
        )
        if status.exit_code != 0:
            _logger.warning(
                "guest_block_device_enumeration_failed",
                exit_code=status.exit_code,
                stderr=status.stderr.strip(),
            )
            raise SandboxError(_ERR_GUEST_SHARED_DEVICE_ENUM)

        device = self._select_guest_block_device(
            status.stdout,
            _GUEST_VFAT_FS_TYPE,
            _QEMU_VVFAT_VOLUME_LABEL,
        )
        if device is None:
            _logger.warning(
                "guest_vfat_device_not_found",
                listing=status.stdout.strip(),
                volume_label=_QEMU_VVFAT_VOLUME_LABEL,
            )
            raise SandboxError(
                _ERR_GUEST_SHARED_DEVICE_NOT_FOUND.format(
                    fs_type=_GUEST_VFAT_FS_TYPE,
                    label=_QEMU_VVFAT_VOLUME_LABEL,
                ),
            )

        _logger.info("guest_vfat_device_discovered", device=device, volume_label=_QEMU_VVFAT_VOLUME_LABEL)
        return device

    async def _mount_linux_shared_volume(self) -> str:
        """Mount the shared volume inside a Linux guest and verify the result.

        The transport is chosen by :meth:`_uses_fat_shared_transport` so the
        mount can never disagree with the argv built by
        :meth:`_shared_folder_args`.

        Returns:
            str: Guest-side mount point of the shared volume.

        Raises:
            SandboxError: If the mount point cannot be created, if no shared
                volume can be located, if the mount command fails, or if the
                monitor launcher is missing once the volume is mounted.
        """
        mount_point = _GUEST_SHARED_ROOT_LINUX
        launch_path = self._linux_launch_path(mount_point)
        if await self._guest_launcher_present(launch_path):
            _logger.info("guest_shared_volume_already_mounted", mount_point=mount_point)
            return mount_point

        mkdir_status = await self._guest_run("mkdir", ["-p", mount_point])
        if mkdir_status.exit_code != 0:
            _logger.warning(
                "guest_shared_mount_point_failed",
                mount_point=mount_point,
                exit_code=mkdir_status.exit_code,
                stderr=mkdir_status.stderr.strip(),
            )
            raise SandboxError(_ERR_GUEST_SHARED_MOUNT_POINT.format(path=mount_point))

        if self._uses_fat_shared_transport():
            source = await self._discover_guest_vfat_device()
            fs_type = _GUEST_VFAT_FS_TYPE
            options = _GUEST_VFAT_MOUNT_OPTIONS
        else:
            source = _SHARED_MOUNT_TAG
            fs_type = _GUEST_9P_FS_TYPE
            options = _GUEST_9P_MOUNT_OPTIONS

        mount_status = await self._guest_run("mount", ["-t", fs_type, "-o", options, source, mount_point])
        if mount_status.exit_code != 0:
            _logger.warning(
                "guest_shared_mount_failed",
                source=source,
                fs_type=fs_type,
                mount_point=mount_point,
                exit_code=mount_status.exit_code,
                stderr=mount_status.stderr.strip(),
            )
            raise SandboxError(
                _ERR_GUEST_SHARED_MOUNT_FAILED.format(source=source, mount_point=mount_point),
            )

        if not await self._guest_launcher_present(launch_path):
            _logger.warning("guest_shared_launcher_missing", launch_path=launch_path, source=source)
            raise SandboxError(_ERR_GUEST_SHARED_LAUNCHER_MISSING.format(path=launch_path))

        _logger.info("guest_shared_volume_mounted", source=source, fs_type=fs_type, mount_point=mount_point)
        return mount_point

    async def _guest_expand_environment(self, variable: str) -> str:
        """Expand one environment variable inside the Windows guest.

        Propagates the ``SandboxError`` raised by :meth:`_guest_run` when the
        query cannot be dispatched at all.

        Args:
            variable: Variable name without its surrounding percent signs.

        Returns:
            str: Expanded value with surrounding whitespace removed, or an
            empty string when the guest reported a failure or left the
            reference unexpanded because the variable is not set.
        """
        reference = f"%{variable}%"
        status = await self._guest_run("cmd.exe", ["/c", "echo", reference])
        value = status.stdout.strip()
        if status.exit_code != 0 or not value or value == reference:
            _logger.warning(
                "guest_environment_unreadable",
                variable=variable,
                exit_code=status.exit_code,
                stdout=value,
            )
            return ""
        return value

    async def _guest_system_drive(self) -> str:
        """Ask the Windows guest which drive it booted from.

        Windows does not have to be installed on ``C:``, and the share probe
        has to skip whichever drive it really is. ``%SystemDrive%`` is expanded
        by the guest's own ``cmd.exe``, so the answer comes from the guest
        rather than from an assumption. A guest that cannot answer falls back
        to the overwhelmingly common designator, which only ever costs one
        wasted existence probe.

        Propagates the ``SandboxError`` raised by :meth:`_guest_run` when the
        query cannot be dispatched at all.

        Returns:
            str: Drive designator such as ``C:``.
        """
        designator = (await self._guest_expand_environment(_WINDOWS_SYSTEM_DRIVE_VARIABLE)).rstrip("\\").upper()
        if len(designator) == len(_WINDOWS_SYSTEM_DRIVE) and designator.endswith(_WINDOWS_DRIVE_SUFFIX) and designator[0].isalpha():
            _logger.debug("guest_system_drive_resolved", system_drive=designator)
            return designator

        _logger.warning("guest_system_drive_unreadable", stdout=designator, fallback=_WINDOWS_SYSTEM_DRIVE)
        return _WINDOWS_SYSTEM_DRIVE

    async def _guest_system_root(self) -> str:
        r"""Ask the Windows guest where its own Windows directory lives.

        The in-guest monitor watches ``%SystemRoot%\\Temp``, so the host has to
        know the same directory to scan it; deriving it from the system drive
        would assume the folder is called ``Windows``, which a guest is free
        not to do. A guest that cannot answer falls back to
        :data:`_WINDOWS_SYSTEM_ROOT`, and the agent script substitutes that
        same literal for an unset ``%SystemRoot%`` before it builds any path
        from it, so the two sides still name one directory.

        Propagates the ``SandboxError`` raised by :meth:`_guest_run` when the
        query cannot be dispatched at all.

        Returns:
            str: Absolute directory such as ``C:\\Windows``, without a trailing
            separator.
        """
        value = (await self._guest_expand_environment(_WINDOWS_SYSTEM_ROOT_VARIABLE)).rstrip("\\")
        if len(value) > len(_WINDOWS_SYSTEM_DRIVE) and value[1:2] == _WINDOWS_DRIVE_SUFFIX and value[0].isalpha():
            _logger.debug("guest_system_root_resolved", system_root=value)
            return value

        _logger.warning("guest_system_root_unreadable", stdout=value, fallback=_WINDOWS_SYSTEM_ROOT)
        return _WINDOWS_SYSTEM_ROOT

    def _windows_drop_watch_roots(self) -> list[str]:
        r"""Return the guest directories dropped files are collected from.

        These must be exactly the directories the in-guest monitor mirrors into
        ``<work root>\output\dropped``: the agent script derives them from the
        guest's own ``%SystemDrive%`` and ``%SystemRoot%``, so the host derives
        them from the same two values, probed by
        :meth:`_resolve_windows_shared_drive`, and falls back to the same two
        literals the script falls back to. A guest that did not install Windows
        on ``C:`` would otherwise leave the agent mirroring from one volume
        while the host scanned another. Until the probe has run the compiled-in
        defaults stand in, which is all a caller reached before the sandbox
        started can use.

        Returns:
            list[str]: Absolute in-guest directories.
        """
        system_drive = self._guest_system_drive_value or _WINDOWS_SYSTEM_DRIVE
        system_root = self._guest_system_root_value or _WINDOWS_SYSTEM_ROOT
        return [
            *(f"{system_drive}\\{relative}" for relative in _WINDOWS_DROP_WATCH_BELOW_SYSTEM_DRIVE),
            *(f"{system_root}\\{relative}" for relative in _WINDOWS_DROP_WATCH_BELOW_SYSTEM_ROOT),
        ]

    def _guest_reg_exe_path(self) -> str:
        r"""Return the guest's ``reg.exe`` under the ``%SystemRoot%`` it reported.

        The in-guest agent's ``Test-AllowedCommand`` accepts an executable only
        when it sits under the share root or under ``System32``/``SysWOW64``
        below the ``%SystemRoot%`` the guest itself reports, so a registry patch
        dispatched at the compiled-in ``C:\Windows`` path is refused outright on
        any guest whose Windows lives elsewhere. The path is therefore built on
        the system root probed by :meth:`_resolve_windows_shared_drive` and
        cached in :attr:`_guest_system_root_value`, exactly as
        :meth:`_windows_drop_watch_roots` builds the watched directories, and
        falls back to :data:`_WINDOWS_SYSTEM_ROOT` only when the guest could not
        answer - the same literal the agent script substitutes for an unset
        ``%SystemRoot%``, so both sides still name one executable.

        Returns:
            str: Absolute in-guest path to ``reg.exe``, for example
            ``D:\WinNT\System32\reg.exe``.
        """
        system_root = self._guest_system_root_value or _WINDOWS_SYSTEM_ROOT
        return f"{system_root}\\{_WINDOWS_REG_EXE_RELATIVE}"

    async def _resolve_windows_shared_drive(self) -> str:
        r"""Find the drive letter the FAT shared volume received in the guest.

        QEMU does not control which letter Windows assigns to the FAT virtio
        drive, so the letter is probed for rather than assumed. The guest's own
        ``%SystemDrive%`` and ``%SystemRoot%`` are read in the same pass and
        kept: the drive probe has to skip the boot volume, and
        :meth:`_windows_drop_watch_roots` has to name the same directories the
        in-guest monitor derives from those two variables.

        Returns:
            str: Guest-side root of the shared volume including the trailing
            backslash, for example ``E:\``.

        Raises:
            SandboxError: If the guest's drive letters cannot be enumerated or
                none of them carries the monitor launcher.
        """
        listing = await self._guest_run("cmd.exe", ["/c", "fsutil", "fsinfo", "drives"])
        if listing.exit_code != 0:
            _logger.warning(
                "guest_drive_enumeration_failed",
                exit_code=listing.exit_code,
                stderr=listing.stderr.strip(),
            )
            raise SandboxError(_ERR_GUEST_SHARED_DRIVE_ENUM)

        self._guest_system_drive_value = await self._guest_system_drive()
        self._guest_system_root_value = await self._guest_system_root()
        letters = self._parse_windows_drive_letters(listing.stdout, self._guest_system_drive_value)
        if not letters:
            _logger.warning("guest_drive_enumeration_empty", listing=listing.stdout.strip())
            raise SandboxError(_ERR_GUEST_SHARED_DRIVE_ENUM)

        for letter in letters:
            guest_root = letter + "\\"
            probe = await self._guest_run("cmd.exe", ["/c", "dir", "/b", self._windows_launch_path(guest_root)])
            if probe.exit_code == 0:
                _logger.info("guest_shared_drive_resolved", guest_root=guest_root)
                return guest_root

        _logger.warning("guest_shared_drive_not_found", candidates=letters)
        raise SandboxError(
            _ERR_GUEST_SHARED_DRIVE_NOT_FOUND.format(relative=_MONITOR_LAUNCH_RELATIVE_WINDOWS),
        )

    async def _mount_guest_shared_volume(self) -> None:
        """Make the host shared folder reachable from inside the guest.

        The host side attaches the folder either as a FAT virtio block device
        or as a virtio-9p export, but neither is usable until the guest acts on
        it: Linux must mount the volume at :data:`_GUEST_SHARED_ROOT_LINUX`,
        and Windows assigns the FAT drive an arbitrary letter that has to be
        discovered. Every step runs through ``guest-exec`` and its exit status
        is read back, so a failure is detected here instead of surfacing later
        as a monitor that never starts.

        Raises:
            SandboxError: If the guest agent is unreachable, if the volume
                cannot be made reachable, or if the guest OS is unsupported.
        """
        if self._shared_folder is None:
            _logger.debug("guest_shared_mount_skipped_no_share")
            return

        await self._ensure_guest_agent_ready()

        guest_os = self._qemu_config.guest_os
        if guest_os == GuestOS.LINUX:
            self._guest_shared_root = await self._mount_linux_shared_volume()
        elif guest_os == GuestOS.WINDOWS:
            self._guest_shared_root = await self._resolve_windows_shared_drive()
        else:
            _logger.warning("guest_shared_mount_unsupported_guest_os", guest_os=str(guest_os))
            raise SandboxError(_ERR_UNSUPPORTED_GUEST_OS)

        _logger.info(
            "guest_shared_volume_ready",
            guest_os=guest_os.value,
            guest_root=self._guest_shared_root,
        )

    def _guest_shared_root_for(self, guest_os: GuestOS) -> str:
        r"""Return the in-guest root every shared-folder path must be built on.

        Single source of truth for the guest side of the share. Windows assigns
        the FAT volume whatever letter it likes, so the root is only known once
        :meth:`_mount_guest_shared_volume` has probed for it; until then the
        compiled-in default stands in, which is all that a caller reached before
        the sandbox started can use.

        Args:
            guest_os: Guest family whose default root applies while no root has
                been resolved.

        Returns:
            str: ``E:\`` style root on Windows (trailing separator included) or
            ``/mnt/shared`` style root on Linux (no trailing separator).
        """
        if self._guest_shared_root is not None:
            return self._guest_shared_root
        if guest_os == GuestOS.WINDOWS:
            return _GUEST_SHARED_ROOT_WINDOWS
        return _GUEST_SHARED_ROOT_LINUX

    def _guest_work_root_for(self, guest_os: GuestOS) -> str:
        r"""Return the in-guest root everything the guest writes is built on.

        The share cannot hold it. QEMU presents the host directory to a Windows
        host's guest through the ``vvfat`` driver, whose write-back path aborts
        the whole virtual machine rather than fail a write, so a guest that
        appends to a log or renames a file into place on the share kills the
        machine it is running in. The share is mounted read-only for that
        reason, and this is where the guest's own output lives instead: monitor
        logs, mirrored dropped files, staged binaries and command results.

        It is on the guest's own disk, so it is writable, private to the guest,
        and survives for as long as the guest does. The host reads back from it
        over the guest agent's file commands rather than through the share.

        Args:
            guest_os: Guest family whose work root applies.

        Returns:
            str: ``C:\intellicrack`` style root on Windows, built on the
            ``%SystemDrive%`` the guest itself reported, or
            ``/var/lib/intellicrack`` on Linux. No trailing separator.
        """
        if guest_os == GuestOS.WINDOWS:
            system_drive = self._guest_system_drive_value or _WINDOWS_SYSTEM_DRIVE
            return f"{system_drive}\\{_GUEST_WORK_ROOT_WINDOWS_RELATIVE}"
        return _GUEST_WORK_ROOT_LINUX

    def _guest_work_path(self, relative: str) -> str:
        """Return the in-guest absolute path of a work-root-relative name.

        Args:
            relative: Path relative to the work root, written with forward
                slashes.

        Returns:
            str: Absolute path of that destination inside the guest.
        """
        root = self._guest_work_root_for(self._qemu_config.guest_os)
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            windows_relative = relative.replace("/", "\\")
            return f"{root}\\{windows_relative}"
        return f"{root}/{relative}"

    def _guest_launch_command(self) -> tuple[str, list[str]]:
        """Build the ``guest-exec`` invocation that starts the monitor agent.

        The launcher path is built from the shared-volume root resolved by
        :meth:`_mount_guest_shared_volume` when it is known, so a FAT volume
        that landed on a letter other than ``Z:`` is still launched correctly.

        Returns:
            tuple[str, list[str]]: Executable and argument list to pass to
            ``guest-exec``.

        Raises:
            SandboxError: If the configured guest OS is unsupported.
        """
        guest_os = self._qemu_config.guest_os
        if guest_os == GuestOS.WINDOWS:
            return ("cmd.exe", ["/c", self._windows_launch_path(self._guest_shared_root_for(guest_os))])
        if guest_os == GuestOS.LINUX:
            return ("/bin/bash", [self._linux_launch_path(self._guest_shared_root_for(guest_os))])

        _logger.warning("bootstrap_guest_agent_unsupported_guest_os", guest_os=str(guest_os))
        raise SandboxError(_ERR_UNSUPPORTED_GUEST_OS)

    async def _bootstrap_guest_agent(self) -> None:
        """Bootstrap monitor agent script inside the guest via qemu-ga.

        Opens the ``org.qemu.guest_agent.0`` channel, waits for qemu-guest-agent to answer ``guest-ping`` on it, then invokes ``guest-exec``
        to run ``start_agent.cmd`` (Windows) or ``start_agent.sh`` (Linux) inside the guest. The qemu-guest-agent binary must already be
        installed in the disk image and configured to start at boot; this method is the host-side trigger that runs the Intellicrack monitor
        scripts using the guest agent channel.

        Propagates ``SandboxError`` when the guest-agent channel cannot be opened, when qemu-guest-agent never responds to ``guest-ping``
        within the configured timeout, when ``guest-exec`` fails, or when the guest OS is unsupported.
        """
        await self._ensure_guest_agent_ready()

        exec_path, exec_args = self._guest_launch_command()
        guest_os = self._qemu_config.guest_os
        guest_pid = await self._guest_agent_exec(exec_path, exec_args, capture_output=False)
        self._agent_guest_pid = guest_pid
        _logger.info(
            "guest_agent_bootstrap_launched",
            guest_os=guest_os.value,
            guest_pid=guest_pid,
            path=exec_path,
            arg=exec_args,
        )

    async def _guest_bootstrap_diagnostic(self) -> str:
        """Read back whatever the guest recorded while starting the monitor agent.

        Propagates the ``SandboxError`` raised by :meth:`_guest_run` when the
        read itself cannot be dispatched into the guest.

        Returns:
            str: Tail of the guest-side bootstrap log, the guest's complaint
            about reading it, or a note that this guest OS keeps no such log.
        """
        if self._qemu_config.guest_os != GuestOS.LINUX:
            return _BOOTSTRAP_LOG_ABSENT

        log_path = f"{_GUEST_WORK_ROOT_LINUX}/{_GUEST_AGENT_LOG_DIR_RELATIVE}/{_GUEST_BOOTSTRAP_LOG_NAME}"
        status = await self._guest_run("tail", ["-n", str(_BOOTSTRAP_LOG_LINES), log_path])
        return status.stdout.strip() or status.stderr.strip() or _BOOTSTRAP_LOG_EMPTY

    async def _await_bootstrap_death(self, guest_pid: int) -> str:
        """Wait until the launched monitor agent exits, and say how.

        Runs alongside the wait for the agent's socket so that a guest-side
        failure ends that wait at once instead of letting it run out. The agent
        serves for as long as the sandbox does, so its process exiting at all is
        the failure - there is no time limit here, only the caller's.

        Args:
            guest_pid: Process qemu-guest-agent reported for the launcher.

        Returns:
            str: Description of the exit, carrying the guest's own record of it.
        """
        while True:
            await asyncio.sleep(_GUEST_COMMAND_POLL_INTERVAL)
            if self._qga is None:
                continue

            status = await self._qga.guest_exec_status(guest_pid)
            if not status.exited:
                continue

            diagnostic = await self._guest_bootstrap_diagnostic()
            _logger.warning(
                "guest_agent_bootstrap_died",
                guest_pid=guest_pid,
                exit_code=status.exit_code,
                diagnostic=diagnostic,
            )
            return _ERR_AGENT_BOOTSTRAP_DIED.format(exit_code=status.exit_code, diagnostic=diagnostic)

    async def _await_agent_or_bootstrap_failure(self, agent: GuestAgentClient, time_limit: float) -> None:
        """Wait for the agent to answer, and stop early if it has died.

        The connect wait on its own can only ever report that the budget ran
        out, which for a guest whose agent died on its first statement means
        minutes of waiting under a message that names neither the agent nor
        what stopped it. Watching the process the bootstrap started turns that
        into an immediate failure carrying the guest's own diagnostic.

        Args:
            agent: Guest agent client to connect.
            time_limit: Total seconds to wait for the agent to become
                reachable.

        Raises:
            SandboxError: If the agent cannot be reached within ``time_limit``,
                or if the process serving it exited first.
        """
        guest_pid = self._agent_guest_pid
        if self._qga is None or guest_pid is None:
            await self._ensure_agent_connected(agent, time_limit)
            return

        connecting = asyncio.create_task(self._ensure_agent_connected(agent, time_limit))
        watching = asyncio.create_task(self._await_bootstrap_death(guest_pid))
        try:
            done, _ = await asyncio.wait({connecting, watching}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (connecting, watching):
                if not task.done():
                    task.cancel()

        if connecting in done:
            await connecting
            return

        raise SandboxError(await watching)

    @staticmethod
    def _anti_evasion_identity(profile: str) -> tuple[str, str]:
        """Return the manufacturer/product identity strings for an anti-evasion profile.

        Single source of truth for vendor and product strings written by
        :meth:`_anti_evasion_smbios_entries` (SMBIOS launch arguments) and by
        :meth:`apply_anti_evasion` (Windows registry patches). Keeping both
        paths driven by the same mapping prevents the detectable inconsistency
        described in audit finding F-0029, where SMBIOS reported one vendor and
        the registry advertised another.

        Args:
            profile: Profile name (``default``, ``workstation``, or ``laptop``).

        Returns:
            tuple[str, str]: ``(manufacturer, product)`` pair. ``manufacturer``
            is the canonical short vendor name (e.g. ``"HP"`` or ``"Dell Inc."``),
            and ``product`` is the consumer-visible product model
            (e.g. ``"HP EliteDesk 800 G6"``).
        """
        if profile == "workstation":
            return ("Dell Inc.", "OptiPlex 7090")
        if profile == "laptop":
            return ("Lenovo", "ThinkPad T14 Gen 3")
        return ("HP", "HP EliteDesk 800 G6")

    @staticmethod
    def _anti_evasion_registry_commands(profile: str, product_id: str, reg_exe_path: str) -> list[tuple[str, list[str]]]:
        r"""Return the Windows registry-patch commands for an anti-evasion profile.

        The returned list is consumed by :meth:`apply_anti_evasion` to dispatch
        ``reg.exe add`` invocations through the guest agent. Each command names
        ``reg.exe`` by the ``reg_exe_path`` the caller resolved from the guest's
        own ``%SystemRoot%`` (see :meth:`_guest_reg_exe_path`) so that the
        in-guest :func:`Test-AllowedCommand` allowlist - which accepts an
        executable only under ``System32``/``SysWOW64`` of that same reported
        root - accepts the invocation on any guest, not only one whose Windows
        lives at ``C:\Windows`` (audit finding F-0022). Manufacturer and product
        strings come from :meth:`_anti_evasion_identity` so they agree with the
        SMBIOS launch arguments (audit finding F-0029).

        Args:
            profile: Anti-evasion profile name (``default``, ``workstation``,
                or ``laptop``).
            product_id: Randomised product identifier written to
                ``HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ProductId``.
            reg_exe_path: Absolute in-guest path to ``reg.exe`` resolved from
                the guest's probed ``%SystemRoot%``.

        Returns:
            list[tuple[str, list[str]]]: Ordered list of ``(executable, argv)``
            pairs. ``executable`` is always ``reg_exe_path``.
        """
        sep = "\\"
        bios_key = sep.join(["HKLM", "HARDWARE", "DESCRIPTION", "System", "BIOS"])
        current_version_key = sep.join(["HKLM", "SOFTWARE", "Microsoft", "Windows", "CurrentVersion"])
        disk_enum_key = sep.join(["HKLM", "SYSTEM", "CurrentControlSet", "Services", "Disk", "Enum"])
        identity_manufacturer, identity_product = QEMUSandbox._anti_evasion_identity(profile)
        return [
            (
                reg_exe_path,
                ["add", bios_key, "/v", "SystemManufacturer", "/t", "REG_SZ", "/d", identity_manufacturer, "/f"],
            ),
            (
                reg_exe_path,
                ["add", bios_key, "/v", "SystemProductName", "/t", "REG_SZ", "/d", identity_product, "/f"],
            ),
            (
                reg_exe_path,
                ["add", current_version_key, "/v", "ProductId", "/t", "REG_SZ", "/d", product_id, "/f"],
            ),
            (
                reg_exe_path,
                ["add", disk_enum_key, "/v", "0", "/t", "REG_SZ", "/d", "WDC WD10EZEX-00BBHA0", "/f"],
            ),
        ]

    def _uses_fat_shared_transport(self) -> bool:
        """Report whether the shared folder is carried by a FAT block device.

        Single source of truth for the transport decision: the argv built by
        :meth:`_shared_folder_args` and the in-guest mount performed by
        :meth:`_mount_guest_shared_volume` must never disagree about which
        transport is in play. virtio-9p is compiled out of every Windows QEMU
        build, and a Windows guest cannot mount a 9p export at all, so either
        condition forces the FAT-backed virtio block device.

        Returns:
            bool: True when the share is a FAT virtio drive, False when it is
            a virtio-9p export.
        """
        return _IS_WINDOWS or self._qemu_config.guest_os == GuestOS.WINDOWS

    def _shared_folder_args(self) -> list[str]:
        """Build the argv exposing the host shared folder to the guest.

        The transport is chosen by what the host QEMU actually supports rather
        than by guest OS. virtio-9p (``-fsdev``/``virtio-9p-pci``) is compiled
        out of every Windows QEMU build - ``-fsdev`` reports "fsdev support is
        disabled" - so on Windows the folder is presented as a FAT-formatted
        virtio block device instead, which both guest types can mount: Linux by
        the ``QEMU VVFAT`` volume label that vvfat writes into the synthesised
        boot sector and root directory, Windows as a drive letter it assigns
        itself. Where 9p is available it remains the transport because it maps
        host permissions and handles writes reliably, neither of which QEMU's
        FAT emulation does.

        Returns:
            list[str]: The ``-drive`` or ``-fsdev``/``-device`` arguments.

        Raises:
            ValueError: If the configured guest OS is unsupported.
        """
        shared = self._shared_folder
        if shared is None:
            return []

        if self._qemu_config.guest_os not in {GuestOS.WINDOWS, GuestOS.LINUX}:
            _logger.error("qemu_command_build_failed_guest_os", guest_os=str(self._qemu_config.guest_os))
            raise ValueError(_ERR_UNSUPPORTED_GUEST_OS)

        if self._uses_fat_shared_transport():
            # ``label=`` is not a -drive option (raw format rejects it), so the
            # volume is identified by QEMU's built-in FAT label instead. The
            # volume is read-only - ``fat:`` rather than ``fat:rw:`` - because
            # vvfat's write-back path aborts the whole virtual machine when it
            # commits a guest's directory changes, taking the guest with it.
            # Nothing in the guest writes here; see _guest_work_root_for.
            return [
                "-drive",
                f"file=fat:{shared},format=raw,if=virtio,readonly=on",
            ]

        return [
            "-fsdev",
            f"local,id=fsdev0,path={shared},security_model=mapped-xattr",
            "-device",
            f"virtio-9p-pci,fsdev=fsdev0,mount_tag={_SHARED_MOUNT_TAG}",
        ]

    @staticmethod
    def _anti_evasion_smbios_entries(profile: str) -> list[dict[str, str]]:
        """Return SMBIOS entries for the selected anti-evasion profile.

        Manufacturer and product strings come from
        :meth:`_anti_evasion_identity` so that the SMBIOS launch arguments
        agree with the Windows registry writes performed in
        :meth:`apply_anti_evasion`.

        Args:
            profile: Profile name (``default``, ``workstation``, or ``laptop``).

        Returns:
            list[dict[str, str]]: SMBIOS entries suitable for ``-smbios`` argv.
        """
        manufacturer, product = QEMUSandbox._anti_evasion_identity(profile)
        if profile == "workstation":
            return [
                {"type": "1", "manufacturer": manufacturer, "product": product, "serial": f"SVC{secrets.token_hex(5).upper()}"},
                {"type": "2", "manufacturer": manufacturer, "product": "0WN7Y6"},
                {"type": "3", "manufacturer": manufacturer, "asset": "0WN7Y6"},
            ]
        if profile == "laptop":
            return [
                {"type": "1", "manufacturer": manufacturer, "product": product, "serial": f"PF{secrets.token_hex(5).upper()}"},
                {"type": "2", "manufacturer": manufacturer, "product": "21AHS00000"},
                {"type": "3", "manufacturer": manufacturer, "asset": "21AHS00000"},
            ]
        return [
            {"type": "1", "manufacturer": manufacturer, "product": product, "serial": f"MXL{secrets.token_hex(5).upper()}"},
            {"type": "2", "manufacturer": manufacturer, "product": "8767"},
            {"type": "3", "manufacturer": manufacturer, "asset": "8767"},
        ]

    async def _launch_disk_path(self) -> Path:
        """Provision the disk this launch will attach, and say where it is.

        Directing the guest at a per-instance overlay is what keeps a second
        sandbox from corrupting the configured image, which QEMU will not
        prevent - it takes no lock on it. Provisioning that overlay is an act
        performed once per launch, so it belongs to the launch and not to
        assembling an argument vector; keeping it here is also what lets the
        argv contract be exercised on a host with no ``qemu-img``.

        Returns:
            Path: The image QEMU should attach read-write.

        Raises:
            SandboxError: If no image is configured.
        """
        image_path = self._qemu_config.image_path
        if image_path is None:
            _logger.error("qemu_launch_disk_unset")
            raise SandboxError(_ERR_NO_IMAGE_UNSET)

        if not self._qemu_config.disk_overlay:
            return image_path

        return await self._create_disk_overlay(image_path)

    async def _build_qemu_command(self, disk_path: Path | None = None) -> list[str]:
        """Build QEMU command line.

        Adds ``-smbios`` entries and a masked ``-cpu`` string for
        anti-evasion. The SMBIOS profile is sourced from
        :class:`QEMUConfig.anti_evasion_profile`. The CPU argument includes
        ``hv-vendor-id``, ``kvm=off`` and ``hypervisor=off`` to reduce
        hypervisor detection via CPUID.

        Args:
            disk_path: Image to attach read-write, as provisioned by
                :meth:`_launch_disk_path`. Omitting it attaches the configured
                image itself, which is only safe when no second sandbox can be
                sharing it.

        Returns:
            list[str]: QEMU command as list of arguments.

        Raises:
            SandboxError: If configuration is invalid.
        """
        if self._qemu_path is None:
            _logger.error("qemu_command_build_failed_no_path")
            raise SandboxError(_ERR_QEMU_PATH)

        image_path = self._qemu_config.image_path
        if image_path is None:
            _logger.error("qemu_command_build_failed_no_image", image_path=None)
            raise SandboxError(_ERR_NO_IMAGE_UNSET)

        if not await asyncio.to_thread(image_path.exists):
            _logger.error("qemu_command_build_failed_no_image", image_path=str(image_path))
            msg = f"{_ERR_NO_IMAGE_MISSING}: {image_path}"
            raise SandboxError(msg)

        attached_disk = disk_path if disk_path is not None else image_path

        if self._accelerator == AcceleratorType.WHPX:
            # WHPX cannot virtualize the feature set of -cpu host or -cpu max
            # (the guest triple-faults into "Unexpected VP exit code 4" during
            # early boot), so the model is qemu64 plus the two features named
            # explicitly. Both are required: Windows 11 24H2 refuses to boot
            # without SSE4.2 and POPCNT, and bare qemu64 advertises neither, so
            # a Windows guest triple-faulted with the same WHPX exit code
            # before its boot manager produced any output. WHPX accepts them
            # named individually - what it rejects is the whole host feature
            # set. The anti-evasion masks ride along unchanged.
            cpu_arg = "qemu64,+sse4.2,+popcnt,hv-vendor-id=AuthenticAMD,kvm=off,hypervisor=off"
        elif self._accelerator == AcceleratorType.KVM:
            cpu_arg = "host,hv-vendor-id=AuthenticAMD,kvm=off,hypervisor=off"
        else:
            cpu_arg = "max,hv-vendor-id=AuthenticAMD,hypervisor=off"

        # WHPX emulates the local APIC inside the hypervisor - QEMU announces
        # "WHPX: setting APIC emulation mode in the hypervisor" when asked for
        # it - and a Windows guest needs that mode. Routing interrupts through
        # userspace instead starves it: measured on Windows 11 24H2 install
        # media, the guest reached its own kernel and then spun forever in a
        # backward-jmp loop at ring 0 with interrupts enabled, never advancing
        # the boot spinner by a single frame, while QEMU's own ioapic counted
        # tens of thousands of undelivered IRQ 0 events. The same media with
        # kernel-irqchip=on reaches Windows Setup in about a minute. The
        # earlier "Unexpected VP exit code 4" that this option was blamed for
        # was the CPU model, not the IRQ chip.
        machine_arg = f"q35,accel={self._accelerator.value}"
        if self._accelerator == AcceleratorType.WHPX:
            machine_arg += ",kernel-irqchip=on"

        cmd: list[str] = [
            str(self._qemu_path),
            *["-machine", machine_arg],
            "-cpu",
            cpu_arg,
            *["-smp", f"cores={self._qemu_config.cpu_cores}"],
            *["-m", str(self._qemu_config.memory_mb)],
            *[
                "-drive",
                f"file={attached_disk},format=qcow2,if=virtio",
            ],
        ]

        for entry in self._anti_evasion_smbios_entries(self._qemu_config.anti_evasion_profile):
            smbios_value = ",".join(f"{k}={v}" for k, v in entry.items())
            cmd.extend(["-smbios", smbios_value])

        if self._qemu_config.display == "none":
            cmd.extend(["-display", "none"])
        elif self._qemu_config.display == "vnc":
            vnc_full_port = self._resolve_vnc_port()
            vnc_display = vnc_full_port - _VNC_PORT_BASE
            self._vnc_port = vnc_full_port
            cmd.extend(["-vnc", f":{vnc_display}"])
        elif self._qemu_config.display == "sdl":
            cmd.extend(["-display", "sdl"])
        elif self._qemu_config.display == "spice":
            spice_port = self._get_free_port(_VNC_PORT_BASE, _VNC_PORT_MAX)
            cmd.extend(["-spice", f"port={spice_port},disable-ticketing=on"])

        # A configured port is honoured as given; zero means allocate. The
        # agent claims two, because the guest-agent chardev binds one above it.
        ssh_port = self._qemu_config.ssh_port or self._allocate_host_port()
        monitor_port = self._qemu_config.monitor_port or self._allocate_host_port()
        agent_port = self._qemu_config.agent_port or self._allocate_host_port(1 + _QGA_CHANNEL_PORT_OFFSET)

        netdev = f"user,id=net0,hostfwd=tcp::{ssh_port}-:22"
        netdev += f",hostfwd=tcp::{agent_port}-:4445"

        if self._shared_folder is not None:
            cmd.extend(self._shared_folder_args())

        # The tablet is what makes the VM Display usable. RFB PointerEvent
        # carries absolute framebuffer coordinates, but a guest whose only
        # pointing device is the q35 board's PS/2 mouse can accept relative
        # motion, so QEMU has to synthesize deltas from a cursor position it
        # can only guess at while the guest applies its own acceleration and
        # edge clamping. The two cursors diverge on the first movement and
        # never resync, and clicks land wherever the guest's cursor drifted
        # to - which reads as a display that ignores input. An absolute device
        # passes the coordinates through untouched. It costs nothing in
        # anti-evasion terms: this guest already carries virtio NIC, serial
        # and 9p devices, so a HID tablet reveals nothing new.
        cmd.extend([
            "-netdev",
            netdev,
            "-device",
            "virtio-net-pci,netdev=net0",
            "-qmp",
            f"tcp:127.0.0.1:{monitor_port},server,nowait",
            "-device",
            "virtio-serial-pci",
            "-chardev",
            f"socket,id=agent,host=127.0.0.1,port={agent_port + _QGA_CHANNEL_PORT_OFFSET},server,nowait",
            "-device",
            "virtserialport,chardev=agent,name=org.qemu.guest_agent.0",
            "-device",
            f"qemu-xhci,id={_USB_CONTROLLER_ID}",
            "-device",
            f"usb-tablet,bus={_USB_CONTROLLER_ID}.0",
        ])
        if self._qemu_config.snapshot_name:
            cmd.extend(["-loadvm", self._qemu_config.snapshot_name])

        # Windows QEMU implements neither option: -daemonize is rejected outright
        # ("invalid option") and -pidfile never produces a file, so the VM is
        # tracked through the live child process instead.
        if not _IS_WINDOWS:
            if self._temp_dir is not None:
                self._pidfile_path = self._temp_dir / "qemu.pid"
                cmd.extend(["-pidfile", str(self._pidfile_path)])
            cmd.append("-daemonize")

        self._qemu_config = QEMUConfig(
            guest_os=self._qemu_config.guest_os,
            image_path=self._qemu_config.image_path,
            cpu_cores=self._qemu_config.cpu_cores,
            memory_mb=self._qemu_config.memory_mb,
            display=self._qemu_config.display,
            ssh_port=ssh_port,
            monitor_port=monitor_port,
            agent_port=agent_port,
            enable_acceleration=self._qemu_config.enable_acceleration,
            snapshot_name=self._qemu_config.snapshot_name,
            shared_folder=self._shared_folder,
            anti_evasion_profile=self._qemu_config.anti_evasion_profile,
            agent_connect_timeout=self._qemu_config.agent_connect_timeout,
            guest_agent_ready_timeout=self._qemu_config.guest_agent_ready_timeout,
        )

        return cmd

    @staticmethod
    def _ensure_qemu_started(qemu_pid: int | None) -> None:
        """Raise SandboxError if QEMU failed to start.

        Args:
            qemu_pid: The QEMU process ID, or None if startup failed.

        Raises:
            SandboxError: If qemu_pid is None.
        """
        if qemu_pid is None:
            _logger.error("qemu_start_failed_no_pid")
            raise SandboxError(_ERR_QEMU_START)

    @staticmethod
    async def _ensure_agent_connected(agent: GuestAgentClient, time_limit: float) -> None:
        """Drive ``GuestAgentClient.connect`` and raise on failure.

        Wraps the connect call so that ``QEMUSandbox.start`` does not raise
        ``SandboxError`` from inside a ``try`` block (ruff ``TRY301``).

        The per-attempt budget is widened to
        :data:`_AGENT_CONNECT_RETRY_INTERVAL` rather than left at
        ``GuestAgentClient.connect``'s 2 s default because the Windows monitor
        agent services its listener only once per main-loop iteration, and each
        iteration also runs a full ``Get-Process`` / ``Get-NetTCPConnection`` /
        ``Get-NetUDPEndpoint`` sweep and a one-second sleep. Under WHPX that
        iteration routinely exceeds two seconds, so a 2 s handshake window
        abandons every freshly opened socket before the agent ever accepts and
        answers it - the connection then piles up as a dead socket the agent
        reaps on its next accept, and a healthy, listening agent is declared
        unreachable for the whole ``time_limit``. A budget comfortably longer
        than one serve iteration lets the first post-bind attempt complete the
        readiness handshake.

        The wait *between* attempts stays short
        (:data:`_AGENT_CONNECT_BACKOFF_INTERVAL`), because the two intervals
        answer different questions. Before the agent binds, its port is refused
        outright and an attempt costs nothing, so what decides how quickly the
        sandbox notices the agent coming up is the backoff alone - and spending
        a whole handshake budget asleep after each refusal would leave only a
        couple of chances inside the default budget.

        Args:
            agent: Guest agent client to connect.
            time_limit: Total seconds to wait for the agent to become
                reachable before failing.

        Raises:
            SandboxError: If the agent socket cannot be reached within
                ``time_limit`` (either by ``connect`` raising or by it
                returning ``False``).
        """
        connect_error: BaseException | None = None
        try:
            connected = await agent.connect(
                time_limit=time_limit,
                retry_interval=_AGENT_CONNECT_RETRY_INTERVAL,
                backoff_interval=_AGENT_CONNECT_BACKOFF_INTERVAL,
            )
        except (OSError, asyncio.CancelledError, TimeoutError) as agent_error:
            _logger.warning(
                "guest_agent_connect_exception",
                error=str(agent_error),
                timeout_seconds=time_limit,
            )
            connect_error = agent_error
            connected = False

        if not connected:
            _logger.warning(
                "guest_agent_connect_failed",
                timeout_seconds=time_limit,
            )
            error_message = _ERR_AGENT_CONNECT_FAILED.format(timeout=time_limit)
            if connect_error is not None:
                raise SandboxError(error_message) from connect_error
            raise SandboxError(error_message)

    async def _prepare_qemu_shared_folders(self) -> None:
        """Create temp dir, shared folder, and the standard subdirectories."""
        self._temp_dir = Path(await asyncio.to_thread(tempfile.mkdtemp, prefix="intellicrack_qemu_"))
        self._shared_folder = self._temp_dir / "shared"
        await asyncio.to_thread(self._shared_folder.mkdir, parents=True, exist_ok=True)

        await asyncio.to_thread((self._shared_folder / "input").mkdir, exist_ok=True)
        await asyncio.to_thread((self._shared_folder / "output").mkdir, exist_ok=True)
        await asyncio.to_thread((self._shared_folder / "logs").mkdir, exist_ok=True)
        await asyncio.to_thread((self._shared_folder / "monitor").mkdir, exist_ok=True)

    async def _spawn_qemu_process(self) -> None:
        """Build the QEMU command line and launch the virtual machine.

        On platforms whose QEMU supports ``-daemonize`` the launcher exits once
        the VM is running and its PID is read back from the PID file. Windows
        QEMU supports neither option, so there the VM is a long-lived
        foreground child that must not be waited on; it is retained on
        :attr:`process` and its PID is the sandbox's PID.

        Raises:
            SandboxError: If QEMU exited instead of staying up.
        """
        cmd = await self._build_qemu_command(await self._launch_disk_path())
        _logger.info("qemu_starting", command=" ".join(cmd))
        _logger.info("subprocess_spawning", argv=cmd, executable=cmd[0] if cmd else None)

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        if not _IS_WINDOWS:
            _, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=_PROCESS_COMMUNICATE_TIMEOUT,
            )
            self._check_qemu_started(process.returncode, stderr)
            return

        self.process = process
        try:
            await asyncio.wait_for(process.wait(), timeout=_WINDOWS_LAUNCH_GRACE_S)
        except TimeoutError:
            _logger.info("qemu_running_foreground", pid=process.pid)
            recorder = QemuOutputRecorder(process)
            recorder.start()
            self._output_recorder = recorder
            return

        stderr_bytes = await process.stderr.read() if process.stderr is not None else b""
        self._check_qemu_started(process.returncode, stderr_bytes)
        # A zero exit is still a failed launch here: the VM was supposed to stay up.
        _logger.error(
            "qemu_exited_immediately",
            returncode=process.returncode,
            error=stderr_bytes.decode(errors="replace").strip(),
        )
        self.process = None
        raise SandboxError(_ERR_QEMU_EXITED_EARLY)

    @staticmethod
    async def _read_pidfile_once(pidfile_path: Path) -> int | None:
        """Attempt to read and parse a QEMU PID file once.

        Args:
            pidfile_path: Path to the QEMU-written PID file.

        Returns:
            int | None: Parsed PID on success, ``None`` if the file does not
            yet exist or its contents cannot be parsed.
        """
        if not await asyncio.to_thread(pidfile_path.exists):
            return None
        try:
            pid_content = await asyncio.to_thread(
                pidfile_path.read_text,
                encoding="utf-8",
            )
            return int(pid_content.strip())
        except (ValueError, OSError):
            return None

    async def _resolve_qemu_pid(self) -> int | None:
        """Determine the running QEMU process's PID.

        Where QEMU daemonizes, the PID is polled out of the PID file it writes.
        On Windows neither mechanism exists, so the PID is taken directly from
        the foreground child retained by :meth:`_spawn_qemu_process` - which is
        also more reliable, since it needs no file round-trip.

        Returns:
            int | None: The QEMU PID, or ``None`` if it could not be resolved.
        """
        if _IS_WINDOWS:
            return self.process.pid if self.process is not None else None

        if self._pidfile_path is None:
            return None

        for attempt in range(_PIDFILE_MAX_RETRIES):
            await asyncio.sleep(_PIDFILE_RETRY_DELAY)
            qemu_pid = await self._read_pidfile_once(self._pidfile_path)
            if qemu_pid is not None:
                return qemu_pid
            _logger.warning("pidfile_read_retry", attempt=attempt + 1)
        return None

    async def _register_qemu_pid(self, qemu_pid: int | None) -> int:
        """Verify the QEMU PID, register it with the process manager, and update state.

        Args:
            qemu_pid: PID parsed from the QEMU PID file (or ``None`` when
                the file was never produced).

        Returns:
            int: The verified PID stored on the sandbox state.
        """
        await self._verify_qemu_pid(qemu_pid)
        self._ensure_qemu_started(qemu_pid)
        verified_pid: int = qemu_pid if qemu_pid is not None else -1

        self._qemu_pid = verified_pid
        self.state.pid = verified_pid
        _logger.info("qemu_started", pid=verified_pid)

        process_manager = ProcessManager.get_instance()
        process_manager.register_external_pid(
            verified_pid,
            name="qemu-vm",
            process_type=ProcessType.SANDBOX,
            metadata={
                "guest_os": self._qemu_config.guest_os.value,
                "image": str(self._qemu_config.image_path),
            },
        )
        return verified_pid

    async def _attach_qemu_agents(self) -> None:
        """Bring up QMP, mount the share, bootstrap the agent, and await it.

        The shared volume is mounted only once qemu-guest-agent answers, and
        always before the monitor launcher is invoked: the launcher lives on
        that volume, so bootstrapping first would exec a path that does not
        exist yet.
        """
        await self._connect_and_verify_qmp()
        await self._mount_guest_shared_volume()
        await self._bootstrap_guest_agent()

        self._agent = GuestAgentClient(
            port=self._qemu_config.agent_port,
            vm_terminated=self.qemu_termination,
        )
        await self._await_agent_or_bootstrap_failure(
            self._agent,
            self._qemu_config.agent_connect_timeout,
        )

    async def _start_impl(self) -> None:
        """Execute the full QEMU sandbox start sequence."""
        await self._prepare_qemu_shared_folders()
        await self._create_guest_agent_script()
        await self._spawn_qemu_process()

        qemu_pid = await self._resolve_qemu_pid()
        await self._register_qemu_pid(qemu_pid)
        await self._attach_qemu_agents()

        self.state.status = "running"
        self.state.started_at = datetime.now(UTC)
        _logger.info("qemu_sandbox_started_successfully", pid=self._qemu_pid, state=self.state.status)

    async def start(self) -> None:
        """Start the QEMU virtual machine.

        Raises:
            SandboxError: If VM cannot be started.
        """
        if self.state.status == "running":
            _logger.warning("qemu_sandbox_already_running", state=self.state.status)
            return

        if not await self.is_available():
            raise SandboxError(_ERR_QEMU_NA)

        log_sandbox_operation("start", "qemu", guest_os=self._qemu_config.guest_os.value)
        self.state.status = "starting"
        self.state.last_error = None

        try:
            await self._start_impl()
        except (OSError, RuntimeError, SandboxError, TimeoutError, ValueError) as e:
            self.state.status = "error"
            self.state.last_error = str(e)
            await self._cleanup()
            _logger.warning("qemu_sandbox_start_failed", error=str(e))
            raise SandboxError(_ERR_SANDBOX_START) from e

    async def _request_agent_shutdown(self) -> bool:
        """Ask qemu-guest-agent to power the guest off.

        Returns:
            bool: True when the request was written to an open agent channel.
        """
        if self._qga is None or not self._qga.connected:
            return False
        return await self._qga.guest_shutdown()

    async def _request_acpi_powerdown(self) -> bool:
        """Press the guest's virtual ACPI power button over QMP.

        Returns:
            bool: True when QEMU accepted ``system_powerdown``.
        """
        if self._qmp is None or not self._qmp.connected:
            return False

        response = await self._qmp.execute_command({"execute": "system_powerdown"})
        if not response.success:
            _logger.warning("qemu_system_powerdown_failed", error=response.error)
            return False
        return True

    async def _await_qemu_exit(self, time_limit: float) -> bool:
        """Wait for the QEMU process to exit of its own accord.

        QEMU exits once its guest powers off, so the process is the completion
        signal for a graceful shutdown. A foreground child is waited on
        directly; a daemonized QEMU is only known by PID and is polled.

        Args:
            time_limit: Seconds to wait before giving up.

        Returns:
            bool: True when QEMU is no longer running.
        """
        process = self.process
        if process is not None:
            if process.returncode is not None:
                return True
            try:
                await asyncio.wait_for(process.wait(), timeout=time_limit)
            except TimeoutError:
                return False
            return True

        if self._qemu_pid is None or self._qemu_pid < 0:
            return False

        try:
            await asyncio.to_thread(psutil.Process(self._qemu_pid).wait, time_limit)
        except psutil.NoSuchProcess:
            return True
        except psutil.TimeoutExpired:
            return False
        except psutil.Error as error:
            _logger.warning("qemu_exit_wait_failed", pid=self._qemu_pid, error=str(error))
            return False
        return True

    async def _shut_down_guest(self) -> bool:
        """Ask the guest to power itself off and wait for QEMU to exit.

        Two independent channels can carry the request. qemu-guest-agent's
        ``guest-shutdown`` is tried first because it runs inside the guest and
        does not depend on the guest honouring ACPI; QMP's ``system_powerdown``
        presses the virtual power button and covers a guest whose agent is gone.
        Each open channel gets an equal share of
        :attr:`QEMUConfig.guest_shutdown_timeout`, so an agent that never
        complies cannot consume the whole budget.

        Returns:
            bool: True when the QEMU process is no longer running, so no forced
            termination is needed.
        """
        if self._output_recorder is not None:
            self._output_recorder.expect_exit()

        budget = self._qemu_config.guest_shutdown_timeout
        if budget <= 0:
            return False

        agent_open = self._qga is not None and self._qga.connected
        monitor_open = self._qmp is not None and self._qmp.connected
        channels = int(agent_open) + int(monitor_open)
        if channels == 0:
            return False
        share = budget / channels

        if await self._await_qemu_exit(0.0):
            _logger.info("qemu_already_exited_before_shutdown_request")
            return True

        if agent_open and await self._request_agent_shutdown() and await self._await_qemu_exit(share):
            _logger.info("qemu_guest_powered_off", channel="guest-agent")
            return True

        if monitor_open and await self._request_acpi_powerdown() and await self._await_qemu_exit(share):
            _logger.info("qemu_guest_powered_off", channel="qmp-system-powerdown")
            return True

        _logger.warning("qemu_guest_shutdown_not_honoured", budget=budget)
        return False

    def qemu_termination(self) -> QemuTermination | None:
        """Report whether the QEMU process has stopped, and how.

        Every guest operation depends on QEMU still running, so a caller that
        is about to wait on the guest can ask first whether there is still a
        guest to wait for. The recorder's account is preferred because it
        carries QEMU's parting output; the process's own exit status is the
        fallback for a QEMU that was never recorded, so a death is still
        reported rather than mistaken for a running machine.

        Returns:
            QemuTermination | None: How QEMU ended, or ``None`` while it is
            still running or is not observable as a child of this process.
        """
        recorder = self._output_recorder
        if recorder is not None and recorder.termination is not None:
            return recorder.termination
        process = self.process
        if process is not None and process.returncode is not None:
            return QemuTermination(returncode=process.returncode, output_tail=())
        return None

    async def _stop_impl(self) -> None:
        """Execute the full QEMU sandbox stop sequence.

        The guest is asked to power itself off first, and given a bounded time
        to do it, because terminating QEMU while the guest runs is a power-cord
        yank: whatever the in-guest monitors have not yet flushed to the shared
        volume is lost, and the guest filesystem is left dirty for the next
        boot. Only a guest that will not comply is cut off.
        """
        powered_off = await self._shut_down_guest()

        if self._agent is not None:
            await self._agent.disconnect()
            self._agent = None

        if self._qga is not None:
            await self._qga.disconnect()
            self._qga = None

        if self._qmp is not None:
            if not powered_off:
                await self._qmp.quit()
            await self._qmp.disconnect()
            self._qmp = None

        if not powered_off:
            await asyncio.sleep(_QEMU_QUIT_SETTLE_S)

        if self._qemu_pid is not None:
            process_manager = ProcessManager.get_instance()
            process_manager.unregister_external_pid(self._qemu_pid)
            self._qemu_pid = None

        await self._reap_foreground_qemu()

        if self._output_recorder is not None:
            await self._output_recorder.aclose()
            self._output_recorder = None

        await self._cleanup()

        self._active_captures.clear()
        self.state.status = "stopped"
        self.state.pid = None
        self._vnc_port = None
        _logger.info("qemu_sandbox_stopped", state=self.state.status)

    async def _reap_foreground_qemu(self) -> None:
        """Ensure the foreground QEMU child is gone and its handle released.

        A QMP ``quit`` normally ends the process on its own, so this waits briefly for that to land and only kills the child when it does
        not. Without it the Windows VM would outlive the sandbox, because there is no daemonized process for the PID-based teardown to act
        on.
        """
        process = self.process
        if process is None:
            return

        if process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), timeout=_WINDOWS_LAUNCH_GRACE_S)
            except TimeoutError:
                _logger.warning("qemu_foreground_kill_required", pid=process.pid)
                try:
                    process.kill()
                except ProcessLookupError:
                    _logger.debug("qemu_foreground_already_gone", pid=process.pid)
                else:
                    await process.wait()

        self.process = None

    async def stop(self) -> None:
        """Stop the QEMU virtual machine.

        Raises:
            SandboxError: If VM cannot be stopped.
        """
        if self.state.status == "stopped":
            _logger.debug("qemu_sandbox_already_stopped", state=self.state.status)
            return

        self.state.status = "stopping"

        try:
            await self._stop_impl()
        except (OSError, RuntimeError, SandboxError) as e:
            self.state.status = "error"
            self.state.last_error = str(e)
            _logger.warning("qemu_sandbox_stop_failed", error=str(e))
            raise SandboxError(_ERR_SANDBOX_STOP) from e

    @staticmethod
    async def _terminate_orphan_qemu(pid_path: Path) -> None:
        """Read ``pid_path`` and terminate the orphan QEMU tree it references.

        Args:
            pid_path: Path to the QEMU-written PID file.
        """
        pid_content = await asyncio.to_thread(pid_path.read_text, encoding="utf-8")
        pid = int(pid_content.strip())
        try:
            ProcessManager.terminate_tree(pid, graceful_timeout=2.0, force_timeout=2.0)
            _logger.info("cleanup_terminated_orphan_qemu_tree", pid=pid)
        except psutil.NoSuchProcess:
            _logger.debug("cleanup_orphan_already_exited", pid=pid, exc_info=True)

    def _release_claimed_host_ports(self) -> None:
        """Return this sandbox's allocated host ports to the allocator.

        Ports the caller pinned explicitly are left alone; only the ones this sandbox allocated are released, and the configuration fields
        holding them are reset to zero so a later start allocates afresh rather than reusing a number another sandbox may since have taken.
        """
        claimed = self._claimed_host_ports
        if not claimed:
            return

        self._release_host_ports(claimed)
        config = self._qemu_config
        self._qemu_config = replace(
            config,
            ssh_port=0 if config.ssh_port in claimed else config.ssh_port,
            monitor_port=0 if config.monitor_port in claimed else config.monitor_port,
            agent_port=0 if config.agent_port in claimed else config.agent_port,
        )
        if self._vnc_port in claimed:
            self._vnc_port = None
        self._claimed_host_ports = set()

    def _unregister_qemu_pid(self) -> None:
        """Drop this sandbox's PID registration if it still holds one.

        A start that fails after the VM was registered would otherwise leave the
        process manager tracking a process this cleanup has just ended.
        """
        if self._qemu_pid is None:
            return

        ProcessManager.get_instance().unregister_external_pid(self._qemu_pid)
        self._qemu_pid = None

    @staticmethod
    async def _remove_temp_tree(temp_dir: Path) -> None:
        """Remove one instance's temporary tree, waiting out lingering handles.

        Windows releases a dead process's file handles asynchronously, so the
        disk overlay can still be open for a moment after QEMU exits and a
        single attempt loses the race. Every failure is retried and the last one
        is reported: the removal this replaced passed ``ignore_errors=True``,
        which cannot fail and cannot log, and that is how 48 abandoned overlays
        accumulated without one line about them anywhere.

        Args:
            temp_dir: The instance's temporary directory.
        """
        last_error: OSError | None = None
        for attempt in range(1, _TEMP_TREE_REMOVE_ATTEMPTS + 1):
            try:
                await asyncio.to_thread(shutil.rmtree, temp_dir)
            except FileNotFoundError:
                return
            except OSError as e:
                last_error = e
            else:
                return
            if attempt < _TEMP_TREE_REMOVE_ATTEMPTS:
                await asyncio.sleep(_TEMP_TREE_REMOVE_BACKOFF_S * attempt)

        _logger.warning(
            "temp_dir_cleanup_failed",
            path=str(temp_dir),
            attempts=_TEMP_TREE_REMOVE_ATTEMPTS,
            error=str(last_error),
        )

    async def _cleanup(self) -> None:
        """Release this instance's process, port and filesystem state.

        The QEMU child is ended before anything is removed. A failed ``start``
        arrives here with the VM still running - the launch succeeded and a
        later step did not - and on Windows nothing else would end it, because
        QEMU implements neither ``-daemonize`` nor ``-pidfile`` there and the
        PID-file branch below can never fire. A running QEMU also holds its disk
        overlay open, which is precisely why the directories that survived a
        failed start held that one file and nothing else: everything not locked
        was removed, and the overlay could not be.

        Every step is idempotent, because :meth:`_stop_impl` has already
        performed each of them by the time it calls this.
        """
        await self._reap_foreground_qemu()
        self._unregister_qemu_pid()
        self._release_claimed_host_ports()

        if self._temp_dir is not None:
            pid_path = self._temp_dir / "qemu.pid"
            if await asyncio.to_thread(pid_path.exists):
                try:
                    await self._terminate_orphan_qemu(pid_path)
                except (OSError, ValueError) as e:
                    _logger.warning("cleanup_pid_check_failed", error=str(e))

        if self._temp_dir is not None:
            await self._remove_temp_tree(self._temp_dir)

        self._temp_dir = None
        self._shared_folder = None
        self._guest_shared_root = None
        self._guest_system_drive_value = None
        self._guest_system_root_value = None
        self._guest_exec_ready = False

    @staticmethod
    def _windows_agent_script_content() -> str:
        r"""Return the Windows guest agent PowerShell script body.

        The script (1) locates the shared volume from its own location -
        ``$PSScriptRoot`` is the ``monitor`` directory of the FAT drive the
        guest mounted, whose parent is the share root - because the host
        generates this file before the guest has assigned that drive a letter,
        (2) launches the eight bundled monitor scripts from its own directory
        with ``-LogDir <share>\logs``, (3) listens on ``0.0.0.0:4445`` for
        argv-style command requests validated against a short allowlist
        (``powershell``, ``cmd``, any ``.exe`` under the share root,
        ``System32`` or ``SysWOW64``) and answers the host's
        :attr:`GuestAgentClient.PING_REQUEST_TYPE` readiness probe with
        :attr:`GuestAgentClient.PONG_MESSAGE_TYPE`, launching each accepted
        command through ``System.Diagnostics.Process`` so its two streams are
        captured separately and verbatim - PowerShell's own ``2>&1`` folds a
        native child's standard error into the error stream this script's
        ``$ErrorActionPreference`` discards, and ``Out-String`` re-renders
        standard output with a line ending the command never wrote - and
        terminating it if the request's own timeout elapses, (4) emits process,
        file, and
        extended network telemetry in the ten-field schema parsed by
        :func:`intellicrack.sandbox.log_parsers.parse_network_log`, and
        (5) mirrors files created below ``%SystemDrive%`` and ``%SystemRoot%``
        into ``<share>\output\dropped``. Those watched roots come from the
        guest's own environment rather than from a hardcoded ``C:``, with
        :data:`_WINDOWS_SYSTEM_DRIVE` and :data:`_WINDOWS_SYSTEM_ROOT`
        substituted for either variable if the guest leaves it unset;
        :meth:`_windows_drop_watch_roots` builds the host-side scan from the
        same two values and the same two fallbacks, so both sides watch one set
        of directories.

        Nothing is mapped over SMB: QEMU's ``smb=`` netdev option needs a host
        ``smbd``, which a Windows host does not have, so the FAT virtio drive
        is the only share that exists.

        Returns:
            str: Full PowerShell script source (UTF-8).
        """
        return r"""$ErrorActionPreference = 'SilentlyContinue'

$monitorDir = $PSScriptRoot
$shareRoot = Split-Path -Parent $monitorDir
$shareRootPrefix = $shareRoot
if (-not $shareRootPrefix.EndsWith('\')) { $shareRootPrefix = $shareRootPrefix + '\' }

$systemDrive = $env:SystemDrive
if (-not $systemDrive) { $systemDrive = 'C:' }
$systemRoot = $env:SystemRoot
if (-not $systemRoot) { $systemRoot = 'C:\Windows' }

$workRoot = Join-Path $systemDrive 'intellicrack'
if (-not (Test-Path $workRoot)) { New-Item -ItemType Directory -Path $workRoot -Force | Out-Null }
$workRootPrefix = $workRoot
if (-not $workRootPrefix.EndsWith('\')) { $workRootPrefix = $workRootPrefix + '\' }

$logDir = Join-Path $workRoot 'logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

$fileLog = Join-Path $logDir 'file_changes.log'
$netLog = Join-Path $logDir 'network_activity.log'
$procLog = Join-Path $logDir 'process_activity.log'
$droppedMirror = Join-Path $workRoot 'output\dropped'
if (-not (Test-Path $droppedMirror)) { New-Item -ItemType Directory -Path $droppedMirror -Force | Out-Null }
$Global:_IC_DroppedMirror = $droppedMirror
$Global:_IC_DropWatchedRoots = @(
    (Join-Path $systemDrive 'Users\Public\Downloads'),
    (Join-Path $systemRoot 'Temp'),
    (Join-Path $systemDrive 'Users\Default\AppData\Local\Temp')
)

$monitorScripts = @(
    'api_trace.ps1',
    'clipboard_monitor.ps1',
    'dll_monitor.ps1',
    'injection_monitor.ps1',
    'kernel_object_monitor.ps1',
    'registry_monitor.ps1',
    'resource_monitor.ps1',
    'service_monitor.ps1'
)
foreach ($scriptName in $monitorScripts) {
    $scriptPath = Join-Path $monitorDir $scriptName
    if (Test-Path $scriptPath) {
        Start-Process -FilePath 'powershell.exe' `
            -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$scriptPath,'-LogDir',$logDir) `
            -WindowStyle Hidden
    }
}

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = ($systemDrive + '\')
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true
$Global:_IC_FileLog = $fileLog
Register-ObjectEvent $watcher 'Created' -MessageData $fileLog -Action {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $full = $Event.SourceEventArgs.FullPath
    "$ts|created|$full" | Out-File -Append $Event.MessageData -Encoding utf8
    $mirror = $Global:_IC_DroppedMirror
    if ($mirror -and (Test-Path $mirror)) {
        foreach ($root in $Global:_IC_DropWatchedRoots) {
            if ($full.ToLower().StartsWith($root.ToLower())) {
                try {
                    if (Test-Path -LiteralPath $full -PathType Leaf) {
                        $name = [System.IO.Path]::GetFileName($full)
                        $stamp = (Get-Date).ToString('yyyyMMddHHmmssfff')
                        $dest = Join-Path $mirror ("${stamp}_${name}")
                        Copy-Item -LiteralPath $full -Destination $dest -Force -ErrorAction Stop
                    }
                } catch {
                    "$ts|mirror_failed|$full|$($_.Exception.Message)" | Out-File -Append $Event.MessageData -Encoding utf8
                }
                break
            }
        }
    }
} | Out-Null
Register-ObjectEvent $watcher 'Changed' -MessageData $fileLog -Action {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts|modified|$($Event.SourceEventArgs.FullPath)" | Out-File -Append $Event.MessageData -Encoding utf8
} | Out-Null
Register-ObjectEvent $watcher 'Deleted' -MessageData $fileLog -Action {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts|deleted|$($Event.SourceEventArgs.FullPath)" | Out-File -Append $Event.MessageData -Encoding utf8
} | Out-Null

$allowedNames = @('powershell', 'powershell.exe', 'cmd', 'cmd.exe')
$allowedRoots = @($shareRootPrefix, $workRootPrefix, ($systemRoot + '\System32\'), ($systemRoot + '\SysWOW64\'))
function Test-AllowedCommand($cmdValue) {
    if ([string]::IsNullOrEmpty($cmdValue)) { return $false }
    $lower = $cmdValue.ToLower()
    if ($allowedNames -contains $lower) { return $true }
    if (-not $lower.EndsWith('.exe')) { return $false }
    foreach ($root in $allowedRoots) {
        if ($lower.StartsWith($root.ToLower())) { return $true }
    }
    return $false
}

$quoteChar = [char]34

# Which of the two renderings below an argument needs is decided by the callee,
# because the two parsers are genuinely different and neither escape survives
# the other. Everything reached here is a real executable, so only the command
# interpreter itself reads its tail by its own rules.
function Test-ShellParsedCallee($commandPath) {
    if ([string]::IsNullOrEmpty($commandPath)) { return $false }
    $leaf = [System.IO.Path]::GetFileName([string]$commandPath).ToLower()
    return ($leaf -eq 'cmd' -or $leaf -eq 'cmd.exe')
}

# cmd.exe never sees an argv: it re-parses its own tail, where a backslash is an
# ordinary path character and only quotes group. Escaping for CommandLineToArgvW
# here would hand it 'cd /d \"C:\dir\"' and it would answer 'The filename,
# directory name, or volume label syntax is incorrect'. So an argument for the
# interpreter is held together and otherwise left exactly as the caller wrote
# it - a shell command line's internal quoting is the caller's own.
function ConvertTo-ShellCommandLineArgument($value) {
    $text = [string]$value
    if ($text.Length -gt 0 -and $text.IndexOfAny([char[]]@([char]32, [char]9)) -lt 0) { return $text }
    return $quoteChar + $text + $quoteChar
}

# Every other callee splits this command line by CommandLineToArgvW's rules, so
# an argument only survives if it is escaped by them: a quote inside the
# argument has to be written as backslash-quote, and any run of backslashes
# immediately before a quote - including the closing one this adds - has to be
# doubled, or the last of them escapes that quote instead of standing for
# itself. Wrapping without either escape is what silently rewrote arguments
# before (S17-D73): a quoted value lost its quotes and split, and a path ending
# in a separator swallowed the argument after it.
function ConvertTo-CommandLineArgument($value) {
    $backslashChar = [char]92
    $text = [string]$value
    if ($text.Length -gt 0 -and $text.IndexOfAny([char[]]@([char]32, [char]9, $quoteChar)) -lt 0) { return $text }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append($quoteChar)
    $index = 0
    while ($index -lt $text.Length) {
        $slashes = 0
        while ($index -lt $text.Length -and $text[$index] -eq $backslashChar) {
            $slashes++
            $index++
        }
        if ($index -eq $text.Length) {
            [void]$builder.Append([string]::new($backslashChar, $slashes * 2))
            break
        }
        if ($text[$index] -eq $quoteChar) {
            [void]$builder.Append([string]::new($backslashChar, $slashes * 2 + 1))
            [void]$builder.Append($quoteChar)
        } else {
            [void]$builder.Append([string]::new($backslashChar, $slashes))
            [void]$builder.Append($text[$index])
        }
        $index++
    }
    [void]$builder.Append($quoteChar)
    return $builder.ToString()
}

function Invoke-GuestCommand($commandPath, $commandArgs, $timeoutSeconds) {
    $shellParsed = Test-ShellParsedCallee $commandPath
    $rendered = @()
    foreach ($item in $commandArgs) {
        if ($shellParsed) { $rendered += (ConvertTo-ShellCommandLineArgument $item) }
        else { $rendered += (ConvertTo-CommandLineArgument $item) }
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $commandPath
    $startInfo.Arguments = [string]::Join(' ', $rendered)
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $startInfo
    [void]$proc.Start()

    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()

    $limitMs = -1
    if ($timeoutSeconds) { $limitMs = [int]([double]$timeoutSeconds * 1000) }
    $timedOut = -not $proc.WaitForExit($limitMs)
    if ($timedOut) {
        try { $proc.Kill() } catch { }
        [void]$proc.WaitForExit()
    }

    $outTask.Wait()
    $errTask.Wait()

    $capturedError = $errTask.Result
    if ($timedOut) {
        $capturedError = $capturedError + 'command did not exit within ' + $timeoutSeconds + 's and was terminated'
    }
    return @{
        StandardOutput = $outTask.Result
        StandardError = $capturedError
        ExitCode = $proc.ExitCode
    }
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 4445)
$listener.Start()

function Send-Message($stream, $data) {
    $json = ConvertTo-Json $data -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
}

$knownProcs = @{}
$prevConnKeys = @{}
$prevConnKeyCap = 8192

while ($true) {
    if ($listener.Pending()) {
        $client = $listener.AcceptTcpClient()
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        while ($client.Connected) {
            try {
                $line = $reader.ReadLine()
                if ($null -eq $line) { break }
                $request = ConvertFrom-Json $line
                if ($request.type -eq 'ping') {
                    Send-Message $stream @{
                        type = 'pong'
                        data = @{}
                    }
                }
                elseif ($request.type -eq 'execute') {
                    $cmd = [string]$request.command
                    $cmdArgs = @()
                    if ($request.args) { $cmdArgs = @($request.args) }
                    $output = ''
                    $errorOutput = ''
                    $exitCode = 0
                    if (-not (Test-AllowedCommand $cmd)) {
                        $errorOutput = "command not in allowlist: $cmd"
                        $exitCode = -1
                    } else {
                        try {
                            $captured = Invoke-GuestCommand $cmd $cmdArgs $request.timeout
                            $output = $captured.StandardOutput
                            $errorOutput = $captured.StandardError
                            $exitCode = $captured.ExitCode
                            if ($null -eq $exitCode) { $exitCode = 0 }
                        } catch {
                            $errorOutput = $_.Exception.Message
                            $exitCode = 1
                        }
                    }
                    Send-Message $stream @{
                        type = 'result'
                        data = @{
                            exit_code = $exitCode
                            stdout = $output
                            stderr = $errorOutput
                        }
                    }
                }
            } catch {
                break
            }
        }
        $client.Close()
    }

    $currentProcs = Get-Process | Select-Object Id, Name, Path
    foreach ($proc in $currentProcs) {
        if (-not $knownProcs.ContainsKey($proc.Id)) {
            $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            "$ts|created|$($proc.Id)|$($proc.Name)|$($proc.Path)" | Out-File -Append $procLog -Encoding utf8
            $knownProcs[$proc.Id] = $proc.Name
        }
    }
    $currentIds = $currentProcs | ForEach-Object { $_.Id }
    $terminated = $knownProcs.Keys | Where-Object { $_ -notin $currentIds }
    foreach ($id in $terminated) {
        $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        "$ts|terminated|$id|$($knownProcs[$id])" | Out-File -Append $procLog -Encoding utf8
        $knownProcs.Remove($id)
    }

    $procNameByPid = @{}
    foreach ($p in $currentProcs) { $procNameByPid[$p.Id] = $p.Name }

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
    foreach ($conn in $tcpConns) {
        $state = [string]$conn.State
        $owner = $conn.OwningProcess
        $pname = ''
        if ($owner -and $procNameByPid.ContainsKey($owner)) { $pname = $procNameByPid[$owner] }
        $key = "tcp|$($conn.LocalAddress):$($conn.LocalPort)|$($conn.RemoteAddress):$($conn.RemotePort)|$state"
        if (-not $prevConnKeys.ContainsKey($key)) {
            $prevConnKeys[$key] = $true
            "$ts|connection|$($conn.LocalAddress):$($conn.LocalPort)|$($conn.RemoteAddress):$($conn.RemotePort)|$state|tcp|0|0|$owner|$pname" | Out-File -Append $netLog -Encoding utf8
        }
    }

    $udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    foreach ($ep in $udpEndpoints) {
        $owner = $ep.OwningProcess
        $pname = ''
        if ($owner -and $procNameByPid.ContainsKey($owner)) { $pname = $procNameByPid[$owner] }
        $key = "udp|$($ep.LocalAddress):$($ep.LocalPort)"
        if (-not $prevConnKeys.ContainsKey($key)) {
            $prevConnKeys[$key] = $true
            "$ts|bind|$($ep.LocalAddress):$($ep.LocalPort)|0.0.0.0:0|Listen|udp|0|0|$owner|$pname" | Out-File -Append $netLog -Encoding utf8
        }
    }

    if ($prevConnKeys.Count -gt $prevConnKeyCap) {
        $prevConnKeys.Clear()
    }

    Start-Sleep -Seconds 1
}
"""

    @staticmethod
    def bundled_scripts_dir() -> Path:
        """Return the on-disk directory that contains bundled monitor PS1 scripts.

        Returns:
            Path: Absolute path to the bundled ``scripts`` directory. The
            path is resolved from this module's location and is therefore
            safe to compute synchronously even from async callers.
        """
        return Path(__file__).resolve().parent / "scripts"

    @staticmethod
    def traceevent_assemblies_dir() -> Path:
        """Return the on-disk directory that contains vendored ETW tracing assemblies.

        Returns:
            Path: Absolute path to ``vendor/traceevent`` at the repository
            root, resolved via :func:`intellicrack.core.config.get_project_root`
            so it is correct regardless of the working directory the sandbox
            backend is invoked from.
        """
        return get_project_root() / "vendor" / "traceevent"

    async def _create_guest_agent_script(self) -> None:
        r"""Create guest agent scripts and stage bundled monitor scripts.

        On Windows, writes ``agent.ps1`` and ``start_agent.cmd`` into the
        host-side shared folder's ``monitor`` subdirectory, alongside the eight
        bundled PS1 monitor scripts. Both generated scripts derive the in-guest
        share root from their own location rather than naming a drive letter,
        because the guest has not assigned one yet when they are written: the
        launcher resolves ``agent.ps1`` through ``%~dp0`` and the agent
        resolves the logs, output and monitor directories through
        ``$PSScriptRoot``. On Linux, writes the Python agent and its startup
        shell script.

        The Linux agent runs four monitors. Beside the file and process
        monitors it samples the kernel socket tables into
        ``network_activity.log`` in the ten-field schema parsed by
        :func:`intellicrack.sandbox.log_parsers.parse_network_log` - hex
        endpoints decoded to printable addresses and ports, state codes decoded
        to the same state vocabulary the Windows monitor emits, and each socket
        inode attributed to its owning process by walking the per-process
        file-descriptor links - and samples ``/proc`` counters into
        ``resource_monitor.log`` in the seven-field schema parsed by
        :func:`intellicrack.sandbox.log_parsers.parse_resource_log`, taking two
        readings so the CPU column is a real busy percentage and the disk and
        network columns are real per-second rates rather than counters. Both
        logs were previously written only by the Windows monitor path, which
        left the Network Activity and Resources report tabs permanently empty
        for a Linux guest.

        The Windows agent bundle also carries every vendored ETW assembly
        found by :func:`enumerate_traceevent_assembly_files` into the same
        monitor directory as ``api_trace.ps1`` and ``injection_monitor.ps1``:
        both scripts search their own directory (``$PSScriptRoot``) for
        ``Microsoft.Diagnostics.Tracing.TraceEvent.dll`` among other
        locations, so staging it there is what lets either script find ETW
        at all rather than exiting within a second of starting with "DLL not
        found". Both scripts also pre-load every other assembly staged
        alongside it and install an ``AssemblyResolve`` handler before
        loading it, which is what lets ``Add-Type`` actually load the
        library under Windows PowerShell 5.1's Desktop CLR rather than
        failing past discovery with a ``ReflectionTypeLoadException``.

        Raises:
            ValueError: If an unsupported guest OS is configured.
        """
        if self._shared_folder is None:
            return

        monitor_dir = self._shared_folder / "monitor"

        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            agent_script = monitor_dir / "agent.ps1"
            agent_content = self._windows_agent_script_content()
            await asyncio.to_thread(agent_script.write_text, agent_content, encoding="utf-8")

            scripts_src = await asyncio.to_thread(self.bundled_scripts_dir)
            for script_name in MONITOR_SCRIPT_NAMES:
                src = scripts_src / script_name
                dst = monitor_dir / script_name
                if await asyncio.to_thread(src.exists):
                    await asyncio.to_thread(shutil.copy2, src, dst)
                else:
                    _logger.warning("monitor_script_missing", script=script_name, path=str(src))

            traceevent_src = await asyncio.to_thread(self.traceevent_assemblies_dir)
            assembly_rel_paths = await asyncio.to_thread(enumerate_traceevent_assembly_files, traceevent_src)
            if not assembly_rel_paths:
                _logger.warning("traceevent_assemblies_missing", path=str(traceevent_src))
            for assembly_rel_path in assembly_rel_paths:
                src = traceevent_src / assembly_rel_path
                dst = monitor_dir / assembly_rel_path
                await asyncio.to_thread(dst.parent.mkdir, parents=True, exist_ok=True)
                await asyncio.to_thread(shutil.copy2, src, dst)

            startup_script = monitor_dir / "start_agent.cmd"
            # %~dp0 is the directory this launcher was started from, which is
            # the share's own monitor directory whatever letter the guest gave
            # the FAT volume. The letter cannot be known here: the file is
            # written before QEMU is even launched.
            startup_content = (
                '@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0agent.ps1"\r\n'
            )
        elif self._qemu_config.guest_os == GuestOS.LINUX:
            agent_script = monitor_dir / "agent.py"
            agent_content = '''#!/usr/bin/env python3
"""QEMU Guest Agent for Intellicrack sandbox monitoring.

This agent runs inside the QEMU guest VM to:
- Monitor process creation and termination
- Track file system changes (if inotify available)
- Record kernel socket tables as network activity
- Sample CPU, memory, disk and network resource usage
- Execute commands from the host and return results
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

WORK_ROOT: Path = Path("/var/lib/intellicrack")
LOG_DIR: Path = WORK_ROOT / "logs"
DROPPED_MIRROR_DIR: Path = WORK_ROOT / "output" / "dropped"
DROPPED_WATCH_ROOTS: tuple[str, ...] = ("/tmp", "/var/tmp", "/home")
PORT: int = 4445
RECV_BUFFER_SIZE: int = 65536
DEFAULT_COMMAND_TIMEOUT: int = 30
MONITOR_POLL_INTERVAL: float = 1.0
RESOURCE_SAMPLE_INTERVAL: float = 5.0
PROC_ROOT: Path = Path("/proc")
NETWORK_LOG_NAME: str = "network_activity.log"
RESOURCE_LOG_NAME: str = "resource_monitor.log"
PROC_NET_TABLES: tuple[tuple[str, str], ...] = (
    ("net/tcp", "tcp"),
    ("net/tcp6", "tcp"),
    ("net/udp", "udp"),
    ("net/udp6", "udp"),
)
PROC_NET_MIN_FIELDS: int = 10
PROC_NET_INODE_INDEX: int = 9
SOCKET_LINK_PREFIX: str = "socket:["
CONNECTION_KEY_CAP: int = 8192
IPV4_PACKED_LENGTH: int = 4
IPV6_PACKED_LENGTH: int = 16
IPV6_WORD_LENGTH: int = 4
TCP_STATE_NAMES: dict[str, str] = {
    "01": "Established",
    "02": "SynSent",
    "03": "SynReceived",
    "04": "FinWait1",
    "05": "FinWait2",
    "06": "TimeWait",
    "07": "Closed",
    "08": "CloseWait",
    "09": "LastAck",
    "0A": "Listen",
    "0B": "Closing",
    "0C": "SynReceived",
}
UNKNOWN_STATE: str = "Unknown"
ESTABLISHED_STATE: str = "Established"
LISTEN_STATE: str = "Listen"
CONNECTION_OPERATION: str = "connection"
BIND_OPERATION: str = "bind"
PROC_STAT_MIN_FIELDS: int = 5
CPU_IDLE_INDEX: int = 3
CPU_IOWAIT_INDEX: int = 4
KIB_PER_MIB: float = 1024.0
DISK_SECTOR_BYTES: int = 512
DISKSTATS_MIN_FIELDS: int = 14
DISKSTATS_NAME_INDEX: int = 2
DISKSTATS_SECTORS_READ_INDEX: int = 5
DISKSTATS_SECTORS_WRITTEN_INDEX: int = 9
DISK_EXCLUDED_PREFIXES: tuple[str, ...] = ("loop", "ram", "zram", "dm-")
NET_DEV_MIN_FIELDS: int = 16
NET_DEV_RECV_BYTES_INDEX: int = 0
NET_DEV_SENT_BYTES_INDEX: int = 8
NET_EXCLUDED_INTERFACES: tuple[str, ...] = ("lo",)

# Before the handler, not in main(): a FileHandler opens its file as it is
# constructed, and this runs at import. A guest that has not run the agent
# before has no work root at all, so leaving this to main() meant the agent died
# of FileNotFoundError before a line of it ran.
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "agent.log"),
        logging.StreamHandler(sys.stderr),
    ],
)
_logger: logging.Logger = logging.getLogger("sandbox.qemu.agent")


def file_monitor() -> None:
    """Monitor file system changes using inotify.

    Logs all file operations (create, modify, delete, etc.) to the
    file_changes.log file in the shared log directory.
    """
    try:
        import inotify.adapters
    except ImportError:
        _logger.warning("inotify_module_unavailable", extra={"reason": "import failed"})
        return

    try:
        inotify_tree = inotify.adapters.InotifyTree("/")
        _logger.info("file_monitoring_started", extra={"watch_root": "/"})
        try:
            DROPPED_MIRROR_DIR.mkdir(parents=True, exist_ok=True)
        except OSError as mkdir_err:
            _logger.debug("dropped_mirror_dir_create_failed", extra={"error": str(mkdir_err)})
        for event in inotify_tree.event_gen(yield_nones=False):
            event_header, type_names, watch_path, filename = event
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            operation = type_names[0].lower() if type_names else "unknown"
            full_path = f"{watch_path}/{filename}" if filename else watch_path
            try:
                log_path = LOG_DIR / "file_changes.log"
                with log_path.open("a", encoding="utf-8") as log_file:
                    log_file.write(f"{timestamp}|{operation}|{full_path}\\n")
            except OSError as write_err:
                _logger.debug("file_change_log_write_failed", extra={"error": str(write_err)})
            if operation == "in_create" and filename:
                _mirror_dropped_file(full_path)
    except OSError as inotify_err:
        _logger.error("inotify_init_failed", extra={"error": str(inotify_err)})


def _mirror_dropped_file(full_path: str) -> None:
    """Copy a newly-created file under watched roots into the dropped mirror.

    Args:
        full_path: Absolute path of the newly-created file.
    """
    for root in DROPPED_WATCH_ROOTS:
        if not full_path.startswith(root + "/") and full_path != root:
            continue
        try:
            src = Path(full_path)
            if not src.is_file():
                return
            stamp = time.strftime("%Y%m%d%H%M%S")
            dest = DROPPED_MIRROR_DIR / f"{stamp}_{src.name}"
            shutil.copy2(src, dest)
        except OSError as copy_err:
            _logger.debug("dropped_mirror_copy_failed", extra={"src": full_path, "error": str(copy_err)})
        return


def process_monitor() -> None:
    """Monitor process creation and termination via /proc.

    Polls /proc directory to detect new and terminated processes,
    logging activity to the process_activity.log file.
    """
    known_pids: set[int] = set()
    _logger.info("process_monitoring_started", extra={"poll_interval": MONITOR_POLL_INTERVAL})

    while True:
        current_pids: set[int] = set()
        try:
            proc_entries = os.listdir("/proc")
        except OSError as list_err:
            _logger.debug("proc_list_failed", extra={"error": str(list_err)})
            time.sleep(MONITOR_POLL_INTERVAL)
            continue

        for pid_str in proc_entries:
            if not pid_str.isdigit():
                continue

            pid = int(pid_str)
            current_pids.add(pid)

            if pid not in known_pids:
                process_name = _get_process_name(pid)
                if process_name is not None:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    _log_process_activity(timestamp, "created", pid, process_name)

        terminated_pids = known_pids - current_pids
        for pid in terminated_pids:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            _log_process_activity(timestamp, "terminated", pid, None)

        known_pids = current_pids
        time.sleep(MONITOR_POLL_INTERVAL)


def _get_process_name(pid: int) -> str | None:
    """Read process name from /proc/<pid>/comm.

    Args:
        pid: Process ID to look up.

    Returns:
        Process name string or None if not accessible.
    """
    try:
        comm_path = Path(f"/proc/{pid}/comm")
        with comm_path.open("r", encoding="utf-8") as comm_file:
            return comm_file.read().strip()
    except (OSError, PermissionError, FileNotFoundError):
        _logger.debug("process_name_lookup_failed", exc_info=True)
        return None


def _log_process_activity(
    timestamp: str, operation: str, pid: int, name: str | None
) -> None:
    """Write process activity to the log file.

    Args:
        timestamp: Formatted timestamp string.
        operation: Either 'created' or 'terminated'.
        pid: Process ID.
        name: Process name (may be None for terminated processes).
    """
    try:
        log_path = LOG_DIR / "process_activity.log"
        with log_path.open("a", encoding="utf-8") as log_file:
            if name is not None:
                log_file.write(f"{timestamp}|{operation}|{pid}|{name}\\n")
            else:
                log_file.write(f"{timestamp}|{operation}|{pid}\\n")
    except OSError as write_err:
        _logger.debug("process_activity_log_write_failed", extra={"error": str(write_err)})


def _log_field(value: object) -> str:
    """Render one value as a pipe-delimited monitor-log field.

    Args:
        value: Value to render.

    Returns:
        Field text with the delimiter and any line breaks neutralised.
    """
    text = str(value)
    text = text.replace("|", "_")
    text = text.replace("\\r", " ")
    return text.replace("\\n", " ")


def _append_log(name: str, line: str) -> None:
    """Append one record to a monitor log in the shared log directory.

    Args:
        name: Log file name under the shared log directory.
        line: Fully rendered record without its trailing newline.
    """
    try:
        log_path = LOG_DIR / name
        with log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(line + "\\n")
    except OSError as write_err:
        _logger.debug("monitor_log_write_failed", extra={"log": name, "error": str(write_err)})


def _read_proc_text(relative: str, proc_root: Path = PROC_ROOT) -> str:
    """Read a file below the proc filesystem, tolerating an unreadable entry.

    Args:
        relative: Path of the file relative to the proc mount point.
        proc_root: Mount point of the proc filesystem.

    Returns:
        File contents, or an empty string when the file cannot be read.
    """
    try:
        return (proc_root / relative).read_text(encoding="utf-8", errors="replace")
    except OSError as read_err:
        _logger.debug("proc_read_failed", extra={"path": relative, "error": str(read_err)})
        return ""


def decode_proc_ip(hex_address: str) -> str:
    """Decode a proc-filesystem hexadecimal address into printable form.

    The kernel prints each 32-bit word of an address in host byte order, so
    every four-byte group is reversed before it is formatted.

    Args:
        hex_address: Hexadecimal address exactly as the kernel printed it.

    Returns:
        Dotted-quad or colon-separated address, or an empty string when the
        token is not a recognised address width.
    """
    try:
        packed = bytes.fromhex(hex_address)
    except ValueError:
        return ""
    if len(packed) == IPV4_PACKED_LENGTH:
        return socket.inet_ntop(socket.AF_INET, packed[::-1])
    if len(packed) == IPV6_PACKED_LENGTH:
        regrouped = b"".join(
            packed[offset:offset + IPV6_WORD_LENGTH][::-1]
            for offset in range(0, IPV6_PACKED_LENGTH, IPV6_WORD_LENGTH)
        )
        return socket.inet_ntop(socket.AF_INET6, regrouped)
    return ""


def decode_proc_endpoint(raw: str) -> str:
    """Decode a proc-filesystem ``address:port`` token into printable form.

    IPv6 addresses are bracketed so the address and the port stay separable.

    Args:
        raw: Hexadecimal ``address:port`` token from a kernel socket table.

    Returns:
        Endpoint text, or an empty string when the address cannot be decoded.
    """
    hex_address, _, hex_port = raw.partition(":")
    try:
        port = int(hex_port, 16)
    except ValueError:
        port = 0
    address = decode_proc_ip(hex_address)
    if not address:
        return ""
    if ":" in address:
        return "[" + address + "]:" + str(port)
    return address + ":" + str(port)


def socket_inode_owners(proc_root: Path = PROC_ROOT) -> dict[str, tuple[int, str]]:
    """Map socket inode numbers to the process that holds each socket open.

    Every process file-descriptor directory is walked and each descriptor that
    points at ``socket:[inode]`` attributes that inode to the owning process.

    Args:
        proc_root: Mount point of the proc filesystem.

    Returns:
        Mapping of inode number to the owning process id and name.
    """
    owners: dict[str, tuple[int, str]] = {}
    try:
        entries = os.listdir(proc_root)
    except OSError as list_err:
        _logger.debug("proc_pid_list_failed", extra={"error": str(list_err)})
        return owners
    for pid_str in entries:
        if not pid_str.isdigit():
            continue
        fd_dir = proc_root / pid_str / "fd"
        try:
            fd_names = os.listdir(fd_dir)
        except OSError as fd_err:
            _logger.debug("proc_fd_list_failed", extra={"pid": pid_str, "error": str(fd_err)})
            continue
        pid = int(pid_str)
        process_name = _read_proc_text(pid_str + "/comm", proc_root).strip()
        for fd_name in fd_names:
            try:
                target = os.readlink(fd_dir / fd_name)
            except OSError:
                continue
            if target.startswith(SOCKET_LINK_PREFIX) and target.endswith("]"):
                owners[target[len(SOCKET_LINK_PREFIX):-1]] = (pid, process_name)
    return owners


def parse_proc_net_table(text: str, protocol: str) -> list[tuple[str, str, str, str, str]]:
    """Parse one kernel socket table into decoded connection rows.

    Args:
        text: Full contents of a proc-filesystem socket table.
        protocol: Transport protocol the table describes.

    Returns:
        One tuple of protocol, local endpoint, remote endpoint, state name and
        socket inode per decodable row.
    """
    rows: list[tuple[str, str, str, str, str]] = []
    for raw_line in text.splitlines():
        fields = raw_line.split()
        if len(fields) < PROC_NET_MIN_FIELDS or not fields[0].endswith(":"):
            continue
        local_endpoint = decode_proc_endpoint(fields[1])
        if not local_endpoint:
            continue
        remote_endpoint = decode_proc_endpoint(fields[2])
        state = TCP_STATE_NAMES.get(fields[3].upper(), UNKNOWN_STATE)
        rows.append((protocol, local_endpoint, remote_endpoint, state, fields[PROC_NET_INODE_INDEX]))
    return rows


def format_connection_record(
    timestamp: str,
    protocol: str,
    local_endpoint: str,
    remote_endpoint: str,
    state: str,
    pid: int | None,
    process_name: str,
) -> str:
    """Render one socket observation in the ten-field network log schema.

    Datagram sockets carry the same state column as stream sockets, so an
    unconnected datagram socket is reported as a bind in the listening state
    and a connected one as a connection in the established state. Neither the
    kernel socket tables nor their Windows counterpart expose per-socket byte
    counters, so both byte columns are reported as zero rather than invented.

    Args:
        timestamp: Observation timestamp.
        protocol: Transport protocol of the socket.
        local_endpoint: Local ``address:port`` endpoint.
        remote_endpoint: Remote ``address:port`` endpoint.
        state: Decoded socket state name.
        pid: Owning process id, or None when the socket could not be attributed.
        process_name: Owning process name, empty when unknown.

    Returns:
        Pipe-delimited record ready to append to the network activity log.
    """
    if protocol == "udp":
        connected = state == ESTABLISHED_STATE
        operation = CONNECTION_OPERATION if connected else BIND_OPERATION
        rendered_state = ESTABLISHED_STATE if connected else LISTEN_STATE
    else:
        operation = CONNECTION_OPERATION
        rendered_state = state
    return "|".join([
        _log_field(timestamp),
        operation,
        _log_field(local_endpoint),
        _log_field(remote_endpoint),
        _log_field(rendered_state),
        _log_field(protocol),
        "0",
        "0",
        "" if pid is None else str(pid),
        _log_field(process_name),
    ])


def collect_network_records(
    timestamp: str,
    seen_keys: dict[str, bool],
    proc_root: Path = PROC_ROOT,
) -> list[str]:
    """Collect newly observed sockets as network activity log records.

    Args:
        timestamp: Observation timestamp applied to every new record.
        seen_keys: Mutable set of connection keys already reported; updated in
            place and cleared once it exceeds its cap.
        proc_root: Mount point of the proc filesystem.

    Returns:
        Pipe-delimited records for sockets not previously reported.
    """
    owners = socket_inode_owners(proc_root)
    records: list[str] = []
    for relative, protocol in PROC_NET_TABLES:
        table = _read_proc_text(relative, proc_root)
        if not table:
            continue
        for row in parse_proc_net_table(table, protocol):
            row_protocol, local_endpoint, remote_endpoint, state, inode = row
            key = "|".join([row_protocol, local_endpoint, remote_endpoint, state])
            if key in seen_keys:
                continue
            seen_keys[key] = True
            owner = owners.get(inode)
            records.append(
                format_connection_record(
                    timestamp,
                    row_protocol,
                    local_endpoint,
                    remote_endpoint,
                    state,
                    None if owner is None else owner[0],
                    "" if owner is None else owner[1],
                ),
            )
    if len(seen_keys) > CONNECTION_KEY_CAP:
        seen_keys.clear()
    return records


def network_monitor(proc_root: Path = PROC_ROOT) -> None:
    """Poll the kernel socket tables and log newly observed connections.

    Args:
        proc_root: Mount point of the proc filesystem.
    """
    seen_keys: dict[str, bool] = {}
    _logger.info("network_monitoring_started", extra={"poll_interval": MONITOR_POLL_INTERVAL})
    while True:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        for record in collect_network_records(timestamp, seen_keys, proc_root):
            _append_log(NETWORK_LOG_NAME, record)
        time.sleep(MONITOR_POLL_INTERVAL)


def read_cpu_totals(proc_root: Path = PROC_ROOT) -> tuple[int, int]:
    """Read the aggregate CPU time counters from the kernel statistics file.

    Args:
        proc_root: Mount point of the proc filesystem.

    Returns:
        Total and idle CPU time in kernel ticks; both zero when unavailable.
    """
    for raw_line in _read_proc_text("stat", proc_root).splitlines():
        fields = raw_line.split()
        if not fields or fields[0] != "cpu":
            continue
        values = [int(field) for field in fields[1:] if field.isdigit()]
        if len(values) < PROC_STAT_MIN_FIELDS:
            return (0, 0)
        return (sum(values), values[CPU_IDLE_INDEX] + values[CPU_IOWAIT_INDEX])
    return (0, 0)


def read_memory_used_mb(proc_root: Path = PROC_ROOT) -> float:
    """Read physical memory currently in use, in mebibytes.

    Args:
        proc_root: Mount point of the proc filesystem.

    Returns:
        Used memory in mebibytes, rounded to two decimal places.
    """
    total_kib = 0
    available_kib = 0
    for raw_line in _read_proc_text("meminfo", proc_root).splitlines():
        label, _, remainder = raw_line.partition(":")
        fields = remainder.split()
        if not fields or not fields[0].isdigit():
            continue
        if label == "MemTotal":
            total_kib = int(fields[0])
        elif label == "MemAvailable":
            available_kib = int(fields[0])
    used_kib = total_kib - available_kib
    if used_kib < 0:
        used_kib = 0
    return round(used_kib / KIB_PER_MIB, 2)


def _is_partition_of(name: str, device_names: set[str]) -> bool:
    """Report whether a block device name is a partition of another device.

    Args:
        name: Block device name to classify.
        device_names: Every block device name present in the statistics file.

    Returns:
        True when the name is a partition of another listed device.
    """
    for candidate in device_names:
        if candidate == name or not name.startswith(candidate):
            continue
        suffix = name[len(candidate):]
        if suffix.isdigit():
            return True
        if suffix.startswith("p") and suffix[1:].isdigit():
            return True
    return False


def read_process_io_totals(proc_root: Path = PROC_ROOT) -> tuple[int, int]:
    """Sum storage bytes read and written across every readable process.

    This is the fallback source used when the kernel exposes no block device
    statistics to the guest.

    Args:
        proc_root: Mount point of the proc filesystem.

    Returns:
        Cumulative bytes read and written by all processes.
    """
    read_bytes = 0
    write_bytes = 0
    try:
        entries = os.listdir(proc_root)
    except OSError as list_err:
        _logger.debug("proc_pid_list_failed", extra={"error": str(list_err)})
        return (0, 0)
    for pid_str in entries:
        if not pid_str.isdigit():
            continue
        for raw_line in _read_proc_text(pid_str + "/io", proc_root).splitlines():
            label, _, remainder = raw_line.partition(":")
            value = remainder.strip()
            if not value.isdigit():
                continue
            if label == "read_bytes":
                read_bytes += int(value)
            elif label == "write_bytes":
                write_bytes += int(value)
    return (read_bytes, write_bytes)


def read_disk_totals(proc_root: Path = PROC_ROOT) -> tuple[int, int]:
    """Read cumulative bytes read and written across whole block devices.

    Partitions, loop, ram and device-mapper entries are skipped so the totals
    count each physical transfer once.

    Args:
        proc_root: Mount point of the proc filesystem.

    Returns:
        Cumulative bytes read and written since boot.
    """
    entries: list[tuple[str, int, int]] = []
    for raw_line in _read_proc_text("diskstats", proc_root).splitlines():
        fields = raw_line.split()
        if len(fields) < DISKSTATS_MIN_FIELDS:
            continue
        name = fields[DISKSTATS_NAME_INDEX]
        if name.startswith(DISK_EXCLUDED_PREFIXES):
            continue
        sectors_read = fields[DISKSTATS_SECTORS_READ_INDEX]
        sectors_written = fields[DISKSTATS_SECTORS_WRITTEN_INDEX]
        if not (sectors_read.isdigit() and sectors_written.isdigit()):
            continue
        entries.append((name, int(sectors_read), int(sectors_written)))
    if not entries:
        return read_process_io_totals(proc_root)
    device_names = {entry[0] for entry in entries}
    read_bytes = 0
    write_bytes = 0
    for name, sectors_read, sectors_written in entries:
        if _is_partition_of(name, device_names):
            continue
        read_bytes += sectors_read * DISK_SECTOR_BYTES
        write_bytes += sectors_written * DISK_SECTOR_BYTES
    return (read_bytes, write_bytes)


def read_net_totals(proc_root: Path = PROC_ROOT) -> tuple[int, int]:
    """Read cumulative bytes sent and received on non-loopback interfaces.

    Args:
        proc_root: Mount point of the proc filesystem.

    Returns:
        Cumulative bytes sent and bytes received since boot.
    """
    sent_bytes = 0
    received_bytes = 0
    for raw_line in _read_proc_text("net/dev", proc_root).splitlines():
        name, separator, remainder = raw_line.partition(":")
        if not separator:
            continue
        interface = name.strip()
        if not interface or interface in NET_EXCLUDED_INTERFACES:
            continue
        fields = remainder.split()
        if len(fields) < NET_DEV_MIN_FIELDS:
            continue
        received_field = fields[NET_DEV_RECV_BYTES_INDEX]
        sent_field = fields[NET_DEV_SENT_BYTES_INDEX]
        if not (received_field.isdigit() and sent_field.isdigit()):
            continue
        received_bytes += int(received_field)
        sent_bytes += int(sent_field)
    return (sent_bytes, received_bytes)


def read_resource_counters(proc_root: Path = PROC_ROOT) -> tuple[int, int, int, int, int, int]:
    """Read every cumulative counter a resource sample is derived from.

    Args:
        proc_root: Mount point of the proc filesystem.

    Returns:
        Total CPU ticks, idle CPU ticks, disk bytes read, disk bytes written,
        network bytes sent and network bytes received.
    """
    cpu_total, cpu_idle = read_cpu_totals(proc_root)
    disk_read, disk_write = read_disk_totals(proc_root)
    net_sent, net_received = read_net_totals(proc_root)
    return (cpu_total, cpu_idle, disk_read, disk_write, net_sent, net_received)


def cpu_percent_between(previous: tuple[int, int], current: tuple[int, int]) -> float:
    """Compute busy CPU percentage between two CPU time readings.

    Args:
        previous: Total and idle CPU ticks from the earlier reading.
        current: Total and idle CPU ticks from the later reading.

    Returns:
        Percentage of the elapsed CPU time that was not idle.
    """
    total_delta = current[0] - previous[0]
    idle_delta = current[1] - previous[1]
    if total_delta <= 0:
        return 0.0
    busy_delta = total_delta - idle_delta
    if busy_delta < 0:
        busy_delta = 0
    return round(busy_delta * 100.0 / total_delta, 2)


def _counter_rate(previous: int, current: int, elapsed: float) -> int:
    """Convert a pair of cumulative counter readings into a per-second rate.

    Args:
        previous: Counter value from the earlier reading.
        current: Counter value from the later reading.
        elapsed: Seconds between the two readings.

    Returns:
        Bytes per second, or zero when the counter did not advance.
    """
    if elapsed <= 0.0:
        return 0
    delta = current - previous
    if delta < 0:
        return 0
    return int(delta / elapsed)


def format_resource_sample(
    timestamp: str,
    previous: tuple[int, int, int, int, int, int],
    current: tuple[int, int, int, int, int, int],
    elapsed: float,
    memory_mb: float,
) -> str:
    """Render one resource sample in the seven-field resource log schema.

    Args:
        timestamp: Sample timestamp.
        previous: Counters from the earlier reading.
        current: Counters from the later reading.
        elapsed: Seconds between the two readings.
        memory_mb: Physical memory in use at the later reading.

    Returns:
        Pipe-delimited record ready to append to the resource monitor log.
    """
    return "|".join([
        _log_field(timestamp),
        str(cpu_percent_between((previous[0], previous[1]), (current[0], current[1]))),
        str(memory_mb),
        str(_counter_rate(previous[2], current[2], elapsed)),
        str(_counter_rate(previous[3], current[3], elapsed)),
        str(_counter_rate(previous[4], current[4], elapsed)),
        str(_counter_rate(previous[5], current[5], elapsed)),
    ])


def resource_monitor(proc_root: Path = PROC_ROOT) -> None:
    """Sample CPU, memory, disk and network usage and log real deltas.

    Args:
        proc_root: Mount point of the proc filesystem.
    """
    previous = read_resource_counters(proc_root)
    previous_at = time.monotonic()
    _logger.info("resource_monitoring_started", extra={"sample_interval": RESOURCE_SAMPLE_INTERVAL})
    while True:
        time.sleep(RESOURCE_SAMPLE_INTERVAL)
        current = read_resource_counters(proc_root)
        sampled_at = time.monotonic()
        record = format_resource_sample(
            time.strftime("%Y-%m-%d %H:%M:%S"),
            previous,
            current,
            sampled_at - previous_at,
            read_memory_used_mb(proc_root),
        )
        _append_log(RESOURCE_LOG_NAME, record)
        previous = current
        previous_at = sampled_at


def handle_client(conn: socket.socket) -> None:
    """Handle a client connection from the host.

    Receives JSON commands and executes them, returning results.

    Args:
        conn: Connected client socket.
    """
    client_addr = "unknown"
    try:
        client_addr = str(conn.getpeername())
    except OSError:
        _logger.debug("client_peername_unavailable", exc_info=True)

    _logger.debug("client_connected", extra={"client_addr": client_addr})

    try:
        while True:
            data = conn.recv(RECV_BUFFER_SIZE)
            if not data:
                break

            try:
                request: dict[str, Any] = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as parse_err:
                _logger.warning("invalid_client_request", extra={"client_addr": client_addr, "error": str(parse_err)})
                continue

            if request.get("type") == "ping":
                pong_bytes = (json.dumps({"type": "pong", "data": {}}) + "\\n").encode("utf-8")
                conn.send(pong_bytes)
            elif request.get("type") == "execute":
                response = _execute_command(request)
                response_bytes = (json.dumps(response) + "\\n").encode("utf-8")
                conn.send(response_bytes)

    except ConnectionResetError:
        _logger.debug("client_disconnected", extra={"client_addr": client_addr})
    except OSError as sock_err:
        _logger.debug("client_socket_error", extra={"client_addr": client_addr, "error": str(sock_err)})
    finally:
        try:
            conn.close()
        except OSError:
            _logger.debug("client_close_failed", exc_info=True)
        _logger.debug("client_connection_closed", extra={"client_addr": client_addr})


def _execute_command(request: dict[str, Any]) -> dict[str, Any]:
    """Execute a command from a client request.

    Args:
        request: JSON request with 'command', 'args', and optional 'timeout'.

    Returns:
        Response dict with 'type' and 'data' containing execution results.
    """
    cmd = request.get("command", "")
    args: list[str] = request.get("args", [])
    timeout = request.get("timeout", DEFAULT_COMMAND_TIMEOUT)

    if not cmd:
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": "No command specified"},
        }

    try:
        result = subprocess.run(
            [cmd] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "type": "result",
            "data": {
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        }
    except subprocess.TimeoutExpired:
        _logger.debug("command_execution_timeout", extra={"command": cmd, "timeout": timeout})
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": f"Command timed out after {timeout}s"},
        }
    except FileNotFoundError:
        _logger.debug("command_not_found", extra={"command": cmd})
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": f"Command not found: {cmd}"},
        }
    except PermissionError:
        _logger.debug("command_permission_denied", extra={"command": cmd})
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": f"Permission denied: {cmd}"},
        }
    except OSError as os_err:
        _logger.debug("command_os_error", extra={"command": cmd, "error": str(os_err)})
        return {
            "type": "result",
            "data": {"exit_code": -1, "stdout": "", "stderr": str(os_err)},
        }


def main() -> None:
    """Main entry point for the guest agent."""
    _logger.info("guest_agent_starting", extra={"port": PORT})

    process_thread = threading.Thread(target=process_monitor, daemon=True)
    process_thread.start()

    file_thread = threading.Thread(target=file_monitor, daemon=True)
    file_thread.start()

    network_thread = threading.Thread(target=network_monitor, daemon=True)
    network_thread.start()

    resource_thread = threading.Thread(target=resource_monitor, daemon=True)
    resource_thread.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", PORT))
        server.listen(5)
        _logger.info("agent_listening", extra={"host": "0.0.0.0", "port": PORT})

        while True:
            try:
                conn, addr = server.accept()
                client_thread = threading.Thread(
                    target=handle_client, args=(conn,), daemon=True
                )
                client_thread.start()
            except OSError as accept_err:
                _logger.error("accept_failed", extra={"error": str(accept_err)})
                break
    except OSError as bind_err:
        _logger.error("port_bind_failed", extra={"port": PORT, "error": str(bind_err)})
    finally:
        server.close()


if __name__ == "__main__":
    main()
'''
            await asyncio.to_thread(agent_script.write_text, agent_content, encoding="utf-8", newline="")

            startup_script = monitor_dir / "start_agent.sh"
            agent_path = f"{_GUEST_SHARED_ROOT_LINUX}/{_MONITOR_AGENT_RELATIVE_LINUX}"
            log_dir = f"{_GUEST_WORK_ROOT_LINUX}/{_GUEST_AGENT_LOG_DIR_RELATIVE}"
            # ``exec`` rather than a background job, and a redirect rather than a
            # discarded stream: backgrounding made the shell exit 0 whatever
            # became of the agent, so the pid qemu-guest-agent reported belonged
            # to a shell that had already succeeded and the agent's own failure
            # went nowhere. Now the reported pid is the agent, and whatever it
            # said on its way out is on the guest's disk.
            startup_content = (
                f"#!/bin/bash\nmkdir -p '{log_dir}'\nexec python3 '{agent_path}' >>'{log_dir}/{_GUEST_BOOTSTRAP_LOG_NAME}' 2>&1\n"
            )
        else:
            raise ValueError(_ERR_UNSUPPORTED_GUEST_OS)

        # Verbatim, because the host writing these is a Windows one and text
        # mode would otherwise turn every "\n" into "\r\n". Each launcher above
        # already carries the terminators its own interpreter needs, and a
        # shell script full of carriage returns is one bash refuses to run.
        await asyncio.to_thread(startup_script.write_text, startup_content, encoding="utf-8", newline="")

        _logger.debug("guest_agent_scripts_created", path=str(monitor_dir))

    async def run_command(
        self,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Execute a shell command line in the sandbox.

        ``command`` is a command line for the guest's own shell: it may carry
        redirections, ``&&`` and quoted paths, and a working directory is
        applied by prefixing that interpreter's own ``cd``, quoted for it and
        carrying whatever switch it needs to cross volumes (see
        :meth:`_guest_change_directory_command`). The in-guest agent launches an
        executable directly rather than through a shell, so the whole line is
        handed to the guest's command interpreter instead of being sent as if
        it were the name of a program.

        The agent captures that child's two streams separately and verbatim, so
        the triple returned here carries the bytes the command really wrote on
        each of them rather than a rendering of them.

        Args:
            command: Command line to execute.
            time_limit: Optional timeout override in seconds.
            working_directory: Optional working directory.

        Returns:
            tuple[int, str, str]: Tuple of (exit_code, stdout, stderr).

        Raises:
            SandboxError: If execution fails.
        """
        _logger.info("qemu_run_command_started", command=command, time_limit=time_limit, working_directory=working_directory)
        if self.state.status != "running":
            raise SandboxError(_ERR_NOT_RUNNING)

        termination = self.qemu_termination()
        if termination is not None:
            _logger.warning("qemu_stopped_before_command", returncode=termination.returncode)
            raise SandboxError(_ERR_QEMU_PROCESS_GONE.format(detail=termination.describe()))

        effective_timeout = time_limit or self._config.timeout_seconds

        shell, shell_args = self._guest_shell_invocation(command, working_directory)
        if self._agent is not None and self._agent.is_connected:
            return await self._agent.send_command(shell, shell_args, time_limit=effective_timeout)

        if self._uses_fat_shared_transport():
            # The share is a read-only vvfat volume on this transport, so the
            # guest cannot publish a result file onto it and the host cannot
            # make a newly written script appear inside a running guest. The
            # command goes over the guest agent instead, which is the only
            # channel that reaches a live guest at all.
            status = await self._guest_run(shell, shell_args, time_limit=effective_timeout)
            return (self._guest_exit_code(status, command), status.stdout, status.stderr)

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        script_id = secrets.token_hex(8)
        result_name = f"result_{script_id}.txt"
        stdout_name = f"{script_id}.stdout"
        stderr_name = f"{script_id}.stderr"
        script_name, script_content = self._generate_execution_script(
            command=command,
            working_directory=working_directory,
            script_id=script_id,
            result_name=result_name,
            stdout_name=stdout_name,
            stderr_name=stderr_name,
        )

        script_path = self._shared_folder / "input" / script_name
        result_path = self._shared_folder / "output" / result_name
        stdout_path = self._shared_folder / "output" / stdout_name
        stderr_path = self._shared_folder / "output" / stderr_name
        await asyncio.to_thread(script_path.write_text, script_content, encoding="utf-8")

        return await self._poll_for_result(
            result_path=result_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            script_path=script_path,
            time_limit=effective_timeout,
            vm_terminated=self.qemu_termination,
        )

    def _guest_change_directory_command(self, working_directory: str) -> str:
        r"""Build the guest command that enters ``working_directory``.

        The quoting rules belong to the interpreter
        :meth:`_guest_shell_invocation` selects, so both are decided by the one
        guest-OS predicate. ``cmd.exe`` needs ``/d``: without it a directory on
        a volume other than the shell's current one only changes that volume's
        remembered directory and leaves the shell where it was, so everything
        after the ``cd`` runs somewhere else while the ``cd`` still reports
        success. Both interpreters need the path held together as one token -
        ``cmd.exe`` accepts no quote inside a path because Windows forbids one
        there, and ``/bin/bash`` gets the shell's own quoting from
        :func:`shlex.quote` rather than a hand-rolled escape it would then
        reinterpret.

        Args:
            working_directory: In-guest directory the command is to enter.

        Returns:
            str: Command line entering ``working_directory`` in the guest's own
            interpreter.
        """
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            return f'cd /d "{working_directory}"'
        return f"cd {shlex.quote(working_directory)}"

    def _guest_shell_invocation(
        self,
        command_line: str,
        working_directory: str | None = None,
    ) -> tuple[str, list[str]]:
        """Wrap a shell command line in the guest's own command interpreter.

        A working directory is applied by prefixing the interpreter's own
        ``cd`` (see :meth:`_guest_change_directory_command`), so the directory
        is quoted for whichever interpreter is about to read it.

        Args:
            command_line: Command line the guest's shell is to interpret.
            working_directory: Optional in-guest directory to run it from.

        Returns:
            tuple[str, list[str]]: Executable and argument vector that run
            ``command_line`` through the guest's shell.
        """
        if working_directory:
            command_line = f"{self._guest_change_directory_command(working_directory)} && {command_line}"
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            return (_WINDOWS_SHELL, [_WINDOWS_SHELL_COMMAND_FLAG, command_line])
        return (_LINUX_SHELL, [_LINUX_SHELL_COMMAND_FLAG, command_line])

    async def _run_guest_program(
        self,
        executable: str,
        args: Sequence[str],
        time_limit: int,
    ) -> tuple[int, str, str]:
        r"""Run one in-guest program addressed by its own path.

        The in-guest agent validates the executable it is handed against its
        allowlist and then launches it directly, so the path travels unquoted
        in the request's ``command`` field with the arguments in ``args``: a
        path carrying spaces stays a single token that way, without quotes the
        allowlist check would first have to undo. Only the shared-folder
        fallback, where a generated script is interpreted by the guest's shell,
        needs the invocation flattened into a command line - and there the
        quotes are what hold such a path together.

        Propagates the ``SandboxError`` raised by :meth:`run_command` when that
        fallback cannot dispatch the invocation at all.

        Args:
            executable: Absolute in-guest path of the program to run.
            args: Argument list passed to the program.
            time_limit: Execution timeout in seconds.

        Returns:
            tuple[int, str, str]: Tuple of (exit_code, stdout, stderr).
        """
        if self._agent is not None and self._agent.is_connected:
            return await self._agent.send_command(executable, args, time_limit=time_limit)

        command_line = " ".join(f'"{token}"' for token in [executable, *args])
        return await self.run_command(command_line, time_limit=time_limit)

    def _generate_execution_script(
        self,
        *,
        command: str,
        working_directory: str | None,
        script_id: str,
        result_name: str,
        stdout_name: str,
        stderr_name: str,
    ) -> tuple[str, str]:
        """Generate an OS-specific execution script for the sandbox guest.

        The generated script redirects the command's standard output to a
        ``stdout_name`` sidecar file and standard error to a ``stderr_name``
        sidecar file (both under the guest's shared ``output`` folder), then
        writes the command's exit code to ``result_name``. The exit-code file
        is the polling sentinel and is written last so the host only observes
        the result after both sidecar files have been fully flushed.

        Args:
            command: Command to execute in the guest.
            working_directory: Optional working directory for the command.
            script_id: Unique identifier for the script file.
            result_name: Name of the result file containing the exit code.
            stdout_name: Name of the sidecar file capturing stdout.
            stderr_name: Name of the sidecar file capturing stderr.

        Returns:
            tuple[str, str]: Tuple of (script_filename, script_content).

        Raises:
            ValueError: If an unsupported guest OS is configured.
        """
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            script_name = f"exec_{script_id}.cmd"
            guest_root = self._guest_shared_root_for(GuestOS.WINDOWS)
            stdout_guest_path = f"{guest_root}output\\{stdout_name}"
            stderr_guest_path = f"{guest_root}output\\{stderr_name}"
            result_guest_path = f"{guest_root}output\\{result_name}"
            cd_line = self._guest_change_directory_command(working_directory) if working_directory else ""
            script_content = (
                "@echo off\r\n"
                f"{cd_line}\r\n"
                f'({command}) 1> "{stdout_guest_path}" 2> "{stderr_guest_path}"\r\n'
                f'echo %ERRORLEVEL% > "{result_guest_path}"\r\n'
            )
        elif self._qemu_config.guest_os == GuestOS.LINUX:
            script_name = f"exec_{script_id}.sh"
            guest_root = self._guest_shared_root_for(GuestOS.LINUX)
            stdout_guest_path = f"{guest_root}/output/{stdout_name}"
            stderr_guest_path = f"{guest_root}/output/{stderr_name}"
            result_guest_path = f"{guest_root}/output/{result_name}"
            cd_line = self._guest_change_directory_command(working_directory) if working_directory else ""
            script_content = (
                f'#!/bin/bash\n{cd_line}\n( {command} ) > "{stdout_guest_path}" 2> "{stderr_guest_path}"\necho $? > "{result_guest_path}"\n'
            )
        else:
            _logger.error(
                "execution_script_unsupported_guest_os",
                guest_os=str(self._qemu_config.guest_os),
                script_id=script_id,
            )
            raise ValueError(_ERR_UNSUPPORTED_GUEST_OS)
        return script_name, script_content

    @staticmethod
    async def _poll_for_result(
        *,
        result_path: Path,
        time_limit: int,
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
        script_path: Path | None = None,
        vm_terminated: Callable[[], QemuTermination | None] | None = None,
    ) -> tuple[int, str, str]:
        """Poll the shared folder for command execution results.

        Waits for ``result_path`` to appear, then reads the exit code and
        the contents of the optional ``stdout_path`` / ``stderr_path`` sidecar
        files written by the guest execution script. Sidecar files and the
        result/script files are removed after successful read so the shared
        folder does not accumulate per-invocation artefacts.

        Args:
            result_path: Path to the expected result file containing the
                exit code.
            time_limit: Maximum time in seconds to wait.
            stdout_path: Optional path to the stdout sidecar file.
            stderr_path: Optional path to the stderr sidecar file.
            script_path: Optional path to the originating execution script,
                cleaned up alongside the result and sidecars.
            vm_terminated: Optional probe answering whether the virtual machine
                expected to write the result has stopped. A result can only
                arrive from a running guest, so once the machine is gone there
                is nothing left to wait for.

        Returns:
            tuple[int, str, str]: Tuple of (exit_code, stdout, stderr).

        Raises:
            SandboxError: If the virtual machine stopped before writing a result.
            SandboxTimeoutError: If the command times out.
        """
        start_time = time.time()
        while time.time() - start_time < time_limit:
            await asyncio.sleep(1)
            if await asyncio.to_thread(result_path.exists):
                try:
                    result_text = await asyncio.to_thread(
                        result_path.read_text,
                        encoding="utf-8",
                    )
                    result_text = result_text.strip()
                    exit_code = int(result_text) if result_text.isdigit() else -1
                except (OSError, ValueError) as e:
                    _logger.warning("result_read_failed", error=str(e))
                    continue
                stdout_text = await QEMUSandbox._read_sidecar(stdout_path)
                stderr_text = await QEMUSandbox._read_sidecar(stderr_path)
                await QEMUSandbox._cleanup_result_artifacts(
                    result_path=result_path,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    script_path=script_path,
                )
                return (exit_code, stdout_text, stderr_text)

            if vm_terminated is not None:
                termination = vm_terminated()
                if termination is not None:
                    _logger.warning(
                        "qemu_stopped_while_awaiting_result",
                        returncode=termination.returncode,
                        output_tail=list(termination.output_tail),
                    )
                    raise SandboxError(_ERR_QEMU_PROCESS_GONE.format(detail=termination.describe()))

        _logger.warning("command_timed_out", timeout_seconds=time_limit)
        raise SandboxTimeoutError(_ERR_CMD_TIMEOUT, timeout_seconds=time_limit)

    @staticmethod
    async def _read_sidecar(path: Path | None) -> str:
        """Read a guest-written sidecar file, returning empty string if missing.

        Args:
            path: Optional sidecar file path. ``None`` returns an empty string.

        Returns:
            str: The decoded text contents of the file, or an empty string
            when the file does not exist or cannot be decoded.
        """
        if path is None:
            return ""
        if not await asyncio.to_thread(path.exists):
            return ""
        try:
            return await asyncio.to_thread(path.read_text, encoding="utf-8", errors="replace")
        except OSError as exc:
            _logger.warning("sidecar_read_failed", path=str(path), error=str(exc))
            return ""

    @staticmethod
    async def _cleanup_result_artifacts(
        *,
        result_path: Path,
        stdout_path: Path | None,
        stderr_path: Path | None,
        script_path: Path | None,
    ) -> None:
        """Remove per-invocation script/result/sidecar files.

        Errors are logged at debug level and otherwise suppressed because
        the shared folder may be on a FAT image that occasionally rejects
        deletes while the guest still holds a handle. The next invocation
        uses a fresh ``script_id`` so leftover files never cause name
        collisions.

        Args:
            result_path: Result file containing the exit code.
            stdout_path: Optional stdout sidecar file.
            stderr_path: Optional stderr sidecar file.
            script_path: Optional script file produced by the host.
        """
        candidates: tuple[Path | None, ...] = (
            result_path,
            stdout_path,
            stderr_path,
            script_path,
        )
        for candidate in candidates:
            if candidate is None:
                continue
            try:
                await asyncio.to_thread(candidate.unlink, missing_ok=True)
            except OSError as exc:
                _logger.warning(
                    "result_artifact_cleanup_failed",
                    path=str(candidate),
                    error=str(exc),
                )

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        time_limit: int | None = None,
        companions: Sequence[Path] | None = None,
        *,
        monitor: bool = True,
    ) -> ExecutionReport:
        """Run a binary in the sandbox with monitoring.

        Args:
            binary_path: Path to the binary to run.
            args: Optional command line arguments.
            time_limit: Optional timeout override in seconds.
            companions: Optional files or directories to place beside the
                binary, for a target that cannot run alone.
            monitor: Whether to monitor behavior.

        Returns:
            ExecutionReport: ExecutionReport with results and activity.

        Raises:
            SandboxError: If execution fails.
            ValueError: If the guest OS type is unsupported.
        """
        _logger.info("qemu_run_binary_started", binary=str(binary_path), arg_count=len(args) if args else 0, monitor=monitor)
        if self.state.status != "running":
            raise SandboxError(_ERR_NOT_RUNNING)

        if not await asyncio.to_thread(binary_path.exists):
            _logger.warning("binary_not_found", path=str(binary_path))
            raise SandboxError(_ERR_BINARY_NOT_FOUND)

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        effective_timeout = time_limit or self._config.timeout_seconds
        start_time = time.time()

        await self.copy_to_sandbox(binary_path, f"input/{binary_path.name}")
        if companions:
            await self.stage_companions(companions, binary_path, "input")

        if monitor:
            collected = self._collected_root()
            if collected is not None:
                logs_folder = collected / "logs"
                log_files = await asyncio.to_thread(lambda: list(logs_folder.glob("*.log")))
                for log_file in log_files:
                    await asyncio.to_thread(log_file.unlink)

        if self._qemu_config.guest_os in {GuestOS.WINDOWS, GuestOS.LINUX}:
            binary_sandbox_path = self._guest_work_path(f"input/{binary_path.name}")
        else:
            raise ValueError(_ERR_UNSUPPORTED_GUEST_OS)

        result: ExecutionResult
        try:
            exit_code, stdout, stderr = await self._run_guest_program(
                binary_sandbox_path,
                args or [],
                effective_timeout,
            )
            result = "success" if exit_code == 0 else "error"
        except SandboxTimeoutError as e:
            _logger.warning("sandbox_execution_timeout", binary=binary_path.name, timeout=effective_timeout)
            result = "timeout"
            stderr = str(e)
            stdout = ""
            exit_code = -1
        except SandboxError as e:
            _logger.warning("sandbox_execution_error", binary=binary_path.name, error=str(e))
            result = "error"
            stderr = str(e)
            stdout = ""
            exit_code = -1
        duration = time.time() - start_time

        logs = _MonitoringLogs()
        if monitor:
            await self._wait_for_logs_stable()
            await self._collect_guest_logs()
            logs = await self._collect_monitoring_logs()

        return ExecutionReport(
            result=result,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            file_changes=logs.file_changes,
            registry_changes=logs.registry_changes,
            network_activity=logs.network_activity,
            process_activity=logs.process_activity,
            api_calls=logs.api_calls,
            service_changes=logs.service_changes,
            kernel_objects=logs.kernel_objects,
            dll_loads=logs.dll_loads,
            injection_events=logs.injection_events,
            resource_samples=logs.resource_samples,
            clipboard_events=logs.clipboard_events,
            collector_outages=logs.collector_outages,
        )

    def _collected_root(self) -> Path | None:
        """Return the host directory the guest's own output is collected into.

        Deliberately not the shared folder. That directory backs a read-only
        vvfat volume the guest is still reading, and writing into a directory
        vvfat has already built its FAT over is how this whole class of failure
        started. The collected copies therefore live beside it instead.

        Returns:
            Path | None: The collection root, or ``None`` before the sandbox
            has anywhere on the host to put one.
        """
        if self._temp_dir is not None:
            return self._temp_dir / "collected"
        # The share is created inside the working directory, so its parent is
        # that directory. Deriving it this way means a sandbox holding a share
        # always has somewhere to collect into, in whichever order the two were
        # established.
        if self._shared_folder is not None:
            return self._shared_folder.parent / "collected"
        return None

    async def _collect_guest_logs(self) -> None:
        """Copy every monitor log out of the guest and onto the host.

        The guest writes its logs to its own disk (see
        :meth:`_guest_work_root_for`), so there is nothing on the share for the
        host to read and the files have to be fetched over the guest agent. A
        log that is simply absent - a collector that never ran, or a guest
        without the Windows-only ETW collectors - is not an error and leaves no
        file behind, which the parsers already treat as "no records".
        """
        collected = self._collected_root()
        if collected is None or self._qga is None or not self._qga.connected:
            return

        logs_dir = collected / "logs"
        await asyncio.to_thread(logs_dir.mkdir, parents=True, exist_ok=True)
        names = (*_MONITORING_LOG_NAMES, *_COLLECTOR_LIFECYCLE_LOG_NAMES)
        for name in names:
            guest_path = self._guest_work_path(f"logs/{name}")
            try:
                payload = await self._read_guest_file(guest_path)
            except SandboxError as error:
                # Absent logs are the normal case for collectors that a given
                # guest does not run, so this is reported at debug and the
                # parser is left to see no file at all.
                _logger.debug("guest_log_not_collected", name=name, guest_path=guest_path, error=str(error))
                continue
            await asyncio.to_thread((logs_dir / name).write_bytes, payload)
            _logger.debug("guest_log_collected", name=name, size_bytes=len(payload))

    async def _collect_monitoring_logs(self) -> _MonitoringLogs:
        """Parse every monitor log file into a :class:`_MonitoringLogs` aggregate.

        The logs are read from the host-side collection root rather than the
        share, because the guest writes them to its own disk and
        :meth:`_collect_guest_logs` is what brings them across.

        Returns:
            _MonitoringLogs: All monitor-log parse results collected from
            the guest's ``logs`` folder. Each field is populated from the
            corresponding parser in :mod:`intellicrack.sandbox.log_parsers`
            and defaults to an empty list when the matching log file is
            absent. ``collector_outages`` is only populated for a Windows
            guest, since only the Windows agent stages the ETW-based
            ``api_trace`` and ``injection_monitor`` collectors it reports on.
        """
        shared = self._collected_root()
        collector_outages: list[CollectorOutage] = []
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            for collector, lifecycle_log in (
                ("api_trace", "api_trace.lifecycle.log"),
                ("injection_monitor", "injection_monitor.lifecycle.log"),
            ):
                outage = await parse_collector_lifecycle(shared, collector, lifecycle_log)
                if outage is not None:
                    collector_outages.append(outage)
        return _MonitoringLogs(
            file_changes=await parse_file_log(shared, "file_changes.log"),
            registry_changes=await parse_registry_log(shared, "registry_monitor.log"),
            network_activity=await parse_network_log(shared, "network_activity.log"),
            process_activity=await parse_process_log(shared, "process_activity.log"),
            api_calls=await parse_api_trace_log(shared, "api_trace.log"),
            service_changes=await parse_service_log(shared, "service_monitor.log"),
            kernel_objects=await parse_kernel_object_log(shared, "kernel_object_monitor.log"),
            dll_loads=await parse_dll_log(shared, "dll_monitor.log"),
            injection_events=await parse_injection_log(shared, "injection_monitor.log"),
            collector_outages=collector_outages,
            resource_samples=await parse_resource_log(shared, "resource_monitor.log"),
            clipboard_events=await parse_clipboard_log(shared, "clipboard_monitor.log"),
        )

    async def _wait_for_logs_stable(
        self,
        *,
        poll_delay: float = _LOGS_STABLE_POLL_DELAY_S,
        stable_polls: int = _LOGS_STABLE_REQUIRED_POLLS,
        max_wait: float = _LOGS_STABLE_MAX_WAIT_S,
    ) -> None:
        """Wait until all monitoring log files have stopped growing.

        Polls every log in :data:`_MONITORING_LOG_NAMES` through
        :meth:`_current_log_sizes` - which reads the guest's own disk on the
        FAT transport and the host side of the share otherwise - and treats the
        set as stable when each file's size has been unchanged for
        ``stable_polls`` consecutive polls. Caps total wait at ``max_wait``
        seconds. Files that do not yet exist are treated as having size ``0``
        so that long-quiescent monitors do not block the readiness check.

        Host-side ``stat`` calls are dispatched via :func:`asyncio.to_thread`
        so the event loop is not blocked. Elapsed time is measured with
        :func:`time.monotonic`.

        Args:
            poll_delay: Seconds to sleep between polls. Must be positive.
            stable_polls: Number of consecutive unchanged polls required to
                consider a log file stable. Must be at least one.
            max_wait: Maximum total seconds to wait before returning even if
                stability has not been reached.

        Raises:
            ValueError: If ``poll_delay`` is not positive, ``stable_polls``
                is less than one, or ``max_wait`` is negative.
            SandboxError: If the shared folder has not been initialized.
        """
        if poll_delay <= 0:
            _logger.warning("wait_for_logs_stable_invalid_poll_delay", poll_delay=poll_delay)
            raise ValueError(_ERR_LOGS_STABLE_POLL_DELAY)
        if stable_polls < 1:
            _logger.warning("wait_for_logs_stable_invalid_stable_polls", stable_polls=stable_polls)
            raise ValueError(_ERR_LOGS_STABLE_STABLE_POLLS)
        if max_wait < 0:
            _logger.warning("wait_for_logs_stable_invalid_max_wait", max_wait=max_wait)
            raise ValueError(_ERR_LOGS_STABLE_MAX_WAIT)
        if self._shared_folder is None:
            _logger.warning("wait_for_logs_stable_no_shared_folder")
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        previous_sizes: dict[str, int] = dict.fromkeys(_MONITORING_LOG_NAMES, -1)
        unchanged_counts: dict[str, int] = dict.fromkeys(_MONITORING_LOG_NAMES, 0)

        start = time.monotonic()
        while True:
            sizes = await self._current_log_sizes()
            for name in _MONITORING_LOG_NAMES:
                current_size = sizes.get(name, 0)
                if current_size == previous_sizes[name]:
                    unchanged_counts[name] += 1
                else:
                    unchanged_counts[name] = 1
                    previous_sizes[name] = current_size

            if all(count >= stable_polls for count in unchanged_counts.values()):
                _logger.debug(
                    "logs_stable_reached",
                    elapsed_seconds=time.monotonic() - start,
                    stable_polls=stable_polls,
                )
                return

            if time.monotonic() - start >= max_wait:
                _logger.warning(
                    "logs_stable_max_wait_elapsed",
                    max_wait_seconds=max_wait,
                    stable_polls=stable_polls,
                )
                return

            await asyncio.sleep(poll_delay)

    @staticmethod
    def _stat_log_size(path: Path) -> int:
        """Return a log file's size, treating an absent file as empty.

        Args:
            path: File whose size to read.

        Returns:
            int: File size in bytes, or ``0`` if the file does not exist.
        """
        try:
            return path.stat().st_size
        except FileNotFoundError:
            _logger.warning("logs_stable_stat_missing", path=str(path))
            return 0

    async def _guest_log_sizes(self) -> dict[str, int]:
        """Read the size of every log the guest is currently writing.

        Returns:
            dict[str, int]: Log file name to size in bytes. A guest that has
            produced no logs yet, or that cannot be asked, contributes nothing
            and is therefore seen as unchanged.
        """
        logs_dir = self._guest_work_path("logs")
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            # ``%~nxI`` is the name with extension and ``%~zI`` the size. They
            # are separated by a space rather than a pipe because cmd.exe would
            # read a pipe here as a redirection before ``for`` ever ran.
            command = f'for %I in ("{logs_dir}\\*.log") do @echo %~nxI %~zI'
        else:
            command = f'find "{logs_dir}" -maxdepth 1 -type f -name "*.log" -printf "%f %s\\n"'
        try:
            exit_code, stdout, _ = await self.run_command(command, time_limit=_LOG_SIZE_PROBE_TIMEOUT)
        except SandboxError as error:
            _logger.debug("guest_log_sizes_unavailable", error=str(error))
            return {}
        if exit_code != 0:
            return {}

        sizes: dict[str, int] = {}
        for line in stdout.splitlines():
            name, separator, raw = line.strip().rpartition(" ")
            if not separator or not raw.isdigit():
                continue
            sizes[name] = int(raw)
        return sizes

    async def _current_log_sizes(self) -> dict[str, int]:
        """Read the current size of every monitor log, wherever it is written.

        On the FAT transport the guest writes to its own disk and the host side
        of the share never changes, so a size read there would report every log
        as instantly stable. The guest is asked directly instead.

        Returns:
            dict[str, int]: Log file name to size in bytes, zero for a log that
            does not exist yet.
        """
        if self._uses_fat_shared_transport():
            guest_sizes = await self._guest_log_sizes()
            return {name: guest_sizes.get(name, 0) for name in _MONITORING_LOG_NAMES}

        folder = self._shared_folder
        if folder is None:
            return dict.fromkeys(_MONITORING_LOG_NAMES, 0)
        logs_folder = folder / "logs"
        return {name: await asyncio.to_thread(self._stat_log_size, logs_folder / name) for name in _MONITORING_LOG_NAMES}

    async def copy_to_sandbox(self, source: Path, dest: str) -> None:
        """Copy a file into the sandbox.

        Once a FAT-transport guest is running, the file goes only into that
        guest's work root over the guest agent. vvfat fixed its view of the
        share when QEMU started, so a host write there would be invisible to
        the guest, and it would be mutating a directory vvfat is actively
        mapping. A guest agent that is not connected therefore fails the copy
        rather than leaving the caller with a file the guest cannot see.

        Args:
            source: Local source path.
            dest: Destination path relative to shared folder.

        Raises:
            SandboxError: If copy fails.
        """
        _logger.info("qemu_copy_to_sandbox_started", source=str(source), dest=dest)
        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        if not await asyncio.to_thread(source.exists):
            _logger.warning("source_file_not_found", path=str(source))
            raise SandboxError(_ERR_SOURCE_NOT_FOUND)

        if self._uses_fat_shared_transport() and self.state.status == "running":
            if self._qga is None or not self._qga.connected:
                raise SandboxError(_ERR_QEMU_GA_NOT_CONNECTED)
            await self._stage_file_in_guest(source, dest)
            return

        dest_path = self._shared_folder / dest
        await asyncio.to_thread(dest_path.parent.mkdir, parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source, dest_path)
            _logger.debug("file_copied_to_sandbox", source=str(source), dest=dest)
        except OSError as e:
            _logger.warning("copy_to_sandbox_failed", error=str(e), source=str(source), dest=dest)
            raise SandboxError(_ERR_COPY_TO_SANDBOX) from e

        await self._stage_file_in_guest(source, dest)

    async def _open_guest_file(self, path: str) -> int:
        """Open a guest file for writing through qemu-guest-agent.

        Args:
            path: Absolute in-guest path to create or truncate.

        Returns:
            int: The agent's handle for the opened file.

        Raises:
            SandboxError: If the agent refuses the open or returns no handle.
        """
        if self._qga is None:
            raise SandboxError(_ERR_QEMU_GA_NOT_CONNECTED)
        reply = await self._qga.execute_command(
            {"execute": "guest-file-open", "arguments": {"path": path, "mode": "wb"}},
            _QGA_FILE_COMMAND_TIMEOUT,
        )
        if not reply.success:
            raise SandboxError(_ERR_GUEST_FILE_OPEN_FAILED.format(path=path, error=reply.error or "unknown error"))
        # QMPResponse.data carries the reply's "return" member itself, which
        # for guest-file-open is the bare handle rather than an object.
        handle: object = reply.data
        if not isinstance(handle, int):
            raise SandboxError(_ERR_GUEST_FILE_NO_HANDLE.format(path=path))
        return handle

    async def _write_guest_file_chunk(self, handle: int, chunk: bytes, path: str) -> None:
        """Write one buffer to an open guest file through qemu-guest-agent.

        Args:
            handle: Agent handle returned by :meth:`_open_guest_file`.
            chunk: Raw bytes to append.
            path: In-guest path, used only for failure messages.

        Raises:
            SandboxError: If the agent refuses the write or accepts less than
                the whole buffer.
        """
        if self._qga is None:
            raise SandboxError(_ERR_QEMU_GA_NOT_CONNECTED)
        reply = await self._qga.execute_command(
            {
                "execute": "guest-file-write",
                "arguments": {"handle": handle, "buf-b64": base64.b64encode(chunk).decode("ascii")},
            },
            _QGA_FILE_COMMAND_TIMEOUT,
        )
        if not reply.success:
            raise SandboxError(_ERR_GUEST_FILE_WRITE_FAILED.format(path=path, error=reply.error or "unknown error"))
        payload = _as_mapping(reply.data)
        written = payload.get("count") if payload is not None else None
        if isinstance(written, int) and written != len(chunk):
            raise SandboxError(_ERR_GUEST_FILE_SHORT_WRITE.format(written=written, expected=len(chunk), path=path))

    async def _open_guest_file_for_read(self, path: str) -> int:
        """Open a guest file for reading through qemu-guest-agent.

        Args:
            path: Absolute in-guest path to open.

        Returns:
            int: The agent's handle for the opened file.

        Raises:
            SandboxError: If the agent refuses the open or returns no handle.
        """
        if self._qga is None:
            raise SandboxError(_ERR_QEMU_GA_NOT_CONNECTED)
        reply = await self._qga.execute_command(
            {"execute": "guest-file-open", "arguments": {"path": path, "mode": "rb"}},
            _QGA_FILE_COMMAND_TIMEOUT,
        )
        if not reply.success:
            raise SandboxError(_ERR_GUEST_FILE_READ_OPEN_FAILED.format(path=path, error=reply.error or "unknown error"))
        handle: object = reply.data
        if not isinstance(handle, int):
            raise SandboxError(_ERR_GUEST_FILE_NO_HANDLE.format(path=path))
        return handle

    async def _read_guest_file_chunk(self, handle: int, path: str) -> tuple[bytes, bool]:
        """Read one buffer from an open guest file through qemu-guest-agent.

        Args:
            handle: Agent handle returned by :meth:`_open_guest_file_for_read`.
            path: In-guest path, used only for failure messages.

        Returns:
            tuple[bytes, bool]: The bytes read and whether the file ended. An
            empty buffer with ``False`` cannot occur: the agent reports the end
            of the file explicitly, so a short read is not mistaken for one.

        Raises:
            SandboxError: If the agent refuses the read or answers with
                something other than the documented ``buf-b64``/``eof`` pair.
        """
        if self._qga is None:
            raise SandboxError(_ERR_QEMU_GA_NOT_CONNECTED)
        reply = await self._qga.execute_command(
            {"execute": "guest-file-read", "arguments": {"handle": handle, "count": _QGA_FILE_READ_CHUNK}},
            _QGA_FILE_COMMAND_TIMEOUT,
        )
        if not reply.success:
            raise SandboxError(_ERR_GUEST_FILE_READ_FAILED.format(path=path, error=reply.error or "unknown error"))
        payload = _as_mapping(reply.data)
        if payload is None:
            raise SandboxError(_ERR_GUEST_FILE_READ_MALFORMED.format(path=path))
        encoded = payload.get("buf-b64")
        eof = payload.get("eof")
        if not isinstance(eof, bool) or not isinstance(encoded, str):
            raise SandboxError(_ERR_GUEST_FILE_READ_MALFORMED.format(path=path))
        try:
            chunk = base64.b64decode(encoded, validate=True)
        except binascii.Error as error:
            raise SandboxError(_ERR_GUEST_FILE_READ_MALFORMED.format(path=path)) from error
        return (chunk, eof)

    async def _read_guest_file(self, guest_path: str) -> bytes:
        """Read a whole guest file over qemu-guest-agent.

        This is the only way the host gets at what the guest produced. The
        share is read-only to the guest (see :meth:`_guest_work_root_for`), so
        a file the guest wrote exists on the guest's own disk and nowhere the
        host can open directly.

        Args:
            guest_path: Absolute in-guest path to read.

        Returns:
            bytes: The file's contents.

        Raises:
            SandboxError: If the agent refuses the open or a read, or the file
                exceeds :data:`_QGA_FILE_READ_LIMIT`.
        """
        handle = await self._open_guest_file_for_read(guest_path)
        collected = bytearray()
        try:
            while True:
                chunk, eof = await self._read_guest_file_chunk(handle, guest_path)
                collected.extend(chunk)
                if len(collected) > _QGA_FILE_READ_LIMIT:
                    raise SandboxError(_ERR_GUEST_FILE_TOO_LARGE.format(path=guest_path, limit=_QGA_FILE_READ_LIMIT))
                if eof:
                    break
        finally:
            await self._close_guest_file(handle)
        return bytes(collected)

    async def _close_guest_file(self, handle: int) -> None:
        """Close a guest file handle, tolerating a channel that has gone away.

        Args:
            handle: Agent handle returned by :meth:`_open_guest_file`.
        """
        if self._qga is None:
            return
        reply = await self._qga.execute_command(
            {"execute": "guest-file-close", "arguments": {"handle": handle}},
            _QGA_FILE_COMMAND_TIMEOUT,
        )
        if not reply.success:
            _logger.warning("guest_file_close_failed", handle=handle, error=reply.error)

    async def _stage_file_in_guest(self, source: Path, dest: str) -> None:
        """Write a staged file into the running guest over qemu-guest-agent.

        The host-side copy alone is not enough once the VM is up. On Windows
        hosts the shared folder reaches the guest as a QEMU **vvfat** block
        device, and vvfat presents the directory as it was when QEMU started:
        anything the host writes afterwards never appears inside the guest, so
        a binary staged for a run is simply not there when the agent tries to
        execute it. Files staged *before* the VM boots are in that snapshot and
        need nothing further, which is why this is a no-op until the agent
        channel exists.

        The file lands under the guest's work root rather than on the share.
        The share is mounted read-only precisely so that vvfat's write-back
        path is never entered (see :meth:`_guest_work_root_for`), so the agent
        could not write there even if it wanted to. The in-guest allowlist
        accepts the work root for the same reason it accepts the share root, so
        a binary staged here is executable exactly as a pre-boot copy would be.

        A guest file that cannot be created or filled surfaces as the
        ``SandboxError`` raised by :meth:`_open_guest_file` or
        :meth:`_write_guest_file_chunk`, rather than as a run that later fails
        with a misleading "not found" from inside the guest.

        Args:
            source: Host file whose bytes are to be written.
            dest: Destination path relative to the work root.
        """
        if self._qga is None or not self._qga.connected:
            return

        guest_path = self._guest_work_path(dest)
        # The work root is on the guest's own disk and nothing creates it ahead
        # of this, so every parent in the destination is created first. That
        # includes the single-component case - unlike the share, whose top-level
        # subdirectories existed host-side before the guest booted.
        relative_parent = PurePosixPath(dest).parent
        if relative_parent.parts:
            await self._ensure_guest_directory(self._guest_work_path(str(relative_parent)))
        else:
            await self._ensure_guest_directory(self._guest_work_root_for(self._qemu_config.guest_os))

        payload = await asyncio.to_thread(source.read_bytes)
        handle = await self._open_guest_file(guest_path)
        try:
            for start in range(0, len(payload), _QGA_FILE_WRITE_CHUNK):
                await self._write_guest_file_chunk(handle, payload[start : start + _QGA_FILE_WRITE_CHUNK], guest_path)
        finally:
            await self._close_guest_file(handle)

        _logger.info("file_staged_in_guest", guest_path=guest_path, size_bytes=len(payload))

    def _guest_mkdir_command(self, guest_dir: str) -> tuple[str, list[str]]:
        """Build the guest-exec invocation that creates a directory tree.

        ``cmd.exe``'s ``mkdir`` creates every missing intermediate directory in
        one call on Windows, and ``mkdir -p`` does the same on Linux, so a
        single invocation is enough regardless of how many path components are
        missing.

        Args:
            guest_dir: Absolute in-guest path of the directory to create.

        Returns:
            tuple[str, list[str]]: Executable and argument list for the
            configured guest family.
        """
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            return "cmd.exe", ["/c", "mkdir", guest_dir]
        return "mkdir", ["-p", guest_dir]

    async def _ensure_guest_directory(self, guest_dir: str) -> None:
        """Create a directory, and any missing parents, inside the guest.

        The creation is best-effort: a directory that already exists makes the
        guest-side ``mkdir`` fail, which is not an error, and a directory that
        genuinely could not be created still surfaces through the
        :class:`SandboxError` :meth:`_open_guest_file` raises immediately
        afterward when the write that depends on it cannot proceed either.

        Args:
            guest_dir: Absolute in-guest path of the directory to create.
        """
        path, args = self._guest_mkdir_command(guest_dir)
        try:
            status = await self._guest_run(path, args)
        except SandboxError as e:
            _logger.debug("guest_directory_create_failed", guest_dir=guest_dir, error=str(e))
            return
        if status.exit_code != 0:
            _logger.debug(
                "guest_directory_create_nonzero_exit",
                guest_dir=guest_dir,
                exit_code=status.exit_code,
                stderr=status.stderr.strip(),
            )

    async def copy_from_sandbox(self, source: str, dest: Path) -> None:
        """Copy a file out of the sandbox.

        Where the guest can write to the share the file is read from the host
        side of it directly. A running FAT-transport guest cannot: the share is
        a read-only vvfat volume (see :meth:`_guest_work_root_for`), so
        anything it produced lives under its work root on its own disk and is
        fetched over the guest agent instead. A path the caller gave relative
        to the share resolves against the work root, which is where the same
        ``input/``, ``output/`` and ``logs/`` tree now lives. With no guest
        running there is nothing to ask, and the host side of the share is
        read as before.

        Args:
            source: Source path relative to the shared folder.
            dest: Local destination path.

        Raises:
            SandboxError: If copy fails.
        """
        _logger.info("qemu_copy_from_sandbox_started", source=source, dest=str(dest))
        if self._uses_fat_shared_transport() and self.state.status == "running":
            payload = await self._read_guest_file(self._guest_work_path(source))
            await asyncio.to_thread(dest.parent.mkdir, parents=True, exist_ok=True)
            try:
                await asyncio.to_thread(dest.write_bytes, payload)
            except OSError as e:
                _logger.warning("copy_from_sandbox_failed", error=str(e), source=source, dest=str(dest))
                raise SandboxError(_ERR_COPY_FROM_SANDBOX) from e
            _logger.debug("file_copied_from_guest", source=source, dest=str(dest), size=len(payload))
            return

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        source_path = self._shared_folder / source

        if not await asyncio.to_thread(source_path.exists):
            _logger.warning("sandbox_source_file_not_found", path=source)
            raise SandboxError(_ERR_SOURCE_NOT_FOUND)

        await asyncio.to_thread(dest.parent.mkdir, parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.copy2, source_path, dest)
            _logger.debug("file_copied_from_sandbox", source=source, dest=str(dest))
        except OSError as e:
            _logger.warning("copy_from_sandbox_failed", error=str(e), source=source, dest=str(dest))
            raise SandboxError(_ERR_COPY_FROM_SANDBOX) from e

    async def _query_guest_block_devices(self) -> list[dict[str, object]]:
        """Read the topmost node of every guest-visible block device.

        Returns:
            list[dict[str, object]]: One ``inserted`` record per device that
            currently has media, in QEMU's order.

        Raises:
            SandboxError: If the monitor is not connected or refuses the query.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        result = await self._qmp.query_block()
        if not result.success:
            _logger.warning("query_block_failed", error=result.error)
            raise SandboxError(_ERR_SNAPSHOT_NO_DISK)

        devices = _as_sequence(result.data) or []
        inserted: list[dict[str, object]] = []
        for device in devices:
            record = _as_mapping(device)
            if record is None:
                continue
            medium = _as_mapping(record.get("inserted"))
            if medium is not None:
                inserted.append(medium)
        return inserted

    async def _snapshot_target_devices(self) -> list[str]:
        """Resolve the block-device ids a disk-only snapshot may be written to.

        ``blockdev-snapshot-internal-sync`` addresses a device by its
        ``query-block`` id rather than its node name, so this pairs the writable
        qcow2 media that :meth:`_snapshot_target_nodes` selects by node with the
        outer device id ``query-block`` reports for the same medium. The same
        writable-qcow2 filter keeps the read-only install media and the shared
        copy-on-write backing image (S17-D58) out of the set.

        Returns:
            list[str]: Device ids, in QEMU's device order.

        Raises:
            SandboxError: If the monitor is not connected, refuses the query, or
                the guest exposes no disk that can hold a snapshot.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        result = await self._qmp.query_block()
        if not result.success:
            _logger.warning("query_block_failed", error=result.error)
            raise SandboxError(_ERR_SNAPSHOT_NO_DISK)

        devices: list[str] = []
        for entry in _as_sequence(result.data) or []:
            record = _as_mapping(entry)
            if record is None:
                continue
            medium = _as_mapping(record.get("inserted"))
            device = record.get("device")
            if (
                medium is not None
                and medium.get("drv") == _SNAPSHOT_DISK_FORMAT
                and medium.get("ro") is False
                and isinstance(device, str)
                and device
            ):
                devices.append(device)

        if not devices:
            _logger.warning("snapshot_no_capable_disk")
            raise SandboxError(_ERR_SNAPSHOT_NO_DISK)
        return devices

    async def _take_disk_only_snapshot(self, name: str) -> None:
        """Snapshot the qcow2 contents of every writable disk, without machine state.

        This is the create path for an accelerator that blocks machine-state
        snapshots. It is synchronous - each device's outcome is on its own
        reply, not in the job list - and it stores no CPU or RAM state, so a
        restore of it cannot resume a running guest the way a full snapshot
        could; that is the weaker guarantee the caller is told about.

        Args:
            name: Snapshot name to write into each qcow2.

        Raises:
            SandboxError: If the monitor is not connected or any device refuses
                the snapshot.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        for device in await self._snapshot_target_devices():
            reply = await self._qmp.blockdev_snapshot_internal_sync(device, name)
            if not reply.success:
                _logger.warning("snapshot_disk_only_failed", device=device, snapshot_name=name, error=reply.error)
                raise SandboxError(
                    _ERR_SNAPSHOT_DISK_ONLY_FAILED.format(device=device, error=reply.error or _ERR_SNAPSHOT_JOB_REFUSED),
                )

    async def _snapshot_target_nodes(self) -> list[str]:
        """Resolve the block nodes an internal snapshot may be written to.

        Only a writable qcow2 can hold one, which rules out both the read-only
        install media a guest may still have attached and, importantly, the
        backing image behind each instance's copy-on-write overlay. The
        overlay and its backing image are both qcow2, so a filter on format
        alone would offer the shared base - the very image S17-D58 stopped
        instances from writing to.

        Returns:
            list[str]: Node names, in QEMU's device order.

        Raises:
            SandboxError: If the guest exposes no disk that can hold one.
        """
        nodes = [
            name
            for medium in await self._query_guest_block_devices()
            if medium.get("drv") == _SNAPSHOT_DISK_FORMAT and medium.get("ro") is False and isinstance(name := medium.get("node-name"), str)
        ]
        if not nodes:
            _logger.warning("snapshot_no_capable_disk")
            raise SandboxError(_ERR_SNAPSHOT_NO_DISK)
        return nodes

    @staticmethod
    def _new_snapshot_job_id(action: str) -> str:
        """Mint an identifier for one snapshot job.

        Args:
            action: Short verb naming the operation, used only for readability
                in QEMU's job list and this module's logs.

        Returns:
            str: A job id unique to this operation.
        """
        return f"intellicrack-{action}-{secrets.token_hex(4)}"

    async def _await_snapshot_job(self, job_id: str, failure: str) -> None:
        """Wait for a snapshot job to conclude and surface what it really did.

        The job-based snapshot commands answer immediately with an empty
        object; whether the work succeeded is reported separately, as an
        ``error`` member on the concluded job. Reading that member is the whole
        point of using these commands instead of ``savevm``/``loadvm``/
        ``delvm``, whose failures arrive as monitor text inside a *successful*
        QMP reply and so cannot be told from success at all.

        The job is dismissed either way, because a concluded job QEMU is still
        tracking would otherwise accumulate for the life of the VM.

        Args:
            job_id: Identifier the job was started with.
            failure: Message prefix describing the operation.

        Raises:
            SandboxError: If the job failed, disappeared, or never finished.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        budget = self._qemu_config.snapshot_timeout
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            listing = await self._qmp.query_jobs()
            if not listing.success:
                _logger.warning("snapshot_job_query_failed", job_id=job_id, error=listing.error)
                message = f"{failure}: {listing.error or _ERR_SNAPSHOT_JOB_UNREADABLE}"
                raise SandboxError(message)

            record = self._find_job(listing.data, job_id)
            if record is None:
                _logger.warning("snapshot_job_vanished", job_id=job_id)
                message = f"{failure}: {_ERR_SNAPSHOT_JOB_GONE.format(job_id=job_id)}"
                raise SandboxError(message)

            if record.get("status") == _JOB_STATUS_CONCLUDED:
                error = record.get("error")
                await self._qmp.job_dismiss(job_id)
                if isinstance(error, str):
                    _logger.warning("snapshot_job_failed", job_id=job_id, error=error)
                    message = f"{failure}: {error}"
                    raise SandboxError(message)
                return

            await asyncio.sleep(_SNAPSHOT_JOB_POLL_INTERVAL_S)

        _logger.warning("snapshot_job_timed_out", job_id=job_id, budget=budget)
        message = f"{failure}: {_ERR_SNAPSHOT_JOB_TIMEOUT.format(job_id=job_id, budget=budget)}"
        raise SandboxError(message)

    @staticmethod
    def _find_job(payload: object, job_id: str) -> dict[str, object] | None:
        """Pick one job out of a ``query-jobs`` reply.

        Args:
            payload: The reply's ``return`` member.
            job_id: Identifier to look for.

        Returns:
            dict[str, object] | None: The job record, or None if absent.
        """
        for entry in _as_sequence(payload) or []:
            record = _as_mapping(entry)
            if record is not None and record.get("id") == job_id:
                return record
        return None

    async def _machine_is_running(self) -> bool:
        """Report whether the machine's processors are executing right now.

        Returns:
            bool: True only if QEMU says so. An unreadable status answers
            False, because this decides whether to start a machine, and
            starting one the operator deliberately stopped is worse than
            declining to.
        """
        if self._qmp is None:
            return False
        reply = await self._qmp.query_status()
        if not reply.success:
            _logger.warning("snapshot_run_state_unreadable", error=reply.error)
            return False
        record = _as_mapping(reply.data)
        return record is not None and record.get("running") is True

    async def _resume_after_failed_snapshot_job(self, action: str, *, was_running: bool) -> str:
        """Start the machine again if the failed job is what stopped it.

        Args:
            action: Short verb naming the operation, for logging.
            was_running: Whether the machine was executing before the job.

        Returns:
            str: A clause naming the machine's fate, to be appended to the
            failure the caller is about to raise, or an empty string when the
            job left the machine as it found it.
        """
        if not was_running or self._qmp is None or await self._machine_is_running():
            return ""

        resumed = await self._qmp.cont()
        if not resumed.success or not await self._machine_is_running():
            reason = resumed.error or _ERR_SNAPSHOT_JOB_UNREADABLE
            _logger.error("snapshot_machine_left_stopped", action=action, error=reason)
            return _SNAPSHOT_MACHINE_STUCK.format(reason=reason)

        _logger.warning("snapshot_machine_resumed", action=action)
        return _SNAPSHOT_MACHINE_RESUMED

    async def _run_snapshot_job(
        self,
        action: str,
        failure: str,
        start: Callable[[], Awaitable[QMPResponse]],
        job_id: str,
    ) -> None:
        """Run one snapshot job and leave the machine as the job found it.

        QEMU stops the machine to load a snapshot and does not start it again
        when the job fails. A refused restore therefore costs the caller the
        guest itself: the processors never run again, every later guest command
        spends its whole budget timing out, and the sandbox goes on reporting
        itself as running. Measured against QEMU 10.1.0, ``query-status`` after
        a ``snapshot-load`` of a tag that does not exist is ``restore-vm`` with
        ``running: false``, and it stays there.

        The run state is read before the command is even issued, because the
        stop happens inside the job - the command itself is accepted and
        answers immediately - so reading it afterwards would be a race against
        the very thing being measured.

        Args:
            action: Short verb naming the operation, for logging.
            failure: Message prefix describing the operation.
            start: Issues the command that creates the job.
            job_id: Identifier the job was started with.

        Raises:
            SandboxError: If the command was refused or the job failed.
        """
        was_running = await self._machine_is_running()
        request = await start()

        if not request.success:
            _logger.warning("snapshot_job_rejected", action=action, job_id=job_id, error=request.error)
            refused = f"{failure}: {request.error or _ERR_SNAPSHOT_JOB_REFUSED}"
            detail, state = await self._snapshot_failure_detail(action, refused, was_running=was_running)
            raise SandboxError(detail, vm_state=state)

        try:
            await self._await_snapshot_job(job_id, failure)
        except SandboxError as failed:
            detail, state = await self._snapshot_failure_detail(action, failed.message, was_running=was_running)
            raise SandboxError(detail, vm_state=state) from failed

    async def _snapshot_failure_detail(self, action: str, message: str, *, was_running: bool) -> tuple[str, str]:
        """Repair the machine a failed snapshot job stopped, then describe both.

        Args:
            action: Short verb naming the operation, for logging.
            message: What went wrong with the job itself.
            was_running: Whether the machine was executing before the job.

        Returns:
            tuple[str, str]: The failure text to raise, and the machine's run
            state afterwards, so a caller can tell a refused operation from a
            lost guest.
        """
        fate = await self._resume_after_failed_snapshot_job(action, was_running=was_running)
        running = await self._machine_is_running()
        return (f"{message}{fate}", _VM_STATE_RUNNING if running else _VM_STATE_STOPPED)

    async def take_snapshot(self, name: str) -> str:
        """Take a snapshot of the VM.

        A full snapshot serialises CPU and RAM state as well as the disk. WHPX -
        the only accelerator Windows guests run under here - registers migration
        blockers against exactly that machine state, so ``snapshot-save`` can
        never conclude under it and the whole Snapshots surface would be dead on
        Windows. When the accelerator blocks machine state, a disk-only internal
        snapshot is taken instead: it stores the qcow2 contents and nothing of
        the running machine, which WHPX permits. A disk-only snapshot is a
        weaker guarantee - it cannot resume a running guest on restore - so
        which kind was taken is logged rather than passed off as the same thing.

        Args:
            name: Snapshot name.

        Returns:
            str: Snapshot identifier.

        Raises:
            SandboxError: If snapshot fails.
        """
        _logger.info("qemu_take_snapshot_started", snapshot_name=name)
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        if self._accelerator == AcceleratorType.WHPX:
            await self._take_disk_only_snapshot(name)
            _logger.info("snapshot_created", snapshot_name=name, kind="disk_only")
            return name

        nodes = await self._snapshot_target_nodes()
        job_id = self._new_snapshot_job_id("save")
        monitor = self._qmp
        await self._run_snapshot_job(
            "save",
            _ERR_SNAPSHOT_CREATE,
            lambda: monitor.snapshot_save(job_id, name, nodes[0], nodes),
            job_id,
        )

        _logger.info("snapshot_created", snapshot_name=name, kind="full", nodes=nodes)
        return name

    async def restore_snapshot(self, snapshot_id: str) -> None:
        """Restore a VM snapshot.

        Args:
            snapshot_id: Snapshot name to restore.

        Raises:
            SandboxError: If restore fails.
        """
        _logger.info("qemu_restore_snapshot_started", snapshot_id=snapshot_id)
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        nodes = await self._snapshot_target_nodes()
        job_id = self._new_snapshot_job_id("load")
        monitor = self._qmp
        await self._run_snapshot_job(
            "load",
            _ERR_SNAPSHOT_RESTORE,
            lambda: monitor.snapshot_load(job_id, snapshot_id, nodes[0], nodes),
            job_id,
        )

        _logger.info("snapshot_restored", snapshot_id=snapshot_id)

    async def list_snapshots(self) -> list[str]:
        """List available snapshots.

        The names come from the block layer's own records rather than from the
        ``info snapshots`` monitor table. That table was parsed by column, and
        rows were kept only when the first column was numeric - but QEMU prints
        ``--`` there for these snapshots, so every row was discarded and the
        list came back empty for a disk that plainly held snapshots.

        Returns:
            list[str]: Snapshot names, in the order the disks report them and
            without repeating a name that spans several disks. Empty when the
            monitor is not connected.
        """
        if self._qmp is None:
            return []

        names: list[str] = []
        for medium in await self._query_guest_block_devices():
            image = _as_mapping(medium.get("image"))
            if image is None:
                continue
            for entry in _as_sequence(image.get("snapshots")) or []:
                record = _as_mapping(entry)
                if record is None:
                    continue
                name = record.get("name")
                if isinstance(name, str) and name not in names:
                    names.append(name)

        return names

    async def delete_snapshot(self, name: str) -> None:
        """Delete a snapshot, and refuse to pretend one that never existed is gone.

        QEMU's job-based ``snapshot-delete`` is lenient where its siblings are
        not: it finishes ``concluded`` with no error for a tag no disk holds,
        while ``snapshot-load`` of that same tag fails loudly and the
        block-layer command refuses it outright. Passing that leniency on lets
        an operator delete a tag they misspelled and be told it worked, so the
        tag is checked against the block layer's own records before the job is
        started and again after it reports finishing.

        Args:
            name: Snapshot name to delete.

        Raises:
            SandboxError: If the monitor is not connected, no such snapshot
                exists, the deletion fails, or the tag outlives a job that
                reported success.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        if name not in await self.list_snapshots():
            _logger.warning("snapshot_delete_absent", snapshot_name=name)
            raise SandboxError(_ERR_SNAPSHOT_ABSENT.format(name=name))

        nodes = await self._snapshot_target_nodes()
        job_id = self._new_snapshot_job_id("delete")
        monitor = self._qmp
        await self._run_snapshot_job(
            "delete",
            _ERR_SNAPSHOT_DELETE,
            lambda: monitor.snapshot_delete(job_id, name, nodes),
            job_id,
        )

        if name in await self.list_snapshots():
            _logger.error("snapshot_delete_ineffective", snapshot_name=name, nodes=nodes)
            raise SandboxError(_ERR_SNAPSHOT_SURVIVED.format(name=name))

        _logger.info("snapshot_deleted", snapshot_name=name)

    async def start_pcap_capture(self) -> str:
        """Start packet capture on the sandbox network.

        Returns:
            str: Capture identifier for stopping later.

        Raises:
            SandboxError: If capture cannot be started.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        capture_id = f"pcap_{secrets.token_hex(8)}"
        pcap_path = self._shared_folder / "output" / f"{capture_id}.pcap"

        result = await self._qmp.execute_command({
            "execute": "object-add",
            "arguments": {
                "qom-type": "filter-dump",
                "id": capture_id,
                "netdev": "net0",
                "filename": str(pcap_path),
            },
        })

        if not result.success:
            _logger.warning("pcap_start_failed", error=result.error, capture_id=capture_id)
            raise SandboxError(_ERR_PCAP_START_FAILED)

        self._active_captures[capture_id] = pcap_path
        _logger.info("pcap_capture_started", capture_id=capture_id, path=str(pcap_path))
        return capture_id

    async def stop_pcap_capture(self, capture_id: str, output_path: Path | None = None) -> Path:
        """Stop packet capture and retrieve the PCAP file.

        Args:
            capture_id: Capture identifier from start_pcap_capture.
            output_path: Optional path to save the PCAP file.

        Returns:
            Path: Path to the saved PCAP file.

        Raises:
            SandboxError: If capture cannot be stopped.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        if capture_id not in self._active_captures:
            raise SandboxError(_ERR_PCAP_NOT_ACTIVE)

        result = await self._qmp.execute_command({
            "execute": "object-del",
            "arguments": {"id": capture_id},
        })

        if not result.success:
            _logger.warning("pcap_stop_failed", error=result.error, capture_id=capture_id)
            raise SandboxError(_ERR_PCAP_STOP_FAILED)

        pcap_path = self._active_captures.pop(capture_id)

        if output_path is not None:
            await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, pcap_path, output_path)
            _logger.info("pcap_saved", capture_id=capture_id, path=str(output_path))
            return output_path

        _logger.info("pcap_capture_stopped", capture_id=capture_id, path=str(pcap_path))
        return pcap_path

    @staticmethod
    async def _wait_for_ppm_stable(ppm_path: Path) -> None:
        """Wait until a PPM file size stops changing between polls.

        Polls ``ppm_path.stat().st_size`` twice per iteration with a short
        delay between reads. The file is considered stable when two
        consecutive size reads are equal and non-zero.

        Args:
            ppm_path: Path to the PPM file produced by QEMU ``screendump``.

        Raises:
            SandboxError: If the PPM file never stabilizes before the poll
                budget is exhausted.
        """
        await asyncio.sleep(_SCREENSHOT_INITIAL_DELAY_S)
        previous_size = -1
        for _ in range(_SCREENSHOT_STABILITY_MAX_POLLS):
            try:
                current_size = await asyncio.to_thread(lambda: ppm_path.stat().st_size)
            except FileNotFoundError:
                _logger.warning("ppm_stat_missing", ppm_path=str(ppm_path))
                await asyncio.sleep(_SCREENSHOT_STABILITY_POLL_DELAY_S)
                continue
            if current_size > 0 and current_size == previous_size:
                return
            previous_size = current_size
            await asyncio.sleep(_SCREENSHOT_STABILITY_POLL_DELAY_S)
        raise SandboxError(_ERR_SCREENSHOT_NOT_STABLE)

    async def capture_screenshot(self, output_path: Path | None = None) -> Path:
        """Capture a screenshot of the sandbox display.

        Performs a QMP ``screendump`` to a PPM file in the shared folder,
        polls the file size for stability (two consecutive ``stat`` reads
        equal with at least :data:`_SCREENSHOT_STABILITY_POLL_DELAY_S`
        delay between them), then converts to PNG. A conversion failure is
        reported as :class:`SandboxError` rather than silently returning a
        partial PPM.

        Args:
            output_path: Optional path to save the screenshot.

        Returns:
            Path: Path to the saved screenshot file.

        Raises:
            SandboxError: If the screenshot cannot be captured, stabilized,
                or converted.
        """
        _logger.info("qemu_capture_screenshot_started", output_path=str(output_path) if output_path else None)
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        screenshot_id = secrets.token_hex(8)
        ppm_path = self._shared_folder / "output" / f"screenshot_{screenshot_id}.ppm"

        result = await self._qmp.execute_command({
            "execute": "screendump",
            "arguments": {"filename": str(ppm_path)},
        })

        if not result.success:
            _logger.warning("screenshot_failed", error=result.error)
            raise SandboxError(_ERR_SCREENSHOT_FAILED)

        await self._wait_for_ppm_stable(ppm_path)

        png_path = ppm_path.with_suffix(".png")
        try:
            await asyncio.to_thread(_ppm_p6_to_png, ppm_path, png_path)
        except (OSError, ValueError) as exc:
            _logger.warning("ppm_to_png_conversion_failed", error=str(exc))
            raise SandboxError(_ERR_SCREENSHOT_CONVERSION_FAILED) from exc

        await asyncio.to_thread(ppm_path.unlink, missing_ok=True)
        final_path: Path = png_path

        if output_path is not None:
            await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, final_path, output_path)
            _logger.info("screenshot_saved", path=str(output_path))
            return output_path

        _logger.info("screenshot_captured", path=str(final_path))
        return final_path

    async def apply_anti_evasion(self, profile: str = "default") -> dict[str, Any]:
        """Apply guest-side anti-evasion registry patches.

        SMBIOS and CPUID masking are applied at VM launch through
        :meth:`_build_qemu_command`; only guest-side registry patches that
        require the guest agent can be applied post-launch. The launch-time
        techniques reported in the result are sourced from
        :attr:`QEMUConfig.anti_evasion_profile`, which is fixed at the time
        :meth:`start` was called.

        The ``profile`` argument must therefore match the profile the sandbox
        was launched with. If the caller passes a different profile, this
        method raises :class:`SandboxError` rather than silently returning a
        success result whose launch-time techniques do not correspond to the
        requested profile. To use a different profile, set
        :attr:`QEMUConfig.anti_evasion_profile` before invoking
        :meth:`start`.

        Args:
            profile: Anti-evasion profile the caller intends to apply. Must
                equal :attr:`QEMUConfig.anti_evasion_profile` of the running
                sandbox.

        Returns:
            dict[str, Any]: Dictionary describing applied techniques. Contains
            ``profile`` (the active launch-time profile), ``techniques``
            (list of technique identifiers actually in effect), and
            ``count`` (length of ``techniques``).

        Raises:
            SandboxError: If the sandbox is not running, QMP is disconnected,
                or ``profile`` does not match the launch-time profile.
        """
        _logger.info("qemu_apply_anti_evasion_started", profile=profile)
        if self.state.status != "running":
            _logger.error("anti_evasion_skipped_sandbox_not_running", state=self.state.status, profile=profile)
            raise SandboxError(_ERR_NOT_RUNNING)

        if self._qmp is None:
            _logger.error("anti_evasion_skipped_qmp_not_connected", profile=profile)
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        current_profile: str = self._qemu_config.anti_evasion_profile
        if profile != current_profile:
            _logger.error(
                "anti_evasion_profile_mismatch",
                requested_profile=profile,
                current_profile=current_profile,
            )
            raise SandboxError(
                _ERR_ANTI_EVASION_PROFILE_MISMATCH.format(
                    requested=profile,
                    current=current_profile,
                ),
            )

        techniques: list[str] = [f"smbios_type_{entry['type']}_launch_arg" for entry in self._anti_evasion_smbios_entries(current_profile)]
        techniques.append("cpuid_hypervisor_mask_launch_arg")

        failures: list[str] = []
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            failures = await self._apply_windows_anti_evasion(current_profile, techniques)

        if failures:
            reasons = "; ".join(failures)
            _logger.error(
                "anti_evasion_guest_side_failed",
                profile=current_profile,
                technique_count=len(techniques),
                failures=failures,
            )
            raise SandboxError(_ERR_ANTI_EVASION_GUEST_SIDE_FAILED.format(profile=current_profile, reasons=reasons))

        _logger.info("anti_evasion_applied", profile=current_profile, technique_count=len(techniques))
        return {"profile": current_profile, "techniques": techniques, "count": len(techniques)}

    async def _apply_windows_anti_evasion(self, profile: str, techniques: list[str]) -> list[str]:
        """Apply the guest-side Windows hardening, recording every part that failed.

        The launch-time techniques the caller already holds cannot fail - they
        are read off the fixed launch profile - but the registry patches and the
        MAC randomisation run real commands in the guest and can. Appending only
        the successes and dropping the failures on the floor let a run in which
        the agent was never connected, or every command timed out, report the
        same clean success as one in which everything worked. The failures are
        gathered and returned so the caller can refuse to call that a success.

        Args:
            profile: The active launch-time profile.
            techniques: Accumulator the successful guest-side techniques are
                appended to, in place.

        Returns:
            list[str]: One human-readable reason per guest-side step that did
            not succeed. Empty when every attempted step worked.
        """
        if self._agent is None or not self._agent.is_connected:
            return [_ERR_ANTI_EVASION_AGENT_ABSENT]

        failures: list[str] = []
        registry_commands = self._anti_evasion_registry_commands(
            profile,
            secrets.token_hex(8).upper(),
            self._guest_reg_exe_path(),
        )
        for cmd_name, cmd_args in registry_commands:
            exit_code, _, _ = await self._agent.send_command(cmd_name, cmd_args)
            if exit_code == 0:
                techniques.append("registry_patch")
            else:
                failures.append(_ERR_ANTI_EVASION_COMMAND_FAILED.format(name=cmd_name, exit_code=exit_code))

        mac_octets = [f"{secrets.randbelow(256):02X}" for _ in range(5)]
        mac_literal = "00-" + "-".join(mac_octets)
        mac_ps_command = f"Set-NetAdapter -Name Ethernet -MacAddress '{mac_literal}' -Confirm:$false"
        mac_exit_code, _, _ = await self._agent.send_command(
            "powershell.exe",
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                mac_ps_command,
            ],
        )
        if mac_exit_code == 0:
            techniques.append("mac_address_randomize")
        else:
            failures.append(_ERR_ANTI_EVASION_COMMAND_FAILED.format(name="mac_address_randomize", exit_code=mac_exit_code))

        return failures

    async def dump_memory(
        self,
        output_path: Path | None = None,
        target_pid: int | None = None,
    ) -> Path:
        """Dump guest memory to a file.

        QEMU dumps the entire VM via the ``dump-guest-memory`` QMP command, so
        ``target_pid`` is accepted for interface parity with
        :meth:`WindowsSandbox.dump_memory` but is not used to filter the dump.
        The value is recorded in the debug log for traceability.

        Args:
            output_path: Optional path to save the memory dump.
            target_pid: Ignored for QEMU. Accepted for interface parity with
                Windows Sandbox where it selects the process to dump.

        Returns:
            Path: Path to the saved memory dump file.

        Raises:
            SandboxError: If memory dump fails.
        """
        _logger.info("qemu_dump_memory_started", output_path=str(output_path) if output_path else None, target_pid=target_pid)
        if target_pid is not None:
            _logger.debug("qemu_dump_memory_ignoring_target_pid", target_pid=target_pid)
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        dump_id = secrets.token_hex(8)
        dump_path = self._shared_folder / "output" / f"memdump_{dump_id}.raw"

        # Detached deliberately. A synchronous dump-guest-memory does not answer
        # until the guest's whole RAM is on disk - measured at 3.6 s for a
        # 1024 MB guest against QEMU 10.1.0, so roughly half a minute for the
        # 8192 MB guests this backend runs - which is far past any sane reply
        # timeout and holds the monitor lock for the duration, stalling every
        # other query. Detached, the reply lands in about two milliseconds and
        # the real progress is read from query-dump.
        result = await self._qmp.execute_command({
            "execute": "dump-guest-memory",
            "arguments": {
                "paging": False,
                "protocol": f"file:{dump_path}",
                "detach": True,
            },
        })

        if not result.success:
            _logger.warning("memory_dump_rejected", error=result.error)
            message = f"{_ERR_MEMORY_DUMP_FAILED}: {result.error or _ERR_MEMORY_DUMP_REFUSED}"
            raise SandboxError(message)

        await self._await_memory_dump(dump_path)

        _logger.info("memory_dump_created", path=str(dump_path))

        if output_path is not None:
            await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, dump_path, output_path)
            _logger.info("memory_dump_saved", path=str(output_path))
            return output_path

        return dump_path

    async def _await_memory_dump(self, dump_path: Path) -> None:
        """Wait for a detached guest memory dump and report what really happened.

        ``query-dump`` carries global, sticky state: measured against QEMU
        10.1.0 it reports ``status: "none"`` before any dump, and after a
        *rejected* request it still reports the previous dump's ``completed``.
        That is why the request's own reply is checked before this method is
        entered - polling alone cannot tell a refused dump from a finished one.

        Args:
            dump_path: File the dump is being written to.

        Raises:
            SandboxError: If the monitor is gone, the dump failed, the status
                could not be read, the budget ran out, or nothing was written.
        """
        if self._qmp is None:
            raise SandboxError(_ERR_QMP_NOT_CONNECTED)

        budget = self._qemu_config.memory_dump_timeout
        deadline = time.monotonic() + budget
        progress = 0
        while time.monotonic() < deadline:
            reply = await self._qmp.execute_command({"execute": "query-dump"})
            state = _as_mapping(reply.data) if reply.success else None
            if state is None:
                _logger.warning("memory_dump_status_unreadable", error=reply.error)
                message = f"{_ERR_MEMORY_DUMP_FAILED}: {reply.error or _ERR_MEMORY_DUMP_UNREADABLE}"
                raise SandboxError(message)

            status = state.get("status")
            completed = state.get("completed")
            if isinstance(completed, int):
                progress = completed

            # "none" is the state QEMU reports before a dump has started, and
            # the accepted request has not necessarily reached the dump thread
            # by the time this first poll goes out. The request's own reply was
            # already checked, so here it means "not started yet", not "no dump
            # was asked for".
            if status in {_DUMP_STATUS_ACTIVE, _DUMP_STATUS_NONE}:
                await asyncio.sleep(_DUMP_POLL_INTERVAL_S)
                continue

            if status != _DUMP_STATUS_COMPLETED:
                _logger.warning("memory_dump_failed", status=str(status), completed=progress)
                message = f"{_ERR_MEMORY_DUMP_FAILED}: QEMU reported the dump as {status}"
                raise SandboxError(message)

            written = await asyncio.to_thread(_file_size_or_zero, dump_path)
            if written == 0:
                _logger.warning("memory_dump_empty", path=str(dump_path))
                message = f"{_ERR_MEMORY_DUMP_FAILED}: {_ERR_MEMORY_DUMP_EMPTY.format(path=dump_path)}"
                raise SandboxError(message)

            _logger.info("memory_dump_finished", path=str(dump_path), bytes_written=written)
            return

        _logger.warning("memory_dump_timed_out", budget=budget, completed=progress)
        message = f"{_ERR_MEMORY_DUMP_FAILED}: {_ERR_MEMORY_DUMP_TIMEOUT.format(budget=budget, completed=progress)}"
        raise SandboxError(message)

    async def extract_dropped_files(self, output_path: Path | None = None) -> Path:
        """Extract files created by the binary during execution.

        Which extraction path runs is decided by the transport:

        1. FAT transport: the share is read-only to the guest, so the guest
           gathers the watched directories and the watcher's mirror into its
           own work root and the host pulls that tree back over the guest
           agent. There is no host-visible copy to fall back to.
        2. virtio-9p transport, agent connected: dispatches an allowlisted
           shell wrapper (``cmd.exe /c "xcopy ..."`` on Windows or
           ``/bin/bash -c "cp -r ..."`` on Linux) for each watched guest
           directory so the guest copies created files into the per-call
           staging directory under the shared folder.
        3. virtio-9p transport, agent unreachable: copies any files the
           guest's monitor has mirrored under ``<shared>/output/dropped/``
           into the staging directory using ``shutil.copy2``.

        Whichever path ran, the staging directory must contain at least one
        file or the call is treated as a genuine failure.

        Args:
            output_path: Optional path to save the ZIP archive.

        Returns:
            Path: Path to the ZIP archive containing the extracted files.

        Raises:
            SandboxError: If the sandbox is not running, no shared folder
                is configured, or neither extraction path produced any
                files.
        """
        _logger.info("qemu_extract_dropped_files_started", output_path=str(output_path) if output_path else None)
        if self.state.status != "running":
            _logger.error("dropped_files_extraction_skipped_not_running", state=self.state.status)
            raise SandboxError(_ERR_NOT_RUNNING)

        if self._shared_folder is None:
            _logger.error("dropped_files_extraction_shared_folder_not_initialized")
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        extract_id = secrets.token_hex(8)
        staging_dir = self._staging_root_for(extract_id)
        await asyncio.to_thread(staging_dir.mkdir, parents=True, exist_ok=True)

        guest_dirs = self._drop_watch_roots()

        agent_used = False
        if self._uses_fat_shared_transport():
            # The guest cannot copy anything onto a read-only share, so it
            # gathers into its own work root and the host pulls the result back
            # over the guest agent. That pull is the only channel there is here,
            # so there is no host-side fallback to fall back to.
            agent_used = True
            await self._gather_dropped_in_guest(guest_dirs, extract_id)
            await self._pull_guest_directory(self._guest_work_path(f"output/dropped_{extract_id}"), staging_dir)
        elif self._agent is not None and self._agent.is_connected:
            agent_used = True
            shared_base = self._guest_shared_root_for(self._qemu_config.guest_os)
            for guest_dir in guest_dirs:
                if self._qemu_config.guest_os == GuestOS.WINDOWS:
                    inner_cmd = f'xcopy /S /E /Y /I "{guest_dir}" "{shared_base}output\\dropped_{extract_id}\\{Path(guest_dir).name}"'
                else:
                    dir_name = Path(guest_dir).name
                    inner_cmd = f'cp -r "{guest_dir}" "{shared_base}/output/dropped_{extract_id}/{dir_name}" 2>/dev/null'
                wrapped_command, wrapped_args = self._guest_shell_invocation(inner_cmd)
                exit_code, stdout, stderr = await self._agent.send_command(
                    wrapped_command,
                    args=wrapped_args,
                    time_limit=_DROPPED_COPY_TIMEOUT,
                )
                _logger.debug(
                    "dropfile_agent_copy_dispatched",
                    guest_dir=guest_dir,
                    wrapped_command=wrapped_command,
                    exit_code=exit_code,
                    stdout_len=len(stdout),
                    stderr_len=len(stderr),
                )

        if not agent_used:
            await self._host_collect_dropped_files(staging_dir=staging_dir)

        files_collected = await asyncio.to_thread(self._count_files_recursive, staging_dir)
        _logger.debug(
            "dropfile_collection_completed",
            agent_used=agent_used,
            files_collected=files_collected,
            staging_dir=str(staging_dir),
        )

        if files_collected == 0:
            try:
                await asyncio.to_thread(shutil.rmtree, staging_dir, ignore_errors=True)
            except OSError as cleanup_err:
                _logger.warning(
                    "staging_dir_cleanup_failed",
                    error=str(cleanup_err),
                    staging_dir=str(staging_dir),
                )
            _logger.error(
                "dropped_files_extract_empty",
                agent_used=agent_used,
                shared_folder=str(self._shared_folder),
            )
            raise SandboxError(_ERR_EXTRACT_FILES_FAILED)

        zip_filename = f"dropped_files_{extract_id}.zip"
        zip_path = staging_dir.parent / zip_filename

        def _create_zip() -> None:
            """Write the staging directory contents into a zip archive at ``zip_path``."""
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for file_path in staging_dir.rglob("*"):
                    if file_path.is_file():
                        arcname = file_path.relative_to(staging_dir)
                        zf.write(file_path, arcname)

        await asyncio.to_thread(_create_zip)

        try:
            await asyncio.to_thread(shutil.rmtree, staging_dir, ignore_errors=True)
        except OSError as e:
            _logger.warning("staging_dir_cleanup_failed", error=str(e), staging_dir=str(staging_dir))

        _logger.info("dropped_files_extracted", zip_path=str(zip_path), files=files_collected)

        if output_path is not None:
            await asyncio.to_thread(output_path.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(shutil.copy2, zip_path, output_path)
            return output_path

        return zip_path

    def _staging_root_for(self, extract_id: str) -> Path:
        """Return the host directory one extraction gathers its files into.

        On the FAT transport this is under the collection root rather than the
        share: the share backs a read-only vvfat volume the guest is still
        reading, and writing into a directory vvfat has already built its FAT
        over is the failure this whole transport change exists to avoid.

        Args:
            extract_id: Identifier making this extraction's directory unique.

        Returns:
            Path: Directory the extraction stages into, not yet created.

        Raises:
            SandboxError: If the sandbox has no working directory or shared
                folder to stage beneath.
        """
        if self._uses_fat_shared_transport():
            collected = self._collected_root()
            if collected is None:
                raise SandboxError(_ERR_NO_SHARED_FOLDER)
            return collected / "dropped" / f"dropped_{extract_id}"
        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)
        return self._shared_folder / "output" / f"dropped_{extract_id}"

    def _drop_watch_roots(self) -> list[str]:
        """Return the guest directories dropped files are collected from.

        Returns:
            list[str]: Absolute in-guest directories for the configured guest.
        """
        if self._qemu_config.guest_os == GuestOS.WINDOWS:
            return self._windows_drop_watch_roots()
        return [
            PurePosixPath("/", "tmp").as_posix(),
            PurePosixPath("/", "var", "tmp").as_posix(),
            "/home",
        ]

    async def _gather_dropped_in_guest(self, guest_dirs: list[str], extract_id: str) -> None:
        """Have the guest copy every watched directory into its own work root.

        The watcher's mirror is copied in as well, so a file the guest created
        and then deleted during the run is still collected.

        Args:
            guest_dirs: Absolute in-guest directories to gather from.
            extract_id: Identifier of the extraction being gathered.
        """
        target = self._guest_work_path(f"output/dropped_{extract_id}")
        mirror = self._guest_work_path("output/dropped")
        windows = self._qemu_config.guest_os == GuestOS.WINDOWS
        separator = "\\" if windows else "/"
        for guest_dir in [*guest_dirs, mirror]:
            leaf = PureWindowsPath(guest_dir).name if windows else PurePosixPath(guest_dir).name
            destination = f"{target}{separator}{leaf}"
            command = f'xcopy /S /E /Y /I "{guest_dir}" "{destination}"' if windows else f'cp -r "{guest_dir}" "{destination}" 2>/dev/null'
            exit_code, stdout, stderr = await self.run_command(command, time_limit=_DROPPED_COPY_TIMEOUT)
            _logger.debug(
                "dropfile_guest_copy_dispatched",
                guest_dir=guest_dir,
                exit_code=exit_code,
                stdout_len=len(stdout),
                stderr_len=len(stderr),
            )

    async def _list_guest_directory(self, guest_dir: str) -> list[str]:
        """List every regular file beneath a guest directory, recursively.

        Args:
            guest_dir: Absolute in-guest directory to walk.

        Returns:
            list[str]: Absolute in-guest paths, empty when the directory holds
            no files or does not exist.
        """
        command = f'dir /b /s /a-d "{guest_dir}"' if self._qemu_config.guest_os == GuestOS.WINDOWS else f'find "{guest_dir}" -type f'
        exit_code, stdout, _ = await self.run_command(command, time_limit=_DROPPED_LIST_TIMEOUT)
        if exit_code != 0:
            # An empty or missing directory is how both listers report "nothing
            # here", so it is not distinguishable from - and is treated as - a
            # run that dropped nothing.
            _logger.debug("dropfile_listing_empty", guest_dir=guest_dir, exit_code=exit_code)
            return []
        return [line.strip() for line in stdout.splitlines() if line.strip()]

    async def _pull_guest_directory(self, guest_dir: str, destination: Path) -> int:
        """Copy every file beneath a guest directory onto the host.

        Args:
            guest_dir: Absolute in-guest directory to pull.
            destination: Host directory the tree is reproduced under.

        Returns:
            int: Number of files written to the host.
        """
        prefix_length = len(guest_dir) + 1
        pulled = 0
        pulled_bytes = 0
        listing = await self._list_guest_directory(guest_dir)
        for guest_path in listing:
            if pulled >= _DROPPED_PULL_MAX_FILES or pulled_bytes >= _DROPPED_PULL_MAX_BYTES:
                _logger.warning(
                    "dropfile_pull_capped",
                    guest_dir=guest_dir,
                    listed=len(listing),
                    pulled=pulled,
                    pulled_bytes=pulled_bytes,
                    skipped=len(listing) - pulled,
                )
                break
            relative = guest_path[prefix_length:].replace("\\", "/").strip("/")
            if not relative:
                continue
            try:
                payload = await self._read_guest_file(guest_path)
            except SandboxError as error:
                _logger.debug("dropfile_pull_failed", guest_path=guest_path, error=str(error))
                continue
            target = destination / relative
            await asyncio.to_thread(target.parent.mkdir, parents=True, exist_ok=True)
            await asyncio.to_thread(target.write_bytes, payload)
            pulled += 1
            pulled_bytes += len(payload)
        _logger.debug("dropfile_pull_completed", guest_dir=guest_dir, pulled=pulled, pulled_bytes=pulled_bytes)
        return pulled

    async def _host_collect_dropped_files(self, staging_dir: Path) -> None:
        """Copy guest-mirrored dropped files into the staging directory host-side.

        Reads from ``<shared>/output/dropped/`` (populated by the guest agent's
        file watcher) and copies every regular file beneath it into
        ``staging_dir``, preserving relative paths. Used as a fallback when the
        guest agent is disconnected.

        Args:
            staging_dir: Per-call destination directory under the shared folder.
        """
        if self._shared_folder is None:
            return
        mirror_dir = self._shared_folder / "output" / "dropped"
        if not await asyncio.to_thread(mirror_dir.exists):
            _logger.debug(
                "dropfile_mirror_absent",
                mirror_dir=str(mirror_dir),
            )
            return

        def _copy_tree() -> int:
            """Copy mirror contents into the staging directory.

            Returns:
                int: Number of files copied.
            """
            copied = 0
            for src in mirror_dir.rglob("*"):
                if not src.is_file():
                    continue
                rel = src.relative_to(mirror_dir)
                dst = staging_dir / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                copied += 1
            return copied

        copied = await asyncio.to_thread(_copy_tree)
        _logger.info(
            "dropped_files_host_collected",
            mirror_dir=str(mirror_dir),
            files_copied=copied,
        )

    @staticmethod
    def _count_files_recursive(directory: Path) -> int:
        """Count regular files under ``directory`` recursively.

        Args:
            directory: Root directory to scan.

        Returns:
            int: Number of regular files found; zero if the directory is
                missing.
        """
        if not directory.exists():
            return 0
        return sum(bool(entry.is_file()) for entry in directory.rglob("*"))

    async def yara_scan(
        self,
        rules_path: str | None = None,
        scan_target: str = "files",
    ) -> list[dict[str, Any]]:
        """Run YARA rules against sandbox artifacts.

        An empty result means the rules matched nothing in artifacts that were
        really scanned. Having nothing to scan is a different outcome and is
        raised rather than returned, so a scan that never reached the guest
        cannot be mistaken for a clean one.

        Args:
            rules_path: Path to YARA rules file. Uses built-in rules if None.
            scan_target: What to scan - 'files' for dropped files, 'memory' for memory dump.

        Returns:
            list[dict[str, Any]]: List of YARA match dictionaries.

        Raises:
            SandboxError: If the scan target is unknown, the sandbox has no
                shared folder, or there is nothing of the requested kind to
                scan.
        """
        _logger.info("qemu_yara_scan_started", rules_path=rules_path, scan_target=scan_target)
        if scan_target not in YARA_SCAN_TARGETS:
            _logger.warning("yara_scan_unknown_target", scan_target=scan_target)
            raise SandboxError(
                ERR_YARA_UNKNOWN_TARGET.format(target=scan_target, expected=", ".join(YARA_SCAN_TARGETS)),
            )
        yara = require_yara()

        if self._shared_folder is None:
            raise SandboxError(_ERR_NO_SHARED_FOLDER)

        yara_compile: Any = yara.compile
        compiled_rules: Any
        if rules_path is not None:
            compiled_rules = await asyncio.to_thread(yara_compile, filepath=rules_path)
        else:
            default_rules = """
rule SuspiciousStrings {
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "CreateRemoteThread"
        $s4 = "VirtualAllocEx"
        $s5 = "WriteProcessMemory"
        $s6 = "NtUnmapViewOfSection"
        $s7 = "WScript.Shell"
        $s8 = /HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/
    condition:
        any of them
}

rule PackedBinary {
    strings:
        $upx = "UPX!"
        $aspack = ".aspack"
        $themida = ".themida"
    condition:
        any of them
}
"""
            compiled_rules = await asyncio.to_thread(yara_compile, source=default_rules)

        matches: list[dict[str, Any]] = []
        output_dir = self._shared_folder / "output"

        if scan_target == YARA_TARGET_MEMORY:
            dump_files = await asyncio.to_thread(lambda: list(output_dir.glob("memdump_*.raw")))
            if not dump_files:
                _logger.warning("yara_scan_no_memory_dump", output_dir=str(output_dir))
                raise SandboxError(ERR_YARA_NO_MEMORY_DUMP.format(path=output_dir))
            for dump_file in dump_files:
                file_matches: list[Any] = await asyncio.to_thread(compiled_rules.match, filepath=str(dump_file))
                matches.extend(_format_yara_match(ym, str(dump_file), "memory") for ym in file_matches)
        else:
            scan_files: list[Path] = []
            zip_files = await asyncio.to_thread(lambda: list(output_dir.glob("dropped_files_*.zip")))
            if zip_files:
                extract_dir = output_dir / f"yara_scan_{secrets.token_hex(4)}"
                await asyncio.to_thread(extract_dir.mkdir, parents=True, exist_ok=True)

                def _extract_zips() -> list[Path]:
                    """Extract dropped-file zip archives into the scan directory.

                    Returns:
                        list[Path]: All regular files found under the extract root.
                    """
                    extracted: list[Path] = []
                    for zf_path in zip_files:
                        with zipfile.ZipFile(zf_path, "r") as zf:
                            zf.extractall(extract_dir)
                    extracted.extend(fp for fp in extract_dir.rglob("*") if fp.is_file())
                    return extracted

                scan_files = await asyncio.to_thread(_extract_zips)
            else:
                scan_files = await asyncio.to_thread(scannable_output_files, output_dir)

            if not scan_files:
                _logger.warning("yara_scan_no_artifacts", output_dir=str(output_dir))
                raise SandboxError(ERR_YARA_NO_ARTIFACTS.format(path=output_dir))

            for scan_file in scan_files:
                try:
                    file_matches = await asyncio.to_thread(compiled_rules.match, filepath=str(scan_file))
                    matches.extend(_format_yara_match(ym, str(scan_file), "files") for ym in file_matches)
                except (OSError, RuntimeError) as e:
                    _logger.warning("yara_file_scan_error", file=str(scan_file), error=str(e))

        _logger.info("yara_scan_complete", match_count=len(matches), scan_target=scan_target)
        return matches
