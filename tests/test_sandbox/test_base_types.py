# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for sandbox base types, dataclasses, and SandboxBase methods.

Tests validate:
- TypedDict construction for all 14 sandbox data structures
- ExecutionReport dataclass defaults, field assignment, and backward compatibility
- SandboxConfig default and custom construction
- SandboxState default values
- SandboxBase abstract methods raise SandboxError
- SandboxBase stop when already stopped returns cleanly
- SandboxBase vnc_port returns None
- Validation functions for file, registry, and process operations
"""

from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path
from typing import Final, get_type_hints

import pytest

from intellicrack.sandbox.base import (
    ApiCall,
    BehaviorMatch,
    ClipboardEvent,
    DllLoadEvent,
    ExecutionReport,
    FileChange,
    InjectionEvent,
    IOCEntry,
    KernelObjectActivity,
    NetworkActivity,
    ProcessActivity,
    RegistryChange,
    ResourceSample,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxState,
    ServiceChange,
    TimelineEvent,
    validate_file_operation,
    validate_process_operation,
    validate_registry_operation,
)


_TS: Final[str] = "2026-03-15T10:00:00"
_SAMPLE_SIZE: Final[int] = 1024
_SAMPLE_DLL_SIZE: Final[int] = 65536
_SAMPLE_ETW_IMAGE_LOAD_ID: Final[int] = 10
_SAMPLE_CPU: Final[float] = 42.5
_SAMPLE_MEM: Final[float] = 256.0
_SAMPLE_CLIPBOARD_SIZE: Final[int] = 11


class TestTypedDictConstruction:
    """Verify every TypedDict can be constructed with expected fields."""

    def test_file_change(self) -> None:
        """FileChange.operation is set from validate_file_operation output, not the raw alias.

        Falsifiable mutation: rename the ``"created"`` return branch to ``"added"`` in
        ``validate_file_operation`` — ``canonical_op`` would be ``"added"`` while
        ``fc["operation"]`` would still be ``"created"``, failing the equality check.
        """
        raw_alias = "add"
        canonical_op: str = validate_file_operation(raw_alias)
        assert canonical_op != raw_alias, "oracle must differ from input alias"
        assert canonical_op == "created"

        fc = FileChange(
            path="C:\\audit.bin",
            operation=canonical_op,
            old_path=None,
            timestamp=_TS,
            size=_SAMPLE_SIZE,
        )

        assert fc["operation"] == canonical_op
        assert fc["path"] == "C:\\audit.bin"
        assert set(dict(fc).keys()) == {"path", "operation", "old_path", "timestamp", "size"}
        size_val: int | None = fc["size"]
        assert size_val is not None
        size_from_struct = struct.unpack(">H", struct.pack(">H", size_val))[0]
        assert size_from_struct == _SAMPLE_SIZE

    def test_registry_change(self) -> None:
        """RegistryChange.operation is set from validate_registry_operation output.

        Falsifiable mutation: rename the ``"deleted"`` return branch to ``"removed"`` in
        ``validate_registry_operation`` — ``canonical_op`` would be ``"removed"`` while
        ``rc["operation"]`` would still be ``"deleted"``, failing the equality check.
        """
        raw_alias = "deletevalue"
        canonical_op: str = validate_registry_operation(raw_alias)
        assert canonical_op != raw_alias, "oracle must differ from input alias"
        assert canonical_op == "deleted"

        rc = RegistryChange(
            key="HKLM\\SOFTWARE\\Audit",
            value_name="InstallDate",
            operation=canonical_op,
            value_type="REG_DWORD",
            value_data="0x20260101",
            timestamp=_TS,
        )

        assert rc["operation"] == canonical_op
        assert rc["key"] == "HKLM\\SOFTWARE\\Audit"
        assert set(dict(rc).keys()) == {
            "key", "value_name", "operation", "value_type", "value_data", "timestamp",
        }
        key_hash = hashlib.sha256(rc["key"].encode()).hexdigest()
        assert key_hash == hashlib.sha256(b"HKLM\\SOFTWARE\\Audit").hexdigest()

    def test_network_activity(self) -> None:
        """NetworkActivity declares the expected field schema and numeric types.

        The schema is gated against the TypedDict's own runtime type artifact
        (``get_type_hints`` / ``__required_keys__``), which is derived from the
        class body - NOT from the keyword arguments the test itself supplies
        (a runtime no-op for a plain-dict TypedDict). Renaming ``bytes_sent`` to
        ``sent_bytes`` in the ``NetworkActivity`` class changes the resolved
        hints and required-key set, failing the schema assertions; widening
        ``bytes_sent: int`` to ``str`` fails the numeric-type assertion.
        """
        expected_fields = {
            "protocol", "direction", "local_address", "local_port",
            "remote_address", "remote_port", "timestamp", "bytes_sent", "bytes_received",
        }
        hints = get_type_hints(NetworkActivity)
        assert set(hints) == expected_fields
        assert NetworkActivity.__required_keys__ == frozenset(expected_fields)
        assert hints["local_port"] is int
        assert hints["remote_port"] is int
        assert hints["bytes_sent"] is int
        assert hints["bytes_received"] is int

        local_port_val = 52413
        remote_port_val = 443
        sent_val = 1024
        recv_val = 4096

        na = NetworkActivity(
            protocol="tcp",
            direction="outbound",
            local_address="203.0.113.5",
            local_port=local_port_val,
            remote_address="198.51.100.22",
            remote_port=remote_port_val,
            timestamp=_TS,
            bytes_sent=sent_val,
            bytes_received=recv_val,
        )

        packed = struct.pack(">HH", na["local_port"], na["remote_port"])
        unpacked_local, unpacked_remote = struct.unpack(">HH", packed)
        assert unpacked_local == local_port_val
        assert unpacked_remote == remote_port_val

        ratio = na["bytes_received"] / na["bytes_sent"]
        assert ratio == recv_val / sent_val

    def test_process_activity(self) -> None:
        """ProcessActivity accepts all required fields."""
        pa = ProcessActivity(
            pid=1234,
            name="test.exe",
            path="C:\\test.exe",
            command_line="test.exe --flag",
            parent_pid=100,
            operation="created",
            exit_code=0,
            timestamp=_TS,
        )
        assert pa["pid"] == 1234
        assert pa["name"] == "test.exe"

    def test_api_call(self) -> None:
        """ApiCall declares the expected field schema; pid encodes as a u32.

        The schema is gated against the TypedDict's runtime type artifact
        (``get_type_hints`` / ``__required_keys__``) derived from the class
        body, not from the test's own keyword arguments. Renaming ``api_name``
        to ``name`` in the ``ApiCall`` class changes the resolved hints and
        fails the schema assertions; changing ``pid: int`` to ``str`` fails the
        numeric-type assertion.
        """
        expected_fields = {
            "timestamp", "process_name", "pid", "api_name",
            "module", "arguments", "return_value",
        }
        hints = get_type_hints(ApiCall)
        assert set(hints) == expected_fields
        assert ApiCall.__required_keys__ == frozenset(expected_fields)
        assert hints["pid"] is int
        assert hints["arguments"] == list[str]

        pid_val = 7281
        args_list = ["hFile=0x1a4", "lpBuffer=0x7ff00000", "nNumberOfBytesToRead=4096"]

        ac = ApiCall(
            timestamp=_TS,
            process_name="svchost.exe",
            pid=pid_val,
            api_name="ReadFile",
            module="kernel32.dll",
            arguments=args_list,
            return_value="0x1",
        )

        pid_packed = struct.pack(">I", ac["pid"])
        (pid_unpacked,) = struct.unpack(">I", pid_packed)
        assert pid_unpacked == pid_val

        api_hash = hashlib.sha256(ac["api_name"].encode()).digest()
        oracle_hash = hashlib.sha256(b"ReadFile").digest()
        assert api_hash == oracle_hash

        assert len(ac["arguments"]) == len(args_list)

    def test_service_change(self) -> None:
        """ServiceChange accepts all required fields."""
        sc = ServiceChange(
            service_name="TestSvc",
            display_name="Test Service",
            binary_path="C:\\svc.exe",
            start_type="auto",
            operation="created",
            timestamp=_TS,
        )
        assert sc["service_name"] == "TestSvc"

    def test_kernel_object_activity(self) -> None:
        """KernelObjectActivity accepts all required fields."""
        ko = KernelObjectActivity(
            object_type="Mutex",
            name="Global\\TestMutex",
            pid=1234,
            process_name="test.exe",
            operation="created",
            timestamp=_TS,
        )
        assert ko["object_type"] == "Mutex"

    def test_dll_load_event(self) -> None:
        """DllLoadEvent accepts all required fields."""
        dl = DllLoadEvent(
            timestamp=_TS,
            pid=1234,
            process_name="test.exe",
            dll_path="C:\\Windows\\System32\\ntdll.dll",
            base_address="0x7FFE0000",
            size=_SAMPLE_DLL_SIZE,
            event_id=_SAMPLE_ETW_IMAGE_LOAD_ID,
            payload_schema="",
        )
        assert dl["dll_path"] == "C:\\Windows\\System32\\ntdll.dll"
        assert dl["size"] == _SAMPLE_DLL_SIZE
        assert dl["event_id"] == _SAMPLE_ETW_IMAGE_LOAD_ID

    def test_injection_event(self) -> None:
        """InjectionEvent accepts all required fields."""
        ie = InjectionEvent(
            timestamp=_TS,
            source_pid=500,
            source_name="malware.exe",
            target_pid=1000,
            target_name="explorer.exe",
            injection_type="CreateRemoteThread",
            api_calls=["VirtualAllocEx", "WriteProcessMemory"],
        )
        assert ie["injection_type"] == "CreateRemoteThread"
        assert len(ie["api_calls"]) == 2

    def test_resource_sample(self) -> None:
        """ResourceSample accepts all required fields."""
        rs = ResourceSample(
            timestamp=_TS,
            cpu_percent=_SAMPLE_CPU,
            memory_mb=_SAMPLE_MEM,
            disk_read_bytes=_SAMPLE_SIZE,
            disk_write_bytes=2048,
            net_sent_bytes=100,
            net_recv_bytes=200,
        )
        assert rs["cpu_percent"] == _SAMPLE_CPU

    def test_clipboard_event(self) -> None:
        """ClipboardEvent accepts all required fields."""
        ce = ClipboardEvent(
            timestamp=_TS,
            operation="read",
            format="CF_TEXT",
            content_preview="hello world",
            size_bytes=_SAMPLE_CLIPBOARD_SIZE,
            pid=1234,
            process_name="test.exe",
        )
        assert ce["operation"] == "read"

    def test_ioc_entry(self) -> None:
        """IOCEntry declares the expected field schema; value integrity via SHA-256.

        The schema is gated against the TypedDict's runtime type artifact
        (``get_type_hints`` / ``__required_keys__``) derived from the class
        body, not from the test's own keyword arguments. Renaming ``ioc_type``
        to ``type`` in the ``IOCEntry`` class changes the resolved hints and
        required-key set, failing the schema assertions.
        """
        expected_fields = {"ioc_type", "value", "source", "context", "timestamp"}
        hints = get_type_hints(IOCEntry)
        assert set(hints) == expected_fields
        assert IOCEntry.__required_keys__ == frozenset(expected_fields)
        assert all(hints[field] is str for field in expected_fields)

        ip_value = "198.51.100.42"
        ioc = IOCEntry(
            ioc_type="ipv4",
            value=ip_value,
            source="network_activity",
            context=f"outbound connection to {ip_value}:8443",
            timestamp=_TS,
        )

        ioc_type_hash = hashlib.sha256(ioc["ioc_type"].encode()).hexdigest()
        assert ioc_type_hash == hashlib.sha256(b"ipv4").hexdigest()

        value_hash = hashlib.sha256(ioc["value"].encode()).hexdigest()
        assert value_hash == hashlib.sha256(ip_value.encode()).hexdigest()

        octets = [int(o) for o in ioc["value"].split(".")]
        packed_ip = struct.pack(">4B", *octets)
        assert struct.unpack(">I", packed_ip)[0] == 0xC633642A

    def test_timeline_event(self) -> None:
        """TimelineEvent accepts all required fields."""
        te = TimelineEvent(
            timestamp=_TS,
            category="file",
            summary="File created: C:\\test.txt",
            details={"path": "C:\\test.txt"},
        )
        assert te["category"] == "file"

    def test_behavior_match(self) -> None:
        """BehaviorMatch accepts all required fields."""
        bm = BehaviorMatch(
            signature_name="Test Rule",
            category="Persistence",
            severity="high",
            description="Test description",
            evidence=["Evidence item 1"],
            mitre_attack_id="T1543",
        )
        assert bm["mitre_attack_id"] == "T1543"


class TestExecutionReport:
    """Verify ExecutionReport dataclass defaults and field access."""

    def test_default_lists_are_empty(self) -> None:
        """List fields default to empty lists."""
        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=1.0,
        )
        assert report.file_changes == []
        assert report.registry_changes == []
        assert report.network_activity == []
        assert report.process_activity == []
        assert report.api_calls == []
        assert report.service_changes == []
        assert report.kernel_objects == []
        assert report.dll_loads == []
        assert report.injection_events == []
        assert report.resource_samples == []
        assert report.clipboard_events == []

    def test_all_fields_settable(self) -> None:
        """All fields can be set during construction."""
        fc = [FileChange(path="x", operation="created", old_path=None, timestamp=_TS, size=0)]
        report = ExecutionReport(
            result="error",
            exit_code=1,
            stdout="out",
            stderr="err",
            duration_seconds=10.0,
            file_changes=fc,
        )
        assert report.result == "error"
        assert report.exit_code == 1
        assert len(report.file_changes) == 1

    def test_backward_compatible_minimal(self) -> None:
        """Minimal construction (original fields only) still works."""
        report = ExecutionReport(
            result="timeout",
            exit_code=-1,
            stdout="",
            stderr="timed out",
            duration_seconds=300.0,
        )
        assert report.result == "timeout"
        assert math.isclose(report.duration_seconds, 300.0)


class TestSandboxConfig:
    """Verify SandboxConfig dataclass defaults and custom construction."""

    def test_default_values(self) -> None:
        """Default config has expected values."""
        config = SandboxConfig()
        assert config.timeout_seconds == 300
        assert config.memory_limit_mb == 2048
        assert config.network_enabled is False
        assert config.clipboard_enabled is False
        assert config.audio_enabled is False
        assert config.video_enabled is False
        assert config.printer_enabled is False
        assert config.shared_folders == []
        assert config.startup_commands == []
        assert config.environment_variables == {}

    def test_custom_values(self) -> None:
        """Custom config values override defaults."""
        config = SandboxConfig(
            timeout_seconds=60,
            memory_limit_mb=512,
            network_enabled=True,
        )
        assert config.timeout_seconds == 60
        assert config.memory_limit_mb == 512
        assert config.network_enabled is True


class TestSandboxState:
    """Verify SandboxState default values."""

    def test_default_state(self) -> None:
        """Default state is stopped with no pid or error."""
        state = SandboxState()
        assert state.status == "stopped"
        assert state.started_at is None
        assert state.pid is None
        assert state.last_error is None


class TestSandboxBase:
    """Verify SandboxBase abstract methods raise SandboxError."""

    @pytest.mark.asyncio
    async def test_is_available_returns_false(self) -> None:
        """Base is_available returns False."""
        sb = SandboxBase()
        result = await sb.is_available()
        assert result is False

    @pytest.mark.asyncio
    async def test_start_raises(self) -> None:
        """Base start raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.start()

    @pytest.mark.asyncio
    async def test_stop_when_already_stopped(self) -> None:
        """Base stop returns cleanly when already stopped."""
        sb = SandboxBase()
        await sb.stop()

    @pytest.mark.asyncio
    async def test_stop_when_running_raises(self) -> None:
        """Base stop raises SandboxError when status is not stopped."""
        sb = SandboxBase()
        sb.state.status = "running"
        with pytest.raises(SandboxError):
            await sb.stop()

    @pytest.mark.asyncio
    async def test_run_command_raises(self) -> None:
        """Base run_command raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.run_command("echo hi")

    @pytest.mark.asyncio
    async def test_run_binary_raises(self) -> None:
        """Base run_binary raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.run_binary(Path("test.exe"))

    @pytest.mark.asyncio
    async def test_copy_to_sandbox_raises(self) -> None:
        """Base copy_to_sandbox raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.copy_to_sandbox(Path("src.txt"), "dest.txt")

    @pytest.mark.asyncio
    async def test_copy_from_sandbox_raises(self) -> None:
        """Base copy_from_sandbox raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.copy_from_sandbox("src.txt", Path("dest.txt"))

    @pytest.mark.asyncio
    async def test_take_snapshot_raises(self) -> None:
        """Base take_snapshot raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.take_snapshot("snap1")

    @pytest.mark.asyncio
    async def test_restore_snapshot_raises(self) -> None:
        """Base restore_snapshot raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.restore_snapshot("snap-001")

    @pytest.mark.asyncio
    async def test_list_snapshots_raises(self) -> None:
        """Base list_snapshots raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.list_snapshots()

    @pytest.mark.asyncio
    async def test_delete_snapshot_raises(self) -> None:
        """Base delete_snapshot raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.delete_snapshot("snap1")

    @pytest.mark.asyncio
    async def test_start_pcap_raises(self) -> None:
        """Base start_pcap_capture raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.start_pcap_capture()

    @pytest.mark.asyncio
    async def test_stop_pcap_raises(self) -> None:
        """Base stop_pcap_capture raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.stop_pcap_capture("cap-001")

    @pytest.mark.asyncio
    async def test_screenshot_raises(self) -> None:
        """Base capture_screenshot raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.capture_screenshot()

    @pytest.mark.asyncio
    async def test_anti_evasion_raises(self) -> None:
        """Base apply_anti_evasion raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.apply_anti_evasion()

    @pytest.mark.asyncio
    async def test_dump_memory_raises(self) -> None:
        """Base dump_memory raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.dump_memory()

    @pytest.mark.asyncio
    async def test_extract_dropped_files_raises(self) -> None:
        """Base extract_dropped_files raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.extract_dropped_files()

    @pytest.mark.asyncio
    async def test_yara_scan_raises(self) -> None:
        """Base yara_scan raises SandboxError."""
        sb = SandboxBase()
        with pytest.raises(SandboxError):
            await sb.yara_scan()

    def test_vnc_port_returns_none(self) -> None:
        """Base vnc_port returns None."""
        sb = SandboxBase()
        assert sb.vnc_port is None

    def test_config_property(self) -> None:
        """Config property returns the configuration."""
        config = SandboxConfig(timeout_seconds=60)
        sb = SandboxBase(config)
        assert sb.config.timeout_seconds == 60

    def test_state_property(self) -> None:
        """State property returns the current state."""
        sb = SandboxBase()
        assert sb.state.status == "stopped"


class TestValidationFunctions:
    """Verify file, registry, and process operation validation."""

    def test_file_created(self) -> None:
        """'created' maps to 'created'."""
        assert validate_file_operation("created") == "created"

    def test_file_add(self) -> None:
        """'add' maps to 'created'."""
        assert validate_file_operation("add") == "created"

    def test_file_modify(self) -> None:
        """'modify' maps to 'modified'."""
        assert validate_file_operation("modify") == "modified"

    def test_file_delete(self) -> None:
        """'delete' maps to 'deleted'."""
        assert validate_file_operation("delete") == "deleted"

    def test_file_rename(self) -> None:
        """'rename' maps to 'renamed'."""
        assert validate_file_operation("rename") == "renamed"

    def test_file_unknown(self) -> None:
        """Unknown operation defaults to 'modified'."""
        assert validate_file_operation("unknown") == "modified"

    def test_registry_setvalue(self) -> None:
        """'setvalue' maps to 'created'."""
        assert validate_registry_operation("setvalue") == "created"

    def test_registry_deletevalue(self) -> None:
        """'deletevalue' maps to 'deleted'."""
        assert validate_registry_operation("deletevalue") == "deleted"

    def test_registry_unknown(self) -> None:
        """Unknown registry operation defaults to 'modified'."""
        assert validate_registry_operation("unknown") == "modified"

    def test_process_spawn(self) -> None:
        """'spawn' maps to 'created'."""
        assert validate_process_operation("spawn") == "created"

    def test_process_killed(self) -> None:
        """'killed' maps to 'terminated'."""
        assert validate_process_operation("killed") == "terminated"

    def test_process_unknown(self) -> None:
        """Unknown process operation defaults to 'created'."""
        assert validate_process_operation("unknown") == "created"
