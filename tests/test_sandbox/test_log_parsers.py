# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the consolidated sandbox log parsers.

Each parser is exercised by writing a real on-disk log file under a
temporary shared-folder root (``<tmp_path>/logs/<name>``), then calling
the parser and asserting on its return value. No mocking is used; the
parsers read the same files the in-guest agents write at runtime.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any, Final, Protocol

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

from intellicrack.sandbox import log_parsers


class _LogParser(Protocol):
    """Callable Protocol for the consolidated sandbox log parsers."""

    def __call__(
        self,
        shared_folder: Path | None,
        log_name: str = ...,
    ) -> Coroutine[Any, Any, list[Any]]:
        """Parse a log file under ``<shared_folder>/logs/<log_name>``.

        Args:
            shared_folder: Sandbox shared folder root, or ``None``.
            log_name: Log file name relative to ``<shared_folder>/logs/``.

        Returns:
            Coroutine[Any, Any, list[Any]]: Coroutine that resolves to a
            list of parsed records (concrete TypedDict varies per parser).
        """
        ...


parse_file_log = log_parsers.parse_file_log
parse_registry_log = log_parsers.parse_registry_log
parse_network_log = log_parsers.parse_network_log
parse_process_log = log_parsers.parse_process_log
parse_service_log = log_parsers.parse_service_log
parse_kernel_object_log = log_parsers.parse_kernel_object_log
parse_dll_log = log_parsers.parse_dll_log
parse_injection_log = log_parsers.parse_injection_log
parse_resource_log = log_parsers.parse_resource_log
parse_clipboard_log = log_parsers.parse_clipboard_log
parse_api_trace_log = log_parsers.parse_api_trace_log
read_log_lines = log_parsers.read_log_lines
FILE_LOG_MIN_PARTS = log_parsers.FILE_LOG_MIN_PARTS
REGISTRY_LOG_MIN_PARTS = log_parsers.REGISTRY_LOG_MIN_PARTS
NETWORK_LOG_MIN_PARTS = log_parsers.NETWORK_LOG_MIN_PARTS
PROCESS_LOG_MIN_PARTS = log_parsers.PROCESS_LOG_MIN_PARTS
SERVICE_LOG_MIN_PARTS = log_parsers.SERVICE_LOG_MIN_PARTS
KERNEL_LOG_MIN_PARTS = log_parsers.KERNEL_LOG_MIN_PARTS
DLL_LOG_MIN_PARTS = log_parsers.DLL_LOG_MIN_PARTS
INJECTION_LOG_MIN_PARTS = log_parsers.INJECTION_LOG_MIN_PARTS
RESOURCE_LOG_MIN_PARTS = log_parsers.RESOURCE_LOG_MIN_PARTS
CLIPBOARD_LOG_MIN_PARTS = log_parsers.CLIPBOARD_LOG_MIN_PARTS
API_LOG_MIN_PARTS = log_parsers.API_LOG_MIN_PARTS


_TS: Final[str] = "2026-04-25T10:00:00"
_TS2: Final[str] = "2026-04-25T10:00:01"


def _write_log(folder: Path, name: str, content: str) -> None:
    """Write ``content`` to ``<folder>/logs/<name>``.

    Args:
        folder: Shared-folder root.
        name: Log file name.
        content: Body to write to the log file.
    """
    logs_dir = folder / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / name).write_text(content, encoding="utf-8")


class TestReadLogLines:
    """Tests for :func:`read_log_lines`."""

    @pytest.mark.asyncio
    async def test_returns_empty_when_shared_folder_is_none(self) -> None:
        """Confirm the helper returns an empty list when the folder is unset."""
        result = await read_log_lines(None, "any.log")
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_when_file_missing(self, tmp_path: Path) -> None:
        """Confirm the helper returns an empty list when the log file does not exist.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        result = await read_log_lines(tmp_path, "missing.log")
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_stripped_non_empty_lines(self, tmp_path: Path) -> None:
        """Confirm the helper strips whitespace and skips blank lines.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(tmp_path, "x.log", "  alpha  \n\n  beta\n   \n  gamma  \n")
        result = await read_log_lines(tmp_path, "x.log")
        assert result == ["alpha", "beta", "gamma"]


class TestParseFileLog:
    """Tests for :func:`parse_file_log`."""

    @pytest.mark.asyncio
    async def test_parses_minimal_three_field_lines(self, tmp_path: Path) -> None:
        """Confirm three-field rows produce records without ``old_path``/``size``.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "file_monitor.log",
            f"{_TS}|created|C:\\Temp\\a.txt\n",
        )
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 1
        assert result[0]["path"] == "C:\\Temp\\a.txt"
        assert result[0]["operation"] == "created"
        assert result[0]["timestamp"] == _TS
        assert result[0]["old_path"] is None
        assert result[0]["size"] is None

    @pytest.mark.asyncio
    async def test_extracts_old_path_and_size(self, tmp_path: Path) -> None:
        """Confirm the optional ``old_path`` and ``size`` fields are picked up.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "file_monitor.log",
            f"{_TS}|renamed|C:\\new.txt|C:\\old.txt|1024\n",
        )
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 1
        assert result[0]["old_path"] == "C:\\old.txt"
        assert result[0]["size"] == 1024

    @pytest.mark.asyncio
    async def test_skips_lines_below_min_parts(self, tmp_path: Path) -> None:
        """Confirm rows with too few fields are dropped silently.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "file_monitor.log",
            f"{_TS}|created\n{_TS2}|created|C:\\b.txt\n",
        )
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 1
        assert result[0]["path"] == "C:\\b.txt"

    def test_min_parts_constant_value(self) -> None:
        """Confirm the public constant matches the schema requirement."""
        assert FILE_LOG_MIN_PARTS == 3


class TestParseRegistryLog:
    """Tests for :func:`parse_registry_log`."""

    @pytest.mark.asyncio
    async def test_parses_minimal_three_field_lines(self, tmp_path: Path) -> None:
        """Confirm three-field rows yield records with ``None`` value details.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "registry_monitor.log",
            f"{_TS}|created|HKLM\\SOFTWARE\\Run\n",
        )
        result = await parse_registry_log(tmp_path, "registry_monitor.log")
        assert len(result) == 1
        assert result[0]["key"] == "HKLM\\SOFTWARE\\Run"
        assert result[0]["operation"] == "created"
        assert result[0]["value_name"] is None

    @pytest.mark.asyncio
    async def test_extracts_full_value_record(self, tmp_path: Path) -> None:
        """Confirm a six-field row produces a fully populated record.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "registry_monitor.log",
            f"{_TS}|modified|HKLM\\SOFTWARE\\App|Setting|REG_SZ|enabled\n",
        )
        result = await parse_registry_log(tmp_path, "registry_monitor.log")
        assert len(result) == 1
        assert result[0]["value_name"] == "Setting"
        assert result[0]["value_type"] == "REG_SZ"
        assert result[0]["value_data"] == "enabled"

    def test_min_parts_constant_value(self) -> None:
        """Confirm the public constant matches the schema requirement."""
        assert REGISTRY_LOG_MIN_PARTS == 3


class TestParseNetworkLog:
    """Tests for :func:`parse_network_log`."""

    @pytest.mark.asyncio
    async def test_full_ten_field_row(self, tmp_path: Path) -> None:
        """Confirm a complete ten-field row produces a populated record.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|connect|192.168.1.10:49152|203.0.113.5:443|established|tcp|1024|2048|500|payload.exe\n"
        _write_log(tmp_path, "network_monitor.log", line)
        result = await parse_network_log(tmp_path, "network_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["protocol"] == "tcp"
        assert rec["direction"] == "outbound"
        assert rec["local_address"] == "192.168.1.10"
        assert rec["local_port"] == 49152
        assert rec["remote_address"] == "203.0.113.5"
        assert rec["remote_port"] == 443
        assert rec["bytes_sent"] == 1024
        assert rec["bytes_received"] == 2048

    @pytest.mark.asyncio
    async def test_listen_state_is_inbound(self, tmp_path: Path) -> None:
        """Confirm a ``listen`` state is mapped to inbound direction.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|listen|0.0.0.0:8080|0.0.0.0:0|listen|tcp|0|0|600|svc.exe\n"
        _write_log(tmp_path, "network_monitor.log", line)
        result = await parse_network_log(tmp_path, "network_monitor.log")
        assert result[0]["direction"] == "inbound"

    @pytest.mark.asyncio
    async def test_ipv6_bracketed_address(self, tmp_path: Path) -> None:
        """Confirm IPv6 ``[ipv6]:port`` addresses split correctly.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|connect|[fe80::1]:443|[2001:db8::5]:80|established|tcp|10|20|700|net.exe\n"
        _write_log(tmp_path, "network_monitor.log", line)
        result = await parse_network_log(tmp_path, "network_monitor.log")
        rec = result[0]
        assert rec["local_address"] == "fe80::1"
        assert rec["local_port"] == 443
        assert rec["remote_address"] == "2001:db8::5"
        assert rec["remote_port"] == 80

    @pytest.mark.asyncio
    async def test_unknown_protocol_falls_back_to_other(self, tmp_path: Path) -> None:
        """Confirm an unknown protocol token is normalized to ``other``.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|connect|10.0.0.1:5000|10.0.0.2:6000|established|sctp|0|0|800|x.exe\n"
        _write_log(tmp_path, "network_monitor.log", line)
        result = await parse_network_log(tmp_path, "network_monitor.log")
        assert result[0]["protocol"] == "other"

    @pytest.mark.asyncio
    async def test_drops_short_lines(self, tmp_path: Path) -> None:
        """Confirm rows with fewer than ten fields are dropped silently.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(tmp_path, "network_monitor.log", f"{_TS}|connect|too-short\n")
        result = await parse_network_log(tmp_path, "network_monitor.log")
        assert result == []

    def test_min_parts_constant_value(self) -> None:
        """Confirm the public constant matches the ten-field schema."""
        assert NETWORK_LOG_MIN_PARTS == 10


class TestParseProcessLog:
    """Tests for :func:`parse_process_log`."""

    @pytest.mark.asyncio
    async def test_minimal_four_field_row(self, tmp_path: Path) -> None:
        """Confirm a four-field row produces a record with ``None`` extras.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "process_monitor.log",
            f"{_TS}|created|1234|payload.exe\n",
        )
        result = await parse_process_log(tmp_path, "process_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["pid"] == 1234
        assert rec["name"] == "payload.exe"
        assert rec["path"] is None
        assert rec["command_line"] is None
        assert rec["parent_pid"] is None
        assert rec["exit_code"] is None

    @pytest.mark.asyncio
    async def test_full_eight_field_row(self, tmp_path: Path) -> None:
        """Confirm an eight-field row populates all optional fields.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|created|1234|payload.exe|C:\\payload.exe|payload.exe -x|500|0\n"
        _write_log(tmp_path, "process_monitor.log", line)
        result = await parse_process_log(tmp_path, "process_monitor.log")
        rec = result[0]
        assert rec["path"] == "C:\\payload.exe"
        assert rec["command_line"] == "payload.exe -x"
        assert rec["parent_pid"] == 500
        assert rec["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_negative_exit_code_parses(self, tmp_path: Path) -> None:
        """Confirm signed integer exit codes round-trip correctly.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|terminated|999|crash.exe|C:\\crash.exe|crash.exe|100|-1\n"
        _write_log(tmp_path, "process_monitor.log", line)
        result = await parse_process_log(tmp_path, "process_monitor.log")
        assert result[0]["exit_code"] == -1
        assert result[0]["operation"] == "terminated"

    def test_min_parts_constant_value(self) -> None:
        """Confirm the public constant matches the schema requirement."""
        assert PROCESS_LOG_MIN_PARTS == 4


class TestParseServiceLog:
    """Tests for :func:`parse_service_log`."""

    @pytest.mark.asyncio
    async def test_full_six_field_row(self, tmp_path: Path) -> None:
        """Confirm a six-field service record is parsed correctly.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|created|MalSvc|Malicious Svc|C:\\m.exe|auto\n"
        _write_log(tmp_path, "service_monitor.log", line)
        result = await parse_service_log(tmp_path, "service_monitor.log")
        rec = result[0]
        assert rec["service_name"] == "MalSvc"
        assert rec["display_name"] == "Malicious Svc"
        assert rec["binary_path"] == "C:\\m.exe"
        assert rec["start_type"] == "auto"
        assert rec["operation"] == "created"

    def test_min_parts_constant_value(self) -> None:
        """Confirm the public constant matches the schema requirement."""
        assert SERVICE_LOG_MIN_PARTS == 6


class TestParseKernelObjectLog:
    """Tests for :func:`parse_kernel_object_log`."""

    @pytest.mark.asyncio
    async def test_full_six_field_row(self, tmp_path: Path) -> None:
        """Confirm a six-field kernel-object record is parsed correctly.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|Mutex|Global\\X|500|payload.exe|created\n"
        _write_log(tmp_path, "kernel_object_monitor.log", line)
        result = await parse_kernel_object_log(tmp_path, "kernel_object_monitor.log")
        rec = result[0]
        assert rec["object_type"] == "Mutex"
        assert rec["name"] == "Global\\X"
        assert rec["pid"] == 500
        assert rec["process_name"] == "payload.exe"
        assert rec["operation"] == "created"

    def test_min_parts_constant_value(self) -> None:
        """Confirm the public constant matches the schema requirement."""
        assert KERNEL_LOG_MIN_PARTS == 6


class TestParseDllLog:
    """Tests for :func:`parse_dll_log`."""

    @pytest.mark.asyncio
    async def test_full_six_field_row(self, tmp_path: Path) -> None:
        """Confirm a six-field DLL load record is parsed correctly.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|500|payload.exe|C:\\Windows\\kernel32.dll|0x7FFE0000|65536\n"
        _write_log(tmp_path, "dll_monitor.log", line)
        result = await parse_dll_log(tmp_path, "dll_monitor.log")
        rec = result[0]
        assert rec["pid"] == 500
        assert rec["process_name"] == "payload.exe"
        assert rec["dll_path"] == "C:\\Windows\\kernel32.dll"
        assert rec["base_address"] == "0x7FFE0000"
        assert rec["size"] == 65536

    def test_min_parts_constant_value(self) -> None:
        """Confirm the public constant matches the schema requirement."""
        assert DLL_LOG_MIN_PARTS == 6


class TestParseInjectionLog:
    """Tests for :func:`parse_injection_log`."""

    @pytest.mark.asyncio
    async def test_full_seven_field_row(self, tmp_path: Path) -> None:
        """Confirm a seven-field injection record is parsed correctly.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|500|payload.exe|1234|explorer.exe|CreateRemoteThread|VirtualAllocEx, WriteProcessMemory, CreateRemoteThread\n"
        _write_log(tmp_path, "injection_monitor.log", line)
        result = await parse_injection_log(tmp_path, "injection_monitor.log")
        rec = result[0]
        assert rec["source_pid"] == 500
        assert rec["target_pid"] == 1234
        assert rec["target_name"] == "explorer.exe"
        assert rec["injection_type"] == "CreateRemoteThread"
        assert rec["api_calls"] == [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ]

    def test_min_parts_constant_value(self) -> None:
        """Confirm the public constant matches the schema requirement."""
        assert INJECTION_LOG_MIN_PARTS == 7


class TestParseResourceLog:
    """Tests for :func:`parse_resource_log`."""

    @pytest.mark.asyncio
    async def test_full_seven_field_row(self, tmp_path: Path) -> None:
        """Confirm a seven-field resource sample is parsed correctly.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|45.5|256.25|1024|2048|512|256\n"
        _write_log(tmp_path, "resource_monitor.log", line)
        result = await parse_resource_log(tmp_path, "resource_monitor.log")
        rec = result[0]
        assert math.isclose(rec["cpu_percent"], 45.5)
        assert math.isclose(rec["memory_mb"], 256.25)
        assert rec["disk_read_bytes"] == 1024
        assert rec["disk_write_bytes"] == 2048
        assert rec["net_sent_bytes"] == 512
        assert rec["net_recv_bytes"] == 256

    @pytest.mark.asyncio
    async def test_blank_numerics_default_to_zero(self, tmp_path: Path) -> None:
        """Confirm empty numeric fields default to zero rather than raising.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|||0|0|0|0\n"
        _write_log(tmp_path, "resource_monitor.log", line)
        result = await parse_resource_log(tmp_path, "resource_monitor.log")
        rec = result[0]
        assert math.isclose(rec["cpu_percent"], 0.0, abs_tol=1e-9)
        assert math.isclose(rec["memory_mb"], 0.0, abs_tol=1e-9)

    def test_min_parts_constant_value(self) -> None:
        """Confirm the public constant matches the schema requirement."""
        assert RESOURCE_LOG_MIN_PARTS == 7


class TestParseClipboardLog:
    """Tests for :func:`parse_clipboard_log`."""

    @pytest.mark.asyncio
    async def test_full_seven_field_row(self, tmp_path: Path) -> None:
        """Confirm a seven-field clipboard event is parsed correctly.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|read|CF_TEXT|secret|6|500|payload.exe\n"
        _write_log(tmp_path, "clipboard_monitor.log", line)
        result = await parse_clipboard_log(tmp_path, "clipboard_monitor.log")
        rec = result[0]
        assert rec["operation"] == "read"
        assert rec["format"] == "CF_TEXT"
        assert rec["content_preview"] == "secret"
        assert rec["size_bytes"] == 6
        assert rec["pid"] == 500
        assert rec["process_name"] == "payload.exe"

    def test_min_parts_constant_value(self) -> None:
        """Confirm the public constant matches the schema requirement."""
        assert CLIPBOARD_LOG_MIN_PARTS == 7


class TestParseApiTraceLog:
    """Tests for :func:`parse_api_trace_log`."""

    @pytest.mark.asyncio
    async def test_full_seven_field_row(self, tmp_path: Path) -> None:
        """Confirm a seven-field API call record is parsed correctly.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|payload.exe|500|CreateFileW|kernel32.dll|C:\\file.txt;GENERIC_WRITE|0x100\n"
        _write_log(tmp_path, "api_trace.log", line)
        result = await parse_api_trace_log(tmp_path, "api_trace.log")
        rec = result[0]
        assert rec["process_name"] == "payload.exe"
        assert rec["pid"] == 500
        assert rec["api_name"] == "CreateFileW"
        assert rec["module"] == "kernel32.dll"
        assert rec["arguments"] == ["C:\\file.txt", "GENERIC_WRITE"]
        assert rec["return_value"] == "0x100"

    @pytest.mark.asyncio
    async def test_empty_arguments_field(self, tmp_path: Path) -> None:
        """Confirm an empty arguments field yields an empty list.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|payload.exe|500|GetTickCount|kernel32.dll||0x12345\n"
        _write_log(tmp_path, "api_trace.log", line)
        result = await parse_api_trace_log(tmp_path, "api_trace.log")
        assert result[0]["arguments"] == []

    def test_min_parts_constant_value(self) -> None:
        """Confirm the public constant matches the schema requirement."""
        assert API_LOG_MIN_PARTS == 7


class TestQemuFilenameAliases:
    """Tests confirming both Windows and QEMU log file names work."""

    @pytest.mark.asyncio
    async def test_qemu_file_changes_alias(self, tmp_path: Path) -> None:
        """Confirm parsers honour the QEMU-side ``file_changes.log`` filename.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(tmp_path, "file_changes.log", f"{_TS}|created|C:\\Temp\\x\n")
        result = await parse_file_log(tmp_path, "file_changes.log")
        assert len(result) == 1
        assert result[0]["path"] == "C:\\Temp\\x"

    @pytest.mark.asyncio
    async def test_qemu_registry_changes_alias(self, tmp_path: Path) -> None:
        """Confirm parsers honour the QEMU-side ``registry_changes.log`` filename.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "registry_changes.log",
            f"{_TS}|modified|HKCU\\Software\\App\n",
        )
        result = await parse_registry_log(tmp_path, "registry_changes.log")
        assert len(result) == 1
        assert result[0]["key"] == "HKCU\\Software\\App"

    @pytest.mark.asyncio
    async def test_qemu_network_activity_alias(self, tmp_path: Path) -> None:
        """Confirm parsers honour the QEMU-side ``network_activity.log`` filename.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|connect|10.0.0.1:5000|10.0.0.2:6000|established|udp|1|2|3|x.exe\n"
        _write_log(tmp_path, "network_activity.log", line)
        result = await parse_network_log(tmp_path, "network_activity.log")
        assert len(result) == 1
        assert result[0]["protocol"] == "udp"

    @pytest.mark.asyncio
    async def test_qemu_process_activity_alias(self, tmp_path: Path) -> None:
        """Confirm parsers honour the QEMU-side ``process_activity.log`` filename.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "process_activity.log",
            f"{_TS}|created|7777|svc.exe\n",
        )
        result = await parse_process_log(tmp_path, "process_activity.log")
        assert len(result) == 1
        assert result[0]["pid"] == 7777


class TestMissingFolderBehaviour:
    """Tests confirming graceful behaviour when no shared folder is provided."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "parser",
        [
            parse_file_log,
            parse_registry_log,
            parse_network_log,
            parse_process_log,
            parse_service_log,
            parse_kernel_object_log,
            parse_dll_log,
            parse_injection_log,
            parse_resource_log,
            parse_clipboard_log,
            parse_api_trace_log,
        ],
    )
    async def test_returns_empty_for_none_folder(self, parser: _LogParser) -> None:
        """Confirm every parser tolerates a ``None`` shared folder.

        Args:
            parser: The parser callable being exercised.
        """
        result = await parser(None, "any.log")
        assert result == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("parser", "log_name"),
        [
            (parse_file_log, "file_monitor.log"),
            (parse_registry_log, "registry_monitor.log"),
            (parse_network_log, "network_monitor.log"),
            (parse_process_log, "process_monitor.log"),
            (parse_service_log, "service_monitor.log"),
            (parse_kernel_object_log, "kernel_object_monitor.log"),
            (parse_dll_log, "dll_monitor.log"),
            (parse_injection_log, "injection_monitor.log"),
            (parse_resource_log, "resource_monitor.log"),
            (parse_clipboard_log, "clipboard_monitor.log"),
            (parse_api_trace_log, "api_trace.log"),
        ],
    )
    async def test_returns_empty_when_log_missing(
        self,
        tmp_path: Path,
        parser: _LogParser,
        log_name: str,
    ) -> None:
        """Confirm every parser returns an empty list when its log file is absent.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
            parser: The parser callable being exercised.
            log_name: Default log file name expected by the parser.
        """
        result = await parser(tmp_path, log_name)
        assert result == []
