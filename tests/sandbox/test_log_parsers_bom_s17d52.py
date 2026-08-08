# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for S17-D52: BOM-prefixed monitor logs corrupt the first record.

The in-guest monitor scripts write their log files with PowerShell's default
``Out-File``/``Add-Content`` encoding, which stamps a UTF-8 byte-order-mark
(``EF BB BF``) at the start of every log file: ``file_changes.log``,
``network_activity.log``, ``clipboard_monitor.log``, ``injection_monitor.log``,
``resource_monitor.log`` and the other monitor logs all begin this way on a
real Windows 11 QEMU guest. Before the fix, :func:`read_log_lines` decoded the
file as plain ``utf-8``, so the BOM character (``\ufeff``) survived into the
first field of the first parsed record of every log-backed tab.

These tests write real on-disk log files carrying a genuine UTF-8 BOM
(the literal ``EF BB BF`` byte sequence, not just the decoded character) in
the exact pipe-delimited schema each in-guest monitor emits, then exercise
every ``parse_*`` function in :mod:`intellicrack.sandbox.log_parsers` against
those files. No mocking is used: the parsers read the same bytes the guest
monitors would have written.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.sandbox.log_parsers import (
    parse_api_trace_log,
    parse_clipboard_log,
    parse_dll_log,
    parse_file_log,
    parse_injection_log,
    parse_kernel_object_log,
    parse_network_log,
    parse_process_log,
    parse_registry_log,
    parse_resource_log,
    parse_service_log,
    read_log_lines,
)


if TYPE_CHECKING:
    from pathlib import Path

_UTF8_BOM: Final[bytes] = b"\xef\xbb\xbf"
_BOM_CHAR: Final[str] = "\ufeff"

# Timestamps mirroring the exact corrupted values observed on the live
# Windows 11 QEMU guest run that surfaced S17-D52.
_TS_SPACE: Final[str] = "2026-08-07 15:19:47"
_TS_ISO: Final[str] = "2026-08-07T15:19:53.0641788+00:00"


def _write_bom_log(folder: Path, name: str, body: str) -> None:
    """Write ``body`` to ``<folder>/logs/<name>`` prefixed with a UTF-8 BOM.

    The BOM is written as the literal ``EF BB BF`` byte sequence that
    PowerShell's ``Out-File``/``Add-Content`` cmdlets stamp onto every
    monitor log, not merely the decoded ``\ufeff`` character, so the test
    exercises the identical byte layout produced on a real guest.

    Args:
        folder: Shared-folder root the parser will read from.
        name: Log file name under ``<folder>/logs/``.
        body: Text content to write after the BOM, encoded as UTF-8.
    """
    logs_dir = folder / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / name).write_bytes(_UTF8_BOM + body.encode("utf-8"))


def _assert_no_bom(record: dict[str, Any]) -> None:
    """Assert that no string field (or string list element) carries a BOM.

    Each string field, and each string element of a list field, is
    asserted to be free of the ``\ufeff`` BOM character.

    Args:
        record: A parsed monitor-log record as a plain mapping.
    """
    for key, value in record.items():
        if isinstance(value, str):
            assert _BOM_CHAR not in value, f"field {key!r} carries a BOM: {value!r}"
        elif isinstance(value, list):
            items = cast("list[object]", value)
            for item in items:
                if isinstance(item, str):
                    assert _BOM_CHAR not in item, f"field {key!r} carries a BOM in a list element: {item!r}"


class TestReadLogLinesStripsBom:
    """Tests confirming :func:`read_log_lines` never returns a BOM-prefixed line."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_first_line_is_clean(self, tmp_path: Path) -> None:
        """Confirm the BOM does not survive into the first returned line.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_bom_log(tmp_path, "diag.log", f"{_TS_ISO}|some diagnostic text\n")
        lines = await read_log_lines(tmp_path, "diag.log")
        assert len(lines) == 1
        assert _BOM_CHAR not in lines[0]
        assert lines[0] == f"{_TS_ISO}|some diagnostic text"

    @pytest.mark.asyncio
    async def test_bom_prefixed_multi_line_log_only_first_line_affected(self, tmp_path: Path) -> None:
        """Confirm subsequent lines are unaffected and the first is still cleaned.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        body = f"{_TS_SPACE}|first record\n{_TS_ISO}|second record\n"
        _write_bom_log(tmp_path, "diag.log", body)
        lines = await read_log_lines(tmp_path, "diag.log")
        assert lines == [f"{_TS_SPACE}|first record", f"{_TS_ISO}|second record"]
        assert all(_BOM_CHAR not in line for line in lines)


class TestParseFileLogBom:
    """Tests confirming :func:`parse_file_log` strips the BOM from ``file_changes.log``."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_file_changes_log(self, tmp_path: Path) -> None:
        """Confirm the timestamp field of the first record has no BOM.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_bom_log(tmp_path, "file_changes.log", f"{_TS_SPACE}|created|C:\\Temp\\a.txt\n")
        result = await parse_file_log(tmp_path, "file_changes.log")
        assert len(result) == 1
        assert result[0]["timestamp"] == _TS_SPACE
        _assert_no_bom(dict(result[0]))


class TestParseRegistryLogBom:
    """Tests confirming :func:`parse_registry_log` strips the BOM."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_registry_changes_log(self, tmp_path: Path) -> None:
        """Confirm the timestamp field of the first record has no BOM.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_bom_log(tmp_path, "registry_changes.log", f"{_TS_ISO}|created|HKLM\\SOFTWARE\\Run\n")
        result = await parse_registry_log(tmp_path, "registry_changes.log")
        assert len(result) == 1
        assert result[0]["timestamp"] == _TS_ISO
        _assert_no_bom(dict(result[0]))


class TestParseNetworkLogBom:
    """Tests confirming :func:`parse_network_log` strips the BOM from ``network_activity.log``."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_network_activity_log(self, tmp_path: Path) -> None:
        """Confirm the timestamp field of the first record has no BOM.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS_ISO}|connect|192.168.1.10:49152|203.0.113.5:443|established|tcp|1024|2048|500|payload.exe\n"
        _write_bom_log(tmp_path, "network_activity.log", line)
        result = await parse_network_log(tmp_path, "network_activity.log")
        assert len(result) == 1
        assert result[0]["timestamp"] == _TS_ISO
        _assert_no_bom(dict(result[0]))


class TestParseProcessLogBom:
    """Tests confirming :func:`parse_process_log` strips the BOM from ``process_activity.log``."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_process_activity_log(self, tmp_path: Path) -> None:
        """Confirm the timestamp field of the first record has no BOM.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_bom_log(tmp_path, "process_activity.log", f"{_TS_SPACE}|created|1234|payload.exe\n")
        result = await parse_process_log(tmp_path, "process_activity.log")
        assert len(result) == 1
        assert result[0]["timestamp"] == _TS_SPACE
        _assert_no_bom(dict(result[0]))


class TestParseServiceLogBom:
    """Tests confirming :func:`parse_service_log` strips the BOM."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_service_monitor_log(self, tmp_path: Path) -> None:
        """Confirm the timestamp field of the first record has no BOM.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_bom_log(tmp_path, "service_monitor.log", f"{_TS_ISO}|created|MalSvc|Malicious Svc|C:\\m.exe|auto\n")
        result = await parse_service_log(tmp_path, "service_monitor.log")
        assert len(result) == 1
        assert result[0]["timestamp"] == _TS_ISO
        _assert_no_bom(dict(result[0]))


class TestParseKernelObjectLogBom:
    """Tests confirming :func:`parse_kernel_object_log` strips the BOM."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_kernel_object_monitor_log(self, tmp_path: Path) -> None:
        """Confirm the timestamp field of the first record has no BOM.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_bom_log(tmp_path, "kernel_object_monitor.log", f"{_TS_SPACE}|Mutex|Global\\X|500|payload.exe|created\n")
        result = await parse_kernel_object_log(tmp_path, "kernel_object_monitor.log")
        assert len(result) == 1
        assert result[0]["timestamp"] == _TS_SPACE
        _assert_no_bom(dict(result[0]))


class TestParseDllLogBom:
    """Tests confirming :func:`parse_dll_log` strips the BOM."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_dll_monitor_log(self, tmp_path: Path) -> None:
        """Confirm the timestamp field of the first record has no BOM.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS_ISO}|500|payload.exe|C:\\Windows\\kernel32.dll|0x7FFE0000|65536\n"
        _write_bom_log(tmp_path, "dll_monitor.log", line)
        result = await parse_dll_log(tmp_path, "dll_monitor.log")
        assert len(result) == 1
        assert result[0]["timestamp"] == _TS_ISO
        _assert_no_bom(dict(result[0]))


class TestParseInjectionLogBom:
    """Tests confirming :func:`parse_injection_log` strips the BOM from ``injection_monitor.log``."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_injection_monitor_log(self, tmp_path: Path) -> None:
        """Confirm the timestamp field of the first record has no BOM.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS_SPACE}|500|payload.exe|1234|explorer.exe|CreateRemoteThread|VirtualAllocEx,WriteProcessMemory\n"
        _write_bom_log(tmp_path, "injection_monitor.log", line)
        result = await parse_injection_log(tmp_path, "injection_monitor.log")
        assert len(result) == 1
        assert result[0]["timestamp"] == _TS_SPACE
        _assert_no_bom(dict(result[0]))


class TestParseResourceLogBom:
    """Tests confirming :func:`parse_resource_log` strips the BOM from ``resource_monitor.log``."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_resource_monitor_log(self, tmp_path: Path) -> None:
        """Confirm the timestamp field of the first record has no BOM.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_bom_log(tmp_path, "resource_monitor.log", f"{_TS_ISO}|45.5|256.25|1024|2048|512|256\n")
        result = await parse_resource_log(tmp_path, "resource_monitor.log")
        assert len(result) == 1
        assert result[0]["timestamp"] == _TS_ISO
        _assert_no_bom(dict(result[0]))


class TestParseClipboardLogBom:
    """Tests confirming :func:`parse_clipboard_log` strips the BOM from ``clipboard_monitor.log``."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_clipboard_monitor_log(self, tmp_path: Path) -> None:
        """Confirm the timestamp field of the first record has no BOM.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_bom_log(tmp_path, "clipboard_monitor.log", f"{_TS_SPACE}|read|CF_TEXT|secret|6|500|payload.exe\n")
        result = await parse_clipboard_log(tmp_path, "clipboard_monitor.log")
        assert len(result) == 1
        assert result[0]["timestamp"] == _TS_SPACE
        _assert_no_bom(dict(result[0]))


class TestParseApiTraceLogBom:
    """Tests confirming :func:`parse_api_trace_log` strips the BOM from ``api_trace.log``."""

    @pytest.mark.asyncio
    async def test_bom_prefixed_api_trace_log(self, tmp_path: Path) -> None:
        """Confirm the timestamp field of the first record has no BOM.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS_ISO}|payload.exe|500|CreateFileW|kernel32.dll|C:\\file.txt;GENERIC_WRITE|0x100\n"
        _write_bom_log(tmp_path, "api_trace.log", line)
        result = await parse_api_trace_log(tmp_path, "api_trace.log")
        assert len(result) == 1
        assert result[0]["timestamp"] == _TS_ISO
        _assert_no_bom(dict(result[0]))
