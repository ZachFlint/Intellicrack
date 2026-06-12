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


class TestParseFileLogEdgeCases:
    """Adversarial and boundary inputs for :func:`parse_file_log`.

    The parser splits on an unescaped ``|`` and has no quoting, so these
    tests pin the exact documented behaviour for paths that contain the
    delimiter, non-numeric/negative sizes, operation-alias normalisation,
    non-ASCII characters, CRLF line endings, and interleaved valid/malformed
    lines.
    """

    @pytest.mark.asyncio
    async def test_pipe_inside_path_shifts_remainder_into_optional_fields(self, tmp_path: Path) -> None:
        """Confirm an unescaped pipe truncates the path and shifts the remainder.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(tmp_path, "file_monitor.log", f"{_TS}|created|C:\\a|b.txt\n")
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["path"] == "C:\\a"
        assert rec["old_path"] == "b.txt"
        assert rec["operation"] == "created"
        assert rec["size"] is None

    @pytest.mark.asyncio
    async def test_drive_and_unc_colons_survive_in_path(self, tmp_path: Path) -> None:
        """Confirm colon-bearing Windows paths are preserved verbatim.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "file_monitor.log",
            f"{_TS}|created|C:\\Program Files\\App\\a.txt||4096\n",
        )
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["path"] == "C:\\Program Files\\App\\a.txt"
        assert rec["old_path"] is None
        assert rec["size"] == 4096

    @pytest.mark.asyncio
    async def test_non_numeric_and_negative_size_drop_to_none(self, tmp_path: Path) -> None:
        """Confirm a non-``isdigit`` size (including negatives) yields ``None``.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "file_monitor.log",
            f"{_TS}|renamed|C:\\new.txt|C:\\old.txt|-5\n{_TS2}|created|C:\\b.txt||NaN\n",
        )
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 2
        assert result[0]["old_path"] == "C:\\old.txt"
        assert result[0]["size"] is None
        assert result[1]["old_path"] is None
        assert result[1]["size"] is None

    @pytest.mark.asyncio
    async def test_zero_size_parses_as_integer_zero(self, tmp_path: Path) -> None:
        """Confirm the size field value ``"0"`` is stored as integer 0, not None.

        ``"0".isdigit()`` is ``True`` so the parser must store ``0`` rather
        than silently dropping the field to ``None``.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "file_monitor.log",
            f"{_TS}|created|C:\\empty.txt||0\n",
        )
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 1
        assert result[0]["size"] == 0
        assert result[0]["old_path"] is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("raw_op", "expected_op"),
        [
            ("move", "renamed"),
            ("rename", "renamed"),
            ("renamed", "renamed"),
            ("delete", "deleted"),
            ("remove", "deleted"),
            ("unlink", "deleted"),
            ("write", "modified"),
            ("modify", "modified"),
            ("change", "modified"),
            ("update", "modified"),
            ("frobnicate", "modified"),
            ("add", "created"),
            ("new", "created"),
            ("create", "created"),
        ],
    )
    async def test_operation_aliases_normalize(self, tmp_path: Path, raw_op: str, expected_op: str) -> None:
        """Confirm raw operation tokens map to canonical operations.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
            raw_op: The raw operation token written to the log line.
            expected_op: The canonical operation the parser must emit.
        """
        _write_log(tmp_path, "file_monitor.log", f"{_TS}|{raw_op}|C:\\x.txt\n")
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 1
        assert result[0]["operation"] == expected_op

    @pytest.mark.asyncio
    async def test_non_ascii_path_round_trips_unchanged(self, tmp_path: Path) -> None:
        """Confirm UTF-8 file paths with accented and CJK characters survive parsing.

        The log file is written and read with UTF-8 encoding; the parser must
        preserve non-ASCII path strings byte-for-byte without replacement or
        truncation.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        path_value: str = "C:\\Utilisateurs\\Répertoire\\文件.txt"
        _write_log(
            tmp_path,
            "file_monitor.log",
            f"{_TS}|created|{path_value}\n",
        )
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 1
        assert result[0]["path"] == path_value
        assert result[0]["operation"] == "created"
        assert result[0]["old_path"] is None
        assert result[0]["size"] is None

    @pytest.mark.asyncio
    async def test_non_ascii_old_path_round_trips_unchanged(self, tmp_path: Path) -> None:
        """Confirm UTF-8 old_path values survive the rename record format.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        new_path: str = "C:\\Données\\新しい.bin"
        old_path: str = "C:\\Données\\旧い.bin"
        _write_log(
            tmp_path,
            "file_monitor.log",
            f"{_TS}|renamed|{new_path}|{old_path}|512\n",
        )
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 1
        assert result[0]["path"] == new_path
        assert result[0]["old_path"] == old_path
        assert result[0]["size"] == 512

    @pytest.mark.asyncio
    async def test_crlf_line_endings_are_stripped(self, tmp_path: Path) -> None:
        """Confirm Windows CRLF line endings do not corrupt field values.

        ``pathlib.Path.read_text`` splits on both LF and CRLF; the
        subsequent ``.strip()`` removes any residual carriage return
        that might otherwise appear in the final field of a
        CRLF-terminated line.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        body: str = f"{_TS}|created|C:\\file.txt\r\n{_TS2}|deleted|C:\\other.txt\r\n"
        _write_log(tmp_path, "file_monitor.log", body)
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 2
        assert result[0]["path"] == "C:\\file.txt"
        assert result[0]["operation"] == "created"
        assert result[1]["path"] == "C:\\other.txt"
        assert result[1]["operation"] == "deleted"

    @pytest.mark.asyncio
    async def test_empty_path_field_stored_as_empty_string(self, tmp_path: Path) -> None:
        """Confirm an empty third field is stored verbatim as an empty string.

        The parser takes ``parts[2]`` directly; it does not substitute
        ``None`` for empty strings in the required path field.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(tmp_path, "file_monitor.log", f"{_TS}|created|\n")
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert len(result) == 1
        path_value: object = result[0]["path"]
        assert isinstance(path_value, str)
        assert len(path_value) == 0
        assert result[0]["operation"] == "created"

    @pytest.mark.asyncio
    async def test_interleaved_valid_and_malformed_lines_preserve_order(self, tmp_path: Path) -> None:
        """Confirm only well-formed rows survive and original order is kept.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        body = f"{_TS}|created|C:\\first.txt\n{_TS2}|created\n\n{_TS2}|deleted|C:\\second.txt\ngarbage-without-delimiters\n"
        _write_log(tmp_path, "file_monitor.log", body)
        result = await parse_file_log(tmp_path, "file_monitor.log")
        assert [(r["operation"], r["path"]) for r in result] == [
            ("created", "C:\\first.txt"),
            ("deleted", "C:\\second.txt"),
        ]


class TestParseRegistryLogEdgeCases:
    """Adversarial and boundary inputs for :func:`parse_registry_log`.

    Covers non-ASCII keys/values, empty optional fields collapsing to
    ``None``, extra trailing fields beyond the schema being ignored, and a
    pipe embedded in the registry key.
    """

    @pytest.mark.asyncio
    async def test_non_ascii_key_and_value_round_trip(self, tmp_path: Path) -> None:
        """Confirm UTF-8 keys and value data survive parsing unchanged.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "registry_monitor.log",
            f"{_TS}|modified|HKLM\\Softé|Vél|REG_SZ|déta\n",
        )
        result = await parse_registry_log(tmp_path, "registry_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["key"] == "HKLM\\Softé"
        assert rec["value_name"] == "Vél"
        assert rec["value_type"] == "REG_SZ"
        assert rec["value_data"] == "déta"

    @pytest.mark.asyncio
    async def test_extra_trailing_field_is_ignored(self, tmp_path: Path) -> None:
        """Confirm a seventh field beyond the six-field schema is dropped.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "registry_monitor.log",
            f"{_TS}|modified|HKLM\\App|Setting|REG_DWORD|1|SPURIOUS\n",
        )
        result = await parse_registry_log(tmp_path, "registry_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["value_name"] == "Setting"
        assert rec["value_type"] == "REG_DWORD"
        assert rec["value_data"] == "1"

    @pytest.mark.asyncio
    async def test_empty_middle_value_type_collapses_to_none(self, tmp_path: Path) -> None:
        """Confirm an empty ``value_type`` becomes ``None`` while data is kept.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "registry_monitor.log",
            f"{_TS}|setvalue|HKCU\\K|Name||data\n",
        )
        result = await parse_registry_log(tmp_path, "registry_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["operation"] == "created"
        assert rec["value_name"] == "Name"
        assert rec["value_type"] is None
        assert rec["value_data"] == "data"

    @pytest.mark.asyncio
    async def test_pipe_in_key_shifts_value_fields(self, tmp_path: Path) -> None:
        """Confirm an unescaped pipe in the key truncates it and shifts fields.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "registry_monitor.log",
            f"{_TS}|created|HKLM\\Weird|RunKey|ValueName\n",
        )
        result = await parse_registry_log(tmp_path, "registry_monitor.log")
        assert len(result) == 1
        rec = result[0]
        # split on '|' yields [ts, created, "HKLM\\Weird", "RunKey", "ValueName"]
        # so value_name=parts[3] and value_type=parts[4].
        assert rec["key"] == "HKLM\\Weird"
        assert rec["value_name"] == "RunKey"
        assert rec["value_type"] == "ValueName"
        assert rec["value_data"] is None


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


class TestParseNetworkLogEdgeCases:
    """Adversarial and boundary inputs for :func:`parse_network_log`.

    The parser splits on ``|`` and then further parses address:port pairs.
    These tests pin exact behaviour for non-ASCII process names, an address
    token with no port separator, the ``bound`` state mapping to inbound,
    and the ``icmp`` protocol normalization.
    """

    @pytest.mark.asyncio
    async def test_non_ascii_process_name_survives(self, tmp_path: Path) -> None:
        """Confirm a UTF-8 process name in the tenth field round-trips unchanged.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|connect|10.0.0.1:1234|10.0.0.2:80|established|tcp|100|200|999|ré\xedseau.exe\n"
        _write_log(tmp_path, "network_monitor.log", line)
        result = await parse_network_log(tmp_path, "network_monitor.log")
        assert len(result) == 1
        assert result[0]["local_address"] == "10.0.0.1"
        assert result[0]["local_port"] == 1234
        assert result[0]["remote_address"] == "10.0.0.2"
        assert result[0]["remote_port"] == 80
        assert result[0]["bytes_sent"] == 100
        assert result[0]["bytes_received"] == 200

    @pytest.mark.asyncio
    async def test_bound_state_maps_to_inbound(self, tmp_path: Path) -> None:
        """Confirm a ``bound`` state string is classified as inbound.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|bind|0.0.0.0:53|0.0.0.0:0|bound|udp|0|0|500|dns.exe\n"
        _write_log(tmp_path, "network_monitor.log", line)
        result = await parse_network_log(tmp_path, "network_monitor.log")
        assert len(result) == 1
        assert result[0]["direction"] == "inbound"
        assert result[0]["protocol"] == "udp"

    @pytest.mark.asyncio
    async def test_icmp_protocol_label_preserved(self, tmp_path: Path) -> None:
        """Confirm ``icmp`` protocol round-trips to the canonical ``icmp`` literal.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|connect|192.168.0.1:0|192.168.0.2:0|established|icmp|0|512|300|ping.exe\n"
        _write_log(tmp_path, "network_monitor.log", line)
        result = await parse_network_log(tmp_path, "network_monitor.log")
        assert len(result) == 1
        assert result[0]["protocol"] == "icmp"

    @pytest.mark.asyncio
    async def test_address_without_port_yields_zero_port(self, tmp_path: Path) -> None:
        """Confirm an address token with no colon separator yields port zero.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|connect|192.168.0.1|10.0.0.1|established|tcp|0|0|400|x.exe\n"
        _write_log(tmp_path, "network_monitor.log", line)
        result = await parse_network_log(tmp_path, "network_monitor.log")
        assert len(result) == 1
        assert result[0]["local_port"] == 0
        assert result[0]["local_address"] == "192.168.0.1"

    @pytest.mark.asyncio
    async def test_malformed_bytes_fields_default_to_zero(self, tmp_path: Path) -> None:
        """Confirm non-numeric bytes_sent/bytes_received default to zero.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|connect|1.2.3.4:80|5.6.7.8:443|established|tcp|UNKNOWN|NaN|100|svc.exe\n"
        _write_log(tmp_path, "network_monitor.log", line)
        result = await parse_network_log(tmp_path, "network_monitor.log")
        assert len(result) == 1
        assert result[0]["bytes_sent"] == 0
        assert result[0]["bytes_received"] == 0

    @pytest.mark.asyncio
    async def test_interleaved_valid_and_short_lines_are_filtered(self, tmp_path: Path) -> None:
        """Confirm rows below ten fields are dropped while valid rows survive in order.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line1 = f"{_TS}|connect|1.1.1.1:443|2.2.2.2:1024|established|tcp|10|20|111|a.exe\n"
        line2 = f"{_TS2}|too|short\n"
        line3 = f"{_TS2}|listen|0.0.0.0:8080|0.0.0.0:0|listen|tcp|0|0|222|b.exe\n"
        _write_log(tmp_path, "network_monitor.log", line1 + line2 + line3)
        result = await parse_network_log(tmp_path, "network_monitor.log")
        assert len(result) == 2
        assert result[0]["local_port"] == 443
        assert result[1]["direction"] == "inbound"


class TestParseProcessLogEdgeCases:
    """Adversarial and boundary inputs for :func:`parse_process_log`.

    Covers non-ASCII process names, pipe embedded in the command-line
    field (which shifts optional fields), non-numeric pid falling back
    to zero, and all optional fields supplied as empty strings.
    """

    @pytest.mark.asyncio
    async def test_non_ascii_process_name_survives(self, tmp_path: Path) -> None:
        """Confirm a UTF-8 process name in the name field round-trips unchanged.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "process_monitor.log",
            f"{_TS}|created|1234|procéssus.exe\n",
        )
        result = await parse_process_log(tmp_path, "process_monitor.log")
        assert len(result) == 1
        assert result[0]["name"] == "procéssus.exe"
        assert result[0]["pid"] == 1234

    @pytest.mark.asyncio
    async def test_pipe_in_command_line_shifts_optional_fields(self, tmp_path: Path) -> None:
        """Confirm an unescaped pipe in the command-line field shifts subsequent fields.

        The parser uses a naive split on ``|``, so a pipe inside the
        command line causes the remainder to be interpreted as subsequent
        optional columns. This test pins that documented behaviour.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|created|42|cmd.exe|C:\\cmd.exe|cmd.exe /c echo|hello|500|0\n"
        _write_log(tmp_path, "process_monitor.log", line)
        result = await parse_process_log(tmp_path, "process_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["pid"] == 42
        assert rec["name"] == "cmd.exe"
        assert rec["path"] == "C:\\cmd.exe"
        assert rec["command_line"] == "cmd.exe /c echo"

    @pytest.mark.asyncio
    async def test_non_numeric_pid_defaults_to_zero(self, tmp_path: Path) -> None:
        """Confirm a non-numeric pid string produces a pid of zero via safe_int.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(
            tmp_path,
            "process_monitor.log",
            f"{_TS}|created|NOT_A_PID|svc.exe\n",
        )
        result = await parse_process_log(tmp_path, "process_monitor.log")
        assert len(result) == 1
        assert result[0]["pid"] == 0
        assert result[0]["name"] == "svc.exe"

    @pytest.mark.asyncio
    async def test_empty_optional_fields_via_explicit_pipes_are_none(self, tmp_path: Path) -> None:
        """Confirm empty optional field strings collapse to ``None``.

        A row with eight pipe-separated fields where path/cmd/ppid/exit are
        all empty strings should yield ``None`` for all four optional columns.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|created|9999|blank.exe||||\n"
        _write_log(tmp_path, "process_monitor.log", line)
        result = await parse_process_log(tmp_path, "process_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["path"] is None
        assert rec["command_line"] is None
        assert rec["parent_pid"] is None
        assert rec["exit_code"] is None

    @pytest.mark.asyncio
    async def test_interleaved_valid_and_malformed_rows_preserve_order(self, tmp_path: Path) -> None:
        """Confirm only well-formed rows survive and their relative order is kept.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        body = f"{_TS}|created|111|first.exe\ngarbage\n{_TS2}|terminated|222|second.exe\n"
        _write_log(tmp_path, "process_monitor.log", body)
        result = await parse_process_log(tmp_path, "process_monitor.log")
        assert len(result) == 2
        assert result[0]["pid"] == 111
        assert result[0]["operation"] == "created"
        assert result[1]["pid"] == 222
        assert result[1]["operation"] == "terminated"


class TestParseServiceLogEdgeCases:
    """Adversarial and boundary inputs for :func:`parse_service_log`.

    Covers non-ASCII display names, a pipe embedded in the binary path
    (which shifts the start_type field), and rows below the six-field
    minimum being dropped.
    """

    @pytest.mark.asyncio
    async def test_non_ascii_display_name_survives(self, tmp_path: Path) -> None:
        """Confirm a UTF-8 display name round-trips unchanged.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|created|SvcA|服务程序|C:\\svc.exe|manual\n"
        _write_log(tmp_path, "service_monitor.log", line)
        result = await parse_service_log(tmp_path, "service_monitor.log")
        assert len(result) == 1
        assert result[0]["display_name"] == "服务程序"
        assert result[0]["service_name"] == "SvcA"
        assert result[0]["start_type"] == "manual"

    @pytest.mark.asyncio
    async def test_pipe_in_binary_path_shifts_start_type(self, tmp_path: Path) -> None:
        """Confirm an unescaped pipe in binary_path shifts the start_type field.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|created|SvcB|My Svc|C:\\Windows|system32\\svc.exe|auto\n"
        _write_log(tmp_path, "service_monitor.log", line)
        result = await parse_service_log(tmp_path, "service_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["binary_path"] == "C:\\Windows"
        assert rec["start_type"] == "system32\\svc.exe"

    @pytest.mark.asyncio
    async def test_short_rows_below_six_fields_are_dropped(self, tmp_path: Path) -> None:
        """Confirm a row with fewer than six fields is silently dropped.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        short_line = f"{_TS}|created|SvcX|Display\n"
        valid_line = f"{_TS2}|deleted|SvcY|Good Svc|C:\\y.exe|disabled\n"
        _write_log(tmp_path, "service_monitor.log", short_line + valid_line)
        result = await parse_service_log(tmp_path, "service_monitor.log")
        assert len(result) == 1
        assert result[0]["service_name"] == "SvcY"
        assert result[0]["operation"] == "deleted"


class TestParseKernelObjectLogEdgeCases:
    """Adversarial and boundary inputs for :func:`parse_kernel_object_log`.

    Covers non-ASCII object names, an unescaped pipe inside the name field
    (which shifts pid and process_name), and a non-numeric pid defaulting to
    zero via ``safe_int``.
    """

    @pytest.mark.asyncio
    async def test_non_ascii_object_name_survives(self, tmp_path: Path) -> None:
        """Confirm a UTF-8 kernel object name round-trips unchanged.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|Mutex|Global\\événement|1024|kernel.exe|opened\n"
        _write_log(tmp_path, "kernel_object_monitor.log", line)
        result = await parse_kernel_object_log(tmp_path, "kernel_object_monitor.log")
        assert len(result) == 1
        assert result[0]["name"] == "Global\\événement"
        assert result[0]["object_type"] == "Mutex"
        assert result[0]["operation"] == "opened"

    @pytest.mark.asyncio
    async def test_pipe_in_object_name_shifts_pid_field(self, tmp_path: Path) -> None:
        """Confirm an unescaped pipe in the name field shifts pid and process_name.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|Semaphore|Weird|Name|2048|target.exe|created\n"
        _write_log(tmp_path, "kernel_object_monitor.log", line)
        result = await parse_kernel_object_log(tmp_path, "kernel_object_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["object_type"] == "Semaphore"
        assert rec["name"] == "Weird"
        assert rec["pid"] == 0
        assert rec["process_name"] == "2048"

    @pytest.mark.asyncio
    async def test_non_numeric_pid_defaults_to_zero(self, tmp_path: Path) -> None:
        """Confirm a non-numeric pid token in the pid field becomes zero.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|Event|MyEvent|NOT_A_PID|proc.exe|opened\n"
        _write_log(tmp_path, "kernel_object_monitor.log", line)
        result = await parse_kernel_object_log(tmp_path, "kernel_object_monitor.log")
        assert len(result) == 1
        assert result[0]["pid"] == 0
        assert result[0]["process_name"] == "proc.exe"

    @pytest.mark.asyncio
    async def test_short_rows_below_six_fields_are_dropped(self, tmp_path: Path) -> None:
        """Confirm rows with fewer than six fields are silently dropped.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        short = f"{_TS}|Mutex|OnlyFive\n"
        valid = f"{_TS2}|Event|Global\\GoodEvent|500|host.exe|created\n"
        _write_log(tmp_path, "kernel_object_monitor.log", short + valid)
        result = await parse_kernel_object_log(tmp_path, "kernel_object_monitor.log")
        assert len(result) == 1
        assert result[0]["name"] == "Global\\GoodEvent"


class TestParseDllLogEdgeCases:
    """Adversarial and boundary inputs for :func:`parse_dll_log`.

    Covers the extended 8-column format that F-0019 introduces, non-ASCII
    DLL paths, zero-valued extension columns from legacy 6-column records,
    and short rows below the six-field minimum being dropped.
    """

    @pytest.mark.asyncio
    async def test_extended_eight_column_format_parsed(self, tmp_path: Path) -> None:
        """Confirm the extended F-0019 eight-column record populates event_id and payload_schema.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|1200|explorer.exe||0x0|0|4097|ImageId,ProcessId,ImageBase\n"
        _write_log(tmp_path, "dll_monitor.log", line)
        result = await parse_dll_log(tmp_path, "dll_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["pid"] == 1200
        assert not rec["dll_path"]
        assert rec["event_id"] == 4097
        assert rec["payload_schema"] == "ImageId,ProcessId,ImageBase"

    @pytest.mark.asyncio
    async def test_legacy_six_column_event_id_zero_schema_empty(self, tmp_path: Path) -> None:
        """Confirm a legacy six-column record yields event_id=0 and empty payload_schema.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|500|legacy.exe|C:\\Windows\\ntdll.dll|0x77000000|512000\n"
        _write_log(tmp_path, "dll_monitor.log", line)
        result = await parse_dll_log(tmp_path, "dll_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["event_id"] == 0
        assert not rec["payload_schema"]
        assert rec["dll_path"] == "C:\\Windows\\ntdll.dll"
        assert rec["size"] == 512000

    @pytest.mark.asyncio
    async def test_non_ascii_dll_path_survives(self, tmp_path: Path) -> None:
        """Confirm a UTF-8 DLL path round-trips without corruption.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|700|app.exe|C:\\Programme\\Bibliothèque.dll|0xABCD0000|32768\n"
        _write_log(tmp_path, "dll_monitor.log", line)
        result = await parse_dll_log(tmp_path, "dll_monitor.log")
        assert len(result) == 1
        assert result[0]["dll_path"] == "C:\\Programme\\Bibliothèque.dll"

    @pytest.mark.asyncio
    async def test_short_rows_below_six_fields_are_dropped(self, tmp_path: Path) -> None:
        """Confirm rows with fewer than six fields are silently dropped.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        short = f"{_TS}|300|only.exe|C:\\short.dll\n"
        valid = f"{_TS2}|400|full.exe|C:\\full.dll|0x1000|8192\n"
        _write_log(tmp_path, "dll_monitor.log", short + valid)
        result = await parse_dll_log(tmp_path, "dll_monitor.log")
        assert len(result) == 1
        assert result[0]["pid"] == 400
        assert result[0]["dll_path"] == "C:\\full.dll"


class TestParseInjectionLogEdgeCases:
    """Adversarial and boundary inputs for :func:`parse_injection_log`.

    Covers an empty api_calls field (yielding an empty list), a single
    api_call entry with no commas, non-ASCII target names, and rows below
    the minimum being dropped.
    """

    @pytest.mark.asyncio
    async def test_empty_api_calls_field_yields_empty_list(self, tmp_path: Path) -> None:
        """Confirm an empty api_calls field produces an empty list.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|500|injector.exe|1234|explorer.exe|SetWindowsHookEx|\n"
        _write_log(tmp_path, "injection_monitor.log", line)
        result = await parse_injection_log(tmp_path, "injection_monitor.log")
        assert len(result) == 1
        assert result[0]["api_calls"] == []

    @pytest.mark.asyncio
    async def test_single_api_call_without_comma(self, tmp_path: Path) -> None:
        """Confirm a single api_call with no commas produces a one-element list.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|500|injector.exe|1234|explorer.exe|NtWriteVirtualMemory|NtWriteVirtualMemory\n"
        _write_log(tmp_path, "injection_monitor.log", line)
        result = await parse_injection_log(tmp_path, "injection_monitor.log")
        assert len(result) == 1
        assert result[0]["api_calls"] == ["NtWriteVirtualMemory"]
        assert result[0]["injection_type"] == "NtWriteVirtualMemory"

    @pytest.mark.asyncio
    async def test_non_ascii_target_name_survives(self, tmp_path: Path) -> None:
        """Confirm a UTF-8 target process name round-trips unchanged.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|100|src.exe|200|cibleé.exe|CreateRemoteThread|VirtualAllocEx\n"
        _write_log(tmp_path, "injection_monitor.log", line)
        result = await parse_injection_log(tmp_path, "injection_monitor.log")
        assert len(result) == 1
        assert result[0]["target_name"] == "cibleé.exe"
        assert result[0]["source_pid"] == 100
        assert result[0]["target_pid"] == 200

    @pytest.mark.asyncio
    async def test_whitespace_trimmed_from_api_call_entries(self, tmp_path: Path) -> None:
        """Confirm leading and trailing whitespace is stripped from each api_call token.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|500|src.exe|600|dst.exe|DLL|  VirtualAllocEx ,  WriteProcessMemory  , CreateRemoteThread\n"
        _write_log(tmp_path, "injection_monitor.log", line)
        result = await parse_injection_log(tmp_path, "injection_monitor.log")
        assert len(result) == 1
        assert result[0]["api_calls"] == [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ]

    @pytest.mark.asyncio
    async def test_short_rows_below_seven_fields_are_dropped(self, tmp_path: Path) -> None:
        """Confirm rows with fewer than seven fields are silently dropped.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        short = f"{_TS}|500|src.exe|600\n"
        valid = f"{_TS2}|100|a.exe|200|b.exe|CreateRemoteThread|VirtualAllocEx\n"
        _write_log(tmp_path, "injection_monitor.log", short + valid)
        result = await parse_injection_log(tmp_path, "injection_monitor.log")
        assert len(result) == 1
        assert result[0]["source_pid"] == 100


class TestParseResourceLogEdgeCases:
    """Adversarial and boundary inputs for :func:`parse_resource_log`.

    Covers non-parseable float tokens (inf, NaN, alphabetic) defaulting to
    0.0, extremely large integer values for disk/net bytes, and rows below
    the minimum being silently dropped.
    """

    @pytest.mark.asyncio
    async def test_alphabetic_cpu_and_memory_tokens_default_to_zero(self, tmp_path: Path) -> None:
        """Confirm alphabetic float tokens default to 0.0 via safe_float.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|UNKNOWN|N/A|0|0|0|0\n"
        _write_log(tmp_path, "resource_monitor.log", line)
        result = await parse_resource_log(tmp_path, "resource_monitor.log")
        assert len(result) == 1
        assert math.isclose(result[0]["cpu_percent"], 0.0, abs_tol=1e-9)
        assert math.isclose(result[0]["memory_mb"], 0.0, abs_tol=1e-9)

    @pytest.mark.asyncio
    async def test_very_large_disk_bytes_parse_correctly(self, tmp_path: Path) -> None:
        """Confirm very large integer byte counts (> 2^32) survive without overflow.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        large: int = 2**40
        line = f"{_TS}|12.5|1024.0|{large}|{large}|0|0\n"
        _write_log(tmp_path, "resource_monitor.log", line)
        result = await parse_resource_log(tmp_path, "resource_monitor.log")
        assert len(result) == 1
        assert result[0]["disk_read_bytes"] == large
        assert result[0]["disk_write_bytes"] == large

    @pytest.mark.asyncio
    async def test_short_rows_below_seven_fields_are_dropped(self, tmp_path: Path) -> None:
        """Confirm rows with fewer than seven pipe-separated fields are silently dropped.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        short = f"{_TS}|10.0|256.0|0|0\n"
        valid = f"{_TS2}|5.0|128.0|1024|2048|512|256\n"
        _write_log(tmp_path, "resource_monitor.log", short + valid)
        result = await parse_resource_log(tmp_path, "resource_monitor.log")
        assert len(result) == 1
        assert math.isclose(result[0]["cpu_percent"], 5.0)
        assert result[0]["disk_read_bytes"] == 1024


class TestParseClipboardLogEdgeCases:
    """Adversarial and boundary inputs for :func:`parse_clipboard_log`.

    Covers non-ASCII content previews, a pipe embedded in the content
    preview (which shifts pid and process_name), and an empty content
    preview field producing an empty string.
    """

    @pytest.mark.asyncio
    async def test_non_ascii_content_preview_survives(self, tmp_path: Path) -> None:
        """Confirm a UTF-8 content preview round-trips unchanged.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|write|CF_UNICODETEXT|ユーザー|8|300|notepad.exe\n"
        _write_log(tmp_path, "clipboard_monitor.log", line)
        result = await parse_clipboard_log(tmp_path, "clipboard_monitor.log")
        assert len(result) == 1
        assert result[0]["content_preview"] == "ユーザー"
        assert result[0]["format"] == "CF_UNICODETEXT"
        assert result[0]["operation"] == "write"

    @pytest.mark.asyncio
    async def test_pipe_in_content_preview_shifts_remaining_fields(self, tmp_path: Path) -> None:
        """Confirm an unescaped pipe inside the content preview shifts pid/process fields.

        The parser splits on ``|`` naively. For the input line:
        ``ts|read|CF_TEXT|hello|world|6|500|clip.exe``
        the extra ``|`` shifts the positional schema so parts[3]=``hello``
        is the content_preview, parts[4]=``world`` becomes size_bytes
        (non-numeric -> 0), parts[5]=``6`` becomes pid, and
        parts[6]=``500`` becomes process_name. This test pins that
        documented behaviour so regressions are detectable.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|read|CF_TEXT|hello|world|6|500|clip.exe\n"
        _write_log(tmp_path, "clipboard_monitor.log", line)
        result = await parse_clipboard_log(tmp_path, "clipboard_monitor.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["content_preview"] == "hello"
        assert rec["size_bytes"] == 0
        assert rec["pid"] == 6
        assert rec["process_name"] == "500"

    @pytest.mark.asyncio
    async def test_empty_content_preview_becomes_empty_string(self, tmp_path: Path) -> None:
        """Confirm an empty content_preview field is stored as an empty string.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|read|CF_BITMAP||0|400|paint.exe\n"
        _write_log(tmp_path, "clipboard_monitor.log", line)
        result = await parse_clipboard_log(tmp_path, "clipboard_monitor.log")
        assert len(result) == 1
        assert not result[0]["content_preview"]

    @pytest.mark.asyncio
    async def test_short_rows_below_seven_fields_are_dropped(self, tmp_path: Path) -> None:
        """Confirm rows with fewer than seven fields are silently dropped.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        short = f"{_TS}|read|CF_TEXT|data|12\n"
        valid = f"{_TS2}|write|CF_OEMTEXT|info|4|600|word.exe\n"
        _write_log(tmp_path, "clipboard_monitor.log", short + valid)
        result = await parse_clipboard_log(tmp_path, "clipboard_monitor.log")
        assert len(result) == 1
        assert result[0]["operation"] == "write"
        assert result[0]["process_name"] == "word.exe"


class TestParseApiTraceLogEdgeCases:
    """Adversarial and boundary inputs for :func:`parse_api_trace_log`.

    Covers non-ASCII api_names and process names, semicolons inside
    individual argument tokens (which the parser treats as argument
    delimiters), a pipe embedded in the arguments field shifting return_value,
    and rows below the minimum being dropped.
    """

    @pytest.mark.asyncio
    async def test_non_ascii_api_name_and_process_survive(self, tmp_path: Path) -> None:
        """Confirm UTF-8 api_name and process_name round-trip unchanged.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|procéss.exe|800|测试Api|modéle.dll|arg1|0x0\n"
        _write_log(tmp_path, "api_trace.log", line)
        result = await parse_api_trace_log(tmp_path, "api_trace.log")
        assert len(result) == 1
        assert result[0]["process_name"] == "procéss.exe"
        assert result[0]["api_name"] == "测试Api"
        assert result[0]["module"] == "modéle.dll"

    @pytest.mark.asyncio
    async def test_semicolons_in_argument_tokens_split_correctly(self, tmp_path: Path) -> None:
        """Confirm the arguments field is split on semicolons and filtered.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|app.exe|900|NtCreateFile|ntdll.dll|\\??\\C:\\foo.txt;0x80000000;0x0|STATUS_SUCCESS\n"
        _write_log(tmp_path, "api_trace.log", line)
        result = await parse_api_trace_log(tmp_path, "api_trace.log")
        assert len(result) == 1
        assert result[0]["arguments"] == [
            "\\??\\C:\\foo.txt",
            "0x80000000",
            "0x0",
        ]
        assert result[0]["return_value"] == "STATUS_SUCCESS"

    @pytest.mark.asyncio
    async def test_non_numeric_pid_defaults_to_zero(self, tmp_path: Path) -> None:
        """Confirm a non-numeric pid token produces zero via safe_int.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|app.exe|BADPID|Sleep|kernel32.dll|100|0x0\n"
        _write_log(tmp_path, "api_trace.log", line)
        result = await parse_api_trace_log(tmp_path, "api_trace.log")
        assert len(result) == 1
        assert result[0]["pid"] == 0
        assert result[0]["api_name"] == "Sleep"

    @pytest.mark.asyncio
    async def test_short_rows_below_seven_fields_are_dropped(self, tmp_path: Path) -> None:
        """Confirm rows with fewer than seven fields are silently dropped.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        short = f"{_TS}|app.exe|100|SomeApi\n"
        valid = f"{_TS2}|svc.exe|200|RegOpenKey|advapi32.dll|HKLM|0x0\n"
        _write_log(tmp_path, "api_trace.log", short + valid)
        result = await parse_api_trace_log(tmp_path, "api_trace.log")
        assert len(result) == 1
        assert result[0]["api_name"] == "RegOpenKey"
        assert result[0]["return_value"] == "0x0"

    @pytest.mark.asyncio
    async def test_pipe_in_arguments_field_shifts_return_value(self, tmp_path: Path) -> None:
        """Confirm an unescaped pipe inside the arguments field shifts return_value.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        line = f"{_TS}|app.exe|100|CreateMutex|kernel32.dll|arg1|arg2|0xHANDLE\n"
        _write_log(tmp_path, "api_trace.log", line)
        result = await parse_api_trace_log(tmp_path, "api_trace.log")
        assert len(result) == 1
        rec = result[0]
        assert rec["arguments"] == ["arg1"]
        assert rec["return_value"] == "arg2"


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
