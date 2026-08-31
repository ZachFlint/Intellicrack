# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit7 F-0019 parser tests for the extended ``dll_monitor.log`` format.

Validates the host-side parser:

* preserves legacy 6-column rows verbatim,
* surfaces the new ``event_id`` / ``payload_schema`` columns when the
  remediated PowerShell monitor emits them,
* tolerates rows that mix the two layouts.

These tests run on every platform because the parser is pure Python.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from intellicrack.sandbox.log_parsers import parse_dll_log


if TYPE_CHECKING:
    from pathlib import Path


def _write_log(shared_folder: Path, lines: list[str]) -> None:
    """Materialise a ``dll_monitor.log`` under the simulated shared folder.

    Args:
        shared_folder: Synthetic sandbox shared-folder root.
        lines: Pipe-delimited log lines to emit (no trailing newlines
            required).
    """
    logs_dir = shared_folder / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "dll_monitor.log").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def test_legacy_six_column_row_still_parses(tmp_path: Path) -> None:
    """Pre-audit7 log rows with 6 columns must still parse.

    Args:
        tmp_path: Pytest-provided temp directory used as the sandbox
            shared-folder root.
    """
    _write_log(
        tmp_path,
        [
            "2026-05-14T10:00:00.000+00:00|1234|notepad|C:\\Windows\\System32\\user32.dll|0x7FFE000000|123456",
        ],
    )

    events = asyncio.run(parse_dll_log(tmp_path))
    assert len(events) == 1
    event = events[0]
    assert event["timestamp"] == "2026-05-14T10:00:00.000+00:00"
    assert event["pid"] == 1234
    assert event["process_name"] == "notepad"
    assert event["dll_path"] == "C:\\Windows\\System32\\user32.dll"
    assert event["base_address"] == "0x7FFE000000"
    assert event["size"] == 123456
    assert event["event_id"] == 0
    assert not event["payload_schema"]


def test_extended_eight_column_parsed_row(tmp_path: Path) -> None:
    """A parsed event with the new trailing columns must surface them.

    Args:
        tmp_path: Pytest-provided temp directory used as the sandbox
            shared-folder root.
    """
    _write_log(
        tmp_path,
        [
            "2026-05-14T10:00:01.000+00:00|2345|powershell|C:\\Windows\\System32\\kernel32.dll|0x7FFE100000|654321|5|",
        ],
    )

    events = asyncio.run(parse_dll_log(tmp_path))
    assert len(events) == 1
    event = events[0]
    assert event["dll_path"] == "C:\\Windows\\System32\\kernel32.dll"
    assert event["event_id"] == 5
    assert not event["payload_schema"]


def test_extended_eight_column_unparsed_row_carries_event_id_and_schema(
    tmp_path: Path,
) -> None:
    """F-0019: rows from the unparsed branch carry the diagnostic fields.

    The dll_monitor.ps1 image-load handler now emits a structured record
    with ``image_path`` empty plus ``event_id`` and ``payload_schema``
    when the payload field names do not match the known list. The
    parser must surface those fields to the report consumer.

    Args:
        tmp_path: Pytest-provided temp directory used as the sandbox
            shared-folder root.
    """
    _write_log(
        tmp_path,
        [
            "2026-05-14T10:00:02.000+00:00|4096|chrome||0x0|0|17|ImagePath,EventTime,SomethingExotic",
        ],
    )

    events = asyncio.run(parse_dll_log(tmp_path))
    assert len(events) == 1
    event = events[0]
    assert not event["dll_path"]
    assert event["event_id"] == 17
    assert event["payload_schema"] == "ImagePath,EventTime,SomethingExotic"
    assert event["pid"] == 4096
    assert event["process_name"] == "chrome"


def test_mixed_legacy_and_extended_rows(tmp_path: Path) -> None:
    """Legacy and extended rows must coexist in the same log.

    Args:
        tmp_path: Pytest-provided temp directory used as the sandbox
            shared-folder root.
    """
    _write_log(
        tmp_path,
        [
            "2026-05-14T10:00:00.000+00:00|11|svchost|C:\\Windows\\System32\\rpcrt4.dll|0xA00000|500000",
            "2026-05-14T10:00:01.000+00:00|22|chrome||0x0|0|99|FieldA,FieldB",
            "2026-05-14T10:00:02.000+00:00|33|edge|C:\\Windows\\System32\\ntdll.dll|0xB00000|600000|5|",
        ],
    )

    events = asyncio.run(parse_dll_log(tmp_path))
    assert len(events) == 3
    assert events[0]["dll_path"] == "C:\\Windows\\System32\\rpcrt4.dll"
    assert events[0]["event_id"] == 0
    assert not events[1]["dll_path"]
    assert events[1]["event_id"] == 99
    assert events[1]["payload_schema"] == "FieldA,FieldB"
    assert events[2]["dll_path"] == "C:\\Windows\\System32\\ntdll.dll"
    assert events[2]["event_id"] == 5


def test_malformed_short_row_is_skipped(tmp_path: Path) -> None:
    """Rows with fewer than 6 columns must be skipped silently.

    Args:
        tmp_path: Pytest-provided temp directory used as the sandbox
            shared-folder root.
    """
    _write_log(
        tmp_path,
        [
            "2026-05-14|44|partial|too|few",
            "2026-05-14T10:00:00.000+00:00|55|ok|C:\\path.dll|0x0|0",
        ],
    )

    events = asyncio.run(parse_dll_log(tmp_path))
    assert len(events) == 1
    assert events[0]["pid"] == 55
