# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage for the guest-summary parser in the sandbox telemetry blocker.

``parse_blocking_result`` reads the pipe-delimited record the guest script
prints after editing its hosts file and firewall. These tests feed it
captured-output strings and check what a caller would act on: a parsed
summary only when the record is whole, and ``None`` whenever the guest did not
demonstrably report what it did.
"""

from __future__ import annotations

import pytest

from intellicrack.sandbox.telemetry_blocking import parse_blocking_result


MARKER = "INTELLICRACK_TELEMETRY_BLOCK"


def test_output_without_marker_line_yields_none() -> None:
    """Output holding no marker line at all is reported as unreadable."""
    noise = "Windows PowerShell\r\nCopyright (C) Microsoft Corporation.\r\nblocking started\r\n"

    assert parse_blocking_result(noise) is None
    assert parse_blocking_result("") is None


def test_unrelated_lines_before_marker_are_skipped() -> None:
    """Lines that do not start with the marker are ignored, not parsed."""
    output = (
        "banner line | with | pipes\r\n"
        f"not{MARKER}|9|9|netsh|C:\\decoy\\hosts|\r\n"
        f"  {MARKER}|31|2|netsecurity|C:\\Windows\\System32\\drivers\\etc\\hosts|\r\n"
    )

    summary = parse_blocking_result(output)

    assert summary == {
        "hosts_entries": 31,
        "firewall_rules": 2,
        "firewall_backend": "netsecurity",
        "hosts_path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "problems": [],
    }


def test_problems_field_is_split_into_a_list() -> None:
    """The trailing problems field becomes a list of trimmed messages."""
    output = f"{MARKER}|0|1|netsh|C:\\h|first failed ;; second failed\n"

    summary = parse_blocking_result(output)

    assert summary is not None
    assert summary["hosts_entries"] == 0
    assert summary["firewall_rules"] == 1
    assert summary["problems"] == ["first failed", "second failed"]


@pytest.mark.parametrize(
    "record",
    [
        f"{MARKER}|1|2|netsh|C:\\h",
        f"{MARKER}|1|2|netsh|C:\\h||extra",
        f"{MARKER}|",
    ],
    ids=["one-field-short", "one-field-extra", "marker-without-fields"],
)
def test_wrong_field_count_yields_none(record: str) -> None:
    """A marker record with the wrong number of fields is rejected.

    Args:
        record: A marker line whose field count differs from the contract.
    """
    assert parse_blocking_result(record + "\r\n") is None


@pytest.mark.parametrize(
    "record",
    [
        f"{MARKER}|many|2|netsh|C:\\h|",
        f"{MARKER}|1|-2|netsh|C:\\h|",
        f"{MARKER}||2|netsh|C:\\h|",
    ],
    ids=["word-hosts-count", "negative-rules-count", "empty-hosts-count"],
)
def test_non_numeric_count_yields_none(record: str) -> None:
    """A count that is not a run of digits invalidates the whole record.

    Args:
        record: A marker line with one garbled count field.
    """
    assert parse_blocking_result(record + "\r\n") is None
