# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-gate tests for sandbox analysis functions (Group 06 Wave 5).

Covers:
  S12-01 — ``extract_iocs`` correctly identifies SHA1 hashes (40-char hex
            strings) embedded in file change paths; the SHA1 regex pattern
            is exercised independently of SHA256/MD5 patterns.
  S12-02 — ``generate_timeline`` resource category is missing (PD-011
            RED-BY-DESIGN): a ``ResourceSample`` in the report does not
            produce a ``"resource"``-category event in the timeline.
"""

from __future__ import annotations

import pytest

from intellicrack.sandbox.analysis import extract_iocs, generate_timeline
from intellicrack.sandbox.base import ExecutionReport, FileChange, ResourceSample


_SHA1_KNOWN: str = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
_SHA256_KNOWN: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _report_with_file_changes(file_changes: list[FileChange]) -> ExecutionReport:
    """Build an ExecutionReport containing only the given file changes.

    Args:
        file_changes: List of FileChange entries to include.

    Returns:
        ExecutionReport: Minimal report with the supplied file changes.
    """
    return ExecutionReport(
        result="success",
        exit_code=0,
        stdout="",
        stderr="",
        duration_seconds=0.0,
        file_changes=file_changes,
    )


def _report_with_resource_samples(resource_samples: list[ResourceSample]) -> ExecutionReport:
    """Build an ExecutionReport containing only the given resource samples.

    Args:
        resource_samples: List of ResourceSample entries to include.

    Returns:
        ExecutionReport: Minimal report with the supplied resource samples.
    """
    return ExecutionReport(
        result="success",
        exit_code=0,
        stdout="",
        stderr="",
        duration_seconds=0.0,
        resource_samples=resource_samples,
    )


def _report_with_all(
    file_changes: list[FileChange],
    resource_samples: list[ResourceSample],
) -> ExecutionReport:
    """Build an ExecutionReport with both file changes and resource samples.

    Args:
        file_changes: List of FileChange entries to include.
        resource_samples: List of ResourceSample entries to include.

    Returns:
        ExecutionReport: Minimal report combining both data sets.
    """
    return ExecutionReport(
        result="success",
        exit_code=0,
        stdout="",
        stderr="",
        duration_seconds=0.0,
        file_changes=file_changes,
        resource_samples=resource_samples,
    )


class TestExtractIocsSha1:
    """Gate for S12-01: extract_iocs identifies SHA1 hashes in file paths."""

    def test_sha1_in_file_path_yields_sha1_ioc_type(self) -> None:
        r"""A 40-char hex stem in a file path is extracted as 'sha1'.

        Oracle: ``_SHA1_PATTERN = re.compile(r'\b([a-fA-F0-9]{40})\b')``
        matches the 40-char SHA1 prefix; ``_add_ioc("sha1", val, ...)`` is
        called when the pattern fires and the deduplication guard passes.
        Known oracle value: SHA1 of the empty string =
        ``da39a3ee5e6b4b0d3255bfef95601890afd80709``.

        Mutation: removing the SHA1 branch from ``_scan_text`` means no
        ``sha1`` IOC is produced, failing the assertion.
        """
        path_with_sha1 = rf"C:\Malware\{_SHA1_KNOWN}.bin"
        report = _report_with_file_changes([
            FileChange(
                path=path_with_sha1,
                operation="created",
                old_path=None,
                timestamp="2026-01-01T00:00:00Z",
                size=None,
            ),
        ])

        iocs = extract_iocs(report)
        sha1_iocs = [i for i in iocs if i["ioc_type"] == "sha1"]

        assert len(sha1_iocs) >= 1, f"Expected at least one 'sha1' IOC for path containing {_SHA1_KNOWN!r}; got {iocs!r}"
        sha1_values = [i["value"] for i in sha1_iocs]
        assert _SHA1_KNOWN in sha1_values, f"SHA1 value {_SHA1_KNOWN!r} not found; got sha1 values {sha1_values!r}"

    def test_sha1_source_field_is_file_changes(self) -> None:
        """IOC extracted from a file_change path has source='file_changes'.

        Oracle: ``extract_iocs`` calls ``_scan_text(change['path'], 'file_changes')``
        for each file change.  Mutation: using a different source label fails
        the equality assertion.
        """
        path_with_sha1 = rf"C:\Temp\{_SHA1_KNOWN}"
        report = _report_with_file_changes([
            FileChange(
                path=path_with_sha1,
                operation="modified",
                old_path=None,
                timestamp="2026-01-01T00:00:00Z",
                size=512,
            ),
        ])

        iocs = extract_iocs(report)
        sha1_iocs = [i for i in iocs if i["ioc_type"] == "sha1" and i["value"] == _SHA1_KNOWN]
        assert len(sha1_iocs) == 1, f"Expected exactly one sha1 IOC; got {sha1_iocs!r}"
        assert sha1_iocs[0]["source"] == "file_changes", f"Expected source='file_changes'; got {sha1_iocs[0]['source']!r}"

    def test_sha1_deduplicated_when_same_hash_in_two_paths(self) -> None:
        """The same SHA1 hash from two different file paths appears only once.

        Oracle: ``extract_iocs`` maintains a ``seen: set[tuple[str, str]]``
        keyed on ``(ioc_type, value)``; the second occurrence is skipped.
        Mutation: removing deduplication produces two sha1 entries with the
        same value, failing the ``len == 1`` assertion.
        """
        report = _report_with_file_changes([
            FileChange(
                path=rf"C:\first\{_SHA1_KNOWN}.dll",
                operation="created",
                old_path=None,
                timestamp="2026-01-01T00:00:01Z",
                size=None,
            ),
            FileChange(
                path=rf"C:\second\{_SHA1_KNOWN}.exe",
                operation="modified",
                old_path=None,
                timestamp="2026-01-01T00:00:02Z",
                size=None,
            ),
        ])

        iocs = extract_iocs(report)
        sha1_iocs = [i for i in iocs if i["ioc_type"] == "sha1"]
        assert len(sha1_iocs) == 1, f"SHA1 hash from two paths must be deduplicated; got {sha1_iocs!r}"

    def test_sha1_not_emitted_when_same_prefix_already_classified_as_sha256(self) -> None:
        """SHA1 is suppressed when the 64-char SHA256 with that prefix is already seen.

        Oracle: the deduplication guard
        ``if ("sha256", val + val[:24]) not in seen`` prevents a SHA1 value
        from being re-emitted when the longer hash that starts with the same
        40 chars has already been classified as SHA256.

        Mutation: removing the guard causes both SHA256 and SHA1 IOCs to
        be emitted for the same prefix, failing the ``len == 0`` assertion.
        """
        sha1_prefix = _SHA1_KNOWN
        sha256_with_sha1_prefix = sha1_prefix + sha1_prefix[:24]
        report = _report_with_file_changes([
            FileChange(
                path=rf"C:\hashes\{sha256_with_sha1_prefix}.bin",
                operation="created",
                old_path=None,
                timestamp="2026-01-01T00:00:00Z",
                size=None,
            ),
        ])

        iocs = extract_iocs(report)
        sha256_found = [i for i in iocs if i["ioc_type"] == "sha256"]
        sha1_found = [i for i in iocs if i["ioc_type"] == "sha1" and i["value"] == sha1_prefix]

        assert sha256_found, f"SHA256 IOC should be extracted for 64-char hex; got {iocs!r}"
        assert not sha1_found, f"SHA1 should be suppressed when SHA256 with same prefix is already seen; got {sha1_found!r}"


class TestGenerateTimelineResourceCategory:
    """Gate for S12-02: generate_timeline resource category is absent (PD-011 RED-BY-DESIGN).

    The production code has no ``_timeline_add_resource_events`` handler.
    This test asserts the CORRECT CONTRACT (resource events in the report
    must produce events with category='resource') but currently FAILS because
    the handler does not exist.  The gate is permanently RED until PD-011 is
    fixed.
    """

    def test_resource_sample_produces_resource_category_event(self) -> None:
        """ResourceSample in report must yield a 'resource' category event.

        Oracle: every other category (file, registry, network, process, api,
        service, kernel, dll, injection, clipboard) has a dedicated
        ``_timeline_add_*_events`` helper; the resource category should
        follow the same pattern.  ``ResourceSample`` contains a timestamp
        field which the timeline can use as the event timestamp.

        PD-011 RED-BY-DESIGN: ``generate_timeline`` has no resource handler.
        The function iterates only 10 named ``if _should_include("X"):``
        blocks; "resource" is absent.  Mutation: adding a
        ``_timeline_add_resource_events`` handler that appends events with
        ``category='resource'`` turns this gate green.
        """
        report = _report_with_resource_samples([
            ResourceSample(
                timestamp="2026-01-01T00:00:00Z",
                cpu_percent=45.0,
                memory_mb=256.0,
                disk_read_bytes=1024,
                disk_write_bytes=0,
                net_sent_bytes=0,
                net_recv_bytes=0,
            ),
        ])

        events = generate_timeline(report)
        resource_events = [e for e in events if e["category"] == "resource"]

        assert resource_events, (
            f"PD-011: generate_timeline has no 'resource' handler. A ResourceSample in the report must produce at least one TimelineEvent with category='resource'; got events={[e['category'] for e in events]!r}"
        )

    def test_resource_event_timestamp_matches_sample_timestamp(self) -> None:
        """Resource timeline event timestamp must match the ResourceSample timestamp.

        Oracle: all other timeline handlers copy the source event's timestamp
        directly into the TimelineEvent.  The resource handler must do the same.

        PD-011 RED-BY-DESIGN: This test is also red until the resource handler
        is implemented.
        """
        ts = "2026-01-01T12:34:56Z"
        report = _report_with_resource_samples([
            ResourceSample(
                timestamp=ts,
                cpu_percent=10.0,
                memory_mb=128.0,
                disk_read_bytes=0,
                disk_write_bytes=0,
                net_sent_bytes=0,
                net_recv_bytes=0,
            ),
        ])

        events = generate_timeline(report)
        resource_events = [e for e in events if e["category"] == "resource"]

        assert resource_events, "PD-011: No 'resource' category events produced by generate_timeline."
        assert resource_events[0]["timestamp"] == ts, (
            f"Resource event timestamp must match sample timestamp {ts!r}; got {resource_events[0]['timestamp']!r}"
        )

    def test_resource_category_filter_returns_only_resource_events(self) -> None:
        """generate_timeline with categories=['resource'] returns only resource events.

        Oracle: the ``_should_include(category)`` guard applies to all
        categories; a filter of ``['resource']`` must return only resource events,
        not file events even if file_changes are present.

        PD-011 RED-BY-DESIGN: Red because no resource events are produced at all.
        """
        report = _report_with_all(
            file_changes=[
                FileChange(
                    path="C:\\file.exe",
                    operation="created",
                    old_path=None,
                    timestamp="2026-01-01T00:00:00Z",
                    size=None,
                ),
            ],
            resource_samples=[
                ResourceSample(
                    timestamp="2026-01-01T00:00:01Z",
                    cpu_percent=20.0,
                    memory_mb=64.0,
                    disk_read_bytes=0,
                    disk_write_bytes=0,
                    net_sent_bytes=0,
                    net_recv_bytes=0,
                ),
            ],
        )

        events = generate_timeline(report, categories=["resource"])
        non_resource = [e for e in events if e["category"] != "resource"]

        assert not non_resource, (
            f"Category filter=['resource'] must suppress non-resource events; got non-resource events: {non_resource!r}"
        )
        assert len(events) >= 1, (
            "PD-011: Category filter=['resource'] returned no events because no 'resource' handler exists in generate_timeline."
        )


@pytest.mark.parametrize(
    ("ioc_type", "hash_value"),
    [
        ("sha1", _SHA1_KNOWN),
        ("sha256", _SHA256_KNOWN),
    ],
)
def test_hash_ioc_types_are_distinct(ioc_type: str, hash_value: str) -> None:
    """SHA1 and SHA256 are correctly classified separately by extract_iocs.

    Args:
        ioc_type: Expected IOC type string.
        hash_value: Known hash value of the correct length.

    Oracle: ``_SHA1_PATTERN`` matches exactly 40 hex chars; ``_SHA256_PATTERN``
    matches exactly 64 hex chars.  Swapping the two regexes would misclassify
    each hash.  Mutation: applying SHA256 regex to a 40-char hash would fail
    because 40 != 64.
    """
    path = rf"C:\test\{hash_value}.bin"
    report = _report_with_file_changes([
        FileChange(
            path=path,
            operation="created",
            old_path=None,
            timestamp="2026-01-01T00:00:00Z",
            size=None,
        ),
    ])

    iocs = extract_iocs(report)
    typed_iocs = [i for i in iocs if i["ioc_type"] == ioc_type and i["value"] == hash_value]

    assert len(typed_iocs) >= 1, f"Expected at least one '{ioc_type}' IOC with value {hash_value!r}; got {iocs!r}"
