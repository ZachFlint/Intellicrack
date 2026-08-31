# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Host-side report harvesting and console presentation.

After the container exits, the host driver inspects the bind-mounted
``reports/tests/`` tree to produce a normalized :class:`SummaryRecord`. The
record contains the exit code, pytest counts, coverage percentage, and
absolute host paths for every artifact produced by the run. A companion
helper :func:`print_host_summary` prints the record to the operator's
console in a format that preserves the information surfaced by the prior
Windows Sandbox harness.

Every artifact name carries the run's identity token, so two containers
running at the same time never write to the same file. The aggregate
``test-log.txt`` history operators rely on is preserved by
:func:`merge_run_log_into_shared`, which appends a finished run's own log to
it host-side -- after the container exited and no writer still holds the
handle across the Windows bind mount.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from defusedxml import ElementTree as DefusedET


if TYPE_CHECKING:
    from .test_types import TestType


_PROJECT_ROOT = Path("D:/Intellicrack")
_REPORTS_ROOT = _PROJECT_ROOT / "reports" / "tests"
_SHARED_LOG_NAME = "test-log.txt"
_SHARED_LOG_APPEND_ATTEMPTS = 5
_SHARED_LOG_RETRY_SECONDS = 0.2
_COLOR_RESET = "\033[0m"
_COLOR_CYAN = "\033[36m"
_COLOR_GREEN = "\033[32m"
_COLOR_RED = "\033[31m"
_COLOR_YELLOW = "\033[33m"
_COLOR_BOLD = "\033[1m"


@dataclass(frozen=True, slots=True)
class TestCounts:
    """Aggregate counts from a JUnit XML result file.

    Attributes:
        tests: Total number of test cases collected.
        passed: Number of tests that passed.
        failed: Number of tests that failed.
        skipped: Number of tests that were skipped.
        errors: Number of tests that errored during collection or setup.
        duration_seconds: Total pytest reported duration.
    """

    tests: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: int = 0
    duration_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class ReportPaths:
    """Host-visible paths to per-run artifacts.

    Attributes:
        junit: Path to the JUnit XML file, if present.
        coverage_xml: Path to the coverage XML report, if present.
        coverage_html: Path to the coverage HTML directory, if present.
        html_report: Path to the pytest-html report, if present.
        log: Path to this run's own ``test-log_<token>.txt``, if present.
        summary: Path to the structured JSON summary, if present.
        bench: Path to the pytest-benchmark JSON, if present.
        shared_log: Path to the aggregate append-only ``test-log.txt`` history,
            if present.
    """

    junit: Path | None = None
    coverage_xml: Path | None = None
    coverage_html: Path | None = None
    html_report: Path | None = None
    log: Path | None = None
    summary: Path | None = None
    bench: Path | None = None
    shared_log: Path | None = None


@dataclass(frozen=True, slots=True)
class SummaryRecord:
    """Normalized summary of a single sandbox test run.

    Attributes:
        test_type: Identifier of the executed test mode.
        timestamp: UTC timestamp string ``yyyyMMdd_HHmmss`` matching the artifact stem.
        exit_code: Pytest process exit code captured by the container entrypoint.
        counts: Parsed pytest counts from the JUnit XML report.
        coverage_percent: Line coverage percentage, or ``None`` when not collected.
        paths: Host-visible paths for each artifact produced by the run.
        module: Module argument when the run targeted a specific module.
        extra_args: Extra pytest arguments forwarded to the container.
        run_id: Identity component that made this run's artifact names unique.
    """

    test_type: str
    timestamp: str
    exit_code: int
    counts: TestCounts = field(default_factory=TestCounts)
    coverage_percent: float | None = None
    paths: ReportPaths = field(default_factory=ReportPaths)
    module: str | None = None
    extra_args: tuple[str, ...] = field(default_factory=tuple)
    run_id: str = ""


def _parse_junit(junit_path: Path) -> TestCounts:
    """Parse a JUnit XML file into a :class:`TestCounts` record.

    Args:
        junit_path: Absolute path to the JUnit XML file.

    Returns:
        TestCounts: Aggregate counts for the run. Missing files or malformed
            XML yield a zero-valued record rather than raising.
    """
    if not junit_path.exists():
        return TestCounts()

    try:
        root = DefusedET.parse(junit_path).getroot()
    except DefusedET.ParseError:
        return TestCounts()
    if root is None:
        return TestCounts()

    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    tests = 0
    failures = 0
    errors = 0
    skipped = 0
    duration = 0.0
    for suite in suites:
        tests += int(suite.attrib.get("tests", "0") or 0)
        failures += int(suite.attrib.get("failures", "0") or 0)
        errors += int(suite.attrib.get("errors", "0") or 0)
        skipped += int(suite.attrib.get("skipped", "0") or 0)
        duration += float(suite.attrib.get("time", "0") or 0.0)

    passed = max(tests - failures - errors - skipped, 0)
    return TestCounts(
        tests=tests,
        passed=passed,
        failed=failures,
        skipped=skipped,
        errors=errors,
        duration_seconds=round(duration, 3),
    )


def _parse_coverage(coverage_xml: Path) -> float | None:
    """Extract line coverage percentage from a Cobertura XML file.

    Args:
        coverage_xml: Absolute path to the coverage XML file.

    Returns:
        float | None: Line coverage as a percentage (0.0-100.0), or ``None``
            when the file is absent or unparseable.
    """
    if not coverage_xml.exists():
        return None
    try:
        root = DefusedET.parse(coverage_xml).getroot()
    except DefusedET.ParseError:
        return None
    if root is None:
        return None
    line_rate = root.attrib.get("line-rate")
    if line_rate is None:
        return None
    try:
        return round(float(line_rate) * 100.0, 2)
    except ValueError:
        return None


def _first_existing(candidates: list[Path]) -> Path | None:
    """Return the first path in ``candidates`` that exists on disk.

    Args:
        candidates: Ordered list of paths to probe.

    Returns:
        Path | None: The first existing path, or ``None`` if none exist.
    """
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def artifact_suffix(test_type: str, timestamp: str, run_id: str) -> str:
    """Compose the filename suffix shared by a run's artifacts.

    Args:
        test_type: Test mode identifier.
        timestamp: Run timestamp ``mm-dd-yyyy_HH-MM``.
        run_id: Per-run identity component.

    Returns:
        str: ``<test_type>_<timestamp>_<run_id>``.
    """
    return f"{test_type}_{timestamp}_{run_id}"


def run_log_path(test_type: str, timestamp: str, run_id: str) -> Path:
    """Return the host path of a run's own container log.

    Args:
        test_type: Test mode identifier.
        timestamp: Run timestamp ``mm-dd-yyyy_HH-MM``.
        run_id: Per-run identity component.

    Returns:
        Path: Absolute host path to ``test-log_<suffix>.txt``.
    """
    return _REPORTS_ROOT / f"test-log_{artifact_suffix(test_type, timestamp, run_id)}.txt"


def shared_log_path() -> Path:
    """Return the host path of the aggregate append-only test log.

    Returns:
        Path: Absolute host path to ``test-log.txt``.
    """
    return _REPORTS_ROOT / _SHARED_LOG_NAME


def _append_bytes(destination: Path, payload: bytes) -> bool:
    """Append raw bytes to a file, reporting whether the write succeeded.

    Args:
        destination: File to append to; created when missing.
        payload: Bytes to append.

    Returns:
        bool: ``True`` on success, ``False`` when the file could not be opened
            or written (for example while another process holds it open).
    """
    try:
        with destination.open("ab") as handle:
            handle.write(payload)
    except OSError:
        return False
    return True


def merge_run_log_into_shared(run_log: Path) -> bool:
    """Append a finished run's log to the aggregate ``test-log.txt`` history.

    Each container writes its own ``test-log_<suffix>.txt`` so two concurrent
    runs never contend for one handle across the Windows bind mount, which
    previously produced sharing violations. The operator-facing aggregate
    history is preserved by folding the run's log into ``test-log.txt`` once
    the container has exited. Two host drivers can still reach this point at
    the same instant, so a locked destination is retried a bounded number of
    times before giving up.

    Args:
        run_log: Path to the per-run log written by the container.

    Returns:
        bool: ``True`` when the run's output was appended; ``False`` when the
            per-run log is absent or empty, or the shared file stayed locked
            for the whole retry window.
    """
    if not run_log.is_file():
        return False
    payload = run_log.read_bytes()
    if not payload:
        return False
    destination = shared_log_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(_SHARED_LOG_APPEND_ATTEMPTS):
        if _append_bytes(destination, payload):
            return True
        if attempt < _SHARED_LOG_APPEND_ATTEMPTS - 1:
            time.sleep(_SHARED_LOG_RETRY_SECONDS)
    return False


def _resolve_report_paths(test_type: str, timestamp: str, run_id: str) -> ReportPaths:
    """Locate all artifacts produced for a given run.

    The layout is flat: every artifact lives directly under ``reports/tests/``
    with a filename of the form ``<kind>_<testtype>_<timestamp>_<run_id>.<ext>``.
    The run id keeps runs started within the same minute apart. The run's own
    ``test-log_<suffix>.txt`` is reported as :attr:`ReportPaths.log`; the
    aggregate ``test-log.txt`` history is reported as
    :attr:`ReportPaths.shared_log`.

    Args:
        test_type: Test mode identifier used in the filename stem.
        timestamp: Timestamp ``mm-dd-yyyy_HH-MM`` forming the filename suffix.
        run_id: Per-run identity component completing the filename suffix.

    Returns:
        ReportPaths: Populated paths for artifacts that exist on disk.
    """
    suffix = artifact_suffix(test_type, timestamp, run_id)
    return ReportPaths(
        junit=_first_existing([_REPORTS_ROOT / f"junit_{suffix}.xml"]),
        coverage_xml=_first_existing([_REPORTS_ROOT / f"coverage_{suffix}.xml"]),
        coverage_html=_first_existing([_REPORTS_ROOT / f"coverage-html_{suffix}"]),
        html_report=_first_existing([_REPORTS_ROOT / f"report_{suffix}.html"]),
        log=_first_existing([_REPORTS_ROOT / f"test-log_{suffix}.txt"]),
        summary=_first_existing([_REPORTS_ROOT / f"summary_{suffix}.json"]),
        bench=_first_existing([_REPORTS_ROOT / f"bench_{suffix}.json"]),
        shared_log=_first_existing([shared_log_path()]),
    )


def harvest_reports(
    test_type: TestType,
    timestamp: str,
    exit_code: int,
    *,
    run_id: str,
    module: str | None = None,
    extra_args: tuple[str, ...] = (),
) -> SummaryRecord:
    """Collect artifacts produced by a sandbox run into a summary record.

    Args:
        test_type: The :class:`~scripts.sandbox.test_types.TestType` that
            produced the run.
        timestamp: Run timestamp matching the artifact filenames.
        exit_code: Pytest exit code reported by the container entrypoint.
        run_id: Per-run identity component matching the artifact filenames.
        module: Module argument used for module-scoped runs.
        extra_args: Extra pytest arguments forwarded to the container.

    Returns:
        SummaryRecord: Normalized summary record suitable for display or JSON
            export.
    """
    type_value = test_type.value
    paths = _resolve_report_paths(type_value, timestamp, run_id)
    counts = _parse_junit(paths.junit) if paths.junit else TestCounts()
    coverage = _parse_coverage(paths.coverage_xml) if paths.coverage_xml else None

    return SummaryRecord(
        test_type=type_value,
        timestamp=timestamp,
        exit_code=exit_code,
        counts=counts,
        coverage_percent=coverage,
        paths=paths,
        module=module,
        extra_args=extra_args,
        run_id=run_id,
    )


def write_summary_json(record: SummaryRecord, destination: Path) -> None:
    """Serialize a summary record to a JSON file on disk.

    Args:
        record: Summary record to persist.
        destination: Absolute destination path. Parent directories are created
            if missing.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {
        "test_type": record.test_type,
        "timestamp": record.timestamp,
        "run_id": record.run_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "exit_code": record.exit_code,
        "counts": {
            "tests": record.counts.tests,
            "passed": record.counts.passed,
            "failed": record.counts.failed,
            "skipped": record.counts.skipped,
            "errors": record.counts.errors,
            "duration_seconds": record.counts.duration_seconds,
        },
        "coverage_percent": record.coverage_percent,
        "module": record.module,
        "extra_args": list(record.extra_args),
        "report_paths": {
            "junit": str(record.paths.junit) if record.paths.junit else None,
            "coverage_xml": str(record.paths.coverage_xml) if record.paths.coverage_xml else None,
            "coverage_html": str(record.paths.coverage_html) if record.paths.coverage_html else None,
            "html_report": str(record.paths.html_report) if record.paths.html_report else None,
            "log": str(record.paths.log) if record.paths.log else None,
            "summary": str(record.paths.summary) if record.paths.summary else None,
            "bench": str(record.paths.bench) if record.paths.bench else None,
            "shared_log": str(record.paths.shared_log) if record.paths.shared_log else None,
        },
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _status_color(record: SummaryRecord) -> str:
    """Pick a color code based on the run outcome.

    Args:
        record: Summary record under inspection.

    Returns:
        str: ANSI color escape sequence appropriate for the overall status.
    """
    if record.exit_code == 0 and record.counts.failed == 0 and record.counts.errors == 0:
        return _COLOR_GREEN
    if record.counts.failed or record.counts.errors:
        return _COLOR_RED
    return _COLOR_YELLOW


def print_host_summary(record: SummaryRecord) -> None:
    """Emit a human-readable summary of a run to stdout.

    The output intentionally mirrors and extends the prior Windows Sandbox
    harness so operators see familiar fields (counts, duration, coverage) plus
    the new structured artifacts (``latest/``, ``summary.json``).

    Args:
        record: Summary record to display.
    """
    color = _status_color(record)
    status = "PASS" if record.exit_code == 0 else f"FAIL (exit {record.exit_code})"
    header = f"{_COLOR_BOLD}{color}[SANDBOX] {record.test_type} -- {status}{_COLOR_RESET}"
    print()
    print(header)
    print(f"  timestamp      : {record.timestamp}")
    if record.run_id:
        print(f"  run id         : {record.run_id}")
    print(
        "  counts         : "
        f"total={record.counts.tests} "
        f"{_COLOR_GREEN}passed={record.counts.passed}{_COLOR_RESET} "
        f"{_COLOR_RED}failed={record.counts.failed}{_COLOR_RESET} "
        f"{_COLOR_YELLOW}skipped={record.counts.skipped}{_COLOR_RESET} "
        f"errors={record.counts.errors}",
    )
    print(f"  duration       : {record.counts.duration_seconds:.2f}s")
    if record.coverage_percent is not None:
        print(f"  coverage       : {record.coverage_percent:.2f}%")
    if record.module:
        print(f"  module         : {record.module}")
    if record.extra_args:
        print(f"  extra args     : {' '.join(record.extra_args)}")
    print(f"  {_COLOR_CYAN}artifacts{_COLOR_RESET}")
    for label, value in (
        ("junit", record.paths.junit),
        ("coverage xml", record.paths.coverage_xml),
        ("coverage html", record.paths.coverage_html),
        ("pytest html", record.paths.html_report),
        ("bench", record.paths.bench),
        ("summary", record.paths.summary),
        ("run log", record.paths.log),
        ("shared log", record.paths.shared_log),
    ):
        if value is not None:
            print(f"    {label:<14} {value}")
    print()
