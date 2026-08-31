# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""S18-D13: every collector that reports a lifecycle must be read for outages.

S17-D50(b) built the outage channel so an empty tab could be told apart from a
collector that never watched, but only ``api_trace`` and ``injection_monitor``
were ever read through it. ``dll_monitor`` and ``kernel_object_monitor`` write
the same ``timestamp|collector|state|detail`` lifecycle log and were not.

That gap is not hypothetical. Across six live re-drives against the real Windows
guest the agent's launcher started different subsets of the eight monitors - once
none of them, once all but ``dll_monitor`` - and reported no outage for any of
the ones it missed, because none of the missing ones were in the list. The run
came back with an empty DLL tab and nothing anywhere in the report to separate
that from a sample that loaded no libraries.

The first gate below never restates which collectors those are: it reads the
lifecycle log every shipped monitor script writes and requires the reporter to
cover exactly that set, so a monitor added later with a lifecycle log of its own
cannot be quietly left out either.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

from intellicrack.sandbox.log_parsers import collect_collector_outages


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPTS_DIR: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts"

# Every monitor names its own lifecycle log in a Join-Path against $LogDir. The
# collector name the reporter uses is the log's own stem, which is also what the
# script writes into the second field of each line.
_LIFECYCLE_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"Join-Path\s+-Path\s+\$LogDir\s+-ChildPath\s+'(?P<name>[A-Za-z0-9_]+)\.lifecycle\.log'",
)

_TS: Final[str] = "2026-08-15T10:00:00.0000000Z"
_LOGS_DIR_NAME: Final[str] = "logs"


def _collectors_that_report_a_lifecycle() -> set[str]:
    """Read the collector names out of the shipped monitor scripts.

    Returns:
        set[str]: Every collector whose script writes a lifecycle log.
    """
    found: set[str] = set()
    for script in sorted(_SCRIPTS_DIR.glob("*.ps1")):
        text = script.read_text(encoding="utf-8-sig")
        found.update(match.group("name") for match in _LIFECYCLE_PATH_RE.finditer(text))
    return found


def _write_lifecycle(logs_dir: Path, collector: str, states: tuple[tuple[str, str], ...]) -> None:
    """Write a collector's lifecycle log exactly as its script would.

    Args:
        logs_dir: Directory the host collected the guest's logs into.
        collector: Collector name written into the second field.
        states: ``(state, detail)`` pairs to record, in order.
    """
    logs_dir.mkdir(parents=True, exist_ok=True)
    lines = "".join(f"{_TS}|{collector}|{state}|{detail}\n" for state, detail in states)
    (logs_dir / f"{collector}.lifecycle.log").write_text(lines, encoding="utf-8")


class TestEveryLifecycleReportingCollectorIsCovered:
    """The reporter's collector set has to match what the guest actually reports."""

    def test_the_producers_are_actually_found(self) -> None:
        """A regex that matched nothing would make the coverage assertion vacuous."""
        found = _collectors_that_report_a_lifecycle()
        assert len(found) >= 2, (
            f"no lifecycle-writing monitor scripts were found under {_SCRIPTS_DIR}, so the coverage "
            f"assertion below would pass against an empty set: {found!r}"
        )

    @pytest.mark.asyncio
    async def test_no_collector_reports_a_lifecycle_the_host_never_reads(self, tmp_path: Path) -> None:
        """Every script that reports a lifecycle must be surfaced when it never starts.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        expected = _collectors_that_report_a_lifecycle()
        (tmp_path / _LOGS_DIR_NAME).mkdir(parents=True, exist_ok=True)

        outages = await collect_collector_outages(tmp_path)
        reported = {outage["collector"] for outage in outages}

        assert expected <= reported, (
            f"{sorted(expected - reported)} write a lifecycle log the host never reads, so a run in which "
            f"they never started is indistinguishable from one in which they saw nothing; reported={sorted(reported)}"
        )

    @pytest.mark.asyncio
    async def test_no_reported_collector_is_a_phantom(self, tmp_path: Path) -> None:
        """A name no script writes would be an outage against a collector that does not exist.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        expected = _collectors_that_report_a_lifecycle()
        (tmp_path / _LOGS_DIR_NAME).mkdir(parents=True, exist_ok=True)

        outages = await collect_collector_outages(tmp_path)
        reported = {outage["collector"] for outage in outages}

        assert reported <= expected, (
            f"the report names {sorted(reported - expected)} as collectors, but no shipped monitor script "
            f"writes a lifecycle log under those names"
        )


@pytest.mark.asyncio
class TestTheNewlyCoveredCollectorsBehaveLikeTheOriginalTwo:
    """Coverage is only worth having if the outage carries what the collector recorded."""

    async def test_a_dll_monitor_that_never_started_is_an_outage(self, tmp_path: Path) -> None:
        """The measured live failure: the launcher missed dll_monitor and the tab went quiet.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        logs_dir = tmp_path / _LOGS_DIR_NAME
        for collector in ("api_trace", "injection_monitor", "kernel_object_monitor"):
            _write_lifecycle(logs_dir, collector, (("started", "stop_event=IntellicrackMonitorStop"),))

        outages = await collect_collector_outages(tmp_path)
        by_collector = {outage["collector"]: outage for outage in outages}

        assert "dll_monitor" in by_collector, (
            f"a dll_monitor that never started was not reported, so its empty tab reads as a clean run: {outages!r}"
        )
        assert "never reported starting" in by_collector["dll_monitor"]["reason"]
        assert by_collector["dll_monitor"]["exit_code"] is None
        assert set(by_collector) == {"dll_monitor"}, (
            f"collectors that reported starting and never stopping must not be reported: {outages!r}"
        )

    async def test_a_kernel_object_monitor_that_died_carries_its_own_detail(self, tmp_path: Path) -> None:
        """kernel_object_monitor.ps1 records its stop with ``stop_requested``, and that must survive.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        logs_dir = tmp_path / _LOGS_DIR_NAME
        for collector in ("api_trace", "injection_monitor", "dll_monitor"):
            _write_lifecycle(logs_dir, collector, (("started", "stop_event=IntellicrackMonitorStop"),))
        _write_lifecycle(
            logs_dir,
            "kernel_object_monitor",
            (
                ("started", "poll_interval_ms=250 stop_event=IntellicrackMonitorStop"),
                ("first_sweep_complete", "seen_handle_count=4821"),
                ("stopped", "stop_requested=False"),
            ),
        )

        outages = await collect_collector_outages(tmp_path)
        by_collector = {outage["collector"]: outage for outage in outages}

        assert "kernel_object_monitor" in by_collector, f"a kernel_object_monitor that stopped mid-run was not reported: {outages!r}"
        assert "stop_requested=False" in by_collector["kernel_object_monitor"]["reason"], (
            f"the outage dropped the detail the collector recorded for its own death: {by_collector['kernel_object_monitor']!r}"
        )
        assert set(by_collector) == {"kernel_object_monitor"}, (
            f"only the collector that stopped may be reported, and its intermediate states must not count "
            f"as a stop for anyone else: {outages!r}"
        )
