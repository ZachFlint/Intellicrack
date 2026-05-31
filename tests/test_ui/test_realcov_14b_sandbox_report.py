# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real monitor-log coverage for :mod:`intellicrack.ui.panels.sandbox_panel`.

The audit flagged the sandbox panel report view as never exercised against
real captured monitor data: only combo-box wiring was tested.

These tests write genuine pipe-delimited monitor logs in the exact wire schema
that the in-guest agents under ``sandbox/scripts/`` emit, parse them with the
**production** :mod:`intellicrack.sandbox.log_parsers` async helpers, assemble a
real :class:`~intellicrack.sandbox.base.ExecutionReport`, and drive it through
:meth:`SandboxPanel.load_execution_report`. Assertions verify the panel's
file-change, registry-change, and network-activity trees materialise exactly
the records the real parser produced from the real log files. The parsing
pipeline under test is the real one; nothing about file/registry/network record
extraction is mocked.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.base import ExecutionReport
from intellicrack.sandbox.log_parsers import (
    parse_file_log,
    parse_network_log,
    parse_registry_log,
)
from intellicrack.ui.panels.sandbox_panel import SandboxPanel


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.sandbox.base import FileChange, NetworkActivity, RegistryChange


_FILE_LOG = (
    "2026-05-30T12:00:00|created|C:\\Users\\analyst\\AppData\\drop.exe||4096\n"
    "2026-05-30T12:00:01|modified|C:\\Windows\\Temp\\stage.bin||8192\n"
    "2026-05-30T12:00:02|renamed|C:\\Windows\\Temp\\final.bin|C:\\Windows\\Temp\\stage.bin|8192\n"
    "2026-05-30T12:00:03|deleted|C:\\Users\\analyst\\AppData\\drop.exe||"
)

_REGISTRY_LOG = (
    "2026-05-30T12:00:00|created|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|Updater|REG_SZ|drop.exe\n"
    "2026-05-30T12:00:01|modified|HKCU\\Software\\Classes\\exefile\\shell\\open\\command||REG_SZ|hijack.exe\n"
    "2026-05-30T12:00:02|deleted|HKLM\\System\\CurrentControlSet\\Services\\Defender||"
)

_NETWORK_LOG = (
    "2026-05-30T12:00:00|connect|192.168.56.10:50122|93.184.216.34:443|ESTABLISHED|tcp|512|1024|1234|drop.exe\n"
    "2026-05-30T12:00:01|connect|192.168.56.10:50123|8.8.8.8:53|NONE|udp|64|128|1234|drop.exe"
)


def _write_logs(shared_folder: Path) -> None:
    """Write the real monitor-log fixtures under ``<shared_folder>/logs``.

    Args:
        shared_folder: Sandbox shared-folder root to populate.
    """
    logs_dir = shared_folder / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "file_monitor.log").write_text(_FILE_LOG, encoding="utf-8")
    (logs_dir / "registry_monitor.log").write_text(_REGISTRY_LOG, encoding="utf-8")
    (logs_dir / "network_monitor.log").write_text(_NETWORK_LOG, encoding="utf-8")


def _parse_report(shared_folder: Path) -> ExecutionReport:
    """Parse the real monitor logs into a real :class:`ExecutionReport`.

    Args:
        shared_folder: Sandbox shared-folder root holding the logs.

    Returns:
        ExecutionReport: Report populated from the production log parsers.
    """

    async def _gather() -> tuple[
        list[FileChange],
        list[RegistryChange],
        list[NetworkActivity],
    ]:
        return await asyncio.gather(
            parse_file_log(shared_folder),
            parse_registry_log(shared_folder),
            parse_network_log(shared_folder),
        )

    file_changes, registry_changes, network_activity = asyncio.run(_gather())
    return ExecutionReport(
        result="success",
        exit_code=0,
        stdout="",
        stderr="",
        duration_seconds=3.0,
        file_changes=file_changes,
        registry_changes=registry_changes,
        network_activity=network_activity,
    )


@pytest.fixture
def real_report(tmp_path: Path) -> ExecutionReport:
    """Provide a real execution report parsed from real monitor logs.

    Args:
        tmp_path: Pytest temporary directory fixture serving as the shared
            sandbox folder.

    Returns:
        ExecutionReport: Report parsed by the production log parsers.
    """
    _write_logs(tmp_path)
    return _parse_report(tmp_path)


class TestRealMonitorLogParsing:
    """The production parsers must extract the real records from the logs."""

    @staticmethod
    def test_parsers_extract_expected_record_counts(real_report: ExecutionReport) -> None:
        """Parsed record counts must match the real log line counts.

        Args:
            real_report: Report parsed from the real monitor logs.
        """
        assert len(real_report.file_changes) == 4
        assert len(real_report.registry_changes) == 3
        assert len(real_report.network_activity) == 2

    @staticmethod
    def test_parsed_records_carry_real_field_values(real_report: ExecutionReport) -> None:
        """Parsed records must carry the real fields decoded from the schema.

        Args:
            real_report: Report parsed from the real monitor logs.
        """
        operations = [change["operation"] for change in real_report.file_changes]
        assert operations == ["created", "modified", "renamed", "deleted"]
        renamed = next(c for c in real_report.file_changes if c["operation"] == "renamed")
        assert renamed["old_path"] == "C:\\Windows\\Temp\\stage.bin"
        assert renamed["size"] == 8192

        https_conn = next(
            a for a in real_report.network_activity if a["remote_port"] == 443
        )
        assert https_conn["protocol"] == "tcp"
        assert https_conn["remote_address"] == "93.184.216.34"
        assert https_conn["bytes_sent"] == 512


@pytest.mark.usefixtures("qapp")
class TestSandboxPanelReportRendering:
    """The panel report trees must render every real parsed record."""

    @staticmethod
    def test_file_changes_tree_matches_real_records(real_report: ExecutionReport) -> None:
        """The file-changes tree row count must equal the real file changes.

        Args:
            real_report: Report parsed from the real monitor logs.
        """
        panel = SandboxPanel()
        panel.load_execution_report(real_report)
        assert panel._file_changes_tree.topLevelItemCount() == len(real_report.file_changes)

    @staticmethod
    def test_registry_changes_tree_matches_real_records(
        real_report: ExecutionReport,
    ) -> None:
        """The registry-changes tree row count must equal the real records.

        Args:
            real_report: Report parsed from the real monitor logs.
        """
        panel = SandboxPanel()
        panel.load_execution_report(real_report)
        assert panel._registry_changes_tree.topLevelItemCount() == len(
            real_report.registry_changes,
        )

    @staticmethod
    def test_network_tree_matches_real_records(real_report: ExecutionReport) -> None:
        """The network tree row count must equal the real network events.

        Args:
            real_report: Report parsed from the real monitor logs.
        """
        panel = SandboxPanel()
        panel.load_execution_report(real_report)
        assert panel._network_tree.topLevelItemCount() == len(real_report.network_activity)

    @staticmethod
    def test_reload_clears_previous_real_report(
        real_report: ExecutionReport,
        tmp_path: Path,
    ) -> None:
        """Loading a second real report must replace, not append, the rows.

        Args:
            real_report: First report parsed from the real monitor logs.
            tmp_path: Temporary directory used for the second log set.
        """
        panel = SandboxPanel()
        panel.load_execution_report(real_report)
        assert panel._file_changes_tree.topLevelItemCount() == 4

        smaller_folder = tmp_path / "second"
        logs_dir = smaller_folder / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        (logs_dir / "file_monitor.log").write_text(
            "2026-05-30T13:00:00|created|C:\\Windows\\Temp\\only.bin||16",
            encoding="utf-8",
        )
        second_report = _parse_report(smaller_folder)

        panel.load_execution_report(second_report)

        assert panel._file_changes_tree.topLevelItemCount() == 1
        assert panel._registry_changes_tree.topLevelItemCount() == 0
        assert panel._network_tree.topLevelItemCount() == 0
