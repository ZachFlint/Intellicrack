# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for PowerShell monitor source fixes (F-0008, F-0018, F-0019, F-0017).

Validates that the inline PowerShell scripts generated for file, process,
registry, and network monitors no longer contain the defective patterns
identified in audit-4.
"""

from __future__ import annotations

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.windows import WindowsSandbox


class TestFileMonitorSource:
    """Tests for F-0008: file monitor must use -MessageData, not $using:."""

    def test_no_using_scope_in_action(self) -> None:
        """File monitor action block must not reference $using:logPath."""
        source = WindowsSandbox._file_monitor_source()
        assert "$using:" not in source

    def test_message_data_passed_to_register(self) -> None:
        """Register-ObjectEvent calls must pass -MessageData $logPath."""
        source = WindowsSandbox._file_monitor_source()
        assert "-MessageData $logPath" in source

    def test_action_reads_event_message_data(self) -> None:
        """Action block must read $Event.MessageData for the log path."""
        source = WindowsSandbox._file_monitor_source()
        assert "$Event.MessageData" in source

    def test_action_uses_local_log_path_var(self) -> None:
        """Action must write to the local variable bound via MessageData."""
        source = WindowsSandbox._file_monitor_source()
        assert "Out-File -Append -FilePath $lp" in source


class TestProcessMonitorSource:
    """Tests for F-0018: process monitor must not shadow $pid automatic variable."""

    def test_no_dollar_pid_assignment(self) -> None:
        """Process monitor must not assign to $pid (automatic variable)."""
        source = WindowsSandbox._process_monitor_source()
        assert "$pid = " not in source
        assert "$pid=" not in source

    def test_uses_proc_id_variable(self) -> None:
        """Process monitor must use $procId instead of $pid."""
        source = WindowsSandbox._process_monitor_source()
        assert "$procId = [int]$p.ProcessId" in source
        assert "foreach ($procId in" in source


class TestNetworkMonitorSource:
    """Tests for F-0018 extension: network monitor must not shadow $pid."""

    def test_no_dollar_pid_assignment(self) -> None:
        """Network monitor must not assign to $pid (automatic variable)."""
        source = WindowsSandbox._network_monitor_source()
        assert "$pid = " not in source

    def test_uses_owner_pid_variable(self) -> None:
        """Network monitor must use $ownerPid instead of $pid."""
        source = WindowsSandbox._network_monitor_source()
        assert "$ownerPid = [int]$c.OwningProcess" in source
        assert "$ownerPid = [int]$u.OwningProcess" in source


class TestRegistryMonitorSource:
    """Tests for F-0019: registry monitor must detect actual value type."""

    def test_no_hardcoded_reg_sz(self) -> None:
        """Registry monitor must not hardcode REG_SZ for all values."""
        source = WindowsSandbox._registry_monitor_source()
        assert "|REG_SZ|" not in source

    def test_get_reg_value_type_function(self) -> None:
        """Registry monitor must define Get-RegValueType helper."""
        source = WindowsSandbox._registry_monitor_source()
        assert "function Get-RegValueType" in source

    def test_dynamic_type_in_snapshot(self) -> None:
        """Snapshot-Values must record per-value registry type."""
        source = WindowsSandbox._registry_monitor_source()
        assert "Get-RegValueType" in source
        assert "$vtype" in source

    def test_type_included_in_log_entry(self) -> None:
        """Log lines must embed the dynamic registry type variable."""
        source = WindowsSandbox._registry_monitor_source()
        assert "$rtype" in source

    def test_key_split_on_three_parts(self) -> None:
        """Key must be split into 3 parts (path :: name :: type)."""
        source = WindowsSandbox._registry_monitor_source()
        assert "-split '::', 3" in source

    def test_set_item_property_not_new_item_property(self) -> None:
        """Registry monitor must not use New-ItemProperty (unapproved verb)."""
        source = WindowsSandbox._registry_monitor_source()
        assert "New-ItemProperty" not in source


class TestDispatcherSource:
    """Tests for F-0017: dispatcher catch block must not silently swallow errors."""

    def test_catch_block_logs_error(self) -> None:
        """Dispatcher outer catch block must log the error message."""
        source = WindowsSandbox(SandboxConfig(timeout_seconds=30))._dispatcher_ps1_source()
        assert "dispatcher_errors.log" in source

    def test_error_message_captured(self) -> None:
        """Dispatcher catch block must capture exception message."""
        source = WindowsSandbox(SandboxConfig(timeout_seconds=30))._dispatcher_ps1_source()
        assert "$_.Exception.Message" in source or "$errMsg" in source
