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
        source = getattr(WindowsSandbox, "_file_monitor_source")()
        assert "$using:" not in source

    def test_message_data_passed_to_register(self) -> None:
        """Register-ObjectEvent calls must pass -MessageData $logPath."""
        source = getattr(WindowsSandbox, "_file_monitor_source")()
        assert "-MessageData $logPath" in source

    def test_action_reads_event_message_data(self) -> None:
        """Action block must bind $lp from $Event.MessageData for the log path.

        The action block must open with the assignment ``$lp = $Event.MessageData``
        so that the local variable carries the log path, not a $using:-scope
        capture.  Asserting the bare token ``$Event.MessageData`` anywhere in
        the source is insufficient because it could appear in a comment or dead
        branch; the binding line is the functional artifact of F-0008.
        """
        source = getattr(WindowsSandbox, "_file_monitor_source")()
        assert "$lp = $Event.MessageData" in source

    def test_action_uses_local_log_path_var(self) -> None:
        """Action must write to $lp and all four event types must register with shared action.

        Three constraints are checked simultaneously so that removing any one
        breaks this test:

        1. The action block emits ``Out-File -Append -FilePath $lp``, meaning
           the bound local variable is what drives the write path.
        2. All four filesystem events (Created, Changed, Deleted, Renamed) are
           registered with the shared ``$action`` block, confirmed by counting
           exactly four ``Register-ObjectEvent`` occurrences that pass
           ``-Action $action``.
        3. Each registration also passes ``-MessageData $logPath``, tying the
           write to the correct log-path variable via the MessageData mechanism.
        """
        source = getattr(WindowsSandbox, "_file_monitor_source")()
        assert "Out-File -Append -FilePath $lp" in source
        assert source.count("Register-ObjectEvent") == 4
        assert source.count("-Action $action -MessageData $logPath") == 4


class TestProcessMonitorSource:
    """Tests for F-0018: process monitor must not shadow $pid automatic variable."""

    def test_no_dollar_pid_assignment(self) -> None:
        """Process monitor must not assign to $pid (automatic variable)."""
        source = getattr(WindowsSandbox, "_process_monitor_source")()
        assert "$pid = " not in source
        assert "$pid=" not in source

    def test_uses_proc_id_variable(self) -> None:
        """Process monitor must use $procId in log lines, not the $pid automatic variable.

        F-0018 requires that process IDs are captured in ``$procId`` and that
        this variable is what gets written to the log file.  Asserting only that
        ``$procId`` is defined (the assignment exists) is not sufficient; the
        log-emit lines must also interpolate ``$procId`` so a rename of the
        variable without updating the log line would be caught here.
        """
        source = getattr(WindowsSandbox, "_process_monitor_source")()
        assert "$procId = [int]$p.ProcessId" in source
        assert "foreach ($procId in" in source
        assert "$ts|created|$procId|" in source
        assert "$ts|terminated|$procId|" in source


class TestNetworkMonitorSource:
    """Tests for F-0018 extension: network monitor must not shadow $pid."""

    def test_no_dollar_pid_assignment(self) -> None:
        """Network monitor must not assign to $pid (automatic variable)."""
        source = getattr(WindowsSandbox, "_network_monitor_source")()
        assert "$pid = " not in source

    def test_uses_owner_pid_variable(self) -> None:
        """Network monitor must interpolate $ownerPid into both TCP and UDP log lines.

        F-0018 requires using ``$ownerPid`` rather than ``$pid``.  The assignment
        alone is insufficient: if the variable were defined but the log-emit lines
        still used a literal or the wrong variable the fix would be incomplete.
        Both the TCP connection log line and the UDP bind log line must carry
        ``$ownerPid|$name`` so each protocol's entry is correctly attributed.
        Asserting a plain substring ``in source`` is not sufficient because only
        one of the two log lines could carry ``$ownerPid|$name`` while the other
        regresses to a different token and the substring check would still pass.
        Requiring exactly two occurrences ensures both protocol paths are covered:
        removing ``$ownerPid|$name`` from either the TCP or UDP emit line will
        flip this assertion from green to red.
        """
        source = getattr(WindowsSandbox, "_network_monitor_source")()
        assert "$ownerPid = [int]$c.OwningProcess" in source
        assert "$ownerPid = [int]$u.OwningProcess" in source
        assert source.count("$ownerPid|$name") == 2


class TestRegistryMonitorSource:
    """Tests for F-0019: registry monitor must detect actual value type."""

    def test_no_hardcoded_reg_sz(self) -> None:
        """Registry monitor must not hardcode REG_SZ; type must come from $vtype/$rtype.

        Absence of ``|REG_SZ|`` alone is insufficient to prove dynamic detection:
        the source could hardcode a different literal (``|REG_DWORD|``) or omit
        the type entirely and the old assertion would still pass.  The two
        additional assertions confirm that the emitted log lines interpolate the
        dynamically-computed ``$rtype`` variable rather than any literal type
        token, binding the prohibition on hardcoded literals to the positive
        requirement for variable interpolation.
        """
        source = getattr(WindowsSandbox, "_registry_monitor_source")()
        assert "|REG_SZ|" not in source
        assert "$ts|created|$path|$name|$rtype|$val" in source
        assert "$ts|modified|$path|$name|$rtype|$val" in source

    def test_get_reg_value_type_function(self) -> None:
        """Registry monitor must define Get-RegValueType helper."""
        source = getattr(WindowsSandbox, "_registry_monitor_source")()
        assert "function Get-RegValueType" in source

    def test_dynamic_type_in_snapshot(self) -> None:
        """Snapshot-Values must invoke Get-RegValueType per value and store the result.

        Presence of the function name and the variable ``$vtype`` anywhere in the
        source does not prove the function is actually called per value: it could
        be defined but never invoked.  The assignment ``$vtype = Get-RegValueType``
        with the argument ``-RegPath`` is the concrete artifact that proves the
        per-value call exists; the composite key that embeds ``$vtype`` confirms
        the result flows into the snapshot record rather than being discarded.
        """
        source = getattr(WindowsSandbox, "_registry_monitor_source")()
        assert "$vtype = Get-RegValueType -RegPath" in source
        assert "$it.PSPath + '::' + $p.Name + '::' + $vtype" in source

    def test_type_included_in_log_entry(self) -> None:
        """Log lines must embed $rtype in both the changed-values and deleted-values loops.

        The variable ``$rtype`` alone anywhere in the source is not a gate: it
        could live in a dead branch.  The F-0019 fix requires that ``$rtype`` is
        extracted from the composite key via ``-split '::', 3`` in TWO separate
        loops — one for created/modified values and one for deleted values — and
        then interpolated directly inside the ``Out-File`` log-line in both.
        Asserting a plain substring for the extraction assignment is not
        sufficient because both loops share the same extraction expression: if
        one loop's extraction were removed the ``in source`` check would still
        pass because the other occurrence satisfies it.  Requiring exactly two
        occurrences of the extraction assignment pins both loops; additionally
        asserting that the deleted log line also carries ``$rtype`` confirms the
        deleted-values loop's emit is not regressed independently.
        """
        source = getattr(WindowsSandbox, "_registry_monitor_source")()
        assert source.count("$rtype = if ($full.Count -gt 2) { $full[2] } else { 'Unknown' }") == 2
        assert "$ts|created|$path|$name|$rtype|$val" in source
        assert "$ts|deleted|$path|$name|$rtype|" in source

    def test_key_split_on_three_parts(self) -> None:
        """Key must be split into 3 parts (path :: name :: type)."""
        source = getattr(WindowsSandbox, "_registry_monitor_source")()
        assert "-split '::', 3" in source

    def test_set_item_property_not_new_item_property(self) -> None:
        """Registry monitor must not use New-ItemProperty (unapproved verb)."""
        source = getattr(WindowsSandbox, "_registry_monitor_source")()
        assert "New-ItemProperty" not in source


class TestDispatcherSource:
    """Tests for F-0017: dispatcher catch block must not silently swallow errors."""

    def test_catch_block_logs_error(self) -> None:
        """Dispatcher outer catch block must log the error message."""
        source = getattr(WindowsSandbox(SandboxConfig(timeout_seconds=30)), "_dispatcher_ps1_source")()
        assert "dispatcher_errors.log" in source

    def test_error_message_captured(self) -> None:
        """Dispatcher catch block must capture exception message."""
        source = getattr(WindowsSandbox(SandboxConfig(timeout_seconds=30)), "_dispatcher_ps1_source")()
        assert "$_.Exception.Message" in source or "$errMsg" in source
