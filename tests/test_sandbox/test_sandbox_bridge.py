# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the SandboxBridge tool bridge.

Tests validate:
- Bridge instantiation, name, capabilities
- Tool definition completeness (26 functions, all resolve to methods)
- Tool definition parameter names match method signatures
- Initialize/shutdown lifecycle
- Create/destroy sandbox instances
- Run binary, execute command
- File copy to/from sandbox
- Status and list
- QEMU snapshot operations
- QEMU-specific methods (cont, pending messages)
- New capabilities (pcap, screenshot, anti-evasion, memory dump, extract files, yara)
- Analysis wrappers (IOCs, timeline, behaviors, C2, diff)
- VNC port retrieval
- _report_to_dict conversion
"""

from __future__ import annotations

import inspect
from typing import Final

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError, ToolName
from intellicrack.sandbox.base import ExecutionReport


_EXPECTED_FUNC_COUNT: Final[int] = 26
_MIN_DESC_LEN: Final[int] = 5
_WIN_INSTANCE: Final[str] = "win-test-001"
_QEMU_INSTANCE: Final[str] = "qemu-test-001"
_WIN_NOREPORT: Final[str] = "win-noreport-001"
_QEMU_NOREPORT: Final[str] = "qemu-noreport-001"
_MISSING_INSTANCE: Final[str] = "nonexistent-instance"
_REPORT_DICT_KEY_COUNT: Final[int] = 17


class TestBridgeInstantiation:
    """Verify bridge construction and basic properties."""

    def test_not_none(self) -> None:
        """Bridge instantiates successfully."""
        bridge = SandboxBridge()
        assert bridge is not None

    def test_name_is_sandbox(self) -> None:
        """Bridge name is ToolName.SANDBOX."""
        bridge = SandboxBridge()
        assert bridge.name == ToolName.SANDBOX

    def test_manager_initially_none(self) -> None:
        """Manager is None before initialization."""
        bridge = SandboxBridge()
        assert getattr(bridge, "_manager") is None

    def test_capabilities_dynamic_analysis(self) -> None:
        """Bridge supports dynamic analysis."""
        bridge = SandboxBridge()
        caps = getattr(bridge, "_capabilities")
        assert caps.supports_dynamic_analysis is True

    def test_capabilities_no_patching(self) -> None:
        """Bridge does not support patching."""
        bridge = SandboxBridge()
        caps = getattr(bridge, "_capabilities")
        assert caps.supports_patching is False


class TestToolDefinition:
    """Verify tool definition completeness and consistency."""

    def test_definition_exists(self) -> None:
        """Tool definition is not None."""
        bridge = SandboxBridge()
        assert bridge.tool_definition is not None

    def test_function_count(self) -> None:
        """Tool definition has expected number of functions."""
        bridge = SandboxBridge()
        funcs = bridge.tool_definition.functions
        assert len(funcs) == _EXPECTED_FUNC_COUNT

    def test_all_have_descriptions(self) -> None:
        """All functions have descriptions longer than 5 characters."""
        bridge = SandboxBridge()
        for func in bridge.tool_definition.functions:
            assert len(func.description) > _MIN_DESC_LEN, f"{func.name} has short description"

    def test_all_resolve_to_methods(self) -> None:
        """All function names resolve to callable methods on the bridge."""
        bridge = SandboxBridge()
        for func in bridge.tool_definition.functions:
            method_name = func.name.split(".", 1)[1] if "." in func.name else func.name
            assert hasattr(bridge, method_name), f"Method {method_name} not found"
            assert callable(getattr(bridge, method_name)), f"{method_name} not callable"

    def test_parameter_names_match_signatures(self) -> None:
        """Parameter names in tool definitions match method signatures."""
        bridge = SandboxBridge()
        for func in bridge.tool_definition.functions:
            method_name = func.name.split(".", 1)[1] if "." in func.name else func.name
            method = getattr(bridge, method_name)
            sig = inspect.signature(method)
            sig_params = {
                p_name
                for p_name, p in sig.parameters.items()
                if p_name != "self"
                and p.kind
                not in {
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                }
            }
            def_params = {p.name for p in func.parameters}
            assert def_params.issubset(sig_params), f"{func.name}: tool params {def_params - sig_params} not in method sig {sig_params}"

    def test_no_duplicate_names(self) -> None:
        """No duplicate function names in tool definition."""
        bridge = SandboxBridge()
        names = [f.name for f in bridge.tool_definition.functions]
        assert len(names) == len(set(names))

    def test_all_params_have_types(self) -> None:
        """All parameters have a type specified."""
        bridge = SandboxBridge()
        for func in bridge.tool_definition.functions:
            for param in func.parameters:
                assert param.type, f"{func.name}.{param.name} has no type"

    def test_tool_name_matches(self) -> None:
        """Tool definition tool_name matches bridge name."""
        bridge = SandboxBridge()
        assert bridge.tool_definition.tool_name == ToolName.SANDBOX


class TestInitializeShutdown:
    """Verify bridge initialization and shutdown."""

    @pytest.mark.asyncio()
    async def test_initialize_creates_manager(self) -> None:
        """Initialize creates a manager."""
        bridge = SandboxBridge()
        await bridge.initialize()
        assert getattr(bridge, "_manager") is not None

    @pytest.mark.asyncio()
    async def test_initialize_sets_connected(self) -> None:
        """Initialize sets state to connected."""
        bridge = SandboxBridge()
        await bridge.initialize()
        assert bridge.state.connected is True

    @pytest.mark.asyncio()
    async def test_shutdown_clears_manager(self, sandbox_bridge: SandboxBridge) -> None:
        """Shutdown clears the manager.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        await sandbox_bridge.shutdown()
        assert getattr(sandbox_bridge, "_manager") is None

    @pytest.mark.asyncio()
    async def test_shutdown_resets_state(self, sandbox_bridge: SandboxBridge) -> None:
        """Shutdown resets state.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        await sandbox_bridge.shutdown()
        assert sandbox_bridge.state.connected is False

    @pytest.mark.asyncio()
    async def test_ensure_manager_creates(self) -> None:
        """ensure_manager creates manager if None."""
        bridge = SandboxBridge()
        mgr = bridge.ensure_manager()
        assert mgr is not None

    @pytest.mark.asyncio()
    async def test_ensure_manager_idempotent(self, sandbox_bridge: SandboxBridge) -> None:
        """ensure_manager returns existing manager.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        mgr1 = sandbox_bridge.ensure_manager()
        mgr2 = sandbox_bridge.ensure_manager()
        assert mgr1 is mgr2


class TestCreateDestroy:
    """Verify create and destroy sandbox operations."""

    @pytest.mark.asyncio()
    async def test_create_returns_dict(self, sandbox_bridge: SandboxBridge) -> None:
        """Create returns dict with instance_id, type, status, created_at.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.create(sandbox_type="windows")
        assert "instance_id" in result
        assert "type" in result
        assert "status" in result
        assert "created_at" in result

    @pytest.mark.asyncio()
    async def test_create_qemu(self, sandbox_bridge: SandboxBridge) -> None:
        """Create with qemu type succeeds.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.create(sandbox_type="qemu")
        assert result["type"] == "qemu"

    @pytest.mark.asyncio()
    async def test_destroy_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Destroy existing instance returns success.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.destroy(_WIN_INSTANCE)
        assert result["success"] is True

    @pytest.mark.asyncio()
    async def test_destroy_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Destroy nonexistent instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.destroy(_MISSING_INSTANCE)

    @pytest.mark.asyncio()
    async def test_create_failure_raises(self) -> None:
        """Create on bridge with no available types raises ToolError on real manager."""
        bridge = SandboxBridge()
        await bridge.initialize()
        with pytest.raises(ToolError):
            await bridge.create(sandbox_type="windows")


class TestExecuteCommand:
    """Verify command execution in sandbox."""

    @pytest.mark.asyncio()
    async def test_execute_returns_output(self, sandbox_bridge: SandboxBridge) -> None:
        """Execute returns dict with exit_code, stdout, stderr.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.execute(_WIN_INSTANCE, "dir")
        assert "exit_code" in result
        assert "stdout" in result
        assert "stderr" in result
        assert result["exit_code"] == 0

    @pytest.mark.asyncio()
    async def test_execute_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Execute on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.execute(_MISSING_INSTANCE, "dir")


class TestFileCopy:
    """Verify file copy operations."""

    @pytest.mark.asyncio()
    async def test_copy_to_missing_instance(self, sandbox_bridge: SandboxBridge) -> None:
        """Copy to missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.copy_to(_MISSING_INSTANCE, "src.txt", "dest.txt")

    @pytest.mark.asyncio()
    async def test_copy_to_missing_source(self, sandbox_bridge: SandboxBridge) -> None:
        """Copy with nonexistent source file raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.copy_to(_WIN_INSTANCE, "/nonexistent/file.bin", "dest.txt")

    @pytest.mark.asyncio()
    async def test_copy_from_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Copy from sandbox returns success dict.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.copy_from(_WIN_INSTANCE, "sandbox_file.txt", "local.txt")
        assert result["success"] is True

    @pytest.mark.asyncio()
    async def test_copy_from_missing_instance(self, sandbox_bridge: SandboxBridge) -> None:
        """Copy from missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.copy_from(_MISSING_INSTANCE, "src.txt", "dest.txt")


class TestStatusAndList:
    """Verify status and list operations."""

    @pytest.mark.asyncio()
    async def test_status_returns_dict(self, sandbox_bridge: SandboxBridge) -> None:
        """Status returns dict with expected keys.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.status()
        assert "available_types" in result
        assert "active_count" in result
        assert "instances" in result

    @pytest.mark.asyncio()
    async def test_list_returns_instances(self, sandbox_bridge: SandboxBridge) -> None:
        """List returns instance dicts with expected keys.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.list()
        assert len(result) >= 2
        assert "id" in result[0]
        assert "type" in result[0]
        assert "status" in result[0]


class TestSnapshots:
    """Verify snapshot operations (QEMU only)."""

    @pytest.mark.asyncio()
    async def test_snapshot_create_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot create on QEMU returns snapshot_id.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.snapshot_create(_QEMU_INSTANCE, "snap1")
        assert "snapshot_id" in result

    @pytest.mark.asyncio()
    async def test_snapshot_create_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot create on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.snapshot_create(_WIN_INSTANCE, "snap1")

    @pytest.mark.asyncio()
    async def test_snapshot_create_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot create on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.snapshot_create(_MISSING_INSTANCE, "snap1")

    @pytest.mark.asyncio()
    async def test_snapshot_restore_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot restore on QEMU succeeds after create.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        create_result = await sandbox_bridge.snapshot_create(_QEMU_INSTANCE, "restore_test")
        result = await sandbox_bridge.snapshot_restore(
            _QEMU_INSTANCE,
            create_result["snapshot_id"],
        )
        assert result["success"] is True

    @pytest.mark.asyncio()
    async def test_snapshot_restore_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot restore on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.snapshot_restore(_WIN_INSTANCE, "snap-001")

    @pytest.mark.asyncio()
    async def test_snapshot_list_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot list on QEMU returns snapshot list.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        await sandbox_bridge.snapshot_create(_QEMU_INSTANCE, "list_test")
        result = await sandbox_bridge.snapshot_list(_QEMU_INSTANCE)
        assert "snapshots" in result
        assert len(result["snapshots"]) >= 1

    @pytest.mark.asyncio()
    async def test_snapshot_list_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot list on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.snapshot_list(_WIN_INSTANCE)

    @pytest.mark.asyncio()
    async def test_snapshot_delete_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot delete on QEMU succeeds.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        await sandbox_bridge.snapshot_create(_QEMU_INSTANCE, "del_test")
        result = await sandbox_bridge.snapshot_delete(_QEMU_INSTANCE, "del_test")
        assert result["success"] is True

    @pytest.mark.asyncio()
    async def test_snapshot_delete_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot delete on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.snapshot_delete(_WIN_INSTANCE, "snap1")


class TestQEMUSpecificMethods:
    """Verify QEMU-specific methods (cont, pending messages)."""

    @pytest.mark.asyncio()
    async def test_cont_success(self, sandbox_bridge: SandboxBridge) -> None:
        """cont on QEMU with QMP returns success.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.cont(_QEMU_INSTANCE)
        assert result["success"] is True

    @pytest.mark.asyncio()
    async def test_cont_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """cont on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.cont(_WIN_INSTANCE)

    @pytest.mark.asyncio()
    async def test_cont_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """cont on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.cont(_MISSING_INSTANCE)

    @pytest.mark.asyncio()
    async def test_pending_messages_success(self, sandbox_bridge: SandboxBridge) -> None:
        """get_pending_messages returns messages from agent.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.get_pending_messages(_QEMU_INSTANCE)
        assert "messages" in result
        assert result["count"] >= 1

    @pytest.mark.asyncio()
    async def test_pending_messages_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """get_pending_messages on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.get_pending_messages(_WIN_INSTANCE)

    @pytest.mark.asyncio()
    async def test_pending_messages_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """get_pending_messages on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.get_pending_messages(_MISSING_INSTANCE)


class TestNewCapabilities:
    """Verify new sandbox capabilities (pcap, screenshot, etc.)."""

    @pytest.mark.asyncio()
    async def test_pcap_start(self, sandbox_bridge: SandboxBridge) -> None:
        """pcap_start returns capture_id.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.pcap_start(_WIN_INSTANCE)
        assert "capture_id" in result

    @pytest.mark.asyncio()
    async def test_pcap_start_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """pcap_start on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.pcap_start(_MISSING_INSTANCE)

    @pytest.mark.asyncio()
    async def test_pcap_stop(self, sandbox_bridge: SandboxBridge) -> None:
        """pcap_stop returns pcap_path.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        start = await sandbox_bridge.pcap_start(_WIN_INSTANCE)
        result = await sandbox_bridge.pcap_stop(_WIN_INSTANCE, start["capture_id"])
        assert "pcap_path" in result

    @pytest.mark.asyncio()
    async def test_screenshot(self, sandbox_bridge: SandboxBridge) -> None:
        """screenshot returns screenshot_path.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.screenshot(_WIN_INSTANCE)
        assert "screenshot_path" in result

    @pytest.mark.asyncio()
    async def test_screenshot_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """screenshot on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.screenshot(_MISSING_INSTANCE)

    @pytest.mark.asyncio()
    async def test_anti_evasion(self, sandbox_bridge: SandboxBridge) -> None:
        """anti_evasion returns techniques dict.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.anti_evasion(_WIN_INSTANCE)
        assert "techniques" in result

    @pytest.mark.asyncio()
    async def test_memory_dump(self, sandbox_bridge: SandboxBridge) -> None:
        """memory_dump returns dump_path.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.memory_dump(_WIN_INSTANCE)
        assert "dump_path" in result

    @pytest.mark.asyncio()
    async def test_extract_files(self, sandbox_bridge: SandboxBridge) -> None:
        """extract_dropped_files returns zip_path.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.extract_dropped_files(_WIN_INSTANCE)
        assert "zip_path" in result

    @pytest.mark.asyncio()
    async def test_yara_scan(self, sandbox_bridge: SandboxBridge) -> None:
        """yara_scan returns matches.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.yara_scan(_WIN_INSTANCE)
        assert "matches" in result
        assert result["match_count"] >= 1

    @pytest.mark.asyncio()
    async def test_yara_scan_with_rules(self, sandbox_bridge: SandboxBridge) -> None:
        """yara_scan with rules_path passes it through.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.yara_scan(
            _WIN_INSTANCE,
            rules_path="/rules/custom.yar",
        )
        assert result["match_count"] >= 1

    @pytest.mark.asyncio()
    async def test_yara_scan_memory_target(self, sandbox_bridge: SandboxBridge) -> None:
        """yara_scan with scan_target='memory' succeeds.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.yara_scan(
            _WIN_INSTANCE,
            scan_target="memory",
        )
        assert "matches" in result

    @pytest.mark.asyncio()
    async def test_yara_scan_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """yara_scan on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.yara_scan(_MISSING_INSTANCE)


class TestAnalysisWrappers:
    """Verify analysis method wrappers on the bridge."""

    @pytest.mark.asyncio()
    async def test_extract_iocs_success(self, sandbox_bridge: SandboxBridge) -> None:
        """extract_iocs returns IOC list from report.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.extract_iocs(_WIN_INSTANCE)
        assert "iocs" in result
        assert "count" in result

    @pytest.mark.asyncio()
    async def test_extract_iocs_no_report_raises(self, bridge_no_reports: SandboxBridge) -> None:
        """extract_iocs with no report raises ToolError.

        Args:
            bridge_no_reports: SandboxBridge fixture whose instances have no execution reports.
        """
        with pytest.raises(ToolError, match="No execution report"):
            await bridge_no_reports.extract_iocs(_WIN_NOREPORT)

    @pytest.mark.asyncio()
    async def test_extract_iocs_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """extract_iocs on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.extract_iocs(_MISSING_INSTANCE)

    @pytest.mark.asyncio()
    async def test_timeline_success(self, sandbox_bridge: SandboxBridge) -> None:
        """timeline returns events list.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.timeline(_WIN_INSTANCE)
        assert "events" in result
        assert "count" in result

    @pytest.mark.asyncio()
    async def test_timeline_with_categories(self, sandbox_bridge: SandboxBridge) -> None:
        """timeline with categories filter works.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.timeline(_WIN_INSTANCE, categories=["file"])
        assert "events" in result

    @pytest.mark.asyncio()
    async def test_timeline_no_report_raises(self, bridge_no_reports: SandboxBridge) -> None:
        """timeline with no report raises ToolError.

        Args:
            bridge_no_reports: SandboxBridge fixture whose instances have no execution reports.
        """
        with pytest.raises(ToolError, match="No execution report"):
            await bridge_no_reports.timeline(_WIN_NOREPORT)

    @pytest.mark.asyncio()
    async def test_detect_behaviors_success(self, sandbox_bridge: SandboxBridge) -> None:
        """detect_behaviors returns matches list.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.detect_behaviors(_WIN_INSTANCE)
        assert "matches" in result
        assert "count" in result

    @pytest.mark.asyncio()
    async def test_detect_behaviors_no_report_raises(self, bridge_no_reports: SandboxBridge) -> None:
        """detect_behaviors with no report raises ToolError.

        Args:
            bridge_no_reports: SandboxBridge fixture whose instances have no execution reports.
        """
        with pytest.raises(ToolError, match="No execution report"):
            await bridge_no_reports.detect_behaviors(_WIN_NOREPORT)

    @pytest.mark.asyncio()
    async def test_detect_behaviors_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """detect_behaviors on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.detect_behaviors(_MISSING_INSTANCE)

    @pytest.mark.asyncio()
    async def test_detect_c2_success(self, sandbox_bridge: SandboxBridge) -> None:
        """detect_c2 returns pattern list.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.detect_c2(_WIN_INSTANCE)
        assert "patterns" in result
        assert "count" in result

    @pytest.mark.asyncio()
    async def test_detect_c2_no_report_raises(self, bridge_no_reports: SandboxBridge) -> None:
        """detect_c2 with no report raises ToolError.

        Args:
            bridge_no_reports: SandboxBridge fixture whose instances have no execution reports.
        """
        with pytest.raises(ToolError, match="No execution report"):
            await bridge_no_reports.detect_c2(_WIN_NOREPORT)

    @pytest.mark.asyncio()
    async def test_diff_success(self, sandbox_bridge: SandboxBridge) -> None:
        """diff returns structured diff dict.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.diff(_WIN_INSTANCE, _QEMU_INSTANCE)
        assert "diff" in result
        assert "instance_id_a" in result
        assert "instance_id_b" in result

    @pytest.mark.asyncio()
    async def test_diff_missing_a_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """diff with missing instance_a raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.diff(_MISSING_INSTANCE, _QEMU_INSTANCE)

    @pytest.mark.asyncio()
    async def test_diff_missing_b_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """diff with missing instance_b raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.diff(_WIN_INSTANCE, _MISSING_INSTANCE)

    @pytest.mark.asyncio()
    async def test_diff_no_report_a_raises(self, bridge_no_reports: SandboxBridge) -> None:
        """diff with no report on instance_a raises ToolError.

        Args:
            bridge_no_reports: SandboxBridge fixture whose instances have no execution reports.
        """
        with pytest.raises(ToolError, match="No execution report"):
            await bridge_no_reports.diff(_WIN_NOREPORT, _QEMU_NOREPORT)


class TestGetVncPort:
    """Verify VNC port retrieval."""

    @pytest.mark.asyncio()
    async def test_returns_port(self, sandbox_bridge: SandboxBridge) -> None:
        """get_vnc_port returns port number for instance with VNC.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        port = await sandbox_bridge.get_vnc_port(_WIN_INSTANCE)
        assert port == 5900

    @pytest.mark.asyncio()
    async def test_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """get_vnc_port on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.get_vnc_port(_MISSING_INSTANCE)


class TestReportToDict:
    """Verify _report_to_dict conversion."""

    def test_contains_all_keys(self) -> None:
        """Converted dict contains all expected keys."""
        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="out",
            stderr="err",
            duration_seconds=1.0,
        )
        result = getattr(SandboxBridge, "_report_to_dict")(report, "test-id")
        expected_keys = {
            "instance_id",
            "result",
            "exit_code",
            "stdout",
            "stderr",
            "duration_seconds",
            "file_changes",
            "registry_changes",
            "network_activity",
            "process_activity",
            "api_calls",
            "service_changes",
            "kernel_objects",
            "dll_loads",
            "injection_events",
            "resource_samples",
            "clipboard_events",
        }
        assert expected_keys == set(result.keys())

    def test_preserves_instance_id(self) -> None:
        """Converted dict preserves the instance_id."""
        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
        )
        result = getattr(SandboxBridge, "_report_to_dict")(report, "my-instance")
        assert result["instance_id"] == "my-instance"

    def test_list_fields_are_plain_lists(self) -> None:
        """List fields in converted dict are plain Python lists."""
        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
        )
        result = getattr(SandboxBridge, "_report_to_dict")(report, "test")
        for key in [
            "file_changes",
            "registry_changes",
            "network_activity",
            "process_activity",
            "api_calls",
            "service_changes",
            "kernel_objects",
            "dll_loads",
            "injection_events",
            "resource_samples",
            "clipboard_events",
        ]:
            assert isinstance(result[key], list)
