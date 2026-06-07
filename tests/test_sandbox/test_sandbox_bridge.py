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

import hashlib
import inspect
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError, ToolName
from intellicrack.sandbox.base import ExecutionReport
from tests.test_sandbox.conftest import LocalProcessSandbox, StubInstance


if TYPE_CHECKING:
    from intellicrack.sandbox.base import SandboxConfig
    from intellicrack.sandbox.manager import SandboxManager


_EXPECTED_FUNC_COUNT: Final[int] = 27
_MIN_DESC_LEN: Final[int] = 5
_WIN_INSTANCE: Final[str] = "win-test-001"
_QEMU_INSTANCE: Final[str] = "qemu-test-001"
_WIN_NOREPORT: Final[str] = "win-noreport-001"
_QEMU_NOREPORT: Final[str] = "qemu-noreport-001"
_MISSING_INSTANCE: Final[str] = "nonexistent-instance"
_REPORT_DICT_KEY_COUNT: Final[int] = 17
_REAL_INSTANCE: Final[str] = "real-localproc-001"


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

    @pytest.mark.asyncio
    async def test_initialize_creates_manager(self) -> None:
        """Initialize creates a manager."""
        bridge = SandboxBridge()
        await bridge.initialize()
        assert getattr(bridge, "_manager") is not None

    @pytest.mark.asyncio
    async def test_initialize_sets_connected(self) -> None:
        """Initialize sets state to connected."""
        bridge = SandboxBridge()
        await bridge.initialize()
        assert bridge.state.connected is True

    @pytest.mark.asyncio
    async def test_shutdown_clears_manager(self, sandbox_bridge: SandboxBridge) -> None:
        """Shutdown clears the manager.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        await sandbox_bridge.shutdown()
        assert getattr(sandbox_bridge, "_manager") is None

    @pytest.mark.asyncio
    async def test_shutdown_resets_state(self, sandbox_bridge: SandboxBridge) -> None:
        """Shutdown resets state.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        await sandbox_bridge.shutdown()
        assert sandbox_bridge.state.connected is False

    @pytest.mark.asyncio
    async def test_ensure_manager_creates(self) -> None:
        """ensure_manager creates manager if None."""
        bridge = SandboxBridge()
        mgr = bridge.ensure_manager()
        assert mgr is not None

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
    async def test_create_qemu(self, sandbox_bridge: SandboxBridge) -> None:
        """Create with qemu type succeeds.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.create(sandbox_type="qemu")
        assert result["type"] == "qemu"

    @pytest.mark.asyncio
    async def test_destroy_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Destroy existing instance returns success.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.destroy(_WIN_INSTANCE)
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_destroy_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Destroy nonexistent instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.destroy(_MISSING_INSTANCE)

    @pytest.mark.asyncio
    async def test_create_failure_raises(self) -> None:
        """Create on bridge with no available types raises ToolError on real manager."""
        bridge = SandboxBridge()
        await bridge.initialize()
        with pytest.raises(ToolError):
            await bridge.create(sandbox_type="windows")


class TestExecuteCommand:
    """Verify command execution in sandbox."""

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
    async def test_execute_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Execute on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.execute(_MISSING_INSTANCE, "dir")


class TestFileCopy:
    """Verify file copy operations."""

    @pytest.mark.asyncio
    async def test_copy_to_missing_instance(self, sandbox_bridge: SandboxBridge) -> None:
        """Copy to missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.copy_to(_MISSING_INSTANCE, "src.txt", "dest.txt")

    @pytest.mark.asyncio
    async def test_copy_to_missing_source(self, sandbox_bridge: SandboxBridge) -> None:
        """Copy with nonexistent source file raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.copy_to(_WIN_INSTANCE, "/nonexistent/file.bin", "dest.txt")

    @pytest.mark.asyncio
    async def test_copy_from_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Copy from sandbox returns success dict.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.copy_from(_WIN_INSTANCE, "sandbox_file.txt", "local.txt")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_copy_from_missing_instance(self, sandbox_bridge: SandboxBridge) -> None:
        """Copy from missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.copy_from(_MISSING_INSTANCE, "src.txt", "dest.txt")


class TestStatusAndList:
    """Verify status and list operations."""

    @pytest.mark.asyncio
    async def test_status_returns_dict(self, sandbox_bridge: SandboxBridge) -> None:
        """Status returns dict with expected keys.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.status()
        assert "available_types" in result
        assert "active_count" in result
        assert "instances" in result

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
    async def test_snapshot_create_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot create on QEMU returns snapshot_id.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.snapshot_create(_QEMU_INSTANCE, "snap1")
        assert "snapshot_id" in result

    @pytest.mark.asyncio
    async def test_snapshot_create_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot create on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.snapshot_create(_WIN_INSTANCE, "snap1")

    @pytest.mark.asyncio
    async def test_snapshot_create_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot create on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.snapshot_create(_MISSING_INSTANCE, "snap1")

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
    async def test_snapshot_restore_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot restore on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.snapshot_restore(_WIN_INSTANCE, "snap-001")

    @pytest.mark.asyncio
    async def test_snapshot_list_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot list on QEMU returns snapshot list.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        await sandbox_bridge.snapshot_create(_QEMU_INSTANCE, "list_test")
        result = await sandbox_bridge.snapshot_list(_QEMU_INSTANCE)
        assert "snapshots" in result
        assert len(result["snapshots"]) >= 1

    @pytest.mark.asyncio
    async def test_snapshot_list_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot list on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.snapshot_list(_WIN_INSTANCE)

    @pytest.mark.asyncio
    async def test_snapshot_delete_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot delete on QEMU succeeds.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        await sandbox_bridge.snapshot_create(_QEMU_INSTANCE, "del_test")
        result = await sandbox_bridge.snapshot_delete(_QEMU_INSTANCE, "del_test")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_snapshot_delete_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot delete on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.snapshot_delete(_WIN_INSTANCE, "snap1")


class TestQEMUSpecificMethods:
    """Verify QEMU-specific methods (cont, pending messages)."""

    @pytest.mark.asyncio
    async def test_cont_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Cont on QEMU with QMP returns success.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.cont(_QEMU_INSTANCE)
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_cont_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Cont on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.cont(_WIN_INSTANCE)

    @pytest.mark.asyncio
    async def test_cont_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Cont on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.cont(_MISSING_INSTANCE)

    @pytest.mark.asyncio
    async def test_pending_messages_success(self, sandbox_bridge: SandboxBridge) -> None:
        """get_pending_messages returns messages from agent.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.get_pending_messages(_QEMU_INSTANCE)
        assert "messages" in result
        assert result["count"] >= 1

    @pytest.mark.asyncio
    async def test_pending_messages_non_qemu_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """get_pending_messages on non-QEMU raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError, match="QEMU"):
            await sandbox_bridge.get_pending_messages(_WIN_INSTANCE)

    @pytest.mark.asyncio
    async def test_pending_messages_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """get_pending_messages on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.get_pending_messages(_MISSING_INSTANCE)


class TestNewCapabilities:
    """Verify new sandbox capabilities (pcap, screenshot, etc.)."""

    @pytest.mark.asyncio
    async def test_pcap_start(self, sandbox_bridge: SandboxBridge) -> None:
        """Pcap_start returns capture_id.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.pcap_start(_QEMU_INSTANCE)
        assert "capture_id" in result

    @pytest.mark.asyncio
    async def test_pcap_start_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Pcap_start on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.pcap_start(_MISSING_INSTANCE)

    @pytest.mark.asyncio
    async def test_pcap_stop(self, sandbox_bridge: SandboxBridge) -> None:
        """Pcap_stop returns pcap_path.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        start = await sandbox_bridge.pcap_start(_QEMU_INSTANCE)
        result = await sandbox_bridge.pcap_stop(_QEMU_INSTANCE, start["capture_id"])
        assert "pcap_path" in result

    @pytest.mark.asyncio
    async def test_screenshot(self, sandbox_bridge: SandboxBridge) -> None:
        """Screenshot returns screenshot_path.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.screenshot(_QEMU_INSTANCE)
        assert "screenshot_path" in result

    @pytest.mark.asyncio
    async def test_screenshot_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Screenshot on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.screenshot(_MISSING_INSTANCE)

    @pytest.mark.asyncio
    async def test_anti_evasion(self, sandbox_bridge: SandboxBridge) -> None:
        """Anti_evasion returns techniques dict.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.anti_evasion(_QEMU_INSTANCE)
        assert "techniques" in result

    @pytest.mark.asyncio
    async def test_memory_dump(self, sandbox_bridge: SandboxBridge) -> None:
        """Memory_dump returns dump_path.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.memory_dump(_QEMU_INSTANCE)
        assert "dump_path" in result

    @pytest.mark.asyncio
    async def test_extract_files(self, sandbox_bridge: SandboxBridge) -> None:
        """Extract_dropped_files returns zip_path.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.extract_dropped_files(_QEMU_INSTANCE)
        assert "zip_path" in result

    @pytest.mark.asyncio
    async def test_yara_scan(self, sandbox_bridge: SandboxBridge) -> None:
        """yara_scan returns matches.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.yara_scan(_WIN_INSTANCE)
        assert "matches" in result
        assert result["match_count"] >= 1

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
    async def test_yara_scan_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """yara_scan on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.yara_scan(_MISSING_INSTANCE)


class TestAnalysisWrappers:
    """Verify analysis method wrappers on the bridge."""

    @pytest.mark.asyncio
    async def test_extract_iocs_success(self, sandbox_bridge: SandboxBridge) -> None:
        """extract_iocs returns IOC list from report.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.extract_iocs(_WIN_INSTANCE)
        assert "iocs" in result
        assert "count" in result

    @pytest.mark.asyncio
    async def test_extract_iocs_no_report_raises(self, bridge_no_reports: SandboxBridge) -> None:
        """extract_iocs with no report raises ToolError.

        Args:
            bridge_no_reports: SandboxBridge fixture whose instances have no execution reports.
        """
        with pytest.raises(ToolError, match="No execution report"):
            await bridge_no_reports.extract_iocs(_WIN_NOREPORT)

    @pytest.mark.asyncio
    async def test_extract_iocs_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """extract_iocs on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.extract_iocs(_MISSING_INSTANCE)

    @pytest.mark.asyncio
    async def test_timeline_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Timeline returns events list.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.timeline(_WIN_INSTANCE)
        assert "events" in result
        assert "count" in result

    @pytest.mark.asyncio
    async def test_timeline_with_categories(self, sandbox_bridge: SandboxBridge) -> None:
        """Timeline with categories filter works.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.timeline(_WIN_INSTANCE, categories=["file"])
        assert "events" in result

    @pytest.mark.asyncio
    async def test_timeline_no_report_raises(self, bridge_no_reports: SandboxBridge) -> None:
        """Timeline with no report raises ToolError.

        Args:
            bridge_no_reports: SandboxBridge fixture whose instances have no execution reports.
        """
        with pytest.raises(ToolError, match="No execution report"):
            await bridge_no_reports.timeline(_WIN_NOREPORT)

    @pytest.mark.asyncio
    async def test_detect_behaviors_success(self, sandbox_bridge: SandboxBridge) -> None:
        """detect_behaviors returns matches list.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.detect_behaviors(_WIN_INSTANCE)
        assert "matches" in result
        assert "count" in result

    @pytest.mark.asyncio
    async def test_detect_behaviors_no_report_raises(self, bridge_no_reports: SandboxBridge) -> None:
        """detect_behaviors with no report raises ToolError.

        Args:
            bridge_no_reports: SandboxBridge fixture whose instances have no execution reports.
        """
        with pytest.raises(ToolError, match="No execution report"):
            await bridge_no_reports.detect_behaviors(_WIN_NOREPORT)

    @pytest.mark.asyncio
    async def test_detect_behaviors_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """detect_behaviors on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.detect_behaviors(_MISSING_INSTANCE)

    @pytest.mark.asyncio
    async def test_detect_c2_success(self, sandbox_bridge: SandboxBridge) -> None:
        """detect_c2 returns pattern list.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.detect_c2(_WIN_INSTANCE)
        assert "patterns" in result
        assert "count" in result

    @pytest.mark.asyncio
    async def test_detect_c2_no_report_raises(self, bridge_no_reports: SandboxBridge) -> None:
        """detect_c2 with no report raises ToolError.

        Args:
            bridge_no_reports: SandboxBridge fixture whose instances have no execution reports.
        """
        with pytest.raises(ToolError, match="No execution report"):
            await bridge_no_reports.detect_c2(_WIN_NOREPORT)

    @pytest.mark.asyncio
    async def test_diff_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Diff returns structured diff dict.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.diff(_WIN_INSTANCE, _QEMU_INSTANCE)
        assert "diff" in result
        assert "instance_id_a" in result
        assert "instance_id_b" in result

    @pytest.mark.asyncio
    async def test_diff_missing_a_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Diff with missing instance_a raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.diff(_MISSING_INSTANCE, _QEMU_INSTANCE)

    @pytest.mark.asyncio
    async def test_diff_missing_b_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Diff with missing instance_b raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.diff(_WIN_INSTANCE, _MISSING_INSTANCE)

    @pytest.mark.asyncio
    async def test_diff_no_report_a_raises(self, bridge_no_reports: SandboxBridge) -> None:
        """Diff with no report on instance_a raises ToolError.

        Args:
            bridge_no_reports: SandboxBridge fixture whose instances have no execution reports.
        """
        with pytest.raises(ToolError, match="No execution report"):
            await bridge_no_reports.diff(_WIN_NOREPORT, _QEMU_NOREPORT)


class TestGetVncPort:
    """Verify VNC port retrieval."""

    @pytest.mark.asyncio
    async def test_returns_port(self, sandbox_bridge: SandboxBridge) -> None:
        """Get_vnc_port returns port number for instance with VNC.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        port = await sandbox_bridge.get_vnc_port(_QEMU_INSTANCE)
        assert port == 5900

    @pytest.mark.asyncio
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


class _RealLocalManager:
    """A real, non-mock manager that drives a genuine ``LocalProcessSandbox``.

    Unlike the in-memory stub manager, this manager executes binaries as real
    OS subprocesses through :class:`LocalProcessSandbox`, captures their real
    exit code, stdout, stderr, and the file-system changes actually observed by
    diffing the work directory. It exposes exactly the surface the
    :class:`SandboxBridge` reaches for (``run_binary``, ``get``, ``instances``,
    ``destroy``, ``get_status``, ``get_available_types``) so the bridge's own
    code paths -- not a simulated double -- are the thing under test.
    """

    def __init__(self, sandbox: LocalProcessSandbox) -> None:
        """Initialise the manager around a started real sandbox.

        Args:
            sandbox: A started :class:`LocalProcessSandbox`.
        """
        self._sandbox: LocalProcessSandbox = sandbox
        inst = StubInstance(sandbox, "windows", instance_id=_REAL_INSTANCE)
        self._instances: dict[str, StubInstance] = {_REAL_INSTANCE: inst}

    @property
    def instances(self) -> list[StubInstance]:
        """Return all tracked instances.

        Returns:
            list[StubInstance]: The live instance list.
        """
        return list(self._instances.values())

    @property
    def active_count(self) -> int:
        """Return the number of running instances.

        Returns:
            int: Count of instances whose status is ``running``.
        """
        return sum(inst.state.status == "running" for inst in self._instances.values())

    async def get(self, instance_id: str) -> StubInstance | None:
        """Return an instance by id.

        Args:
            instance_id: Instance identifier.

        Returns:
            StubInstance | None: The instance, or ``None`` when absent.
        """
        return self._instances.get(instance_id)

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        sandbox_type: str = "windows",
        config: SandboxConfig | None = None,
        time_limit: int | None = None,
        qemu_config: object = None,
        *,
        monitor: bool = True,
        reuse_instance: bool = False,
    ) -> tuple[StubInstance, ExecutionReport]:
        """Execute a binary for real through the wrapped sandbox.

        Args:
            binary_path: Path to the binary to execute.
            args: Optional command-line arguments.
            sandbox_type: Sandbox flavour (recorded on the instance).
            config: Unused sandbox configuration.
            time_limit: Optional timeout in seconds.
            qemu_config: Unused QEMU configuration.
            monitor: Whether to diff the work directory for file changes.
            reuse_instance: Unused reuse flag.

        Returns:
            tuple[StubInstance, ExecutionReport]: The instance and the real report.
        """
        del config, qemu_config, reuse_instance, sandbox_type
        report = await self._sandbox.run_binary(
            binary_path=binary_path,
            args=args,
            time_limit=time_limit,
            monitor=monitor,
        )
        inst = self._instances[_REAL_INSTANCE]
        inst.binary_path = binary_path
        inst.last_report = report
        return (inst, report)

    async def destroy(self, instance_id: str) -> None:
        """Stop and remove an instance.

        Args:
            instance_id: Instance identifier.

        Raises:
            KeyError: If the instance is unknown.
        """
        if instance_id not in self._instances:
            msg = f"unknown instance: {instance_id}"
            raise KeyError(msg)
        inst = self._instances.pop(instance_id)
        await inst.sandbox.stop()

    async def get_status(self) -> dict[str, object]:
        """Return manager status.

        Returns:
            dict[str, object]: Status with available types and instance summaries.
        """
        return {
            "available_types": await self.get_available_types(),
            "max_instances": 1,
            "active_count": self.active_count,
            "total_count": len(self._instances),
            "instances": [
                {
                    "id": inst.id,
                    "type": inst.sandbox_type,
                    "status": inst.state.status,
                    "created_at": inst.created_at.isoformat(),
                    "last_used": inst.last_used.isoformat(),
                    "binary": str(inst.binary_path) if inst.binary_path else None,
                }
                for inst in self._instances.values()
            ],
        }

    async def get_available_types(self) -> list[str]:
        """Return the supported sandbox types.

        Returns:
            list[str]: The single real backend type.
        """
        return ["windows"]


def _write_driver_script(directory: Path, *, artifact_name: str, payload: bytes, message: str, exit_code: int) -> Path:
    """Write a deterministic Python driver whose every effect is known up front.

    The driver writes ``payload`` to ``artifact_name`` in its current directory,
    prints ``message`` to stdout, and exits with ``exit_code``. Because the test
    chooses all of these independently, they serve as a trusted oracle for the
    behaviour the bridge must faithfully surface.

    Args:
        directory: Directory the script file is written into.
        artifact_name: Name of the artefact the script creates at run time.
        payload: Exact bytes written to the artefact.
        message: Exact text printed to stdout (no trailing newline).
        exit_code: Process exit code the script returns.

    Returns:
        Path: Path to the generated driver script.
    """
    script = directory / "bridge_driver.py"
    source = (
        f"import sys\ndata = {payload!r}\nopen({artifact_name!r}, 'wb').write(data)\nsys.stdout.write({message!r})\nsys.exit({exit_code})\n"
    )
    script.write_text(source, encoding="utf-8")
    return script


@pytest.mark.integration
@pytest.mark.spawns_process
class TestBridgeRealSandboxLifecycle:
    """Drive the bridge against a genuine subprocess-executing sandbox.

    These tests replace the fixture-heavy in-memory paths with a real
    ``LocalProcessSandbox`` so a regression in how the bridge starts execution,
    surfaces process output, or relays observed artefacts is actually caught.
    """

    @staticmethod
    def _bridge_with_real_manager(local_process_sandbox: LocalProcessSandbox) -> SandboxBridge:
        """Build a bridge backed by a real local-process manager.

        Args:
            local_process_sandbox: Started real sandbox fixture.

        Returns:
            SandboxBridge: Bridge with a real manager attached.
        """
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", _RealLocalManager(local_process_sandbox)))
        return bridge

    @pytest.mark.asyncio
    async def test_run_binary_surfaces_real_exit_stdout_and_artifact(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """A real run through the bridge reports the exact exit code, stdout, and dropped file.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory for the driver script.
        """
        payload = b"BRIDGE-REAL-SANDBOX-\x00\x01\x02\xfe\xff"
        script = _write_driver_script(
            tmp_path,
            artifact_name="dropped.bin",
            payload=payload,
            message="bridge-run-ok",
            exit_code=0,
        )
        bridge = self._bridge_with_real_manager(local_process_sandbox)

        result = await bridge.run_binary(str(sys.executable), args=[str(script)], time_limit=60)

        assert result["instance_id"] == _REAL_INSTANCE
        assert result["result"] == "success"
        assert result["exit_code"] == 0
        assert result["stdout"] == "bridge-run-ok"
        assert len(result["stderr"]) == 0
        assert result["duration_seconds"] > 0.0

        created = [c for c in result["file_changes"] if c["operation"] == "created"]
        dropped = [c for c in created if c["path"] == "dropped.bin"]
        assert len(dropped) == 1, f"bridge must surface the one genuinely created artefact, got {result['file_changes']}"
        assert dropped[0]["size"] == len(payload)

        on_disk = local_process_sandbox.workdir / "dropped.bin"
        assert on_disk.read_bytes() == payload
        assert hashlib.sha256(on_disk.read_bytes()).hexdigest() == hashlib.sha256(payload).hexdigest()
        assert bridge.state.binary_loaded is True
        assert bridge.state.target_path == Path(sys.executable)

    @pytest.mark.asyncio
    async def test_run_binary_surfaces_real_nonzero_exit(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """A real non-zero exit is surfaced by the bridge with the exact code and ``error`` result.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory for the driver script.
        """
        script = _write_driver_script(
            tmp_path,
            artifact_name="ignored.bin",
            payload=b"z",
            message="bridge-failed",
            exit_code=9,
        )
        bridge = self._bridge_with_real_manager(local_process_sandbox)

        result = await bridge.run_binary(str(sys.executable), args=[str(script)], time_limit=60)

        assert result["result"] == "error"
        assert result["exit_code"] == 9
        assert result["stdout"] == "bridge-failed"

    @pytest.mark.asyncio
    async def test_run_binary_missing_path_raises_tool_error(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """The bridge raises ``ToolError`` for a non-existent binary before any execution.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory used to build a missing path.
        """
        bridge = self._bridge_with_real_manager(local_process_sandbox)
        missing = tmp_path / "no_such_binary.exe"

        with pytest.raises(ToolError, match="Binary not found"):
            await bridge.run_binary(str(missing), time_limit=10)

    @pytest.mark.asyncio
    async def test_extract_iocs_from_genuinely_observed_artifact_path(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """IOC extraction reflects an IPv4 embedded in a file the process really created.

        The driver drops a file whose name embeds ``203.0.113.50``; the real
        sandbox observes that artefact by diffing its work directory, the bridge
        relays it, and the analysis module extracts the IPv4 from the observed
        ``file_changes`` path. A regression that lost the file-change relay would
        drop the IOC entirely.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory for the driver script.
        """
        script = _write_driver_script(
            tmp_path,
            artifact_name="beacon-203.0.113.50.log",
            payload=b"observed",
            message="dropped",
            exit_code=0,
        )
        bridge = self._bridge_with_real_manager(local_process_sandbox)

        run_result = await bridge.run_binary(str(sys.executable), args=[str(script)], time_limit=60)
        observed_paths = {c["path"] for c in run_result["file_changes"]}
        assert "beacon-203.0.113.50.log" in observed_paths

        ioc_result = await bridge.extract_iocs(_REAL_INSTANCE)

        assert ioc_result["instance_id"] == _REAL_INSTANCE
        ipv4_iocs = {ioc["value"] for ioc in ioc_result["iocs"] if ioc["ioc_type"] == "ipv4"}
        assert "203.0.113.50" in ipv4_iocs
        assert ioc_result["count"] == len(ioc_result["iocs"])

    @pytest.mark.asyncio
    async def test_copy_to_then_copy_from_roundtrips_real_bytes(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """Copying a real file in and back out through the bridge preserves exact bytes.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory for source and destination files.
        """
        payload = bytes(range(256)) + b"ROUNDTRIP"
        source = tmp_path / "input.bin"
        source.write_bytes(payload)
        recovered = tmp_path / "recovered.bin"
        bridge = self._bridge_with_real_manager(local_process_sandbox)

        copy_in = await bridge.copy_to(_REAL_INSTANCE, str(source), "staged/input.bin")
        assert copy_in["success"] is True
        assert (local_process_sandbox.workdir / "staged" / "input.bin").read_bytes() == payload

        copy_out = await bridge.copy_from(_REAL_INSTANCE, "staged/input.bin", str(recovered))
        assert copy_out["success"] is True
        assert recovered.read_bytes() == payload

    @pytest.mark.asyncio
    async def test_copy_from_missing_sandbox_file_raises_tool_error(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """Extracting a file that the sandbox never produced raises ``ToolError``.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory for the destination path.
        """
        bridge = self._bridge_with_real_manager(local_process_sandbox)
        dest = tmp_path / "out.bin"

        with pytest.raises(ToolError, match="Copy from sandbox failed"):
            await bridge.copy_from(_REAL_INSTANCE, "never_created.bin", str(dest))

    @pytest.mark.asyncio
    async def test_status_and_list_reflect_the_real_instance(
        self,
        local_process_sandbox: LocalProcessSandbox,
        tmp_path: Path,
    ) -> None:
        """After a real run the bridge's status and list report the live instance and binary.

        Args:
            local_process_sandbox: Started real sandbox fixture.
            tmp_path: Pytest temporary directory for the driver script.
        """
        script = _write_driver_script(
            tmp_path,
            artifact_name="x.bin",
            payload=b"x",
            message="ok",
            exit_code=0,
        )
        bridge = self._bridge_with_real_manager(local_process_sandbox)
        await bridge.run_binary(str(sys.executable), args=[str(script)], time_limit=60)

        status = await bridge.status()
        assert status["available_types"] == ["windows"]
        assert status["active_count"] == 1
        assert status["total_count"] == 1

        instances = await bridge.list()
        assert len(instances) == 1
        entry = instances[0]
        assert entry["id"] == _REAL_INSTANCE
        assert entry["type"] == "windows"
        assert entry["status"] == "running"
        assert entry["binary"] == str(sys.executable)

    @pytest.mark.asyncio
    async def test_extract_iocs_no_report_raises_before_run(
        self,
        local_process_sandbox: LocalProcessSandbox,
    ) -> None:
        """IOC extraction before any run raises ``ToolError`` because no report exists yet.

        Args:
            local_process_sandbox: Started real sandbox fixture.
        """
        bridge = self._bridge_with_real_manager(local_process_sandbox)

        with pytest.raises(ToolError, match="No execution report"):
            await bridge.extract_iocs(_REAL_INSTANCE)
