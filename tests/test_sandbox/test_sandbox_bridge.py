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
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError, ToolName
from intellicrack.sandbox.base import ExecutionReport
from tests._helpers.process_cleanup import allow_host_process_tests, is_sandboxed
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

# VNC port advertised by the conftest ``InMemoryQEMUSandbox.vnc_port`` property.
_VNC_PORT: Final[int] = 5900

# True when running on host (not inside the Docker sandbox and not explicitly
# opted in).  Used as the ``condition`` for ``@pytest.mark.skipif`` on the
# integration test class so the decorator is visible in the source rather than
# relying solely on the global conftest ``spawns_process`` hook.
INTEGRATION_SANDBOX: Final[bool] = not is_sandboxed() and not allow_host_process_tests()

# The remote address in the ``sandbox_bridge`` fixture's win instance report.
# This is the Tor exit node IP used as a realistic public outbound address.
_WIN_REMOTE_IP: Final[str] = "185.220.101.45"


@pytest.mark.unit
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


@pytest.mark.unit
class TestToolDefinition:
    """Verify tool definition completeness and consistency."""

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

    @pytest.mark.asyncio
    async def test_all_definition_functions_dispatch_to_real_behavior(
        self,
        sandbox_bridge: SandboxBridge,
        tmp_path: Path,
    ) -> None:
        """Every tool-definition function dispatches end-to-end and returns its documented value.

        Resolves each ``tool_definition`` function name to a bridge method exactly the
        way the production ``ToolRegistry.execute_tool_call`` dispatch does (via
        ``getattr``), then *invokes* it against the real fixture instances with arguments
        derived from real fixture state. Each invocation is checked against an oracle
        independent of the bridge: a documented return key whose value is computed from
        the fixture (the known instance IDs, the ``InMemorySandbox`` constant return
        values, the ``StubManager`` advertised types, and a real on-disk source file).

        This replaces the previous existence-only ``hasattr``/``callable`` smoke check:
        a method that exists but returns wrong data, drops the documented key, or relays
        the wrong instance id now fails. The set of names exercised is asserted to equal
        the full set of definition function names, so adding a tool without a real
        dispatch assertion also fails.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
            tmp_path: Pytest temporary directory used for a real copy_to source file.
        """
        bridge = sandbox_bridge
        tmpdir = Path(tempfile.gettempdir())
        source_file = tmp_path / "dispatch_source.bin"
        source_file.write_bytes(b"DISPATCH-SRC\x00\x01")
        recovered = tmp_path / "dispatch_recovered.bin"

        definition_names: set[str] = {
            func.name.split(".", 1)[1] if "." in func.name else func.name for func in bridge.tool_definition.functions
        }
        for name in definition_names:
            method = getattr(bridge, name, None)
            assert callable(method), f"definition function {name!r} does not resolve to a callable bridge method"

        exercised: set[str] = set()

        async def _dispatch(name: str, *args: object, **kwargs: object) -> dict[str, Any]:
            """Invoke a bridge tool by its definition name via getattr dispatch.

            Args:
                name: Bare definition function name (no ``sandbox.`` prefix).
                *args: Positional arguments forwarded to the resolved method.
                **kwargs: Keyword arguments forwarded to the resolved method.

            Returns:
                dict[str, Any]: The dispatched method's result dictionary.
            """
            method: Any = getattr(bridge, name)
            exercised.add(name)
            return cast("dict[str, Any]", await method(*args, **kwargs))

        status = await _dispatch("status")
        assert status["active_count"] == 2
        assert set(status["available_types"]) == {"windows", "qemu"}

        list_entries = cast("list[dict[str, Any]]", await getattr(bridge, "list")())
        exercised.add("list")
        assert {entry["id"] for entry in list_entries} == {_WIN_INSTANCE, _QEMU_INSTANCE}

        vnc_method: Any = getattr(bridge, "get_vnc_port")
        exercised.add("get_vnc_port")
        assert await vnc_method(_QEMU_INSTANCE) == _VNC_PORT

        assert (await _dispatch("execute", _WIN_INSTANCE, "dir"))["stdout"] == "ok: dir"
        assert (await _dispatch("copy_to", _WIN_INSTANCE, str(source_file), "staged.bin"))["success"] is True
        assert (await _dispatch("copy_from", _WIN_INSTANCE, "staged.bin", str(recovered)))["success"] is True

        assert (await _dispatch("yara_scan", _WIN_INSTANCE))["match_count"] == 1
        assert (await _dispatch("extract_iocs", _WIN_INSTANCE))["instance_id"] == _WIN_INSTANCE
        assert (await _dispatch("timeline", _WIN_INSTANCE))["count"] == 2
        assert (await _dispatch("detect_behaviors", _WIN_INSTANCE))["count"] == 0
        assert (await _dispatch("detect_c2", _WIN_INSTANCE))["count"] == 0
        assert (await _dispatch("diff", _WIN_INSTANCE, _QEMU_INSTANCE))["instance_id_a"] == _WIN_INSTANCE

        assert (await _dispatch("cont", _QEMU_INSTANCE))["data"] == {"status": "running"}
        assert (await _dispatch("get_pending_messages", _QEMU_INSTANCE))["count"] == 1
        assert (await _dispatch("screenshot", _QEMU_INSTANCE))["screenshot_path"] == str(tmpdir / "screenshot.png")
        assert (await _dispatch("anti_evasion", _QEMU_INSTANCE))["profile"] == "default"
        assert (await _dispatch("memory_dump", _QEMU_INSTANCE))["dump_path"] == str(tmpdir / "memdump.raw")
        assert (await _dispatch("extract_dropped_files", _QEMU_INSTANCE))["zip_path"] == str(tmpdir / "dropped.zip")

        capture_id = (await _dispatch("pcap_start", _QEMU_INSTANCE))["capture_id"]
        assert capture_id == "cap-001"
        assert (await _dispatch("pcap_stop", _QEMU_INSTANCE, capture_id))["pcap_path"] == str(tmpdir / "capture.pcap")

        snapshot_id = (await _dispatch("snapshot_create", _QEMU_INSTANCE, "dispatch_snap"))["snapshot_id"]
        assert snapshot_id == "snap-dispatch_snap"
        assert (await _dispatch("snapshot_list", _QEMU_INSTANCE))["snapshots"] == [snapshot_id]
        assert (await _dispatch("snapshot_restore", _QEMU_INSTANCE, snapshot_id))["success"] is True
        assert (await _dispatch("snapshot_delete", _QEMU_INSTANCE, "dispatch_snap"))["success"] is True

        created = await _dispatch("create", sandbox_type="qemu")
        assert created["type"] == "qemu"
        assert (await _dispatch("run_binary", sys.executable, sandbox_type="windows"))["result"] == "success"
        assert (await _dispatch("destroy", _WIN_INSTANCE))["success"] is True

        assert exercised == definition_names, (
            f"dispatch coverage drift: not exercised {sorted(definition_names - exercised)}, "
            f"unexpected {sorted(exercised - definition_names)}"
        )

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


@pytest.mark.unit
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


@pytest.mark.unit
class TestCreateDestroy:
    """Verify create and destroy sandbox operations."""

    @pytest.mark.asyncio
    async def test_create_returns_dict(self, sandbox_bridge: SandboxBridge) -> None:
        """Create returns dict with instance_id, type, status, created_at.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.create(sandbox_type="windows")
        assert isinstance(result["instance_id"], str)
        assert len(result["instance_id"]) > 0
        assert result["type"] == "windows"
        assert result["status"] == "running"
        assert isinstance(result["created_at"], str)
        assert result["created_at"].endswith("+00:00")

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
    async def test_create_translates_unavailable_type_to_typed_tool_error(self) -> None:
        """Create against the real manager raises a typed ToolError pinned to the capability-absence reason.

        Drives the genuine ``SandboxManager`` (created by ``initialize``), which probes
        ``WindowsSandbox.is_available()``. The oracle is the manager's own contract in
        ``intellicrack.sandbox.manager.SandboxManager.create``: when the type is not
        available it raises ``SandboxError("Sandbox type not available: windows")``, and
        the bridge must wrap that as ``ToolError`` prefixed with ``"Failed to create
        sandbox"`` while recording the unwrapped manager reason in
        ``state.last_error``. The ``match`` and ``last_error`` assertions pin *why* the
        failure occurred, so a regression that fails create for an unrelated reason (or
        stops translating the manager error / stops recording ``last_error``) no longer
        passes vacuously.

        When the host genuinely provides Windows Sandbox the create-failure path cannot
        be exercised, so the test skips rather than asserting a contradiction.
        """
        bridge = SandboxBridge()
        await bridge.initialize()
        manager = bridge.ensure_manager()
        available = await manager.get_available_types()
        if "windows" in available:
            pytest.skip("Windows Sandbox is available on this host; the create-failure path cannot be exercised")

        with pytest.raises(ToolError, match="Failed to create sandbox: Sandbox type not available: windows"):
            await bridge.create(sandbox_type="windows")

        assert bridge.state.last_error == "Sandbox type not available: windows"


@pytest.mark.unit
class TestExecuteCommand:
    """Verify command execution in sandbox."""

    @pytest.mark.asyncio
    async def test_execute_returns_output(self, sandbox_bridge: SandboxBridge) -> None:
        """Execute returns dict with exact exit_code, stdout, stderr from InMemorySandbox.

        InMemorySandbox.run_command returns ``(0, f"ok: {command}", "")``, so the bridge
        must surface exactly those values without transformation.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.execute(_WIN_INSTANCE, "dir")
        assert result["exit_code"] == 0
        assert result["stdout"] == "ok: dir"
        assert not result["stderr"]

    @pytest.mark.asyncio
    async def test_execute_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """Execute on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.execute(_MISSING_INSTANCE, "dir")


@pytest.mark.unit
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


@pytest.mark.unit
class TestStatusAndList:
    """Verify status and list operations."""

    @pytest.mark.asyncio
    async def test_status_returns_dict(self, sandbox_bridge: SandboxBridge) -> None:
        """Status returns dict with exact values from StubManager.

        The StubManager advertises ``["windows", "qemu"]`` as available types,
        both fixtures are started (status ``"running"``), so ``active_count`` is 2
        and the instances list has exactly 2 entries with the known IDs.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.status()
        assert set(result["available_types"]) == {"windows", "qemu"}
        assert result["active_count"] == 2
        instance_ids = {inst["id"] for inst in result["instances"]}
        assert instance_ids == {_WIN_INSTANCE, _QEMU_INSTANCE}

    @pytest.mark.asyncio
    async def test_list_returns_instances(self, sandbox_bridge: SandboxBridge) -> None:
        """List returns exact instance records for both pre-populated instances.

        The fixture creates one ``windows`` and one ``qemu`` instance, both
        ``running``. The bridge must faithfully relay IDs, types, and statuses.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.list()
        assert len(result) == 2
        by_id = {entry["id"]: entry for entry in result}
        assert by_id[_WIN_INSTANCE]["type"] == "windows"
        assert by_id[_WIN_INSTANCE]["status"] == "running"
        assert by_id[_QEMU_INSTANCE]["type"] == "qemu"
        assert by_id[_QEMU_INSTANCE]["status"] == "running"


@pytest.mark.unit
class TestSnapshots:
    """Verify snapshot operations (QEMU only)."""

    @pytest.mark.asyncio
    async def test_snapshot_create_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Snapshot create on QEMU returns snapshot_id with expected name-based format.

        ``InMemorySandbox.take_snapshot(name)`` returns ``f"snap-{name}"`` which the
        bridge must surface without modification as ``snapshot_id``.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.snapshot_create(_QEMU_INSTANCE, "snap1")
        assert result["snapshot_id"] == "snap-snap1"
        assert result["name"] == "snap1"
        assert result["instance_id"] == _QEMU_INSTANCE

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
        """Snapshot list surfaces the exact snapshot ID created by take_snapshot.

        After creating ``"list_test"``, ``InMemorySandbox.list_snapshots()`` returns
        ``["snap-list_test"]``. The bridge must relay that exact value.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        await sandbox_bridge.snapshot_create(_QEMU_INSTANCE, "list_test")
        result = await sandbox_bridge.snapshot_list(_QEMU_INSTANCE)
        assert result["instance_id"] == _QEMU_INSTANCE
        assert result["count"] == len(result["snapshots"])
        assert "snap-list_test" in result["snapshots"]

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


@pytest.mark.unit
class TestQEMUSpecificMethods:
    """Verify QEMU-specific methods (cont, pending messages)."""

    @pytest.mark.asyncio
    async def test_cont_success(self, sandbox_bridge: SandboxBridge) -> None:
        """Cont on QEMU surfaces the exact QMP response from StubQMP.

        ``StubQMP.cont()`` returns ``QMPResponse(success=True, data={"status": "running"})``.
        The bridge must relay ``success=True``, the QMP response's ``data`` dict,
        and the ``instance_id``.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.cont(_QEMU_INSTANCE)
        assert result["success"] is True
        assert result["instance_id"] == _QEMU_INSTANCE
        assert result["data"] == {"status": "running"}

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
        """get_pending_messages faithfully relays the StubAgent's single heartbeat message.

        ``StubAgent.get_pending_messages()`` returns exactly one ``AgentMessage`` with
        ``message_type="heartbeat"``. The bridge must serialise it without dropping or
        renaming the type field; the result must have ``count == 1`` and
        ``messages[0]["type"] == "heartbeat"``.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.get_pending_messages(_QEMU_INSTANCE)
        assert result["count"] == 1
        assert len(result["messages"]) == 1
        assert result["messages"][0]["type"] == "heartbeat"

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


@pytest.mark.unit
class TestNewCapabilities:
    """Verify new sandbox capabilities (pcap, screenshot, etc.)."""

    @pytest.mark.asyncio
    async def test_pcap_start(self, sandbox_bridge: SandboxBridge) -> None:
        """Pcap_start returns the exact capture_id from InMemorySandbox.

        ``InMemorySandbox.start_pcap_capture()`` always returns ``"cap-001"`` and
        the bridge must relay that value unchanged.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.pcap_start(_QEMU_INSTANCE)
        assert result["capture_id"] == "cap-001"
        assert result["instance_id"] == _QEMU_INSTANCE

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
        """Pcap_stop surfaces the exact PCAP path from InMemorySandbox.

        ``InMemorySandbox.stop_pcap_capture()`` returns ``_TMPDIR / "capture.pcap"``
        when no output path is supplied; the bridge must relay that exact string path.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        start = await sandbox_bridge.pcap_start(_QEMU_INSTANCE)
        result = await sandbox_bridge.pcap_stop(_QEMU_INSTANCE, start["capture_id"])
        expected_path = str(Path(tempfile.gettempdir()) / "capture.pcap")
        assert result["pcap_path"] == expected_path
        assert result["capture_id"] == start["capture_id"]
        assert result["instance_id"] == _QEMU_INSTANCE

    @pytest.mark.asyncio
    async def test_screenshot(self, sandbox_bridge: SandboxBridge) -> None:
        """Screenshot surfaces the exact path from InMemorySandbox.

        ``InMemorySandbox.capture_screenshot()`` returns ``_TMPDIR / "screenshot.png"``
        when no output path is supplied; the bridge must relay that exact string path.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.screenshot(_QEMU_INSTANCE)
        expected_path = str(Path(tempfile.gettempdir()) / "screenshot.png")
        assert result["screenshot_path"] == expected_path
        assert result["instance_id"] == _QEMU_INSTANCE

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
        """Anti_evasion surfaces the exact techniques dict from InMemorySandbox.

        ``InMemorySandbox.apply_anti_evasion("default")`` returns
        ``{"profile": "default", "techniques_applied": 5}``; the bridge must relay
        that dict unchanged inside the ``techniques`` field.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.anti_evasion(_QEMU_INSTANCE)
        assert result["instance_id"] == _QEMU_INSTANCE
        assert result["profile"] == "default"
        assert result["techniques"] == {"profile": "default", "techniques_applied": 5}

    @pytest.mark.asyncio
    async def test_memory_dump(self, sandbox_bridge: SandboxBridge) -> None:
        """Memory_dump on a QEMU instance surfaces the exact path from InMemorySandbox.

        ``InMemorySandbox.dump_memory()`` returns ``_TMPDIR / "memdump.raw"`` when no
        output path is supplied; QEMU does not require ``target_pid``.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.memory_dump(_QEMU_INSTANCE)
        expected_path = str(Path(tempfile.gettempdir()) / "memdump.raw")
        assert result["dump_path"] == expected_path
        assert result["instance_id"] == _QEMU_INSTANCE

    @pytest.mark.asyncio
    async def test_extract_files(self, sandbox_bridge: SandboxBridge) -> None:
        """Extract_dropped_files surfaces the exact ZIP path from InMemorySandbox.

        ``InMemorySandbox.extract_dropped_files()`` returns ``_TMPDIR / "dropped.zip"``
        when no output path is supplied; the bridge must relay that exact string path.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.extract_dropped_files(_QEMU_INSTANCE)
        expected_path = str(Path(tempfile.gettempdir()) / "dropped.zip")
        assert result["zip_path"] == expected_path
        assert result["instance_id"] == _QEMU_INSTANCE

    @pytest.mark.asyncio
    async def test_yara_scan(self, sandbox_bridge: SandboxBridge) -> None:
        """yara_scan surfaces the exact match from InMemorySandbox.

        ``InMemorySandbox.yara_scan()`` returns exactly one match with
        ``rule="SuspiciousPE"``, ``target="files"``, ``rules_file="builtin"``
        when no custom rules are supplied and ``scan_target`` defaults to ``"files"``.
        The bridge must relay all fields without truncation.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.yara_scan(_WIN_INSTANCE)
        assert result["match_count"] == 1
        assert result["matches"][0]["rule"] == "SuspiciousPE"
        assert result["matches"][0]["target"] == "files"
        assert result["matches"][0]["rules_file"] == "builtin"

    @pytest.mark.asyncio
    async def test_yara_scan_with_rules(self, sandbox_bridge: SandboxBridge) -> None:
        """yara_scan with rules_path passes the path through to InMemorySandbox.

        When ``rules_path="/rules/custom.yar"`` is supplied, ``InMemorySandbox``
        echoes that path as ``rules_file`` in the match. The bridge must preserve it.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.yara_scan(
            _WIN_INSTANCE,
            rules_path="/rules/custom.yar",
        )
        assert result["match_count"] == 1
        assert result["matches"][0]["rules_file"] == "/rules/custom.yar"

    @pytest.mark.asyncio
    async def test_yara_scan_memory_target(self, sandbox_bridge: SandboxBridge) -> None:
        """yara_scan with scan_target='memory' surfaces the correct target field.

        ``InMemorySandbox.yara_scan(scan_target="memory")`` echoes ``"memory"`` in
        the match's ``target`` field; the bridge must relay that unchanged.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.yara_scan(
            _WIN_INSTANCE,
            scan_target="memory",
        )
        assert result["match_count"] == 1
        assert result["matches"][0]["target"] == "memory"

    @pytest.mark.asyncio
    async def test_yara_scan_missing_raises(self, sandbox_bridge: SandboxBridge) -> None:
        """yara_scan on missing instance raises ToolError.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        with pytest.raises(ToolError):
            await sandbox_bridge.yara_scan(_MISSING_INSTANCE)


@pytest.mark.unit
class TestAnalysisWrappers:
    """Verify analysis method wrappers on the bridge."""

    @pytest.mark.asyncio
    async def test_extract_iocs_success(self, sandbox_bridge: SandboxBridge) -> None:
        """extract_iocs returns the exact IOC surfaced by the win instance's report.

        The win instance's ``last_report`` contains one outbound TCP connection to
        ``185.220.101.45:443`` (a real Tor exit node used as a realistic public address).
        That public IPv4 address must appear as the sole ``ipv4`` IOC in the result.
        A regression that silently dropped network-activity IOCs would make this test
        go red.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.extract_iocs(_WIN_INSTANCE)
        assert result["instance_id"] == _WIN_INSTANCE
        assert result["count"] == len(result["iocs"])
        ipv4_values = {ioc["value"] for ioc in result["iocs"] if ioc["ioc_type"] == "ipv4"}
        assert _WIN_REMOTE_IP in ipv4_values
        assert result["count"] >= 1

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
        """Timeline returns the exact 2 events produced by the win instance's report.

        The win instance's ``last_report`` has 1 file change and 1 network activity.
        ``generate_timeline`` merges all monitoring streams, so the unfiltered timeline
        must have exactly 2 events. The bridge must relay ``count`` == ``len(events)``.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.timeline(_WIN_INSTANCE)
        assert result["instance_id"] == _WIN_INSTANCE
        assert result["count"] == 2
        assert len(result["events"]) == 2
        categories = {ev["category"] for ev in result["events"]}
        assert categories == {"file", "network"}

    @pytest.mark.asyncio
    async def test_timeline_with_categories(self, sandbox_bridge: SandboxBridge) -> None:
        """Timeline with categories=['file'] returns exactly the 1 file event.

        Filtering to ``"file"`` must suppress the network event and surface only the
        1 file-change entry from the win instance's report.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.timeline(_WIN_INSTANCE, categories=["file"])
        assert result["count"] == 1
        assert result["events"][0]["category"] == "file"

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
        """detect_behaviors returns the exact 0 matches from the win instance's clean report.

        The win instance's report has no persistence, no injection events, no anti-debug
        calls, no suspicious sleep, no beaconing network pattern. ``match_behaviors``
        must return 0 matches; the bridge must surface ``count == 0`` and an empty list.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.detect_behaviors(_WIN_INSTANCE)
        assert result["instance_id"] == _WIN_INSTANCE
        assert result["count"] == 0
        assert result["matches"] == []

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
        """detect_c2 returns 0 patterns for the win instance's single non-C2 connection.

        The win instance has one outbound TCP connection to ``185.220.101.45:443``. Port 443
        is HTTPS (not in ``_C2_PORTS``), there is only a single connection (beaconing
        requires 3+), no DGA domain, and 256 bytes sent (far below exfiltration threshold).
        The bridge must surface ``count == 0`` and an empty patterns list.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.detect_c2(_WIN_INSTANCE)
        assert result["instance_id"] == _WIN_INSTANCE
        assert result["count"] == 0
        assert result["patterns"] == []

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
        """Diff returns correct instance IDs and a non-empty diff structure.

        The win and qemu instances have different reports; the bridge must relay
        ``instance_id_a`` and ``instance_id_b`` exactly and include a ``diff`` dict
        with the per-field comparison keys from ``diff_reports``.

        Args:
            sandbox_bridge: SandboxBridge fixture with pre-populated windows and qemu instances.
        """
        result = await sandbox_bridge.diff(_WIN_INSTANCE, _QEMU_INSTANCE)
        assert result["instance_id_a"] == _WIN_INSTANCE
        assert result["instance_id_b"] == _QEMU_INSTANCE
        diff_section: dict[str, object] = cast("dict[str, object]", result["diff"])
        assert len(diff_section) > 0

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


@pytest.mark.unit
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


@pytest.mark.unit
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
@pytest.mark.skipif(
    INTEGRATION_SANDBOX,
    reason=(
        "Integration tests require real subprocess execution; run inside the "
        "Docker sandbox ('just test') or set INTELLICRACK_ALLOW_HOST_PROCESS_TESTS=1 "
        "to override."
    ),
)
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
