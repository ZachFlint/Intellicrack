# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness remediation gates for the SANDBOX slice (L1 + L2).

Covers agent-10 (``audit/bridge-completeness/agent-10-sandbox-process.md``)
and its verifier (``audit/bridge-completeness/verify/agent-10-sandbox-process-verification.md``):

* S14 -- ``SandboxBridge.stop`` (VM pause) is a real QMP-backed method (L1)
  and is now registered as ``sandbox.stop`` and dispatchable via
  :class:`~intellicrack.core.tools.ToolRegistry` (L2).
* S19 -- ``SandboxBridge.stop_pcap`` (cleanup PCAP-stop) is a real,
  tolerant-no-op method (L1) and is now registered as ``sandbox.stop_pcap``
  and dispatchable via the registry (L2).
* The capability-gate regression: ``sandbox.stop``'s bare method name
  (``stop``) collides with the generic debugger ``TOOL_CAPABILITY_MAP["stop"]
  == "debugging"`` entry, while ``SandboxBridge`` only advertises
  ``supports_dynamic_analysis``. Dispatch must resolve the capability by the
  full dotted ``function_name`` (``"sandbox.stop" -> "dynamic_analysis"``)
  first, not the bare attribute name, or every ``sandbox.stop`` call is
  wrongly blocked as a missing-capability error.
* S2 -- ``sandbox.create``'s VM/environment configuration parameters
  (``timeout_seconds``, ``network_enabled``, ``memory_limit_mb``) are real,
  independently observable ``SandboxConfig`` fields on the created instance.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolError, ToolName
from tests.sandbox.conftest import (
    InMemoryQEMUSandbox,
    InMemorySandbox,
    QMPResponse,
    StubInstance,
    StubManager,
    StubQMP,
)


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.sandbox.base import SandboxConfig
    from intellicrack.sandbox.manager import SandboxManager


class _StubQMPWithStop(StubQMP):
    """QMP client stub exposing a real ``stop()`` in addition to the inherited ``cont()``.

    ``tests.sandbox.conftest.StubQMP`` only implements ``cont()``, since
    it was built for the already-registered ``sandbox.cont`` path. The
    genuine external boundary this slice's tests cannot cross is the real
    QEMU QMP wire protocol; this stub stands in for that boundary only, while
    the real ``SandboxBridge.stop`` method body (state lookup, sandbox-type
    guard, QMP call, response handling, instance bookkeeping) executes for
    real against it. Subclassing ``StubQMP`` (rather than a standalone class)
    keeps it assignable to ``InMemoryQEMUSandbox.qmp``, whose declared type is
    ``StubQMP``.
    """

    def __init__(self) -> None:
        """Initialise the stub with no recorded calls."""
        self.stop_calls: int = 0

    async def stop(self) -> QMPResponse:
        """Return a successful stop response and record the call.

        Returns:
            QMPResponse: A successful QMP response.
        """
        self.stop_calls += 1
        return QMPResponse(success=True, data={"status": "paused"})


@pytest.fixture
def qemu_manager_with_stop() -> tuple[StubManager, _StubQMPWithStop, str]:
    """Build a real ``SandboxBridge``-compatible manager wrapping a QEMU instance.

    Returns:
        tuple[StubManager, _StubQMPWithStop, str]: The stub manager, the QMP
        stub attached to its single instance (for call-count assertions), and
        that instance's id.
    """
    sandbox = InMemoryQEMUSandbox()
    qmp = _StubQMPWithStop()
    sandbox.qmp = qmp
    instance = StubInstance(sandbox, "qemu", instance_id="qemu-stop-001")
    manager = StubManager({"qemu-stop-001": instance})
    return manager, qmp, "qemu-stop-001"


class TestSandboxStopL1:
    """L1: ``SandboxBridge.stop`` performs a real QMP pause and returns real data.

    Falsified by: reverting ``sandbox_bridge.py``'s ``stop`` method body
    (``sandbox_bridge.py:1621-1672``) to a stub/no-op, or breaking its QMP
    response handling, turns every assertion below red.
    """

    @pytest.mark.asyncio
    async def test_stop_calls_qmp_and_returns_paused_status(
        self,
        qemu_manager_with_stop: tuple[StubManager, _StubQMPWithStop, str],
    ) -> None:
        """stop() invokes the real QMP stop() exactly once and reports status=paused.

        Args:
            qemu_manager_with_stop: Fixture providing a manager, QMP stub, and instance id.
        """
        manager, qmp, instance_id = qemu_manager_with_stop
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", manager))

        result = await bridge.stop(instance_id)

        assert qmp.stop_calls == 1, "SandboxBridge.stop must call the QMP client's stop() exactly once"
        assert result["success"] is True
        assert result["status"] == "paused"
        assert result["instance_id"] == instance_id

    @pytest.mark.asyncio
    async def test_stop_rejects_non_qemu_instance(self) -> None:
        """stop() raises ToolError for a Windows-type instance (QEMU-only operation)."""
        sandbox = InMemorySandbox()
        instance = StubInstance(sandbox, "windows", instance_id="win-001")
        manager = StubManager({"win-001": instance})
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", manager))

        with pytest.raises(ToolError, match="QEMU"):
            await bridge.stop("win-001")

    @pytest.mark.asyncio
    async def test_stop_unknown_instance_raises(self) -> None:
        """stop() raises ToolError when the instance id is not found in the manager."""
        manager = StubManager({})
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", manager))

        with pytest.raises(ToolError, match="not found"):
            await bridge.stop("does-not-exist")


class TestSandboxStopPcapL1:
    """L1: ``SandboxBridge.stop_pcap`` is a real, tolerant cleanup variant.

    Falsified by: reverting ``sandbox_bridge.py:1876-1911`` (``stop_pcap``) to
    always raise, always report ``stopped=True``, or fail to consult
    ``_active_pcap_captures`` turns these red.
    """

    @pytest.mark.asyncio
    async def test_stop_pcap_no_active_capture_is_real_noop(self) -> None:
        """stop_pcap() on an instance with no active capture returns stopped=False without error."""
        bridge = SandboxBridge()

        result = await bridge.stop_pcap("no-capture-instance")

        assert result == {"instance_id": "no-capture-instance", "stopped": False}

    @pytest.mark.asyncio
    async def test_stop_pcap_stops_tracked_capture(self) -> None:
        """stop_pcap() stops a genuinely tracked capture and clears bridge-side tracking.

        The clearing of the internal ``_active_pcap_captures`` tracking dict is
        verified through observable behaviour rather than private-attribute
        access: calling ``stop_pcap`` a second time on the same instance must
        now report ``stopped=False`` (nothing left to stop), which can only
        happen if the first call actually removed the tracked capture id.
        """
        sandbox = InMemoryQEMUSandbox()
        instance = StubInstance(sandbox, "qemu", instance_id="pcap-inst-001")
        manager = StubManager({"pcap-inst-001": instance})
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", manager))

        started = await bridge.pcap_start("pcap-inst-001")
        capture_id = started["capture_id"]

        result = await bridge.stop_pcap("pcap-inst-001")

        assert result["instance_id"] == "pcap-inst-001"
        assert result["stopped"] is True
        assert result["capture_id"] == capture_id
        assert "pcap_path" in result

        second_result = await bridge.stop_pcap("pcap-inst-001")
        assert second_result == {"instance_id": "pcap-inst-001", "stopped": False}, (
            "stop_pcap must clear its internal active-capture tracking on success; a second call on the same instance must be a real no-op"
        )


class _ConfigRecordingManager(StubManager):
    """``StubManager`` variant that threads a real ``SandboxConfig`` into the created sandbox.

    The base ``StubManager.create`` (by design, for its own unrelated test
    suite) discards the ``config`` argument entirely, so it cannot observe
    whether ``SandboxBridge.create`` actually built and forwarded a
    ``SandboxConfig`` with the caller's values. Real VM provisioning
    (``WindowsSandbox``/``QEMUSandbox`` availability probing and startup) is
    the genuine external boundary this test cannot cross inside the sandbox
    environment, so this fake manager stands in for the manager layer only;
    ``SandboxBridge.create``'s own parameter-to-``SandboxConfig`` construction
    (``sandbox_bridge.py:1043-1090``) executes for real and is what this test
    falsifies.
    """

    def __init__(self) -> None:
        """Initialise with no pre-populated instances and no recorded config."""
        super().__init__()
        self.last_config: SandboxConfig | None = None

    async def create(
        self,
        sandbox_type: str = "windows",
        config: SandboxConfig | None = None,
        binary_path: Path | None = None,
        qemu_config: object = None,
        *,
        auto_start: bool = True,
    ) -> StubInstance:
        """Record ``config`` before delegating to the real in-memory instance creation.

        Args:
            sandbox_type: Type of sandbox.
            config: Configuration forwarded by the caller; recorded on ``self.last_config``.
            binary_path: Optional binary path.
            qemu_config: Optional QEMU config (unused).
            auto_start: Whether to auto-start.

        Returns:
            StubInstance: Created instance.
        """
        self.last_config = config
        return await super().create(sandbox_type, config, binary_path, qemu_config, auto_start=auto_start)


class TestSandboxCreateConfigL1:
    """L1: ``sandbox.create``'s VM/environment config parameters are real, distinct config fields."""

    @pytest.mark.asyncio
    async def test_create_threads_timeout_network_memory_into_config(self) -> None:
        """create() builds a SandboxConfig with the exact caller-supplied timeout/network/memory values.

        Falsified by: reverting ``sandbox_bridge.py``'s ``create`` to ignore
        ``timeout_seconds``/``network_enabled``/``memory_limit_mb`` (or to
        build the ``SandboxConfig`` with hardcoded defaults instead of the
        caller's values) turns this red.
        """
        manager = _ConfigRecordingManager()
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", manager))

        result = await bridge.create(
            sandbox_type="windows",
            timeout_seconds=777,
            network_enabled=True,
            memory_limit_mb=4096,
        )

        assert isinstance(result["instance_id"], str)
        assert manager.last_config is not None
        assert manager.last_config.timeout_seconds == 777
        assert manager.last_config.network_enabled is True
        assert manager.last_config.memory_limit_mb == 4096

    @pytest.mark.asyncio
    async def test_create_uses_documented_defaults_when_unspecified(self) -> None:
        """create() with no explicit config kwargs builds a SandboxConfig with the documented defaults."""
        manager = _ConfigRecordingManager()
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", manager))

        await bridge.create(sandbox_type="windows")

        assert manager.last_config is not None
        assert manager.last_config.timeout_seconds == 300
        assert manager.last_config.network_enabled is False
        assert manager.last_config.memory_limit_mb == 2048

    @pytest.mark.asyncio
    async def test_create_rejects_unknown_sandbox_type(self) -> None:
        """create() rejects an unsupported sandbox_type before ever reaching the manager."""
        manager = _ConfigRecordingManager()
        bridge = SandboxBridge()
        bridge.attach_manager(cast("SandboxManager", manager))

        with pytest.raises(ToolError):
            await bridge.create(sandbox_type="docker")

        assert manager.last_config is None, "an invalid sandbox_type must be rejected before the manager is ever called"


class TestSandboxToolDefRegistrationL2:
    """L2: ``sandbox.stop`` and ``sandbox.stop_pcap`` are registered ToolFunctions."""

    def test_stop_tool_function_registered_with_matching_name(self) -> None:
        """The tool_definition exposes a 'sandbox.stop' ToolFunction whose param maps to the real signature."""
        bridge = SandboxBridge()
        functions_by_name = {f.name: f for f in bridge.tool_definition.functions}

        assert "sandbox.stop" in functions_by_name, "sandbox.stop must appear in the registered tool definitions (S14)"
        func = functions_by_name["sandbox.stop"]
        param_names = {p.name for p in func.parameters}
        assert param_names == {"instance_id"}, f"sandbox.stop's tool-def parameters must match stop(instance_id); got {param_names}"

    def test_stop_pcap_tool_function_registered_with_matching_name(self) -> None:
        """The tool_definition exposes a 'sandbox.stop_pcap' ToolFunction whose param maps to the real signature."""
        bridge = SandboxBridge()
        functions_by_name = {f.name: f for f in bridge.tool_definition.functions}

        assert "sandbox.stop_pcap" in functions_by_name, "sandbox.stop_pcap must appear in the registered tool definitions (S19)"
        func = functions_by_name["sandbox.stop_pcap"]
        param_names = {p.name for p in func.parameters}
        assert param_names == {"instance_id"}, (
            f"sandbox.stop_pcap's tool-def parameters must match stop_pcap(instance_id); got {param_names}"
        )


class TestSandboxDispatchL2:
    """L2: sandbox.stop / sandbox.stop_pcap dispatch through the real ToolRegistry, not gated by capability."""

    @pytest.mark.asyncio
    async def test_execute_tool_call_dispatches_stop_to_real_method(self, tmp_path: Path) -> None:
        """execute_tool_call('sandbox', 'stop', ...) reaches the real bridge method and is not capability-blocked.

        This is the direct regression gate for the confirmed capability-gate
        bug: reverting ``tools.py``'s ``TOOL_CAPABILITY_MAP.get(function_name)
        or TOOL_CAPABILITY_MAP.get(attr_name)`` back to a bare
        ``TOOL_CAPABILITY_MAP.get(attr_name)`` lookup resolves ``"stop"`` to
        the generic ``"debugging"`` capability. ``SandboxBridge`` never sets
        ``supports_debugging=True`` (only ``supports_dynamic_analysis``), so
        the old code path raises "missing capability" for every
        ``sandbox.stop`` call -- this test would go red immediately.

        Args:
            tmp_path: Pytest temporary directory used as the tools install root.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        await registry.initialize()
        sandbox_bridge = registry.get_sandbox_bridge()

        assert sandbox_bridge.capabilities.has_capability("debugging") is False, (
            "precondition: SandboxBridge must not advertise the 'debugging' capability"
        )

        sandbox = InMemoryQEMUSandbox()
        qmp = _StubQMPWithStop()
        sandbox.qmp = qmp
        instance = StubInstance(sandbox, "qemu", instance_id="dispatch-stop-001")
        manager = StubManager({"dispatch-stop-001": instance})
        sandbox_bridge.attach_manager(cast("SandboxManager", manager))

        result = await registry.execute_tool_call("sandbox", "sandbox.stop", {"instance_id": "dispatch-stop-001"})

        assert isinstance(result, dict)
        assert result["status"] == "paused"
        assert qmp.stop_calls == 1, "dispatch must reach the real SandboxBridge.stop method, not short-circuit on a capability gate"

        await registry.shutdown()

    @pytest.mark.asyncio
    async def test_execute_tool_call_dispatches_stop_pcap_to_real_method(self, tmp_path: Path) -> None:
        """execute_tool_call('sandbox', 'stop_pcap', ...) reaches the real bridge method end to end.

        Args:
            tmp_path: Pytest temporary directory used as the tools install root.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        await registry.initialize()

        result = await registry.execute_tool_call("sandbox", "sandbox.stop_pcap", {"instance_id": "no-such-instance"})

        assert result == {"instance_id": "no-such-instance", "stopped": False}

        await registry.shutdown()

    @pytest.mark.asyncio
    async def test_get_tool_definitions_exposes_sandbox_stop(self, tmp_path: Path) -> None:
        """ToolRegistry.get_tool_definitions() surfaces sandbox.stop through the registry (LLM discoverability).

        Args:
            tmp_path: Pytest temporary directory used as the tools install root.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        await registry.initialize()

        definitions = registry.get_tool_definitions()
        sandbox_def = next(d for d in definitions if d.tool_name == ToolName.SANDBOX)
        function_names = {f.name for f in sandbox_def.functions}

        assert "sandbox.stop" in function_names
        assert "sandbox.stop_pcap" in function_names

        await registry.shutdown()
