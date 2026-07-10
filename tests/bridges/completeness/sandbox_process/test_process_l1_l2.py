# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness remediation gates for the PROCESS slice (L1 + L2).

Covers agent-10 (``audit/bridge-completeness/agent-10-sandbox-process.md``)
and its verifier (``audit/bridge-completeness/verify/agent-10-sandbox-process-verification.md``)
for the 10 previously fully-orphaned (NOT-REGISTERED + NO-CONTROL) PROCESS
bridge methods that are now registered ``process.*`` tool functions:

* P13 ``decommit_memory`` -- real ``VirtualFreeEx(MEM_DECOMMIT)``.
* P29 ``enumerate_services`` -- real SCM query filtered by active/inactive state.
* P38 ``get_mitigation_policy`` -- simplified-schema mitigation query.
* P39 ``get_extension_policy`` -- extension-point-disable mitigation query.
* P55 ``read_registry`` -- explicit hive/key/value registry read.
* P62 ``enumerate_system_processes`` -- dict-shaped process enumeration.
* P63 ``duplicate_token`` -- real ``DuplicateTokenEx``.
* P64 ``remove_privilege`` -- real ``AdjustTokenPrivileges`` removal.
* P65 ``time_thread_wait`` -- real ``WaitForSingleObject`` + timing.
* P66 ``detect_kernel_debugger`` -- real ``NtQueryInformationProcess(ProcessDebugPort)``.

Also covers the two NOT-REGISTERED-but-real duplicate-axis methods
``enumerate_handles``/``enum_handles`` (P25/P26), each now with its own
``process.*`` tool-def alongside the pre-existing ``get_handles``.

Every test drives the real bridge method against the live Windows APIs
against either the test-runner's own process (read-only operations) or a
disposable spawned child process (mutating operations), per project
convention (see ``tests/test_bridges/test_process_bridge.py``).
"""

from __future__ import annotations

import ctypes
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast

import pytest
import pytest_asyncio

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolError, ToolName
from tests._helpers.process_cleanup import ManagedProcess


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator


pytestmark = [
    pytest.mark.skipif(os.name != "nt", reason="Windows only"),
    pytest.mark.asyncio,
]

_REG_CURRENT_VERSION_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_REG_CURRENT_VERSION_HKLM = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"


@pytest_asyncio.fixture(scope="module")
async def process_bridge() -> AsyncGenerator[ProcessBridge]:
    """Create, initialize, and shutdown a ProcessBridge for the module.

    Yields:
        AsyncGenerator[ProcessBridge]: Initialized bridge that will be shut down on teardown.
    """
    bridge = ProcessBridge()
    await bridge.initialize()
    yield bridge
    await bridge.shutdown()


@pytest_asyncio.fixture
async def attached_bridge(process_bridge: ProcessBridge) -> AsyncGenerator[ProcessBridge]:
    """Attach the bridge to the current Python process.

    Args:
        process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.

    Yields:
        AsyncGenerator[ProcessBridge]: The shared bridge with an open handle on the current Python process.
    """
    await process_bridge.open_process(os.getpid(), "all")
    yield process_bridge
    await process_bridge.close()


@pytest.fixture
def notepad_child() -> Generator[int]:
    """Spawn a real, disposable notepad.exe subprocess for mutation-risk tests.

    Some remediated methods (``remove_privilege``, ``duplicate_token``,
    ``detect_kernel_debugger``, ``time_thread_wait``) either permanently
    mutate a token or wait on a handle; running them against the shared
    pytest-interpreter process would risk destabilising the test runner or
    other tests in the same module-scoped session. A disposable spawned
    process gives each test a real, independent target while
    :class:`ManagedProcess` guarantees teardown.

    Yields:
        Generator[int]: PID of the spawned notepad.exe process.
    """
    notepad_path = str(Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "notepad.exe")
    with ManagedProcess([notepad_path], startup_delay=0.5) as proc:
        yield proc.pid


class TestEnumerateSystemProcessesL1:
    """P62: enumerate_system_processes returns real dict-shaped process records."""

    async def test_contains_self_with_correct_fields(self, process_bridge: ProcessBridge) -> None:
        """The current interpreter's own pid/name/thread_count appear with the correct real values.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        records = await process_bridge.enumerate_system_processes()
        assert len(records) > 1, "enumerate_system_processes must return more than one process on a live Windows system"

        self_records = [r for r in records if r["pid"] == os.getpid()]
        assert len(self_records) == 1, f"expected exactly one record for pid={os.getpid()}, found {len(self_records)}"
        record = self_records[0]
        assert isinstance(record["name"], str)
        assert "python" in record["name"].lower(), f"expected a python executable name, got {record['name']!r}"
        assert isinstance(record["parent_pid"], int)
        assert record["parent_pid"] > 0
        assert isinstance(record["thread_count"], int)
        assert record["thread_count"] >= 1


_HANDLE_CHURN_TOLERANCE = 8
"""Max handle_value drift tolerated between the two non-atomic enumerations.

``enumerate_handles`` and ``enum_handles`` each take an independent snapshot
of the live, churning system handle table, so a handful of transient handles
open/close between the two calls. A wrong-field filter or wrong-offset read
would instead make the two handle-value sets grossly diverge (near-disjoint or
very different sizes), which even a small tolerance still catches.
"""


class TestEnumerateHandlesDuplicateAxisL1:
    """P25/P26: enumerate_handles (raw) and enum_handles (type-resolved) agree on handle_value set."""

    async def test_same_handle_values_different_type_representation(self, attached_bridge: ProcessBridge) -> None:
        """Both methods, filtered to our own pid, return the identical handle_value set.

        ``enumerate_handles`` exposes the raw ``object_type_index`` (int);
        ``enum_handles`` resolves the same index to a human-readable
        ``type_name`` (str) via a cached ``NtQueryObject`` lookup. If either
        implementation filtered by the wrong field or read the wrong table
        offset, the two handle-value sets would diverge.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        pid = os.getpid()
        raw_handles = await attached_bridge.enumerate_handles(pid)
        resolved_handles = await attached_bridge.enum_handles(pid)

        assert len(raw_handles) > 0, "the live Python process must hold at least one open handle"
        assert len(resolved_handles) > 0

        raw_values = {h["handle_value"] for h in raw_handles}
        resolved_values = {h["handle_value"] for h in resolved_handles}
        divergent = raw_values ^ resolved_values
        tolerance = max(_HANDLE_CHURN_TOLERANCE, len(raw_values | resolved_values) // 20)
        assert len(divergent) <= tolerance, (
            f"enumerate_handles and enum_handles must agree on the handle_value set for the same pid "
            f"(allowing minor handle-table churn of up to {tolerance}); "
            f"raw-only={raw_values - resolved_values!r}, resolved-only={resolved_values - raw_values!r}"
        )

        assert all(isinstance(h["object_type_index"], int) for h in raw_handles), (
            "enumerate_handles must expose the raw numeric object_type_index"
        )
        resolved_type_names = [h["type_name"] for h in resolved_handles]
        assert all(isinstance(name, str) and name for name in resolved_type_names), (
            "enum_handles must resolve type_name to a non-empty string"
        )
        assert all(isinstance(name, str) and not name.isdigit() for name in resolved_type_names), (
            "enum_handles's type_name must be a resolved name, not a bare numeric index string"
        )

    async def test_enumerate_handles_unfiltered_includes_other_processes(self, attached_bridge: ProcessBridge) -> None:
        """Calling enumerate_handles without a pid filter returns handles for more than one process.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        all_handles = await attached_bridge.enumerate_handles()
        pids = {h["pid"] for h in all_handles}
        assert len(pids) > 1, f"system-wide enumerate_handles() must span multiple processes, got pids={pids!r}"


class TestEnumerateServicesL1:
    """P29: enumerate_services filters by active/inactive state (distinct from list_services' PID filter)."""

    async def test_active_only_returns_a_real_running_service(self, process_bridge: ProcessBridge) -> None:
        """active=True includes the always-running RPC service by its real Windows service name.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        active_services = await process_bridge.enumerate_services(active=True)
        names = {s["name"] for s in active_services}
        assert len(active_services) > 0
        assert "RpcSs" in names, f"the RPC service (RpcSs) is always running on Windows; got service names sample: {list(names)[:20]!r}"

    async def test_all_services_superset_of_active(self, process_bridge: ProcessBridge) -> None:
        """The unfiltered (active=False) call returns at least as many services as the active-only call.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        active_services = await process_bridge.enumerate_services(active=True)
        all_services = await process_bridge.enumerate_services(active=False)
        assert len(all_services) >= len(active_services), (
            "SERVICE_STATE_ALL must return at least as many entries as the SERVICE_ACTIVE-only filter"
        )
        active_names = {s["name"] for s in active_services}
        all_names = {s["name"] for s in all_services}
        assert active_names <= all_names, "every actively-running service name must also appear in the unfiltered enumeration"


class TestReadRegistryL1:
    """P55: read_registry (explicit hive/key/value) cross-validated against reg_read_value."""

    async def test_matches_reg_read_value_with_full_type_name(self, process_bridge: ProcessBridge) -> None:
        """read_registry's data matches reg_read_value's data for the same key, with a full REG_* type name.

        ``reg_read_value`` (already fully ported, P52) returns an
        abbreviated ``"string"``/``"dword"`` type tag; ``read_registry``
        returns the real Windows ``REG_SZ``/``REG_DWORD`` constant name.
        Reading the exact same well-known, always-present registry value
        (``ProductName`` under ``CurrentVersion``) through both methods and
        comparing the decoded data is an independent cross-check that does
        not re-implement either method's decoding logic.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        via_read_registry = await process_bridge.read_registry("HKLM", _REG_CURRENT_VERSION_PATH, "ProductName")
        via_reg_read_value = await process_bridge.reg_read_value(_REG_CURRENT_VERSION_HKLM, "ProductName")

        assert via_read_registry["type"] == "REG_SZ", f"expected the full Windows type name REG_SZ, got {via_read_registry['type']!r}"
        assert via_reg_read_value["type"] == "string", (
            f"sibling reg_read_value must report the abbreviated type; got {via_reg_read_value['type']!r}"
        )
        assert via_read_registry["data"] == via_reg_read_value["data"], (
            "read_registry and reg_read_value must decode the identical real registry value to the same data"
        )
        assert isinstance(via_read_registry["data"], str)
        assert len(via_read_registry["data"]) > 0

    async def test_long_form_hive_name_accepted(self, process_bridge: ProcessBridge) -> None:
        """The long-form HKEY_LOCAL_MACHINE hive name resolves identically to the HKLM abbreviation.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        via_abbrev = await process_bridge.read_registry("HKLM", _REG_CURRENT_VERSION_PATH, "ProductName")
        via_long_form = await process_bridge.read_registry("HKEY_LOCAL_MACHINE", _REG_CURRENT_VERSION_PATH, "ProductName")
        assert via_abbrev["data"] == via_long_form["data"]

    async def test_unknown_hive_raises(self, process_bridge: ProcessBridge) -> None:
        """An unrecognised hive abbreviation raises ToolError.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        with pytest.raises(ToolError):
            await process_bridge.read_registry("HKNOPE", _REG_CURRENT_VERSION_PATH, "ProductName")


class TestMitigationPolicySimplifiedSchemaL1:
    """P38/P39: get_mitigation_policy and get_extension_policy cross-validated against get_mitigation_policies."""

    async def test_simplified_schema_matches_full_query(self, process_bridge: ProcessBridge) -> None:
        """get_mitigation_policy's dep/aslr/cfg flags equal the corresponding get_mitigation_policies entries.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        full = await process_bridge.get_mitigation_policies(os.getpid())
        simplified = await process_bridge.get_mitigation_policy(os.getpid())

        dep = full.get("DEP")
        aslr = full.get("ASLR")
        cfg = full.get("CFG")
        assert isinstance(dep, dict)
        assert isinstance(aslr, dict)
        assert isinstance(cfg, dict)
        dep_dict = cast("dict[str, object]", dep)
        aslr_dict = cast("dict[str, object]", aslr)
        cfg_dict = cast("dict[str, object]", cfg)

        assert simplified["dep"] == dep_dict.get("enabled", False)
        assert simplified["aslr"] == aslr_dict.get("enabled", False)
        assert simplified["cfg"] == cfg_dict.get("enabled", False)
        assert "sehop_via_options_mask" in simplified
        assert isinstance(simplified["sehop_via_options_mask"], int)

    async def test_extension_policy_returns_real_bool_flag(self, process_bridge: ProcessBridge) -> None:
        """get_extension_policy returns a real disable_extension_points boolean for the current process.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        result = await process_bridge.get_extension_policy(os.getpid())
        assert set(result.keys()) == {"disable_extension_points"}
        assert isinstance(result["disable_extension_points"], bool)


class TestDecommitMemoryL1:
    """P13: decommit_memory performs a real VirtualFreeEx(MEM_DECOMMIT) observable via get_memory_map."""

    async def test_decommit_removes_region_from_memory_map(self, attached_bridge: ProcessBridge) -> None:
        """A freshly allocated, committed region disappears from get_memory_map after decommit.

        get_memory_map only appends regions whose MEMORY_BASIC_INFORMATION.State
        is MEM_COMMIT, so a successfully decommitted region's base address must
        no longer appear in the map at all -- a real, independently observable
        WinAPI side effect, not a value the test invents.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        size = 4096
        address = await attached_bridge.allocate(size, protection="rw")

        before = await attached_bridge.get_memory_map()
        before_bases = {r.base_address for r in before}
        assert address in before_bases, "the freshly allocated region must appear as committed before decommit"

        decommitted = await attached_bridge.decommit_memory(os.getpid(), address, size)
        assert decommitted is True

        after = await attached_bridge.get_memory_map()
        after_bases = {r.base_address for r in after}
        assert address not in after_bases, (
            f"decommit_memory must remove the region's committed state; base address {hex(address)} still present in the memory map"
        )


class TestDuplicateTokenL1:
    """P63: duplicate_token performs a real DuplicateTokenEx and yields a distinct, closable handle."""

    @pytest.mark.spawns_process
    async def test_duplicate_token_returns_distinct_closable_handle(self, notepad_child: int) -> None:
        """The duplicated token handle is a positive int distinct from a fresh OpenProcessToken handle and is closable.

        Args:
            notepad_child: PID of a disposable spawned notepad.exe process.
        """
        bridge = ProcessBridge()
        await bridge.initialize()
        try:
            dup_handle = await bridge.duplicate_token(notepad_child)
            assert isinstance(dup_handle, int)
            assert dup_handle > 0

            kernel32 = ctypes.windll.kernel32
            closed = bool(kernel32.CloseHandle(dup_handle))
            assert closed, "the handle returned by duplicate_token must be a real, closable Win32 handle"
        finally:
            await bridge.shutdown()

    async def test_duplicate_token_unknown_pid_raises(self) -> None:
        """duplicate_token raises ToolError for a pid that does not exist."""
        bridge = ProcessBridge()
        await bridge.initialize()
        try:
            with pytest.raises(ToolError):
                await bridge.duplicate_token(999_999_999)
        finally:
            await bridge.shutdown()


class TestRemovePrivilegeL1:
    """P64: remove_privilege performs a real AdjustTokenPrivileges removal, observable via get_token_privileges."""

    @pytest.mark.spawns_process
    async def test_removing_present_privilege_reports_success(self, notepad_child: int) -> None:
        """Removing SeChangeNotifyPrivilege (always present on a normal token) reports True.

        Operates on a disposable spawned child process rather than the
        shared pytest-interpreter process because SE_PRIVILEGE_REMOVED is
        permanent for the life of the token and would corrupt later tests
        sharing the same process.

        Args:
            notepad_child: PID of a disposable spawned notepad.exe process.
        """
        bridge = ProcessBridge()
        await bridge.initialize()
        try:
            privileges_before = await bridge.get_token_privileges(notepad_child)
            names_before = {p["name"] for p in privileges_before}
            assert "SeChangeNotifyPrivilege" in names_before, (
                f"precondition: SeChangeNotifyPrivilege must be present on a normal process token; got {names_before!r}"
            )

            removed = await bridge.remove_privilege(notepad_child, "SeChangeNotifyPrivilege")
            assert removed is True

            privileges_after = await bridge.get_token_privileges(notepad_child)
            names_after = {p["name"] for p in privileges_after}
            assert "SeChangeNotifyPrivilege" not in names_after, (
                "a removed privilege (SE_PRIVILEGE_REMOVED) must no longer be enumerable on the token"
            )
        finally:
            await bridge.shutdown()

    @pytest.mark.spawns_process
    async def test_removing_unknown_privilege_name_reports_false(self, notepad_child: int) -> None:
        """remove_privilege returns False (not an exception) for a syntactically invalid privilege name.

        Args:
            notepad_child: PID of a disposable spawned notepad.exe process.
        """
        bridge = ProcessBridge()
        await bridge.initialize()
        try:
            removed = await bridge.remove_privilege(notepad_child, "SeThisPrivilegeDoesNotExist")
            assert removed is False
        finally:
            await bridge.shutdown()


class TestTimeThreadWaitL1:
    """P65: time_thread_wait performs a real WaitForSingleObject and measures elapsed time."""

    async def test_signaled_after_thread_exits(self, process_bridge: ProcessBridge) -> None:
        """A real worker thread reports 'signaled' with a real elapsed-time measurement once it exits.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        started = threading.Event()
        finished = threading.Event()
        tid_holder: list[int] = []

        def _worker() -> None:
            tid_holder.append(ctypes.windll.kernel32.GetCurrentThreadId())
            started.set()
            finished.wait(timeout=5)

        worker = threading.Thread(target=_worker, daemon=True)
        worker.start()
        assert started.wait(timeout=5), "worker thread failed to start"
        tid = tid_holder[0]

        finished.set()
        worker.join(timeout=5)

        result = await process_bridge.time_thread_wait(tid, timeout_ms=2000)
        assert result["result"] == "signaled", f"expected the exited thread's handle to be signaled; got {result!r}"
        assert isinstance(result["elapsed_us"], int)
        assert result["elapsed_us"] >= 0

    async def test_timeout_when_thread_still_running(self, process_bridge: ProcessBridge) -> None:
        """A thread that is still blocked reports 'timeout' for a short wait window.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        finished = threading.Event()
        started = threading.Event()
        tid_holder: list[int] = []

        def _worker() -> None:
            tid_holder.append(ctypes.windll.kernel32.GetCurrentThreadId())
            started.set()
            finished.wait(timeout=10)

        worker = threading.Thread(target=_worker, daemon=True)
        worker.start()
        assert started.wait(timeout=5), "worker thread failed to start"
        tid = tid_holder[0]

        try:
            result = await process_bridge.time_thread_wait(tid, timeout_ms=100)
            assert result["result"] == "timeout", f"expected a still-running thread to time out; got {result!r}"
        finally:
            finished.set()
            worker.join(timeout=5)

    async def test_unknown_tid_raises(self, process_bridge: ProcessBridge) -> None:
        """time_thread_wait raises ToolError for a thread id that does not exist.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        with pytest.raises(ToolError):
            await process_bridge.time_thread_wait(999_999_999, timeout_ms=100)


class TestDetectKernelDebuggerL1:
    """P66: detect_kernel_debugger performs a real NtQueryInformationProcess(ProcessDebugPort) query."""

    async def test_current_process_has_no_kernel_debugger(self, process_bridge: ProcessBridge) -> None:
        """The pytest-interpreter process itself is not running under a kernel debugger.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        detected = await process_bridge.detect_kernel_debugger(os.getpid())
        assert detected is False

    @pytest.mark.spawns_process
    async def test_spawned_child_has_no_kernel_debugger(self, notepad_child: int) -> None:
        """A freshly spawned, undebugged child process reports no kernel debugger.

        Args:
            notepad_child: PID of a disposable spawned notepad.exe process.
        """
        bridge = ProcessBridge()
        await bridge.initialize()
        try:
            detected = await bridge.detect_kernel_debugger(notepad_child)
            assert detected is False
        finally:
            await bridge.shutdown()

    async def test_unknown_pid_raises(self, process_bridge: ProcessBridge) -> None:
        """detect_kernel_debugger raises ToolError for a pid that does not exist.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        with pytest.raises(ToolError):
            await process_bridge.detect_kernel_debugger(999_999_999)


class TestProcessToolDefRegistrationL2:
    """L2: every remediated PROCESS method is registered with a schema matching its real signature."""

    _REMEDIATED_FUNCTION_SCHEMAS: ClassVar[list[tuple[str, set[str]]]] = [
        ("process.decommit_memory", {"pid", "address", "size"}),
        ("process.enumerate_services", {"active"}),
        ("process.get_mitigation_policy", {"pid"}),
        ("process.get_extension_policy", {"pid"}),
        ("process.read_registry", {"hive", "key_path", "value_name"}),
        ("process.enumerate_system_processes", set()),
        ("process.duplicate_token", {"pid"}),
        ("process.remove_privilege", {"pid", "privilege_name"}),
        ("process.time_thread_wait", {"tid", "timeout_ms"}),
        ("process.detect_kernel_debugger", {"pid"}),
        ("process.enumerate_handles", {"pid"}),
        ("process.enum_handles", {"pid"}),
    ]

    @pytest.mark.parametrize(("function_name", "expected_params"), _REMEDIATED_FUNCTION_SCHEMAS)
    def test_tool_function_registered_with_matching_schema(
        self,
        process_bridge: ProcessBridge,
        function_name: str,
        expected_params: set[str],
    ) -> None:
        """Each newly-registered ToolFunction's parameter names match its real method signature.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
            function_name: Fully-qualified tool-def name (e.g. 'process.decommit_memory').
            expected_params: Expected set of parameter names for the tool-def.
        """
        functions_by_name = {f.name: f for f in process_bridge.tool_definition.functions}
        assert function_name in functions_by_name, f"{function_name} must appear in the registered tool definitions"
        func = functions_by_name[function_name]
        actual_params = {p.name for p in func.parameters}
        assert actual_params == expected_params, f"{function_name}'s tool-def parameters {actual_params} do not match {expected_params}"

        method_name = function_name.split(".", 1)[1]
        method = getattr(process_bridge, method_name, None)
        assert callable(method), f"tool-def {function_name} has no matching callable method {method_name!r}"


class TestProcessDispatchL2:
    """L2: newly-registered PROCESS methods dispatch through the real ToolRegistry."""

    async def test_execute_tool_call_dispatches_enumerate_system_processes(self, tmp_path: Path) -> None:
        """execute_tool_call reaches the real enumerate_system_processes implementation.

        Args:
            tmp_path: Pytest temporary directory used as the tools install root.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        await registry.initialize()

        result = await registry.execute_tool_call("process", "process.enumerate_system_processes", {})

        assert isinstance(result, list)
        records = cast("list[dict[str, object]]", result)
        assert any(r["pid"] == os.getpid() for r in records), "dispatched call must reach the real bridge method, observing this process"

        await registry.shutdown()

    async def test_execute_tool_call_dispatches_detect_kernel_debugger(self, tmp_path: Path) -> None:
        """execute_tool_call reaches the real detect_kernel_debugger implementation for the current process.

        Args:
            tmp_path: Pytest temporary directory used as the tools install root.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        await registry.initialize()

        result = await registry.execute_tool_call("process", "process.detect_kernel_debugger", {"pid": os.getpid()})

        assert result is False

        await registry.shutdown()

    async def test_execute_tool_call_dispatches_read_registry(self, tmp_path: Path) -> None:
        """execute_tool_call reaches the real read_registry implementation with a genuine registry read.

        Args:
            tmp_path: Pytest temporary directory used as the tools install root.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        await registry.initialize()

        result = await registry.execute_tool_call(
            "process",
            "process.read_registry",
            {"hive": "HKLM", "key_path": _REG_CURRENT_VERSION_PATH, "value_name": "ProductName"},
        )

        assert isinstance(result, dict)
        assert result["type"] == "REG_SZ"
        assert isinstance(result["data"], str)
        assert len(result["data"]) > 0

        await registry.shutdown()

    async def test_get_tool_definitions_exposes_all_ten_remediated_functions(self, tmp_path: Path) -> None:
        """ToolRegistry.get_tool_definitions() surfaces all 10 remediated process functions for LLM discovery.

        Args:
            tmp_path: Pytest temporary directory used as the tools install root.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        await registry.initialize()

        definitions = registry.get_tool_definitions()
        process_def = next(d for d in definitions if d.tool_name == ToolName.PROCESS)
        function_names = {f.name for f in process_def.functions}

        expected = {
            "process.decommit_memory",
            "process.enumerate_services",
            "process.get_mitigation_policy",
            "process.get_extension_policy",
            "process.read_registry",
            "process.enumerate_system_processes",
            "process.duplicate_token",
            "process.remove_privilege",
            "process.time_thread_wait",
            "process.detect_kernel_debugger",
        }
        missing = expected - function_names
        assert missing == set(), f"remediated functions missing from the LLM-visible tool definitions: {missing}"

        await registry.shutdown()
