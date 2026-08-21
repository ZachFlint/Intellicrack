# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
"""Registry of tests that can only run natively on the host, not in the sandbox.

The Intellicrack suite runs inside a hardware-less, network-isolated, elevated
Windows Docker container. A subset of tests depends on capabilities that only a
real host provides — an Intel XPU, a running local Ollama daemon, Microsoft
debug symbols, raw physical disks, loopback TCP capture, an un-jobbed process,
a non-elevated shell, or a path outside the container's mounted subtree (the
sandbox mounts only ``tests``/``src``/``docker``/``scripts``/``vendor`` — the
``tools`` tree is absent). Those tests skip in the container and are executed
by the host-native pass (:mod:`scripts.host_native_tests`).

This module is the single source of truth for that set. It is data-driven
rather than decorator-based so the ~100 entries stay in one auditable place and
a falsifiable gate can prove every entry still resolves to a real test. The
conftest collection hook consults :func:`is_host_native_nodeid` to apply the
``host_native`` marker, and the falsifiable gate consults
:func:`iter_registry_entries` to detect drift.

Cloud-provider tests that need paid API keys are intentionally excluded: they
depend on credentials, not host hardware, and never belong here.
"""

from __future__ import annotations

from typing import Final

import pytest


# Marker applied to every registry-listed test; also registered in
# ``pyproject.toml`` and the conftest so ``--strict-markers`` accepts it.
HOST_NATIVE_MARKER: Final[str] = "host_native"

# A pytest node id with an enclosing class has three ``::``-separated fields:
# ``module.py::ClassName::test_function``. A module-level function has two.
_CLASSED_NODEID_FIELD_COUNT: Final[int] = 3

_XPU_E2E: Final[str] = "tests/providers/test_local_xpu_e2e.py"
_TRANSFORMERS: Final[str] = "tests/providers/test_local_transformers_provider.py"
_XPU_STATUS: Final[str] = "tests/ui/test_xpu_status.py"
_XPU_UTILS: Final[str] = "tests/providers/test_realcov_11_xpu_utils.py"
_GPU_PCI: Final[str] = "tests/providers/test_realcov_11_gpu_pci.py"
_XPU_LOADER: Final[str] = "tests/providers/test_xpu_model_loader_wave5.py"
_E2E_CHAT: Final[str] = "tests/providers/test_e2e_chat.py"
_OLLAMA_PROVIDER: Final[str] = "tests/providers/test_ollama_provider.py"
_OLLAMA_CHAT_LIVE: Final[str] = "tests/providers/test_ollama_chat_live.py"
_AGENTIC: Final[str] = "tests/providers/test_agentic_capabilities.py"
_MODEL_DISCOVERY: Final[str] = "tests/providers/test_model_discovery.py"
_PROCESS_BRIDGE: Final[str] = "tests/bridges/test_process_bridge.py"
_SEH_X64_PDATA: Final[str] = "tests/bridges/test_seh_x64_pdata_s14d03.py"
_CUTTER_DECOMPILE: Final[str] = "tests/bridges/test_realcov_03d_cutter_decompile_cfg.py"
_X64DBG_LOAD: Final[str] = "tests/bridges/test_x64dbg_load_attach_s13.py"
_X64DBG_WATCHPOINTS: Final[str] = "tests/bridges/test_x64dbg_watchpoints_s13.py"
_X64DBG_EMBED: Final[str] = "tests/ui/test_x64dbg_embed_finds_window_s13d04.py"
_ANALYSIS_REAL: Final[str] = "tests/sandbox/test_realcov_12b_analysis_real.py"
_INLINE_MONITORS: Final[str] = "tests/sandbox/windows/test_realcov_12b_inline_monitors.py"
_INJECTION_MONITOR: Final[str] = "tests/sandbox/monitors/test_injection_monitor.py"
_KERNEL_OBJECT_MONITOR: Final[str] = "tests/sandbox/monitors/test_kernel_object_monitor.py"
_DLL_MONITOR: Final[str] = "tests/sandbox/monitors/test_dll_monitor.py"
_API_TRACE: Final[str] = "tests/sandbox/monitors/test_api_trace.py"
_SERVICE_MONITOR: Final[str] = "tests/sandbox/monitors/test_service_monitor.py"
_WHPX_CPU_MODEL: Final[str] = "tests/sandbox/qemu/test_whpx_cpu_model_s17d36.py"
_WHPX_IRQCHIP: Final[str] = "tests/sandbox/qemu/test_whpx_irqchip_s17d37.py"
_ABSOLUTE_POINTER: Final[str] = "tests/sandbox/qemu/test_absolute_pointer_s17d41.py"
_SPAWN_HELPER: Final[str] = "tests/sandbox/qemu/test_guest_agent_spawn_helper_s17d47.py"
_VIRTIO_SUBPATHS: Final[str] = "tests/sandbox/qemu/test_virtio_driver_subpaths_s17d44.py"
_DISK_OVERLAY: Final[str] = "tests/sandbox/qemu/test_disk_overlay_isolation_s17d58.py"
_SNAPSHOT_OUTCOME: Final[str] = "tests/sandbox/qemu/test_snapshot_outcome_s17d59.py"
_SNAPSHOT_RUN_STATE: Final[str] = "tests/sandbox/qemu/test_snapshot_run_state_s17d74.py"
_SNAPSHOT_DELETE_OUTCOME: Final[str] = "tests/sandbox/qemu/test_snapshot_delete_outcome_s17d76.py"
_SNAPSHOT_WHPX_DISK_ONLY: Final[str] = "tests/sandbox/qemu/test_snapshot_whpx_disk_only_s17d75.py"
_TEST_SANDBOX_SESSION_REAPED: Final[str] = "tests/sandbox/windows/test_sandbox_test_session_reaped_s17d80.py"
_QMP_EVENT_DEMUX: Final[str] = "tests/sandbox/qemu/test_qmp_event_demux_s17d63.py"
_MEMORY_DUMP_OUTCOME: Final[str] = "tests/sandbox/qemu/test_memory_dump_outcome_s17d61.py"
_GUEST_COMPUTER_NAME: Final[str] = "tests/sandbox/qemu/test_guest_computer_name_s17d46.py"
_LINUX_AGENT_BOOTSTRAP: Final[str] = "tests/sandbox/qemu/test_linux_agent_bootstrap_s17d82.py"
_APP_ICON_FRAMES: Final[str] = "tests/ui/test_app_icon_frames.py"

# Whole test classes whose every method requires a host capability.
HOST_NATIVE_CLASSES: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        (_XPU_E2E, "TestXPUHardwareValidation"),
        (_XPU_E2E, "TestModelLoadingOntoXPU"),
        (_XPU_E2E, "TestRealInference"),
        (_XPU_E2E, "TestStreamingInference"),
        (_XPU_E2E, "TestMultiTurnConversation"),
        (_XPU_E2E, "TestTemperatureAndSampling"),
        (_XPU_E2E, "TestMaxTokensControl"),
        (_XPU_E2E, "TestVRAMManagement"),
        (_XPU_E2E, "TestPromptFormatting"),
        (_XPU_E2E, "TestDtypeSelection"),
        (_XPU_E2E, "TestErrorRecovery"),
        (_TRANSFORMERS, "TestXPUDetection"),
        (_TRANSFORMERS, "TestXPUTests"),
        (_TRANSFORMERS, "TestB580SpecificTests"),
        (_XPU_STATUS, "TestXPUStatusDialogDeviceInfo"),
        (_E2E_CHAT, "TestOllamaE2EChat"),
        (_OLLAMA_PROVIDER, "TestOllamaModelListing"),
        (_WHPX_CPU_MODEL, "TestTheWhpxCpuModelStartsAWindowsKernel"),
        (_WHPX_IRQCHIP, "TestTheWhpxInterruptChipReachesAWindowsGuest"),
        (_ABSOLUTE_POINTER, "TestTheGuestGetsAnAbsolutePointingDevice"),
        (_SPAWN_HELPER, "TestTheAnswerMediumCarriesTheSpawnHelpers"),
        (_SPAWN_HELPER, "TestTheRealVirtioMediumYieldsTheSpawnHelpers"),
        (_VIRTIO_SUBPATHS, "TestTheRealMediumEnumeratesOnlyRealDirectories"),
        (_DISK_OVERLAY, "TestTwoSandboxesNeverOpenTheSameWritableDisk"),
        (_SNAPSHOT_OUTCOME, "TestSnapshotOperationsReportTheRealOutcome"),
        (_SNAPSHOT_RUN_STATE, "TestAFailedSnapshotLeavesTheMachineRunning"),
        (_SNAPSHOT_DELETE_OUTCOME, "TestDeletingASnapshotReportsWhatHappened"),
        (_SNAPSHOT_WHPX_DISK_ONLY, "TestASnapshotCanBeTakenUnderWhpx"),
        (_TEST_SANDBOX_SESSION_REAPED, "TestTheTestSandboxPathLeavesNoSessionRunning"),
        (_QMP_EVENT_DEMUX, "TestQmpRepliesSurviveAsynchronousEvents"),
        (_MEMORY_DUMP_OUTCOME, "TestAMemoryDumpReportsItsRealOutcome"),
        (_GUEST_COMPUTER_NAME, "TestTheEnforcementCommandRenamesARealGuest"),
        (_LINUX_AGENT_BOOTSTRAP, "TestTheDebianGuestReachesAgentReady"),
    },
)

# Individual class methods that require a host capability (their sibling methods
# run fine in the container and must not be marked).
HOST_NATIVE_METHODS: Final[frozenset[tuple[str, str, str]]] = frozenset(
    {
        (_XPU_E2E, "TestModelCacheLifecycle", "test_load_populates_cache"),
        (_XPU_E2E, "TestModelCacheLifecycle", "test_cache_hit_returns_same_object"),
        (_XPU_E2E, "TestProviderConnectionLifecycle", "test_connect_sets_xpu_detection_state"),
        (_XPU_E2E, "TestProviderConnectionLifecycle", "test_connect_sets_device_type"),
        (_XPU_E2E, "TestProviderConnectionLifecycle", "test_disconnect_clears_state"),
        (_XPU_E2E, "TestProviderConnectionLifecycle", "test_get_device_info_after_connect"),
        (_XPU_STATUS, "TestXPUStatusDialogMemory", "test_memory_bar_shows_real_percentage"),
        (_XPU_STATUS, "TestXPUStatusDialogMemory", "test_memory_text_shows_gb_values"),
        (_XPU_UTILS, "TestXpuDeviceInfo", "test_device_zero_info_when_available"),
        (_XPU_UTILS, "TestXpuDeviceInfo", "test_out_of_range_device_returns_none"),
        (_XPU_UTILS, "TestXpuMemoryInfo", "test_out_of_range_memory_info_is_zero_pair"),
        (_XPU_UTILS, "TestInitializeXpu", "test_initialize_returns_real_device"),
        (_XPU_UTILS, "TestInitializeXpu", "test_out_of_range_index_raises_runtime_error"),
        (_GPU_PCI, "TestEnumeratePciMemoryBars", "test_real_gpu_reports_positive_bar"),
        (_GPU_PCI, "TestEnumeratePciMemoryBars", "test_intel_arc_bar_is_at_least_pre_rebar_ceiling"),
        (_GPU_PCI, "TestParseDeviceIdFromPnp", "test_real_intel_arc_ids_parse_to_hex_device_id"),
        (_XPU_LOADER, "TestLocateDevnode", "test_real_gpu_pnp_id_resolves_to_positive_devinst"),
        (_OLLAMA_PROVIDER, "TestOllamaConnection", "test_is_connected_after_connect"),
        (_OLLAMA_PROVIDER, "TestOllamaConnection", "test_provider_name_is_ollama"),
        (_OLLAMA_PROVIDER, "TestOllamaConnection", "test_connection_with_custom_base_url"),
        (_OLLAMA_PROVIDER, "TestOllamaConnection", "test_disconnect_clears_connection_state"),
        (_AGENTIC, "TestAccurateToolSupport", "test_ollama_models_report_accurate_tool_support"),
        (_MODEL_DISCOVERY, "TestOllamaLocalModelListing", "test_display_ollama_models"),
        (_PROCESS_BRIDGE, "TestF0024SymbolInfoSizeOfStruct", "test_resolve_symbol_returns_nonempty_name"),
        (_PROCESS_BRIDGE, "TestF0025ImageHlpModuleStruct", "test_resolve_module_returns_kernel32"),
        (_PROCESS_BRIDGE, "TestF0042SymbolBufferAllocation", "test_resolve_symbol_no_truncation_on_long_name"),
        (_PROCESS_BRIDGE, "TestF0017DeviceHandleType", "test_device_open_known_device_positive_handle"),
        (_PROCESS_BRIDGE, "TestF0016DeviceCloseResult", "test_device_close_valid_handle_returns_true"),
        (_PROCESS_BRIDGE, "TestF0018DeviceIoctlHexInput", "test_device_ioctl_valid_hex_accepted"),
        (_PROCESS_BRIDGE, "TestF0037DeviceIoctlOutputHex", "test_device_ioctl_output_is_hex_string"),
        (_PROCESS_BRIDGE, "TestF0013JobHandleEnumeration", "test_get_job_info_returns_in_job_when_assigned"),
        (_CUTTER_DECOMPILE, "TestRealDecompileGhidra", "test_decompile_produces_c_like_tokens"),
        (_CUTTER_DECOMPILE, "TestRealDecompileGhidra", "test_decompile_is_deterministic_and_addresses_function"),
        (_CUTTER_DECOMPILE, "TestRealCfgBasicBlocks", "test_get_function_graph_returns_multiple_real_blocks_with_edges"),
        (_CUTTER_DECOMPILE, "TestRealCfgBasicBlocks", "test_get_function_graph_blocks_carry_real_disassembly"),
        (_CUTTER_DECOMPILE, "TestRealCfgBasicBlocks", "test_get_function_graph_offsets_match_get_basic_blocks_oracle"),
        (_X64DBG_LOAD, "TestLoadRegistersAttachedProcess", "test_load_then_run_makes_inspection_commands_see_the_attached_process"),
        (
            _X64DBG_WATCHPOINTS,
            "TestGetWatchpointsListsAddedHardwareWatchpoint",
            "test_get_watchpoints_after_set_watchpoint_includes_the_new_address",
        ),
        (
            _X64DBG_WATCHPOINTS,
            "TestGetWatchpointsListsAddedHardwareWatchpoint",
            "test_get_watchpoints_on_fresh_debuggee_returns_empty_without_raising",
        ),
    },
)

# Module-level test functions (no enclosing class) that require a host capability.
HOST_NATIVE_FUNCTIONS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        (_ANALYSIS_REAL, "test_detect_c2_patterns_on_real_c2_port_capture"),
        (_ANALYSIS_REAL, "test_match_behaviors_on_real_capture_is_consistent"),
        (_INLINE_MONITORS, "test_network_monitor_source_captures_live_endpoints"),
        (_OLLAMA_CHAT_LIVE, "test_live_ollama_chat_and_stream"),
        (_INJECTION_MONITOR, "test_script_emits_threat_intel_unavailable_warning_when_not_admin"),
        (_KERNEL_OBJECT_MONITOR, "test_script_logs_sedebug_failure_when_non_admin"),
        (_INJECTION_MONITOR, "test_smoke_lifecycle_records_started_and_stopped"),
        (_DLL_MONITOR, "test_etw_load_event_is_captured_when_admin"),
        (_API_TRACE, "test_smoke_script_emits_start_record_when_dll_available"),
        (_API_TRACE, "test_smoke_script_emits_event_records_under_admin"),
        (_SERVICE_MONITOR, "test_script_records_lifecycle_transitions"),
        (_X64DBG_EMBED, "test_desktop_scoped_finder_locates_window_plain_enum_windows_cannot"),
        (_X64DBG_EMBED, "test_desktop_scoped_finder_returns_none_for_mismatched_pid"),
        (_X64DBG_EMBED, "test_resolve_debugger_window_hwnd_uses_registered_desktop"),
        (_X64DBG_EMBED, "test_get_desktop_handle_for_pid_cleared_after_close"),
        (_SEH_X64_PDATA, "test_seh_chain_x64_target_returns_nonempty_pdata_handlers"),
        (_SEH_X64_PDATA, "test_seh_chain_x64_addresses_resolve_within_loaded_modules"),
        (_APP_ICON_FRAMES, "test_rebranded_tool_icon_matches_app_icon"),
    },
)


def split_nodeid(nodeid: str) -> tuple[str, str | None, str]:
    """Split a pytest node id into (module path, class name, function name).

    Parametrized ids (``...::test[case]``) are normalised to the base function
    name. The module path is normalised to forward slashes so lookups match the
    registry regardless of the host OS path separator.

    Args:
        nodeid: A pytest node id such as ``tests/x.py::TestC::test_f[p]``.

    Returns:
        tuple[str, str | None, str]: The module path (forward-slashed), the
            enclosing class name or ``None`` for a module-level function, and
            the base function name.
    """
    parts = nodeid.split("::")
    module = parts[0].replace("\\", "/")
    func = parts[-1].split("[", 1)[0]
    class_name = parts[1] if len(parts) >= _CLASSED_NODEID_FIELD_COUNT else None
    return module, class_name, func


def is_host_native_nodeid(nodeid: str) -> bool:
    """Return whether a pytest node id names a host-native test.

    Args:
        nodeid: The pytest node id to classify.

    Returns:
        bool: ``True`` when the test requires a real host capability and must
            run only in the host-native pass.
    """
    module, class_name, func = split_nodeid(nodeid)
    if class_name is not None:
        if (module, class_name) in HOST_NATIVE_CLASSES:
            return True
        return (module, class_name, func) in HOST_NATIVE_METHODS
    return (module, func) in HOST_NATIVE_FUNCTIONS


def iter_registry_entries() -> list[str]:
    """Return a human-readable list of every registry entry.

    Used by the falsifiable gate to confirm each entry still resolves to a real
    collected test (i.e. the registry has not drifted from the suite).

    Returns:
        list[str]: One ``module::target`` string per registry entry.
    """
    entries: list[str] = []
    entries.extend(f"{module}::{class_name}" for module, class_name in HOST_NATIVE_CLASSES)
    entries.extend(f"{module}::{class_name}::{func}" for module, class_name, func in HOST_NATIVE_METHODS)
    entries.extend(f"{module}::{func}" for module, func in HOST_NATIVE_FUNCTIONS)
    return entries


def mark_host_native_items(items: list[pytest.Item]) -> int:
    """Apply the ``host_native`` marker to every registry-listed collected item.

    Args:
        items: Collected test items; matching items are marked in place.

    Returns:
        int: The number of items that were marked.
    """
    marker = pytest.mark.host_native
    marked = 0
    for item in items:
        if is_host_native_nodeid(item.nodeid):
            item.add_marker(marker)
            marked += 1
    return marked


def deselect_host_native(config: pytest.Config, items: list[pytest.Item]) -> int:
    """Remove ``host_native`` items from the run and report them as deselected.

    Args:
        config: Active pytest configuration, used to report the deselection.
        items: Mutable list of collected items; host-native items are removed
            in place.

    Returns:
        int: The number of items that were deselected.
    """
    drop = [item for item in items if item.get_closest_marker(HOST_NATIVE_MARKER) is not None]
    if not drop:
        return 0
    keep = [item for item in items if item.get_closest_marker(HOST_NATIVE_MARKER) is None]
    config.hook.pytest_deselected(items=drop)
    items[:] = keep
    return len(drop)


def keep_only_host_native(config: pytest.Config, items: list[pytest.Item]) -> int:
    """Deselect every non-``host_native`` item, keeping only host-native tests.

    Args:
        config: Active pytest configuration, used to report the deselection.
        items: Mutable list of collected items; non-host-native items are
            removed in place.

    Returns:
        int: The number of items kept.
    """
    drop = [item for item in items if item.get_closest_marker(HOST_NATIVE_MARKER) is None]
    if not drop:
        return len(items)
    keep = [item for item in items if item.get_closest_marker(HOST_NATIVE_MARKER) is not None]
    config.hook.pytest_deselected(items=drop)
    items[:] = keep
    return len(keep)
