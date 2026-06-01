# Test Quality Audit — INDEX

Audit of Intellicrack's full test suite against the falsifiability standard in
`.claude/agents/test-writer.md`. Every test function in `tests/` was individually
evaluated by one of 20 parallel Haiku sub-agents (gaps from token-limited first
passes were closed by 7 follow-up sub-chunks and folded into the canonical reports).

## Scope

- **Test files audited:** 354 (`test_*.py` / `*_test.py`; excludes `__init__.py`)
- **conftest.py fixture files audited:** 18 (each assigned to the partition owning its directory)
- **Total test functions audited:** 6152 (100% of the enumerated suite)
- **Partitions:** 20, mutually exclusive and collectively exhaustive (verified — union of all 20 file lists equals the full enumeration, zero gaps, zero double-assignment)

## Aggregate findings by severity

| Severity | Count |
|----------|-------|
| Critical | 16 |
| High | 98 |
| Medium | 209 |
| Low | 206 |
| **Total** | **529** |

- **Test files with ≥1 finding:** 229
- **Test files with ZERO findings:** 125
- **conftest.py fixtures flagged:** 12

## Per-agent summary

| Agent | Test funcs | Files | Crit | High | Med | Low | Findings |
|-------|-----------|-------|------|------|-----|-----|----------|
| 01 | 308 | 17 | 0 | 3 | 9 | 8 | 20 |
| 02 | 308 | 20 | 1 | 4 | 7 | 3 | 15 |
| 03 | 308 | 17 | 2 | 0 | 54 | 79 | 135 |
| 04 | 308 | 17 | 0 | 2 | 5 | 6 | 13 |
| 05 | 308 | 19 | 0 | 2 | 7 | 6 | 15 |
| 06 | 308 | 22 | 0 | 14 | 10 | 21 | 45 |
| 07 | 308 | 18 | 0 | 2 | 3 | 4 | 9 |
| 08 | 308 | 19 | 1 | 2 | 12 | 13 | 28 |
| 09 | 308 | 19 | 0 | 15 | 23 | 22 | 60 |
| 10 | 308 | 20 | 1 | 7 | 0 | 0 | 8 |
| 11 | 308 | 20 | 2 | 0 | 4 | 10 | 16 |
| 12 | 308 | 19 | 0 | 1 | 2 | 6 | 9 |
| 13 | 307 | 18 | 0 | 4 | 4 | 0 | 8 |
| 14 | 307 | 18 | 0 | 0 | 6 | 2 | 8 |
| 15 | 307 | 18 | 0 | 2 | 2 | 3 | 7 |
| 16 | 307 | 18 | 0 | 3 | 5 | 2 | 10 |
| 17 | 307 | 18 | 7 | 31 | 38 | 9 | 85 |
| 18 | 307 | 19 | 1 | 3 | 5 | 7 | 16 |
| 19 | 307 | 18 | 1 | 3 | 11 | 3 | 18 |
| 20 | 307 | 18 | 0 | 0 | 2 | 2 | 4 |
| **All** | **6152** | **372** | **16** | **98** | **209** | **206** | **529** |

## Recurring fake-gate patterns (cross-partition)

1. **Mock-the-thing-under-test** — bridge/sandbox/provider tests that patch the very
   operation they claim to verify (QMP client, guest-agent client, YARA scanner,
   `run_bridge_coroutine_async`, `_probe_type`), so only a mock interaction is proven.
2. **Weak-assertion-on-rich-output** — `is not None` / `len() > 0` / key-existence on
   parsed PE records, disassembly, diffs, and tool-call args whose exact values are
   what matter.
3. **Vacuous construction tests** — dataclass instantiate-and-read-back tests
   (notably the entirety of `test_core/test_types.py`) that assert field == constructor arg.
4. **Source-string smoke tests** — asserting a PowerShell/script file *contains* a
   substring instead of executing it and verifying behavior (e.g. `test_ps_sources.py`).
5. **Cannot-fail guards** — `pytest.skip`/broad `try-except`/OR-fallback tolerances
   that let malformed output pass, plus credential-gated provider tests that skip silently.
6. **Tautological constants** — anti-evasion identity tests and device-ID detection tests
   that compare the implementation to a copy of its own constant.

## Per-agent partitions and file lists

### Agent 01 — 308 test functions across 17 files
- Findings: 0 Critical / 3 High / 9 Medium / 8 Low (20 total)
- Report: [`audit/agent-01.md`](agent-01.md)
- Partition files:
  - `tests/test_audit4/b2_process_tab/conftest.py`
  - `tests/test_audit4/b2_process_tab/test_process_tab.py`
  - `tests/test_audit4/b4_memory_tab/test_memory_tab.py`
  - `tests/test_audit4/b4_memory_tab/test_realcov_14a_memory_tab.py`
  - `tests/test_audit4/c3_hex_data_inspector/test_data_inspector.py`
  - `tests/test_audit5/u7_ui_providerconfig/test_provider_specific_ui.py`
  - `tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py`
  - `tests/test_audit7/sandbox_monitors/conftest.py`
  - `tests/test_audit7/sandbox_monitors/test_dll_log_parser.py`
  - `tests/test_audit7/ui_panels_process/conftest.py`
  - `tests/test_audit7/ui_panels_process/test_threads_auto_refresh.py`
  - `tests/test_bridges/test_process_bridge.py`
  - `tests/test_core/test_process_manager_audit6.py`
  - `tests/test_credentials/test_env_loader_roundtrip_live.py`
  - `tests/test_hexcore_e2e/test_bookmarks.py`
  - `tests/test_hexcore_e2e/test_document_lifecycle.py`
  - `tests/test_ui/log_viewer/test_realcov_15_tail_reader_real_logs.py`

### Agent 02 — 308 test functions across 20 files
- Findings: 1 Critical / 4 High / 7 Medium / 3 Low (15 total)
- Report: [`audit/agent-02.md`](agent-02.md)
- Partition files:
  - `tests/test_audit3/sandbox/conftest.py`
  - `tests/test_audit3/sandbox/test_clipboard_monitor.py`
  - `tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py`
  - `tests/test_audit4/b7_process_panel_workers/test_tracked_refresh_worker.py`
  - `tests/test_audit4/c10_hex_scripting/test_scripting_encoding_print.py`
  - `tests/test_audit5/u5_ui_mainwindow/test_realcov_15_mainwindow_runtime.py`
  - `tests/test_audit7/sandbox_monitors/test_stop_event.py`
  - `tests/test_audit7/ui_wire_sandbox_backend/conftest.py`
  - `tests/test_audit7/ui_wire_sandbox_backend/test_wire_sandbox_backend.py`
  - `tests/test_bridges/test_pe_format.py`
  - `tests/test_core/test_realcov_05b_analysis_aggregator.py`
  - `tests/test_hexcore_e2e/test_bridge_disassembly_deep.py`
  - `tests/test_hexcore_e2e/test_hexpat_evaluator.py`
  - `tests/test_providers/test_message_conversion.py`
  - `tests/test_providers/test_ollama_provider.py`
  - `tests/test_ui/log_viewer/conftest.py`
  - `tests/test_ui/log_viewer/test_realcov_15_window_real_logs.py`
  - `tests/test_ui/log_viewer/test_record.py`
  - `tests/test_ui/test_hxd_panel.py`
  - `tests/test_ui/test_tools_logic.py`

### Agent 03 — 308 test functions across 17 files
- Findings: 2 Critical / 0 High / 54 Medium / 79 Low (135 total)
- Report: [`audit/agent-03.md`](agent-03.md)
- Partition files:
  - `tests/test_audit4/c11_hex_process_memory/test_bridge_route.py`
  - `tests/test_audit4/c13_hex_patches_route/test_patches_bridge_route.py`
  - `tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py`
  - `tests/test_audit4/c2_hex_highlighting_route/test_realcov_13b_highlight_apply.py`
  - `tests/test_audit7/core_orchestration/test_tag_chips_widget.py`
  - `tests/test_audit7/sandbox_manager/test_eviction_deadlock.py`
  - `tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py`
  - `tests/test_bridges/test_frida_bridge.py`
  - `tests/test_bridges/test_x64dbg_audit6.py`
  - `tests/test_core/test_config.py`
  - `tests/test_core/test_orchestrator.py`
  - `tests/test_hexcore_e2e/test_bridge_va_mapping.py`
  - `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py`
  - `tests/test_hexcore_e2e/test_hexpat_control_flow.py`
  - `tests/test_hexcore_e2e/test_undo_redo.py`
  - `tests/test_hexpat/test_realcov_08_parser_unit.py`
  - `tests/test_providers/test_providers_local_audit1.py`

### Agent 04 — 308 test functions across 17 files
- Findings: 0 Critical / 2 High / 5 Medium / 6 Low (13 total)
- Report: [`audit/agent-04.md`](agent-04.md)
- Partition files:
  - `tests/test_audit4/c15_hex_comparison_tempfile/test_diff_temp_cleanup.py`
  - `tests/test_audit4/c6_hex_hashing/test_hashing.py`
  - `tests/test_audit4/c9_hex_disassembly_debounce/test_follow_cursor_debounce.py`
  - `tests/test_audit4/c9_hex_disassembly_debounce/test_realcov_13a_statistics.py`
  - `tests/test_audit5/u4_hexpat_aux/test_compiler_pragma_propagation.py`
  - `tests/test_audit7/sandbox_qemu/test_anti_evasion_profile.py`
  - `tests/test_audit7/sandbox_windows/test_memory_dump_target_pid.py`
  - `tests/test_audit7/u12_hexpat_print_sink/test_bridge_print_sink.py`
  - `tests/test_core/test_process_manager.py`
  - `tests/test_core/test_realcov_07a_yara_scanner.py`
  - `tests/test_hexcore_e2e/test_entropy.py`
  - `tests/test_hexcore_e2e/test_hexcore_rust_audit1.py`
  - `tests/test_hexcore_e2e/test_realcov_09b_typesystem_completer.py`
  - `tests/test_providers/test_credential_loading.py`
  - `tests/test_providers/test_providers_cloud_audit1.py`
  - `tests/test_providers/test_realcov_10_grok_reasoning_effort.py`
  - `tests/test_sandbox/test_analysis.py`

### Agent 05 — 308 test functions across 19 files
- Findings: 0 Critical / 2 High / 7 Medium / 6 Low (15 total)
- Report: [`audit/agent-05.md`](agent-05.md)
- Partition files:
  - `tests/test_bridges/test_ghidra.py`
  - `tests/test_bridges/test_hex_state_audit1.py`
  - `tests/test_bridges/test_x64dbg_events.py`
  - `tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py`
  - `tests/test_hexcore_e2e/test_bridge_signatures.py`
  - `tests/test_hexcore_e2e/test_search.py`
  - `tests/test_hexpat/conftest.py`
  - `tests/test_hexpat/test_lexer.py`
  - `tests/test_hexpat/test_realcov_08_preprocessor_vendor.py`
  - `tests/test_providers/test_discovery_unit.py`
  - `tests/test_providers/test_realcov_10_anthropic_cache.py`
  - `tests/test_providers/test_realcov_11_model_loader.py`
  - `tests/test_ui/log_viewer/test_app_integration.py`
  - `tests/test_ui/log_viewer/test_window.py`
  - `tests/test_ui/test_realcov_14b_script_manager.py`
  - `tests/test_ui/test_realcov_15_chat_panel.py`
  - `tests/test_ui/test_tool_status_dialog_prefetch.py`
  - `tests/ui/conftest.py`
  - `tests/ui/test_system_tab_warnings.py`

### Agent 06 — 308 test functions across 22 files
- Findings: 0 Critical / 14 High / 10 Medium / 21 Low (45 total)
- Report: [`audit/agent-06.md`](agent-06.md)
- Partition files:
  - `tests/conftest.py`
  - `tests/test_audit4/b6_system_tab/conftest.py`
  - `tests/test_audit4/b6_system_tab/test_system_tab.py`
  - `tests/test_audit4/c9_hex_disassembly_debounce/test_realcov_13a_disassembly_output.py`
  - `tests/test_bridges/test_base.py`
  - `tests/test_bridges/test_cutter.py`
  - `tests/test_bridges/test_hex_editor_bottom_audit1.py`
  - `tests/test_core/test_logging_audit6.py`
  - `tests/test_core/test_realcov_06_config_integration.py`
  - `tests/test_hexcore_e2e/conftest.py`
  - `tests/test_hexcore_e2e/test_bridge_ai_context.py`
  - `tests/test_hexcore_e2e/test_bridge_base_convert.py`
  - `tests/test_hexcore_e2e/test_bridge_encoding_decoding.py`
  - `tests/test_hexcore_e2e/test_bridge_structure_bookmarks.py`
  - `tests/test_hexcore_e2e/test_bridge_yara.py`
  - `tests/test_hexcore_e2e/test_data_inspector.py`
  - `tests/test_hexcore_e2e/test_hexpat_preprocessor.py`
  - `tests/test_hexcore_e2e/test_patch_export.py`
  - `tests/test_hexcore_e2e/test_process_memory.py`
  - `tests/test_providers/test_grok_provider.py`
  - `tests/test_providers/test_ollama_chat_live.py`
  - `tests/test_providers/test_registry_thread_safety_live.py`

### Agent 07 — 308 test functions across 18 files
- Findings: 0 Critical / 2 High / 3 Medium / 4 Low (9 total)
- Report: [`audit/agent-07.md`](agent-07.md)
- Partition files:
  - `tests/test_audit4/c6_hex_hashing/test_realcov_13b_base_hashing.py`
  - `tests/test_audit7/config_pyproject/test_runtime_deps.py`
  - `tests/test_bridges/test_parse_helpers.py`
  - `tests/test_bridges/test_x64dbg_new_methods.py`
  - `tests/test_core/test_elevation.py`
  - `tests/test_core/test_realcov_06_error_logging.py`
  - `tests/test_core/test_realcov_06_logging_integration.py`
  - `tests/test_core/test_realcov_06_types_exceptions.py`
  - `tests/test_core/test_tools.py`
  - `tests/test_hexcore_e2e/test_bridge_block_ops.py`
  - `tests/test_hexcore_e2e/test_bridge_disassembly.py`
  - `tests/test_hexcore_e2e/test_bridge_search.py`
  - `tests/test_hexcore_e2e/test_hexpat_complex_patterns.py`
  - `tests/test_hexpat/test_realcov_08_lexer_escapes.py`
  - `tests/test_providers/test_huggingface_provider.py`
  - `tests/test_providers/test_model_discovery.py`
  - `tests/test_providers/test_parse_openai_format_tool_calls.py`
  - `tests/test_ui/test_splash_screen.py`

### Agent 08 — 308 test functions across 19 files
- Findings: 1 Critical / 2 High / 12 Medium / 13 Low (28 total)
- Report: [`audit/agent-08.md`](agent-08.md)
- Partition files:
  - `tests/test_audit3/bridges/test_realcov_04_installer.py`
  - `tests/test_audit5/u2_bridges_frida/test_frida_bridge_audit5.py`
  - `tests/test_audit7/core_orchestration/test_tool_registry_session.py`
  - `tests/test_bridges/test_ghidra_audit6.py`
  - `tests/test_bridges/test_realcov_03c_cutter.py`
  - `tests/test_core/test_realcov_07b_xml_gen.py`
  - `tests/test_core/test_session_audit6.py`
  - `tests/test_credentials/test_credential_store_live.py`
  - `tests/test_hexcore_e2e/test_bridge_bps_ups.py`
  - `tests/test_hexcore_e2e/test_bridge_pe_checksum.py`
  - `tests/test_hexcore_e2e/test_realcov_09b_stdlib_realbin.py`
  - `tests/test_providers/conftest.py`
  - `tests/test_providers/test_local_transformers_live.py`
  - `tests/test_providers/test_openai_provider.py`
  - `tests/test_providers/test_realcov_10_google_safety.py`
  - `tests/test_providers/test_safe_parse_stream_json.py`
  - `tests/test_scripts/test_commit_message.py`
  - `tests/test_ui/test_font_manager.py`
  - `tests/test_ui/test_realcov_13b_hex_sections.py`

### Agent 09 — 308 test functions across 19 files
- Findings: 0 Critical / 15 High / 23 Medium / 22 Low (60 total)
- Report: [`audit/agent-09.md`](agent-09.md)
- Partition files:
  - `tests/test_audit3/sandbox/test_api_trace.py`
  - `tests/test_audit4/b5_modules_tab/conftest.py`
  - `tests/test_audit4/b5_modules_tab/test_realcov_14a_modules_tab.py`
  - `tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py`
  - `tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py`
  - `tests/test_bridges/test_sandbox_bridge.py`
  - `tests/test_core/test_orchestrator_audit6.py`
  - `tests/test_core/test_realcov_07a_transform_pipeline.py`
  - `tests/test_hexcore_e2e/test_bridge_compare_files.py`
  - `tests/test_hexcore_e2e/test_bridge_document_info.py`
  - `tests/test_hexcore_e2e/test_bridge_patches.py`
  - `tests/test_hexcore_e2e/test_bridge_transforms.py`
  - `tests/test_hexcore_e2e/test_encodings.py`
  - `tests/test_providers/test_agentic_capabilities.py`
  - `tests/test_providers/test_providers_package_exports.py`
  - `tests/test_sandbox/test_realcov_04_sandbox_bridge.py`
  - `tests/test_ui/test_app_toolbar_overflow.py`
  - `tests/test_ui/test_realcov_13b_hex_calculator.py`
  - `tests/test_ui/test_realcov_13b_hex_widgets.py`

### Agent 10 — 308 test functions across 20 files
- Findings: 1 Critical / 7 High / 0 Medium / 0 Low (8 total)
- Report: [`audit/agent-10.md`](agent-10.md)
- Partition files:
  - `tests/test_audit3/ui/conftest.py`
  - `tests/test_audit3/ui/test_hxd_panel_wired.py`
  - `tests/test_audit4/b6_system_tab/test_realcov_14a_system_tab.py`
  - `tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py`
  - `tests/test_core/test_realcov_07b_template_manager.py`
  - `tests/test_core/test_types.py`
  - `tests/test_hexcore_e2e/test_bridge_hash_advanced.py`
  - `tests/test_hexcore_e2e/test_bridge_html_export_largefile.py`
  - `tests/test_hexcore_e2e/test_bridge_scripting.py`
  - `tests/test_hexcore_e2e/test_realcov_09a_evaluator_realdata.py`
  - `tests/test_hexpat/test_interpreter.py`
  - `tests/test_hexpat/test_realcov_08_vendor_patterns.py`
  - `tests/test_providers/test_anthropic_provider.py`
  - `tests/test_ui/conftest.py`
  - `tests/test_ui/test_overflow_toolbar.py`
  - `tests/test_ui/test_panel_dock.py`
  - `tests/test_ui/test_realcov_13b_hex_statistics.py`
  - `tests/test_ui/test_realcov_13b_hex_yara.py`
  - `tests/test_ui/test_realcov_14b_sandbox_report.py`
  - `tests/test_ui/test_vnc_widget.py`

### Agent 11 — 308 test functions across 20 files
- Findings: 2 Critical / 0 High / 4 Medium / 10 Low (16 total)
- Report: [`audit/agent-11.md`](agent-11.md)
- Partition files:
  - `tests/test_audit4/c12_hex_sandbox_route/test_sandbox_route.py`
  - `tests/test_audit4/c8_hex_signatures_offload/conftest.py`
  - `tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py`
  - `tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py`
  - `tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py`
  - `tests/test_bridges/test_realcov_04_base.py`
  - `tests/test_bridges/test_x64dbg.py`
  - `tests/test_core/test_realcov_05a_orchestration.py`
  - `tests/test_core/test_tools_audit6.py`
  - `tests/test_credentials/test_oauth_manager_live.py`
  - `tests/test_credentials/test_realcov_15_store_api.py`
  - `tests/test_hexcore_e2e/test_bridge_concurrent.py`
  - `tests/test_hexcore_e2e/test_bridge_copy_as.py`
  - `tests/test_hexcore_e2e/test_bridge_strings.py`
  - `tests/test_providers/test_google_provider.py`
  - `tests/test_providers/test_provider_bugfixes.py`
  - `tests/test_sandbox/conftest.py`
  - `tests/test_sandbox/test_log_helpers.py`
  - `tests/test_sandbox/test_sandbox_bridge.py`
  - `tests/test_ui/test_realcov_15_preferences_dialog.py`

### Agent 12 — 308 test functions across 19 files
- Findings: 0 Critical / 1 High / 2 Medium / 6 Low (9 total)
- Report: [`audit/agent-12.md`](agent-12.md)
- Partition files:
  - `tests/core/test_process_manager_leaks.py`
  - `tests/test_audit3/bridges/test_named_pipe_client.py`
  - `tests/test_audit3/sandbox/test_injection_monitor.py`
  - `tests/test_audit3/ui/test_ghidra_panel.py`
  - `tests/test_audit4/c16_hex_panel_selection_dispatch/test_selection_dispatch.py`
  - `tests/test_audit4/c7_hex_bookmarks_notify/test_bookmark_notify.py`
  - `tests/test_audit4/c9_hex_disassembly_debounce/test_realcov_13a_sections.py`
  - `tests/test_audit5/u8_ui_config_paths/test_config_paths.py`
  - `tests/test_bridges/test_process_win32.py`
  - `tests/test_bridges/test_win32_types.py`
  - `tests/test_core/test_realcov_06_subprocess_compat.py`
  - `tests/test_hexcore_e2e/test_bridge_alignment_color.py`
  - `tests/test_hexcore_e2e/test_bridge_display_modes_complete.py`
  - `tests/test_hexcore_e2e/test_bridge_yara_deep.py`
  - `tests/test_providers/test_http_status_helper.py`
  - `tests/test_providers/test_registry.py`
  - `tests/test_ui/test_process_panel.py`
  - `tests/test_ui/test_realcov_15_resource_url_dispatch.py`
  - `tests/test_ui/test_realcov_15_session_manager_dialog.py`

### Agent 13 — 307 test functions across 18 files
- Findings: 0 Critical / 4 High / 4 Medium / 0 Low (8 total)
- Report: [`audit/agent-13.md`](agent-13.md)
- Partition files:
  - `tests/test_audit3/sandbox/test_resource_monitor.py`
  - `tests/test_audit3/ui/test_script_manager.py`
  - `tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py`
  - `tests/test_audit4/b1_process_panel_base/test_process_panel_base.py`
  - `tests/test_audit4/b3_threads_tab/test_threads_tab.py`
  - `tests/test_audit4/c9_hex_disassembly_debounce/test_realcov_13a_widgets.py`
  - `tests/test_audit7/core_orchestration/test_compiled_yara_protocol.py`
  - `tests/test_audit7/sandbox_windows/test_anti_evasion_wmi_hijack.py`
  - `tests/test_bridges/test_bridges_core_audit1.py`
  - `tests/test_bridges/test_ghidra_f11_audit.py`
  - `tests/test_core/test_analysis_aggregator.py`
  - `tests/test_core/test_script_gen.py`
  - `tests/test_hexcore_e2e/test_bridge_bit_ops.py`
  - `tests/test_hexcore_e2e/test_bridge_copy_as_complete.py`
  - `tests/test_hexcore_e2e/test_bridge_lifecycle.py`
  - `tests/test_hexcore_e2e/test_hashing.py`
  - `tests/test_sandbox/test_log_parsers.py`
  - `tests/test_ui/test_resource_helper.py`

### Agent 14 — 307 test functions across 18 files
- Findings: 0 Critical / 0 High / 6 Medium / 2 Low (8 total)
- Report: [`audit/agent-14.md`](agent-14.md)
- Partition files:
  - `tests/core/test_process_cleanup.py`
  - `tests/test_audit3/core/test_xml_gen.py`
  - `tests/test_audit4/c9_hex_disassembly_debounce/test_realcov_13a_calculator.py`
  - `tests/test_audit5/u4_hexpat_aux/test_parser_aggregate_errors.py`
  - `tests/test_audit5/u6_ui_tools/test_function_xref_population.py`
  - `tests/test_audit7/providers_meta/test_discover_all_cache.py`
  - `tests/test_bridges/test_realcov_02a_x64dbg.py`
  - `tests/test_bridges/test_realcov_03b_ghidra.py`
  - `tests/test_bridges/test_x64dbg_audit7_f0001.py`
  - `tests/test_core/test_logging.py`
  - `tests/test_core/test_realcov_05b_tools.py`
  - `tests/test_core/test_realcov_06_optional_imports.py`
  - `tests/test_hexcore_e2e/test_bridge_pe_introspection.py`
  - `tests/test_hexpat/test_realcov_07b_compiler_pragmas.py`
  - `tests/test_providers/test_openrouter_provider.py`
  - `tests/test_providers/test_provider_loop_rebind.py`
  - `tests/test_providers/test_realcov_11_xpu_utils.py`
  - `tests/test_ui/test_search_async.py`

### Agent 15 — 307 test functions across 18 files
- Findings: 0 Critical / 2 High / 2 Medium / 3 Low (7 total)
- Report: [`audit/agent-15.md`](agent-15.md)
- Partition files:
  - `tests/test_audit3/core/test_disassembler.py`
  - `tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py`
  - `tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py`
  - `tests/test_audit7/sandbox_qemu/test_logs_stable.py`
  - `tests/test_bridges/test_process_audit7.py`
  - `tests/test_bridges/test_realcov_03a_frida_modules.py`
  - `tests/test_core/test_main.py`
  - `tests/test_hexcore_e2e/test_bridge_arithmetic.py`
  - `tests/test_hexcore_e2e/test_bridge_new_capabilities.py`
  - `tests/test_hexcore_e2e/test_bridge_state_integration.py`
  - `tests/test_hexcore_e2e/test_templates.py`
  - `tests/test_providers/test_anthropic_buffers_live.py`
  - `tests/test_providers/test_realcov_10_discovery_extra.py`
  - `tests/test_providers/test_realcov_11_huggingface_logic.py`
  - `tests/test_sandbox/test_base_types.py`
  - `tests/test_sandbox/test_realcov_12b_analysis_real.py`
  - `tests/test_ui/log_viewer/test_proxy.py`
  - `tests/test_ui/test_hex_format.py`

### Agent 16 — 307 test functions across 18 files
- Findings: 0 Critical / 3 High / 5 Medium / 2 Low (10 total)
- Report: [`audit/agent-16.md`](agent-16.md)
- Partition files:
  - `tests/test_audit3/bridges/test_installer.py`
  - `tests/test_audit3/core/test_script_gen.py`
  - `tests/test_audit3/sandbox/test_service_monitor.py`
  - `tests/test_audit5/u9_ui_confirmation/test_confirmation_dialog.py`
  - `tests/test_audit7/sandbox_qemu/test_extract_dropped_files.py`
  - `tests/test_audit7/sandbox_windows/test_realcov_12b_inline_monitors.py`
  - `tests/test_core/test_realcov_05b_process_manager.py`
  - `tests/test_core/test_realcov_07a_disassembler.py`
  - `tests/test_hexcore_e2e/test_bridge_display.py`
  - `tests/test_hexcore_e2e/test_bridge_transforms_deep.py`
  - `tests/test_hexcore_e2e/test_hexpat_parser_e2e.py`
  - `tests/test_hexcore_e2e/test_hexpat_pattern_registry.py`
  - `tests/test_providers/test_google_chat_live.py`
  - `tests/test_providers/test_local_transformers_provider.py`
  - `tests/test_providers/test_tool_call_buffer.py`
  - `tests/test_ui/test_realcov_13b_hex_pattern_code_editor.py`
  - `tests/test_ui/test_realcov_14b_panel_support.py`
  - `tests/test_ui/test_sandbox_panel_fixes.py`

### Agent 17 — 307 test functions across 18 files
- Findings: 7 Critical / 31 High / 38 Medium / 9 Low (85 total)
- Report: [`audit/agent-17.md`](agent-17.md)
- Partition files:
  - `tests/test_audit3/sandbox/test_start_monitors.py`
  - `tests/test_audit4/a4_windows_sandbox/test_ps_sources.py`
  - `tests/test_audit4/b5_modules_tab/test_modules_tab.py`
  - `tests/test_audit5/u3_hexpat_core/test_hexpat_core.py`
  - `tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py`
  - `tests/test_audit7/u12_hexpat_print_sink/test_ui_print_sink.py`
  - `tests/test_core/test_realcov_06_elevation_windows.py`
  - `tests/test_hexcore_e2e/test_binary_diff.py`
  - `tests/test_hexcore_e2e/test_bridge_sandbox.py`
  - `tests/test_hexcore_e2e/test_read_write_ops.py`
  - `tests/test_hexcore_e2e/test_transforms.py`
  - `tests/test_providers/test_e2e_chat.py`
  - `tests/test_providers/test_huggingface_chat_live.py`
  - `tests/test_providers/test_local_xpu_e2e.py`
  - `tests/test_sandbox/test_manager.py`
  - `tests/test_ui/log_viewer/test_model.py`
  - `tests/test_ui/test_dialogs.py`
  - `tests/test_ui/test_realcov_14b_cutter_tabs.py`

### Agent 18 — 307 test functions across 19 files
- Findings: 1 Critical / 3 High / 5 Medium / 7 Low (16 total)
- Report: [`audit/agent-18.md`](agent-18.md)
- Partition files:
  - `tests/test_audit4/b1_process_panel_base/test_realcov_14a_panel_base.py`
  - `tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py`
  - `tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py`
  - `tests/test_bridges/conftest.py`
  - `tests/test_bridges/test_hex_editor_pe_methods.py`
  - `tests/test_bridges/test_realcov_01_hex_editor_pe_real.py`
  - `tests/test_bridges/test_realcov_02b_named_pipe_real.py`
  - `tests/test_bridges/test_schemas.py`
  - `tests/test_hexcore_e2e/test_hex_document_state.py`
  - `tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py`
  - `tests/test_hexpat/test_parse_helpers.py`
  - `tests/test_providers/test_openai_format_helpers.py`
  - `tests/test_providers/test_realcov_10_cancel_request.py`
  - `tests/test_providers/test_realcov_11_gpu_pci.py`
  - `tests/test_providers/test_tool_schema_builders.py`
  - `tests/test_ui/test_icon_manager.py`
  - `tests/test_ui/test_realcov_14b_analysis_panel.py`
  - `tests/test_ui/test_realcov_14b_graph_view.py`
  - `tests/test_ui/test_win32_embed.py`

### Agent 19 — 307 test functions across 18 files
- Findings: 1 Critical / 3 High / 11 Medium / 3 Low (18 total)
- Report: [`audit/agent-19.md`](agent-19.md)
- Partition files:
  - `tests/test_audit3/sandbox/test_dll_monitor.py`
  - `tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py`
  - `tests/test_audit4/b2_process_tab/test_realcov_14a_process_tab.py`
  - `tests/test_audit7/bridges_hex/test_bps_streaming_export.py`
  - `tests/test_audit7/ui_panels_process/test_realcov_14a_x64dbg_panel.py`
  - `tests/test_bridges/test_plugin_deploy.py`
  - `tests/test_bridges/test_realcov_01_pe_format_real_binaries.py`
  - `tests/test_bridges/test_x64dbg_api_coverage.py`
  - `tests/test_hexcore_e2e/test_hexpat_stdlib.py`
  - `tests/test_providers/test_real_bridge_schemas.py`
  - `tests/test_providers/test_realcov_11_local_transformers_logic.py`
  - `tests/test_sandbox/test_realcov_12a_base_contract.py`
  - `tests/test_ui/log_viewer/test_handler.py`
  - `tests/test_ui/log_viewer/test_tail_reader.py`
  - `tests/test_ui/test_app_embedded_tools.py`
  - `tests/test_ui/test_async_bridge.py`
  - `tests/test_ui/test_graph_view.py`
  - `tests/test_ui/test_xpu_status.py`

### Agent 20 — 307 test functions across 18 files
- Findings: 0 Critical / 0 High / 2 Medium / 2 Low (4 total)
- Report: [`audit/agent-20.md`](agent-20.md)
- Partition files:
  - `tests/test_audit3/sandbox/test_kernel_object_monitor.py`
  - `tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py`
  - `tests/test_audit4/b3_threads_tab/test_realcov_14a_threads_tab.py`
  - `tests/test_audit5/u4_hexpat_aux/test_preprocessor_preserves_pragmas.py`
  - `tests/test_audit7/bridges_hex/test_utf16_scanner.py`
  - `tests/test_audit7/core_orchestration/test_tool_state_lifecycle.py`
  - `tests/test_audit7/sandbox_windows/test_launch_failure_detection.py`
  - `tests/test_bridges/test_hex_editor_top_audit1.py`
  - `tests/test_core/test_config_audit6.py`
  - `tests/test_core/test_realcov_07b_script_gen.py`
  - `tests/test_hexcore_e2e/test_bridge_error_handling.py`
  - `tests/test_hexcore_e2e/test_bridge_pattern_engine.py`
  - `tests/test_hexcore_e2e/test_hexpat_data_reader.py`
  - `tests/test_hexpat/test_compiler.py`
  - `tests/test_ui/test_realcov_15_dialog_helpers_logging.py`
  - `tests/test_ui/test_state_persistence.py`
  - `tests/test_ui/test_theme_manager.py`
  - `tests/test_ui/test_tool_panel_detach.py`

## Files with zero findings (125)

- `tests/core/test_process_cleanup.py`
- `tests/core/test_process_manager_leaks.py`
- `tests/test_audit3/bridges/test_installer.py`
- `tests/test_audit3/bridges/test_named_pipe_client.py`
- `tests/test_audit3/core/test_xml_gen.py`
- `tests/test_audit3/sandbox/test_injection_monitor.py`
- `tests/test_audit3/sandbox/test_service_monitor.py`
- `tests/test_audit3/ui/test_ghidra_panel.py`
- `tests/test_audit4/b1_process_panel_base/test_realcov_14a_panel_base.py`
- `tests/test_audit4/b6_system_tab/test_realcov_14a_system_tab.py`
- `tests/test_audit4/c11_hex_process_memory/test_bridge_route.py`
- `tests/test_audit4/c12_hex_sandbox_route/test_sandbox_route.py`
- `tests/test_audit4/c13_hex_patches_route/test_patches_bridge_route.py`
- `tests/test_audit4/c15_hex_comparison_tempfile/test_diff_temp_cleanup.py`
- `tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py`
- `tests/test_audit4/c2_hex_highlighting_route/test_realcov_13b_highlight_apply.py`
- `tests/test_audit4/c6_hex_hashing/test_realcov_13b_base_hashing.py`
- `tests/test_audit4/c7_hex_bookmarks_notify/test_bookmark_notify.py`
- `tests/test_audit4/c9_hex_disassembly_debounce/test_realcov_13a_calculator.py`
- `tests/test_audit4/c9_hex_disassembly_debounce/test_realcov_13a_sections.py`
- `tests/test_audit4/c9_hex_disassembly_debounce/test_realcov_13a_statistics.py`
- `tests/test_audit5/u3_hexpat_core/test_hexpat_core.py`
- `tests/test_audit5/u4_hexpat_aux/test_compiler_pragma_propagation.py`
- `tests/test_audit5/u4_hexpat_aux/test_parser_aggregate_errors.py`
- `tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py`
- `tests/test_audit5/u6_ui_tools/test_function_xref_population.py`
- `tests/test_audit5/u8_ui_config_paths/test_config_paths.py`
- `tests/test_audit5/u9_ui_confirmation/test_confirmation_dialog.py`
- `tests/test_audit7/config_pyproject/test_runtime_deps.py`
- `tests/test_audit7/core_orchestration/test_tag_chips_widget.py`
- `tests/test_audit7/providers_meta/test_discover_all_cache.py`
- `tests/test_audit7/sandbox_manager/test_eviction_deadlock.py`
- `tests/test_audit7/sandbox_qemu/test_anti_evasion_profile.py`
- `tests/test_audit7/sandbox_qemu/test_extract_dropped_files.py`
- `tests/test_audit7/sandbox_qemu/test_logs_stable.py`
- `tests/test_audit7/u12_hexpat_print_sink/test_bridge_print_sink.py`
- `tests/test_bridges/test_hex_editor_bottom_audit1.py`
- `tests/test_bridges/test_hex_state_audit1.py`
- `tests/test_bridges/test_parse_helpers.py`
- `tests/test_bridges/test_process_audit7.py`
- `tests/test_bridges/test_process_win32.py`
- `tests/test_bridges/test_realcov_01_hex_editor_pe_real.py`
- `tests/test_bridges/test_realcov_02a_x64dbg.py`
- `tests/test_bridges/test_realcov_03a_frida_modules.py`
- `tests/test_bridges/test_realcov_03b_ghidra.py`
- `tests/test_bridges/test_x64dbg_audit7_f0001.py`
- `tests/test_core/test_elevation.py`
- `tests/test_core/test_main.py`
- `tests/test_core/test_orchestrator.py`
- `tests/test_core/test_realcov_05b_process_manager.py`
- `tests/test_core/test_realcov_05b_tools.py`
- `tests/test_core/test_realcov_06_error_logging.py`
- `tests/test_core/test_realcov_06_logging_integration.py`
- `tests/test_core/test_realcov_06_optional_imports.py`
- `tests/test_core/test_realcov_06_subprocess_compat.py`
- `tests/test_core/test_realcov_06_types_exceptions.py`
- `tests/test_core/test_realcov_07a_yara_scanner.py`
- `tests/test_core/test_realcov_07b_template_manager.py`
- `tests/test_core/test_tools.py`
- `tests/test_core/test_tools_audit6.py`
- `tests/test_credentials/test_realcov_15_store_api.py`
- `tests/test_hexcore_e2e/test_bridge_block_ops.py`
- `tests/test_hexcore_e2e/test_bridge_concurrent.py`
- `tests/test_hexcore_e2e/test_bridge_disassembly.py`
- `tests/test_hexcore_e2e/test_bridge_encoding_decoding.py`
- `tests/test_hexcore_e2e/test_bridge_hash_advanced.py`
- `tests/test_hexcore_e2e/test_bridge_html_export_largefile.py`
- `tests/test_hexcore_e2e/test_bridge_pe_introspection.py`
- `tests/test_hexcore_e2e/test_bridge_scripting.py`
- `tests/test_hexcore_e2e/test_bridge_search.py`
- `tests/test_hexcore_e2e/test_bridge_signatures.py`
- `tests/test_hexcore_e2e/test_bridge_state_integration.py`
- `tests/test_hexcore_e2e/test_bridge_structure_bookmarks.py`
- `tests/test_hexcore_e2e/test_bridge_yara.py`
- `tests/test_hexcore_e2e/test_data_inspector.py`
- `tests/test_hexcore_e2e/test_hexpat_complex_patterns.py`
- `tests/test_hexcore_e2e/test_hexpat_parser_e2e.py`
- `tests/test_hexcore_e2e/test_hexpat_pattern_registry.py`
- `tests/test_hexcore_e2e/test_hexpat_preprocessor.py`
- `tests/test_hexcore_e2e/test_patch_export.py`
- `tests/test_hexcore_e2e/test_process_memory.py`
- `tests/test_hexcore_e2e/test_realcov_09a_evaluator_realdata.py`
- `tests/test_hexcore_e2e/test_realcov_09b_typesystem_completer.py`
- `tests/test_hexcore_e2e/test_templates.py`
- `tests/test_hexpat/test_interpreter.py`
- `tests/test_hexpat/test_realcov_07b_compiler_pragmas.py`
- `tests/test_hexpat/test_realcov_08_lexer_escapes.py`
- `tests/test_hexpat/test_realcov_08_parser_unit.py`
- `tests/test_hexpat/test_realcov_08_vendor_patterns.py`
- `tests/test_providers/test_anthropic_buffers_live.py`
- `tests/test_providers/test_grok_provider.py`
- `tests/test_providers/test_huggingface_chat_live.py`
- `tests/test_providers/test_model_discovery.py`
- `tests/test_providers/test_openrouter_provider.py`
- `tests/test_providers/test_parse_openai_format_tool_calls.py`
- `tests/test_providers/test_provider_loop_rebind.py`
- `tests/test_providers/test_realcov_10_cancel_request.py`
- `tests/test_providers/test_realcov_10_discovery_extra.py`
- `tests/test_providers/test_realcov_10_grok_reasoning_effort.py`
- `tests/test_providers/test_realcov_11_gpu_pci.py`
- `tests/test_providers/test_realcov_11_huggingface_logic.py`
- `tests/test_providers/test_realcov_11_xpu_utils.py`
- `tests/test_providers/test_registry.py`
- `tests/test_providers/test_tool_call_buffer.py`
- `tests/test_providers/test_tool_schema_builders.py`
- `tests/test_sandbox/test_base_types.py`
- `tests/test_sandbox/test_log_helpers.py`
- `tests/test_sandbox/test_manager.py`
- `tests/test_sandbox/test_realcov_12b_analysis_real.py`
- `tests/test_ui/log_viewer/test_window.py`
- `tests/test_ui/test_dialogs.py`
- `tests/test_ui/test_overflow_toolbar.py`
- `tests/test_ui/test_panel_dock.py`
- `tests/test_ui/test_realcov_13b_hex_statistics.py`
- `tests/test_ui/test_realcov_13b_hex_yara.py`
- `tests/test_ui/test_realcov_14b_analysis_panel.py`
- `tests/test_ui/test_realcov_14b_cutter_tabs.py`
- `tests/test_ui/test_realcov_14b_graph_view.py`
- `tests/test_ui/test_realcov_14b_panel_support.py`
- `tests/test_ui/test_realcov_14b_sandbox_report.py`
- `tests/test_ui/test_realcov_15_session_manager_dialog.py`
- `tests/test_ui/test_sandbox_panel_fixes.py`
- `tests/test_ui/test_search_async.py`
- `tests/test_ui/test_vnc_widget.py`
- `tests/test_ui/test_win32_embed.py`
