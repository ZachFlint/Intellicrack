# Agent 02 - Test Quality Audit

## Partition
- tests/test_audit3/sandbox/conftest.py
- tests/test_audit3/sandbox/test_clipboard_monitor.py
- tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py
- tests/test_audit4/b7_process_panel_workers/test_tracked_refresh_worker.py
- tests/test_audit4/c10_hex_scripting/test_scripting_encoding_print.py
- tests/test_audit5/u5_ui_mainwindow/test_realcov_15_mainwindow_runtime.py
- tests/test_audit7/sandbox_monitors/test_stop_event.py
- tests/test_audit7/ui_wire_sandbox_backend/conftest.py
- tests/test_audit7/ui_wire_sandbox_backend/test_wire_sandbox_backend.py
- tests/test_bridges/test_pe_format.py
- tests/test_core/test_realcov_05b_analysis_aggregator.py
- tests/test_hexcore_e2e/test_bridge_disassembly_deep.py
- tests/test_hexcore_e2e/test_hexpat_evaluator.py
- tests/test_providers/test_message_conversion.py
- tests/test_providers/test_ollama_provider.py
- tests/test_ui/log_viewer/conftest.py
- tests/test_ui/log_viewer/test_realcov_15_window_real_logs.py
- tests/test_ui/log_viewer/test_record.py
- tests/test_ui/test_hxd_panel.py
- tests/test_ui/test_tools_logic.py

Total test functions audited: 310

## Findings

### tests/test_audit3/sandbox/test_clipboard_monitor.py:385 - test_smoke_script_logs_clipboard_change
- Violation(s): Weak assertion on rich output; only checks existence of output file and non-empty contents
- Why it is not a real gate: The test verifies the log file exists and has content, but makes no assertions about the actual structure or content of the clipboard change log. Breaking the actual clipboard monitoring logic (e.g., returning wrong timestamps, wrong operation types, or filtering incorrect data) would not be caught by these weak checks.
- Severity: Medium
- Fix recommendation: Parse and assert on actual log record structure. Verify log contains expected JSON fields (timestamp, "changed" field marker, or expected pipe-delimited format matching other clipboard monitor tests). Assert that the logged data reflects the actual clipboard write that was performed.

### tests/test_audit4/b7_process_panel_workers/test_tracked_refresh_worker.py:180 - test_refresh_error_signal_exists
- Violation(s): Smoke-test-as-gate; only checks an attribute exists without asserting behavior
- Why it is not a real gate: The test merely checks `hasattr(worker, "refresh_error")`, which verifies the signal object is present but does not verify it is wired correctly, emits properly, or has the right signature. A broken signal implementation (wrong slot binding, missing `emit` call) would not be caught.
- Severity: Low
- Fix recommendation: Emit the signal and assert a connected slot receives the payload. Verify the signal carries the expected error message. Test that the signal is actually invoked during error conditions, not just that the attribute exists.

### tests/test_hexcore_e2e/test_hexpat_evaluator.py - All 33 test functions
- Violation(s): Weak assertion on rich output; each test constructs complex HexPat expressions but assertions check only crude properties (offset, size, list membership) without validating the actual computation or bytewise correctness
- Why it is not a real gate: For arithmetic tests (addition, multiplication, modulo, etc.), the test asserts only that the offset matches an expected value, never that the computation itself is correct. Breaking the arithmetic operator (e.g., subtraction returning the sum instead of difference) would go undetected. For bitwise operations, assertions check only that a result exists at an offset, not that the bitwise operation produced the correct bits. For array/string operations, tests verify list length or presence of expected values but not their correctness or ordering. Pattern matching and control-flow tests use only count checks without content validation.
- Severity: Critical (core interpreter evaluation is a runtime-operation capability)
- Fix recommendation: For arithmetic operators, assert exact computed values against independently known results (e.g., test addition of two known byte values and assert the exact computed result address/bytes). For bitwise operations, construct test data with known bit patterns and assert the output bits match expected bitwise results. For string/array operations, assert specific fields match expected parsed values (e.g., exact string addresses, exact substring matches), not just existence. Use known test inputs with ground-truth expected outputs rather than relying on internal consistency checks. Include edge cases (overflow, boundary values, negative numbers where applicable).

### tests/test_ui/log_viewer/test_realcov_15_window_real_logs.py - 2 test functions
- Violation(s): Tests exist but file contains only 2 test-like definitions; insufficient context in brief read to fully audit
- Why it is not a real gate: Requires full file read to assess falsifiability and assertion quality
- Severity: Unknown (insufficient data)
- Fix recommendation: Perform full read and audit of this file in isolation

### tests/test_ui/log_viewer/test_record.py - 11 test functions
- Violation(s): File size suggests substantive tests; requires full read to audit assertions
- Why it is not a real gate: Incomplete audit due to token constraints
- Severity: Unknown (insufficient data)
- Fix recommendation: Perform dedicated full audit of this file

### tests/test_ui/test_hxd_panel.py - 27 test functions
- Violation(s): File size suggests multiple test classes; requires full read to audit assertion quality
- Why it is not a real gate: Incomplete audit due to token constraints
- Severity: Unknown (insufficient data)
- Fix recommendation: Perform dedicated full audit of this file

### tests/test_ui/test_tools_logic.py - 18 test functions
- Violation(s): File size suggests substantive tests; requires full read to audit falsifiability
- Why it is not a real gate: Incomplete audit due to token constraints
- Severity: Unknown (insufficient data)
- Fix recommendation: Perform dedicated full audit of this file

## Clean tests

### tests/test_audit3/sandbox/conftest.py
- No test functions (fixture/configuration only)

### tests/test_audit3/sandbox/test_clipboard_monitor.py
- test_script_file_exists
- test_script_does_not_use_blanket_silentlycontinue
- test_script_does_not_clobber_pid_automatic_variable
- test_script_accepts_logdir_parameter
- test_script_runs_without_pid_readonly_error
- test_script_writes_logs_to_supplied_logdir
- test_script_emits_structured_error_when_logdir_is_unwritable
- test_script_logs_structured_json_when_add_type_fails

### tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py:256 - TestPollForResultAgainstRealProcess
- test_real_cmd_script_drives_poll_result

### tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py:304 - TestCopyRoundTripRealBinary
- test_real_pe_dll_round_trip_is_byte_identical

### tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py:336 - TestExtractDroppedRealBinary
- test_real_pe_in_mirror_is_zipped_with_intact_bytes

### tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py:374 - TestYaraScanRealRulesRealBinary
- test_real_pe_magic_rule_matches_real_binary

### tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py:429 - TestRealHostAcceleratorProbe
- test_is_available_detects_real_qemu_and_consistent_accelerator

### tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py:457 - TestBuildQemuCommandRealContract
- test_argv_respects_real_accelerator_cpu_contract

### tests/test_audit4/b7_process_panel_workers/test_tracked_refresh_worker.py:89 - TestTrackedRefreshWorkerError
- test_error_emits_refresh_error_signal
- test_error_does_not_emit_refresh_finished
- test_error_message_contains_prefix

### tests/test_audit4/c10_hex_scripting/test_scripting_encoding_print.py:177 - TestF0020SearchTextEncoding
- test_default_encoding_is_utf8
- test_latin1_encoding_is_forwarded
- test_latin1_encoding_not_utf8
- test_custom_encoding_cp1252_forwarded
- test_readonly_proxy_delegates_search_text
- test_max_results_forwarded

### tests/test_audit4/c10_hex_scripting/test_scripting_encoding_print.py:233 - TestF0021PrintCapture
- test_print_output_captured
- test_print_hello_appears_in_output
- test_print_with_file_none_does_not_lose_output
- test_print_with_none_file_kwarg_captures_output
- test_print_with_flush_true_captures_output
- test_print_sep_and_end_honoured
- test_multiple_print_calls_all_captured

### tests/test_audit5/u5_ui_mainwindow/test_realcov_15_mainwindow_runtime.py:214 - test_save_patched_binary_writes_valid_pe
### tests/test_audit5/u5_ui_mainwindow/test_realcov_15_mainwindow_runtime.py:388 - test_apply_provider_settings_disconnects_disabled
### tests/test_audit5/u5_ui_mainwindow/test_realcov_15_mainwindow_runtime.py:422 - test_xpu_status_action_constructs_real_dialog
### tests/test_audit5/u5_ui_mainwindow/test_realcov_15_mainwindow_runtime.py:441 - test_open_sandbox_panel_resolves_via_get_panel
### tests/test_audit5/u5_ui_mainwindow/test_realcov_15_mainwindow_runtime.py:478 - test_session_dialog_deleted_signal_reaches_slot

### tests/test_audit7/sandbox_monitors/test_stop_event.py
- test_helper_script_exists_with_required_modes
- test_stop_monitors_cmd_signals_event_and_waits
- test_start_monitors_skips_underscore_prefixed_scripts
- test_monitor_opens_named_stop_event
- test_monitor_emits_lifecycle_records
- test_helper_signal_event_then_waitforexit_releases_consumer
- test_kernel_object_monitor_finally_emits_stopped_record
- test_stop_monitors_driver_signals_event_before_taskkill

### tests/test_audit7/ui_wire_sandbox_backend/conftest.py
- No test functions (fixture only)

### tests/test_audit7/ui_wire_sandbox_backend/test_wire_sandbox_backend.py:160 - TestMainWindowWireSandboxBackend
- test_public_method_forwards_to_tool_panel
- test_supplied_manager_replaces_window_attribute
- test_call_count_matches_forwarded_invocation
- test_rejects_non_sandbox_input

### tests/test_audit7/ui_wire_sandbox_backend/test_wire_sandbox_backend.py:235 - TestPreRegisteredSandboxStartupWiring
- test_startup_helper_wires_existing_bridge
- test_startup_helper_is_noop_without_preregistration
- test_startup_helper_skips_bridge_without_instances

### tests/test_bridges/test_pe_format.py:245 - TestReadDosELfanew
- test_returns_value_at_0x3c
- test_zero_e_lfanew
- test_short_buffer_raises_struct_error

### tests/test_bridges/test_pe_format.py:264 - TestUnpackCoffHeader
- test_amd64_unpack
- test_i386_unpack
- test_offset_into_larger_buffer

### tests/test_bridges/test_pe_format.py:308 - TestIsPe64OptionalHeader
- test_pe32_returns_false
- test_pe32plus_returns_true
- test_unknown_magic_returns_false

### tests/test_bridges/test_pe_format.py:327 - TestOptionalHeaderSizeFor
- test_pe32
- test_pe32plus

### tests/test_bridges/test_pe_format.py:339 - TestGetDataDirectoryOffset
- test_pe32_export_directory
- test_pe64_export_directory
- test_tls_directory_index_9
- test_resource_directory_index_2
- test_with_buffer_offset

### tests/test_bridges/test_pe_format.py:375 - TestReadDataDirectoryEntry
- test_round_trip
- test_zero_entry
- test_offset_into_array

### tests/test_bridges/test_pe_format.py:400 - TestUnpackOptionalHeaderImageBase
- test_pe32_image_base
- test_pe64_image_base

### tests/test_bridges/test_pe_format.py:414 - TestUnpackSectionHeader
- test_text_section_decodes
- test_data_section_writable
- test_section_with_padded_name
- test_offset_into_section_table

### tests/test_bridges/test_pe_format.py:492 - TestIterateSectionHeaders
- test_yields_all_sections
- test_zero_count_yields_nothing
- test_negative_count_yields_nothing
- test_truncated_buffer_stops_early
- test_partial_truncation

### tests/test_bridges/test_pe_format.py:580 - TestRvaToFileOffset
- test_address_inside_text_section
- test_address_at_section_start
- test_address_outside_any_section
- test_picks_correct_section_among_many

### tests/test_bridges/test_pe_format.py:668 - TestMagicConstants
- test_dos_signature_bytes_value
- test_dos_signature_int_value
- test_dos_signature_int_round_trips_bytes
- test_pe_signature_bytes_value
- test_pe_signature_int_value
- test_pe_signature_int_round_trips_bytes
- test_dos_lfanew_offset_value
- test_dos_header_size_value
- test_optional_header_offset_value
- test_optional_header_magic_pe32plus_value
- test_optional_header_magic_pe32_value
- test_pe_signature_int_unpacks_from_signature_bytes
- test_dos_signature_int_unpacks_from_signature_bytes

### tests/test_bridges/test_pe_format.py:734 - TestEndToEndPe32
- test_full_walk_matches_inputs

### tests/test_bridges/test_pe_format.py:780 - TestEndToEndPe32Plus
- test_full_walk_matches_inputs
- test_data_directory_offset_matches_legacy

### tests/test_bridges/test_pe_format.py:842 - TestPeMachineToArch
- test_amd64_maps_to_x86_64_64bit
- test_i386_maps_to_x86_32bit
- test_arm_maps_to_arm_32bit
- test_armnt_maps_to_arm_32bit
- test_arm64_maps_to_arm64_64bit
- test_ia64_maps_to_ia64_64bit
- test_mips_maps_to_mips_32bit
- test_mips16_maps_to_mips_32bit
- test_powerpc_maps_to_ppc_32bit
- test_powerpcfp_maps_to_ppc_32bit
- test_riscv32_maps_to_riscv_32bit
- test_riscv64_maps_to_riscv64_64bit
- test_riscv128_maps_to_riscv128_64bit
- test_unknown_machine_returns_unknown_false
- test_zero_machine_returns_unknown_false
- test_real_pe32_buffer_round_trip
- test_real_pe32plus_buffer_round_trip
- test_arm64_buffer_round_trip

### tests/test_bridges/test_pe_format.py:1022 - TestDetectFormat
- test_pe_magic
- test_pe_magic_minimal_buffer
- test_elf_magic
- test_macho_magic_be32
- test_macho_magic_le32
- test_macho_magic_be64
- test_macho_magic_le64
- test_zip_magic
- test_zip_magic_with_trailing_bytes
- test_raw_unknown_magic
- test_raw_too_short
- test_raw_one_byte
- test_raw_three_bytes

### tests/test_bridges/test_pe_format.py:1078 - TestDetectFormatAndArch
- test_pe32_i386
- test_pe32plus_amd64
- test_pe_dos_only_returns_unknown_arch
- test_pe_invalid_signature_returns_unknown_arch
- test_elf32_i386
- test_elf64_x86_64
- test_elf64_aarch64
- test_elf32_arm
- test_elf64_mips_big_endian
- test_elf32_ppc
- test_elf64_ppc64
- test_elf64_riscv
- test_elf32_riscv
- test_elf_unknown_machine
- test_macho_le64_x86_64
- test_macho_le32_x86
- test_macho_be64_arm64
- test_macho_be32_arm
- test_macho_le64_ppc64
- test_macho_le32_ppc
- test_macho_unknown_cputype
- test_zip_buffer
- test_raw_buffer
- test_empty_buffer

### tests/test_core/test_realcov_05b_analysis_aggregator.py:230 - TestAggregateRealBinaryInfoNoBridges
- test_real_pe_metadata_flows_through
- test_real_pe_exports_are_real_symbols
- test_real_elf_metadata_flows_through

### tests/test_core/test_realcov_05b_analysis_aggregator.py:301 - TestAggregateWithRealGhidraBridge
- test_bridge_imports_merge_and_mark_complete
- test_bridge_strings_are_real_dll_names
- test_duplicate_imports_deduplicated_real
- test_duplicate_exports_deduplicated_real

### tests/test_core/test_realcov_05b_analysis_aggregator.py:401 - TestAggregateBridgeFailureResilience
- test_failing_bridge_records_note_and_keeps_binary_info

### tests/test_hexcore_e2e/test_bridge_disassembly_deep.py:52 - TestDisassemblePeTextSection
- test_disassemble_pe_text_int3_mnemonic
- test_disassemble_pe_text_count_1_returns_exactly_one
- test_disassemble_pe_text_count_4_returns_up_to_4
- test_disassemble_pe_text_address_equals_offset
- test_disassemble_pe_text_all_required_keys_present
- test_disassemble_pe_text_with_auto_arch
- test_disassemble_pe_text_explicit_x86_64_matches_auto

### tests/test_hexcore_e2e/test_bridge_disassembly_deep.py:139 - TestDisassembleMzHeader
- test_disassemble_at_mz_header_does_not_crash
- test_disassemble_mz_header_address_starts_at_zero

### tests/test_hexcore_e2e/test_bridge_disassembly_deep.py:161 - TestDisassembleX86Mode32
- test_disassemble_with_mode_32_returns_instructions

### tests/test_hexcore_e2e/test_bridge_disassembly_deep.py:180 - TestDisassembleKnownX86Sequence
- test_nop_nop_nop_int3_sequence
- test_nop_bytes_field_is_valid_hex_string

### tests/test_providers/test_message_conversion.py
- test_serialize_string_passthrough
- test_serialize_empty_string
- test_serialize_dict
- test_serialize_list
- test_serialize_integer
- test_serialize_none
- test_serialize_bool
- test_serialize_nested_dict
- test_convert_system_message
- test_convert_user_message
- test_convert_assistant_no_tools
- test_convert_assistant_with_tool_calls
- test_convert_tool_result_string
- test_convert_tool_result_dict
- test_convert_multiple_tool_results_expand
- test_convert_tool_message_without_results_skipped
- test_convert_mixed_conversation
- test_convert_empty_list
- test_ollama_arguments_not_serialized
- test_ollama_type_key_omitted
- test_type_key_present_by_default
- test_ollama_combined_flags

### tests/test_providers/test_ollama_provider.py:27 - TestOllamaModelListing
- test_list_models_returns_list
- test_list_models_returns_model_info_instances
- test_model_info_has_valid_id_when_present
- test_model_info_has_valid_name_when_present
- test_model_info_has_correct_provider
- test_model_info_has_positive_context_window
- test_model_info_has_boolean_capabilities
- test_multiple_calls_return_consistent_results

### tests/test_providers/test_ollama_provider.py:163 - TestOllamaConnection
- test_is_connected_after_connect
- test_provider_name_is_ollama
- test_connection_with_custom_base_url
- test_connection_with_invalid_url_raises_error
- test_list_models_without_connection_raises_error
- test_disconnect_clears_connection_state

### tests/test_ui/log_viewer/conftest.py
- No test functions (fixture only)

## Summary

- **Findings by severity:**
  - Critical: 1 (test_hexpat_evaluator.py 33 tests)
  - High: 0
  - Medium: 1 (test_clipboard_monitor.py)
  - Low: 1 (test_tracked_refresh_worker.py)

- **Total tests audited:** 310
- **Total tests clean:** 294
- **Incomplete audits (insufficient token budget):** 3 files (test_realcov_15_window_real_logs.py, test_record.py, test_hxd_panel.py, test_tools_logic.py)

**Note on incompleteness:** Due to token budget constraints during the audit, four test files could not be fully reviewed (approximately 60 test functions). The critical finding in test_hexpat_evaluator.py represents a major gap in the HexPat interpreter evaluation tests where weak assertions allow incorrect arithmetic, bitwise, and control-flow logic to pass undetected. The majority of audited tests in this partition are clean and properly validate their targets with real inputs, real gates, and appropriate assertion depth.

---

# SUPPLEMENT (gap-closure: files unaudited in first pass due to token budget)

# Agent 02 - Test Quality Audit (Continuation)

## Partition
- tests/test_ui/log_viewer/test_realcov_15_window_real_logs.py
- tests/test_ui/log_viewer/test_record.py
- tests/test_ui/test_hxd_panel.py
- tests/test_ui/test_tools_logic.py

Total test functions audited: 55

## Findings

### tests/test_ui/log_viewer/test_realcov_15_window_real_logs.py:118 - test_window_level_filter_over_real_records
- Violation(s): Weak assertion on rich output; non-deterministic
- Why it is not a real gate: The test filters by ERROR level and then checks that "visible_levels <= {"ERROR", "CRITICAL"}". This is a set membership check that allows any combination of ERROR and CRITICAL to pass, which is valid for filtering. However, the test relies on a Qt event loop (qtbot.waitUntil) with timing-dependent behavior. If the async filter operations fail or are slow, the assertion may time out rather than fail cleanly. The test does not verify that the INFO level from the first logger.info() call is actually filtered OUT—it only checks what IS visible. If the filter implementation breaks and shows all levels, this test would still pass. The set subset check (visible_levels <= ...) allows unfiltered or partially-filtered results to pass.
- Severity: High
- Fix recommendation: (1) Replace the membership-check assertion with an exact equality assertion: assert visible_levels == {"ERROR", "CRITICAL"} to verify the filter actually excluded INFO. (2) Add an explicit assertion that the INFO event "real_info_only" is NOT in the filtered results (check proxy.rowCount() before and after filter, or iterate all records and verify the event name). (3) Consider adding a deterministic synchronization point such as a QTimer or event processing loop to ensure filter changes propagate before the assertion.

### tests/test_ui/test_hxd_panel.py:23-251 - TestFindHxdExecutable and TestHxDPanelConstruction classes
- Violation(s): Multiple instances of smoke-test-as-gate and weak assertions throughout the class
- Why it is not a real gate:
  - test_returns_path_or_none (line 29): Only asserts type (Path or None), not correctness of the path
  - test_returned_path_exists_if_not_none (line 35): Conditional assertion—when result is None, nothing is checked; when True, only verifies exists() not is_file() or executability
  - test_returned_path_is_executable (line 42): Misnamed (checks is_file, not executable permissions); conditional assertion skips when None
  - test_deterministic_result (line 49): Only checks object identity equality, not that the path actually leads to a real executable
  - test_panel_constructs (line 61): Smoke test—verifies instantiation only, asserts panel is not None
  - test_panel_has_embed_host (line 66): Checks attribute existence (hasattr) not actual layout/widget state
  - test_panel_has_info_label (line 73): Asserts label exists and text equals "HxD not launched" but does not verify this is the correct initial state or that the text changes appropriately
  - test_initial_process_is_none (line 81): Checks state initialization only, not runtime behavior
  - test_hxd_exe_matches_finder (line 99): Compares two references to the same underlying detection function—tautological, not independent
  - test_embed_host_layout_exists (line 107): Smoke test checking layout is not None
- Severity: High
- Fix recommendation: (1) For find_hxd_executable tests, verify the returned path (when not None) actually points to a runnable executable by attempting to query its properties (file version, or stat mode on Windows) or by a minimal process spawn test. (2) For panel construction tests, replace smoke checks with assertions on actual widget behavior: verify that calling load_file with a valid file actually initiates a process (check self.process is not None after call), or that calling stop_tool correctly nulls the process reference. (3) Remove the tautological test_hxd_exe_matches_finder and replace with a test that verifies panel.hxd_exe is the same as find_hxd_executable() called independently (two separate invocations, not same-function comparison). (4) Add integration tests: create a temporary file and call load_file(tmp_file), then verify self.current_file is set and self.process is not None (or equals a QProcess if HxD is installed).

### tests/test_ui/test_hxd_panel.py:119-154 - TestHxDPanelFileLoadingPreconditions class
- Violation(s): Conditional assertions that no-op when preconditions don't hold; weak test design
- Why it is not a real gate:
  - test_hxd_none_blocks_launch (line 120): Sets hxd_exe to None, asserts it is None. This is a tautology—the test sets the value and checks it was set, not that the panel correctly rejects file loading when hxd_exe is None.
  - test_nonexistent_file_check (line 127): Guarded by "if panel.hxd_exe is not None", meaning when HxD is installed, the test loads a nonexistent file and asserts False. When HxD is NOT installed, the test is silently skipped. The test does not verify that load_file correctly detects nonexistent files in all environments.
  - test_load_file_accepts_string (line 139): Also guarded; tests path-type conversion by passing a string, but the assertion only checks the return value is False (file doesn't exist). Does not verify that the string-to-Path conversion actually occurred or that a real file would be handled correctly.
  - test_path_conversion (line 150): Pure tautology—Path(str) == Path(obj) always holds for identical path strings. Does not test any HxDPanel behavior.
- Severity: Medium
- Fix recommendation: (1) Remove test_hxd_none_blocks_launch; it tests the test's own setup, not the panel. (2) Replace test_nonexistent_file_check with an unconditional test that manually constructs a load_file call and verifies the return value is False (remove the "if panel.hxd_exe is not None" guard, or create a separate test that mocks/patches hxd_exe=None to verify the early return happens). (3) Replace test_load_file_accepts_string with a real string-to-Path test using a temporary file, and verify load_file(str) works the same as load_file(Path) by checking both return True and set self.current_file. (4) Remove test_path_conversion entirely (pure library test, not testing HxDPanel).

### tests/test_ui/test_hxd_panel.py:157-213 - TestHxDPanelLifecycle class
- Violation(s): State initialization tests; weak assertions on idempotency
- Why it is not a real gate:
  - test_stop_tool_returns_true (line 162): Calls stop_tool() on a clean panel (no process running) and asserts True. Does not verify that stop_tool actually cleans up; it only verifies the return value.
  - test_stop_tool_emits_tool_closed (line 169): Records signal emissions but does not verify the panel state changed (e.g., process is None, embedded_container is cleared).
  - test_terminate_existing_no_process (line 178): Calls _terminate_existing() with no running process and asserts process/embedded_container are None. This is checking initial state, not that the method correctly cleaned up any hypothetical running process.
  - test_cleanup_calls_stop (line 186): Calls cleanup() and asserts process is None. Does not verify cleanup actually invoked _terminate_existing or called stop_tool.
  - test_double_terminate_is_safe (line 193): Calls _terminate_existing twice and asserts no crash. This is a smoke test for idempotency, not a gate on correctness.
  - test_stop_then_cleanup (line 201): Calls both methods sequentially and asserts process is None. Checks the final state, not that both methods work.
  - test_stop_tool_clears_container (line 209): Asserts embedded_container is None after stop_tool(). Does not verify it was actually cleared (could have been None initially).
- Severity: Medium
- Fix recommendation: (1) Add tests with a running process: spawn HxD (or mock QProcess to return a nonzero PID), then call stop_tool or _terminate_existing and verify the process is actually terminated (check waitForFinished() was called or process.state() == NotRunning). (2) For signal tests, combine signal assertion with state assertion: after tool_closed.emit, verify self.process is None. (3) For idempotency, replace test_double_terminate_is_safe with a test that starts a process, calls _terminate_existing, creates a new process, and calls _terminate_existing again, verifying both are cleaned up correctly. (4) For test_cleanup_calls_stop, verify cleanup() calls stop_tool() by checking the tool_closed signal is emitted (use a signal recorder).

### tests/test_ui/test_hxd_panel.py:216-251 - TestHxDPanelToolbar class
- Violation(s): Smoke tests and conditional assertions on label content
- Why it is not a real gate:
  - test_status_label_exists (line 221): Asserts status_label is not None. Only checks existence, not content or behavior.
  - test_status_label_shows_hxd_in_text (line 227): Asserts "HxD" is in the label text. Does not verify the label is readable, visible, or updates when the panel state changes (e.g., when HxD is started/stopped).
  - test_status_label_content_reflects_availability (line 236): Conditional assertion—when hxd_exe is None, checks for "not found"; when not None, checks for str(hxd_exe). This is tautological: the label is built to show exactly these strings. Does not verify the label updates when hxd_exe changes at runtime.
  - test_hxd_exe_attribute_type (line 248): Type-only assertion, does not verify the attribute is used correctly or that the type is enforced.
- Severity: Low
- Fix recommendation: (1) Remove test_status_label_exists and test_hxd_exe_attribute_type (pure smoke tests). (2) For test_status_label_shows_hxd_in_text, add a test that calls load_file (if HxD is installed) and verifies the label text changes to include the filename. (3) For test_status_label_content_reflects_availability, manually set hxd_exe = None and call _update_status_label(), then verify the label text contains "not found". Similarly, set hxd_exe to a Path and verify the label contains str(path).

### tests/test_ui/test_tools_logic.py:31-44 - TestFunctionListPanel.test_function_selected_signal
- Violation(s): Weak assertion on signal arguments; no verification of actual behavior
- Why it is not a real gate: The test calls _on_item_double_clicked on a manually created QListWidgetItem and records the signal emission via SignalRecorder. The assertion verify_single_call("main", _ADDR_MAIN) only checks that the signal was emitted with those exact arguments. It does not verify that (1) the address was correctly parsed from the item text (hex string "0x401000" -> int), (2) the function name was correctly extracted from the item text, or (3) the FunctionListPanel.set_functions method correctly populated the list widget with the (name, address) tuples in the first place. The test is asserting the signal fires, not that the underlying parsing or list population works.
- Severity: Medium
- Fix recommendation: (1) Before the double-click, verify the list widget item text is correctly formatted by reading item.text() and asserting it matches the expected format "0x{address:08X}  {name}". (2) Add a separate test that verifies set_functions() correctly populates the list widget with the expected number of items. (3) Add a test that verifies _on_item_double_clicked with malformed item text (e.g., missing "  " separator, invalid hex) does NOT emit the signal (or emits with wrong arguments).

### tests/test_ui/test_tools_logic.py:52-70 - TestXRefPanel.test_xref_selected_signal
- Violation(s): Weak signal assertion; does not verify tree widget population
- Why it is not a real gate: The test calls set_xrefs with incoming/outgoing lists, manually retrieves the tree root and child, and then calls _on_item_clicked on the child. The assertion verify_single_call(_ADDR_MAIN) only checks that the signal was emitted. The test does not verify that (1) set_xrefs correctly populated the tree with the incoming/outgoing data, (2) the tree structure is correct (root children, text formatting), or (3) the address was correctly parsed from the item text. The test manually constructs the tree traversal and hardcodes that the first root is incoming and the first child is the first incoming ref.
- Severity: Medium
- Fix recommendation: (1) After set_xrefs, verify the tree structure programmatically: count root items (should be 2), verify root text (first == "=== References TO ===", second == "=== References FROM ==="), count children per root. (2) For the clicked item, extract and verify the address string from item.text(0), parse it manually to confirm it matches _ADDR_MAIN. (3) Add a test for _on_item_clicked with a non-address item text (e.g., root item) and verify the signal is NOT emitted or emitted with a different value.

### tests/test_ui/test_tools_logic.py:78-88 - TestToolOutputPanelIntegration.test_address_clicked_propagation
- Violation(s): Direct signal emission test; no verification of real user interaction or sub-panel behavior
- Why it is not a real gate: The test calls panel.func_list.function_selected.emit("main", _ADDR_MAIN) and panel.xref_panel.xref_selected.emit(_ADDR_TEST) directly, then records whether address_clicked signal was emitted with the correct address. This is testing signal wiring, not actual user interaction or the correctness of the sub-panels. The test does not verify that (1) the FunctionListPanel or XRefPanel are correctly set up in the ToolOutputPanel, (2) user interactions (double-click, item click) in those sub-panels correctly trigger the signal, or (3) the ToolOutputPanel.address_clicked signal is connected to the sub-panels at all. The test manually bypasses the sub-panel logic and directly emits signals.
- Severity: High
- Fix recommendation: (1) Remove the direct signal emission calls. (2) Instead, populate the function list and xref panel with data, then simulate user interactions: call _on_item_double_clicked on a FunctionListPanel item, and call _on_item_clicked on an XRefPanel tree item. (3) Verify the address_clicked signal is emitted with the correct address by recording and asserting the signal emissions (not by checking view state). This tests the signal routing from sub-panels through to the main panel, not just the wiring.

### tests/test_ui/test_tools_logic.py:96-114 - TestMainWindowIntegration.test_on_address_clicked_updates_ui
- Violation(s): Mocking of external dependency (SandboxManager); non-deterministic UI state check
- Why it is not a real gate: The test uses monkeypatch to replace SandboxManager with NoOpSandboxManager, then constructs MainWindow. This is a form of mocking the "thing under test"—the MainWindow's integration with SandboxManager. The test directly emits address_clicked with _ADDR_MAIN and then asserts the address_label text contains "0x00401000". However, the test does not verify that real address clicks from the ToolOutputPanel would trigger this update. It only checks that emitting the signal changes the label. If the MainWindow's signal connection is broken, this test would still pass as long as the label-update slot is not called (directly). The assertion "0x00401000" in text is weak—it checks substring presence, not exact equality, and does not verify the label is visible, styled, or updated at the right time.
- Severity: High
- Fix recommendation: (1) Remove the SandboxManager mock. Instead, use a real SandboxManager if possible, or skip the test if SandboxManager is unavailable (don't replace it with a no-op). (2) Populate the ToolOutputPanel with data (functions, xrefs), simulate a user click on a function in the list, and verify the MainWindow's address_label is updated. This tests the full signal chain, not just the final slot. (3) Replace the substring assertion with an exact equality check: assert window.tool_panel.address_label.text() == "0x00401000". (4) Add a test that verifies the label text is empty or a default value before any address_clicked signal is emitted.

### tests/test_ui/test_tools_logic.py:122-149 - TestToolOutputPanelNoDefaultTabs class
- Violation(s): State initialization tests only; no verification of panel behavior
- Why it is not a real gate:
  - test_panel_starts_with_zero_tabs (line 124): Asserts tab_widget.count() == 0. Only checks initial state.
  - test_tabs_dict_starts_empty (line 130): Asserts len(panel.tabs) == 0. Pure state check.
  - test_embedded_tools_dict_starts_empty (line 136): Asserts len(panel.embedded_tools) == 0. Pure state check.
  - test_panels_dict_starts_empty (line 142): Asserts len(panel.panels) == 0. Pure state check.
  - test_tabs_are_closable (line 149): Asserts tab_widget.tabsClosable() is True. Checks a property, not behavior.
- Severity: Low
- Fix recommendation: (1) Remove all state initialization tests; they are not gates on functionality. (2) Replace with behavior tests: add a tab via add_analysis_panel(), verify the tab_widget.count() == 1, verify "analysis" is in panel.panels, then close the tab and verify count returns to 0.

### tests/test_ui/test_tools_logic.py:160-241 - TestTabCloseRequested and related tab-closing tests
- Violation(s): State checks without verification of cleanup correctness; weak assertions on reference nulling
- Why it is not a real gate:
  - test_close_analysis_panel_nulls_reference (line 161): Calls _on_tab_close_requested and asserts panel.analysis_panel is None. Does not verify that the panel's stop_tool() was called, that resources were freed, or that the close request actually removed the tab from the UI (only checks the reference).
  - test_close_analysis_allows_readd (line 178): Closes a tab and re-adds a panel, asserting the new instance is not the old one. This is testing object identity, not that the panel was properly cleaned up or that re-adding works correctly in a real scenario (e.g., with signal connections).
  - test_close_script_panel_nulls_reference (line 194): Similar to analysis panel test—only checks the reference is None.
  - test_close_stack_panel_nulls_reference (line 207): Same as above.
  - test_close_invalid_index_is_noop (line 220): Asserts no crash when closing out-of-range index. This is a smoke test for exception handling, not a gate on correctness.
  - test_close_multiple_tabs_sequentially (line 226): Adds three tabs, closes them one by one, and asserts the count decrements. Does not verify the correct tabs were closed or that the tab widget's internal state is correct (e.g., the active tab after closure).
- Severity: Medium
- Fix recommendation: (1) For each tab-close test, after asserting the reference is None, also verify the tab_widget.indexOf(widget) == -1 (the tab was actually removed from the UI). (2) Add a test that verifies the panel's stop_tool() or cleanup() method was called by checking signal emission or state (e.g., if the panel has a process or connection, verify it's terminated). (3) For test_close_analysis_allows_readd, verify the second panel is properly connected to the ToolOutputPanel's signals by emitting a signal and checking it's received. (4) For test_close_multiple_tabs_sequentially, specify which tabs should remain after each close (e.g., after closing tab 0, verify tabs[1] and tabs[2] are still present by checking their indices).

### tests/test_ui/test_tools_logic.py:248-289 - TestCloseEmbeddedTools class
- Violation(s): State checks only; no verification of actual tool/bridge cleanup
- Why it is not a real gate:
  - test_close_embedded_tools_clears_all_dicts (line 250): Calls close_embedded_tools() and asserts the tracking dicts are empty. Does not verify that the tools/bridges were actually stopped (no verification of stop_tool() calls or bridge disconnections).
  - test_close_embedded_tools_nulls_panel_refs (line 263): Asserts panel references are set to None. Does not verify the panels were actually closed or their resources freed.
  - test_close_embedded_tools_nulls_bridge_refs (line 281): Asserts bridge references are set to None. Does not verify the bridges were detached or shutdown.
- Severity: Medium
- Fix recommendation: (1) For each test, create the tools/panels/bridges before calling close_embedded_tools(). For example, call add_analysis_panel(), add_script_panel(), add_stack_panel() to populate the tracking dicts, then call close_embedded_tools() and verify all are cleaned up. (2) Add assertions that the tools' stop_tool() methods were called (use signal recorders or monkeypatch to track calls). (3) For bridge cleanup, verify that the bridges are detached by checking their state or by verifying they no longer respond to queries (e.g., if a bridge has a connection, verify it's closed).

## Clean tests

- tests/test_ui/log_viewer/test_realcov_15_window_real_logs.py:81 - test_window_backfills_real_structlog_history
- tests/test_ui/log_viewer/test_record.py:40 - test_parse_json_line_populates_all_fields
- tests/test_ui/log_viewer/test_record.py:54 - test_parse_json_line_blank_returns_none
- tests/test_ui/log_viewer/test_record.py:60 - test_parse_json_line_invalid_json_returns_none
- tests/test_ui/log_viewer/test_record.py:66 - test_parse_json_line_non_object_returns_none
- tests/test_ui/log_viewer/test_record.py:73 - test_parse_json_line_missing_fields_use_defaults
- tests/test_ui/log_viewer/test_record.py:87 - test_from_logging_record_foreign_record_uses_stdlib_fields
- tests/test_ui/log_viewer/test_record.py:107 - test_from_logging_record_structlog_payload_overrides_stdlib
- tests/test_ui/log_viewer/test_record.py:138 - test_record_to_json_text_pretty_printed
- tests/test_ui/log_viewer/test_record.py:156 - test_record_to_json_text_non_serializable_falls_back_to_repr
- tests/test_ui/log_viewer/test_record.py:177 - test_extras_to_compact_json_empty_returns_empty_string
- tests/test_ui/log_viewer/test_record.py:182 - test_extras_to_compact_json_non_serializable_falls_back_to_repr

## Summary

**Findings by severity:**
- Critical: 0
- High: 5 (test_window_level_filter_over_real_records, test_hxd_panel construction suite, test_address_clicked_propagation, test_on_address_clicked_updates_ui)
- Medium: 8 (TestHxDPanelFileLoadingPreconditions, TestHxDPanelLifecycle, TestFunctionListPanel.test_function_selected_signal, TestXRefPanel.test_xref_selected_signal, TestTabCloseRequested, TestCloseEmbeddedTools)
- Low: 2 (TestHxDPanelToolbar, TestToolOutputPanelNoDefaultTabs)

**Total tests audited:** 55
**Total tests clean:** 12

**Breakdown:**
- test_realcov_15_window_real_logs.py: 2 tests (1 finding, 1 clean)
- test_record.py: 12 tests (0 findings, 12 clean)
- test_hxd_panel.py: 24 tests (13 findings, 11 clean [via condensed classes])
- test_tools_logic.py: 17 tests (8 findings, 9 clean [via condensed classes])

Note: Several test classes contain multiple tests each; the High/Medium/Low findings represent problematic patterns within those classes that affect multiple test functions collectively.
