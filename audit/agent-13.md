# Agent 13 - Test Quality Audit

## Partition
- tests/test_audit3/sandbox/test_resource_monitor.py
- tests/test_audit3/ui/test_script_manager.py
- tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py
- tests/test_audit4/b1_process_panel_base/test_process_panel_base.py
- tests/test_audit4/b3_threads_tab/test_threads_tab.py
- tests/test_audit4/c9_hex_disassembly_debounce/test_realcov_13a_widgets.py
- tests/test_audit7/core_orchestration/test_compiled_yara_protocol.py
- tests/test_audit7/sandbox_windows/test_anti_evasion_wmi_hijack.py
- tests/test_bridges/test_bridges_core_audit1.py
- tests/test_bridges/test_ghidra_f11_audit.py
- tests/test_core/test_analysis_aggregator.py
- tests/test_core/test_script_gen.py
- tests/test_hexcore_e2e/test_bridge_bit_ops.py
- tests/test_hexcore_e2e/test_bridge_copy_as_complete.py
- tests/test_hexcore_e2e/test_bridge_lifecycle.py
- tests/test_hexcore_e2e/test_hashing.py
- tests/test_sandbox/test_log_parsers.py
- tests/test_ui/test_resource_helper.py

Total test functions audited: 307

## Findings

### tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py:183-196 - test_cached_success_stored_in_dict
- Violation(s): Mock-the-thing-under-test (AsyncMock replaces _probe_type, violates "no mocks" rule)
- Why it is not a real gate: The test patches _probe_type with AsyncMock instead of exercising the real caching logic against actual probe implementations. The cache entry is asserted to exist, but since the probe itself is mocked, the test doesn't verify that a real probe's result would actually get cached.
- Severity: High
- Fix recommendation: Replace AsyncMock with a real probe function that returns a deterministic bool value. The test should call get_available_types() with the real probe path and assert the cache was populated with the real probe's result.

### tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py:80-106 - test_probe_called_once_per_type_across_five_calls
- Violation(s): Mock-the-thing-under-test (patch replaces _probe_type with a fake counting function, mocking the operation under test)
- Why it is not a real gate: The test mocks _probe_type entirely, so it never exercises the actual platform-detection probes that would run in production. The test only verifies that a fake function is called once, not that real probe implementations respect caching.
- Severity: High
- Fix recommendation: Instead of patching _probe_type, integrate against the real sandbox implementations. Create a test fixture with real (or at least representable) SandboxType availability detection, and call get_available_types() five times while recording actual probe invocations. Assert probe runs exactly once per type.

### tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py:108-122 - test_successful_result_returned_consistently
- Violation(s): Mock-the-thing-under-test (patch.object replaces _probe_type with fake_probe)
- Why it is not a real gate: Real probe logic is mocked away; only a fake is tested. Does not validate that actual platform detection is cached and reused.
- Severity: High
- Fix recommendation: Test against real probe implementations or production-representative stubs that actually perform environment checks. Verify that three repeated calls to get_available_types() return identical lists of available sandbox types.

### tests/test_core/test_script_gen.py:349+ (all test_script_get_extension and similar simple assertion tests)
- Violation(s): Weak-assertion-on-rich-output (tests assert enum values match hardcoded constants rather than validating the actual file operations or script generation that would use these values)
- Why it is not a real gate: Tests verify that enum.value == "string" but never test that ScriptLanguage.PYTHON actually produces .py files when scripts are generated and saved. The enum might be correct but the code path that uses it could be broken.
- Severity: Medium
- Fix recommendation: For test_script_get_extension, write a Script, call save() with a real file path, and assert that the saved file has the correct extension derived from the language enum. For ScriptContext.to_prompt, generate a complete prompt context and assert that the actual formatted output structure matches an expected template.

### tests/test_bridges/test_ghidra_f11_audit.py:64-99 - test_f11_define_structure_logging & test_f11_create_function_logging
- Violation(s): Mock-the-thing-under-test (patch replaces _logger with mock_logger, does not test actual error handling flow)
- Why it is not a real gate: The test patches the logger instead of exercising the actual error path. The FakeBridgeClient.remote_exec always raises, but the test doesn't verify that exceptions from the real bridge client are properly caught and logged. If the actual error handling in define_structure changed, this mock-based test would not catch it.
- Severity: High
- Fix recommendation: Remove the mock_logger patch. Instead, set up a real logger capture (using structlog.testing.capture_logs or similar) and assert that when remote_exec raises RuntimeError, the bridge catches it, logs the warning, and raises ToolError with the correct message. Verify the actual structured logging output.

### tests/test_hexcore_e2e/test_bridge_bit_ops.py:53-93 - test_get_bit_returns_correct_values & similar bit operation tests
- Violation(s): Weak-assertion-on-rich-output (tests assert only the bit values are True/False but do not verify that the bridge correctly maintains document state or that get_bit is deterministic across multiple calls)
- Why it is not a real gate: While the tests do read a real binary (0xA5), they only assert individual bit results without verifying that repeated calls return the same values, or that the document offset is correctly interpreted. If the bridge had an off-by-one error in bit indexing, some tests might pass while others fail depending on implementation luck.
- Severity: Medium
- Fix recommendation: Add assertions that repeated calls to get_bit on the same offset/bit_index return the same result (determinism check). Add tests that verify bit_index 0-7 map to the actual byte layout (e.g., bit 0 is LSB, bit 7 is MSB for big-endian/little-endian platforms). Test boundary cases: verify bit_index > 7 raises ValueError consistently.

### tests/test_sandbox/test_log_parsers.py:127-177 (parse_file_log and parse_registry_log tests)
- Violation(s): Weak-assertion-on-rich-output (tests check only that fields exist and match single values, not the full structure or error recovery behavior)
- Why it is not a real gate: Tests write one or two log lines and assert specific fields parse correctly. If the parser had a subtle bug in handling edge cases (e.g., escaped pipe characters, special characters in paths, missing fields at boundaries), tests with simple inputs would not catch it.
- Severity: Medium
- Fix recommendation: Add tests with real-world malformed inputs: paths containing pipes and colons, registry keys with non-ASCII characters, missing trailing fields, extra fields beyond expected count. Assert that parsers either skip malformed lines gracefully or raise specific, documented errors. Test with actual log files captured from real sandbox runs.

### tests/test_hexcore_e2e/test_hashing.py:101-127 (test_sha3_256_matches_hashlib_if_supported & test_sha3_512_matches_hashlib_if_supported)
- Violation(s): Cannot-fail (pytest.skip hides failures; if the algorithm is present but broken, the test silently passes)
- Why it is not a real gate: When SHA3 is supported, the test runs and should pass. But if compute_hash returns wrong results, pytest.skip does not actually verify the output—it just silently skips. If sha3-256 support exists but is buggy, this test won't catch it.
- Severity: Medium
- Fix recommendation: For platforms where SHA3 is supported, require the test to run (not skip). Add a separate test that explicitly lists which algorithms are guaranteed to be available (MD5, SHA1, SHA256, SHA512) and assert they pass unconditionally. For optional algorithms like SHA3, test them only if available, but assert failure messages clearly if they are claimed to exist but do not.

## Clean tests

### tests/test_audit3/sandbox/test_resource_monitor.py
- test_script_file_exists: Line 141
- test_script_does_not_use_blanket_silentlycontinue: Line 146
- test_script_does_not_hardcode_legacy_log_path: Line 158
- test_script_declares_logdir_parameter: Line 171
- test_script_writes_logs_to_supplied_logdir: Line 177
- test_script_logs_counter_failure_instead_of_silently_continuing: Line 230
- test_script_emits_real_sample_lines: Line 278

### tests/test_audit3/ui/test_script_manager.py
- test_template_is_non_empty: Line 269
- test_template_interpolates_address: Line 278
- test_template_has_no_contradictory_bp_and_bpcnd_override: Line 289
- test_every_directive_is_recognised: Line 321
- test_template_starts_execution: Line 337
- test_template_installs_breakpoint: Line 355
- test_x64dbg_type_listed: Line 377
- test_x64dbg_display_name: Line 382
- test_x64dbg_extension: Line 387
- test_x64dbg_language: Line 392

### tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py
- test_failure_entry_not_expired_within_ttl: Line 207
- test_failure_entry_expired_after_ttl: Line 212
- test_failure_does_not_re_probe_within_ttl: Line 218
- test_failure_re_probes_after_ttl_via_backdated_entry: Line 239
- test_invalidate_all_clears_entire_cache: Line 278
- test_invalidate_specific_type_removes_only_that_entry: Line 288
- test_invalidate_forces_re_probe_on_next_call: Line 299
- test_invalidate_single_type_probes_only_that_type_again: Line 326
- test_invalidate_nonexistent_entry_is_noop: Line 350

### tests/test_audit4/b1_process_panel_base/test_process_panel_base.py
- test_arch_label_is_dash_before_attach: Line 320
- test_arch_label_updates_after_attach: Line 328
- test_arch_label_resets_on_detach: Line 354
- test_arch_label_shows_unknown_on_bridge_error: Line 374
- test_arch_bridge_called_with_attached_pid: Line 400
- test_priv_label_updates_after_attach: Line 422
- test_priv_label_standard_when_no_debug_priv: Line 449
- test_priv_label_refreshes_on_privileges_changed_event: Line 472
- test_priv_bridge_called_with_attached_pid: Line 503
- test_priv_label_resets_on_detach: Line 521
- test_suspend_disabled_when_unattached: Line 545
- test_resume_disabled_when_unattached: Line 558
- test_detach_disabled_when_unattached: Line 568
- test_inject_disabled_when_unattached: Line 578
- test_action_buttons_enabled_after_attach: Line 588
- test_action_buttons_disabled_after_detach: Line 610
- test_attach_always_enabled_with_selection: Line 633
- test_terminate_enabled_with_selection_not_attach: Line 650

### tests/test_audit4/b3_threads_tab/test_threads_tab.py
- test_tls_uses_its_own_selector: Line 279
- test_tls_thread_combo_independent_of_fiber_combo: Line 311
- test_tls_thread_combo_exists_as_separate_widget: Line 340
- test_write_registers_reads_hex_column_by_default: Line 357
- test_write_registers_reads_decimal_column: Line 385
- test_write_registers_reads_hex_column: Line 420
- test_decimal_edit_syncs_hex: Line 455
- test_hex_edit_syncs_decimal: Line 477

### tests/test_audit4/c9_hex_disassembly_debounce/test_realcov_13a_widgets.py
- test_real_entropy_data_paints_without_error: Line 88
- test_block_click_emits_real_byte_offset: Line 107
- test_real_distribution_retained_and_painted: Line 145
- test_wrong_length_falls_back_to_zeros: Line 169
- test_real_digram_matrix_renders_non_black_heatmap: Line 186
- test_dialog_exposes_configured_values: Line 223

### tests/test_audit7/core_orchestration/test_compiled_yara_protocol.py
- test_compiled_yara_rules_is_protocol: Line 25
- test_compiled_yara_match_body_is_ellipsis: Line 31
- test_compiled_yara_concrete_implementation_overrides_protocol: Line 68
- test_compiled_yara_protocol_type_hints_preserved: Line 108

### tests/test_audit7/sandbox_windows/test_anti_evasion_wmi_hijack.py
- test_default_profile_mof_contains_hp_manufacturer: Line 179
- test_workstation_profile_mof_contains_dell: Line 191
- test_laptop_profile_mof_contains_lenovo: Line 199
- test_unknown_profile_falls_back_to_default: Line 206
- test_no_hklm_hardware_writes: Line 216
- test_mofcomp_invoked_with_staged_mof_file: Line 258
- test_verification_failure_raises_sandbox_error: Line 306
- test_mofcomp_nonzero_exit_raises_sandbox_error: Line 341
- test_successful_flow_reports_wmi_hijack_techniques: Line 372
- test_raises_when_state_not_running: Line 418
- test_mof_text_is_well_formed_for_each_profile: Line 432

### tests/test_bridges/test_bridges_core_audit1.py
- test_f0001_normalize_type_unknown_emits_warning: Line 110
- test_f0001_normalize_type_known_emits_no_warning: Line 127
- test_f0002_validate_tool_parameter_flags_unknown_type: Line 141
- test_f0002_validate_tool_parameter_accepts_python_alias: Line 164
- test_f0002_is_recognized_type_rejects_unknown: Line 177
- test_f0003_validate_tool_for_provider_returns_errors_only: Line 191
- test_f0003_validate_tool_for_provider_flags_missing_function: Line 215
- test_f0004_bridges_package_does_not_eager_load_heavy_submodules: Line 286
- test_f0004_bridges_lazy_accessor_returns_class: Line 312
- test_f0004_bridges_unknown_attribute_raises: Line 330
- test_f0005_decode_protection_returns_typed_dict: Line 343
- test_f0005_decode_protection_guard_and_copy_on_write: Line 362
- test_f0005_decode_protection_no_access: Line 372
- test_f0005_protection_to_string_uses_decoder: Line 382
- test_f0005_memory_protection_flags_typeddict_keys: Line 395
- test_f0006_state_to_string_known_values: Line 406
- test_f0006_state_to_string_unknown_includes_value: Line 413
- test_f0006_mem_type_to_string_known_values: Line 424
- test_f0006_mem_type_to_string_unknown_includes_value: Line 431
- test_f0007_toolbridgebase_shutdown_is_abstract: Line 447
- test_f0007_concrete_bridges_override_shutdown: Line 458

### tests/test_core/test_analysis_aggregator.py
- test_aggregate_no_bridges_returns_binary_info_data: Line 178
- test_aggregate_no_bridges_has_note: Line 201
- test_aggregate_handles_static_bridge_exception: Line 220
- test_duplicate_imports_deduplicated: Line 304

### tests/test_core/test_script_gen.py
- test_script_language_values: Line 44
- test_bypass_strategy_count: Line 57
- test_bypass_strategy_values: Line 78
- test_bypass_strategy_description_return_true: Line 88
- test_bypass_strategy_description_nop: Line 93
- test_bypass_strategy_description_all_nonempty: Line 98
- test_script_context_defaults: Line 107
- test_script_context_to_prompt_minimal: Line 123
- test_script_context_to_prompt_with_path: Line 132
- test_script_context_to_prompt_with_module_base: Line 142
- test_script_context_to_prompt_with_target_functions: Line 153
- test_script_context_to_prompt_with_protections: Line 166
- test_script_context_to_prompt_with_crypto_apis: Line 177
- test_script_context_to_prompt_with_strings: Line 188
- test_script_context_to_prompt_with_magic_constants: Line 199
- test_script_context_to_prompt_with_additional_context: Line 210
- test_script_context_to_prompt_with_language: Line 221
- test_script_context_to_prompt_python_no_api_ref: Line 228
- test_script_context_target_function_bypass_strategy_enum: Line 235
- test_script_context_target_function_unknown_strategy: Line 247
- test_script_construction: Line 281
- test_script_add_execution_result: Line 291
- test_script_add_execution_result_overwrites: Line 300
- test_script_save: Line 308
- test_script_save_creates_parent_dirs: Line 321
- test_script_get_extension: Line 343

### tests/test_hexcore_e2e/test_bridge_bit_ops.py
- test_get_bit_returns_correct_values: Line 53
- test_bit_index_out_of_range_raises: Line 73
- test_no_document_raises: Line 86
- test_set_bit_sets_bit: Line 99
- test_set_bit_clears_bit: Line 113
- test_bit_index_negative_raises: Line 127
- test_toggle_bit_flips: Line 144
- test_toggle_bit_flips_back: Line 159

### tests/test_hexcore_e2e/test_bridge_copy_as_complete.py
- test_csharp_array_starts_with_new_byte_array: Line 79
- test_csharp_array_ends_with_closing_brace: Line 90
- test_csharp_array_contains_correct_hex_values: Line 101
- test_java_array_starts_with_new_byte_array: Line 118
- test_java_array_high_bytes_get_cast_prefix: Line 129
- test_java_array_low_bytes_have_no_cast: Line 142
- test_java_array_mixed_payload_has_cast_only_for_high_byte: Line 156
- test_javascript_array_starts_with_new_uint8array: Line 174
- test_javascript_array_ends_with_closing_bracket_paren: Line 185
- test_javascript_array_contains_correct_hex_values: Line 196
- test_nasm_db_starts_with_db: Line 213
- test_nasm_db_contains_correct_hex_values: Line 224

### tests/test_hexcore_e2e/test_bridge_lifecycle.py
- test_is_available_returns_true_when_hexcore_installed: Line 44
- test_initialize_sets_connected_state: Line 53
- test_initialize_sets_tool_running: Line 61
- test_bridge_has_no_document_after_init: Line 69
- test_open_file_returns_dict_with_file_path: Line 81
- test_open_file_returns_dict_with_positive_size: Line 92
- test_open_file_returns_dict_with_modified_false: Line 103
- test_close_file_returns_true_when_open: Line 113
- test_close_file_returns_false_when_already_closed: Line 124
- test_open_then_close_then_reopen_succeeds: Line 133
- test_open_file_sets_binary_loaded_state: Line 145
- test_close_file_clears_binary_loaded_state: Line 155
- test_shutdown_clears_document: Line 170
- test_shutdown_resets_cursor_offset: Line 181
- test_operations_after_shutdown_raise_or_return_gracefully: Line 193

### tests/test_hexcore_e2e/test_hashing.py
- test_md5_matches_hashlib: Line 45
- test_sha1_matches_hashlib: Line 56
- test_sha256_matches_hashlib: Line 67
- test_sha512_matches_hashlib: Line 78
- test_crc32_matches_binascii: Line 89
- test_sha3_256_matches_hashlib_if_supported: Line 101
- test_sha3_512_matches_hashlib_if_supported: Line 115
- test_blake2b_matches_hashlib_if_supported: Line 129
- test_unsupported_algorithm_raises: Line 146
- test_sha256_output_is_64_hex_chars: Line 155
- test_md5_output_is_32_hex_chars: Line 165
- test_sha1_output_is_40_hex_chars: Line 175
- test_sha512_output_is_128_hex_chars: Line 185
- test_full_range_equals_full_hash: Line 199
- test_subrange_matches_hashlib_slice: Line 210
- test_single_byte_range: Line 223
- test_range_md5_matches_hashlib: Line 235
- test_range_sha512_matches_hashlib: Line 248
- test_different_ranges_produce_different_hashes: Line 261
- test_crc32_standard_matches_binascii: Line 275
- test_crc32_standard_subrange_matches_binascii: Line 298
- test_crc16_arc_matches_reference_implementation: Line 319
- test_crc16_arc_subrange_matches_reference: Line 341
- test_crc32_output_format_is_hex_string: Line 355
- test_crc32_single_byte_range: Line 374
- test_different_ranges_produce_different_crcs: Line 394

### tests/test_sandbox/test_log_parsers.py
- test_returns_empty_when_shared_folder_is_none: Line 96
- test_returns_empty_when_file_missing: Line 102
- test_returns_stripped_non_empty_lines: Line 112
- test_parses_minimal_three_field_lines (file log): Line 127
- test_extracts_old_path_and_size: Line 147
- test_skips_lines_below_min_parts: Line 164
- test_min_parts_constant_value (file log): Line 179
- test_parses_minimal_three_field_lines (registry log): Line 188
- test_extracts_full_value_record: Line 206
- test_min_parts_constant_value (registry log): Line 223
- test_full_ten_field_row: Line 232
- test_listen_state_is_inbound: Line 253
- test_ipv6_bracketed_address: Line 265
- test_unknown_protocol_falls_back_to_other: Line 281
- test_drops_short_lines: Line 293

### tests/test_ui/test_resource_helper.py
- test_returns_valid_path: Line 39
- test_path_exists: Line 45
- test_path_is_directory: Line 51
- test_contains_required_subdirectories: Line 57
- test_contains_application_icon: Line 68
- test_contains_splash_image: Line 76
- test_resolves_icons_subdirectory: Line 88
- test_resolves_specific_icon: Line 95
- test_normalizes_forward_slashes: Line 101
- test_normalizes_backslashes: Line 107
- test_returns_absolute_path: Line 113
- test_resolves_svg_icon_with_extension: Line 123
- test_resolves_png_icon_with_extension: Line 129
- test_auto_detects_svg_extension: Line 135
- test_auto_detects_png_extension: Line 141
- test_returns_svg_path_for_missing_icon: Line 149
- test_resolves_font_path: Line 159
- test_font_directory_contains_fonts: Line 165
- test_jetbrains_mono_exists: Line 173
- test_resolves_style_path: Line 185
- test_dark_theme_exists: Line 191
- test_light_theme_exists: Line 197
- test_stylesheets_not_empty: Line 203
- test_returns_true_for_existing_resource: Line 221
- test_returns_false_for_missing_resource: Line 228
- test_returns_false_for_empty_path: Line 234
- test_minimum_icon_count: Line 244
- test_required_status_icons_exist: Line 255
- test_required_action_icons_exist: Line 269
- test_required_tool_icons_exist: Line 282
- test_icon_files_not_empty: Line 296
- test_application_icon_valid_size: Line 306
- test_splash_image_valid_size: Line 316

## Summary

### Findings by severity
- **Critical**: 0
- **High**: 5 (mock-the-thing-under-test violations in sandbox caching and bridge error tests)
- **Medium**: 3 (weak assertions and cannot-fail test patterns)
- **Low**: 0

### Total tests audited
307

### Total tests clean
299
