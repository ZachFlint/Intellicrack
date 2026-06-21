# Agent 20 - Test Quality Audit

## Partition
- tests/test_audit3/sandbox/test_kernel_object_monitor.py
- tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py
- tests/test_audit4/b3_threads_tab/test_realcov_14a_threads_tab.py
- tests/test_audit5/u4_hexpat_aux/test_preprocessor_preserves_pragmas.py
- tests/test_audit7/bridges_hex/test_utf16_scanner.py
- tests/test_audit7/core_orchestration/test_tool_state_lifecycle.py
- tests/test_audit7/sandbox_windows/test_launch_failure_detection.py
- tests/test_bridges/test_hex_editor_top_audit1.py
- tests/test_core/test_config_audit6.py
- tests/test_core/test_realcov_07b_script_gen.py
- tests/test_hexcore_e2e/test_bridge_error_handling.py
- tests/test_hexcore_e2e/test_bridge_pattern_engine.py
- tests/test_hexcore_e2e/test_hexpat_data_reader.py
- tests/test_hexpat/test_compiler.py
- tests/test_ui/test_realcov_15_dialog_helpers_logging.py
- tests/test_ui/test_state_persistence.py
- tests/test_ui/test_theme_manager.py
- tests/test_ui/test_tool_panel_detach.py

Total test functions audited: 307

## Findings

### tests/test_audit7/sandbox_windows/test_launch_failure_detection.py:23 - _detect_returns_rpc
- Violation(s): Mock-the-thing-under-test, No-assertion/vacuous-assertion
- Why it is not a real gate: This is not a test function; it is a helper used by tests that stub the dialog detector. The helper itself makes no assertions and simply returns a string, acting as a test double. The tests using this helper verify exception raising and message content rather than verifying actual WindowsSandbox._detect_client_failure_dialog behavior on real processes.
- Severity: Low
- Fix recommendation: These are fixture-like helpers, not tests. They are designed to support the tests that use them. The tests consuming these helpers (test_failure_dialog_surfaces_rpc_error, test_live_client_without_dialog_is_noop) do make real assertions on the bridge behavior, so the overall pattern is acceptable. No fix required.

### tests/test_bridges/test_hex_editor_top_audit1.py:192 - _PatchesOnlyDoc
- Violation(s): Smoke-test-as-gate (test class, not function)
- Why it is not a real gate: This is a helper class, not a test function. It is used by tests like test_oversized_offset_for_ips_raises to stub the native export_patches_ips interface. The helper itself makes no assertions.
- Severity: Low
- Fix recommendation: This is a fixture-like stub supporting tests, not a test. The tests that use it (test_oversized_offset_for_ips_raises, test_eof_collision_offset_for_ips_raises, etc.) do make real assertions on OverflowError raising, so the overall pattern is sound. No fix required.

### tests/test_ui/test_state_persistence.py:142 - test_restore_tab_state_tab_openers_keys
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: The test asserts that expected_keys are accessible via panel.find_tab_by_title but never verifies that those tabs actually exist or function correctly. The assertion `isinstance(idx, int)` merely confirms the return type is int, not that the tab is valid, usable, or correctly labeled. Breaking the tab titles would not be caught.
- Severity: Medium
- Fix recommendation: Add assertions to verify that each found tab index is >= 0 (valid), that panel.tab_widget.tabText(idx) equals the expected key exactly, and that the widgets at those indices are valid and functional. Verify tab count matches expected_keys. Verify tab ordering is consistent.

### tests/test_ui/test_theme_manager.py:193 - test_apply_invalid_theme_uses_default
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: The test asserts only that current_theme equals DEFAULT_THEME after calling apply_theme("invalid_theme_name"), but does not verify that the stylesheet was actually applied or that the UI was updated. Breaking the fallback logic that switches to dark theme would still pass this test if current_theme returns the right enum value. The actual stylesheet application is not verified.
- Severity: Medium
- Fix recommendation: Add assertions that verify the stylesheet was actually applied to QApplication by checking the application palette or stylesheet content. Verify that the theme_changed signal was emitted with DEFAULT_THEME. Test that subsequent rendering or palette queries reflect the fallback theme.

## Clean tests

### tests/test_audit3/sandbox/test_kernel_object_monitor.py:137 - test_script_file_exists
### tests/test_audit3/sandbox/test_kernel_object_monitor.py:142 - test_script_uses_millisecond_poll
### tests/test_audit3/sandbox/test_kernel_object_monitor.py:156 - test_script_logs_openprocess_lasterror
### tests/test_audit3/sandbox/test_kernel_object_monitor.py:170 - test_script_attempts_sedebugprivilege
### tests/test_audit3/sandbox/test_kernel_object_monitor.py:199 - test_script_logs_sedebug_failure_when_non_admin
### tests/test_audit3/sandbox/test_kernel_object_monitor.py:264 - test_script_logs_openprocess_failure_for_system_pid
### tests/test_audit3/sandbox/test_kernel_object_monitor.py:394 - test_script_captures_transient_mutex
### tests/test_audit3/sandbox/test_kernel_object_monitor.py:454 - test_script_creates_supplied_logdir
### tests/test_audit3/sandbox/test_kernel_object_monitor.py:473 - test_script_no_orphan_pwsh_after_terminate
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:100 - test_filename_not_matched_as_domain
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:122 - test_file_extension_tld_denylist_entry
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:150 - test_real_hostname_is_matched
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:174 - test_common_tld_in_allowlist
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:193 - test_ace_hostname_accepted
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:202 - test_xn_p1ai_in_tld_allowlist
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:220 - test_double_extension_rejected_as_hostname
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:233 - test_rejects_exe_tld
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:237 - test_rejects_dll_tld
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:241 - test_rejects_unknown_tld
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:245 - test_accepts_com_tld
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:249 - test_accepts_org_tld
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:253 - test_accepts_net_tld
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:257 - test_rejects_single_label
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:261 - test_case_insensitive_tld
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:271 - test_dll_path_not_extracted_as_domain
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:288 - test_exe_path_not_extracted_as_domain
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:308 - test_real_domain_in_registry_extracted
### tests/test_audit4/a2_sandbox_analysis_regex/test_domain_pattern.py:326 - test_txt_filename_in_command_line_not_extracted
### tests/test_audit4/b3_threads_tab/test_realcov_14a_threads_tab.py:172 - test_thread_table_populated_from_real_enumeration
### tests/test_audit4/b3_threads_tab/test_realcov_14a_threads_tab.py:195 - test_thread_count_label_matches_real_rows
### tests/test_audit4/b3_threads_tab/test_realcov_14a_threads_tab.py:209 - test_thread_combos_populated_with_real_tids
### tests/test_audit4/b3_threads_tab/test_realcov_14a_threads_tab.py:229 - test_refresh_discovers_real_main_thread
### tests/test_audit5/u4_hexpat_aux/test_preprocessor_preserves_pragmas.py:31 - test_base_address_directive_recorded_in_output
### tests/test_audit5/u4_hexpat_aux/test_preprocessor_preserves_pragmas.py:40 - test_endian_directive_recorded_in_output
### tests/test_audit5/u4_hexpat_aux/test_preprocessor_preserves_pragmas.py:49 - test_emitted_pragma_comment_does_not_break_lexer
### tests/test_audit5/u4_hexpat_aux/test_preprocessor_preserves_pragmas.py:65 - test_emitted_source_has_no_raw_pragma_directive
### tests/test_audit5/u4_hexpat_aux/test_preprocessor_preserves_pragmas.py:73 - test_extract_pragmas_fast_scans_full_source
### tests/test_audit5/u4_hexpat_aux/test_preprocessor_preserves_pragmas.py:85 - test_multiple_pragmas_all_preserved
### tests/test_audit7/bridges_hex/test_utf16_scanner.py:81 - test_ascii_hello_utf16le_aligned_detected
### tests/test_audit7/bridges_hex/test_utf16_scanner.py:99 - test_ascii_hello_utf16le_misaligned_detected
### tests/test_audit7/bridges_hex/test_utf16_scanner.py:116 - test_superscript_zero_run_rejected
### tests/test_audit7/bridges_hex/test_utf16_scanner.py:130 - test_currency_and_math_symbol_run_rejected
### tests/test_audit7/bridges_hex/test_utf16_scanner.py:144 - test_mixed_payload_returns_only_ascii_run
### tests/test_audit7/core_orchestration/test_tool_state_lifecycle.py:121 - test_bridge_publishes_connect_state_to_session
### tests/test_audit7/core_orchestration/test_tool_state_lifecycle.py:136 - test_bridge_publishes_attach_state_to_session
### tests/test_audit7/core_orchestration/test_tool_state_lifecycle.py:158 - test_bridge_publishes_error_state_to_session
### tests/test_audit7/core_orchestration/test_tool_state_lifecycle.py:171 - test_bridge_detach_clears_state_in_session
### tests/test_audit7/core_orchestration/test_tool_state_lifecycle.py:185 - test_full_lifecycle_cycle
### tests/test_audit7/core_orchestration/test_tool_state_lifecycle.py:216 - test_set_session_publishes_current_state_immediately
### tests/test_audit7/core_orchestration/test_tool_state_lifecycle.py:229 - test_set_session_none_does_not_publish
### tests/test_audit7/sandbox_windows/test_launch_failure_detection.py:138 - test_failure_text_detected
### tests/test_audit7/sandbox_windows/test_launch_failure_detection.py:155 - test_benign_text_ignored
### tests/test_audit7/sandbox_windows/test_launch_failure_detection.py:167 - test_rpc_endpoint_code_uses_actionable_guidance
### tests/test_audit7/sandbox_windows/test_launch_failure_detection.py:175 - test_other_code_uses_generic_message_with_detail
### tests/test_audit7/sandbox_windows/test_launch_failure_detection.py:191 - test_no_process_is_noop
### tests/test_audit7/sandbox_windows/test_launch_failure_detection.py:198 - test_early_client_exit_raises_actionable_error
### tests/test_audit7/sandbox_windows/test_launch_failure_detection.py:210 - test_failure_dialog_surfaces_rpc_error
### tests/test_audit7/sandbox_windows/test_launch_failure_detection.py:232 - test_live_client_without_dialog_is_noop
### tests/test_audit7/sandbox_windows/test_launch_failure_detection.py:256 - test_sandbox_error_propagated_verbatim
### tests/test_audit7/sandbox_windows/test_launch_failure_detection.py:286 - test_os_error_wrapped_in_generic_start_failed
### tests/test_bridges/test_hex_editor_top_audit1.py:90 - test_get_alignment_grid_reflects_set_alignment_grid
### tests/test_bridges/test_hex_editor_top_audit1.py:99 - test_get_alignment_grid_default_is_zero
### tests/test_bridges/test_hex_editor_top_audit1.py:107 - test_get_alignment_grid_registered_as_tool
### tests/test_bridges/test_hex_editor_top_audit1.py:125 - test_close_file_holds_state_lock
### tests/test_bridges/test_hex_editor_top_audit1.py:150 - test_apply_transform_xor_modifies_document
### tests/test_bridges/test_hex_editor_top_audit1.py:170 - test_apply_transform_no_in_place_leaves_document_alone
### tests/test_bridges/test_hex_editor_top_audit1.py:248 - test_oversized_offset_for_ips_raises
### tests/test_bridges/test_hex_editor_top_audit1.py:266 - test_eof_collision_offset_for_ips_raises
### tests/test_bridges/test_hex_editor_top_audit1.py:284 - test_oversized_data_for_ips_raises
### tests/test_bridges/test_hex_editor_top_audit1.py:302 - test_oversized_offset_for_ips32_raises
### tests/test_bridges/test_hex_editor_top_audit1.py:320 - test_eeof_collision_offset_for_ips32_raises
### tests/test_bridges/test_hex_editor_top_audit1.py:339 - test_valid_ips_round_trip_still_works
### tests/test_bridges/test_hex_editor_top_audit1.py:373 - test_apply_truncated_record_data_raises
### tests/test_bridges/test_hex_editor_top_audit1.py:387 - test_apply_missing_terminator_raises
### tests/test_bridges/test_hex_editor_top_audit1.py:401 - test_apply_truncated_rle_record_raises
### tests/test_bridges/test_hex_editor_top_audit1.py:415 - test_apply_well_formed_patch_succeeds
### tests/test_bridges/test_hex_editor_top_audit1.py:446 - test_get_pe_imports_succeeds_on_unmodified_pe
### tests/test_bridges/test_hex_editor_top_audit1.py:465 - test_get_pe_imports_succeeds_after_modification
### tests/test_bridges/test_hex_editor_top_audit1.py:485 - test_get_pe_imports_does_not_raise_for_pe
### tests/test_bridges/test_hex_editor_top_audit1.py:509 - test_yara_scan_unmodified_uses_filepath
### tests/test_bridges/test_hex_editor_top_audit1.py:537 - test_list_hexpat_patterns_raises_when_interpreter_unavailable
### tests/test_bridges/test_hex_editor_top_audit1.py:551 - test_auto_detect_pattern_raises_when_interpreter_unavailable
### tests/test_bridges/test_hex_editor_top_audit1.py:577 - test_apply_template_emits_pattern_executed_event
### tests/test_bridges/test_hex_editor_top_audit1.py:655 - test_get_entropy_uses_python_fallback_when_native_missing
### tests/test_bridges/test_hex_editor_top_audit1.py:673 - test_get_byte_distribution_uses_python_fallback
### tests/test_bridges/test_hex_editor_top_audit1.py:693 - test_get_byte_type_distribution_uses_python_fallback
### tests/test_bridges/test_hex_editor_top_audit1.py:725 - test_read_bytes_caps_oversize_request
### tests/test_bridges/test_hex_editor_top_audit1.py:740 - test_read_bytes_rejects_negative_length
### tests/test_bridges/test_hex_editor_top_audit1.py:764 - test_replace_bytes_emits_per_match_events
### tests/test_bridges/test_hex_editor_top_audit1.py:803 - test_capabilities_omit_macho
### tests/test_bridges/test_hex_editor_top_audit1.py:811 - test_capabilities_disable_scripting
### tests/test_bridges/test_hex_editor_top_audit1.py:825 - test_open_file_replaces_previous_document
### tests/test_bridges/test_hex_editor_top_audit1.py:849 - test_open_file_emits_close_then_open_events
### tests/test_bridges/test_hex_editor_top_audit1.py:964 - test_copy_to_failure_triggers_destroy
### tests/test_bridges/test_hex_editor_top_audit1.py:994 - test_bookmarks_truncated_when_over_limit
### tests/test_bridges/test_hex_editor_top_audit1.py:1015 - test_bookmark_limit_zero_returns_no_bookmarks
### tests/test_bridges/test_hex_editor_top_audit1.py:1073 - test_export_patches_ips32_falls_back_with_log
### tests/test_bridges/test_hex_editor_top_audit1.py:1140 - test_missing_search_text_encoded_raises
### tests/test_bridges/test_hex_editor_top_audit1.py:1165 - test_copy_as_without_selection_raises_tool_error
### tests/test_bridges/test_hex_editor_top_audit1.py:1181 - test_copy_as_with_selection_succeeds
### tests/test_bridges/test_hex_editor_top_audit1.py:1206 - test_initialize_merges_holder_and_bridge_rules
### tests/test_bridges/test_hex_editor_top_audit1.py:1221 - test_holder_rule_takes_precedence_on_conflict
### tests/test_bridges/test_hex_editor_top_audit1.py:1245 - test_save_as_updates_target_path
### tests/test_bridges/test_hex_editor_top_audit1.py:1273 - test_top_k_returns_only_top_k_pairs
### tests/test_bridges/test_hex_editor_top_audit1.py:1294 - test_top_k_zero_returns_full_matrix
### tests/test_bridges/test_hex_editor_top_audit1.py:1351 - test_crc32_ieee_matches_zlib
### tests/test_bridges/test_hex_editor_top_audit1.py:1393 - test_unknown_value_type_raises
### tests/test_bridges/test_hex_editor_top_audit1.py:1408 - test_unknown_endianness_raises
### tests/test_bridges/test_hex_editor_top_audit1.py:1423 - test_known_value_type_still_works
### tests/test_bridges/test_hex_editor_top_audit1.py:1449 - test_target_path_matches_rust_file_path
### tests/test_core/test_config_audit6.py:49 - test_huggingface_in_defaults
### tests/test_core/test_config_audit6.py:56 - test_grok_in_defaults
### tests/test_core/test_config_audit6.py:63 - test_every_enum_member_present
### tests/test_core/test_config_audit6.py:74 - test_round_trip_preserves_user_overrides_for_huggingface
### tests/test_core/test_config_audit6.py:95 - test_round_trip_preserves_user_overrides_for_grok
### tests/test_core/test_config_audit6.py:116 - test_full_round_trip_via_to_dict
### tests/test_core/test_config_audit6.py:128 - test_unknown_provider_skipped
### tests/test_core/test_realcov_07b_script_gen.py:53 - test_python_script_create_save_reload_execute
### tests/test_core/test_realcov_07b_script_gen.py:91 - test_valid_frida_script_passes_node_check
### tests/test_core/test_realcov_07b_script_gen.py:106 - test_syntax_error_rejected_by_node_check
### tests/test_core/test_realcov_07b_script_gen.py:120 - test_keywords_inside_strings_are_removed
### tests/test_core/test_realcov_07b_script_gen.py:128 - test_braces_inside_strings_do_not_count
### tests/test_core/test_realcov_07b_script_gen.py:135 - test_escaped_quote_does_not_terminate_string
### tests/test_core/test_realcov_07b_script_gen.py:142 - test_line_and_block_comments_stripped_preserving_newlines
### tests/test_core/test_realcov_07b_script_gen.py:151 - test_char_literal_brace_is_stripped
### tests/test_core/test_realcov_07b_script_gen.py:158 - test_real_ghidra_script_validates
### tests/test_core/test_realcov_07b_script_gen.py:177 - test_to_prompt_context_includes_real_metadata
### tests/test_core/test_realcov_07b_script_gen.py:203 - test_prepare_ai_prompt_unbound_embeds_frida_reference
### tests/test_core/test_realcov_07b_script_gen.py:212 - test_generate_ghidra_embeds_ghidra_reference
### tests/test_core/test_realcov_07b_script_gen.py:220 - test_generate_cutter_and_x64dbg_embed_their_references
### tests/test_core/test_realcov_07b_script_gen.py:229 - test_api_reference_cache_returns_same_dict
### tests/test_core/test_realcov_07b_script_gen.py:245 - test_no_validator_returns_false_and_leaves_unverified
### tests/test_hexcore_e2e/test_bridge_error_handling.py:47 - test_read_bytes_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:60 - test_write_bytes_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:69 - test_write_bytes_beyond_length_on_loaded_doc
### tests/test_hexcore_e2e/test_bridge_error_handling.py:90 - test_search_hex_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:99 - test_search_text_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:112 - test_disassemble_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:125 - test_yara_scan_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:139 - test_calculate_hash_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:148 - test_calculate_hash_range_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:157 - test_calculate_hash_custom_crc_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:170 - test_get_entropy_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:183 - test_apply_transform_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:192 - test_apply_pipeline_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_error_handling.py:205 - test_decode_text_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:67 - test_compile_simple_struct_returns_nonempty_string
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:78 - test_compile_simple_struct_result_is_valid_json
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:89 - test_compile_syntax_error_raises_value_error
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:98 - test_compile_complex_struct_with_nested_types_is_valid_json
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:109 - test_compile_enum_produces_valid_json
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:120 - test_compile_union_produces_valid_json
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:135 - test_execute_u32_field_returns_field_list
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:148 - test_execute_u32_field_has_correct_size
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:161 - test_execute_u32_field_has_correct_offset
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:174 - test_execute_struct_with_multiple_fields_returns_multiple_results
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:193 - test_execute_at_nonzero_offset
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:206 - test_execute_pattern_field_has_required_keys
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:222 - test_execute_pattern_with_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:231 - test_execute_u16_field_correct_size
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:248 - test_execute_pattern_file_matches_inline_result
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:263 - test_execute_pattern_file_nonexistent_raises_file_not_found
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:275 - test_execute_pattern_file_with_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:287 - test_execute_pattern_file_field_has_required_keys
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:308 - test_list_hexpat_patterns_returns_list
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:317 - test_list_hexpat_patterns_items_have_required_keys
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:329 - test_auto_detect_with_no_document_raises_runtime_error
### tests/test_hexcore_e2e/test_bridge_pattern_engine.py:338 - test_auto_detect_with_pe_file_returns_list
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:32 - test_read_u8
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:37 - test_read_u8_at_offset
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:42 - test_read_u16_little_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:48 - test_read_u16_big_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:54 - test_read_u32_little_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:60 - test_read_u32_big_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:66 - test_read_u64_little_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:72 - test_read_u64_big_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:78 - test_size_property
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:84 - test_read_raw_bytes
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:94 - test_read_s8_positive
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:99 - test_read_s8_negative
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:104 - test_read_s8_min
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:109 - test_read_s16_negative_little_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:114 - test_read_s16_negative_big_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:119 - test_read_s32_negative_little_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:124 - test_read_s64_negative_little_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:129 - test_read_s128_negative_little_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:140 - test_read_float_value
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:146 - test_read_float_big_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:152 - test_read_double_value
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:158 - test_read_double_big_endian
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:168 - test_read_past_end_raises
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:174 - test_read_u32_past_end_raises
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:180 - test_read_negative_offset_raises
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:186 - test_read_at_exact_end_raises
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:192 - test_read_zero_bytes_at_start_succeeds
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:197 - test_read_full_extent_succeeds
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:208 - test_u16_little_vs_big_differ
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:218 - test_u32_little_vs_big_differ
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:225 - test_read_string_null_terminated
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:233 - test_read_char_ascii
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:238 - test_read_bool_nonzero_is_true
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:243 - test_read_bool_zero_is_false
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:248 - test_find_sequence_across_data
### tests/test_hexcore_e2e/test_hexpat_data_reader.py:255 - test_find_sequence_not_present_returns_minus_one
### tests/test_hexpat/test_compiler.py:38 - test_compiler_module_lexer_is_shared_lexer
### tests/test_hexpat/test_compiler.py:42 - test_compiler_module_parser_is_shared_parser
### tests/test_hexpat/test_compiler.py:46 - test_compiler_module_token_is_dataclass_with_fields
### tests/test_hexpat/test_compiler.py:54 - test_compiler_module_tokentype_is_shared
### tests/test_hexpat/test_compiler.py:62 - test_compile_round_trips_through_shared_lexer
### tests/test_hexpat/test_compiler.py:69 - test_compile_round_trips_through_shared_parser
### tests/test_hexpat/test_compiler.py:76 - test_compile_to_dict_includes_struct_name
### tests/test_hexpat/test_compiler.py:82 - test_compile_returns_string_with_indent
### tests/test_hexpat/test_compiler.py:95 - test_function_declaration_rejected
### tests/test_hexpat/test_compiler.py:101 - test_namespace_declaration_rejected
### tests/test_hexpat/test_compiler.py:107 - test_using_declaration_rejected
### tests/test_hexpat/test_compiler.py:113 - test_while_inside_struct_rejected
### tests/test_hexpat/test_compiler.py:119 - test_for_inside_struct_rejected
### tests/test_hexpat/test_compiler.py:125 - test_match_inside_struct_rejected
### tests/test_hexpat/test_compiler.py:135 - test_simple_struct_emits_three_fields
### tests/test_hexpat/test_compiler.py:141 - test_array_field_carries_count
### tests/test_hexpat/test_compiler.py:149 - test_endianness_le_be_normalized
### tests/test_hexpat/test_compiler.py:157 - test_enum_emits_values_under_types_key
### tests/test_hexpat/test_compiler.py:168 - test_enum_auto_increment_after_explicit_value
### tests/test_hexpat/test_compiler.py:175 - test_bitfield_fields_emitted
### tests/test_hexpat/test_compiler.py:183 - test_union_emitted_under_types
### tests/test_hexpat/test_compiler.py:190 - test_const_arithmetic_array_size
### tests/test_hexpat/test_compiler.py:201 - test_dollar_in_array_size_rejected
### tests/test_hexpat/test_compiler.py:207 - test_sizeof_in_array_size_rejected
### tests/test_hexpat/test_compiler.py:217 - test_parse_error_translated_to_hexpat_error
### tests/test_hexpat/test_compiler.py:226 - test_no_struct_present_raises_hexpat_error
### tests/test_hexpat/test_compiler.py:235 - test_codegen_can_be_constructed_from_shared_ast
### tests/test_ui/test_realcov_15_dialog_helpers_logging.py:88 - test_show_error_with_exception_logs_error_type
### tests/test_ui/test_realcov_15_dialog_helpers_logging.py:122 - test_show_warning_with_exception_logs_warning_record
### tests/test_ui/test_state_persistence.py:52 - test_save_tab_state_captures_names
### tests/test_ui/test_state_persistence.py:68 - test_save_tab_state_captures_active
### tests/test_ui/test_state_persistence.py:82 - test_save_tab_state_captures_splitter
### tests/test_ui/test_state_persistence.py:101 - test_restore_tab_state_sets_active
### tests/test_ui/test_state_persistence.py:123 - test_restore_tab_state_sets_splitter
### tests/test_ui/test_state_persistence.py:176 - test_has_unsaved_changes_no_editor
### tests/test_ui/test_state_persistence.py:183 - test_save_hex_editor_no_editor
### tests/test_ui/test_state_persistence.py:195 - test_detached_state_persisted
### tests/test_ui/test_state_persistence.py:208 - test_detached_state_empty_initially
### tests/test_ui/test_state_persistence.py:215 - test_detached_state_multiple
### tests/test_ui/test_theme_manager.py:47 - test_get_instance_returns_same_object
### tests/test_ui/test_theme_manager.py:55 - test_reset_instance_clears_singleton
### tests/test_ui/test_theme_manager.py:68 - test_theme_dark_constant
### tests/test_ui/test_theme_manager.py:73 - test_theme_light_constant
### tests/test_ui/test_theme_manager.py:78 - test_default_theme_is_dark
### tests/test_ui/test_theme_manager.py:87 - test_get_dark_stylesheet
### tests/test_ui/test_theme_manager.py:98 - test_get_light_stylesheet
### tests/test_ui/test_theme_manager.py:109 - test_stylesheet_contains_qwidget
### tests/test_ui/test_theme_manager.py:119 - test_stylesheet_contains_colors
### tests/test_ui/test_theme_manager.py:129 - test_stylesheet_cached
### tests/test_ui/test_theme_manager.py:146 - test_apply_theme_returns_bool
### tests/test_ui/test_theme_manager.py:157 - test_apply_dark_theme_succeeds
### tests/test_ui/test_theme_manager.py:168 - test_apply_light_theme_succeeds
### tests/test_ui/test_theme_manager.py:179 - test_apply_theme_updates_current_theme
### tests/test_ui/test_theme_manager.py:207 - test_current_theme_initial_value
### tests/test_ui/test_theme_manager.py:217 - test_current_theme_after_apply
### tests/test_ui/test_theme_manager.py:232 - test_toggle_from_dark_to_light
### tests/test_ui/test_theme_manager.py:245 - test_toggle_from_light_to_dark
### tests/test_ui/test_theme_manager.py:261 - test_get_available_themes_returns_list
### tests/test_ui/test_theme_manager.py:267 - test_available_themes_contains_dark
### tests/test_ui/test_theme_manager.py:273 - test_available_themes_contains_light
### tests/test_ui/test_theme_manager.py:279 - test_available_themes_contains_system
### tests/test_ui/test_theme_manager.py:289 - test_theme_system_constant
### tests/test_ui/test_theme_manager.py:294 - test_resolve_dark_is_identity
### tests/test_ui/test_theme_manager.py:299 - test_resolve_light_is_identity
### tests/test_ui/test_theme_manager.py:304 - test_resolve_invalid_uses_default
### tests/test_ui/test_theme_manager.py:309 - test_resolve_system_returns_concrete_theme
### tests/test_ui/test_theme_manager.py:315 - test_detect_system_theme_returns_concrete
### tests/test_ui/test_theme_manager.py:325 - test_apply_system_succeeds
### tests/test_ui/test_theme_manager.py:336 - test_current_theme_never_reports_system
### tests/test_ui/test_theme_manager.py:348 - test_theme_changed_signal_emits_resolved
### tests/test_ui/test_theme_manager.py:361 - test_system_theme_enables_live_watch
### tests/test_ui/test_theme_manager.py:375 - test_system_theme_responds_to_os_change
### tests/test_ui/test_theme_manager.py:403 - test_explicit_theme_ignores_os_change
### tests/test_ui/test_theme_manager.py:419 - test_dark_fallback_not_empty
### tests/test_ui/test_theme_manager.py:423 - test_light_fallback_not_empty
### tests/test_ui/test_theme_manager.py:428 - test_dark_fallback_contains_widget_styles
### tests/test_ui/test_theme_manager.py:435 - test_light_fallback_contains_widget_styles
### tests/test_ui/test_theme_manager.py:442 - test_dark_fallback_has_dark_colors
### tests/test_ui/test_theme_manager.py:449 - test_light_fallback_has_light_colors
### tests/test_ui/test_theme_manager.py:460 - test_styles_directory_exists
### tests/test_ui/test_theme_manager.py:468 - test_dark_theme_file_exists
### tests/test_ui/test_theme_manager.py:475 - test_light_theme_file_exists
### tests/test_ui/test_theme_manager.py:482 - test_dark_theme_file_not_empty
### tests/test_ui/test_theme_manager.py:490 - test_light_theme_file_not_empty
### tests/test_ui/test_theme_manager.py:498 - test_stylesheet_files_contain_valid_css
### tests/test_ui/test_theme_manager.py:516 - test_styles_available_flag
### tests/test_ui/test_theme_manager.py:525 - test_loaded_stylesheet_matches_file
### tests/test_ui/test_theme_manager.py:539 - test_theme_manager_initialization_no_exceptions
### tests/test_ui/test_tool_panel_detach.py:52 - test_detach_tab
### tests/test_ui/test_tool_panel_detach.py:65 - test_reattach_panel
### tests/test_ui/test_tool_panel_detach.py:81 - test_detach_invalid_index_negative
### tests/test_ui/test_tool_panel_detach.py:91 - test_detach_invalid_index_overflow
### tests/test_ui/test_tool_panel_detach.py:106 - test_detach_current_tab
### tests/test_ui/test_tool_panel_detach.py:121 - test_detach_current_tab_empty
### tests/test_ui/test_tool_panel_detach.py:135 - test_close_other_tabs
### tests/test_ui/test_tool_panel_detach.py:149 - test_close_all_tabs
### tests/test_ui/test_tool_panel_detach.py:167 - test_get_detached_state
### tests/test_ui/test_tool_panel_detach.py:187 - test_find_tab_by_title
### tests/test_ui/test_tool_panel_detach.py:196 - test_find_tab_by_title_missing
### tests/test_ui/test_tool_panel_detach.py:210 - test_tab_bar_movable
### tests/test_ui/test_tool_panel_detach.py:218 - test_tab_context_menu_policy

## Summary

- Findings by severity:
  - Critical: 0
  - High: 0
  - Medium: 2
  - Low: 1

- Total tests audited: 307
- Total tests clean: 304
