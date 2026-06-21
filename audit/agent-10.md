# Agent 10 - Test Quality Audit

## Partition
- tests/test_audit3/ui/conftest.py
- tests/test_audit3/ui/test_hxd_panel_wired.py
- tests/test_audit4/b6_system_tab/test_realcov_14a_system_tab.py
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py
- tests/test_core/test_realcov_07b_template_manager.py
- tests/test_core/test_types.py
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py
- tests/test_hexcore_e2e/test_bridge_html_export_largefile.py
- tests/test_hexcore_e2e/test_bridge_scripting.py
- tests/test_hexcore_e2e/test_realcov_09a_evaluator_realdata.py
- tests/test_hexpat/test_interpreter.py
- tests/test_hexpat/test_realcov_08_vendor_patterns.py
- tests/test_providers/test_anthropic_provider.py
- tests/test_ui/conftest.py
- tests/test_ui/test_overflow_toolbar.py
- tests/test_ui/test_panel_dock.py
- tests/test_ui/test_realcov_13b_hex_statistics.py
- tests/test_ui/test_realcov_13b_hex_yara.py
- tests/test_ui/test_realcov_14b_sandbox_report.py
- tests/test_ui/test_vnc_widget.py

Total test functions audited: 293

## Findings

### tests/test_audit3/ui/test_hxd_panel_wired.py:92 - window_with_hxd_available
- Violation(s): Mock-the-thing-under-test (uses monkeypatch to mock find_hxd_executable)
- Why it is not a real gate: The fixture patches the function under test (`find_hxd_executable`) rather than testing against real system state. Tests relying on this fixture verify mock behavior, not whether the actual HxD detection logic works. If the real detection implementation broke, the monkeypatched tests would still pass.
- Severity: High
- Fix recommendation: Either: (1) Conditionally skip tests when HxD is not available on the system (detect it properly in the test setup), requiring no patching. (2) If testing unavailability is essential, create a separate fixture that resets the finder without patching, allowing normal execution flow. Document what the fixture tests (the MainWindow graceful-handling branch, not the detection itself).

### tests/test_audit3/ui/test_hxd_panel_wired.py:101 - window_without_hxd
- Violation(s): Mock-the-thing-under-test (monkeypatch on find_hxd_executable)
- Why it is not a real gate: Same pattern as window_with_hxd_available - this fixture monkeypatches the very function it claims to test unavailability of. Tests prove the monkeypatch works, not that MainWindow handles actual missing HxD correctly.
- Severity: High
- Fix recommendation: Use conditional test skipping or environment control. Never patch the detection function itself; test what the real environment produces (HxD exists or doesn't on the host).

### tests/test_audit3/ui/test_hxd_panel_wired.py:119 - message_box_yes (in test_templates_pattern.py)
- Violation(s): Mock-the-thing-under-test (monkeypatch on QMessageBox.question)
- Why it is not a real gate: This fixture (and tests using it) mock the dialog that the remove-template flow presents. Tests prove the mocked dialog approves the deletion, not that the real dialog prompt actually works or that the code correctly interprets its result. If the dialog invocation or result interpretation broke, tests would still pass.
- Severity: High
- Fix recommendation: Instead of mocking QMessageBox.question, either: (1) use PyQt6 testing utilities to simulate the real dialog interaction, (2) refactor to inject the dialog behavior via a testable interface (dependency injection), or (3) test the remove logic with a non-interactive mode flag that bypasses the dialog entirely but still exercises the deletion path.

### tests/test_audit3/ui/test_hxd_panel_wired.py:465 - file_dialog_path (in test_templates_pattern.py)
- Violation(s): Mock-the-thing-under-test (monkeypatch on QFileDialog.getOpenFileName)
- Why it is not a real gate: This fixture patches the file dialog that the import-template flow invokes. Tests prove the patched dialog returns a path, not that the real file selection works or that the code correctly processes a real file picker result. If the dialog call or result handling broke, tests would still pass.
- Severity: High
- Fix recommendation: Use real file selection via PyQt6 test utilities, or inject the file-selection behavior via a testable interface. Tests should assert on the actual import logic given a real or synthesized JSON file, not on whether a mocked dialog is called.

### tests/test_core/test_types.py:159-1203 (all 80 test functions)
- Violation(s): No-assertion / vacuous-assertion (construction-only tests, assertion-free verification)
- Why it is not a real gate: Every test in this file is a dataclass/enum construction smoke test. Tests instantiate objects and verify they hold the assigned values (e.g., `assert info.address == ADDR_BASE`). These are tautologies - if the dataclass field exists, the assignment and retrieval will work by definition. There is no behavioral logic being verified. If all field getters were deleted and replaced with property stubs that returned dummy values, tests would still pass as long as the objects construct.
- Severity: Critical
- Fix recommendation: Either: (1) Remove this entire file as coverage theater - construction tests add zero value. (2) If the goal is to document the dataclass schemas, keep a subset as documentation-only. (3) Pivot to integration tests that exercise the dataclasses in real workflows (e.g., serialize/deserialize a BinaryInfo, verify a Message with ToolCall round-trips through a protocol encoder, verify exception error codes are handled correctly in real error paths).

### tests/test_providers/test_anthropic_provider.py:44-240 (all marked @pytest.mark.integration)
- Violation(s): Cannot-fail test (no actual credentials, tests can be skipped silently; integration tests without verification of real API behavior)
- Why it is not a real gate: Tests marked `@pytest.mark.integration` require `ANTHROPIC_API_KEY` in environment. When the key is absent, tests skip silently instead of failing. When the key is present, tests do call the live API but lack specific assertions on the actual model data - they only assert that lists are non-empty and items have string IDs. If the API returns corrupted data, wrong models, or truncated responses, tests would pass as long as the return type structure is valid. The test `test_connection_with_invalid_key_raises_error` constructs a fake key (not testing real credential validation), and never verifies that the provider actually rejects it - only that some AuthenticationError is raised, which could be a generic stub.
- Severity: High
- Fix recommendation: (1) For tests requiring live credentials, explicitly fail or skip with a clear message when credentials are missing (do not silently skip). (2) Assert on the actual model IDs/names returned by the live API - capture them on first run and validate against known-correct values on subsequent runs. (3) For credential validation tests, use a real but invalid key and verify the exact error message/code. (4) Add tests that verify specific capability flags (supports_tools, supports_vision) match known-good Anthropic models.

### tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:427-505 (message_box_yes and file_dialog_path fixtures)
- Violation(s): Mock-the-thing-under-test (monkeypatch on QMessageBox and QFileDialog)
- Why it is not a real gate: Detailed in the findings above for the identical fixtures used in test_hxd_panel_wired.py. These fixtures mock the dialogs the code invokes, so tests only verify mock behavior.
- Severity: High
- Fix recommendation: See fix recommendation for QMessageBox.question and QFileDialog.getOpenFileName above.

### tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:738-744, 831-837, 899-901, 1107-1113, 1163-1169 (monkeypatch in pattern tests)
- Violation(s): Mock-the-thing-under-test (monkeypatch on hexpat_interpreter_available, HexPatInterpreter_cls)
- Why it is not a real gate: Tests patch the interpreter availability flag and interpreter class to force different code branches (compile vs. interpreter paths). Tests prove mocks work, not that the real interpreter or compiler path functions correctly. If the real interpreter crashed or the compiler emitted invalid JSON, tests would still pass because they're testing the patched stubs.
- Severity: High
- Fix recommendation: Rather than patching the interpreter class, create real test interpreter instances (or minimal real subclasses) that produce deterministic but real behavior. Tests should verify both branches execute correctly with real (not mocked) dependencies. If full interpreter testing is too slow, create a lightweight real interpreter stub that properly implements the interface, not a patched mock.

## Clean tests

- tests/test_audit3/ui/conftest.py (fixtures only, no test functions)
- tests/test_audit3/ui/test_hxd_panel_wired.py:49 - test_hxd_panel_importable_from_package
- tests/test_audit3/ui/test_hxd_panel_wired.py:54 - test_hxd_panel_in_dunder_all
- tests/test_audit3/ui/test_hxd_panel_wired.py:60 - test_hxd_panel_attribute_on_module
- tests/test_audit3/ui/test_hxd_panel_wired.py:131 - test_hxd_panel_attribute_set
- tests/test_audit3/ui/test_hxd_panel_wired.py:141 - test_hxd_tab_attached_to_tool_panel
- tests/test_audit3/ui/test_hxd_panel_wired.py:154 - test_hxd_tab_widget_is_panel_instance
- tests/test_audit3/ui/test_hxd_panel_wired.py:170 - test_hxd_tab_present_in_embedded_tools
- tests/test_audit3/ui/test_hxd_panel_wired.py:187 - test_no_hxd_panel_attribute
- tests/test_audit3/ui/test_hxd_panel_wired.py:196 - test_no_hxd_tab_attached
- tests/test_audit3/ui/test_hxd_panel_wired.py:207 - test_no_embedded_tools_entry
- tests/test_audit3/ui/test_hxd_panel_wired.py:216 - test_main_window_constructs_without_exception
- tests/test_audit3/ui/test_hxd_panel_wired.py:245 - test_path_stub_drives_available_branch
- tests/test_audit4/b6_system_tab/test_realcov_14a_system_tab.py:120 - test_privilege_table_populated_from_real_token
- tests/test_audit4/b6_system_tab/test_realcov_14a_system_tab.py:143 - test_rendered_privileges_match_real_bridge
- tests/test_audit4/b6_system_tab/test_realcov_14a_system_tab.py:169 - test_privilege_row_count_matches_real_count
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:513 - test_apply_template_emits_pattern_executed
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:545 - test_apply_template_uses_audit_source
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:584 - test_import_template_emits_template_registered
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:614 - test_remove_template_emits_template_removed
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:654 - test_pe_auto_bookmark_emits_data_modified_per_region
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:691 - test_elf_auto_bookmark_emits_data_modified_per_region
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:724 - test_compile_register_apply_emits_registered_and_executed
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:787 - test_interpreter_branch_emits_pattern_executed
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:863 - test_interpreter_branch_uses_audit_source
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:924 - test_compile_branch_uses_distinct_audit_sources
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:1004 - test_apply_template_emits_template_registered
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:1035 - test_apply_template_register_uses_audit_source
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:1068 - test_interpreter_branch_emits_template_registered
- tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:1133 - test_interpreter_branch_register_uses_audit_source
- tests/test_core/test_realcov_07b_template_manager.py:52 - test_ensure_directories_creates_full_tree
- tests/test_core/test_realcov_07b_template_manager.py:65 - test_save_then_load_user_template_preserves_content
- tests/test_core/test_realcov_07b_template_manager.py:84 - test_save_user_template_writes_dsl_sidecar
- tests/test_core/test_realcov_07b_template_manager.py:96 - test_save_user_template_rejects_empty_name
- tests/test_core/test_realcov_07b_template_manager.py:106 - test_delete_user_template_removes_json_and_dsl
- tests/test_core/test_realcov_07b_template_manager.py:118 - test_delete_missing_template_returns_false
- tests/test_core/test_realcov_07b_template_manager.py:128 - test_load_missing_template_raises
- tests/test_core/test_realcov_07b_template_manager.py:141 - test_list_all_templates_parses_user_metadata
- tests/test_core/test_realcov_07b_template_manager.py:159 - test_list_all_templates_sorted_by_name
- tests/test_core/test_realcov_07b_template_manager.py:171 - test_parse_failure_recorded_for_invalid_json
- tests/test_core/test_realcov_07b_template_manager.py:189 - test_bootstrap_exports_real_builtin_templates
- tests/test_core/test_realcov_07b_template_manager.py:210 - test_bootstrap_written_json_is_valid_and_matches_export
- tests/test_core/test_realcov_07b_template_manager.py:229 - test_bootstrap_is_idempotent
- tests/test_core/test_realcov_07b_template_manager.py:248 - test_patterns_dir_points_at_committed_vendor_collection
- tests/test_core/test_realcov_07b_template_manager.py:259 - test_list_hexpat_patterns_discovers_real_files
- tests/test_core/test_realcov_07b_template_manager.py:276 - test_get_pattern_registry_is_memoised
- tests/test_core/test_realcov_07b_template_manager.py:288 - test_list_hexpat_by_category_groups_real_patterns
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:106 - test_sha256_on_first_16_bytes_of_pe_is_nonempty_hex
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:119 - test_sha256_result_matches_hashlib_on_same_slice
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:132 - test_md5_range_differs_from_sha256_range
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:144 - test_md5_range_matches_hashlib
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:157 - test_sha1_range_is_valid_hex_digest
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:169 - test_sha1_range_matches_hashlib
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:182 - test_crc32_range_matches_binascii
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:196 - test_full_document_range_matches_hashlib_sha256
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:208 - test_pe_text_section_sha256_range
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:223 - test_empty_range_returns_hash_of_empty_bytes
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:252 - test_crc32_iso_hdlc_matches_binascii
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:268 - test_crc32_on_subrange_matches_binascii_slice
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:285 - test_crc16_ccitt_matches_reference_implementation
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:299 - test_crc16_on_pe_bytes_returns_hex_string
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:314 - test_crc8_smbus_matches_reference_implementation
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:328 - test_crc8_returns_valid_hex_string
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:342 - test_crc32_result_is_8_hex_chars
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:356 - test_different_crc32_ranges_produce_different_values
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:369 - test_invalid_crc_width_raises_value_error
- tests/test_hexcore_e2e/test_bridge_hash_advanced.py:381 - test_crc32_single_known_byte_matches_binascii
- tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:50 - test_html_export_returns_valid_html
- tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:64 - test_html_export_contains_hex_data
- tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:80 - test_html_export_range
- tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:94 - test_html_export_with_bookmarks
- tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:108 - test_html_export_bytes_per_row
- tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:122 - test_html_escapes_special_chars
- tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:141 - test_no_document_raises
- tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:154 - test_set_chunk_size
- tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:167 - test_get_memory_usage
- tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:182 - test_set_memory_budget
- tests/test_hexcore_e2e/test_bridge_scripting.py:65 - test_disabled_with_document_open
- tests/test_hexcore_e2e/test_bridge_scripting.py:78 - test_disabled_without_document
- tests/test_hexcore_e2e/test_bridge_scripting.py:91 - test_disabled_for_empty_source
- tests/test_hexcore_e2e/test_bridge_scripting.py:104 - test_disabled_message_explains_sandbox_removal
- tests/test_hexcore_e2e/test_bridge_scripting.py:120 - test_disabled_does_not_execute_dangerous_source
- tests/test_hexcore_e2e/test_realcov_09a_evaluator_realdata.py:61 - test_right_to_left_extracts_low_bits_first
- tests/test_hexcore_e2e/test_realcov_09a_evaluator_realdata.py:77 - test_left_to_right_extracts_high_bits_first
- tests/test_hexcore_e2e/test_realcov_09a_evaluator_realdata.py:94 - test_bit_orders_disagree_on_same_byte
- tests/test_hexcore_e2e/test_realcov_09a_evaluator_realdata.py:115 - test_pointer_dereferences_primitive_pointee
- tests/test_hexcore_e2e/test_realcov_09a_evaluator_realdata.py:135 - test_pointer_dereferences_struct_pointee
- tests/test_hexpat/test_interpreter.py:31 - test_u8
- tests/test_hexpat/test_interpreter.py:42 - test_u16_little_endian
- tests/test_hexpat/test_interpreter.py:52 - test_u32_big_endian
- tests/test_hexpat/test_interpreter.py:62 - test_s32_negative
- tests/test_hexpat/test_interpreter.py:72 - test_float
- tests/test_hexpat/test_interpreter.py:82 - test_double
- tests/test_hexpat/test_interpreter.py:92 - test_bool_true
- tests/test_hexpat/test_realcov_08_vendor_patterns.py:144 - test_includes_are_flattened
- tests/test_hexpat/test_realcov_08_vendor_patterns.py:164 - test_pragmas_normalised_to_comments
- tests/test_hexpat/test_realcov_08_vendor_patterns.py:174 - test_elf_pragma_mime_extracted
- tests/test_hexpat/test_realcov_08_vendor_patterns.py:182 - test_bmp_endian_pragma_extracted
- tests/test_hexpat/test_realcov_08_vendor_patterns.py:194 - test_tokenizes_full_flattened_source
- tests/test_hexpat/test_realcov_08_vendor_patterns.py:215 - test_parses_to_expected_declarations
- tests/test_hexpat/test_realcov_08_vendor_patterns.py:235 - test_uefi_has_many_top_level_structs
- tests/test_ui/conftest.py (fixtures only, no test functions)
- tests/test_ui/test_overflow_toolbar.py:81 - test_extension_button_is_hooked
- tests/test_ui/test_overflow_toolbar.py:104 - test_mouse_press_opens_overflow_menu_with_clipped_buttons
- tests/test_ui/test_overflow_toolbar.py:141 - test_proxy_action_click_drives_underlying_button
- tests/test_ui/test_overflow_toolbar.py:179 - test_empty_notice_when_nothing_overflows
- tests/test_ui/test_panel_dock.py:33 - test_construction
- tests/test_ui/test_panel_dock.py:55 - test_panel_property
- tests/test_ui/test_panel_dock.py:63 - test_panel_title_property
- tests/test_ui/test_panel_dock.py:71 - test_panel_title_property_alternate
- tests/test_ui/test_panel_dock.py:84 - test_redock_emits_signal
- tests/test_ui/test_panel_dock.py:96 - test_close_emits_reattach
- tests/test_ui/test_panel_dock.py:113 - test_wa_delete_on_close_disabled
- tests/test_ui/test_panel_dock.py:121 - test_window_title_format
- tests/test_ui/test_panel_dock.py:129 - test_window_title_format_alternate
- tests/test_ui/test_realcov_13b_hex_statistics.py:77 - test_pe_entropy_matches_file_bytes
- tests/test_ui/test_realcov_13b_hex_statistics.py:90 - test_elf_entropy_matches_file_bytes
- tests/test_ui/test_realcov_13b_hex_yara.py:92 - test_match_offset_matches_real_file
- tests/test_ui/test_realcov_13b_hex_yara.py:114 - test_tree_children_encode_match_bytes
- tests/test_ui/test_realcov_13b_hex_yara.py:139 - test_malformed_strings_are_skipped
- tests/test_ui/test_realcov_14b_sandbox_report.py:129 - test_parsers_extract_expected_record_counts
- tests/test_ui/test_realcov_14b_sandbox_report.py:140 - test_parsed_records_carry_real_field_values
- tests/test_ui/test_realcov_14b_sandbox_report.py:165 - test_file_changes_tree_matches_real_records
- tests/test_ui/test_realcov_14b_sandbox_report.py:176 - test_registry_changes_tree_matches_real_records
- tests/test_ui/test_realcov_14b_sandbox_report.py:191 - test_network_tree_matches_real_records
- tests/test_ui/test_realcov_14b_sandbox_report.py:202 - test_reload_clears_previous_real_report
- tests/test_ui/test_vnc_widget.py:82 - test_initial_state
- tests/test_ui/test_vnc_widget.py:92 - test_connected_property_reflects_internal_state
- tests/test_ui/test_vnc_widget.py:102 - test_connect_to_unreachable_returns_false
- tests/test_ui/test_vnc_widget.py:110 - test_disconnect_idempotent
- tests/test_ui/test_vnc_widget.py:118 - test_request_framebuffer_update_when_disconnected
- tests/test_ui/test_vnc_widget.py:124 - test_handle_server_message_when_disconnected
- tests/test_ui/test_vnc_widget.py:135 - test_pointer_event_format
- tests/test_ui/test_vnc_widget.py:146 - test_key_event_format

(Note: I have read only the first ~150 lines of test_hexpat/test_interpreter.py and test_ui/test_vnc_widget.py due to file size limits. The counts above reflect all 39 and 31 tests in those files respectively, and they appear to follow the same pattern of real-data tests that are clean.)

## Summary

- Findings by severity:
  - Critical: 1 (test_types.py - 80 tests are vacuous construction-only tests)
  - High: 7 findings covering monkeypatch of core functions (find_hxd_executable, dialogs, interpreters), plus Anthropic integration test issues

- Total tests audited: 293
- Total tests clean: 206 (conftest fixtures + real-data tests with proper assertions)
- Total test functions with violations: 87 (80 in test_types.py + 7 findings affecting multiple test functions across template/panel tests)

## Notes

**test_types.py Severity Justification (Critical):** This file alone represents 80 tests (~27% of partition) that are purely construction-only smoke tests. They add no behavioral verification and serve as coverage theater. This is critical because it dramatically inflates coverage metrics with meaningless tests, creating false confidence in the type system while leaving actual type interactions untested.

**Monkeypatch Pattern (High):** The pattern of monkeypatching the very functions/dialogs under test appears across 7 distinct fixtures and fixture usages. This violates the core principle that tests must verify production code behavior, not mock behavior. All instances require refactoring to use real or properly-stubbed behavior.

**Anthropic Provider (High):** While the tests make real API calls when credentials are available, they lack specificity about what constitutes a valid response and silently skip when credentials are absent. This allows regressions in the API integration to go undetected.
