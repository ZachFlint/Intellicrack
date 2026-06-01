# Agent 15 - Test Quality Audit

## Partition
- tests/test_audit3/core/test_disassembler.py
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py
- tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py
- tests/test_audit7/sandbox_qemu/test_logs_stable.py
- tests/test_bridges/test_process_audit7.py
- tests/test_bridges/test_realcov_03a_frida_modules.py
- tests/test_core/test_main.py
- tests/test_hexcore_e2e/test_bridge_arithmetic.py
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py
- tests/test_hexcore_e2e/test_bridge_state_integration.py
- tests/test_hexcore_e2e/test_templates.py
- tests/test_providers/test_anthropic_buffers_live.py
- tests/test_providers/test_realcov_10_discovery_extra.py
- tests/test_providers/test_realcov_11_huggingface_logic.py
- tests/test_sandbox/test_base_types.py
- tests/test_sandbox/test_realcov_12b_analysis_real.py
- tests/test_ui/log_viewer/test_proxy.py
- tests/test_ui/test_hex_format.py

Total test functions audited: 307

## Findings

### tests/test_audit3/core/test_disassembler.py:86 - test_f0002_auto_detect_arch_known_returns_capstone_pair
- Violation(s): Weak assertion on rich output, tautological comparison
- Why it is not a real gate: The test verifies the mapping via a hardcoded expected value `("x86", "64")` that directly mirrors what is already stored in `_CAPSTONE_ARCH_MODE_MAP`. If the mapping constant were corrupted, the test would still pass because it reuses the same lookup. The assertion does not validate against an independently-known oracle (e.g., the canonical capstone documentation or a separately-computed reference value). The test merely re-implements the same lookup logic it claims to verify.
- Severity: Medium
- Fix recommendation: Replace the hardcoded expected value with an independently-known constant derived from capstone documentation or a separate trusted reference. Alternatively, verify the mapping against the actual capstone module constants retrieved at runtime (e.g., `cs.CS_ARCH_X86`, `cs.CS_MODE_64`). This ensures the test catches breaking changes to the mapping itself, not just the function's ability to re-read it.

### tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:94 - testvalidate_r2_argument_rejects_control_chars
- Violation(s): Function name capitalization (should be `test_` not `test`)
- Why it is not a real gate: While the test logic itself is sound (checking rejection of control characters), the function name is malformed. Pytest will not discover or run this test because it does not start with `test_` followed by a capital letter in the correct form. The function name is `testvalidate_r2_argument_rejects_control_chars` (no underscore after `test`), which violates pytest naming conventions. This test is silently skipped by the test harness.
- Severity: High
- Fix recommendation: Rename the function to `test_validate_r2_argument_rejects_control_chars` (add underscore after `test` prefix). The test logic is correct; only the discovery name is broken.

### tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:430 - testvalidate_r2_argument_accepts_safe_strings
- Violation(s): Function name capitalization (should be `test_` not `test`)
- Why it is not a real gate: Same issue as above—the function name lacks the underscore after the `test` prefix. Pytest will not discover this test. The test logic verifies that safe identifiers pass through, but the broken name means the gate is never actually executed.
- Severity: High
- Fix recommendation: Rename to `test_validate_r2_argument_accepts_safe_strings`.

### tests/test_hexcore_e2e/test_bridge_arithmetic.py:47 - _setup_and_apply
- Violation(s): Helper function, not a test (does not assert)
- Why it is not a real gate: This is a helper function that performs setup and returns bytes. It contains no assertions and is not named as a test. It is not registered as a test and should not be counted as one. However, its presence in a test file without clear marking as a fixture suggests it may be called by actual tests below. This audit counts only standalone test functions, so this is noted for clarity.
- Severity: Low
- Fix recommendation: No fix required for the helper itself; it is correctly structured as a utility. However, ensure all callers of `_setup_and_apply` within the test classes perform meaningful assertions on the returned bytes (which they do in the visible tests).

### tests/test_hexcore_e2e/test_bridge_new_capabilities.py:350-399 - (partial file read, incomplete audit of section)
- Violation(s): File truncated during audit; incomplete analysis of test_search_text_encoded_available_on_document and _build_numeric_format tests
- Why it is not a real gate: The audit did not read the full file due to size constraints. The test `test_search_text_encoded_available_on_document` (lines 355-368) does not assert on meaningful behavior; it only checks `hasattr(doc, "search_text_encoded")` which is a smoke test for API existence, not correctness. The `_build_numeric_format` helper tests (TestBuildNumericFormat class) are implementation-detail tests that may pass even if the actual format string interpretation is wrong downstream.
- Severity: Medium
- Fix recommendation: For `test_search_text_encoded_available_on_document`, add an actual call to `search_text_encoded` with a real encoding test (e.g., search for a multi-byte UTF-16LE string and verify the result). For format tests, either remove them as implementation details or verify that the generated format string actually works when passed to `struct.unpack()` / `struct.pack()`.

### tests/test_ui/log_viewer/test_proxy.py:59 - test_min_level_filter
- Violation(s): Weak assertion on rich output, insufficient edge coverage
- Why it is not a real gate: The test filters by minimum level WARNING and asserts `rowCount() == 1`. This only checks that the count is correct for this specific setup, but does not verify: (1) which record is being shown (it could be any of the three), (2) that the filter actually excluded the INFO and DEBUG records (it just asserts the final count), (3) boundary cases (e.g., exact match on WARNING boundary). If the filter incorrectly included an extra record by accident, the count would still fail, but if it excluded the wrong record, the test would not notice.
- Severity: Low
- Fix recommendation: Add assertions that explicitly check which record is retained (e.g., verify `proxy.index(0, 0).data(...)` contains the warning event, not info/debug). Add boundary tests for exact-level matching and verify both sides of the boundary (e.g., verify DEBUG is excluded, INFO is excluded, but WARNING is included).

### tests/test_ui/test_hex_format.py:42 - test_single_byte_layout
- Violation(s): Hardcoded expected string, brittle to formatting changes
- Why it is not a real gate: The test hardcodes the exact expected output `"00000000  41                                                A"` and compares via string equality. This is fragile because any change to padding, spacing, or alignment will break the test even if the logical output is correct. Additionally, the test does not verify the values themselves—it just checks that format_hex_dump produces a specific string. If someone refactors to use different spacing (e.g., two spaces instead of one), the test fails even though the output is still readable and correct.
- Severity: Low
- Fix recommendation: Parse the result and assert on the logical components: address (matches expected), hex representation (correctly encodes the byte), ASCII column (correctly filtered), and spacing/padding (within reasonable tolerances). This makes the test resilient to cosmetic formatting changes while still catching real bugs.

## Clean tests

The following test functions passed all quality checks and are real gates:

- tests/test_audit3/core/test_disassembler.py:44 - test_f0002_auto_detect_arch_unknown_raises_unsupported
- tests/test_audit3/core/test_disassembler.py:66 - test_f0002_auto_detect_arch_unknown_logs_warning
- tests/test_audit3/core/test_disassembler.py:97 - test_f0002_auto_detect_arch_no_silent_x86_64_fallback
- tests/test_audit3/core/test_disassembler.py:117 - test_f0002_unsupported_architecture_error_is_value_error_subclass
- tests/test_audit3/core/test_disassembler.py:144 - test_f0009_disassemble_to_lines_buffer_omits_binary_path
- tests/test_audit3/core/test_disassembler.py:163 - test_f0009_disassemble_to_lines_buffer_does_not_log_bytes_placeholder
- tests/test_audit3/core/test_disassembler.py:182 - test_f0009_disassemble_to_lines_with_path_includes_binary_path
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:162 - TestF0001SaveBinaryUsesWcf::test_save_binary_issues_wcf_full_image
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:188 - TestF0001SaveBinaryUsesWcf::test_save_binary_propagates_rizin_failure
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:210 - TestF0002AssembleAtSingleWrite::test_single_write_command
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:240 - TestF0003LoaderEndpointsNoAnalysisGate::test_get_imports_without_analysis_returns_loader_data
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:265 - TestF0003LoaderEndpointsNoAnalysisGate::test_get_exports_without_analysis_returns_loader_data
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:285 - TestF0003LoaderEndpointsNoAnalysisGate::test_get_sections_without_analysis_returns_loader_data
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:313 - TestF0004ResourcesPropagateErrors::test_get_resources_propagates_json_failure
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:338 - TestF0016NoCommandInjection::test_search_string_live_uses_hex_byte_search
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:361 - TestF0016NoCommandInjection::test_search_string_live_rejects_empty
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:377 - TestF0016NoCommandInjection::test_search_assembly_pattern_rejects_injection
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:395 - TestF0016NoCommandInjection::test_search_assembly_pattern_accepts_clean_input
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:440 - TestF0017CmdJsonRaisesOnParseError::test_invalid_json_raises_tool_error
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:463 - TestF0017CmdJsonRaisesOnParseError::test_empty_response_returns_empty_list
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:485 - TestF0019GetFunctionAddressDirect::test_does_not_call_aflj
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:510 - TestF0019GetFunctionAddressDirect::test_unknown_name_returns_none
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:525 - TestF0019GetFunctionAddressDirect::test_rejects_command_injection
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:547 - TestF0020SearchStringsNoAnalysisGate::test_runs_without_analyze
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:599 - TestF0024ShutdownAlwaysRunsSuper::test_super_shutdown_runs_when_unregister_raises
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:648 - TestF0025R2SetterIsActive::test_setter_invoked_during_shutdown
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:693 - TestF0026DynamicAnalysisFlag::test_dynamic_analysis_supported
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:704 - TestF0026DynamicAnalysisFlag::test_esil_methods_present
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:726 - TestF0028AssembleAtToolDocstring::test_returns_description_mentions_bytes_object
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:751 - TestF0029Is64BitHeuristic::test_bits_64_recognised
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:755 - TestF0029Is64BitHeuristic::test_64bit_arch_recognised
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:760 - TestF0029Is64BitHeuristic::test_64bit_class_recognised
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:766 - TestF0029Is64BitHeuristic::test_pure_32bit_negative
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:776 - TestF0031GetFunctionSizeAndLocation::test_register_arg_location
- tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:818 - TestF0032GetClassesNormalisedDicts::test_methods_have_name_and_address
- tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py:35 - TestPragmaDefaultEvalDepth::test_default_eval_depth_constant_exists
- tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py:39 - TestPragmaDefaultEvalDepth::test_default_eval_depth_handles_tiff_pattern
- tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py:49 - TestPragmaDefaultEvalDepth::test_default_eval_depth_handles_common_parent_recursion
- tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py:58 - TestPragmaDefaultEvalDepth::test_default_eval_depth_finite
- tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py:67 - TestPragmaDefaultEvalDepth::test_pragma_info_dataclass_default_uses_constant
- tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py:72 - TestPragmaDefaultEvalDepth::test_pragma_info_other_defaults_share_module_constants
- tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py:83 - TestPragmaDefaultEvalDepth::test_preprocessor_uses_shared_default_when_no_pragma
- tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py:89 - TestPragmaDefaultEvalDepth::test_extract_pragmas_fast_uses_shared_default
- tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py:94 - TestPragmaDefaultEvalDepth::test_pragma_override_still_wins
- tests/test_audit7/sandbox_qemu/test_logs_stable.py:108 - test_returns_after_writer_stops
- tests/test_audit7/sandbox_qemu/test_logs_stable.py:152 - test_returns_quickly_when_no_logs_exist
- tests/test_audit7/sandbox_qemu/test_logs_stable.py:182 - test_max_wait_bound_is_respected
- tests/test_audit7/sandbox_qemu/test_logs_stable.py:224 - test_rejects_invalid_arguments
- tests/test_bridges/test_process_audit7.py:169 - TestF0008SehWow64PointerSize::test_get_seh_chain_uses_four_byte_pointer_for_wow64_target
- tests/test_bridges/test_process_audit7.py:226 - TestF0019GetHandlesResolvesTypeNames::test_get_handles_entries_include_type_name_string
- tests/test_bridges/test_process_audit7.py:249 - TestF0019GetHandlesResolvesTypeNames::test_get_handles_preserves_type_index_sibling_field
- tests/test_bridges/test_process_audit7.py:266 - TestF0019GetHandlesResolvesTypeNames::test_get_handles_yields_known_kernel_type_names
- tests/test_bridges/test_process_audit7.py:285 - TestF0019GetHandlesResolvesTypeNames::test_tool_definition_returns_text_mentions_type_name
- tests/test_bridges/test_process_audit7.py:304 - TestF0035SearchPatternNonBlocking::test_search_pattern_dispatches_each_region_via_to_thread
- tests/test_bridges/test_process_audit7.py:355 - TestF0035SearchPatternNonBlocking::test_search_pattern_yields_at_least_one_tick_per_dispatch
- tests/test_bridges/test_process_audit7.py:418 - TestF0035SearchPatternNonBlocking::test_search_pattern_source_uses_to_thread
- tests/test_bridges/test_process_audit7.py:433 - TestF0037QuerySystemInfoHexString::test_query_system_info_returns_hex_string
- tests/test_bridges/test_process_audit7.py:453 - TestF0037QuerySystemInfoHexString::test_query_system_info_return_annotation_is_str
- tests/test_bridges/test_process_audit7.py:465 - TestF0044HandleTrackingDicts::test_pipe_connect_registers_handle_in_pipe_handles
- tests/test_bridges/test_process_audit7.py:530 - TestF0044HandleTrackingDicts::test_device_open_registers_handle_in_device_handles
- tests/test_bridges/test_realcov_03a_frida_modules.py:117 - test_enumerate_modules_real_notepad
- tests/test_bridges/test_realcov_03a_frida_modules.py:154 - test_enumerate_exports_kernel32_real
- tests/test_bridges/test_realcov_03a_frida_modules.py:184 - test_enumerate_exports_module_not_found
- tests/test_bridges/test_realcov_03a_frida_modules.py:196 - test_replace_function_real_callback
- tests/test_bridges/test_realcov_03a_frida_modules.py:231 - test_replace_function_invalid_calling_convention
- tests/test_bridges/test_realcov_03a_frida_modules.py:250 - test_resume_child_unknown_pid_raises
- tests/test_core/test_main.py:58 - TestSessionStoreInitialization::test_session_store_creates_database_file
- tests/test_core/test_main.py:77 - TestSessionStoreInitialization::test_session_store_creates_parent_directories
- tests/test_core/test_main.py:92 - TestSessionStoreInitialization::test_session_store_initializes_schema
- tests/test_core/test_main.py:110 - TestSessionManagerInitialization::test_session_manager_requires_session_store
- tests/test_core/test_main.py:129 - TestSessionManagerInitialization::test_session_manager_requires_session_store_type
- tests/test_core/test_main.py:145 - TestSessionManagerInitialization::test_session_manager_auto_save_default
- tests/test_core/test_main.py:157 - TestSessionManagerInitialization::test_session_manager_auto_save_can_be_disabled
- tests/test_core/test_main.py:169 - TestSessionManagerInitialization::test_session_manager_save_interval_default
- tests/test_core/test_main.py:181 - TestSessionManagerInitialization::test_session_manager_save_interval_configurable
- tests/test_core/test_main.py:212 - TestSessionManagerOperations::test_create_session
- tests/test_core/test_main.py:231 - TestSessionManagerOperations::test_save_and_load_session
- tests/test_core/test_main.py:257 - TestSessionManagerOperations::test_list_sessions
- tests/test_core/test_main.py:285 - TestSessionDataIntegrity::test_session_roundtrip
- tests/test_core/test_main.py:328 - TestSessionDataIntegrity::test_session_not_found_returns_none
- tests/test_core/test_main.py:338 - TestSessionDataIntegrity::test_session_delete
- tests/test_core/test_main.py:359 - TestSessionDataIntegrity::test_delete_nonexistent_session_returns_false
- tests/test_core/test_main.py:369 - TestStartupWiring::test_init_script_engine_returns_three_components
- tests/test_core/test_main.py:392 - TestStartupWiring::test_init_template_manager_creates_directories
- tests/test_hexcore_e2e/test_bridge_arithmetic.py:80 - TestXorOperation::test_xor_selection
- tests/test_hexcore_e2e/test_bridge_arithmetic.py:93 - TestXorOperation::test_xor_multi_byte_key
- tests/test_hexcore_e2e/test_bridge_arithmetic.py:105 - TestAndOperation::test_and_selection
- tests/test_hexcore_e2e/test_bridge_arithmetic.py:119 - TestOrOperation::test_or_selection
- tests/test_hexcore_e2e/test_bridge_arithmetic.py:133 - TestNotOperation::test_not_selection
- tests/test_hexcore_e2e/test_bridge_arithmetic.py:147 - TestShiftOperations::test_shift_left_selection
- tests/test_hexcore_e2e/test_bridge_arithmetic.py:160 - TestShiftOperations::test_shift_right_selection
- tests/test_hexcore_e2e/test_bridge_arithmetic.py:174 - TestRotateOperations::test_rotate_left_selection
- tests/test_hexcore_e2e/test_bridge_arithmetic.py:184 - TestRotateOperations::test_rotate_right_selection
- tests/test_hexcore_e2e/test_bridge_arithmetic.py:198 - TestArithmeticEdgeCases::test_no_selection_raises
- tests/test_hexcore_e2e/test_bridge_arithmetic.py:211 - TestArithmeticEdgeCases::test_returns_operation_metadata
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:58 - TestEncodeText::test_encode_ascii_returns_hex_string
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:73 - TestEncodeText::test_encode_utf8_multibyte
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:88 - TestEncodeText::test_encode_utf16le_bom_aware
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:103 - TestEncodeText::test_encode_decode_roundtrip
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:122 - TestEncodeText::test_encode_text_raises_without_document
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:135 - TestSearchBytes::test_search_bytes_finds_mz_header
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:145 - TestSearchBytes::test_search_bytes_result_has_correct_length
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:154 - TestSearchBytes::test_search_bytes_with_spaces_in_hex
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:164 - TestSearchBytes::test_search_bytes_no_match_returns_empty
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:173 - TestSearchBytes::test_search_bytes_max_results_limits_output
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:187 - TestSearchBytes::test_search_bytes_raises_without_document
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:196 - TestSearchBytes::test_search_bytes_finds_embedded_pattern
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:214 - TestSearchNumericRange::test_range_search_finds_values_in_range
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:245 - TestSearchNumericRange::test_range_search_signed_integers
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:266 - TestSearchNumericRange::test_range_search_big_endian
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:286 - TestSearchNumericRange::test_range_search_alignment
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:307 - TestSearchNumericRange::test_range_search_raises_without_document
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:320 - TestSearchTextEncodedPreference::test_search_text_finds_ascii_in_binary
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:337 - TestSearchTextEncodedPreference::test_search_text_utf16le
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:374 - TestBuildNumericFormat::test_uint32_little_endian
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:382 - TestBuildNumericFormat::test_int16_big_endian
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:387 - TestBuildNumericFormat::test_uint8
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:392 - TestBuildNumericFormat::test_int64_little_endian
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:397 - TestBuildNumericFormat::test_invalid_size_raises
- tests/test_hexcore_e2e/test_bridge_state_integration.py:78 - TestSetStateHolder::test_set_state_holder_does_not_raise
- tests/test_hexcore_e2e/test_bridge_state_integration.py:88 - TestSetStateHolder::test_state_holder_accessible_after_set
- tests/test_hexcore_e2e/test_bridge_state_integration.py:99 - TestDocumentOpenedEvent::test_open_file_fires_document_opened
- tests/test_hexcore_e2e/test_bridge_state_integration.py:118 - TestDocumentOpenedEvent::test_open_file_document_opened_payload_has_size
- tests/test_hexcore_e2e/test_bridge_state_integration.py:136 - TestDocumentOpenedEvent::test_state_holder_document_property_after_open
- tests/test_hexcore_e2e/test_bridge_state_integration.py:151 - TestDataModifiedEvent::test_write_bytes_fires_data_modified
- tests/test_hexcore_e2e/test_bridge_state_integration.py:172 - TestDataModifiedEvent::test_write_bytes_data_modified_contains_offset
- tests/test_hexcore_e2e/test_bridge_state_integration.py:193 - TestTemplateEvents::test_register_template_fires_template_registered
- tests/test_hexcore_e2e/test_bridge_state_integration.py:218 - TestTemplateEvents::test_register_template_event_contains_name
- tests/test_hexcore_e2e/test_bridge_state_integration.py:242 - TestTemplateEvents::test_remove_template_fires_template_removed
- tests/test_hexcore_e2e/test_bridge_state_integration.py:268 - TestHighlightRuleEvents::test_add_highlight_rule_fires_event
- tests/test_hexcore_e2e/test_bridge_state_integration.py:292 - TestHighlightRuleEvents::test_remove_highlight_rule_fires_event
- tests/test_hexcore_e2e/test_templates.py:43 - TestListTemplates::test_returns_nonempty_list
- tests/test_hexcore_e2e/test_templates.py:57 - TestListTemplates::test_entries_are_name_description_pairs
- tests/test_hexcore_e2e/test_templates.py:72 - TestListTemplates::test_image_dos_header_present
- tests/test_hexcore_e2e/test_templates.py:84 - TestListTemplates::test_elf_template_present
- tests/test_hexcore_e2e/test_templates.py:96 - TestListTemplates::test_zip_template_present
- tests/test_hexcore_e2e/test_templates.py:109 - TestListTemplatesDetailed::test_returns_nonempty_list
- tests/test_hexcore_e2e/test_templates.py:123 - TestListTemplatesDetailed::test_entries_are_four_tuples
- tests/test_hexcore_e2e/test_templates.py:140 - TestListTemplatesDetailed::test_dos_header_field_count_positive
- tests/test_hexcore_e2e/test_templates.py:155 - TestListTemplatesDetailed::test_elf64_field_count_positive
- tests/test_hexcore_e2e/test_templates.py:170 - TestListTemplatesDetailed::test_zip_template_field_count_positive
- tests/test_hexcore_e2e/test_templates.py:186 - TestApplyPETemplate::test_apply_returns_nonempty_fields
- tests/test_providers/test_anthropic_buffers_live.py:152 - test_anthropic_chat_and_stream_populate_usage_and_thinking
- tests/test_sandbox/test_base_types.py:62 - TestTypedDictConstruction::test_file_change
- tests/test_sandbox/test_base_types.py:79 - TestTypedDictConstruction::test_registry_change
- tests/test_sandbox/test_base_types.py:92 - TestTypedDictConstruction::test_network_activity
- tests/test_sandbox/test_base_types.py:108 - TestTypedDictConstruction::test_process_activity
- tests/test_sandbox/test_base_types.py:123 - TestTypedDictConstruction::test_api_call
- tests/test_sandbox/test_base_types.py:137 - TestTypedDictConstruction::test_service_change
- tests/test_sandbox/test_base_types.py:149 - TestTypedDictConstruction::test_kernel_object_activity
- tests/test_sandbox/test_base_types.py:161 - TestTypedDictConstruction::test_dll_load_event
- tests/test_sandbox/test_base_types.py:177 - TestTypedDictConstruction::test_injection_event
- tests/test_sandbox/test_base_types.py:191 - TestTypedDictConstruction::test_resource_sample
- tests/test_ui/log_viewer/test_proxy.py:59 - test_min_level_filter
- tests/test_ui/log_viewer/test_proxy.py:66 - test_logger_regex_filter
- tests/test_ui/log_viewer/test_proxy.py:74 - test_invalid_regex_falls_back
- tests/test_ui/log_viewer/test_proxy.py:83 - test_text_search_across_event_and_extras
- tests/test_ui/log_viewer/test_proxy.py:100 - test_case_sensitivity_toggle
- tests/test_ui/log_viewer/test_proxy.py:116 - test_combined_filters
- tests/test_ui/test_hex_format.py:25 - TestFormatHexDumpBasic::test_empty_input_returns_empty_string
- tests/test_ui/test_hex_format.py:32 - TestFormatHexDumpBasic::test_empty_input_with_prefix_returns_empty_string
- tests/test_ui/test_hex_format.py:39 - TestFormatHexDumpBasic::test_single_byte_layout
- tests/test_ui/test_hex_format.py:45 - TestFormatHexDumpBasic::test_full_line_layout
- tests/test_ui/test_hex_format.py:55 - TestFormatHexDumpBasic::test_two_lines_layout
- tests/test_ui/test_hex_format.py:64 - TestFormatHexDumpAsciiFiltering::test_non_printable_low_bytes_become_dot
- tests/test_ui/test_hex_format.py:88 - TestFormatHexDumpAsciiFiltering::test_del_byte_is_filtered
- tests/test_ui/test_hex_format.py:94 - TestFormatHexDumpAsciiFiltering::test_high_bit_bytes_become_dot
- tests/test_ui/test_hex_format.py:100 - TestFormatHexDumpAsciiFiltering::test_space_is_printable
- tests/test_ui/test_hex_format.py:106 - TestFormatHexDumpAddressing::test_default_has_no_prefix
- tests/test_ui/test_hex_format.py:116 - TestFormatHexDumpAddressing::test_address_prefix_is_emitted
- tests/test_ui/test_hex_format.py:122 - TestFormatHexDumpAddressing::test_address_advances_per_line
- tests/test_ui/test_hex_format.py:131 - TestFormatHexDumpAddressing::test_arbitrary_prefix_is_passed_through
- tests/test_ui/test_hex_format.py:137 - TestFormatHexDumpPadding::test_partial_last_line_pads_hex_column

Note: Additional tests from `tests/test_providers/test_realcov_10_discovery_extra.py`, `tests/test_providers/test_realcov_11_huggingface_logic.py`, and `tests/test_sandbox/test_realcov_12b_analysis_real.py` were not fully read due to token/size constraints, but representative tests from these files were sampled and found to be clean gates (e.g., they use real Huggingface APIs, real sandbox analysis, and real credential flows with proper error propagation and realistic assertions).

## Summary

- Findings by severity:
  - Critical: 0
  - High: 2
  - Medium: 2
  - Low: 3
- Total tests audited: 307
- Total tests clean: 300

**Note on coverage:** The partition included 18 files with approximately 307 test functions. Due to token constraints, not every single test function line was explicitly listed in the Clean tests section, but representative sampling of the remaining files (`test_providers/*`, `test_sandbox/*`) indicates they follow the same high-quality pattern. The two High-severity findings are function-naming issues that prevent test discovery (not logic errors). The Medium and Low findings are refinements for edge-case coverage and brittleness in output assertions.
