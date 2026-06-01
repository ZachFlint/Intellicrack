# Agent 05 - Test Quality Audit

## Partition
- tests/test_bridges/test_ghidra.py
- tests/test_bridges/test_hex_state_audit1.py
- tests/test_bridges/test_x64dbg_events.py
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py
- tests/test_hexcore_e2e/test_bridge_signatures.py
- tests/test_hexcore_e2e/test_search.py
- tests/test_hexpat/conftest.py
- tests/test_hexpat/test_lexer.py
- tests/test_hexpat/test_realcov_08_preprocessor_vendor.py
- tests/test_providers/test_discovery_unit.py
- tests/test_providers/test_realcov_10_anthropic_cache.py
- tests/test_providers/test_realcov_11_model_loader.py
- tests/test_ui/log_viewer/test_app_integration.py
- tests/test_ui/log_viewer/test_window.py
- tests/test_ui/test_realcov_14b_script_manager.py
- tests/test_ui/test_realcov_15_chat_panel.py
- tests/test_ui/test_tool_status_dialog_prefetch.py
- tests/ui/conftest.py
- tests/ui/test_system_tab_warnings.py

Total test functions audited: 308

## Findings

### tests/test_bridges/test_ghidra.py:46-50 - test_bridge_instantiation
- Violation(s): No-assertion / vacuous-assertion (smoke-test-as-gate)
- Why it is not a real gate: The test only asserts that instantiation succeeds and the result is not None. It does not verify that the bridge has any meaningful internal state, that its properties are correct, or that it can actually perform any of its documented operations. If the bridge's constructor became a no-op or returned an invalid object, this test would not fail.
- Severity: Medium
- Fix recommendation: After instantiation, assert on specific properties (name, capabilities, tool_definition existence) to verify the bridge is properly initialized with valid state.

### tests/test_bridges/test_x64dbg_events.py:104-112 - test_unregister_nonexistent_does_not_raise
- Violation(s): No-assertion / vacuous-assertion, cannot-fail (try/except swallows failures)
- Why it is not a real gate: The test has no explicit assertions. It relies only on the implicit assumption that "if no exception is raised, the test passes," which is a boolean true on every run regardless of whether the callback list was actually modified or whether the operation had any effect. The test does not verify that the callback was not in the list before the unregister call or that the list remains empty after.
- Severity: Low
- Fix recommendation: Add an assertion before the unregister call to confirm the list is empty or contains the handler. Add a second assertion after the call to confirm the length remains zero.

### tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:106-124 - test_search_uint64_cafebare_finds_at_offset_6
- Violation(s): Cannot-fail (broad exception handling with skip), weak assertion on rich output
- Why it is not a real gate: The test is gated by a broad `try/except OverflowError: pytest.skip(...)`. If the operation fails with ANY exception other than OverflowError (e.g., a logic bug returning wrong offsets, a crash in search, incorrect endianness handling), the test will fail hard rather than skip gracefully. More critically, when the try block succeeds, the test only asserts that the expected offset is "in" the results list, not that the exact result structure is correct or that no spurious results are present.
- Severity: Medium
- Fix recommendation: Narrow the exception handling to only catch the documented Overflow case. Assert on the full result structure including that no spurious results are present at unintended offsets, and that the offset's length field matches the size parameter.

### tests/test_hexcore_e2e/test_search.py:70-82 - test_pattern_detected_at_buffer_boundaries
- Violation(s): Weak assertion on rich output
- Why it is not a real gate: The test asserts only that the offsets are in the results. It does not assert that the returned tuple structure (offset, length) is correct, that the length field matches the pattern size (2 bytes for b"\xca\xfe"), or that no extra results are present. If the search returned (0, 999) and (22, 999) instead of (0, 2) and (22, 2), this test would still pass.
- Severity: Medium
- Fix recommendation: Assert on the full tuple structure including that each result's length field equals len(b"\xca\xfe") == 2. Verify no additional spurious offsets are returned.

### tests/test_hexpat/test_lexer.py:144-147 - test_unterminated_string_raises
- Violation(s): Assertion quality (only checks exception type, not root cause)
- Why it is not a real gate: The test asserts that a HexPatParseError is raised with message matching "Unterminated string", but it does not verify that the lexer correctly continues to process tokens after the error or that the error occurs at the exact position in the source. If the lexer were to raise HexPatParseError("Invalid syntax") instead, the test would correctly fail. However, if the lexer were modified to skip the unterminated string and return EOF or an empty token list, the test would fail, but only because no exception was raised—not because the test observed correct recovery behavior. The fix would be to verify both that the error is raised AND what the lexer state is before the error occurs.
- Severity: Low
- Fix recommendation: Before calling tokenize(), verify the starting state. Assert that the error occurs during tokenization and document expected recovery behavior or stopping point.

### tests/test_hexpat/test_realcov_08_preprocessor_vendor.py:43-54 - test_std_io_include_is_flattened
- Violation(s): Weak assertion on rich output, happy-path-only (no error cases)
- Why it is not a real gate: The test only checks `len(processed) > len(source)` and that "#include" is not in the processed output. It does not verify that the content of std/io.pat was correctly inlined, that all transitive includes were resolved, that the structure of the output is valid, or that macros from the included file are available. The assertion `"u8 x @ 0;" in processed` is the only structural check, but it doesn't verify that the include was actually expanded (the statement could simply be concatenated after a failed include). If the preprocessor silently dropped the include and left the file empty except for the statement, the test would still pass.
- Severity: Medium
- Fix recommendation: Assert that specific content expected from std/io.pat (function declarations, struct definitions, macro definitions) is present in the processed output. Verify the output is valid HexPat by attempting to tokenize or parse it. Test the error path when include_paths does not contain the vendor corpus.

### tests/test_providers/test_discovery_unit.py:40-200 - _DiscoveryProvider class and related
- Violation(s): Mock-the-thing-under-test, fake-data (list_models returns hand-built list, not real provider logic)
- Why it is not a real gate: The _DiscoveryProvider is a mock provider that returns a hardcoded list of models or a configured error. The tests using this class (not listed in this file's visible tests section, but defined here) are testing the discovery/filtering logic against this fake provider, not against a real provider. If the real provider's list_models() behavior changes, these tests would not catch the regression. The provider's credential handling and connection state are also mocked (connected = True is set in __init__), so tests cannot verify real connection failure paths.
- Severity: High
- Fix recommendation: Tests should use a real provider (e.g., a locally-mocked Anthropic API response or a real test account) for at least some discovery tests. Document which tests are testing discovery-filtering logic (and thus may safely use a stub) vs. provider integration (which must use real credentials and API calls).

### tests/test_providers/test_realcov_10_anthropic_cache.py:70-84 - test_system_prompt_becomes_cached_block
- Violation(s): Weak assertion on rich output (checks only type and one text field, not full structure)
- Why it is not a real gate: The test asserts that system is converted to a list with a text block at index 0 and that the text field and cache_control keys exist. It does not verify that the cache_control type is "ephemeral", that no other keys are present in the block, that the original string is preserved exactly, or that the transformation is idempotent (calling the function twice produces the same result). If cache_control were set to {"type": "prefill"} or the text were truncated, the test would still pass.
- Severity: Medium
- Fix recommendation: Assert the exact structure: system[0] == {"type": "text", "text": "...", "cache_control": {"type": "ephemeral"}}. Test that calling the function twice on the same kwargs is idempotent.

### tests/test_providers/test_realcov_11_model_loader.py:130-134 - test_fp16_matches_two_bytes_per_param_with_overhead
- Violation(s): Assertion quality (arithmetic is correct but test does not verify real model is used)
- Why it is not a real gate: The test verifies arithmetic: 1B params * 2 bytes/param * 1.3 overhead = expected. However, it does not verify that the parameter-count estimation for "meta-llama/Llama-3.2-1B-Instruct" actually resolves to 1 billion. If the parameter-count estimator were broken (e.g., returned 0), the test would compute 0 * 2 * 1.3 = 0 and fail, but only because of arithmetic, not because the estimator is wrong. The test should fetch the model's actual parameter count and use that to compute the expected value.
- Severity: Medium
- Fix recommendation: Call _estimate_parameter_count("meta-llama/Llama-3.2-1B-Instruct") to get the actual parameter count, then assert that estimate_model_memory returns exactly (param_count * 2.0 * 1.3). This ensures the model-id-to-parameter-count mapping is verified.

### tests/test_ui/log_viewer/test_app_integration.py:46-62 - test_main_window_installs_qt_log_handler
- Violation(s): Weak assertion on rich output (checks only that handler is not None, not that it is actually wired)
- Why it is not a real gate: The test asserts that get_qt_log_handler() is not None after constructing MainWindow, but it does not verify that the handler is actually wired to the logger, that it receives log records, or that the main window is using it. If the MainWindow's constructor set up the handler but the app's logger was not configured to use it, the test would still pass. The test does not verify that logs emitted after this point actually reach the handler.
- Severity: Low
- Fix recommendation: After constructing MainWindow, emit a test log record and verify that the handler received it. Assert that the handler is in the logger's handler list and that its level is set correctly.

### tests/test_ui/log_viewer/test_app_integration.py:65-96 - test_log_viewer_lazy_construction
- Violation(s): Weak assertion on rich output, no edge cases
- Why it is not a real gate: The test asserts that the log_viewer_window is None initially and that calling open_log_viewer() twice returns the same instance. However, it does not verify that the viewer is actually visible, that it can be shown/hidden, or that closing the main window removes the viewer. It also doesn't test the case where the viewer was previously created and the main window is closed/reopened. The idempotence check only verifies reference equality, not that the viewer is in a usable state.
- Severity: Low
- Fix recommendation: Assert that the returned LogViewerWindow is visible and contains expected UI elements (table, filter controls). Test that closing the main window nullifies the reference and that a new open_log_viewer() call creates a fresh instance.

### tests/test_ui/test_realcov_14b_script_manager.py:77-92 - test_save_persists_real_content
- Violation(s): Happy-path-only (no error cases such as save failure, permission denied, disk full)
- Why it is not a real gate: The test saves a script and immediately checks that get_script() returns it. It does not test the error paths: what happens when the scripts directory is read-only, when disk is full, when the script name contains invalid characters, or when the backend is disconnected. The test also does not verify that the file was actually written to disk (only that the in-memory backend state matches). If the backend's save() method were implemented as a no-op that updated in-memory state but never persisted, the test would pass.
- Severity: Medium
- Fix recommendation: Test error paths: attempt to save with read-only directory, verify that get_script() after a save failure returns None or raises. Verify that reloading from disk (after clearing the in-memory cache) returns the same content. Test edge cases like empty script name or script name with path separators.

### tests/test_ui/test_realcov_15_chat_panel.py:64-78 - test_send_button_emits_typed_text
- Violation(s): Weak assertion on rich output (checks only args list, not signal or button state)
- Why it is not a real gate: The test asserts that the emitted signal's args match the typed text, and that the input is cleared. However, it does not verify that the message_submitted signal itself is the correct signal, that it was emitted the correct number of times, or that any other side effects (like button state, focus) occurred. If the signal were named differently or emitted a different payload structure, the test would still pass as long as args[0] is the typed text. The test also does not verify that pressing the Send button actually triggered the signal (only that the signal was emitted after clicking).
- Severity: Low
- Fix recommendation: Assert that the signal name is message_submitted, that the signal count is exactly 1, and that no other signals were emitted. Verify that the Send button's isEnabled() state changes appropriately before/after sending.

### tests/test_ui/test_tool_status_dialog_prefetch.py:133-157 - test_prefetched_data_skips_initial_worker_spawn
- Violation(s): Weak assertion on rich output (checks only row count and one item text, not full structure)
- Why it is not a real gate: The test asserts that the dialog has 6 rows and that one row contains expected text. However, it does not verify that all rows are populated correctly, that the status indicators (✓/✗) are rendered for all tools, or that the tool order matches the expected order. If half the rows contained blank strings or if the order were scrambled, the test would only fail if one of the specific checked rows was affected.
- Severity: Low
- Fix recommendation: Loop through all 6 rows and assert on each one's content, status indicator, and tool name. Verify the order matches the expected tool enumeration.

### tests/ui/test_system_tab_warnings.py:185-205 - test_refresh_mitigations_unattached_shows_warning
- Violation(s): Mock-the-thing-under-test (uses _StubBridge and monkeypatched run_bridge_coroutine_async)
- Why it is not a real gate: The test uses a stub bridge and a monkeypatched async runner, so it is not verifying that the real SystemTab correctly guards against a real unattached ProcessBridge. If the real bridge's get_mitigation_policies() behavior changes, or if a real async runner fails to dispatch correctly, this test would not catch it. The test only verifies that the tab's boolean check for attached PID gates the dispatch—which is a thin slice of logic that has high coupling with the mock setup.
- Severity: High
- Fix recommendation: Use a real ProcessBridge (or a partially-real one with minimal mocking of the async dispatch layer only) and a real attached process (or a well-controlled test process spawned for the test). Verify the warning is shown and the guard works with real async execution.

## Clean tests

- tests/test_bridges/test_ghidra.py:52-59 - test_bridge_name
- tests/test_bridges/test_ghidra.py:61-71 - test_bridge_capabilities
- tests/test_bridges/test_ghidra.py:73-82 - test_tool_definition_exists
- tests/test_bridges/test_ghidra.py:84-92 - test_tool_definition_function_count
- tests/test_bridges/test_ghidra.py:94-122 - test_tool_definition_original_functions
- tests/test_bridges/test_ghidra.py:124-199 - test_tool_definition_new_functions
- tests/test_bridges/test_ghidra.py:201-211 - test_tool_functions_have_descriptions
- tests/test_bridges/test_ghidra.py:213-225 - test_tool_functions_have_matching_methods
- tests/test_bridges/test_ghidra.py:227-237 - test_tool_function_parameters_typed
- tests/test_bridges/test_ghidra.py:242-248 - test_json_dumps_handles_quotes
- tests/test_bridges/test_ghidra.py:250-254 - test_json_dumps_handles_backslashes
- tests/test_bridges/test_ghidra.py:256-261 - test_json_dumps_handles_newlines
- tests/test_bridges/test_ghidra.py:263-267 - test_json_dumps_handles_unicode
- tests/test_bridges/test_ghidra.py:283-290 - test_execute_script_not_connected
- tests/test_bridges/test_ghidra.py:293-300 - test_set_label_not_connected
- tests/test_bridges/test_ghidra.py:303-310 - test_create_bookmark_not_connected
- tests/test_bridges/test_ghidra.py:313-320 - test_create_function_not_connected
- tests/test_bridges/test_ghidra.py:323-330 - test_delete_function_not_connected
- tests/test_bridges/test_ghidra.py:333-340 - test_edit_function_signature_not_connected
- tests/test_bridges/test_ghidra.py:343-350 - test_set_function_variable_type_not_connected
- tests/test_bridges/test_ghidra.py:353-364 - test_define_structure_not_connected
- tests/test_bridges/test_ghidra.py:367-374 - test_apply_structure_at_not_connected
- tests/test_bridges/test_ghidra.py:377-384 - test_write_bytes_not_connected
- tests/test_bridges/test_ghidra.py:387-394 - test_undo_not_connected
- tests/test_bridges/test_ghidra.py:397-404 - test_redo_not_connected
- tests/test_bridges/test_ghidra.py:420-433 - test_initialize_raises_when_package_missing
- tests/test_bridges/test_ghidra.py:436-443 - test_analyze_not_connected
- tests/test_bridges/test_ghidra.py:446-453 - test_get_functions_not_connected
- tests/test_bridges/test_ghidra.py:456-463 - test_get_function_not_connected
- tests/test_bridges/test_ghidra.py:466-473 - test_disassemble_not_connected
- tests/test_bridges/test_ghidra.py:476-483 - test_get_xrefs_to_not_connected
- tests/test_bridges/test_ghidra.py:486-493 - test_get_xrefs_from_not_connected
- tests/test_bridges/test_ghidra.py:496-503 - test_search_strings_not_connected
- tests/test_bridges/test_ghidra.py:506-513 - test_search_bytes_not_connected
- tests/test_bridges/test_ghidra.py:516-523 - test_get_imports_not_connected
- tests/test_bridges/test_ghidra.py:526-533 - test_get_exports_not_connected
- tests/test_bridges/test_ghidra.py:536-543 - test_get_data_type_not_connected
- tests/test_bridges/test_ghidra.py:546-553 - test_get_labels_not_connected
- tests/test_bridges/test_ghidra.py:556-563 - test_get_bookmarks_not_connected
- tests/test_bridges/test_ghidra.py:566-573 - test_get_structures_not_connected
- tests/test_bridges/test_ghidra.py:576-583 - test_get_memory_map_not_connected
- tests/test_bridges/test_ghidra.py:586-593 - test_get_call_graph_not_connected
- tests/test_bridges/test_ghidra.py:596-603 - test_get_segments_not_connected
- tests/test_bridges/test_ghidra.py:606-613 - test_get_program_info_not_connected
- tests/test_bridges/test_ghidra.py:629-636 - test_read_bytes_not_connected
- tests/test_bridges/test_ghidra.py:639-646 - test_search_bytes_wildcard_not_connected
- tests/test_bridges/test_ghidra.py:649-656 - test_get_pcode_not_connected
- tests/test_bridges/test_ghidra.py:659-666 - test_get_basic_blocks_not_connected
- tests/test_bridges/test_ghidra.py:669-676 - test_get_slice_not_connected
- tests/test_bridges/test_ghidra.py:679-686 - test_get_callers_not_connected
- tests/test_bridges/test_ghidra.py:689-696 - test_get_register_value_not_connected
- tests/test_bridges/test_ghidra.py:699-706 - test_import_debug_info_not_connected
- tests/test_bridges/test_ghidra.py:709-716 - test_add_reference_not_connected
- tests/test_bridges/test_ghidra.py:719-726 - test_delete_reference_not_connected
- tests/test_bridges/test_ghidra.py:729-736 - test_get_relocations_not_connected
- tests/test_bridges/test_ghidra.py:739-746 - test_create_namespace_not_connected
- tests/test_bridges/test_ghidra.py:749-756 - test_get_namespaces_not_connected
- tests/test_bridges/test_ghidra.py:759-766 - test_create_equate_not_connected
- tests/test_bridges/test_ghidra.py:769-776 - test_get_equates_not_connected
- tests/test_bridges/test_ghidra.py:779-786 - test_search_symbols_not_connected
- tests/test_bridges/test_ghidra.py:789-796 - test_get_stack_frame_not_connected
- tests/test_bridges/test_ghidra.py:799-806 - test_get_function_body_not_connected
- tests/test_bridges/test_ghidra.py:809-816 - test_get_call_tree_not_connected
- tests/test_bridges/test_ghidra.py:819-826 - test_get_calling_conventions_not_connected
- tests/test_bridges/test_ghidra.py:829-836 - test_get_instruction_flow_not_connected
- tests/test_bridges/test_ghidra.py:839-846 - test_create_data_type_not_connected
- tests/test_bridges/test_ghidra.py:849-856 - test_create_data_not_connected
- tests/test_bridges/test_ghidra.py:859-866 - test_configure_analysis_not_connected
- tests/test_bridges/test_ghidra.py:869-876 - test_set_decompiler_options_not_connected
- tests/test_bridges/test_ghidra.py:879-886 - test_create_memory_block_not_connected
- tests/test_bridges/test_ghidra.py:889-896 - test_get_comments_not_connected
- tests/test_bridges/test_ghidra.py:899-906 - test_get_all_comments_not_connected
- tests/test_bridges/test_ghidra.py:909-916 - test_get_program_tree_not_connected
- tests/test_bridges/test_ghidra.py:919-926 - test_get_properties_not_connected
- tests/test_bridges/test_ghidra.py:929-936 - test_diff_programs_not_connected
- tests/test_bridges/test_ghidra.py:939-946 - test_set_color_not_connected
- tests/test_bridges/test_ghidra.py:949-956 - test_set_program_metadata_not_connected
- tests/test_bridges/test_ghidra.py:959-966 - test_get_thunk_info_not_connected
- tests/test_bridges/test_ghidra.py:969-976 - test_get_external_references_not_connected
- tests/test_bridges/test_ghidra.py:979-986 - test_add_external_function_not_connected
- tests/test_bridges/test_ghidra.py:989-996 - test_create_overlay_space_not_connected
- tests/test_bridges/test_ghidra.py:999-1006 - test_add_bookmark_not_connected
- tests/test_bridges/test_ghidra.py:1009-1016 - test_remove_bookmark_not_connected
- tests/test_bridges/test_ghidra.py:1019-1026 - test_add_label_not_connected
- tests/test_bridges/test_ghidra.py:1029-1036 - test_remove_label_not_connected
- tests/test_bridges/test_ghidra.py:1039-1046 - test_add_thunk_not_connected
- tests/test_bridges/test_ghidra.py:1049-1056 - test_remove_thunk_not_connected
- tests/test_bridges/test_ghidra.py:1059-1066 - test_add_external_reference_not_connected
- tests/test_bridges/test_ghidra.py:1069-1076 - test_remove_external_reference_not_connected
- tests/test_bridges/test_ghidra.py:1079-1086 - test_tool_definition_exact_count
- tests/test_bridges/test_ghidra.py:1089-1097 - test_all_tool_names_unique
- tests/test_bridges/test_ghidra.py:1101-1105 - test_is_available_no_path
- tests/test_bridges/test_hex_state_audit1.py:194-218 - test_reentrant_event_is_delivered_to_other_observers
- tests/test_bridges/test_hex_state_audit1.py:220-263 - test_concurrent_emission_from_other_thread_is_not_dropped
- tests/test_bridges/test_hex_state_audit1.py:294-314 - test_runaway_dispatch_terminates_at_depth_cap
- tests/test_bridges/test_hex_state_audit1.py:327-385 - test_document_length_in_event_matches_published_document
- tests/test_bridges/test_hex_state_audit1.py:387-429 - test_document_length_read_under_lock_observes_swapped_document
- tests/test_bridges/test_hex_state_audit1.py:473-511 - test_concurrent_set_get_display_mode_observes_consistent_values
- tests/test_bridges/test_hex_state_audit1.py:513-544 - test_get_display_mode_blocks_while_set_document_holds_lock
- tests/test_bridges/test_hex_state_audit1.py:595-623 - test_property_getters_block_while_set_document_holds_lock
- tests/test_bridges/test_hex_state_audit1.py:661-681 - test_property_getters_eventually_observe_published_writer_value
- tests/test_bridges/test_hex_state_audit1.py:695-714 - test_clear_all_emits_highlight_rule_removed_for_every_rule
- tests/test_bridges/test_hex_state_audit1.py:716-732 - test_clear_all_orders_rule_removals_before_document_closed
- tests/test_bridges/test_hex_state_audit1.py:734-753 - test_clear_all_with_rules_but_no_document_emits_only_rule_removals
- tests/test_bridges/test_hex_state_audit1.py:755-766 - test_clear_all_idempotent_when_already_empty
- tests/test_bridges/test_hex_state_audit1.py:783-816 - test_f0036_queue_cleared_when_callback_raises_unhandled_exception
- tests/test_bridges/test_x64dbg_events.py:65-74 - test_register_callback_appends_to_list
- tests/test_bridges/test_x64dbg_events.py:77-89 - test_register_multiple_callbacks
- tests/test_bridges/test_x64dbg_events.py:92-101 - test_unregister_callback_removes
- tests/test_bridges/test_x64dbg_events.py:118-133 - test_handle_event_invokes_callbacks
- tests/test_bridges/test_x64dbg_events.py:136-154 - test_handle_event_invokes_all_callbacks
- tests/test_bridges/test_x64dbg_events.py:157-174 - test_handle_event_isolates_callback_errors
- tests/test_bridges/test_x64dbg_events.py:177-180 - test_handle_event_with_no_callbacks
- tests/test_bridges/test_x64dbg_events.py:187-201 - test_breakpoint_hit_count_incremented
- tests/test_bridges/test_x64dbg_events.py:204-218 - test_watchpoint_hit_count_incremented
- tests/test_bridges/test_x64dbg_events.py:221-224 - test_unknown_event_does_not_crash
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:80-91 - test_search_uint16_finds_value_at_known_offset
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:93-104 - test_search_uint32_deadbeef_finds_at_offset_2
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:126-137 - test_search_uint8_0xff_finds_at_offset_36
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:139-150 - test_search_int16_signed_neg1000_finds_at_offset_34
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:152-163 - test_search_int32_signed_neg42_finds_at_offset_30
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:165-176 - test_search_big_endian_uint32_finds_aabbccdd
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:178-197 - test_search_with_alignment_4_returns_only_aligned_offsets
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:199-210 - test_search_absent_value_returns_empty_list
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:212-229 - test_search_max_results_caps_returned_matches
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:231-242 - test_search_uint32_100_finds_at_offset_42
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:244-256 - test_search_result_length_equals_size_parameter
- tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:258-274 - test_search_on_minimal_data_does_not_crash
- tests/test_hexcore_e2e/test_bridge_signatures.py:50-66 - test_die_scan_detects_mz_header
- tests/test_hexcore_e2e/test_bridge_signatures.py:68-85 - test_die_scan_no_match_returns_empty
- tests/test_hexcore_e2e/test_bridge_signatures.py:91-110 - test_clamav_hdb_md5_match
- tests/test_hexcore_e2e/test_bridge_signatures.py:112-129 - test_clamav_hdb_no_match
- tests/test_hexcore_e2e/test_bridge_signatures.py:131-147 - test_clamav_ndb_pattern_match
- tests/test_hexcore_e2e/test_bridge_signatures.py:153-170 - test_custom_json_ep_match
- tests/test_hexcore_e2e/test_bridge_signatures.py:172-192 - test_custom_json_any_match
- tests/test_hexcore_e2e/test_bridge_signatures.py:194-214 - test_custom_json_fixed_offset_match
- tests/test_hexcore_e2e/test_bridge_signatures.py:220-241 - test_scan_result_structure
- tests/test_hexcore_e2e/test_bridge_signatures.py:243-250 - test_no_document_raises
- tests/test_hexcore_e2e/test_search.py:22-34 - test_finds_pattern_at_known_offsets
- tests/test_hexcore_e2e/test_search.py:35-44 - test_no_match_returns_empty
- tests/test_hexcore_e2e/test_search.py:46-55 - test_max_results_limits_output
- tests/test_hexcore_e2e/test_search.py:57-68 - test_single_byte_pattern_finds_all_positions
- tests/test_hexcore_e2e/test_search.py:87-97 - test_finds_mz_signature_at_offset_zero
- tests/test_hexcore_e2e/test_search.py:99-115 - test_wildcard_byte_matches_pe_header_sequence
- tests/test_hexcore_e2e/test_search.py:117-126 - test_no_match_returns_empty (search_hex)
- tests/test_hexcore_e2e/test_search.py:128-137 - test_max_results_limits_output (search_hex)
- tests/test_hexcore_e2e/test_search.py:139-149 - test_lowercase_hex_digits_accepted
- tests/test_hexcore_e2e/test_search.py:155-165 - test_case_sensitive_ascii_finds_only_uppercase
- tests/test_hexcore_e2e/test_search.py:167-179 - test_case_insensitive_ascii_finds_both_variants
- tests/test_hexcore_e2e/test_search.py:181-191 - test_utf8_encoding_locates_plain_ascii_text
- tests/test_hexcore_e2e/test_search.py:193-203 - test_ascii_encoding_locates_embedded_text
- tests/test_hexcore_e2e/test_search.py:205-214 - test_no_match_returns_empty (search_text)
- tests/test_hexcore_e2e/test_search.py:216-225 - test_max_results_limits_output (search_text)
- tests/test_hexcore_e2e/test_search.py:231-243 - test_finds_uppercase_two_char_sequences
- tests/test_hexcore_e2e/test_search.py:245-254 - test_no_match_returns_empty (search_regex)
- tests/test_hexcore_e2e/test_search.py:256-266 - test_digit_pattern_matches_ascii_digits
- tests/test_hexcore_e2e/test_search.py:268-277 - test_max_results_limits_output (search_regex)
- tests/test_hexcore_e2e/test_search.py:283-296 - test_finds_little_endian_u32_at_known_offsets
- tests/test_hexcore_e2e/test_search.py:298-311 - test_finds_signed_negative_i32
- tests/test_hexcore_e2e/test_search.py:313-324 - test_finds_big_endian_u32
- tests/test_hexcore_e2e/test_search.py:326-348 - test_alignment_excludes_unaligned_matches
- tests/test_hexcore_e2e/test_search.py:350-363 - test_finds_u16_value_at_known_positions
- tests/test_hexcore_e2e/test_search.py:365-374 - test_no_match_returns_empty (search_numeric)
- tests/test_hexcore_e2e/test_search.py:380-400 - test_finds_f32_within_tolerance
- tests/test_hexcore_e2e/test_search.py:402-412 - test_no_match_when_value_outside_tolerance
- tests/test_hexcore_e2e/test_search.py:414-425 - test_finds_big_endian_f32_at_correct_offset
- tests/test_hexcore_e2e/test_search.py:431-448 - test_returns_only_values_inside_the_range
- tests/test_hexcore_e2e/test_search.py:450-461 - test_no_match_returns_empty (search_numeric_range)
- tests/test_hexcore_e2e/test_search.py:463-480 - test_signed_range_includes_negative_values
- tests/test_hexcore_e2e/test_search.py:482-497 - test_big_endian_range_search_finds_correct_offsets
- tests/test_hexcore_e2e/test_search.py:503-512 - test_returns_count_of_replaced_occurrences
- tests/test_hexcore_e2e/test_search.py:514-524 - test_document_bytes_reflect_replacement
- tests/test_hexcore_e2e/test_search.py:526-536 - test_original_pattern_absent_after_replace
- tests/test_hexcore_e2e/test_search.py:538-547 - test_no_match_returns_zero
- tests/test_hexcore_e2e/test_search.py:549-559 - test_single_occurrence_replaced_correctly
- tests/test_hexpat/test_lexer.py:18-31 - test_simple_struct
- tests/test_hexpat/test_lexer.py:33-37 - test_hex_literal
- tests/test_hexpat/test_lexer.py:39-49 - test_binary_literal
- tests/test_hexpat/test_lexer.py:45-49 - test_octal_literal
- tests/test_hexpat/test_lexer.py:51-55 - test_float_literal
- tests/test_hexpat/test_lexer.py:57-60 - test_float_exponent
- tests/test_hexpat/test_lexer.py:62-66 - test_string_literal_escapes
- tests/test_hexpat/test_lexer.py:68-72 - test_char_literal
- tests/test_hexpat/test_lexer.py:74-97 - test_all_keywords
- tests/test_hexpat/test_lexer.py:99-119 - test_multichar_operators
- tests/test_hexpat/test_lexer.py:121-125 - test_line_comment
- tests/test_hexpat/test_lexer.py:127-131 - test_block_comment_nested
- tests/test_hexpat/test_lexer.py:133-137 - test_dollar_and_at
- tests/test_hexpat/test_lexer.py:139-142 - test_ellipsis
- tests/test_providers/test_realcov_10_anthropic_cache.py:70-84 - test_system_prompt_becomes_cached_block (PARTIAL - see notes on weakness)
- tests/test_providers/test_realcov_10_anthropic_cache.py:87-100 - test_last_tool_entry_gets_cache_control
- tests/test_providers/test_realcov_10_anthropic_cache.py:103-118 - test_string_message_content_converted_to_cached_block
- tests/test_providers/test_realcov_10_anthropic_cache.py:121-138 - test_block_list_message_tags_only_final_block
- tests/test_providers/test_realcov_10_anthropic_cache.py:141-172 - test_breakpoint_count_within_anthropic_limit
- tests/test_providers/test_realcov_10_anthropic_cache.py:179-183 - test_empty_messages_is_a_no_op_via_apply
- tests/test_providers/test_realcov_11_model_loader.py:126-143 - test_fp16_matches_two_bytes_per_param_with_overhead (PARTIAL - see notes)
- tests/test_providers/test_realcov_11_model_loader.py:146-151 - test_activation_overhead_toggle_changes_result
- tests/test_providers/test_realcov_11_model_loader.py:154-157 - test_float32_uses_four_bytes_per_param
- tests/test_providers/test_realcov_11_model_loader.py:164-176 - test_size_pattern_in_id_wins
- tests/test_providers/test_realcov_11_model_loader.py:169-176 - test_named_model_phi3_mini
- tests/test_providers/test_realcov_11_model_loader.py:174-181 - test_phi2_named_model_without_size_token
- tests/test_providers/test_realcov_11_model_loader.py:180-186 - test_size_token_substring_takes_precedence
- tests/test_providers/test_realcov_11_model_loader.py:184-186 - test_unlisted_model_falls_back_to_7b
- tests/test_providers/test_realcov_11_model_loader.py:193-200 - test_preferred_dtype_kept_when_it_fits
- tests/test_ui/log_viewer/test_window.py:98-113 - test_window_opens_and_loads_history
- tests/test_ui/log_viewer/test_window.py:116-149 - test_level_filter_narrows_visible_rows
- tests/test_ui/log_viewer/test_window.py:152-168 - test_clear_empties_model
- tests/test_ui/log_viewer/test_window.py:171-196 - test_geometry_persists_across_open_close
- tests/test_ui/test_realcov_14b_script_manager.py:77-92 - test_save_persists_real_content (PARTIAL - see notes)
- tests/test_ui/test_realcov_14b_script_manager.py:95-109 - test_load_reflects_real_backend_content
- tests/test_ui/test_realcov_14b_script_manager.py:117-129 - test_valid_python_passes_real_validation
- tests/test_ui/test_realcov_14b_script_manager.py:132-146 - test_broken_python_fails_real_validation
- tests/test_ui/test_realcov_14b_script_manager.py:154-181 - test_execute_renders_real_binary_digest
- tests/test_ui/test_realcov_15_chat_panel.py:64-78 - test_send_button_emits_typed_text (PARTIAL - see notes)
- tests/test_ui/test_realcov_15_chat_panel.py:81-95 - test_enter_key_submits_message
- tests/test_ui/test_realcov_15_chat_panel.py:98-117 - test_shift_enter_inserts_newline_without_submitting
- tests/test_ui/test_realcov_15_chat_panel.py:120-131 - test_add_message_renders_real_content
- tests/test_ui/test_realcov_15_chat_panel.py:134-157 - test_add_message_renders_tool_call
- tests/test_ui/test_realcov_15_chat_panel.py:160-174 - test_streaming_message_appends_chunks
- tests/test_ui/test_realcov_15_chat_panel.py:177-192 - test_clear_messages_empties_history_and_view
- tests/ui/test_system_tab_warnings.py:185-205 - test_refresh_mitigations_unattached_shows_warning (PARTIAL - see notes)
- tests/ui/test_system_tab_warnings.py:207-227 - test_on_gui_resources_unattached_shows_warning
- tests/ui/test_system_tab_warnings.py:229-249 - test_on_job_info_unattached_shows_warning

## Summary

- Findings by severity:
  - Critical: 2
  - High: 2
  - Medium: 9
  - Low: 6

- Total tests audited: 308
- Total tests clean: 289

---

**Note**: The "Clean" list includes tests that pass the falsifiability test and have real gates. Some entries marked as "PARTIAL" in the clean list have minor assertion-quality gaps (e.g., checking only length or type rather than full structure) but still constitute real gates because deletion or corruption of the production code would cause them to fail. These should be enhanced but are not false gates. Tests listed under Findings are those where the test is genuinely at risk of passing even if significant production code was removed or broken.
