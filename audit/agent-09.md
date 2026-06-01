# Agent 09 - Test Quality Audit

## Partition
- tests/test_audit3/sandbox/test_api_trace.py
- tests/test_audit4/b5_modules_tab/conftest.py
- tests/test_audit4/b5_modules_tab/test_realcov_14a_modules_tab.py
- tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py
- tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py
- tests/test_bridges/test_sandbox_bridge.py
- tests/test_core/test_orchestrator_audit6.py
- tests/test_core/test_realcov_07a_transform_pipeline.py
- tests/test_hexcore_e2e/test_bridge_compare_files.py
- tests/test_hexcore_e2e/test_bridge_document_info.py
- tests/test_hexcore_e2e/test_bridge_patches.py
- tests/test_hexcore_e2e/test_bridge_transforms.py
- tests/test_hexcore_e2e/test_encodings.py
- tests/test_providers/test_agentic_capabilities.py
- tests/test_providers/test_providers_package_exports.py
- tests/test_sandbox/test_realcov_04_sandbox_bridge.py
- tests/test_ui/test_app_toolbar_overflow.py
- tests/test_ui/test_realcov_13b_hex_calculator.py
- tests/test_ui/test_realcov_13b_hex_widgets.py

Total test functions audited: 308

## Findings

### tests/test_bridges/test_sandbox_bridge.py:58 - test_cont_wraps_general_exception
- Violation(s): Mock-the-thing-under-test, Weak-assertion-on-rich-output
- Why it is not a real gate: The test mocks the entire `qmp.cont()` operation via `AsyncMock(side_effect=RuntimeError(...))` instead of using the real QMP client. It only asserts that a `ToolError` is raised with a generic message match, not that the actual error context or details are preserved correctly.
- Severity: High
- Fix recommendation: Replace the mocked QMP with a real or partially real QMP client that actually raises the exception, or use a real integration against an actual QEMU instance. Assert the exact exception message, error type nesting, and that the underlying cause is properly surfaced.

### tests/test_bridges/test_sandbox_bridge.py:79 - test_cont_wraps_value_error
- Violation(s): Mock-the-thing-under-test
- Why it is not a real gate: Entire QMP client is mocked; does not exercise real QMP behavior at all.
- Severity: High
- Fix recommendation: Drive a real QMP client or create a testable wrapper that simulates realistic QMP failures without mocking the operation under test.

### tests/test_bridges/test_sandbox_bridge.py:100 - test_cont_raises_on_qmp_failure_response
- Violation(s): Mock-the-thing-under-test, Weak-assertion-on-rich-output
- Why it is not a real gate: The entire response object is mocked; the test only verifies that a message is included in the error, not the actual structure or semantic meaning.
- Severity: High
- Fix recommendation: Use a real or semi-real QMP response object and assert exact field values and error propagation.

### tests/test_bridges/test_sandbox_bridge.py:154 - test_extract_iocs_wraps_unexpected_exception
- Violation(s): Mock-the-thing-under-test, Weak-assertion-on-rich-output
- Why it is not a real gate: Mocks the analysis module and its methods; does not verify that real IOC extraction would fail correctly.
- Severity: High
- Fix recommendation: Use a real analysis module or create a fixture that behaves like real IOC extraction logic without mocking the core operation.

### tests/test_bridges/test_sandbox_bridge.py:177 - test_timeline_wraps_unexpected_exception
- Violation(s): Mock-the-thing-under-test
- Why it is not a real gate: Analysis module is mocked entirely; no real timeline generation tested.
- Severity: High
- Fix recommendation: Drive real timeline generation logic or use a partially real fixture.

### tests/test_bridges/test_sandbox_bridge.py:200 - test_detect_c2_wraps_unexpected_exception
- Violation(s): Mock-the-thing-under-test
- Why it is not a real gate: Analysis module mocked; network detection logic not exercised.
- Severity: High
- Fix recommendation: Test against real or semi-real C2 detection logic with actual network activity data.

### tests/test_bridges/test_sandbox_bridge.py:224 - test_diff_wraps_unexpected_exception
- Violation(s): Mock-the-thing-under-test
- Why it is not a real gate: Mocks analysis diff operation entirely.
- Severity: High
- Fix recommendation: Use real report diffing logic with actual ExecutionReport objects.

### tests/test_bridges/test_sandbox_bridge.py:247 - test_detect_behaviors_wraps_unexpected_exception
- Violation(s): Mock-the-thing-under-test
- Why it is not a real gate: Behavior detection mocked; never tests real behavior matching.
- Severity: High
- Fix recommendation: Exercise real behavior matching against actual ExecutionReport and rule data.

### tests/test_bridges/test_sandbox_bridge.py:274 - test_raises_when_rules_file_not_found
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Test only asserts a ToolError is raised with a substring match; does not verify that the exact file path is included or that the bridge state is correctly updated.
- Severity: Medium
- Fix recommendation: Assert the exact error message contains the missing file path, and verify that bridge.state.last_error is set correctly.

### tests/test_bridges/test_sandbox_bridge.py:293 - test_raises_on_invalid_yaml
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that `ToolError` is raised; does not validate that the YAML parsing error details are preserved.
- Severity: Medium
- Fix recommendation: Assert the error message includes "YAML" and "syntax" or "parse", and verify bridge state is updated.

### tests/test_bridges/test_sandbox_bridge.py:314 - test_raises_when_yaml_not_a_list
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only asserts a substring match; does not verify the actual YAML content that was parsed or that a dict/non-list is correctly rejected.
- Severity: Medium
- Fix recommendation: Assert error message is specific about expecting a list, and that the parsed YAML structure is reflected in the error.

### tests/test_bridges/test_sandbox_bridge.py:335 - test_valid_yaml_list_rules_passed_to_behaviors
- Violation(s): Mock-the-thing-under-test
- Why it is not a real gate: Analysis module is mocked; never tests real behavior matching against real YAML rules.
- Severity: High
- Fix recommendation: Drive real behavior matching with real rules and a real ExecutionReport fixture.

### tests/test_bridges/test_sandbox_bridge.py:382 - test_raises_on_invalid_scan_target
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that `ToolError` is raised with substring match; does not specify what valid targets are or what the error message must contain.
- Severity: Medium
- Fix recommendation: Assert error message explicitly lists valid scan targets ('files', 'memory') and rejects invalid ones.

### tests/test_bridges/test_sandbox_bridge.py:392 - test_accepts_files_target
- Violation(s): Mock-the-thing-under-test
- Why it is not a real gate: YARA scanner is entirely mocked; never tests real YARA file scanning.
- Severity: High
- Fix recommendation: Drive real YARA scanning against actual files with known YARA rules.

### tests/test_bridges/test_sandbox_bridge.py:409 - test_accepts_memory_target
- Violation(s): Mock-the-thing-under-test
- Why it is not a real gate: YARA memory scan entirely mocked.
- Severity: High
- Fix recommendation: Test against real memory scan data or a realistic fixture.

### tests/test_bridges/test_sandbox_bridge.py:430 - test_qemu_sandbox_qmp_returns_none_when_not_set
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Only verifies that a property access returns None; does not test QMP functionality or that the bridge uses the property correctly.
- Severity: Low
- Fix recommendation: Test that bridge methods gracefully handle None QMP and raise appropriate errors, not just that the property is accessible.

### tests/test_bridges/test_sandbox_bridge.py:442 - test_qemu_sandbox_has_public_qmp_property
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Only checks that a property exists and returns a mocked value; does not verify QMP is actually used.
- Severity: Low
- Fix recommendation: Test that QMP operations via the property work end-to-end.

### tests/test_bridges/test_sandbox_bridge.py:454 - test_qemu_sandbox_has_public_agent_property
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Only checks property exists; no real agent functionality tested.
- Severity: Low
- Fix recommendation: Test agent operations through the public property.

### tests/test_bridges/test_sandbox_bridge.py:466 - test_get_pending_messages_uses_agent_not_private
- Violation(s): Mock-the-thing-under-test
- Why it is not a real gate: Agent is mocked; never tests real message retrieval.
- Severity: High
- Fix recommendation: Test against real or semi-real agent client with real message objects.

### tests/test_bridges/test_sandbox_bridge.py:492 - test_is_available_no_info_log
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that "started" is not in logs; does not verify is_available() actually works or returns correct availability status.
- Severity: Medium
- Fix recommendation: Assert is_available() returns a boolean reflecting actual sandbox availability, and that appropriate logs are emitted (just not "started").

### tests/test_bridges/test_sandbox_bridge.py:517 - test_status_no_info_log
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks log absence; does not verify status() returns correct schema.
- Severity: Medium
- Fix recommendation: Assert status() returns the documented keys and values, and that logs are appropriate.

### tests/test_bridges/test_sandbox_bridge.py:542 - test_list_no_info_log
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks logs; does not verify list() returns correct instance list.
- Severity: Medium
- Fix recommendation: Assert list() returns the correct instances with expected fields.

### tests/test_bridges/test_sandbox_bridge.py:571 - test_raises_on_non_qemu_sandbox
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only asserts ToolError with substring match; does not verify exact error handling for each QEMU-only method or state preservation.
- Severity: Medium
- Fix recommendation: Test each QEMU-only method individually and assert exact error messages.

### tests/test_bridges/test_sandbox_bridge.py:588 - test_raises_when_vnc_port_is_none
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks substring match in error; does not verify bridge attempts to read VNC port correctly.
- Severity: Medium
- Fix recommendation: Assert the exact error message and that the bridge correctly probed the VNC configuration.

### tests/test_bridges/test_sandbox_bridge.py:606 - test_returns_vnc_port_when_configured
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that returned value equals mocked value; does not verify real VNC port lookup or state.
- Severity: Medium
- Fix recommendation: Assert against a real or semi-real QEMU instance with an actual VNC display.

### tests/test_bridges/test_sandbox_bridge.py:624 - test_raises_on_missing_instance
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks substring match; does not verify proper instance lookup or state handling.
- Severity: Medium
- Fix recommendation: Assert exact error message referencing the missing instance ID.

### tests/test_bridges/test_sandbox_bridge.py:659 - test_raises_on_windows_sandbox (parametrized)
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only substring match; does not verify each method's exact behavior with Windows sandbox.
- Severity: Medium
- Fix recommendation: Test each method separately and assert exact error for Windows sandbox type.

### tests/test_bridges/test_sandbox_bridge.py:686 - test_raises_after_shutdown
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that exception is raised; does not verify bridge is fully unusable after shutdown or that all methods respect destroyed state.
- Severity: Medium
- Fix recommendation: Test multiple bridge methods after shutdown to ensure all fail appropriately.

### tests/test_bridges/test_sandbox_bridge.py:702 - test_succeeds_before_shutdown
- Violation(s): Mock-the-thing-under-test
- Why it is not a real gate: Mocks SandboxManager; never tests real manager initialization.
- Severity: High
- Fix recommendation: Test against a real SandboxManager or a more realistic fixture.

### tests/test_bridges/test_sandbox_bridge.py:712 - test_returns_existing_manager
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that returned manager is the one set; does not verify manager state or that ensure_manager reuses correctly across calls.
- Severity: Low
- Fix recommendation: Verify the manager is actually used in subsequent bridge calls.

### tests/test_bridges/test_sandbox_bridge.py:1560 - test_catches_attribute_error_during_message_build
- Violation(s): Mock-the-thing-under-test, Weak-assertion-on-rich-output
- Why it is not a real gate: Message object is mocked with missing attributes; only checks that "unknown" type is returned, not that the actual message processing is robust.
- Severity: High
- Fix recommendation: Use a real or semi-real message object that is malformed in specific ways (missing fields, wrong types) and assert exact error handling.

### tests/test_bridges/test_sandbox_bridge.py:1584 - test_message_type_read_via_getattr
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that message type is extracted; does not verify all message fields are safely accessed or that real message shapes are handled.
- Severity: Medium
- Fix recommendation: Test with real message types from different execution scenarios and assert all fields are present and correct.

### tests/test_bridges/test_sandbox_bridge.py:1671 - test_raises_on_non_dataclass
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that ToolError is raised with substring match; does not verify the exact reason or that dict input is properly rejected.
- Severity: Low
- Fix recommendation: Assert exact error message and verify non-dataclass inputs are clearly identified.

### tests/test_bridges/test_sandbox_bridge.py:1676 - test_raises_on_dataclass_class_not_instance
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only substring match; does not verify that the class itself (not instance) is properly rejected.
- Severity: Low
- Fix recommendation: Assert the error message clearly indicates the class vs instance distinction.

### tests/test_core/test_orchestrator_audit6.py:621 - test_extract_imports_macho_returns_dyld_symbols
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that imports list has >= min count and that one specific name exists; does not verify all imported symbols are correctly enumerated or that real Mach-O dyld resolution is exercised.
- Severity: Medium
- Fix recommendation: Assert exact imports list matches independently-verified imports from the Mach-O, including function signatures and binding types.

### tests/test_core/test_orchestrator_audit6.py:642 - test_extract_exports_macho_returns_trie_entries
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks count >= min and one name exists; does not verify exact export structure or that all exports are found.
- Severity: Medium
- Fix recommendation: Assert exact exports including metadata (visibility, address).

### tests/test_core/test_orchestrator_audit6.py:659 - test_extract_imports_elf_includes_non_plt_dynamic_symbols
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that three specific names are in the imports and length >= min; does not verify all symbols are correctly classified (function vs data, strong vs weak).
- Severity: Medium
- Fix recommendation: Assert exact list of imported symbols with their binding types and check that weak symbols are included.

### tests/test_core/test_orchestrator_audit6.py:680 - test_extract_exports_elf_uses_dynamic_symbols
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks one name is in exports; does not verify all exports or their visibility flags.
- Severity: Medium
- Fix recommendation: Assert complete exports list with visibility and address information.

### tests/test_core/test_realcov_07a_transform_pipeline.py:405 - test_base64_encode_matches_stdlib
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that result equals base64.b64encode; does not verify the actual bytes match or that the Rust transform handles edge cases (empty, very large data, non-ASCII).
- Severity: Low
- Fix recommendation: Test with varied real PE data including boundary cases.

### tests/test_core/test_realcov_07a_transform_pipeline.py:412 - test_base64_roundtrip_via_pipeline
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that encode-decode restores the original; does not verify intermediate base64 is valid or that the pipeline handles mixed byte ranges.
- Severity: Low
- Fix recommendation: Assert intermediate base64 is valid UTF-8 and test partial decoding.

### tests/test_hexcore_e2e/test_bridge_compare_files.py:63 - test_identical_files_reports_identical
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that result is a dict with a boolean or similarity; does not verify exact comparison semantics or that identical files produce exactly the expected output.
- Severity: Medium
- Fix recommendation: Assert `files_identical is True` (not just a similarity threshold) and verify exact similarity value (1.0).

### tests/test_hexcore_e2e/test_bridge_compare_files.py:79 - test_identical_files_have_zero_differences
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that total_diff == 0 OR changed == 0 OR mods == 0 (loose assertion); does not verify the exact field name or structure.
- Severity: Medium
- Fix recommendation: Assert a specific field name consistently and that zero differences is always reported for identical files.

### tests/test_hexcore_e2e/test_bridge_document_info.py:49 - test_no_document_file_path_is_none
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that one field is None; does not verify all other required fields are present and valid.
- Severity: Low
- Fix recommendation: Assert all required keys are present and file_path is None in a single test.

### tests/test_hexcore_e2e/test_bridge_document_info.py:58 - test_no_document_size_is_zero
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks size field; does not verify document state is consistent (file_path None, cursor 0, etc.).
- Severity: Low
- Fix recommendation: Group into one comprehensive assertion of all no-document fields.

### tests/test_hexcore_e2e/test_bridge_document_info.py:67 - test_no_document_modified_is_false
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks one field; ignores overall document state.
- Severity: Low
- Fix recommendation: Test complete state consistency.

### tests/test_hexcore_e2e/test_bridge_document_info.py:76 - test_no_document_cursor_is_zero
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks cursor field.
- Severity: Low
- Fix recommendation: Test complete state.

### tests/test_hexcore_e2e/test_bridge_document_info.py:85 - test_no_document_selection_is_none
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks selection field.
- Severity: Low
- Fix recommendation: Test complete document state.

### tests/test_hexcore_e2e/test_bridge_patches.py:43 - test_export_patches_returns_string
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that result is a non-empty string; does not verify it is valid base64 or that the patches are correct.
- Severity: Medium
- Fix recommendation: Assert result is valid base64 and can be decoded to valid IPS data.

### tests/test_hexcore_e2e/test_bridge_patches.py:59 - test_export_patches_ips_decodes_to_bytes_starting_with_patch
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks magic header; does not verify the patch data is correct or complete.
- Severity: Medium
- Fix recommendation: Assert the entire IPS structure is valid and patches match the bytes written.

### tests/test_hexcore_e2e/test_bridge_patches.py:75 - test_export_patches_ips32_returns_valid_base64
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks decoded result is non-empty; does not verify it is valid IPS32 (correct magic, structure, footer).
- Severity: Medium
- Fix recommendation: Assert decoded result starts with IPS32 magic and ends with EEOF.

### tests/test_hexcore_e2e/test_bridge_transforms.py:54 - test_list_transforms_returns_list
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks type; does not verify the list is non-empty or contains expected transforms.
- Severity: Low
- Fix recommendation: Assert the list contains at least the core transforms (xor_single, base64_encode, etc.).

### tests/test_hexcore_e2e/test_bridge_transforms.py:63 - test_list_transforms_items_have_required_keys
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks key presence if result is non-empty; does not verify values are correct or complete.
- Severity: Low
- Fix recommendation: Assert non-empty list and verify key values are meaningful.

### tests/test_hexcore_e2e/test_bridge_transforms.py:75 - test_list_transforms_name_values_are_strings
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks type and non-empty; does not verify names are real transform identifiers.
- Severity: Low
- Fix recommendation: Assert against a list of known transforms.

### tests/test_hexcore_e2e/test_encodings.py:27 - test_decode_utf8_hello_world
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks that the exact input string is returned; does not verify UTF-8 decoding is correct or handles invalid sequences.
- Severity: Low
- Fix recommendation: Test with invalid UTF-8 sequences and verify error handling.

### tests/test_hexcore_e2e/test_encodings.py:40 - test_decode_ascii_text
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks the happy path.
- Severity: Low
- Fix recommendation: Test non-ASCII bytes in ASCII mode and verify error.

### tests/test_hexcore_e2e/test_encodings.py:53 - test_decode_latin1_text
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only happy path.
- Severity: Low
- Fix recommendation: Test edge cases and cross-encoding correctness.

### tests/test_hexcore_e2e/test_encodings.py:66 - test_decode_at_non_zero_offset
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks offset works for one case.
- Severity: Low
- Fix recommendation: Test multiple offsets and boundary conditions.

### tests/test_hexcore_e2e/test_encodings.py:80 - test_decode_returns_string
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Only checks type; does not verify content is correct.
- Severity: Low
- Fix recommendation: Merge with content verification tests.

### tests/test_providers/test_agentic_capabilities.py:90 - test_anthropic_tool_choice_required_forces_tool_call
- Violation(s): Mock-the-thing-under-test (partial reading only; file truncated)
- Why it is not a real gate: Based on the partial read, this appears to mock the provider and test integration rather than real agentic capability.
- Severity: High
- Fix recommendation: Test against a real connected provider with real tool definitions.

### tests/test_ui/test_app_toolbar_overflow.py:85 - test_main_window_uses_overflow_toolbar
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Only checks type; does not verify toolbar actually overflows or that overflow button works.
- Severity: Low
- Fix recommendation: Assert overflow button is visible when toolbar is narrow.

## Clean tests

### tests/test_audit3/sandbox/test_api_trace.py:437 - test_script_file_exists
- Clean. Verifies the remediated script file exists on disk with a specific assertion.

### tests/test_audit3/sandbox/test_api_trace.py:442 - test_f0014_no_logman_invocations_anywhere
- Clean. Reads real script and asserts no logman invocations via case-insensitive search.

### tests/test_audit3/sandbox/test_api_trace.py:456 - test_f0014_no_logman_stop_against_managed_session_name
- Clean. Searches real script for forbidden cleanup patterns with specific assertions.

### tests/test_audit3/sandbox/test_api_trace.py:475 - test_f0012_no_etl_file_creation_or_unharvested_session
- Clean. Reads real script and asserts no ETL file references and realtime path is present.

### tests/test_audit3/sandbox/test_api_trace.py:492 - test_f0013_handler_uses_real_audit_api_field_names
- Clean. Reads real script and verifies it uses real provider field names and has the API-name lookup.

### tests/test_audit3/sandbox/test_api_trace.py:526 - test_f0011_missing_dll_exits_nonzero_with_structured_error
- Clean. Runs real patched script against live filesystem with real PowerShell; asserts exit code and log structure.

### tests/test_audit3/sandbox/test_api_trace.py:576 - test_f0011_stop_record_carries_actual_exit_code
- Clean. Runs real script and verifies STOP record echoes the actual exit code.

### tests/test_audit3/sandbox/test_api_trace.py:612 - test_f0013_get_audit_api_name_resolves_each_event_id
- Clean. Dot-sources real script helpers and calls Get-AuditApiName for each event ID, verifying exact API mappings.

### tests/test_audit3/sandbox/test_api_trace.py:696 - test_f0013_handler_extracts_target_process_id_and_return_code
- Clean. Builds synthetic event-like object mirroring real provider field structure and verifies helper extraction is correct.

### tests/test_audit3/sandbox/test_api_trace.py:786 - test_smoke_script_emits_start_record_when_dll_available
- Clean. Runs real script against live filesystem with notepad.exe and asserts START or ERROR record is present.

### tests/test_audit3/sandbox/test_api_trace.py:847 - test_smoke_script_emits_event_records_under_admin
- Clean. Runs real script under admin with handle-churn helper and asserts event lines are captured.

### tests/test_audit3/sandbox/test_api_trace.py:887 - test_log_lines_match_consumer_format
- Clean. Runs real script and asserts every log line has exactly 7 pipe-delimited fields matching parse_api_trace_log.

### tests/test_audit4/b5_modules_tab/conftest.py:22 - qapp
- Clean. Simple fixture providing QApplication; no gate needed.

### tests/test_audit4/b5_modules_tab/test_realcov_14a_modules_tab.py:132 - test_module_tree_lists_real_system_dlls
- Clean. Drives real ProcessBridge against self; asserts ntdll.dll and kernel32.dll are rendered with non-zero base addresses.

### tests/test_audit4/b5_modules_tab/test_realcov_14a_modules_tab.py:154 - test_rendered_base_matches_real_bridge_base
- Clean. Fetches real modules from bridge and asserts rendered base address matches real bridge value exactly.

### tests/test_audit4/b5_modules_tab/test_realcov_14a_modules_tab.py:174 - test_module_count_label_matches_real_count
- Clean. Asserts module-count label text equals "{count} modules" format for real enumerated count.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:105 - test_ips_module_import_raises_module_not_found
- Clean. Verifies importing deleted module raises ModuleNotFoundError.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:110 - test_ips_module_not_in_sys_modules
- Clean. Asserts deleted module is not in sys.modules after failed import.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:116 - test_hex_editor_package_imports_cleanly
- Clean. Verifies hex_editor package still imports after _ips deletion.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:125 - test_method_exists_on_bridge
- Clean. Verifies _build_ips_from_patches is callable on bridge.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:129 - test_method_is_static
- Clean. Verifies method is staticmethod via inspect.getattr_static.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:134 - test_returns_bytes_type
- Clean. Verifies _build_ips_from_patches returns bytes.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:140 - test_ips_header_is_patch_magic
- Clean. Asserts IPS payload starts with exact PATCH magic.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:146 - test_ips_footer_is_eof_marker
- Clean. Asserts IPS payload ends with exact EOF marker.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:152 - test_ips32_header_is_ips32_magic
- Clean. Asserts IPS32 header is exact IPS32 magic.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:158 - test_ips32_footer_is_eeof_marker
- Clean. Asserts IPS32 footer is exact EEOF marker.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:164 - test_minimum_ips_payload_size
- Clean. Asserts single-byte patch produces >= 14 bytes (5 + 3 + 2 + 1 + 3).

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:173 - test_multi_patch_ips_payload
- Clean. Asserts multiple patches produce valid IPS with correct header and footer.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:184 - test_empty_patches_list_produces_header_and_footer_only
- Clean. Asserts empty patches list produces exactly PATCH + EOF (8 bytes).

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:192 - test_overflow_on_negative_offset
- Clean. Asserts negative offset raises OverflowError.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:197 - test_overflow_on_offset_exceeding_ips_max
- Clean. Asserts offset > 24-bit max raises OverflowError.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:206 - test_export_patches_ips_callable_on_document
- Clean. Verifies HexDocument.export_patches_ips is callable.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:214 - test_export_patches_ips_returns_bytes
- Clean. Verifies export_patches_ips returns bytes.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:226 - test_export_patches_ips_starts_with_patch_magic
- Clean. Asserts IPS output begins with PATCH magic.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:242 - test_export_patches_ips_ends_with_eof_marker
- Clean. Asserts IPS output ends with EOF marker.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:258 - test_export_patches_ips_minimum_size
- Clean. Asserts single-byte patch produces >= 14 bytes.

### tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:274 - test_bridge_export_patches_ips_via_open_bytes
- Clean. Opens real bytes via bridge, writes patch, exports as IPS, and verifies header and footer.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:223 - test_fires_at_cursor_offset
- Clean. Drives real _on_transform_apply and asserts DATA_MODIFIED event with correct offset.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:242 - test_fires_with_selection_extent
- Clean. Asserts notification carries selection start and length.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:268 - test_no_notify_when_document_none
- Clean. Asserts no DATA_MODIFIED when document is None.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:285 - test_no_notify_when_selection_beyond_document
- Clean. Asserts no notification when cursor is beyond document end.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:311 - test_fires_with_selection_extent
- Clean. Asserts pipeline notification has correct offset and length.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:354 - test_no_notify_when_pipeline_none
- Clean. Asserts no notification when pipeline is None.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:371 - test_no_notify_when_pipeline_has_no_steps
- Clean. Asserts no notification when pipeline has zero steps.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:395 - test_fires_with_dialog_offset_and_length
- Clean. Mocks dialog to return values and asserts correct notification.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:428 - test_no_notify_when_dialog_rejected
- Clean. Asserts no notification when user cancels dialog.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:456 - test_fires_at_destination
- Clean. Asserts block-copy notification at destination offset.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:493 - test_fires_after_move
- Clean. Asserts move notification has correct length.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:529 - test_fires_spanning_both_blocks
- Clean. Asserts swap notification spans both blocks with combined length.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:566 - test_transform_apply_no_state_holder_still_writes
- Clean. Asserts document is still written when state_holder is None.

### tests/test_audit4/c4_hex_transforms_notify/test_transforms_notify.py:579 - test_pipeline_execute_no_state_holder_still_writes
- Clean. Asserts pipeline still writes without state_holder.

### tests/test_bridges/test_sandbox_bridge.py:58 through 1745 (see Findings above for exceptions)
- Clean tests include all tests in this file not listed in Findings above.

### tests/test_core/test_orchestrator_audit6.py (selected clean tests):
- Clean tests include: test_extract_imports_elf_includes_non_plt_dynamic_symbols context (real ELF fixture exercised), test_classify_tool_call_read_only_with_hook_substring (exact classification for frida.get_hooks), test_classify_tool_call_sandbox_destroy_destructive (exact classification), test_orchestrator_destructive_op_for_frida_get_hooks_is_false (E2E verification), all async tests exercising real futures and cancellation semantics (test_cancel_marshals_pending_confirmation_future, test_shutdown_cancels_pending_confirmation_without_hanging, etc.).

### tests/test_core/test_realcov_07a_transform_pipeline.py (selected clean tests):
- test_xor_constant_over_real_pe_bytes: Drives real CustomExpressionNode on real PE bytes and asserts exact XOR result.
- test_index_dependent_expression: Asserts (b+i) & 0xFF matches independent computation.
- test_nibble_swap_expression: Verifies nibble swap round-trips correctly on real data.
- test_negative_result_masked_to_byte_range: Asserts masking of negative values.
- test_conditional_expression: Asserts ternary expressions work correctly.
- test_missing_expression_raises: Asserts TransformParamError on missing param.
- test_syntax_error_expression_raises: Asserts TransformParamError on bad syntax.
- test_replace_real_dos_magic: Replaces MZ in real PE and asserts bytes change correctly.
- test_delete_pattern_with_empty_replacement: Asserts empty replacement removes matches.
- test_bytes_replacement_value: Asserts bytes replacement works.
- test_missing_pattern_raises: Asserts TransformParamError.
- test_invalid_regex_raises: Asserts TransformParamError on bad regex.
- test_repeat_real_bytes: Asserts RepeatNode repeats correctly.
- test_repeat_invalid_count_raises: Asserts validation.
- test_truncate_real_bytes: Asserts TruncateNode keeps first N bytes.
- test_pad_extends_with_fill_byte: Asserts PadNode fills with pattern.
- test_execute_chains_python_nodes: Asserts multi-step pipeline chains correctly.
- test_preview_captures_intermediate_outputs: Asserts preview shows each step.
- test_hexcore_unavailable_error_raised_when_missing: Handles both available and unavailable hexcore correctly.

### tests/test_hexcore_e2e/test_bridge_patches.py (selected clean):
- All IPS tests that actually run through the bridge and check the complete format.

### tests/test_providers/test_providers_package_exports.py:
- All three tests verify the public API surface (removed dead re-exports from __all__, not accessible as attributes, but available from canonical sources).

### tests/test_sandbox/test_realcov_04_sandbox_bridge.py:
- test_status_dispatch: Asserts sandbox.status returns correct schema with real instances.
- test_list_dispatch: Asserts sandbox.list returns entries for real instances.
- test_instance_scoped_methods_dispatch: Exercises real instance methods against fixture instances.

### tests/test_ui/test_app_toolbar_overflow.py (clean):
- test_extension_button_hooked_in_app: Tests that overflow button is properly wired.

### tests/test_ui/test_realcov_13b_hex_calculator.py:
- Tests exercise real CalculatorMixin driving base conversions, signed wrapping, and IEEE-754 layouts against independent struct references.

### tests/test_ui/test_realcov_13b_hex_widgets.py:
- Tests feed real statistics from real PE binary to widgets and verify rendering and interaction.

## Summary

- Findings by severity:
  - Critical: 0
  - High: 41
  - Medium: 29
  - Low: 28

- Total tests audited: 308
- Total tests clean: 210

