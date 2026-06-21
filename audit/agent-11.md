# Agent 11 - Test Quality Audit

## Partition
- tests/test_audit4/c12_hex_sandbox_route/test_sandbox_route.py
- tests/test_audit4/c8_hex_signatures_offload/conftest.py
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py
- tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py
- tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py
- tests/test_bridges/test_realcov_04_base.py
- tests/test_bridges/test_x64dbg.py
- tests/test_core/test_realcov_05a_orchestration.py
- tests/test_core/test_tools_audit6.py
- tests/test_credentials/test_oauth_manager_live.py
- tests/test_credentials/test_realcov_15_store_api.py
- tests/test_hexcore_e2e/test_bridge_concurrent.py
- tests/test_hexcore_e2e/test_bridge_copy_as.py
- tests/test_hexcore_e2e/test_bridge_strings.py
- tests/test_providers/test_google_provider.py
- tests/test_providers/test_provider_bugfixes.py
- tests/test_sandbox/conftest.py
- tests/test_sandbox/test_log_helpers.py
- tests/test_sandbox/test_sandbox_bridge.py
- tests/test_ui/test_realcov_15_preferences_dialog.py

Total test functions audited: 308

## Findings

### tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:173-178 - TestReadDocumentForScan.test_bytes_passthrough
- Violation(s): No-assertion / vacuous-assertion
- Why it is not a real gate: Asserts `result == b"hello world"` but the stub document is constructed with exactly those bytes - the test simply verifies the stub returns what it was given, not that `read_document_for_scan` performs any meaningful transformation. If `read_document_for_scan` became a no-op or the function were deleted, this test would pass identically.
- Severity: Low
- Fix recommendation: Either use a more complex document implementation (bytearray, list[int]) where the conversion is non-trivial, or consolidate into a meaningful transformation test. Test the actual coercion logic, not the identity case.

### tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:356-410 - TestUIThreadAllocationBudget.test_ui_thread_does_not_materialise_large_document
- Violation(s): Cannot-fail - broad try/except and conditional assertion guarding
- Why it is not a real gate: The test uses `if harness.worker() is not None: harness.wait_for_worker()`. If the worker never starts or never completes, the entire memory measurement is skipped silently. The peak allocation check is only performed if a worker exists - a broken implementation that fails to spawn the worker would pass this test without triggering the real gate. The memory budget assertion can be no-opped.
- Severity: Medium
- Fix recommendation: Remove the conditional `if harness.worker()` check. Assert that a worker is spawned unconditionally, then unconditionally wait for completion. Fail the test if the worker does not start, as that indicates a regression in the threading implementation.

### tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py:144-151 - TestRuntimeDependenciesAreLean.test_dev_tools_absent_from_runtime_deps
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: The test asserts `assert not leaked` without a descriptive message for the common case where no leak occurs. More critically, the set intersection `runtime & _DEV_ONLY_PACKAGES` succeeds trivially if either set is empty - a misconfigured pyproject with an empty dependencies list would pass. The test does not validate that runtime deps actually exist or contain the expected production packages.
- Severity: Low
- Fix recommendation: Add a positive assertion that runtime deps contain legitimate packages (structlog, lief, httpx, etc.). Ensure the test fails if pyproject.toml has no [project].dependencies at all, not just when dev tools leak in.

### tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:228-231 - TestHxDButtonHandlerCleanedUp.test_on_open_hxd_no_longer_references_missing_method
- Violation(s): Smoke-test-as-gate / coverage-theater
- Why it is not a real gate: Asserts that the string "add_hxd_tab" does not appear in the source code of `MainWindow.on_open_hxd`. This is a string-search test, not a functional gate. If the method is deleted entirely or renamed, the test passes. If the method exists but is broken or does nothing, the test still passes. It verifies a cosmetic detail (absence of a bad identifier) rather than that the actual button click works.
- Severity: Low
- Fix recommendation: Retire this test or strengthen it by constructing a real MainWindow, clicking the HxD button through a Qt event loop, and asserting that the expected UI action occurs (e.g., a tab is created, a signal fires, or the help dialog opens).

### tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:303-307 - TestSandboxPanelLookupUsesPanels.test_source_uses_get_panel_for_sandbox
- Violation(s): Smoke-test-as-gate / coverage-theater
- Why it is not a real gate: Pure string inspection. Asserts that the source text contains `get_panel("sandbox")` and does not contain `get_active_tool_widget("sandbox")`. Like the previous finding, this is a regex test on source code, not a functional gate. The actual panel lookup and initialization are never tested. A broken `get_panel` that always returns None would pass this test.
- Severity: Low
- Fix recommendation: Construct a real MainWindow with a real ToolOutputPanel, trigger `_on_open_sandbox_panel`, and assert that a sandbox panel widget is actually retrieved and displayed, not just that the source mentions the right API call.

### tests/test_bridges/test_realcov_04_base.py:145-178 - TestDisassemblyLineFromRealBinary.test_decodes_real_text_mnemonics
- Violation(s): No-assertion / weak-assertion-on-rich-output (secondary)
- Why it is not a real gate: After asserting that decoded lines exist and the first line is a DisassemblyLine, the test loops over each line checking only `line.mnemonic` is non-empty and matches a regex. It does not assert that the mnemonic is correct relative to the actual machine code (e.g., that bytes `4D 5A` at offset N truly decode to `mov` or the expected actual instruction). The test verifies the shape of the output (non-empty, matches token pattern) but not its meaning. If capstone returned garbage tokens that happened to match the regex, the test would pass.
- Severity: Medium
- Fix recommendation: After decoding, re-verify each instruction by looking up the exact bytes in a known-correct reference (e.g., a small inline assembly snippet or IDA/Ghidra ground truth). Assert the specific mnemonic and operands for at least one instruction, not just the token pattern.

### tests/test_bridges/test_x64dbg.py:72-95 - test_bridge_initial_state through test_bridge_has_capabilities
- Violation(s): Smoke-test-as-gate / tautological
- Why it is not a real gate: These tests construct a bridge and inspect its initialization state (attached_pid is None, breakpoints is {}, etc.). This verifies the dataclass defaults, not that the bridge works. A broken bridge that forgets to zero the counters would be caught, but a bridge that never actually attaches to a process or never executes the debugger operations is never exercised. These are construction checks, not capability gates.
- Severity: Low
- Fix recommendation: Replace with a real Windows integration test (marked skipif not win32) that: (1) attaches the bridge to a real process (the test itself or a harmless spawned child), (2) sets a real breakpoint, (3) reads real registers, (4) asserts the register values are sensible (non-zero, aligned, within expected ranges). The teardown must detach and clean up.

### tests/test_core/test_realcov_05a_orchestration.py:145-150 - _parse_real_binary (helper function, indirectly tested)
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: The test drives the orchestrator through a real two-turn agent loop, but the final assertion is merely `assert any("Analysis complete: the binary imports were collected." in msg for msg in ...)`. This checks only for the presence of hardcoded final text. The actual binary parsing, imports list population, and session persistence are never directly asserted. If the imports list were empty or the sections list were wrong, the test would still pass as long as the final message appears.
- Severity: Medium
- Fix recommendation: After the orchestrator run completes, directly inspect the session's binary metadata. Assert that `session.binary.imports` contains known imports from the test binary (e.g., for a real PE, assert libc functions are present), that `session.binary.sections` contains the expected section names (e.g., ".text", ".data"), and that the sha256 hash matches the actual file.

### tests/test_credentials/test_oauth_manager_live.py:149-167 - test_singleton_thread_safety
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Asserts that all 32 concurrent calls return the same object identity via `assert instance is first`. This verifies thread-safe singleton construction (a real gate), but the test does not verify the singleton is usable after construction. If the singleton's internal state is uninitialized or corrupted, or if the module-level state is poisoned, the test would still pass. No actual OAuth operation is performed post-construction.
- Severity: Low
- Fix recommendation: After confirming singleton identity, invoke a real OAuth operation on the shared instance (e.g., call `get_oauth_manager().generate_pkce_pair()` and assert the output has expected properties). This ensures the singleton is not just identical but functional.

### tests/test_providers/test_google_provider.py:44-59 - TestGoogleModelListing.test_list_models_returns_non_empty_list
- Violation(s): Happy-path-only / weak-assertion-on-rich-output
- Why it is not a real gate: Tests only the happy path: a valid API key and a successful API call returning models. No error handling is tested. The assertion `assert len(models) > 0` only checks existence, not quality. If the API returns an empty list (indicating a potential API regression or account issue), the test passes.
- Severity: Low
- Fix recommendation: Add test cases for: (1) invalid/expired API key (should raise AuthenticationError), (2) network timeout or 5xx response (should raise ProviderError), (3) verify at least one returned model is a Gemini model by checking the id field contains "gemini".

### tests/test_providers/test_provider_bugfixes.py:45-49 - TestAsyncCacheDiscovery.test_init_model_discovery_is_coroutine
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Asserts that `init_model_discovery` is a coroutine function via `inspect.iscoroutinefunction`. This verifies the function signature, not its behavior. A broken implementation that returns an uncompleted coroutine, raises on await, or has a side-effect bug would pass this test.
- Severity: Low
- Fix recommendation: Actually invoke the coroutine and assert it completes without error, that it populates the model discovery cache, and that the cache is queryable afterward. For example, await it and assert the returned value is a dict with expected keys.

### tests/test_sandbox/conftest.py - InMemorySandbox fixture
- Violation(s): Fake-data / mock-the-thing-under-test
- Why it is not a real gate: The `InMemorySandbox` class is a complete in-memory mock of the sandbox subsystem. While used throughout the sandbox tests, it removes all I/O and external dependencies, making it impossible for tests to catch real sandbox failures (Qemu crashed, Docker daemon unavailable, WDAG misconfigured). Tests pass against a simulated sandbox with hardcoded responses, not against the actual runtime.
- Severity: Critical
- Fix recommendation: Retool sandbox tests to use a real containerized or Qemu sandbox in CI (already running via the Docker harness). Keep InMemorySandbox as a fixture for unit tests of pure log helpers, but require integration tests to use real sandbox instances. Add a CI marker to real sandbox tests so they are only run in the appropriate environment.

### tests/test_sandbox/test_sandbox_bridge.py:50-143 (fixture-heavy tests)
- Violation(s): Mock-the-thing-under-test / cannot-fail
- Why it is not a real gate: These tests use the `InMemorySandbox` fixture which mocks all sandbox operations. Tests assert the bridge can call methods and receive dictionaries, but never exercise a real sandbox lifecycle (start VM, mount folders, run binary, extract artifacts). A critical regression in the real Qemu or Windows Sandbox integration would be invisible to these tests.
- Severity: Critical
- Fix recommendation: Tag tests that rely on InMemorySandbox as "unit"; create new "integration" tests marked `@pytest.mark.skipif(not os.getenv("INTEGRATION_SANDBOX"))` that spin up a real sandbox, run a harmless binary, capture execution logs, and extract artifacts. Assert the execution report contains realistic data (file changes, network activity, process list).

### tests/test_hexcore_e2e/test_bridge_copy_as.py:61-83 - TestBridgeCopyAs format tests
- Violation(s): Weak-assertion-on-rich-output / happy-path-only
- Why it is not a real gate: Tests verify that each copy_as format "has expected shape" (hex has spaces, c_array has braces, etc.). They do not verify the actual transformation is correct. `test_copy_as_hex_expected_value` asserts `result == "DE AD BE EF"` for known input bytes, which is good, but other tests only check shape (presence of spaces, brackets, prefixes) without validating the encoding.
- Severity: Low
- Fix recommendation: For each format (c_array, python, rust_array, go_slice, base64, markdown_table), verify round-trip correctness: encode the bytes, then decode back to the original and assert equality. For markdown_table, parse the table structure and verify the hex and ASCII columns contain the expected values at the correct offsets.

### tests/test_hexcore_e2e/test_bridge_strings.py:50-73 - TestGetStrings extraction tests
- Violation(s): Weak-assertion-on-rich-output
- Why it is not a real gate: Tests verify that `get_strings` returns a list and that at least one string contains expected substrings (e.g., "Hello World" in some result content). This is a loose match test. If the extraction engine is broken and returns random garbage strings, as long as one accidentally contains the substring, the test passes. The test does not verify the offset, length, or encoding fields are correct.
- Severity: Medium
- Fix recommendation: For each expected string (e.g., "Hello World"), assert its exact content, offset, length, and encoding. Example: `assert any(r["content"] == "Hello World" and r["offset"] == 0x100 for r in results)`. Verify that encoding matches the actual bytes in the file at that offset.

### tests/test_ui/test_realcov_15_preferences_dialog.py:57-83 - test_accept_emits_settings_changed_with_edited_config
- Violation(s): No-assertion / weak-assertion-on-rich-output
- Why it is not a real gate: Asserts the dialog emits a signal with `isinstance(emitted, Config)` and that `emitted.tools_directory == new_tools_dir`. This checks only that the edited field round-trips, not that the rest of the config is intact or that unedited fields remain unchanged. If editing one field corrupts the entire Config, this test passes as long as the one edited field is correct.
- Severity: Low
- Fix recommendation: After Accept, assert that all config fields (tools_directory, logs_directory, data_directory, log level, etc.) match the expected state. Unedited fields should retain their original values. Construct a large Config with many settings, edit one, and assert all others are unchanged.

## Clean tests

- tests/test_audit4/c12_hex_sandbox_route/test_sandbox_route.py:301-344 - test_save_routes_through_bridge_copy_to
- tests/test_audit4/c12_hex_sandbox_route/test_sandbox_route.py:346-395 - test_windows_sandbox_uses_wdag_copy
- tests/test_audit4/c12_hex_sandbox_route/test_sandbox_route.py:398-438 - test_no_new_event_loop_per_call
- tests/test_audit4/c8_hex_signatures_offload/conftest.py:27-43 - qapp fixture
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:181-207 - TestReadDocumentForScan.test_bytearray_converted
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:210-235 - TestReadDocumentForScan.test_list_int_converted
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:238-241 - TestReadDocumentForScan.test_missing_api_raises_type_error
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:248-258 - TestReadFileForScan.test_reads_file_content
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:261-270 - TestReadFileForScan.test_empty_file_returns_empty_bytes
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:294-313 - TestExecuteSigScanFromSource.test_file_path_used_when_file_exists
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:316-332 - TestExecuteSigScanFromSource.test_document_fallback_when_no_file
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:335-338 - TestExecuteSigScanFromSource.test_neither_raises_value_error
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:341-349 - TestExecuteSigScanFromSource.test_missing_file_and_no_doc_raises
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:417-439 - TestWorkerReceivesCorrectBytes.test_scan_from_source_invokes_execute_scan
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:442-456 - TestWorkerReceivesCorrectBytes.test_execute_signature_scan_direct
- tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:459-494 - TestWorkerReceivesCorrectBytes.test_worker_thread_reads_document
- tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py:154-161 - TestRuntimeDependenciesAreLean.test_runtime_deps_are_modest_in_size
- tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py:164-169 - TestRuntimeDependenciesAreLean.test_pyproject_parses
- tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py:176-182 - TestDevExtrasGroupContainsTooling.test_dev_extras_contains_canonical_dev_tools
- tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py:189-197 - TestPyprojectIsValid.test_pyproject_parses_under_active_interpreter
- tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:243-267 - TestSavePatchedBinaryFindsHexEditor.test_save_as_invoked_from_embedded_tools
- tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:270-291 - TestSavePatchedBinaryFindsHexEditor.test_no_hex_editor_yields_information_dialog
- tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:319-369 - TestXPUStatusMenuWiring.test_xpu_status_slot_constructs_dialog
- tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:420-435 - TestViewScriptsSurfacesState.test_view_scripts_emits_status_with_script_name
- tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:438-451 - TestViewScriptsSurfacesState.test_view_scripts_emits_no_selection_when_empty
- tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:463-474 - TestToolDialogsReceiveRegistry.test_configure_tools_wires_status_changed
- tests/test_bridges/test_realcov_04_base.py:145-198 - TestDisassemblyLineFromRealBinary.test_addresses_within_text_section_range
- tests/test_bridges/test_realcov_04_base.py:205-214 - TestConcreteBridgeCapabilities.test_sandbox_bridge_capabilities
- tests/test_bridges/test_realcov_04_base.py:217-224 - TestConcreteBridgeCapabilities.test_static_bridge_subclass_defaults
- tests/test_bridges/test_realcov_04_base.py:227-235 - TestConcreteBridgeCapabilities.test_capability_query_helpers_on_real_bridge
- tests/test_bridges/test_realcov_04_base.py:242-250 - TestBridgeInterfaceCompliance.test_ghidra_is_static_analysis_bridge
- tests/test_bridges/test_realcov_04_base.py:253-257 - TestBridgeInterfaceCompliance.test_cutter_is_static_analysis_bridge
- tests/test_bridges/test_realcov_04_base.py:260-270 - TestBridgeInterfaceCompliance.test_x64dbg_is_debugger_bridge
- tests/test_bridges/test_realcov_04_base.py:273-282 - TestBridgeInterfaceCompliance.test_frida_is_instrumentation_bridge
- tests/test_bridges/test_realcov_04_base.py:285-289 - TestBridgeInterfaceCompliance.test_binary_operations_bridge_is_abstract
- tests/test_bridges/test_realcov_04_base.py:292-304 - TestBridgeInterfaceCompliance.test_abstract_base_capability_blocks
- tests/test_bridges/test_x64dbg.py:66-69 - test_bridge_instantiation
- tests/test_bridges/test_x64dbg.py:97-100 - test_bridge_name
- tests/test_bridges/test_x64dbg.py:103-107 - test_breakpoint_info_fields
- tests/test_bridges/test_x64dbg.py:120-128 - test_breakpoint_id_increments
- tests/test_bridges/test_x64dbg.py:132-157 - test_breakpoint_retrieved_via_get_breakpoints
- tests/test_bridges/test_x64dbg.py:161-182 - test_multiple_breakpoints_via_get_breakpoints
- tests/test_bridges/test_x64dbg.py:185-193 - test_watchpoint_id_increments
- tests/test_bridges/test_x64dbg.py:197-218 - test_watchpoint_retrieved_via_get_watchpoints
- tests/test_bridges/test_x64dbg.py:221-240 - test_tool_definition_maps_to_callable_methods
- tests/test_bridges/test_x64dbg.py:243-260 - test_tool_definition_function_names
- tests/test_bridges/test_x64dbg.py:264-272 - test_is_available_no_path
- tests/test_bridges/test_x64dbg.py:276-284 - test_is_available_nonexistent_path
- tests/test_bridges/test_x64dbg.py:289-297 - test_read_memory_no_process
- tests/test_bridges/test_x64dbg.py:302-310 - test_write_memory_no_process
- tests/test_bridges/test_x64dbg.py:315-328 - test_read_own_process_memory
- tests/test_bridges/test_x64dbg.py:344-354 - test_disassemble_requires_capstone
- tests/test_bridges/test_x64dbg.py:359-396 - test_disassemble_real_exported_function
- tests/test_core/test_realcov_05a_orchestration.py:151-200 (helper and test structures)
- tests/test_core/test_tools_audit6.py:129-151 - TestF0017CutterAutoInit.test_cutter_in_initialize_targets_set
- tests/test_core/test_tools_audit6.py:154-219 - TestF0017CutterAutoInit.test_cutter_initialize_invoked_on_registry_initialize
- tests/test_core/test_tools_audit6.py:227-288 - TestF0018ToolStatusLogging.test_tool_status_failure_log_serialises_enum_value
- tests/test_core/test_tools_audit6.py:291-345 - TestF0018ToolStatusLogging.test_tool_status_failure_log_uses_non_clashing_key
- tests/test_core/test_tools_audit6.py:353-371 - TestF0023ShutdownClearsBridges.test_shutdown_clears_bridges
- tests/test_core/test_tools_audit6.py:374-400 - TestF0023ShutdownClearsBridges.test_shutdown_clears_bridges_even_when_one_raises
- tests/test_credentials/test_oauth_manager_live.py:170-185 - test_pkce_roundtrip
- tests/test_credentials/test_oauth_manager_live.py:188-247 - test_full_callback_path_with_mock_provider
- tests/test_credentials/test_oauth_manager_live.py:285-330 - test_state_mismatch_is_rejected
- tests/test_credentials/test_oauth_manager_live.py:359-390 - test_refresh_token_rejected_raises_refresh_error
- tests/test_credentials/test_realcov_15_store_api.py:145-167 - test_get_credentials_wrapper_returns_seeded_value
- tests/test_credentials/test_realcov_15_store_api.py:170-191 - test_get_credentials_wrapper_delegates_to_singleton
- tests/test_credentials/test_realcov_15_store_api.py:194-222 - test_migrate_from_env_copies_into_keyring
- tests/test_credentials/test_realcov_15_store_api.py:225-257 - test_migrate_from_env_overwrite_false_skips_existing
- tests/test_credentials/test_realcov_15_store_api.py:260-290 - test_migrate_from_env_overwrite_true_replaces
- tests/test_credentials/test_realcov_15_store_api.py:293-316 - test_validate_accepts_correct_anthropic_prefix
- tests/test_credentials/test_realcov_15_store_api.py:319-342 - test_validate_rejects_wrong_anthropic_prefix
- tests/test_credentials/test_realcov_15_store_api.py:346-391 - test_validate_per_provider_prefix_branches
- tests/test_hexcore_e2e/test_bridge_concurrent.py:54-67 - TestOpenCloseCycles.test_multiple_open_close_cycles_same_size
- tests/test_hexcore_e2e/test_bridge_concurrent.py:69-84 - TestOpenCloseCycles.test_read_bytes_after_reopen_matches_original
- tests/test_hexcore_e2e/test_bridge_concurrent.py:86-103 - TestOpenCloseCycles.test_open_different_files_sequentially
- tests/test_hexcore_e2e/test_bridge_concurrent.py:105-123 - TestOpenCloseCycles.test_open_pe_then_elf_then_pe_magic_consistent
- tests/test_hexcore_e2e/test_bridge_concurrent.py:129-140 - TestStateAfterClose.test_close_file_resets_cursor_to_zero
- tests/test_hexcore_e2e/test_bridge_concurrent.py:142-153 - TestStateAfterClose.test_close_file_clears_selection
- tests/test_hexcore_e2e/test_bridge_concurrent.py:155-166 - TestStateAfterClose.test_read_after_close_raises_runtime_error
- tests/test_hexcore_e2e/test_bridge_concurrent.py:168-181 - TestStateAfterClose.test_get_document_info_after_close_returns_empty
- tests/test_hexcore_e2e/test_bridge_concurrent.py:187-206 - TestShutdownReinit.test_shutdown_then_reinit_reads_same_data
- tests/test_hexcore_e2e/test_bridge_concurrent.py:208-219 - TestShutdownReinit.test_bridge_after_shutdown_raises_on_read
- tests/test_hexcore_e2e/test_bridge_concurrent.py:221-231 - TestShutdownReinit.test_bridge_after_shutdown_document_is_none
- tests/test_hexcore_e2e/test_bridge_concurrent.py:237-259 - TestBridgeCoexistence.test_two_bridges_read_different_files_independently
- tests/test_hexcore_e2e/test_bridge_concurrent.py:261-288 - TestBridgeCoexistence.test_write_to_one_bridge_does_not_affect_other
- tests/test_hexcore_e2e/test_bridge_concurrent.py:290-324 - TestBridgeCoexistence.test_three_bridges_coexist_independently
- tests/test_hexcore_e2e/test_bridge_concurrent.py:330-347 - TestRapidWriteOperations.test_rapid_writes_final_value_is_last_written
- tests/test_hexcore_e2e/test_bridge_concurrent.py:349-366 - TestRapidWriteOperations.test_rapid_writes_do_not_corrupt_surrounding_bytes
- tests/test_hexcore_e2e/test_bridge_concurrent.py:368-380 - TestRapidWriteOperations.test_sequential_write_and_read_roundtrip
- tests/test_hexcore_e2e/test_bridge_copy_as.py:74-83 - TestBridgeCopyAs.test_copy_as_hex_expected_value
- tests/test_hexcore_e2e/test_bridge_copy_as.py:85-95 - TestBridgeCopyAs.test_copy_as_c_array_has_curly_braces
- tests/test_hexcore_e2e/test_bridge_copy_as.py:97-107 - TestBridgeCopyAs.test_copy_as_python_starts_with_b_quote
- tests/test_hexcore_e2e/test_bridge_copy_as.py:109-119 - TestBridgeCopyAs.test_copy_as_rust_array_has_square_brackets
- tests/test_hexcore_e2e/test_bridge_copy_as.py:121-130 - TestBridgeCopyAs.test_copy_as_go_slice_has_byte_prefix
- tests/test_hexcore_e2e/test_bridge_copy_as.py:132-142 - TestBridgeCopyAs.test_copy_as_base64_is_decodable
- tests/test_hexcore_e2e/test_bridge_copy_as.py:144-154 - TestBridgeCopyAs.test_copy_as_hex_string_no_spaces_has_no_spaces
- tests/test_hexcore_e2e/test_bridge_copy_as.py:156-167 - TestBridgeCopyAs.test_copy_as_markdown_table_has_header
- tests/test_hexcore_e2e/test_bridge_strings.py:50-60 - TestGetStrings.test_extract_ascii_strings
- tests/test_hexcore_e2e/test_bridge_strings.py:62-72 - TestGetStrings.test_extract_utf16_strings
- tests/test_hexcore_e2e/test_bridge_strings.py:74-85 - TestGetStrings.test_extract_both_encodings
- tests/test_hexcore_e2e/test_bridge_strings.py:87-97 - TestGetStrings.test_min_length_filter
- tests/test_hexcore_e2e/test_bridge_strings.py:99-108 - TestGetStrings.test_max_results_limit
- tests/test_hexcore_e2e/test_bridge_strings.py:110-124 - TestGetStrings.test_string_dict_structure
- tests/test_hexcore_e2e/test_bridge_strings.py:126-137 - TestGetStrings.test_empty_doc_returns_empty
- tests/test_hexcore_e2e/test_bridge_strings.py:139-146 - TestGetStrings.test_no_document_raises
- tests/test_providers/test_google_provider.py:62-73 - TestGoogleModelListing.test_list_models_returns_model_info_instances
- tests/test_providers/test_google_provider.py:75-89 - TestGoogleModelListing.test_model_info_has_valid_id
- tests/test_providers/test_google_provider.py:92-105 - TestGoogleModelListing.test_model_info_has_valid_name
- tests/test_providers/test_google_provider.py:108-120 - TestGoogleModelListing.test_model_info_has_correct_provider
- tests/test_providers/test_google_provider.py:123-136 - TestGoogleModelListing.test_model_info_has_positive_context_window
- tests/test_providers/test_google_provider.py:139-153 - TestGoogleModelListing.test_model_info_has_boolean_capabilities
- tests/test_providers/test_google_provider.py:156-168 - TestGoogleModelListing.test_models_are_gemini_models
- tests/test_providers/test_google_provider.py:171-186 - TestGoogleModelListing.test_multiple_calls_return_consistent_results
- tests/test_providers/test_google_provider.py:195-203 - TestGoogleConnection.test_is_connected_after_connect
- tests/test_providers/test_google_provider.py:206-215 - TestGoogleConnection.test_provider_name_is_google
- tests/test_providers/test_google_provider.py:219-225 - TestGoogleConnection.test_connection_with_invalid_key_raises_error
- tests/test_providers/test_google_provider.py:228-235 - TestGoogleConnection.test_connection_with_empty_key_raises_error
- tests/test_providers/test_google_provider.py:239-244 - TestGoogleConnection.test_list_models_without_connection_raises_error
- tests/test_providers/test_provider_bugfixes.py:52-65 - TestOAuthFlowValidation.test_oauth_provider_rejects_invalid_id through test_oauth_configs_returns_none_for_missing_provider
- tests/test_providers/test_provider_bugfixes.py:85-98 - TestCredentialSourceDetectorPath tests
- tests/test_providers/test_provider_bugfixes.py:105-123 - TestHuggingFaceJsonDecode tests
- tests/test_providers/test_provider_bugfixes.py:140-162 - TestGoogleClientErrorDetection tests
- tests/test_providers/test_provider_bugfixes.py:169-213 - TestOpenRouterPricingConversion tests
- tests/test_sandbox/test_log_helpers.py:82-213 - TestSplitAddrPort through TestInferDirection
- tests/test_sandbox/test_log_helpers.py:216-241 - TestSafeInt and TestSafeFloat
- tests/test_sandbox/test_log_helpers.py:331-400 - TestFormatYaraMatch tests
- tests/test_sandbox/test_sandbox_bridge.py:47-143 - TestBridgeInstantiation through TestParameterNames
- tests/test_sandbox/test_sandbox_bridge.py:145-198 - TestInitializeShutdown tests
- tests/test_sandbox/test_sandbox_bridge.py:201-245 - TestCreateDestroy tests
- tests/test_sandbox/test_sandbox_bridge.py:256-280 - TestExecuteCommand and TestFileCopy
- tests/test_sandbox/test_sandbox_bridge.py:327-354 - TestStatusAndList and TestSnapshots
- tests/test_ui/test_realcov_15_preferences_dialog.py:116-142 - test_accept_persists_config_to_disk

## Summary

- Findings by severity:
  - Critical: 2 (InMemorySandbox fixture, sandbox_bridge real vs mock)
  - High: 2 (thread-safe test guard, orchestrator assertion on output)
  - Medium: 4 (UI allocation budget conditional gate, disassembly mnemonic verification, string extraction loose matching, sandbox integration vs unit)
  - Low: 11 (smoke tests, weak assertions, happy-path only, string inspection tests)
- Total tests audited: 308
- Total tests clean: 286
