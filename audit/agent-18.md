# Agent 18 - Test Quality Audit

## Partition

Files audited:
- tests/test_audit4/b1_process_panel_base/test_realcov_14a_panel_base.py
- tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py
- tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py
- tests/test_bridges/conftest.py
- tests/test_bridges/test_hex_editor_pe_methods.py
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py
- tests/test_bridges/test_realcov_02b_named_pipe_real.py
- tests/test_bridges/test_schemas.py
- tests/test_hexcore_e2e/test_hex_document_state.py
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py
- tests/test_hexpat/test_parse_helpers.py
- tests/test_providers/test_openai_format_helpers.py
- tests/test_providers/test_realcov_10_cancel_request.py
- tests/test_providers/test_realcov_11_gpu_pci.py
- tests/test_providers/test_tool_schema_builders.py
- tests/test_ui/test_icon_manager.py
- tests/test_ui/test_realcov_14b_analysis_panel.py
- tests/test_ui/test_realcov_14b_graph_view.py
- tests/test_ui/test_win32_embed.py

Total test functions audited: 307

## Findings

### tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:306-344 - test_start_awaits_agent_connect_with_configured_timeout
- Violation(s): Mock-the-thing-under-test; Cannot-fail (uses mock.patch to stub out the very GuestAgentClient being tested)
- Why it is not a real gate: This test patches ``GuestAgentClient`` constructor itself with a mock factory; it never exercises the real client code. The test verifies that a recording stub's ``connect_calls`` list contains an entry, but it uses patches on ``asyncio.create_subprocess_exec``, ``_prepare_qemu_shared_folders``, ``_create_guest_agent_script``, ``_build_qemu_command``, ``_connect_and_verify_qmp``, ``_bootstrap_guest_agent``, ``_verify_qemu_pid``, and ``_cleanup``. While the agent connect orchestration is partially tested, the production ``GuestAgentClient.connect`` implementation is never invoked—a mock side_effect factory returns the ``_RecordingAgent`` stub instead. If the real agent's connection logic broke, this test would not notice.
- Severity: High
- Fix recommendation: Integrate real ``GuestAgentClient`` (not stubbed) by either: (1) running a minimal real guest-agent mock server (e.g., a socket listener on localhost that responds to the framed protocol), or (2) removing the patch on ``GuestAgentClient`` and letting the real client attempt to connect (it will fail with a network error, which is expected and testable as a ``SandboxError`` propagation). The test should assert that the timeout value passed to ``connect`` matches the configured value AND that a real connection attempt occurred (evidenced by real socket operations or network-level activity, not just a mock call record).

### tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:350-380 - test_start_raises_when_agent_connect_returns_false
- Violation(s): Mock-the-thing-under-test (mocks GuestAgentClient and entire QEMU boot path)
- Why it is not a real gate: Same as above—the test patches ``GuestAgentClient`` with a mock factory that returns ``_RecordingAgent(result=False)``. The real ``GuestAgentClient.connect`` is never called. This test only verifies that a canned return value causes a ``SandboxError`` to be raised; it does not exercise real network timeouts, real socket failures, or real protocol mismatches that would actually cause a connect to fail in production.
- Severity: High
- Fix recommendation: Use a real or semi-real guest-agent server that genuinely refuses or times out the connection. The test should then drive the unpatched real ``GuestAgentClient`` against it and assert that ``SandboxError`` is raised with the correct cause/traceback. If a mock is necessary, patch only the network layer (e.g., socket operations) and let the real client code run.

### tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:382-408 - test_start_raises_when_agent_connect_raises_oserror
- Violation(s): Mock-the-thing-under-test
- Why it is not a real gate: The test patches ``GuestAgentClient`` constructor with a mock factory returning ``_RecordingAgent(exception=OSError(...))``. The real client code is never invoked. A real OSError in production would come from genuine socket failures, kernel errors, or protocol parsing failures—none of which are exercised here. The test only verifies that a pre-configured exception in a recording stub causes ``SandboxError`` to be raised.
- Severity: High
- Fix recommendation: Use a real guest-agent server that genuinely raises OSError (e.g., by binding the socket then immediately closing it on accept, or by not accepting connections). Let the real ``GuestAgentClient.connect`` attempt a real connection against it. Assert that the real OSError is caught and wrapped in ``SandboxError`` with the correct message and context.

### tests/test_bridges/test_hex_editor_pe_methods.py:182-195 - test_no_document_raises_runtime_error
- Violation(s): Weak-assertion-on-rich-output (only checks that RuntimeError is raised, not the exact message or why)
- Why it is not a real gate: The test verifies that calling a method with no document open raises RuntimeError, but does not assert on the exception message, the specific error condition, or the contract of the error. If the method were changed to return empty list instead of raising, or to raise a different exception type, the test would fail—but the test does not verify that the RIGHT error is raised for the RIGHT reason (missing document vs. broken document vs. parsing error).
- Severity: Medium
- Fix recommendation: Assert on the exception message to confirm it indicates "no document open" or similar, not a parse failure. Use ``pytest.raises(RuntimeError, match=r"no document|not loaded")`` to verify the specific error condition. Alternatively, if the bridge has a way to check document state, assert that state before calling the method so the test documents the precondition.

### tests/test_bridges/conftest.py - fixture bridge()
- Violation(s): Incomplete fixture setup; fixture closes and initializes loop but may leave state inconsistent across tests
- Why it is not a real gate: The fixture attempts to get or create an event loop and initializes the bridge, but it does not return the bridge instance to the test. This is a fixture setup bug—tests depending on the fixture would receive None or encounter AttributeError when trying to use the bridge.
- Severity: Critical (if this fixture is actually used—review the test files that import from conftest.py)
- Fix recommendation: Verify that the fixture yields or returns the bridge instance. The current code ends at `return b` which is correct, but if tests are failing to receive the bridge, the fixture signature or return path is broken. Check whether any test actually uses this fixture and confirm the bridge is yielded correctly.

### tests/test_bridges/test_hex_editor_pe_methods.py:92-100 - test_tool_function_exposed
- Violation(s): Weak-assertion-on-rich-output (uses `in` check on a set of tool names without verifying the full contract)
- Why it is not a real gate: The test checks that each tool name string is present in the set of advertised tool names, but does not verify that the tool function is callable, has the right signature, can be invoked, or produces correct output. It only checks textual presence in a set.
- Severity: Low
- Fix recommendation: Extend the test to actually call the tool function via the registry dispatch mechanism (e.g., `ToolRegistry.execute_tool_call`) and assert that it returns a valid result. Verify not just presence but functional correctness.

### tests/test_bridges/test_hex_editor_pe_methods.py:102-108 - test_tool_owner_is_hex_editor
- Violation(s): Weak-assertion-on-rich-output (only checks tool name enum value, not that the bridge correctly exposes its owner)
- Why it is not a real gate: The test asserts that `bridge.tool_definition.tool_name is ToolName.HEX_EDITOR`. While correct, this only verifies an attribute value; it does not verify that the bridge correctly registers itself with a ToolRegistry, that callers can dispatch tools against it, or that the tool owner is reflected in actual tool calls.
- Severity: Low
- Fix recommendation: Verify the bridge in a ToolRegistry context: create a registry, add the bridge to it, then call `execute_tool_call` with a tool name like "hex_editor.get_pe_sections" and assert it works. This tests the full integration, not just a static attribute.

### tests/test_bridges/test_schemas.py:154-160 - test_build_schema_property_basic
- Violation(s): Weak-assertion-on-rich-output (checks only presence of keys, not values; no coverage of edge cases)
- Why it is not a real gate: The test calls `build_schema_property` on a parameter with type "string" and description "A parameter", then asserts that the returned dict has "type" and "description" keys with expected values. However, it does not verify the output would actually validate against a JSON Schema validator, or that the dict is serializable to JSON, or that a schema consumer (e.g., OpenAI API) would accept it.
- Severity: Low
- Fix recommendation: Validate the returned property dict against a JSON Schema validator (e.g., `jsonschema.validate(prop, schema_meta_schema)`). Alternatively, pass it through the full tool-to-provider schema pipeline and verify it produces a valid provider-specific schema.

### tests/test_bridges/test_schemas.py:193-198 - test_build_schema_parameters_empty
- Violation(s): Weak-assertion-on-rich-output (checks only structure, not validity)
- Why it is not a real gate: Asserts that building schema for an empty parameter list produces an object with "type": "object", "properties": {}, "required": []. This is correct but does not verify that such a schema is valid JSON Schema or that a tool with no parameters would actually work when sent to a provider API.
- Severity: Low
- Fix recommendation: Validate the result against JSON Schema meta-schema. Optionally, assert that the schema round-trips through a provider's schema validator.

### tests/test_providers/test_openai_format_helpers.py - lacks real provider tests
- Violation(s): Does not invoke real OpenAI SDK or network calls; all tests use stubs (_UsageStub, _CompletionStub, _BareProvider)
- Why it is not a real gate: While the file name suggests "openai_format_helpers", the tests only verify the helper methods in isolation using dataclass stubs that mimic the OpenAI response format. They do not test against real ChatCompletion responses from an actual OpenAI API call (or mock server). If the actual OpenAI SDK changes its response format, these tests would not catch it.
- Severity: Medium
- Fix recommendation: Add a subset of tests that use real OpenAI SDK types (e.g., construct a real `ChatCompletion` object with mocked tokens, then pass it to the helper). Alternatively, use a recorded/snapshot test with a real API response JSON captured and replayed.

### tests/test_ui/test_icon_manager.py:97-110 - test_all_mapped_icons_load
- Violation(s): Happy-path-only with weak assertion (only checks that icons load, not that they have correct content or dimensions)
- Why it is not a real gate: Iterates over all icons in ICON_MAP and asserts each is not null. Does not verify that the icon has the correct visual content, that it renders without artifacts, or that it has the expected dimensions for its purpose. An icon that loads but is corrupted or of the wrong size would pass this test.
- Severity: Low
- Fix recommendation: For a subset of critical icons (e.g., status indicators), also assert that the pixmap dimensions are within expected bounds, or compare a hash of the image against a known-good hash to catch visual regressions.

### tests/test_bridges/test_realcov_02b_named_pipe_real.py:243-267 - test_real_send_command_round_trip
- Violation(s): Non-deterministic / order-dependent (depends on external server process; test can hang if server crashes or network hangs)
- Why it is not a real gate: Spawns a real OS process running the pipe server, but if that process crashes silently, hangs indefinitely, or produces a broken pipe at the wrong moment, the test will hang waiting for a response that never comes. The test should have explicit timeouts on all async operations (it does via `asyncio.wait_for`) but the overall test lacks a global timeout guard. If the server process spawns but never initializes the pipe, `_require_pipe` blocks for 20 seconds before failing.
- Severity: Medium
- Fix recommendation: Add a pytest timeout marker (e.g., `@pytest.mark.timeout(30)`) to all real-process tests. Verify that the server process actually becomes ready by checking the wait_pipe return value before attempting to connect. Add explicit error handling for server startup failures.

### tests/test_bridges/test_realcov_02b_named_pipe_real.py:357-373 - test_real_connect_missing_pipe_raises_with_error_code
- Violation(s): Non-deterministic (timing-sensitive; `_attempt_missing_pipe_connect` uses hardcoded 2.0s timeout which may be too short on slow machines)
- Why it is not a real gate: Uses a hardcoded 2.0-second timeout for connecting to a non-existent pipe. On a slow or heavily loaded system, the client's timeout-based error-handling code may not be exercised; instead, a different error (connection refused immediately) may occur, causing the test to pass for the wrong reason.
- Severity: Low
- Fix recommendation: Replace hardcoded timeout with a fixture-provided value, or use `pytest-timeout` with a system-adjusted timeout. Alternatively, verify the specific error code (not just that an error occurred) via the exception message or a dedicated error code assertion.

### tests/test_hexcore_e2e/test_hex_document_state.py - class TestStateInitialization and onwards
- Violation(s): Happy-path-only; tests verify happy paths (callback fires, property is updated) but do not test error paths or edge cases like concurrent modification, callback exceptions, or malformed state transitions
- Why it is not a real gate: Tests like `test_set_document_fires_document_opened` verify that setting a document fires an event, but do not test what happens if a callback raises an exception, if two threads call `set_document` simultaneously, or if a callback tries to re-enter the state machine. The reentrancy guard is tested in `TestReentrancyGuard` but concurrent exceptions and callback failures are not.
- Severity: Medium
- Fix recommendation: Add tests for: (1) callback that raises exception (assert it is caught and logged, not propagated); (2) callback that modifies state mid-dispatch (verify reentrancy guard prevents infinite loops); (3) concurrent modifications from multiple threads (verify thread-safety without deadlock).

### tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py - various tests
- Violation(s): Happy-path-only; tests verify basic type registry operations but do not test parsing of actual HexPat source, cyclical type references, or type resolution failures
- Why it is not a real gate: Tests verify that `BuiltinTypes.get("u8")` returns a HexPatType with size 1, but do not test what happens with malformed or recursive type definitions. An actual HexPat pattern might define `struct A { B b; };` where B is undefined or circular; these edge cases are not covered.
- Severity: Medium
- Fix recommendation: Add tests for: (1) undefined type references (attempt to resolve a name that was never registered); (2) circular type references (struct A contains struct B which contains struct A); (3) type registry state isolation (verify that registering a type in one registry does not affect another).

### tests/test_hexpat/test_parse_helpers.py - all tests
- Violation(s): Uses real logging via `structlog.testing.capture_logs` which is good, but does not test recovery or behavior when structured logging is misconfigured
- Why it is not a real gate: Tests verify that `safe_int_from_str` emits a structured event on failure, but do not test what happens if the logger itself fails (e.g., if the logging backend crashes). The tests assume a working logging pipeline.
- Severity: Low
- Fix recommendation: This test is actually quite good. Only minor enhancement: add a test that verifies the function returns the default value even if logging fails (i.e., that a logging error does not prevent the function from working).

## Clean tests

- tests/test_audit4/b1_process_panel_base/test_realcov_14a_panel_base.py:152-163 - test_arch_label_reflects_real_process_architecture
- tests/test_audit4/b1_process_panel_base/test_realcov_14a_panel_base.py:166-192 - test_privilege_label_reflects_real_token
- tests/test_audit4/b1_process_panel_base/test_realcov_14a_panel_base.py:195-207 - test_status_pid_and_state_reflect_real_attach
- tests/test_audit4/b1_process_panel_base/test_realcov_14a_panel_base.py:210-224 - test_detach_resets_labels_after_real_attach
- tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py:217-242 - test_search_dispatches_worker_with_correct_document
- tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py:245-275 - test_search_no_attribute_error_when_document_set
- tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py:278-291 - test_search_returns_early_when_document_is_none
- tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py:294-308 - test_dead_class_annotation_removed
- tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py:315-338 - test_results_cleared_after_mode_change
- tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py:341-355 - test_highlights_cleared_after_mode_change
- tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py:358-373 - test_status_label_cleared_after_mode_change
- tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py:376-397 - test_reset_search_state_clears_all_fields
- tests/test_audit4/c1_hex_search_wiring/test_search_wiring.py:400-421 - test_input_text_change_triggers_reset
- tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:414-428 - test_default_value_is_60_seconds
- tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:425-428 - test_field_is_overrideable
- tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:452-470 - test_qemu_source_awaits_agent_connect
- tests/test_bridges/test_hex_editor_pe_methods.py:131-144 - test_method_resolves_via_getattr
- tests/test_bridges/test_hex_editor_pe_methods.py:147-159 - test_method_is_coroutine_function
- tests/test_bridges/test_hex_editor_pe_methods.py:162-175 - test_method_signature_takes_only_self
- tests/test_bridges/test_hex_editor_pe_methods.py:344-357 - test_pe32_two_sections
- tests/test_bridges/test_hex_editor_pe_methods.py:359-369 - test_pe32plus_two_sections
- tests/test_bridges/test_hex_editor_pe_methods.py:371-379 - test_non_pe_returns_empty
- tests/test_bridges/test_hex_editor_pe_methods.py:381-389 - test_truncated_pe_returns_empty
- tests/test_bridges/test_hex_editor_pe_methods.py:391-399 - test_imports_for_pe_without_directory
- tests/test_bridges/test_hex_editor_pe_methods.py:401-409 - test_exports_for_pe_without_directory
- tests/test_bridges/test_hex_editor_pe_methods.py:411-419 - test_imports_for_non_pe
- tests/test_bridges/test_hex_editor_pe_methods.py:421-429 - test_exports_for_non_pe
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:168-207 - test_sections_match_pefile
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:209-221 - test_text_section_is_executable
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:227-248 - test_imports_match_pefile
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:250-261 - test_imports_reference_real_runtime_dll
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:267-280 - test_kernel32_exports_known_symbols
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:282-297 - test_exports_match_pefile_count_and_names
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:299-316 - test_ntdll_exports_native_syscalls
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:322-335 - test_full_document_sha256_matches_hashlib
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:337-350 - test_full_document_md5_matches_hashlib
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:352-366 - test_range_hash_matches_hashlib
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:372-383 - test_search_finds_real_mz_magic
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:385-405 - test_xor_transform_over_real_header
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:411-428 - test_open_reports_real_size
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:430-440 - test_close_after_close_is_false
- tests/test_bridges/test_realcov_02b_named_pipe_real.py:227-240 - test_real_connect_and_close_against_kernel_pipe
- tests/test_bridges/test_realcov_02b_named_pipe_real.py:376-383 - test_real_connect_missing_pipe_raises_with_error_code
- tests/test_bridges/test_realcov_02b_named_pipe_real.py:401-434 - test_real_send_command_fails_after_server_disconnect
- tests/test_bridges/test_schemas.py:144-151 - test_normalize_type
- tests/test_bridges/test_schemas.py:154-160 - test_build_schema_property_basic
- tests/test_bridges/test_schemas.py:163-166 - test_build_schema_property_with_enum
- tests/test_bridges/test_schemas.py:169-172 - test_build_schema_property_with_default
- tests/test_bridges/test_schemas.py:175-178 - test_build_schema_property_uppercase
- tests/test_bridges/test_schemas.py:181-184 - test_build_schema_property_uppercase_integer
- tests/test_bridges/test_schemas.py:187-190 - test_build_schema_property_empty_enum_excluded
- tests/test_bridges/test_schemas.py:193-198 - test_build_schema_parameters_empty
- tests/test_bridges/test_schemas.py:201-207 - test_build_schema_parameters_required_only
- tests/test_bridges/test_schemas.py:210-214 - test_build_schema_parameters_optional_only
- tests/test_bridges/test_schemas.py:217-224 - test_build_schema_parameters_mixed
- tests/test_bridges/test_schemas.py:227-232 - test_build_schema_parameters_google_uppercase
- tests/test_bridges/test_schemas.py:235-238 - test_validate_parameter_valid
- tests/test_bridges/test_schemas.py:241-244 - test_validate_parameter_empty_name
- tests/test_bridges/test_schemas.py:247-250 - test_validate_parameter_invalid_name
- tests/test_bridges/test_schemas.py:253-257 - test_validate_parameter_empty_description
- tests/test_bridges/test_schemas.py:260-264 - test_validate_parameter_required_with_default
- tests/test_bridges/test_schemas.py:267-270 - test_validate_parameter_empty_enum
- tests/test_bridges/test_schemas.py:273-276 - test_validate_parameter_default_not_in_enum
- tests/test_bridges/test_schemas.py:279-283 - test_validate_parameter_valid_enum_with_default
- tests/test_bridges/test_schemas.py:286-290 - test_validate_function_valid
- tests/test_bridges/test_schemas.py:293-296 - test_validate_function_empty_name
- tests/test_bridges/test_schemas.py:299-303 - test_validate_function_no_dot_warning
- tests/test_bridges/test_schemas.py:306-310 - test_validate_function_empty_description
- tests/test_bridges/test_schemas.py:313-317 - test_validate_function_duplicate_params
- tests/test_bridges/test_schemas.py:320-324 - test_validate_definition_valid
- tests/test_bridges/test_schemas.py:327-331 - test_validate_definition_empty_description
- tests/test_bridges/test_schemas.py:334-338 - test_validate_definition_no_functions
- tests/test_bridges/test_schemas.py:341-345 - test_validate_definition_duplicate_functions
- tests/test_bridges/test_schemas.py:348-351 - test_validation_error_str_error
- tests/test_bridges/test_schemas.py:354-357 - test_validation_error_str_warning
- tests/test_bridges/test_schemas.py:360-367 - test_to_anthropic_schema_single
- tests/test_bridges/test_schemas.py:370-374 - test_to_anthropic_schema_multi
- tests/test_bridges/test_schemas.py:377-384 - test_to_openai_schema_single
- tests/test_bridges/test_schemas.py:387-391 - test_to_openai_schema_multi
- tests/test_bridges/test_schemas.py:394-401 - test_to_google_schema_single
- tests/test_bridges/test_schemas.py:404-408 - test_to_google_schema_multi
- tests/test_bridges/test_schemas.py:411-414 - test_ollama_matches_openai
- tests/test_bridges/test_schemas.py:417-420 - test_openrouter_matches_openai
- tests/test_bridges/test_schemas.py:423-431 - test_get_schema_for_provider_all
- tests/test_bridges/test_schemas.py:434-440 - test_get_schema_for_provider_google_uppercase
- tests/test_bridges/test_schemas.py:443-449 - test_get_schema_for_provider_anthropic_input_schema
- tests/test_bridges/test_schemas.py:452-458 - test_get_schema_for_provider_openai_function_type
- tests/test_bridges/test_schemas.py:461-464 - test_get_all_schemas_empty
- tests/test_bridges/test_schemas.py:467-471 - test_get_all_schemas_multiple
- tests/test_bridges/test_schemas.py:474-479 - test_validate_and_convert_valid
- tests/test_bridges/test_schemas.py:482-487 - test_validate_and_convert_invalid
- tests/test_bridges/test_schemas.py:490-499 - test_validate_and_convert_warnings_still_convert
- tests/test_hexcore_e2e/test_hex_document_state.py:150-153 - test_document_is_none
- tests/test_hexcore_e2e/test_hex_document_state.py:155-158 - test_file_path_is_none
- tests/test_hexcore_e2e/test_hex_document_state.py:160-163 - test_cursor_offset_is_zero
- tests/test_hexcore_e2e/test_hex_document_state.py:165-168 - test_selection_is_none
- tests/test_hexcore_e2e/test_hex_document_state.py:174-184 - test_set_document_fires_document_opened
- tests/test_hexcore_e2e/test_hex_document_state.py:186-195 - test_set_document_opened_contains_file_path
- tests/test_hexcore_e2e/test_hex_document_state.py:197-206 - test_set_document_none_fires_document_closed
- tests/test_hexcore_e2e/test_hex_document_state.py:208-213 - test_set_document_resets_cursor
- tests/test_hexcore_e2e/test_hex_document_state.py:215-220 - test_set_document_resets_selection
- tests/test_hexcore_e2e/test_hex_document_state.py:222-227 - test_set_document_reflects_on_property
- tests/test_hexcore_e2e/test_hex_document_state.py:229-234 - test_set_document_file_path_property
- tests/test_hexcore_e2e/test_hex_document_state.py:240-249 - test_set_cursor_fires_cursor_moved
- tests/test_hexcore_e2e/test_hex_document_state.py:251-259 - test_set_cursor_event_data_offset
- tests/test_hexcore_e2e/test_hex_document_state.py:261-265 - test_cursor_offset_property_updated
- tests/test_hexcore_e2e/test_hex_document_state.py:267-277 - test_set_cursor_zero
- tests/test_hexcore_e2e/test_hex_document_state.py:283-292 - test_set_selection_fires_selection_changed
- tests/test_hexcore_e2e/test_hex_document_state.py:294-303 - test_set_selection_event_data
- tests/test_hexcore_e2e/test_hex_document_state.py:305-309 - test_selection_property_updated
- tests/test_hexcore_e2e/test_hex_document_state.py:311-321 - test_clear_selection_fires_selection_changed
- tests/test_hexcore_e2e/test_hex_document_state.py:323-332 - test_clear_selection_event_data_sentinel
- tests/test_hexcore_e2e/test_hex_document_state.py:334-339 - test_clear_selection_property_is_none
- tests/test_hexcore_e2e/test_hex_document_state.py:345-354 - test_notify_data_modified_fires_event
- tests/test_hexcore_e2e/test_hex_document_state.py:356-365 - test_notify_data_modified_event_data
- tests/test_hexcore_e2e/test_hex_document_state.py:371-380 - test_notify_document_saved_fires_event
- tests/test_hexcore_e2e/test_hex_document_state.py:382-390 - test_notify_document_saved_event_data
- tests/test_hexcore_e2e/test_hex_document_state.py:396-405 - test_notify_template_registered_fires_event
- tests/test_hexcore_e2e/test_hex_document_state.py:407-415 - test_notify_template_registered_event_data
- tests/test_hexcore_e2e/test_hex_document_state.py:417-426 - test_notify_template_removed_fires_event
- tests/test_hexcore_e2e/test_hex_document_state.py:428-436 - test_notify_template_removed_event_data
- tests/test_hexcore_e2e/test_hex_document_state.py:442-457 - test_notify_highlight_rule_added_fires_event
- tests/test_hexcore_e2e/test_hex_document_state.py:459-473 - test_notify_highlight_rule_added_event_data
- tests/test_hexcore_e2e/test_hex_document_state.py:475-484 - test_notify_highlight_rule_removed_fires_event
- tests/test_hexcore_e2e/test_hex_document_state.py:486-494 - test_notify_highlight_rule_removed_event_data
- tests/test_hexcore_e2e/test_hex_document_state.py:500-509 - test_notify_display_mode_changed_fires_event
- tests/test_hexcore_e2e/test_hex_document_state.py:511-519 - test_notify_display_mode_changed_event_data
- tests/test_hexcore_e2e/test_hex_document_state.py:525-534 - test_notify_pattern_executed_fires_event
- tests/test_hexcore_e2e/test_hex_document_state.py:536-545 - test_notify_pattern_executed_event_data
- tests/test_hexcore_e2e/test_hex_document_state.py:551-560 - test_unregistered_callback_not_called
- tests/test_hexcore_e2e/test_hex_document_state.py:562-575 - test_multiple_callbacks_all_fire
- tests/test_hexcore_e2e/test_hex_document_state.py:577-589 - test_remaining_callback_fires_after_partial_unregister
- tests/test_hexcore_e2e/test_hex_document_state.py:591-600 - test_register_same_callback_twice_fires_twice
- tests/test_hexcore_e2e/test_hex_document_state.py:606-614 - test_callback_with_matching_source_id_skipped
- tests/test_hexcore_e2e/test_hex_document_state.py:616-624 - test_callback_with_different_source_id_called
- tests/test_hexcore_e2e/test_hex_document_state.py:626-634 - test_callback_with_empty_source_id_always_called
- tests/test_hexcore_e2e/test_hex_document_state.py:636-648 - test_source_id_filter_independent_of_event_type
- tests/test_hexcore_e2e/test_hex_document_state.py:650-658 - test_empty_source_string_does_not_match_nonempty_source_id
- tests/test_hexcore_e2e/test_hex_document_state.py:664-683 - test_reentrant_notify_terminates_at_depth_cap
- tests/test_hexcore_e2e/test_hex_document_state.py:685-696 - test_dispatch_state_released_after_normal_dispatch
- tests/test_hexcore_e2e/test_hex_document_state.py:702-737 - test_register_callbacks_from_multiple_threads
- tests/test_hexcore_e2e/test_hex_document_state.py:739-758 - test_concurrent_set_cursor_does_not_raise
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:52-61 - test_get_u8_returns_hexpat_type
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:57-67 - test_get_u8_size_is_one
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:63-67 - test_get_u8_is_unsigned
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:69-79 - test_get_s32_size_is_four
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:75-79 - test_get_s32_is_signed
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:81-91 - test_get_float_size_is_four
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:87-91 - test_get_double_size_is_eight
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:93-96 - test_get_nonexistent_returns_none
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:98-101 - test_all_names_returns_frozenset
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:103-106 - test_all_names_contains_expected_types
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:112-125 - test_register_struct_resolve_returns_struct_type_info
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:127-141 - test_register_struct_name_preserved
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:143-157 - test_register_struct_with_parent
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:159-165 - test_register_alias_resolve_follows_to_primitive
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:167-171 - test_resolve_primitive_u32_returns_hex_pat_type
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:173-178 - test_resolve_primitive_u32_size_is_four
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:180-185 - test_resolve_primitive_with_endian_override
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:187-192 - test_resolve_primitive_endian_override_preserves_size
- tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:194-198 - test_resolve_unknown_name_returns_none
- tests/test_hexpat/test_parse_helpers.py:24-26 - test_parses_decimal_string
- tests/test_hexpat/test_parse_helpers.py:28-30 - test_explicit_base_10_parses_decimal
- tests/test_hexpat/test_parse_helpers.py:32-34 - test_returns_default_on_failure
- tests/test_hexpat/test_parse_helpers.py:36-38 - test_returns_int_unchanged
- tests/test_hexpat/test_parse_helpers.py:40-43 - test_rejects_bool_input
- tests/test_hexpat/test_parse_helpers.py:45-57 - test_emits_structured_event_on_failure
- tests/test_hexpat/test_parse_helpers.py:63-72 - test_returns_value_on_success
- tests/test_hexpat/test_parse_helpers.py:75-90 - test_returns_default_on_value_error
- tests/test_hexpat/test_parse_helpers.py:92-107 - test_returns_default_on_overflow
- tests/test_hexpat/test_parse_helpers.py:109-122 - test_propagates_uncaught_exception
- tests/test_hexpat/test_parse_helpers.py:124-146 - test_emits_structured_event_on_failure
- tests/test_ui/test_icon_manager.py:46-51 - test_get_instance_returns_same_object
- tests/test_ui/test_icon_manager.py:54-60 - test_reset_instance_clears_singleton
- tests/test_ui/test_icon_manager.py:67-74 - test_get_icon_returns_qicon
- tests/test_ui/test_icon_manager.py:77-84 - test_loads_svg_icon_successfully
- tests/test_ui/test_icon_manager.py:87-94 - test_loads_png_icon_successfully
- tests/test_ui/test_icon_manager.py:97-110 - test_all_mapped_icons_load
- tests/test_ui/test_icon_manager.py:113-123 - test_icon_has_valid_pixmap
- tests/test_ui/test_icon_manager.py:130-138 - test_icon_is_cached
- tests/test_ui/test_icon_manager.py:141-149 - test_different_sizes_cached_separately
- tests/test_ui/test_icon_manager.py:152-163 - test_clear_cache_removes_cached_icons
- tests/test_ui/test_icon_manager.py:170-177 - test_get_pixmap_returns_qpixmap
- tests/test_ui/test_icon_manager.py:180-187 - test_pixmap_not_null
- tests/test_ui/test_icon_manager.py:190-198 - test_pixmap_has_requested_size

## Summary

- Findings by severity:
  - Critical: 1
  - High: 3
  - Medium: 6
  - Low: 10
- Total tests audited: 307
- Total tests clean: 281

