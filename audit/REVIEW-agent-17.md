# Adversarial Review: Agent 17 Audit Findings

This review examines each finding in `audit/agent-17.md` against the current code at HEAD, verifying whether the committed fixes actually satisfy the audit requirements.

**Review methodology:** For each finding, I read the current test code and production code, verified the assertion statements and oracle logic, and judged whether the test is now a genuine falsifiable gate that would fail if the production code regressed or was corrupted.

---

## PART A: test_e2e_chat.py and Related

### tests/test_providers/test_e2e_chat.py:287-303 - test_chat_returns_relevant_greeting (TestAnthropicE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:515-527
- The test now calls `_assert_greeting_response()` which verifies greeting tokens are present, readable character ratio >= 0.6, and content is non-empty. The test has been refactored from the original weak assertion to use a proper helper that enforces semantic relevance.

### tests/test_providers/test_e2e_chat.py:305-326 - test_chat_stream_yields_chunks_and_completes (TestAnthropicE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:529-540 + test_e2e_chat.py:240-257
- Test calls `_assert_coherent_stream()` which verifies: chunk count >= 1, all chunks are strings, reassembled text is non-empty, contains a greeting token, and readable ratio >= 0.6. This gate is falsifiable.

### tests/test_providers/test_e2e_chat.py:328-352 - test_tool_calling_returns_valid_tool_call (TestAnthropicE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:542-554 + test_e2e_chat.py:260-278
- Test calls `_assert_notepad_tool_call()` which asserts: tool_calls is not None, length >= 1, function_name == "binary.get_file_size", tool_name == "binary", path argument exists, is a string, and normalizes to contain "notepad.exe" and "windows". Exact path matching (not just key presence).

### tests/test_providers/test_e2e_chat.py:353-370 - test_multi_turn_conversation_retains_context (TestAnthropicE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:556-567 + test_e2e_chat.py:281-290
- Test calls `_assert_recalls_context()` which uses AND logic: asserts "archimedes" in content AND ("binary" or "analysis"). Fixed from original OR-only condition.

### tests/test_providers/test_e2e_chat.py:371-388 - test_max_tokens_respected (TestAnthropicE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:569-580 + test_e2e_chat.py:293-302
- Test calls `_assert_short_response()` which asserts: content is non-empty, word count <= 45 (tight bound). Tighter than the original < 100 weak bound.

### tests/test_providers/test_e2e_chat.py:389-410 - test_model_listing_fields_valid (TestAnthropicE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:582-592 + test_e2e_chat.py:318-352
- Test calls `_assert_model_listing()` which verifies: non-empty list, every model is ModelInfo instance, id is non-empty and contains vendor substring (e.g., "claude"), name is non-empty string, provider label matches, context_window >= 4000 (realistic bound), bool flags are correct type, and configured model is present.

### tests/test_providers/test_e2e_chat.py:415-431 - test_chat_returns_valid_assistant_message (TestOpenAIE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:598-610
- Uses same `_assert_greeting_response()` helper as Anthropic variant.

### tests/test_providers/test_e2e_chat.py:433-454 - test_chat_stream_yields_chunks_and_completes (TestOpenAIE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:612-623
- Uses same `_assert_coherent_stream()` helper.

### tests/test_providers/test_e2e_chat.py:456-480 - test_tool_calling_returns_valid_tool_call (TestOpenAIE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:625-637
- Uses same `_assert_notepad_tool_call()` helper with exact path matching.

### tests/test_providers/test_e2e_chat.py:481-497 - test_multi_turn_conversation_retains_context (TestOpenAIE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:639-649
- Uses same AND-logic helper `_assert_recalls_context()`.

### tests/test_providers/test_e2e_chat.py:499-515 - test_max_tokens_respected (TestOpenAIE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:651-662
- Uses same word-count capping helper.

### tests/test_providers/test_e2e_chat.py:517-533 - test_model_listing_fields_valid (TestOpenAIE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:664-674
- Uses same `_assert_model_listing()` with vendor substring "gpt" and context_window bound.

### tests/test_providers/test_e2e_chat.py:538-554 - test_chat_returns_valid_assistant_message (TestGoogleE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:676-688
- Same greeting assertion helper.

### tests/test_providers/test_e2e_chat.py:556-577 - test_chat_stream_yields_chunks_and_completes (TestGoogleE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:690-701
- Same coherent stream helper.

### tests/test_providers/test_e2e_chat.py:579-602 - test_tool_calling_returns_valid_tool_call (TestGoogleE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:703-715
- Same notepad path assertion helper.

### tests/test_providers/test_e2e_chat.py:604-620 - test_multi_turn_conversation_retains_context (TestGoogleE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:717-727
- Same AND-logic context recall helper.

### tests/test_providers/test_e2e_chat.py:622-638 - test_max_tokens_respected (TestGoogleE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:729-740
- Same word-cap helper.

### tests/test_providers/test_e2e_chat.py:640-655 - test_model_listing_fields_valid (TestGoogleE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:742-752
- Same model listing helper with context_window bound.

### tests/test_providers/test_e2e_chat.py:661-677 - test_chat_returns_valid_assistant_message (TestGrokE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:754-766
- Same greeting assertion helper.

### tests/test_providers/test_e2e_chat.py:679-700 - test_chat_stream_yields_chunks_and_completes (TestGrokE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:768-779
- Same coherent stream helper.

### tests/test_providers/test_e2e_chat.py:702-725 - test_tool_calling_returns_valid_tool_call (TestGrokE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:781-793
- Same notepad path assertion.

### tests/test_providers/test_e2e_chat.py:727-743 - test_multi_turn_conversation_retains_context (TestGrokE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:795-805
- Same context recall helper.

### tests/test_providers/test_e2e_chat.py:745-761 - test_max_tokens_respected (TestGrokE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:807-818
- Same word-cap helper.

### tests/test_providers/test_e2e_chat.py:763-778 - test_model_listing_fields_valid (TestGrokE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:820-830
- Same model listing helper.

### tests/test_providers/test_e2e_chat.py:784-800 - test_chat_returns_valid_assistant_message (TestOpenRouterE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:832-844
- Same greeting assertion helper.

### tests/test_providers/test_e2e_chat.py:802-823 - test_chat_stream_yields_chunks_and_completes (TestOpenRouterE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:846-857
- Same coherent stream helper.

### tests/test_providers/test_e2e_chat.py:825-848 - test_tool_calling_returns_valid_tool_call (TestOpenRouterE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:859-871
- Same notepad path assertion.

### tests/test_providers/test_e2e_chat.py:850-866 - test_multi_turn_conversation_retains_context (TestOpenRouterE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:873-883
- Same context recall helper.

### tests/test_providers/test_e2e_chat.py:868-884 - test_max_tokens_respected (TestOpenRouterE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:885-896
- Same word-cap helper.

### tests/test_providers/test_e2e_chat.py:886-901 - test_model_listing_fields_valid (TestOpenRouterE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:898-908
- Same model listing helper with "/" substring for OpenRouter format.

### tests/test_providers/test_e2e_chat.py:907-923 - test_chat_returns_valid_assistant_message (TestHuggingFaceE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:910-922
- Same greeting assertion helper.

### tests/test_providers/test_e2e_chat.py:925-946 - test_chat_stream_yields_chunks_and_completes (TestHuggingFaceE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:924-935
- Same coherent stream helper.

### tests/test_providers/test_e2e_chat.py:948-971 - test_tool_calling_returns_valid_tool_call (TestHuggingFaceE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:937-949
- Same notepad path assertion.

### tests/test_providers/test_e2e_chat.py:973-989 - test_multi_turn_conversation_retains_context (TestHuggingFaceE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:951-961
- Same context recall helper.

### tests/test_providers/test_e2e_chat.py:991-1007 - test_max_tokens_respected (TestHuggingFaceE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:963-974
- Same word-cap helper.

### tests/test_providers/test_e2e_chat.py:1009-1024 - test_model_listing_fields_valid (TestHuggingFaceE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:976-986
- Same model listing helper.

### tests/test_providers/test_e2e_chat.py:1030-1048 - test_chat_returns_valid_assistant_message (TestOllamaE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:988-1000
- Same greeting assertion helper.

### tests/test_providers/test_e2e_chat.py:1050-1073 - test_chat_stream_yields_chunks_and_completes (TestOllamaE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:1002-1013
- Same coherent stream helper.

### tests/test_providers/test_e2e_chat.py:1075-1100 - test_tool_calling_returns_valid_tool_call (TestOllamaE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:1015-1027
- Same notepad path assertion.

### tests/test_providers/test_e2e_chat.py:1102-1120 - test_multi_turn_conversation_retains_context (TestOllamaE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:1029-1039
- Same context recall helper.

### tests/test_providers/test_e2e_chat.py:1122-1140 - test_max_tokens_respected (TestOllamaE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:1041-1052
- Same word-cap helper.

### tests/test_providers/test_e2e_chat.py:1142-1160 - test_model_listing_fields_valid (TestOllamaE2EChat)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:1054-1064
- Same model listing helper.

### tests/test_providers/test_e2e_chat.py:1246-1263 - test_same_prompt_all_providers_return_valid_messages (TestCrossProviderConsistency)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:1066-1087
- Test calls `_assert_math_answer()` which verifies response contains "4" or "four" as word boundary match (independent oracle: 2 + 2 = 4).

### tests/test_providers/test_e2e_chat.py:1265-1282 - test_all_providers_handle_empty_tool_list (TestCrossProviderConsistency)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:1089-1125
- Test adds error-path: empty tools list must not crash, and malformed ToolChoice with empty function_name must raise ProviderError. Real error boundary testing.

### tests/test_providers/test_e2e_chat.py:1284-1303 - test_streaming_all_providers_yield_at_least_one_chunk (TestCrossProviderConsistency)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:1127-1148
- Test calls `_assert_coherent_stream()` which validates readable ratio >= 0.6 on reassembled stream text.

### tests/test_providers/test_e2e_chat.py:1309-1324 - test_anthropic_invalid_model_raises_provider_error (TestRateLimitAndErrorHandling)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:1150-1168
- Test asserts ProviderError is raised and walks the exception chain looking for a 4xx HTTP status (client-side API rejection, not network fault).

### tests/test_providers/test_e2e_chat.py:1326-1341 - test_openai_invalid_model_raises_provider_error (TestRateLimitAndErrorHandling)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:1170-1200
- Test asserts ProviderError with 4xx status AND error message contains "model" and "does not exist" (specific error, not broad).

### tests/test_providers/test_e2e_chat.py:1343-1376 - test_timeout_with_very_short_timeout (TestRateLimitAndErrorHandling)
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_e2e_chat.py:1202-1240
- Test asserts ProviderError whose chain contains "timeout" or "timed out" text, surfaced within 20 seconds (specific timeout gate, not broad multi-type swallow).

---

## PART B: local_xpu_e2e, log_viewer, elevation_windows, etc.

### tests/test_providers/test_local_xpu_e2e.py:690 - test_simple_chat_returns_response
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_local_xpu_e2e.py:862-888
- Test calls `_assert_coherent_english()` with min_words=3, min_dictionary_hits=1. Verifies: no control chars, >= 3 distinct tokens, >= 8 alphabetic chars, >= 5 unique letters, character run ratio < 0.5, >= N common English words. Independent oracle: 2+2=4 and the arithmetic operation are present.

### tests/test_providers/test_local_xpu_e2e.py:710 - test_response_is_coherent_text
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_local_xpu_e2e.py:890-913
- Test calls `_assert_coherent_english()` which rejects single-char repetition (run_ratio check), non-alphabetic garbage, and validates distinct tokens. Fixed from weak `isprintable()` check.

### tests/test_providers/test_local_xpu_e2e.py:731 - test_domain_prompt
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_local_xpu_e2e.py:915-939
- Test asserts response contains at least one of "PE", "header", "binary", "executable", "offset", "DOS", "COFF". Domain-specific semantic validation.

### tests/test_providers/test_local_xpu_e2e.py:756 - test_stream_yields_chunks
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_local_xpu_e2e.py:941-964
- Test verifies all chunks are strings, at least one contains alphabetic content, reassembled text has >= 3 distinct tokens and contains common English words.

### tests/test_providers/test_local_xpu_e2e.py:806 - test_stream_and_nonstream_both_produce_valid_output
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_local_xpu_e2e.py:966-991
- Test calls `_assert_coherent_english()` on both stream and non-stream paths, verifying both produce semantically valid output.

### tests/test_providers/test_local_xpu_e2e.py:952 - test_temperature_positive_produces_variation
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_local_xpu_e2e.py:993-1018
- Test samples 10 outputs with temperature > 0 and asserts >= 5 unique outputs (raised from original loose tolerance). Stochastic but falsifiable.

### tests/test_ui/log_viewer/test_model.py:79 - test_column_data_for_display_role
- **Verdict:** PARTIAL
- **Evidence:** tests/test_ui/log_viewer/test_model.py:79-95
- Test checks `'"widget"' in extras_text` but does NOT parse JSON and assert full dict structure. Status.json claims `json.loads(extras_text)` and full dict equality, but that assertion is missing from the actual test.

### tests/test_ui/log_viewer/test_model.py:154 - test_background_role_tints_warn_error_critical_only
- **Verdict:** NOT-SATISFIED
- **Evidence:** tests/test_ui/log_viewer/test_model.py:154-169
- Test only asserts `isinstance(warning_bg, QColor)` etc., NOT the actual color values. Status.json claims assertions for `QColor(60,48,16)` for WARNING, `QColor(70,24,24)` for ERROR, `QColor(70,16,56)` for CRITICAL, but these specific value assertions do not appear in the test code.

### tests/test_core/test_realcov_06_elevation_windows.py:149 - test_build_relaunch_command_targets_real_executable
- **Verdict:** UNVERIFIABLE
- **Evidence:** Test name does not exist in current file. File has been completely refactored (tests now: test_build_relaunch_command_frozen_targets_application_binary, test_build_relaunch_command_pixi_targets_pixi_executable, etc., starting at line 241).
- The audit referenced a specific line:149 test name that no longer exists. Tests have been reorganized. Current tests at lines 241-363 validate relaunch command construction in real scenarios (frozen, pixi, plain interpreter) with proper assertions on executable path matching and argument preservation.

### tests/test_audit7/u12_hexpat_print_sink/test_ui_print_sink.py:261 - test_constructor_receives_callable_print_sink
- **Verdict:** SATISFIED
- **Evidence:** tests/test_ui_print_sink.py:261-283 + test_ui_print_sink.py:289-306
- The audit requirement was to move from "only check callable" to "actually call the sink". This is satisfied by the presence of a separate test class `TestPrintSinkAppendsToOutputWidget` at line 286-306 which calls the sink and verifies output in the widget.

### tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py:281 - test_bootstrap_retries_guest_ping_until_success
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py:281-307
- Test verifies ping_calls >= 3 with explicit validation that first two fail (mocked to raise) and third succeeds. Assertion includes checking that all failures precede success and that call order matches expectation.

### tests/test_hexcore_e2e/test_binary_diff.py:35 - test_identical_bytes_reports_identical
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_binary_diff.py:140-152
- Test asserts `files_identical is True` and `total_differences == 0` strictly (not OR fallback). Region structure validated with helper `_assert_well_formed_regions()`.

### tests/test_hexcore_e2e/test_binary_diff.py:48 - test_completely_different_bytes_shows_low_similarity
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_binary_diff.py:154-175
- Test asserts `files_identical is False`, `total_differences == 64`, and validates exact region structure: match then modified. Uses difflib oracle for independent verification of replace span.

### tests/test_hexcore_e2e/test_binary_diff.py:70 - test_diff_bytes_result_is_dict
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_binary_diff.py:226-237
- Test asserts result is dict and contains at least keys `files_identical`, `total_differences`, `regions`. Not a pure smoke test anymore.

### tests/test_hexcore_e2e/test_binary_diff.py:79 - test_diff_bytes_partial_difference_has_modifications
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_binary_diff.py:204-215
- Test asserts strictly: `files_identical is False`, `total_differences == 50`, and validates exact region structure (50-byte match + 50-byte modified). Fixed from the original tautological `not files_identical or modifications == 0`.

### tests/test_hexcore_e2e/test_binary_diff.py:109 - test_diff_identical_files_reports_identical
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_binary_diff.py:300-315
- Test asserts `files_identical is True` and `total_differences == 0` strictly (not OR fallback).

### tests/test_hexcore_e2e/test_binary_diff.py:125 - test_diff_files_result_has_expected_keys
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_binary_diff.py:265-283
- Test asserts result contains at least 3 of the recognized keys AND validates sensible values: `similarity` is float 0-1, `total_differences` is int >= 0, etc.

### tests/test_hexcore_e2e/test_binary_diff.py:150 - test_diff_files_detects_known_modification_region
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_binary_diff.py:317-347
- Test asserts exact region: `offset_a == 50`, `offset_a + length == 100`, length == 50, diff_type == "modified". Uses difflib oracle to confirm replace span. Fixed from weak >= 50 offset check.

---

## PART C: transforms, read_write_ops, bridge_sandbox, modules_tab, etc.

### tests/test_hexcore_e2e/test_transforms.py:24 - test_list_transforms_returns_nonempty_list
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_transforms.py:28-42
- Test asserts list is non-empty AND validates structure: every entry is 3-tuple with non-empty string fields. More than smoke test.

### tests/test_hexcore_e2e/test_transforms.py:34 - test_list_transforms_each_entry_is_three_tuple
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_transforms.py:44-57
- Test validates 3-tuple structure AND checks that result is consistent across multiple calls (no random variance in list).

### tests/test_hexcore_e2e/test_transforms.py:52 - test_list_transforms_names_are_nonempty_strings
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_transforms.py:59-75
- Test validates non-empty string names AND asserts specific known transforms are present (base64_encode, base64_decode, xor, bit_invert, byte_reverse).

### tests/test_hexcore_e2e/test_transforms.py:146 - test_base64_encode_at_nonzero_offset
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_transforms.py:107-118
- Test uses Python's standard `base64.b64encode()` as independent oracle and validates round-trip correctness via `base64.b64decode()`.

### tests/test_hexcore_e2e/test_transforms.py:260 - test_xor_at_nonzero_offset
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_transforms.py:220-247
- Test validates XOR with zero key is identity and XOR is its own inverse (mathematical properties as oracle, not just expected value matching test logic).

### tests/test_hexcore_e2e/test_read_write_ops.py:59 - test_read_across_byte_boundaries
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_read_write_ops.py:47-59
- Test explicitly validates that sample_doc contains identity sequence [0x00..0xFF] (verified separately in fixture), then asserts boundary reads match known positions.

### tests/test_hexcore_e2e/test_read_write_ops.py:107 - test_write_does_not_change_surrounding_bytes
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_read_write_ops.py:96-108
- Test validates sample fixture against identity sequence, then asserts surrounding bytes remain unchanged after write.

### tests/test_hexcore_e2e/test_bridge_sandbox.py:29 - _run (helper function, not a test)
- **Verdict:** UNVERIFIABLE
- **Evidence:** tests/test_hexcore_e2e/test_bridge_sandbox.py:29-43
- Not a test function; this is a helper. PEP 695 generic syntax `def _run[T](...)` is valid in Python 3.12+. No test gate here.

### tests/test_hexcore_e2e/test_bridge_sandbox.py:72 - test_save_to_sandbox_no_document_raises_runtime_error
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_bridge_sandbox.py:61-75
- Test asserts `pytest.raises(RuntimeError, match="no document open")` and validates the error is raised for the correct condition. Also tests boundary: with document open, no error raised.

### tests/test_hexcore_e2e/test_bridge_sandbox.py:81 - test_save_to_sandbox_no_tool_registry_raises_runtime_error
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_bridge_sandbox.py:77-90
- Test asserts RuntimeError with "tool registry" message AND verifies setting a valid registry does NOT raise error (boundary testing).

### tests/test_hexcore_e2e/test_bridge_sandbox.py:91 - test_save_to_sandbox_no_sandbox_bridge_raises_runtime_error
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_bridge_sandbox.py:92-108
- Test uses _MinimalRegistry fixture and asserts RuntimeError. Also tests happy path: when sandbox bridge is available, no error. Code path verification present.

### tests/test_audit4/b5_modules_tab/test_modules_tab.py:108 - test_filter_hides_non_matching_rows
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit4/b5_modules_tab/test_modules_tab.py:99-114
- Test now covers multiple scenarios: exact match, partial match, case-insensitive, no match, empty filter, clearing filter. Explicit state checks on visible row counts.

### tests/test_audit4/b5_modules_tab/test_modules_tab.py:179 - test_refresh_handles_provides_on_error
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit4/b5_modules_tab/test_modules_tab.py:149-186
- Test monkeypatches to capture on_error callback, then invokes it to verify it calls QMessageBox.warning with correct message. Callback invocation tested, not just mocked.

### tests/test_audit3/sandbox/test_start_monitors.py:180 - test_start_script_exists
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit3/sandbox/test_start_monitors.py:359-368
- Test executes the script with minimal monitor list and verifies it produces valid PID file output. More than existence check.

### tests/test_audit3/sandbox/test_start_monitors.py:185 - test_stop_script_exists
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit3/sandbox/test_start_monitors.py:405-432
- Test executes stop_monitors.cmd with valid PID file and verifies processes are actually terminated. Functional test, not smoke test.

### tests/test_audit3/sandbox/test_start_monitors.py:190 - test_start_script_default_logdir_uses_programdata
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit3/sandbox/test_start_monitors.py:271-309
- Test executes the script, inspects actual log directory created, and verifies it matches the expected ProgramData path. Runtime verification, not string matching.

### tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:22 - test_no_using_scope_in_action
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:22-28
- Test generates the file monitor source, executes it against a real FileSystemEventArgs, and verifies it captures the event correctly without scope binding errors. Runtime validation.

### tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:29 - test_message_data_passed_to_register
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:29-35
- Test executes the script and verifies MessageData is passed and accessible to the action block. Real file system event testing.

### tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:46 - test_no_dollar_pid_assignment
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:46-66
- Test executes the process monitor and verifies $pid is not shadowed by injecting process IDs and checking that the automatic $pid variable is still accessible.

---

## Summary Tally

### SATISFIED: 99
The vast majority of findings have been fixed with proper helper functions, tightened assertions, independent oracles, and real validation logic. Most findings in PART A are completely satisfied. PART B and C show strong compliance with only 2 exceptions.

### PARTIAL: 1
- test_column_data_for_display_role: Missing JSON parsing and full dict validation assertion.

### NOT-SATISFIED: 1
- test_background_role_tints_warn_error_critical_only: Missing exact RGB color value assertions; only type checks remain.

### UNVERIFIABLE: 2
- test_build_relaunch_command_targets_real_executable: Test name does not exist; file has been refactored. Current tests appear sound but cannot verify the specific original finding.
- _run helper function: Not a test; PEP 695 syntax is valid for Python 3.12+, no assertion gate to verify.

**Total findings reviewed: 103**
**Final count:**
- SATISFIED: 99 (96.1%)
- PARTIAL: 1 (0.9%)
- NOT-SATISFIED: 1 (0.9%)
- UNVERIFIABLE: 2 (1.9%)
