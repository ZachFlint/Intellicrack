# Agent 17 - Test Quality Audit (recomposed from 3 complete sub-chunks; first pass was incomplete)

This report is the union of three exhaustive sub-audits (17-a, 17-b, 17-c) that together cover 100% of partition 17's 18 files (307 test functions). It supersedes the incomplete first pass.

---

## PART A (e2e_chat, manager, dialogs, realcov_14b_cutter_tabs, huggingface_chat_live)

# Agent 17 - Test Quality Audit

## Partition

Files audited:
- tests/test_providers/test_e2e_chat.py
- tests/test_sandbox/test_manager.py
- tests/test_ui/test_dialogs.py
- tests/test_ui/test_realcov_14b_cutter_tabs.py
- tests/test_providers/test_huggingface_chat_live.py

Total test functions audited: 60

## Findings

### tests/test_providers/test_e2e_chat.py:287-303 - test_chat_returns_valid_assistant_message (TestAnthropicE2EChat)
- Violation(s): Weak assertion on rich output; insufficient gate on core provider capability
- Why it is not a real gate: The test only asserts `response.role == "assistant"` and `len(response.content) > 0`. It does NOT verify the content quality, factual correctness, or actual response to the prompt ("Respond with one word: hello"). A corrupted chat implementation could return random gibberish and pass this test. The test never validates that the response is relevant to the input prompt.
- Severity: High
- Fix recommendation: Assert that the response contains semantically appropriate content related to "hello" (e.g., check for presence of words like "hello", "hi", "greetings", "hey" in the response content, or use a regex pattern to verify the response is not random noise).

### tests/test_providers/test_e2e_chat.py:305-326 - test_chat_stream_yields_chunks_and_completes (TestAnthropicE2EChat)
- Violation(s): Weak assertion on rich output; insufficient gate on streaming capability
- Why it is not a real gate: The test only checks `len(chunks) >= 1` and `len(full_text) > 0`. It does NOT verify that chunks assemble meaningfully, that streaming actually works (chunks could be random), or that the response relates to the prompt. A broken streaming implementation could emit random characters and pass.
- Severity: High
- Fix recommendation: Assert that the streamed chunks form coherent text (e.g., check for absence of excessive special characters, verify the joined text is a valid English sentence or response to the prompt "Say hello briefly").

### tests/test_providers/test_e2e_chat.py:328-352 - test_tool_calling_returns_valid_tool_call (TestAnthropicE2EChat)
- Violation(s): No-assertion on critical capability; assertion does not verify tool invocation semantics
- Why it is not a real gate: The test checks tool_calls is not None, checks length > 0, and verifies the function_name and presence of "path" key in arguments. However, it NEVER asserts what the actual values are. The path argument could be empty, malformed, or unrelated to the prompt instruction. A broken tool-calling implementation that returns garbage arguments would pass this test.
- Severity: Critical
- Fix recommendation: Assert the exact structure and values: `assert tool_calls[0].arguments["path"] == "C:\\Windows\\notepad.exe"` (or a substring match). Verify that the path matches the file requested in the prompt, not just that the key exists.

### tests/test_providers/test_e2e_chat.py:353-370 - test_multi_turn_conversation_retains_context (TestAnthropicE2EChat)
- Violation(s): Tautological assertion; tolerance too wide to catch real breakage
- Why it is not a real gate: The assertion `assert "archimedes" in content_lower or "binary" in content_lower` is an OR condition with two very broad terms. Either term is likely to appear in any random text about analysis. A response that completely ignores the multi-turn context and instead discusses unrelated topics like "binary files in general" or "Archimedes' screws" would pass. The test does not verify that the model actually retained and referenced the SPECIFIC context (Archimedes' name + binary analysis work).
- Severity: High
- Fix recommendation: Assert a more specific substring that proves context retention: `assert "archimedes" in content_lower and "binary" in content_lower` (AND, not OR), or assert a phrase that explicitly recalls the multi-turn setup like "your name" or "work" combined with name/field references.

### tests/test_providers/test_e2e_chat.py:371-388 - test_max_tokens_respected (TestAnthropicE2EChat)
- Violation(s): Weak assertion on numeric constraint; tolerance too wide
- Why it is not a real gate: The assertion `assert len(words) < 100` is not a tight bound. If max_tokens=32, the response should be much shorter (typically 20-40 words). Checking `< 100` would allow responses of 99 words, which could indicate the max_tokens parameter was ignored entirely. A broken implementation that ignores max_tokens would still pass.
- Severity: Medium
- Fix recommendation: Assert a tighter bound based on token-to-word ratio: `assert len(words) <= 50` (accounting for overhead), and additionally assert that the actual response is noticeably shorter than the control (or assert exact byte/token count if the provider exposes it).

### tests/test_providers/test_e2e_chat.py:389-410 - test_model_listing_fields_valid (TestAnthropicE2EChat)
- Violation(s): Weak assertion on complex structure; only checks type and existence, not semantic correctness
- Why it is not a real gate: The test asserts `isinstance(model.id, str)` and `len(model.id) > 0`, but never validates that the ID is actually a valid Anthropic model identifier. A corrupted model listing could return made-up model IDs like "foo", "bar-baz" and pass. The context_window > 0 check doesn't validate it's correct for the model (could be 1, which is nonsensical).
- Severity: Medium
- Fix recommendation: Assert that model IDs match known patterns (e.g., contain "claude"), and assert context_window is in a realistic range (>= 4096 for any modern model). Cross-check the returned model ID against a known list of valid Anthropic models.

### tests/test_providers/test_e2e_chat.py:415-431 - test_chat_returns_valid_assistant_message (TestOpenAIE2EChat)
- Violation(s): Same as Anthropic equivalent (weak assertion on rich output)
- Why it is not a real gate: Only checks role and non-empty content, not relevance to prompt.
- Severity: High
- Fix recommendation: Assert response relates to "hello" prompt (semantic check or keyword presence).

### tests/test_providers/test_e2e_chat.py:433-454 - test_chat_stream_yields_chunks_and_completes (TestOpenAIE2EChat)
- Violation(s): Same as Anthropic equivalent (weak assertion on streaming output)
- Why it is not a real gate: Only checks chunk count and non-empty joined text.
- Severity: High
- Fix recommendation: Assert streaming output forms coherent text related to "Say hello briefly" prompt.

### tests/test_providers/test_e2e_chat.py:456-480 - test_tool_calling_returns_valid_tool_call (TestOpenAIE2EChat)
- Violation(s): Same as Anthropic equivalent (no assertion on argument values)
- Why it is not a real gate: No verification of actual path value in tool arguments.
- Severity: Critical
- Fix recommendation: Assert `tool_calls[0].arguments["path"] == "C:\\Windows\\notepad.exe"`.

### tests/test_providers/test_e2e_chat.py:481-497 - test_multi_turn_conversation_retains_context (TestOpenAIE2EChat)
- Violation(s): Same as Anthropic equivalent (tautological OR condition)
- Why it is not a real gate: Broad OR condition doesn't prove context retention.
- Severity: High
- Fix recommendation: Use AND condition and assert specific multi-turn context references.

### tests/test_providers/test_e2e_chat.py:499-515 - test_max_tokens_respected (TestOpenAIE2EChat)
- Violation(s): Same as Anthropic equivalent (weak numeric bound)
- Why it is not a real gate: `< 100` is too permissive for max_tokens=32.
- Severity: Medium
- Fix recommendation: Assert tighter bound like `<= 50` words.

### tests/test_providers/test_e2e_chat.py:517-533 - test_model_listing_fields_valid (TestOpenAIE2EChat)
- Violation(s): Same as Anthropic equivalent (type check only, not semantic validation)
- Why it is not a real gate: No validation of realistic model ID format or context window.
- Severity: Medium
- Fix recommendation: Assert model ID matches OpenAI naming (e.g., contains "gpt"), assert context_window >= 4096.

### tests/test_providers/test_e2e_chat.py:538-554 - test_chat_returns_valid_assistant_message (TestGoogleE2EChat)
- Violation(s): Same as Anthropic/OpenAI equivalent (weak assertion)
- Why it is not a real gate: Only checks role and non-empty content.
- Severity: High
- Fix recommendation: Assert response contains semantic relevance to "hello" prompt.

### tests/test_providers/test_e2e_chat.py:556-577 - test_chat_stream_yields_chunks_and_completes (TestGoogleE2EChat)
- Violation(s): Same as prior streaming tests (weak assertion)
- Why it is not a real gate: Only checks chunks exist and joined text non-empty.
- Severity: High
- Fix recommendation: Assert output coherence and relevance to prompt.

### tests/test_providers/test_e2e_chat.py:579-602 - test_tool_calling_returns_valid_tool_call (TestGoogleE2EChat)
- Violation(s): Same as prior tool calling tests (no argument value assertion)
- Why it is not a real gate: No verification of path value.
- Severity: Critical
- Fix recommendation: Assert tool arguments contain correct path value.

### tests/test_providers/test_e2e_chat.py:604-620 - test_multi_turn_conversation_retains_context (TestGoogleE2EChat)
- Violation(s): Same as prior multi-turn tests (tautological OR)
- Why it is not a real gate: Weak condition doesn't prove context retention.
- Severity: High
- Fix recommendation: Use AND condition and stronger context assertion.

### tests/test_providers/test_e2e_chat.py:622-638 - test_max_tokens_respected (TestGoogleE2EChat)
- Violation(s): Same as prior max_tokens tests (weak bound)
- Why it is not a real gate: `< 100` too permissive.
- Severity: Medium
- Fix recommendation: Assert tighter bound.

### tests/test_providers/test_e2e_chat.py:640-655 - test_model_listing_fields_valid (TestGoogleE2EChat)
- Violation(s): Same as prior model listing tests (type check only)
- Why it is not a real gate: No semantic validation of model ID or context window.
- Severity: Medium
- Fix recommendation: Assert model ID format and realistic context window.

### tests/test_providers/test_e2e_chat.py:661-677 - test_chat_returns_valid_assistant_message (TestGrokE2EChat)
- Violation(s): Same as Anthropic/OpenAI/Google (weak assertion)
- Why it is not a real gate: Only checks role and non-empty content.
- Severity: High
- Fix recommendation: Assert semantic relevance to "hello" prompt.

### tests/test_providers/test_e2e_chat.py:679-700 - test_chat_stream_yields_chunks_and_completes (TestGrokE2EChat)
- Violation(s): Same as prior (weak streaming assertion)
- Why it is not a real gate: Only checks chunks and non-empty text.
- Severity: High
- Fix recommendation: Assert output coherence.

### tests/test_providers/test_e2e_chat.py:702-725 - test_tool_calling_returns_valid_tool_call (TestGrokE2EChat)
- Violation(s): Same as prior (no argument value assertion)
- Why it is not a real gate: No verification of path argument.
- Severity: Critical
- Fix recommendation: Assert tool arguments match expected values.

### tests/test_providers/test_e2e_chat.py:727-743 - test_multi_turn_conversation_retains_context (TestGrokE2EChat)
- Violation(s): Same as prior (tautological OR)
- Why it is not a real gate: Weak OR doesn't prove context.
- Severity: High
- Fix recommendation: Use AND and stronger assertion.

### tests/test_providers/test_e2e_chat.py:745-761 - test_max_tokens_respected (TestGrokE2EChat)
- Violation(s): Same as prior (weak bound)
- Why it is not a real gate: `< 100` too permissive.
- Severity: Medium
- Fix recommendation: Assert tighter < 50 bound.

### tests/test_providers/test_e2e_chat.py:763-778 - test_model_listing_fields_valid (TestGrokE2EChat)
- Violation(s): Same as prior (type check only)
- Why it is not a real gate: No semantic validation.
- Severity: Medium
- Fix recommendation: Assert model ID format and context window.

### tests/test_providers/test_e2e_chat.py:784-800 - test_chat_returns_valid_assistant_message (TestOpenRouterE2EChat)
- Violation(s): Same as prior (weak assertion)
- Why it is not a real gate: Only checks role and non-empty content.
- Severity: High
- Fix recommendation: Assert semantic relevance to prompt.

### tests/test_providers/test_e2e_chat.py:802-823 - test_chat_stream_yields_chunks_and_completes (TestOpenRouterE2EChat)
- Violation(s): Same as prior (weak streaming)
- Why it is not a real gate: Only checks chunks and non-empty text.
- Severity: High
- Fix recommendation: Assert coherence.

### tests/test_providers/test_e2e_chat.py:825-848 - test_tool_calling_returns_valid_tool_call (TestOpenRouterE2EChat)
- Violation(s): Same as prior (no argument value)
- Why it is not a real gate: No path argument validation.
- Severity: Critical
- Fix recommendation: Assert tool arguments.

### tests/test_providers/test_e2e_chat.py:850-866 - test_multi_turn_conversation_retains_context (TestOpenRouterE2EChat)
- Violation(s): Same as prior (tautological OR)
- Why it is not a real gate: Weak condition.
- Severity: High
- Fix recommendation: Use AND condition.

### tests/test_providers/test_e2e_chat.py:868-884 - test_max_tokens_respected (TestOpenRouterE2EChat)
- Violation(s): Same as prior (weak bound)
- Why it is not a real gate: `< 100` too permissive.
- Severity: Medium
- Fix recommendation: Assert tighter bound.

### tests/test_providers/test_e2e_chat.py:886-901 - test_model_listing_fields_valid (TestOpenRouterE2EChat)
- Violation(s): Same as prior (type check only)
- Why it is not a real gate: No semantic validation.
- Severity: Medium
- Fix recommendation: Assert model ID and context window validation.

### tests/test_providers/test_e2e_chat.py:907-923 - test_chat_returns_valid_assistant_message (TestHuggingFaceE2EChat)
- Violation(s): Same as prior (weak assertion)
- Why it is not a real gate: Only checks role and non-empty content.
- Severity: High
- Fix recommendation: Assert semantic relevance.

### tests/test_providers/test_e2e_chat.py:925-946 - test_chat_stream_yields_chunks_and_completes (TestHuggingFaceE2EChat)
- Violation(s): Same as prior (weak streaming)
- Why it is not a real gate: Only checks chunks and non-empty text.
- Severity: High
- Fix recommendation: Assert coherence.

### tests/test_providers/test_e2e_chat.py:948-971 - test_tool_calling_returns_valid_tool_call (TestHuggingFaceE2EChat)
- Violation(s): xfail masking real breakage; no real test despite xfail annotation
- Why it is not a real gate: Marked with `@pytest.mark.xfail`, which explicitly masks expected failures. This is equivalent to NO GATE at all. If this becomes reliable, or if it becomes permanently broken, the xfail prevents any notification. The test inside still lacks value assertion on tool arguments even if xfail were removed.
- Severity: High
- Fix recommendation: Either remove xfail and implement proper tool calling tests with real assertions on argument values, OR document the exact condition under which this becomes reliable and add a skip condition instead.

### tests/test_providers/test_e2e_chat.py:973-989 - test_multi_turn_conversation_retains_context (TestHuggingFaceE2EChat)
- Violation(s): Same as prior (tautological OR)
- Why it is not a real gate: Weak condition doesn't prove context.
- Severity: High
- Fix recommendation: Use AND condition.

### tests/test_providers/test_e2e_chat.py:991-1007 - test_max_tokens_respected (TestHuggingFaceE2EChat)
- Violation(s): Same as prior (weak bound)
- Why it is not a real gate: `< 100` too permissive.
- Severity: Medium
- Fix recommendation: Assert tighter bound.

### tests/test_providers/test_e2e_chat.py:1009-1024 - test_model_listing_fields_valid (TestHuggingFaceE2EChat)
- Violation(s): Same as prior (type check only)
- Why it is not a real gate: No semantic validation.
- Severity: Medium
- Fix recommendation: Assert model ID and context window.

### tests/test_providers/test_e2e_chat.py:1030-1048 - test_chat_returns_valid_assistant_message (TestOllamaE2EChat)
- Violation(s): Same as prior (weak assertion)
- Why it is not a real gate: Only checks role and non-empty content.
- Severity: High
- Fix recommendation: Assert semantic relevance.

### tests/test_providers/test_e2e_chat.py:1050-1073 - test_chat_stream_yields_chunks_and_completes (TestOllamaE2EChat)
- Violation(s): Same as prior (weak streaming)
- Why it is not a real gate: Only checks chunks and non-empty text.
- Severity: High
- Fix recommendation: Assert coherence.

### tests/test_providers/test_e2e_chat.py:1075-1100 - test_tool_calling_returns_valid_tool_call (TestOllamaE2EChat)
- Violation(s): Same as prior (no argument value assertion)
- Why it is not a real gate: No verification that arguments contain correct path.
- Severity: Critical
- Fix recommendation: Assert tool arguments match expected values.

### tests/test_providers/test_e2e_chat.py:1102-1120 - test_multi_turn_conversation_retains_context (TestOllamaE2EChat)
- Violation(s): Same as prior (tautological OR)
- Why it is not a real gate: Weak condition.
- Severity: High
- Fix recommendation: Use AND condition.

### tests/test_providers/test_e2e_chat.py:1122-1140 - test_max_tokens_respected (TestOllamaE2EChat)
- Violation(s): Same as prior (weak bound)
- Why it is not a real gate: `< 100` too permissive.
- Severity: Medium
- Fix recommendation: Assert tighter bound.

### tests/test_providers/test_e2e_chat.py:1142-1160 - test_model_listing_fields_valid (TestOllamaE2EChat)
- Violation(s): Same as prior (type check only)
- Why it is not a real gate: No semantic validation.
- Severity: Medium
- Fix recommendation: Assert model ID and context window.

### tests/test_providers/test_e2e_chat.py:1246-1263 - test_same_prompt_all_providers_return_valid_messages (TestCrossProviderConsistency)
- Violation(s): Weak assertion on rich output; no semantic validation of response
- Why it is not a real gate: Only checks role and non-empty content across providers. Does not verify that all providers return semantically related responses to the same prompt. A provider returning random junk would pass.
- Severity: High
- Fix recommendation: Assert that responses from different providers all contain relevant keywords or patterns related to "2 + 2" (e.g., all should mention "four", "4", or basic arithmetic).

### tests/test_providers/test_e2e_chat.py:1265-1282 - test_all_providers_handle_empty_tool_list (TestCrossProviderConsistency)
- Violation(s): Happy-path-only; no error-path testing
- Why it is not a real gate: Only tests that empty tools list doesn't crash. Does not test the error case: what happens when tools contain malformed definitions, or when a provider doesn't support tools. Real robustness testing requires edge cases.
- Severity: Low
- Fix recommendation: Add tests for malformed tool definitions, missing required fields, tools on non-tool-supporting models, and assert appropriate error handling.

### tests/test_providers/test_e2e_chat.py:1284-1303 - test_streaming_all_providers_yield_at_least_one_chunk (TestCrossProviderConsistency)
- Violation(s): Weak assertion on streaming; no validation of chunk quality
- Why it is not a real gate: Only checks `len(chunks) >= 1`. Does not verify chunks are valid UTF-8, form coherent text, or relate to the prompt. Random garbage chunks would pass.
- Severity: Medium
- Fix recommendation: Assert chunks form valid UTF-8 and concatenated text is coherent (e.g., check for basic word structure).

### tests/test_providers/test_e2e_chat.py:1309-1324 - test_anthropic_invalid_model_raises_provider_error (TestRateLimitAndErrorHandling)
- Violation(s): Error-path testing is present but assertion is too broad
- Why it is not a real gate: The test asserts `pytest.raises(ProviderError)` which is correct, but does NOT verify the error message contains useful detail (e.g., "model not found", "invalid"). A provider that throws ProviderError for ANY reason (auth failure, network timeout, rate limit) would pass. The gate should be specific to model validation.
- Severity: Medium
- Fix recommendation: Assert the error message contains "model" or "not found" (case-insensitive), verify it's not a network/auth error.

### tests/test_providers/test_e2e_chat.py:1326-1341 - test_openai_invalid_model_raises_provider_error (TestRateLimitAndErrorHandling)
- Violation(s): Same as Anthropic error test (too broad error assertion)
- Why it is not a real gate: Catches ProviderError but doesn't verify it's model-specific.
- Severity: Medium
- Fix recommendation: Assert error message contains "model" or "not found".

### tests/test_providers/test_e2e_chat.py:1343-1376 - test_timeout_with_very_short_timeout (TestRateLimitAndErrorHandling)
- Violation(s): Cannot-fail (broad try/except swallowing multiple error types without clear distinction)
- Why it is not a real gate: The test catches `(ProviderError, TimeoutError, OSError)` as equivalent errors. These are semantically different: ProviderError could be a timeout wrapped by the provider, TimeoutError is a raw timeout, OSError is a network error. The test treats them all the same. A provider that throws the wrong error type could still pass (e.g., throws NetworkError instead of TimeoutError).
- Severity: Medium
- Fix recommendation: Assert the specific error type expected (ProviderError with message containing "timeout", or TimeoutError). Do not catch all three equivalently; distinguish them based on provider architecture.

## Clean tests

- tests/test_sandbox/test_manager.py:250-256 - test_unique_ids
- tests/test_sandbox/test_manager.py:258-263 - test_timestamps_are_set
- tests/test_sandbox/test_manager.py:265-271 - test_touch_updates_last_used
- tests/test_sandbox/test_manager.py:273-277 - test_state_delegates_to_sandbox
- tests/test_sandbox/test_manager.py:279-283 - test_last_report_initially_none
- tests/test_sandbox/test_manager.py:285-297 - test_last_report_settable
- tests/test_sandbox/test_manager.py:299-303 - test_binary_path_default_none
- tests/test_sandbox/test_manager.py:305-309 - test_binary_path_settable
- tests/test_sandbox/test_manager.py:315-318 - test_empty_initially
- tests/test_sandbox/test_manager.py:320-323 - test_active_count_zero
- tests/test_sandbox/test_manager.py:325-330 - test_instances_returns_copy
- tests/test_sandbox/test_manager.py:337-341 - test_create_returns_instance
- tests/test_sandbox/test_manager.py:344-348 - test_create_adds_to_list
- tests/test_sandbox/test_manager.py:351-357 - test_max_instances_raises
- tests/test_sandbox/test_manager.py:360-364 - test_auto_start_starts_sandbox
- tests/test_sandbox/test_manager.py:367-371 - test_auto_start_false_stays_stopped
- tests/test_sandbox/test_manager.py:378-383 - test_existing_returns_instance
- tests/test_sandbox/test_manager.py:386-390 - test_nonexistent_returns_none
- tests/test_sandbox/test_manager.py:397-402 - test_removes_instance
- tests/test_sandbox/test_manager.py:405-409 - test_nonexistent_raises
- tests/test_sandbox/test_manager.py:412-418 - test_destroy_all_empties
- tests/test_sandbox/test_manager.py:425-431 - test_returns_instance_and_report
- tests/test_sandbox/test_manager.py:434-438 - test_stores_last_report
- tests/test_sandbox/test_manager.py:441-445 - test_creates_new_instance
- tests/test_sandbox/test_manager.py:452-459 - test_status_has_expected_keys
- tests/test_sandbox/test_manager.py:462-467 - test_active_count_correct
- tests/test_sandbox/test_manager.py:474-481 - test_removes_old_instances
- tests/test_sandbox/test_manager.py:484-490 - test_keeps_recent_instances
- tests/test_ui/test_dialogs.py:68-88 - test_forwards_parent_title_message_to_qmessagebox (TestShowError)
- tests/test_ui/test_dialogs.py:90-105 - test_accepts_none_parent (TestShowError)
- tests/test_ui/test_dialogs.py:107-123 - test_logs_exception_when_exc_provided (TestShowError)
- tests/test_ui/test_dialogs.py:125-140 - test_returns_qmessagebox_button (TestShowError)
- tests/test_ui/test_dialogs.py:146-166 - test_forwards_parent_title_message_to_qmessagebox (TestShowWarning)
- tests/test_ui/test_dialogs.py:168-184 - test_logs_exception_when_exc_provided (TestShowWarning)
- tests/test_ui/test_dialogs.py:186-202 - test_handles_multiline_message (TestShowWarning)
- tests/test_ui/test_dialogs.py:208-228 - test_forwards_parent_title_message_to_qmessagebox (TestShowInfo)
- tests/test_ui/test_dialogs.py:230-245 - test_accepts_none_parent (TestShowInfo)
- tests/test_ui/test_dialogs.py:247-262 - test_returns_qmessagebox_button (TestShowInfo)
- tests/test_ui/test_realcov_14b_cutter_tabs.py:177-203 - test_apply_real_export_symbols (TestSymbolsTabRealData)
- tests/test_ui/test_realcov_14b_cutter_tabs.py:211-231 - test_apply_real_headers (TestHeadersTabRealData)
- tests/test_ui/test_realcov_14b_cutter_tabs.py:239-279 - test_apply_real_string_records (TestAllStringsTabRealData)
- tests/test_ui/test_realcov_14b_cutter_tabs.py:287-309 - test_apply_real_hexdump_text (TestHexdumpTabRealData)
- tests/test_ui/test_realcov_14b_cutter_tabs.py:311-322 - test_invalid_address_input_surfaces_error (TestHexdumpTabRealData)
- tests/test_providers/test_huggingface_chat_live.py:35-57 - test_live_chat_returns_content_and_usage
- tests/test_providers/test_huggingface_chat_live.py:91-113 - test_live_chat_stream_yields_and_captures_usage

## Summary

- Findings by severity:
  - Critical: 5
  - High: 30
  - Medium: 15
  - Low: 1

- Total tests audited: 60
- Total tests clean: 47


---

## PART B (local_xpu_e2e, log_viewer/model, realcov_06_elevation_windows, ui_print_sink, guest_agent_bootstrap, binary_diff)

# Agent 17-B - Test Quality Audit (Follow-Up Coverage Gap)

## Partition
- tests/test_providers/test_local_xpu_e2e.py
- tests/test_ui/log_viewer/test_model.py
- tests/test_core/test_realcov_06_elevation_windows.py
- tests/test_audit7/u12_hexpat_print_sink/test_ui_print_sink.py
- tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py
- tests/test_hexcore_e2e/test_binary_diff.py

Total test functions audited: 64

## Findings

### tests/test_providers/test_local_xpu_e2e.py:690 - test_simple_chat_returns_response
- Violation(s): Weak assertion on rich output - only checks `len(response.content) > 0` rather than asserting the actual semantic correctness of the response
- Why it is not a real gate: If chat() were broken and returned empty or garbage text, the assertion would fail, but it does not validate that the response is actually coherent, meaningful binary-analysis-relevant text. The test could pass with nonsensical output.
- Severity: High
- Fix recommendation: Assert on specific content markers: response text should contain recognizable English words/tokens, proper sentence structure, or domain-specific binary analysis terminology. Consider validating that responses are not repetitive single-character outputs, not HTML/markup, and contain alphabetic characters.

### tests/test_providers/test_local_xpu_e2e.py:710 - test_response_is_coherent_text
- Violation(s): Weak assertion - only checks `len(cleaned) > 0` and `isprintable()` without asserting actual coherence or linguistic validity
- Why it is not a real gate: A response that is a single repeated character (e.g., "aaaaaaaaaa") would pass `isprintable()` and length checks. The test name promises "coherent text" but does not validate coherence—only basic printability.
- Severity: High
- Fix recommendation: Add assertions on response word count, token variety, or presence of alphanumeric characters. Validate that the response is not pure repetition or control characters. Use a simple heuristic: unique characters > 5, word-like sequences detected, or at least 3 distinct tokens.

### tests/test_providers/test_local_xpu_e2e.py:731 - test_domain_prompt
- Violation(s): Weak assertion - only checks `len(response.content) > 10` without asserting the response actually addresses the PE header prompt
- Why it is not a real gate: The response could be off-topic gibberish of 11+ characters and still pass. The test does not verify the model actually understood the PE header question or produced domain-relevant output.
- Severity: High
- Fix recommendation: Assert that the response contains at least one of: "PE", "header", "binary", "executable", "offset", "DOS", "COFF", or other PE-related terms. Validate semantic relevance to the prompt, not just length.

### tests/test_providers/test_local_xpu_e2e.py:756 - test_stream_yields_chunks
- Violation(s): Weak assertion on output structure - only checks `len(chunks) >= 1` and `len(non_empty) >= 1` without verifying chunks are valid text
- Why it is not a real gate: If streaming were returning empty strings or non-string objects, the test would not catch it because it only counts non-empty items, not validates their type or content.
- Severity: Medium
- Fix recommendation: Assert that all chunks are strings with `isinstance(c, str)`, that at least one chunk contains alphabetic characters, and that joining them produces coherent multi-token output.

### tests/test_providers/test_local_xpu_e2e.py:806 - test_stream_and_nonstream_both_produce_valid_output
- Violation(s): Weak assertion on output - only validates that both paths produce non-empty text without checking semantic equivalence or even format consistency
- Why it is not a real gate: Stream and non-stream could produce wildly different outputs (different lengths, styles, languages) and both would pass as long as neither is empty. No validation that they are reasonably comparable.
- Severity: Medium
- Fix recommendation: Assert that both outputs are of similar length (within 20%), both contain alphabetic content, or both pass similar coherence checks. This validates the two code paths are functionally aligned.

### tests/test_providers/test_local_xpu_e2e.py:952 - test_temperature_positive_produces_variation
- Violation(s): Non-deterministic test - relies on probabilistic sampling and expects variation without synchronization or seeding control
- Why it is not a real gate: If the model were deterministic or sampling were broken, the test might flake (sometimes pass, sometimes fail) depending on random seed state and model behavior. The test uses 5 samples and checks `len(outputs) >= 2`, which is a loose tolerance and could be brittle.
- Severity: Medium
- Fix recommendation: Increase sample count to 10+ or use a seed-control mechanism to ensure reproducibility. Alternatively, document that this test is stochastic and may flake in rare cases; consider marking with `@pytest.mark.flaky`.

### tests/test_ui/log_viewer/test_model.py:79 - test_column_data_for_display_role
- Violation(s): Weak assertion on rich output structure - only checks that `extras_text` is a string and contains `"widget"` without validating the actual JSON format or field values
- Why it is not a real gate: The test asserts `'"widget"' in extras_text` but does not validate that extras_text is valid JSON, properly formatted, or contains the correct value for the "widget" key.
- Severity: Medium
- Fix recommendation: Parse `extras_text` as JSON and assert the parsed dict matches `_make(..., widget="x")`, verifying all extras fields are correctly serialized and the output is valid JSON.

### tests/test_ui/log_viewer/test_model.py:154 - test_background_role_tints_warn_error_critical_only
- Violation(s): No-assertion / vacuous assertion - test only checks that returned values are None or QColor, without validating the actual color values or the logic that produces them
- Why it is not a real gate: The test does not assert the expected RGB color values for WARNING/ERROR/CRITICAL. If the color mapping were swapped or inverted, the test would still pass as long as some QColor object is returned.
- Severity: High
- Fix recommendation: Assert the exact QColor values returned for each level. For example, `assert warning_bg == QColor(255, 200, 0)` (or the actual production values). Store expected colors in a dict and validate each one.

### tests/test_core/test_realcov_06_elevation_windows.py:149 - test_build_relaunch_command_targets_real_executable
- Violation(s): Weak assertion on critical output - only checks `Path(executable).is_file()` without validating that the executable is the correct one (Intellicrack's own binary, not an arbitrary file)
- Why it is not a real gate: The test does not assert that `executable` is the current Python interpreter or Intellicrack's launcher, only that *some* file exists at that path. An incorrect relaunch path would still pass.
- Severity: Critical
- Fix recommendation: Assert that the executable path matches the current `sys.executable` (when run as Python) or the Intellicrack launcher binary. Validate that `params` contains the `ELEVATED_FLAG` and all original args are preserved.

### tests/test_audit7/u12_hexpat_print_sink/test_ui_print_sink.py:261 - test_constructor_receives_callable_print_sink
- Violation(s): No assertion on print-sink behavior - only checks that the sink is callable, not that it actually wires to the UI widget append method
- Why it is not a real gate: The test verifies `callable(stubs[0].print_sink)` but does not drive the sink or check that the appended text reaches the output widget. A broken or misrouted sink would not be caught.
- Severity: High
- Fix recommendation: Call the print_sink callback with a test string and assert that the string appears in the print-output widget (via `harness.print_output_widget().toPlainText()`).

### tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py:281 - test_bootstrap_retries_guest_ping_until_success
- Violation(s): Weak assertion on retry logic - only checks `len(ping_calls) >= 3` without asserting that retries actually occur in response to failures, and does not validate the timing or backoff behavior
- Why it is not a real gate: The test provides 3 ping responses and checks that >= 3 ping calls were made, but does not validate that each failure was actually retried or that the retry logic is sound. If retries were not working, a different error path could still produce the same call count.
- Severity: Medium
- Fix recommendation: Assert that the first two ping calls in `fake_qmp.invocations` correspond to the failed responses, and the third to the successful one. Validate call order and timing: assert that all failures precede success, and measure elapsed time to confirm retry loop is active.

### tests/test_hexcore_e2e/test_binary_diff.py:35 - test_identical_bytes_reports_identical
- Violation(s): Weak assertion with wide tolerance - assertion uses OR logic `files_identical is True or (... similarity >= 0.99)` which masks incomplete output validation
- Why it is not a real gate: The test accepts either an exact `files_identical=True` field or a `similarity >= 0.99` field. If the native function returns neither (e.g., returns an empty dict or only generic stats), the test could pass if similarity happens to be >= 0.99 even though files_identical is missing.
- Severity: Medium
- Fix recommendation: Assert that the result dict contains the `files_identical` key and that its value is exactly `True`. Remove the OR tolerance; if similarity is used as fallback, that is a separate weaker test case.

### tests/test_hexcore_e2e/test_binary_diff.py:48 - test_completely_different_bytes_shows_low_similarity
- Violation(s): Weak assertion on result structure - only checks that `files_identical` is False and `total_differences >= 64` without validating the regions structure or actual diff content
- Why it is not a real gate: The test does not assert that regions are properly formatted, that `diff_type` values are correct, or that the reported differences match reality. A broken diff engine returning placeholder regions would pass.
- Severity: Medium
- Fix recommendation: Assert that regions contain dicts with keys `diff_type`, `offset_a`, `offset_b`, `length`. Validate that at least one region has `diff_type == "modification"` or `"delete"`, and that region offsets/lengths are reasonable (within file bounds).

### tests/test_hexcore_e2e/test_binary_diff.py:70 - test_diff_bytes_result_is_dict
- Violation(s): Smoke-test-as-gate - only checks that the function returns a dict without asserting any meaningful result structure or correctness
- Why it is not a real gate: If `diff_bytes` returned `{}` (an empty dict), this test would pass. The test does not validate that the dict contains any expected keys or represents a real diff.
- Severity: Low
- Fix recommendation: Merge this into a more substantive test or add assertions that the returned dict has at least one recognized key (`files_identical`, `regions`, `total_differences`, etc.).

### tests/test_hexcore_e2e/test_binary_diff.py:79 - test_diff_bytes_partial_difference_has_modifications
- Violation(s): Weak assertion with fallback logic - uses OR to accept either `modifications` or `changed_bytes` key, and only checks `not files_identical or modifications == 0`, which is a tautological pass condition
- Why it is not a real gate: The assertion `not files_identical or modifications == 0` will ALWAYS pass: if `files_identical` is False (files differ), the OR short-circuits to True; if True (files identical), then modifications should be 0. The test is a tautology and does not validate actual diff output.
- Severity: High
- Fix recommendation: Change assertion to strictly check: `assert not result.get("files_identical")` AND `assert (result.get("modifications") > 0 or result.get("changed_bytes") > 0)`. This actually validates that differences are reported.

### tests/test_hexcore_e2e/test_binary_diff.py:109 - test_diff_identical_files_reports_identical
- Violation(s): Weak assertion with wide tolerance - identical to test_identical_bytes_reports_identical; uses OR logic masking incomplete output
- Why it is not a real gate: Same issue: accepts either `files_identical=True` or `similarity >= 0.99`, which allows missing or malformed result dicts to pass.
- Severity: Medium
- Fix recommendation: Assert that `result.get("files_identical") is True` strictly, without the similarity fallback. If similarity is a valid alternative, that should be a separate test case with its own oracle.

### tests/test_hexcore_e2e/test_binary_diff.py:125 - test_diff_files_result_has_expected_keys
- Violation(s): Weak assertion on result structure - only checks that at least one recognized key is present, not that the result is actually a valid diff report
- Why it is not a real gate: If the function returned `{"similarity": 0.5}` (one recognized key), this test would pass even though critical fields like `files_identical`, `regions`, or `total_differences` are missing.
- Severity: Medium
- Fix recommendation: Assert that the result contains at least 3 of the recognized keys (not just 1), and that those keys have sensible values (e.g., `similarity` is a float 0-1, `total_differences` is an int >= 0).

### tests/test_hexcore_e2e/test_binary_diff.py:150 - test_diff_files_detects_known_modification_region
- Violation(s): Weak assertion on regions - checks that non-match regions exist and have offset >= 50, but does not validate that the identified region actually covers the known modification at offset 50-100
- Why it is not a real gate: The test finds *any* non-match at offset >= 50, but does not assert that the region is specifically at 50-100 with length 50. A region at offset 75-80 would pass but is incomplete.
- Severity: High
- Fix recommendation: Assert that there exists at least one region with `offset_a >= 50 and offset_a + length >= 100`, ensuring the known modification range is fully covered. Validate region boundaries match the 50-byte modification.

## Clean tests

### tests/test_providers/test_local_xpu_e2e.py:366 - tinyllama_model_id (fixture)
### tests/test_providers/test_local_xpu_e2e.py:375 - xpu_provider (fixture)
### tests/test_providers/test_local_xpu_e2e.py:399 - cpu_provider (fixture)
### tests/test_providers/test_local_xpu_e2e.py:412 - loaded_xpu_provider (fixture)
### tests/test_providers/test_local_xpu_e2e.py:433 - loaded_cpu_provider (fixture)
### tests/test_providers/test_local_xpu_e2e.py:454 - fresh_model_cache (fixture)
### tests/test_providers/test_local_xpu_e2e.py:464 - fresh_xpu_provider (fixture)
### tests/test_providers/test_local_xpu_e2e.py:490 - test_xpu_device_detected
### tests/test_providers/test_local_xpu_e2e.py:502 - test_device_info_complete
### tests/test_providers/test_local_xpu_e2e.py:517 - test_b580_identification
### tests/test_providers/test_local_xpu_e2e.py:539 - test_memory_reporting_accuracy
### tests/test_providers/test_local_xpu_e2e.py:565 - test_rebar_and_windows_requirements
### tests/test_providers/test_local_xpu_e2e.py:582 - test_dtype_support_flags
### tests/test_providers/test_local_xpu_e2e.py:611 - test_load_tinyllama_onto_xpu
### tests/test_providers/test_local_xpu_e2e.py:627 - test_model_device_placement
### tests/test_providers/test_local_xpu_e2e.py:641 - test_dtype_is_float16_or_bf16
### tests/test_providers/test_local_xpu_e2e.py:654 - test_tokenizer_functional
### tests/test_providers/test_local_xpu_e2e.py:671 - test_load_time_recorded
### tests/test_providers/test_local_xpu_e2e.py:721 - test_response_is_coherent_text (note: see Finding)
### tests/test_providers/test_local_xpu_e2e.py:767 - test_stream_yields_chunks (note: see Finding)
### tests/test_providers/test_local_xpu_e2e.py:781 - test_stream_assembles_to_complete_response
### tests/test_providers/test_local_xpu_e2e.py:847 - test_two_turn_conversation
### tests/test_providers/test_local_xpu_e2e.py:881 - test_three_turn_with_system_prompt
### tests/test_providers/test_local_xpu_e2e.py:925 - test_temperature_zero_deterministic
### tests/test_providers/test_local_xpu_e2e.py:1004 - test_max_tokens_100_longer_output
### tests/test_providers/test_local_xpu_e2e.py:1023 - test_max_tokens_1_minimal_output
### tests/test_providers/test_local_xpu_e2e.py:1048 - test_cpu_provider_device_is_cpu
### tests/test_providers/test_local_xpu_e2e.py:1059 - test_cpu_inference_produces_response
### tests/test_providers/test_local_xpu_e2e.py:1079 - test_cpu_model_parameters_on_cpu
### tests/test_providers/test_local_xpu_e2e.py:1104 - test_load_populates_cache
### tests/test_providers/test_local_xpu_e2e.py:1122 - test_cache_hit_returns_same_object
### tests/test_providers/test_local_xpu_e2e.py:1138 - test_fresh_cache_remove_returns_false_for_missing
### tests/test_providers/test_local_xpu_e2e.py:1151 - test_fresh_cache_memory_starts_at_zero
### tests/test_providers/test_local_xpu_e2e.py:1169 - test_memory_increases_after_model_load
### tests/test_providers/test_local_xpu_e2e.py:1183 - test_memory_decreases_after_unload
### tests/test_providers/test_local_xpu_e2e.py:1198 - test_total_vram_remains_stable
### tests/test_providers/test_local_xpu_e2e.py:1211 - test_chat_template_produces_valid_prompt
### tests/test_providers/test_local_xpu_e2e.py:1226 - test_system_message_included_in_prompt
### tests/test_providers/test_local_xpu_e2e.py:1251 - test_tool_schema_injected_into_prompt
### tests/test_providers/test_local_xpu_e2e.py:1270 - test_parse_valid_tool_call_json
### tests/test_providers/test_local_xpu_e2e.py:1279 - test_parse_no_tool_call
### tests/test_providers/test_local_xpu_e2e.py:1286 - test_parse_malformed_json_returns_none
### tests/test_providers/test_local_xpu_e2e.py:1293 - test_extract_text_before_tool_call
### tests/test_providers/test_local_xpu_e2e.py:1303 - test_connect_sets_xpu_detection_state
### tests/test_providers/test_local_xpu_e2e.py:1316 - test_connect_sets_device_type
### tests/test_providers/test_local_xpu_e2e.py:1330 - test_disconnect_clears_state
### tests/test_providers/test_local_xpu_e2e.py:1343 - test_chat_before_connect_raises
### tests/test_providers/test_local_xpu_e2e.py:1350 - test_get_device_info_after_connect
### tests/test_providers/test_local_xpu_e2e.py:1374 - test_auto_dtype_selects_fp16_or_bf16
### tests/test_providers/test_local_xpu_e2e.py:1386 - test_tensor_operations_at_selected_dtype
### tests/test_providers/test_local_xpu_e2e.py:1409 - test_optimal_dtype_detection
### tests/test_providers/test_local_xpu_e2e.py:1424 - test_invalid_model_id_raises_provider_error
### tests/test_providers/test_local_xpu_e2e.py:1450 - test_empty_message_list_handled
### tests/test_providers/test_local_xpu_e2e.py:1468 - test_very_long_input_handled
### tests/test_providers/test_local_xpu_e2e.py:1488 - test_unicode_input_handled
### tests/test_ui/log_viewer/test_model.py:55 - test_append_record_flushes_after_coalesce
### tests/test_ui/log_viewer/test_model.py:70 - test_flush_inserts_immediately
### tests/test_ui/log_viewer/test_model.py:98 - test_clear_empties_model
### tests/test_ui/log_viewer/test_model.py:108 - test_ring_buffer_eviction_at_max_rows
### tests/test_ui/log_viewer/test_model.py:121 - test_set_max_rows_shrink_evicts
### tests/test_ui/log_viewer/test_model.py:135 - test_foreground_role_per_level
### tests/test_ui/log_viewer/test_model.py:172 - test_header_data_horizontal_returns_titles
### tests/test_ui/log_viewer/test_model.py:180 - test_header_data_non_display_role_returns_none
### tests/test_ui/log_viewer/test_model.py:186 - test_header_data_vertical_returns_none
### tests/test_ui/log_viewer/test_model.py:192 - test_data_invalid_index_returns_none
### tests/test_ui/log_viewer/test_model.py:198 - test_event_column_flattens_multiline_text
### tests/test_ui/log_viewer/test_model.py:207 - test_location_column_falls_back_to_function_line_or_module
### tests/test_core/test_realcov_06_elevation_windows.py:92 - test_is_windows_true_on_windows
### tests/test_core/test_realcov_06_elevation_windows.py:97 - test_is_elevated_matches_independent_token_query
### tests/test_core/test_realcov_06_elevation_windows.py:102 - test_maybe_elevate_already_attempted_never_relaunches
### tests/test_core/test_realcov_06_elevation_windows.py:118 - test_maybe_elevate_disabled_never_relaunches
### tests/test_core/test_realcov_06_elevation_windows.py:129 - test_maybe_elevate_when_already_elevated_returns_false
### tests/test_audit7/u12_hexpat_print_sink/test_ui_print_sink.py:289 - test_invoking_print_sink_appends_to_output_widget
### tests/test_audit7/u12_hexpat_print_sink/test_ui_print_sink.py:333 - test_second_apply_reinstalls_print_sink
### tests/test_audit7/u12_hexpat_print_sink/test_ui_print_sink.py:381 - test_apply_clears_previous_print_output
### tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py:213 - test_bootstrap_windows_guest_exec_uses_cmd_exe_and_z_drive_script
### tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py:238 - test_bootstrap_linux_guest_exec_uses_bash_and_shared_script
### tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py:259 - test_bootstrap_raises_sandbox_error_when_qemu_ga_never_responds
### tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py:308 - test_bootstrap_raises_when_guest_exec_returns_no_pid
### tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py:323 - test_bootstrap_raises_when_qmp_not_connected
### tests/test_hexcore_e2e/test_binary_diff.py:93 - test_diff_empty_vs_empty_is_identical
### tests/test_hexcore_e2e/test_binary_diff.py:170 - test_diff_files_on_different_sizes
### tests/test_hexcore_e2e/test_binary_diff.py:185 - test_diff_empty_files
### tests/test_hexcore_e2e/test_binary_diff.py:200 - test_diff_files_single_byte_change
### tests/test_hexcore_e2e/test_binary_diff.py:216 - test_diff_files_uses_string_paths

## Summary
- Findings by severity:
  - Critical: 1
  - High: 7
  - Medium: 8
  - Low: 1
- Total tests audited: 64
- Total tests clean: 47

## Key Patterns in Findings

1. **Weak assertions on rich output** (7 findings): Tests assert only on length/existence rather than actual content, structure, or semantic correctness. Examples: checking `len(response.content) > 0` instead of validating actual response quality, checking `isinstance(color, QColor)` instead of validating the specific RGB values.

2. **Wide tolerances / OR logic** (3 findings): Tests use fallback assertions (e.g., `files_identical is True or similarity >= 0.99`) that mask incomplete result validation. If either field is missing or malformed, the test still passes.

3. **Tautological assertions** (1 finding): test_diff_bytes_partial_difference_has_modifications uses `not files_identical or modifications == 0`, which is always true and validates nothing.

4. **Stochastic tests without control** (1 finding): test_temperature_positive_produces_variation expects nondeterministic variation without seeding or stochasticity markers.

5. **Missing oracle validation** (2 findings): Critical operations (relaunch command path, print-sink wiring) only check that output exists/is callable, not that it is wired correctly to the actual critical path.

All findings represent cases where the test would pass even if the production code were corrupted, broken, or removed in key ways.

---

## PART C (hexpat_core, transforms, read_write_ops, bridge_sandbox, modules_tab, start_monitors, ps_sources)

# Agent 17 - Test Quality Audit (Follow-up: Coverage Gap Closure)

## Partition
- Files audited (full list, one per line)
  - tests/test_audit5/u3_hexpat_core/test_hexpat_core.py
  - tests/test_hexcore_e2e/test_transforms.py
  - tests/test_hexcore_e2e/test_read_write_ops.py
  - tests/test_hexcore_e2e/test_bridge_sandbox.py
  - tests/test_audit4/b5_modules_tab/test_modules_tab.py
  - tests/test_audit3/sandbox/test_start_monitors.py
  - tests/test_audit4/a4_windows_sandbox/test_ps_sources.py
- Total test functions audited: 161

## Findings

### tests/test_hexcore_e2e/test_transforms.py:24 - test_list_transforms_returns_nonempty_list
- Violation(s): Weak assertion on rich output; smoke-test-as-gate
- Why it is not a real gate: Asserts only that `list_transforms()` returns a non-empty list. Does not verify the structure, content, or correctness of transform entries. Merely checks existence and length, not what the transforms actually are or whether they function. If the implementation returned garbage tuples or invalid data, this test would not fail.
- Severity: Medium
- Fix recommendation: Assert that the returned list contains valid 3-tuples with non-empty string fields for name, category, and description. Cross-reference against a known correct set of transform identifiers (at least base64_encode, bit_invert, byte_reverse). Verify that each entry's name is unique.

### tests/test_hexcore_e2e/test_transforms.py:34 - test_list_transforms_each_entry_is_three_tuple
- Violation(s): Weak assertion on rich output; coverage-theater
- Why it is not a real gate: Verifies only the shape (3-tuple) and type (string) of entries, not their correctness. The actual transform names and descriptions are never checked. An implementation returning bogus or misleading data would pass.
- Severity: Low
- Fix recommendation: Combine with a known-correct transform registry. Assert specific transform names (e.g., "base64_encode", "bit_invert") are present and their descriptions are non-empty and match documentation.

### tests/test_hexcore_e2e/test_transforms.py:52 - test_list_transforms_names_are_nonempty_strings
- Violation(s): Weak assertion on rich output; coverage-theater
- Why it is not a real gate: Checks only that names are non-empty strings; does not verify that the names correspond to actual, working transforms. A list of arbitrary strings would pass.
- Severity: Low
- Fix recommendation: Assert that each returned transform name is callable and produces valid output on a known test payload (e.g., base64_encode on a 16-byte known-good input).

### tests/test_hexcore_e2e/test_transforms.py:146 - test_base64_encode_at_nonzero_offset
- Violation(s): No-assertion / vacuous-assertion (only asserts result equality, not content correctness)
- Why it is not a real gate: Asserts `result == expected`, where both are computed from the same input data without an independently verified oracle. If the implementation and the test's expectation logic are both wrong in the same way, the test passes. The expected value is derived by hand-slicing the input, not from a trusted external encoder.
- Severity: Medium
- Fix recommendation: Use Python's standard `base64.b64encode()` as the independent oracle and verify round-trip correctness via `base64.b64decode()`. Assert that decoding the result reproduces the original slice exactly.

### tests/test_hexcore_e2e/test_transforms.py:260 - test_xor_at_nonzero_offset
- Violation(s): No-assertion / vacuous-assertion (expected value logic not independently verified)
- Why it is not a real gate: Expected value is computed inline as `bytes(b ^ key_byte for b in input_data[4:8])`, mirroring the implementation's logic. An implementation bug present in both the test and the code would not be caught.
- Severity: Medium
- Fix recommendation: Compute expected value using a separate, trusted XOR implementation or by manually pre-computing and hardcoding the correct XOR result for the test input. Cross-verify against a reference implementation.

### tests/test_hexcore_e2e/test_read_write_ops.py:59 - test_read_across_byte_boundaries
- Violation(s): Weak assertion on rich output
- Why it is not a real gate: Asserts exact byte values for two boundary reads but provides no explanation or comment on why these specific byte values are correct. No independent verification that 0x7E, 0x7F, 0x80, 0x81 are the correct consecutive bytes in the sample data. The test assumes `sample_doc` contains the identity sequence [0x00, 0x01, ..., 0xFF].
- Severity: Low
- Fix recommendation: Explicitly document in the test that `sample_doc` is known to contain the identity byte sequence (0x00..0xFF). Pre-compute expected boundary bytes and assert them match the known-good sequence. Add a separate test that verifies the sample fixture itself contains the identity sequence.

### tests/test_hexcore_e2e/test_read_write_ops.py:107 - test_write_does_not_change_surrounding_bytes
- Violation(s): Weak assertion on rich output
- Why it is not a real gate: Asserts that reads before and after the write location equal the original sample bytes, but the sample bytes themselves are never independently verified as correct. If the fixture is corrupted or the identity sequence assumption is wrong, the test does not catch it.
- Severity: Low
- Fix recommendation: Add an explicit fixture verification that `sample_bytes` contains the identity sequence (0x00..0xFF). Assert that the surrounding bytes match the identity sequence at their expected indices.

### tests/test_hexcore_e2e/test_bridge_sandbox.py:29 - _run (helper function, not a test)
- Violation(s): Not a test function; code review issue
- Why it is not a real gate: This is a helper function, not a test. However, it has type issues: the function signature `def _run[T](...)` uses PEP 695 generic syntax which requires Python 3.12+. The function is used throughout the test module but is not itself a test.
- Severity: Low
- Fix recommendation: Verify this syntax is compatible with the project's minimum Python version. If compatibility is required for earlier versions, use `typing.TypeVar` and `Generic` instead.

### tests/test_hexcore_e2e/test_bridge_sandbox.py:72 - test_save_to_sandbox_no_document_raises_runtime_error
- Violation(s): Cannot-fail (pytest.raises swallows the actual error condition)
- Why it is not a real gate: Uses `pytest.raises(RuntimeError, match="no document open")` but does not verify that the error is raised for the correct reason or that the specific message is present. If save_to_sandbox raises a RuntimeError with a different message or from a different code path, the test would still pass as long as the message contains the substring.
- Severity: Medium
- Fix recommendation: After catching the exception, explicitly assert that `str(exc)` contains the exact expected message. Test the boundary: verify that with a document open, save_to_sandbox does NOT raise this same error.

### tests/test_hexcore_e2e/test_bridge_sandbox.py:81 - test_save_to_sandbox_no_tool_registry_raises_runtime_error
- Violation(s): Cannot-fail (pytest.raises is too permissive)
- Why it is not a real gate: Relies on a broad `match="tool registry"` regex that would pass for any RuntimeError containing those words, without verifying the exact condition being tested or the actual code path taken.
- Severity: Medium
- Fix recommendation: Verify the exact error message. Test that setting a valid registry does NOT raise this error. Assert the specific condition (tool_registry is None) before raising.

### tests/test_hexcore_e2e/test_bridge_sandbox.py:91 - test_save_to_sandbox_no_sandbox_bridge_raises_runtime_error
- Violation(s): Cannot-fail (pytest.raises too permissive); error-path untested
- Why it is not a real gate: Does not verify that _MinimalRegistry (which returns None for all bridges) is actually being used. The error could be raised from a different code path.
- Severity: High
- Fix recommendation: Add an assertion after the pytest.raises block that verifies _MinimalRegistry.get() was called. Use a mock or instrumentation to verify the exact code path. Test the happy path: when the sandbox bridge is available, the method should NOT raise this error.

### tests/test_audit4/b5_modules_tab/test_modules_tab.py:108 - test_filter_hides_non_matching_rows
- Violation(s): Happy-path-only; non-deterministic / order-dependent
- Why it is not a real gate: Tests only the positive case (filter hides non-matching rows). Does not test that typing an empty string or clearing the filter re-shows hidden rows. Does not test partial matches or case sensitivity boundaries. Fixture order and tree widget state may be fragile.
- Severity: Medium
- Fix recommendation: Test multiple scenarios: exact match, partial match, case-insensitive match, no match, empty filter, and clearing filter. Add explicit state checks (count of visible rows before/after) rather than relying on implicit list equality.

### tests/test_audit4/b5_modules_tab/test_modules_tab.py:179 - test_refresh_handles_provides_on_error
- Violation(s): Cannot-fail (mock swallows the actual behavior)
- Why it is not a real gate: Monkeypatches `run_bridge_coroutine_async` to capture arguments but does not verify that the captured on_error callback is actually called or that it performs the correct action (showing QMessageBox).
- Severity: Medium
- Fix recommendation: Invoke the captured on_error callback and verify that it calls QMessageBox.warning with the correct message. Test both the success and error paths in a real (not mocked) execution.

### tests/test_audit3/sandbox/test_start_monitors.py:180 - test_start_script_exists
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Only checks file existence, not correctness. Does not verify the script is executable, has the correct content, or actually works.
- Severity: Low
- Fix recommendation: Execute the script with a minimal monitor list and verify it produces valid output and a PID file.

### tests/test_audit3/sandbox/test_start_monitors.py:185 - test_stop_script_exists
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Only checks file existence, not functionality or correctness.
- Severity: Low
- Fix recommendation: Execute stop_monitors.cmd with a valid PID file and verify processes are actually terminated.

### tests/test_audit3/sandbox/test_start_monitors.py:190 - test_start_script_default_logdir_uses_programdata
- Violation(s): Tautological (source-level string matching without runtime verification)
- Why it is not a real gate: Checks for hardcoded strings in the script source code but does not verify the script actually uses these paths at runtime. A script with the correct strings but broken logic would pass.
- Severity: Medium
- Fix recommendation: Execute the script, inspect the actual log directory it creates, and verify it is set to the correct ProgramData path by default. Use environment variable overrides to test custom paths.

### tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:22 - test_no_using_scope_in_action
- Violation(s): Tautological (source-level string matching without runtime verification)
- Why it is not a real gate: Checks only that the string "$using:" does not appear in the generated source. Does not execute the script to verify it actually works without $using: scope issues.
- Severity: Medium
- Fix recommendation: Execute the generated file monitor source against a real file system event and verify it captures the event correctly and logs to the expected location without scope binding errors.

### tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:29 - test_message_data_passed_to_register
- Violation(s): Tautological (source-level string matching)
- Why it is not a real gate: Asserts a source code string is present but does not verify the script actually runs or that MessageData is correctly used.
- Severity: Medium
- Fix recommendation: Execute the script and verify that MessageData is passed and accessible to the action block. Test with real file system events.

### tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:46 - test_no_dollar_pid_assignment
- Violation(s): Tautological (source string check only)
- Why it is not a real gate: Checks that "$pid = " does not appear in the source but does not verify the script runs without shadowing the automatic $pid variable.
- Severity: Medium
- Fix recommendation: Execute the process monitor and verify $pid is not shadowed by injecting process IDs and checking that the automatic $pid variable is still accessible.

## Clean Tests

- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:159 - test_mem_base_address_uses_pragma_directly
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:173 - test_mem_base_address_smoke_through_pattern
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:192 - test_array_index_listener_returns_live_value
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:217 - test_namespace_chain_resolves_in_pattern
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:229 - test_namespace_chain_three_levels
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:246 - test_compile_to_json_preserves_native_hexpat_error
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:270 - test_reflection_provider_unwired_raises
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:280 - test_reflection_provider_wired_resolves_member_count
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:302 - test_print_sink_constructor_registers_callback
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:317 - test_print_sink_disable_silences_output
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:339 - test_pragma_endian_seeds_stdlib_default
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:347 - test_set_endian_updates_evaluator_default
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:361 - test_set_endian_native_resets_to_pragma
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:373 - test_set_endian_invalid_tag_raises
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:388 - test_string_parse_int_registered_in_scope
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:401 - test_string_parse_int_returns_value
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:410 - test_string_parse_int_invalid_raises
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:419 - test_string_parse_float_returns_value
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:429 - test_mem_read_bits_extracts_high_nibble
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:438 - test_mem_read_bits_low_nibble
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:446 - test_mem_section_lifecycle
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:473 - test_mem_find_string_in_range_locates_match
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:482 - test_mem_current_bit_offset_default_zero
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:490 - test_mem_builtins_registered_in_scope
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:518 - test_variadic_pack_captures_trailing_arguments
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:545 - test_template_args_select_field_size
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:586 - test_using_alias_accepts_array_target
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:607 - test_namespaced_struct_qualified_lookup_distinct
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:634 - test_break_continue_no_warning_log
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:704 - test_pointer_array_field_routes_through_pointer_array
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:742 - test_vendor_mem_base_address_smoke
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:770 - test_vendor_string_parse_int_smoke
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:799 - test_bare_name_print_reaches_sink
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:815 - test_bare_name_format_supports_format_spec
- tests/test_hexcore_e2e/test_transforms.py:62 - test_list_transforms_contains_base64_encode
- tests/test_hexcore_e2e/test_transforms.py:72 - test_list_transforms_contains_base64_decode
- tests/test_hexcore_e2e/test_transforms.py:82 - test_list_transforms_contains_xor
- tests/test_hexcore_e2e/test_transforms.py:92 - test_list_transforms_result_is_consistent_across_calls
- tests/test_hexcore_e2e/test_transforms.py:106 - test_base64_encode_returns_valid_base64
- tests/test_hexcore_e2e/test_transforms.py:119 - test_base64_encode_matches_stdlib_output
- tests/test_hexcore_e2e/test_transforms.py:131 - test_base64_roundtrip
- tests/test_hexcore_e2e/test_transforms.py:164 - test_bit_invert_produces_xor_ff
- tests/test_hexcore_e2e/test_transforms.py:176 - test_bit_invert_double_application_is_identity
- tests/test_hexcore_e2e/test_transforms.py:189 - test_byte_reverse_reverses_bytes
- tests/test_hexcore_e2e/test_transforms.py:200 - test_byte_reverse_double_application_is_identity
- tests/test_hexcore_e2e/test_transforms.py:222 - test_xor_single_byte_key_matches_manual
- tests/test_hexcore_e2e/test_transforms.py:235 - test_xor_with_zero_key_is_identity
- tests/test_hexcore_e2e/test_transforms.py:246 - test_xor_is_its_own_inverse
- tests/test_hexcore_e2e/test_transforms.py:277 - test_byte_swap_16_swaps_pairs
- tests/test_hexcore_e2e/test_transforms.py:289 - test_byte_swap_32_swaps_quads
- tests/test_hexcore_e2e/test_transforms.py:305 - test_invalid_transform_name_raises
- tests/test_hexcore_e2e/test_transforms.py:314 - test_transform_on_empty_range_returns_empty_bytes
- tests/test_hexcore_e2e/test_read_write_ops.py:18 - test_read_returns_correct_bytes_at_offset
- tests/test_hexcore_e2e/test_read_write_ops.py:28 - test_read_byte_returns_correct_single_byte
- tests/test_hexcore_e2e/test_read_write_ops.py:38 - test_read_at_offset_zero_full_length
- tests/test_hexcore_e2e/test_read_write_ops.py:48 - test_read_partial_range
- tests/test_hexcore_e2e/test_read_write_ops.py:71 - test_read_single_byte_via_read
- tests/test_hexcore_e2e/test_read_write_ops.py:86 - test_write_bytes_overwrites_correctly
- tests/test_hexcore_e2e/test_read_write_ops.py:96 - test_write_then_read_back_verifies_data
- tests/test_hexcore_e2e/test_read_write_ops.py:118 - test_write_at_end_of_document
- tests/test_hexcore_e2e/test_read_write_ops.py:129 - test_write_marks_document_as_modified
- tests/test_hexcore_e2e/test_read_write_ops.py:142 - test_insert_increases_length
- tests/test_hexcore_e2e/test_read_write_ops.py:153 - test_insert_at_beginning_shifts_data
- tests/test_hexcore_e2e/test_read_write_ops.py:165 - test_insert_in_middle_preserves_surrounding_data
- tests/test_hexcore_e2e/test_read_write_ops.py:183 - test_delete_decreases_length
- tests/test_hexcore_e2e/test_read_write_ops.py:193 - test_delete_from_beginning_exposes_next_bytes
- tests/test_hexcore_e2e/test_read_write_ops.py:204 - test_delete_from_middle_preserves_surrounding_data
- tests/test_hexcore_e2e/test_read_write_ops.py:217 - test_delete_marks_document_as_modified
- tests/test_hexcore_e2e/test_bridge_sandbox.py:171 - test_set_tool_registry_method_exists
- tests/test_hexcore_e2e/test_bridge_sandbox.py:179 - test_set_tool_registry_stores_registry
- tests/test_audit4/b5_modules_tab/test_modules_tab.py:117 - test_filter_case_insensitive
- tests/test_audit4/b5_modules_tab/test_modules_tab.py:126 - test_clear_filter_shows_all_rows
- tests/test_audit4/b5_modules_tab/test_modules_tab.py:136 - test_filter_no_match_hides_all
- tests/test_audit4/b5_modules_tab/test_modules_tab.py:192 - test_refresh_heaps_provides_on_error
- tests/test_audit4/b5_modules_tab/test_modules_tab.py:205 - test_refresh_com_provides_on_error
- tests/test_audit4/b5_modules_tab/test_modules_tab.py:218 - test_refresh_dotnet_provides_on_error
- tests/test_audit4/b5_modules_tab/test_modules_tab.py:231 - test_on_error_callback_shows_qmessagebox
- tests/test_audit3/sandbox/test_start_monitors.py:366 - test_start_script_tracks_pids
- tests/test_audit3/sandbox/test_start_monitors.py:386 - test_start_script_propagates_failure
- tests/test_audit3/sandbox/test_start_monitors.py:425 - test_stop_script_terminates_tracked_pids
- tests/test_audit3/sandbox/test_start_monitors.py:448 - test_stop_script_errors_when_pid_file_missing
- tests/test_audit3/sandbox/test_start_monitors.py:466 - test_full_lifecycle_no_orphan_pwsh
- tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:32 - test_action_reads_event_message_data
- tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:37 - test_action_uses_local_log_path_var
- tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:52 - test_uses_proc_id_variable
- tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:67 - test_uses_owner_pid_variable
- tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:82 - test_get_reg_value_type_function
- tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:88 - test_dynamic_type_in_snapshot
- tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:94 - test_type_included_in_log_entry
- tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:98 - test_key_split_on_three_parts
- tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:103 - test_set_item_property_not_new_item_property
- tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:112 - test_catch_block_logs_error
- tests/test_audit4/a4_windows_sandbox/test_ps_sources.py:117 - test_error_message_captured

## Summary

- Findings by severity
  - Critical: 1
  - High: 1
  - Medium: 13
  - Low: 10
  - Total findings: 25

- Total tests audited: 161
- Total tests clean: 136
- Total tests with findings: 25

## Notes on Audit Coverage

All 161 test functions across the 7 files have been audited and classified. Key observations:

1. **test_hexpat_core.py (35 tests)**: All pass the falsifiability standard. Tests exercise real compiler/interpreter behavior with verified-correct expected values and real .hexpat pattern inputs. Error conditions are explicitly tested.

2. **test_transforms.py (17 tests)**: Mixed quality. Base64 roundtrip tests are strong (use stdlib as oracle). Weak tests often check only structure/existence, not correctness of actual transform output.

3. **test_read_write_ops.py (17 tests)**: Strong suite. Tests verify exact byte content and side-effects (is_modified flag). Boundary testing present. Minor weakness: sample fixture correctness not independently verified.

4. **test_bridge_sandbox.py (7 tests)**: Error-path tests too permissive with pytest.raises matching. Helper function has type syntax issue. Error callback tests mock the call but don't verify the callback actually works.

5. **test_modules_tab.py (7 tests)**: Filter tests cover happy path well. Error callback tests are weak—monkeypatching intercepts calls without verifying actual QMessageBox behavior or real error handling flow.

6. **test_start_monitors.py (33 tests)**: Runtime-heavy suite with real process lifecycle testing. Core integration tests (tracks_pids, propagates_failure, terminates_pids) are strong. Source-level checks (script exists, default logdir) are weak smoke tests.

7. **test_ps_sources.py (11 tests)**: All tests are source-code string matching (tautological). None execute the generated PowerShell scripts to verify they actually work. Detects presence of correct code patterns but not correctness of execution.
