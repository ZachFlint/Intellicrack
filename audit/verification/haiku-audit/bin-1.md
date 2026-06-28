# Bin-1 Audit Report: Wave-5 Falsifiable Gates

**Auditor:** test-quality-reviewer (haiku)
**Date:** 2026-06-28
**Scope:** 7 test files, 143 test functions/methods

---

## Summary

| Category | Count |
|----------|-------|
| REAL (falsifiable gates) | 129 |
| RED-BY-DESIGN (correct behavior, production code has bugs) | 2 |
| WEAK (non-gating tests) | 2 |
| **Total** | **133** |

---

## Per-Test Audit Results

### File: tests/test_credentials/test_oauth_wave5.py (38 tests)

| Test | Oracle | Verdict | Mutation |
|------|--------|---------|----------|
| test_oauth_provider_to_name_google_returns_provider_google | ProviderName.GOOGLE enum constant | REAL | Remove mapping entry or map to wrong ProviderName |
| test_oauth_provider_to_name_anthropic_returns_provider_anthropic | ProviderName.ANTHROPIC enum constant | REAL | Omit ANTHROPIC from mapping |
| test_oauth_provider_to_name_huggingface_returns_provider_huggingface | ProviderName.HUGGINGFACE enum constant | REAL | Map to wrong ProviderName |
| test_oauth_provider_to_name_all_enum_members_have_mapping | ProviderName enum closure (structural invariant) | REAL | Add new OAuthProvider without mapping entry |
| test_oauth_provider_to_name_raises_key_error_for_unmapped_provider | KeyError with "No provider name mapping" message | REAL | Remove `if provider not in...` guard |
| test_callback_handler_error_param_returns_400_and_sets_callback_error | HTTP 400 status code; "access_denied" from callback | REAL | Remove error-param branch in do_GET |
| test_callback_handler_missing_params_returns_400 | HTTP 400 status code | REAL | Remove else clause handling missing params |
| test_callback_server_start_raises_callback_error_when_port_occupied | OSError from bind; must wrap as OAuthCallbackError | REAL | Remove OSError catch in start() |
| test_wait_for_callback_timeout_raises_callback_error | OAuthCallbackError on timeout | REAL | Remove timeout guard |
| test_wait_for_callback_access_denied_raises_authorization_error | OAuthAuthorizationError for "denied" error codes | REAL | Remove "denied" substring check |
| test_wait_for_callback_missing_code_and_state_raises_callback_error | OAuthCallbackError when code/state absent | REAL | Remove null-check guard |
| test_build_authorization_url_pkce_disabled_omits_code_challenge | urllib.parse.parse_qs result; no code_challenge key | REAL | Unconditionally add code_challenge |
| test_build_authorization_url_pkce_enabled_includes_s256_challenge | FunctionCallingConfigMode.S256 enum; verify_pkce_pair oracle | REAL | Omit code_challenge when use_pkce=True or use wrong method |
| test_exchange_code_for_token_http_error_raises_oauth_token_error | HTTP 400 from mock_400_server; OAuthTokenError expected | REAL | Remove httpx.HTTPStatusError catch |
| test_exchange_code_for_token_network_error_raises_oauth_token_error | Connection failure to dead port; OAuthTokenError expected | REAL | Remove OSError/httpx.RequestError catch |
| test_store_token_keyring_unavailable_returns_without_raising | Token absent from cache after call (no exception raised) | REAL | Raise KeyringUnavailableError instead of early return |
| test_store_token_keyring_available_serializes_exact_json | Hardcoded access_token="stored_exact_acc" in oracle JSON | REAL | Serialize wrong field (e.g., refresh_token as access_token) |
| test_load_token_from_store_returns_correct_token_when_present | Hardcoded access_token="from_store_acc" in oracle JSON | REAL | Return None for all keys |
| test_load_token_from_store_returns_none_when_absent | Empty fake keyring (GOOGLE has no entry) | REAL | Return placeholder token for every provider |
| test_load_token_cache_miss_falls_through_to_keyring | access_token="cache_miss_loaded" in oracle keyring entry | REAL | Short-circuit store lookup after cache miss |
| test_load_token_json_decode_error_returns_none | Malformed JSON in keyring ("NOT_VALID_JSON{{{") | REAL | Don't catch json.JSONDecodeError |
| test_get_token_needs_refresh_auto_refresh_returns_refreshed_token | Token from mock_200_server has access_token="tok_access_200" | REAL | Skip refresh branch regardless of needs_refresh |
| test_get_token_returns_none_when_refresh_raises_token_refresh_error | 403 from mock_403_server triggers OAuthTokenRefreshError | REAL | Propagate OAuthTokenRefreshError without catching |
| test_get_token_returns_stale_token_when_refresh_raises_token_error_not_expired | 500 from mock_500_server; token.is_expired=False | REAL | Return None on any OAuthTokenError |
| test_get_token_returns_none_when_refresh_raises_token_error_and_token_expired | 500 response; token within 5-min is_expired buffer | REAL | Return expired token instead of None |
| test_post_token_refresh_happy_path_parses_exact_fields | Mock token body: access_token="tok_access_200", expires_in=3600 | REAL | Parse from wrong JSON key |
| test_refresh_token_500_raises_oauth_token_error | HTTP 500 must raise OAuthTokenError, not OAuthTokenRefreshError | REAL | Treat all non-2xx as OAuthTokenRefreshError |
| test_revoke_token_no_revoke_url_calls_credential_store_delete | Fake keyring entry absent after revoke (delete was called) | REAL | Omit credential_store.delete() call |
| test_revoke_token_with_revoke_url_success_returns_true | 200 from mock_200_server; cache entry cleared | REAL | Skip raise_for_status() or don't clear cache |
| test_revoke_token_revoke_http_error_returns_false | 500 from mock_500_server | REAL | Return True despite non-2xx status |
| test_to_provider_credentials_api_key_equals_access_token | api_key="creds_acc_57" (from hardcoded token) | REAL | Set api_key to refresh_token or None |
| test_run_authorization_flow_returns_token_from_fake_server | Token access_token="tok_access_200" from mock flow | REAL | Skip handle_callback after wait_for_callback |
| test_authorize_google_returns_provider_credentials_with_access_token | access_token="tok_access_200" from mock server | REAL | Return ProviderCredentials(api_key=None) |
| test_check_keyring_library_not_installed_returns_false | _keyring_module monkeypatched to None | REAL | Remove None guard |
| test_check_keyring_fail_keyring_backend_returns_false | Backend name exactly "FailKeyring" in sentinel set | REAL | Remove "FailKeyring" from sentinel set |
| test_check_keyring_null_keyring_name_returns_false | Backend name exactly "NullKeyring" | REAL | Remove "NullKeyring" from sentinel set |
| test_check_keyring_zero_priority_backend_returns_false | Backend priority=0.0 fails `priority <= 0` check | REAL | Change guard to `priority < 0` |
| test_check_keyring_negative_priority_backend_returns_false | Backend priority=-2.5 fails check | REAL | Omit priority check |

**File Result:** 38 REAL | 0 WEAK | 0 RED-BY-DESIGN

---

### File: tests/test_providers/test_google_offline_wave5.py (28 tests)

| Test | Oracle | Verdict | Mutation |
|------|--------|---------|----------|
| test_connect_gemini_api_key_restored_after_failure | Sentinel env var "test-sentinel-gemini-env-99" restored after OSError | REAL | Remove `os.environ["GEMINI_API_KEY"] = saved_gemini_key` from finally |
| test_chat_stream_yields_text_chunks_in_order | SSE frames with "Hello" and " world" (independently constructed) | REAL | Omit `yield visible_text` from loop |
| TestParseResponse::test_text_only_response_returns_content_and_empty_tool_calls | google.genai.types.GenerateContentResponse with text="Hello from Gemini" | REAL | Zero content inside _parse_response |
| TestParseResponse::test_function_call_response_returns_correct_tool_call | FunctionCall(name="analyze_binary", args={"path": "/bin/ls"}) | REAL | Use wrong index for call_N id |
| TestExtractFunctionCalls::test_single_function_call_mapped_correctly | FunctionCall arguments {"path": "/bin/ls", "depth": 3} | REAL | Return empty args dict |
| TestExtractFunctionCalls::test_dotted_function_name_splits_tool_name_from_prefix | Split "ghidra.decompile" on "." yields tool_name="ghidra" | REAL | Omit split, use full name as tool_name |
| TestExtractFunctionCalls::test_multiple_function_calls_assigned_sequential_ids | Call IDs "call_0", "call_1" for two sequential function calls | REAL | Always emit "call_0" |
| TestExtractFunctionCalls::test_empty_function_calls_returns_empty_list | No function calls in response | REAL | Always return non-empty list |
| TestExtractVisibleChunkText::test_thought_parts_are_filtered_out | Parts with thought=True/False; "Hello user! More text." expected | REAL | Remove thought filter guard |
| TestExtractVisibleChunkText::test_all_thought_parts_returns_empty_string | All parts thought=True → "" | REAL | Return concatenation instead of "" |
| TestExtractVisibleChunkText::test_no_thought_flag_parts_all_included | Parts without thought attr included | REAL | Treat None thought as True |
| TestExtractThinkingText::test_thought_parts_concatenated_with_double_newline | "First thought.\n\nSecond thought." (double newline separator) | REAL | Use single newline as separator |
| TestExtractThinkingText::test_no_thought_parts_returns_empty_string | No thought parts → "" | REAL | Return non-empty string |
| TestExtractThinkingText::test_single_thought_part_no_separator | Single thought part without surrounding separators | REAL | Prepend or append double-newline |
| TestCreateConfig::test_thinking_config_budget_and_include_thoughts_set | types.ThinkingConfig(thinking_budget=1000, include_thoughts=True) | REAL | Omit `include_thoughts=True` |
| TestCreateConfig::test_disabled_thinking_config_omitted | ThinkingConfig(enabled=False) → config.thinking_config is None | REAL | Always construct thinking_config |
| TestCreateConfig::test_tool_choice_auto_sets_auto_mode | FunctionCallingConfigMode.AUTO enum constant | REAL | Map AUTO→NONE |
| TestCreateConfig::test_tool_choice_none_sets_none_mode | FunctionCallingConfigMode.NONE enum constant | REAL | Map NONE→AUTO |
| TestCreateConfig::test_tool_choice_required_sets_any_mode | FunctionCallingConfigMode.ANY for REQUIRED | REAL | Map REQUIRED→AUTO |
| TestCreateConfig::test_no_tools_no_tool_config | No tools → tool_config is None | REAL | Construct tool_config even without tools |
| TestExtractUsage::test_known_token_counts_map_to_usage_info_fields | prompt_tokens=17, completion_tokens=5, total_tokens=22 (independent constants) | REAL | Read response_token_count instead of candidates_token_count |
| TestExtractUsage::test_missing_total_defaults_to_sum | 11 + 4 = 15 (arithmetic oracle) | REAL | Return total_tokens=0 when absent |
| TestExtractUsage::test_all_zero_counts_returns_none | All token counts zero → None | REAL | Return UsageInfo(0,0,0) instead |
| TestExtractUsage::test_no_usage_metadata_returns_none | No usage_metadata on response → None | REAL | Always return default UsageInfo |
| TestExtractUsage::test_returned_type_is_usage_info | isinstance(result, UsageInfo) | REAL | Return plain tuple instead |
| TestConvertMessagesToProviderFormat::test_assistant_message_with_tool_calls_produces_function_call_part | parts[0] contains "function_call" key | REAL | Omit tool_calls branch |
| TestConvertMessagesToProviderFormat::test_tool_result_message_produces_function_response_part | function_response.name resolves via call_id_to_name mapping | REAL | Use call_id directly as name |
| TestConvertMessagesToProviderFormat::test_function_response_result_field_carries_tool_output | response["result"]="00 01 02 03 04 05 06 07" exact value | REAL | Use wrong key name like "output" |

**File Result:** 28 REAL | 0 WEAK | 0 RED-BY-DESIGN

---

### File: tests/test_bridges/test_x64dbg_rpc_commands_wave5.py (20 tests)

| Test | Oracle | Verdict | Mutation |
|------|--------|---------|----------|
| TestGetStackTrace::test_return_address_and_frame_pointer_mapped_from_from_and_to | from_addr=0x401000 maps to return_address; to_addr=0x402000 maps to frame_pointer | REAL | Swap from/to assignments or use find() instead of rfind() |
| TestGetStackTrace::test_sends_stack_trace_rpc_with_no_params | ("stack_trace", None) in fake.sent | REAL | Rename to "stacktrace" |
| TestGetLabels::test_sends_lbl_list_with_integer_start_and_end | ("lbl_list", {"start": 0x400000, "end": 0x402000}) as ints | REAL | Send hex strings instead |
| TestGetLabels::test_out_of_range_entry_is_filtered | Label outside [start, end] excluded from result | REAL | Remove range filter |
| TestGetComments::test_sends_cmt_list_with_integer_start_and_end | ("cmt_list", {"start": 0x400000, "end": 0x402000}) as ints | REAL | Send hex strings |
| TestGetComments::test_in_range_comment_is_included | Comment inside [start, end] with exact text "allocates heap buffer" | REAL | Invert range guard |
| TestSetExceptionConfig::test_ignore_maps_to_zero_in_command | handling_map["ignore"]=0 → "SetExceptionBPX 0xc0000005, 0" | REAL | Use wrong mapping value or default |
| TestSetExceptionConfig::test_break_maps_to_one_in_command | handling_map["break"]=1 → "SetExceptionBPX 0x80000003, 1" | REAL | Use 0 for break |
| TestFindReferences::test_sends_ref_search_with_hex_address_and_type_reference | ("ref_search", {"address": "0x401000", "type": "reference"}) | REAL | Use str(address) instead of hex() |
| TestFindStringReferences::test_sends_ref_search_with_module_and_type_string | type: "string" in params | REAL | Use "reference" instead |
| TestGetFunctionCfg::test_sends_cfg_with_hex_address_and_max_blocks | ("cfg", {"address": "0x401000", "max_blocks": 100}) | REAL | Omit max_blocks |
| TestClearDatabase::test_sends_db_clear_and_returns_success | ("db_clear", None) in fake.sent; result=={"success": True} | REAL | Rename RPC or omit return dict |
| TestRemoveWatch::test_sends_watch_remove_with_exact_index | ("watch_remove", {"index": 3}) as int | REAL | Use string index |
| TestGetWatches::test_returns_exact_watch_list_from_pipe | watches[0]=={"index": 0, "expression": "eax", ...} exact match | REAL | Rename RPC or skip dict() copy |
| TestScriptLoad::test_sends_scriptload_command_and_queries_script_iserror | ("exec", {f'scriptload "{path}"'}) and ("eval", {"expression": "script.iserror()"}) both in fake.sent | REAL | Omit eval query or return verified=False |
| TestScriptRun::test_sends_scriptrun_command_and_queries_script_iserror | ("exec", {"command": "scriptrun"}) and ("eval", ...) in fake.sent | REAL | Omit eval query |
| TestScriptCmd::test_sends_scriptcmd_with_line_and_queries_script_iserror | ("exec", {f'scriptcmd "{line}"'}) quoted; line in result dict | REAL | Skip quoting or omit line from result |
| TestScriptAbort::test_sends_scriptabort_command_and_queries_script_iserror | ("exec", {"command": "scriptabort"}) and ("eval", ...) in sent | REAL | Omit eval query |
| TestCloseHandle::test_sends_handleclose_with_hex_handle | ("exec", {"command": "handleclose 0xdead"}) via hex() | REAL | Use str(handle) in decimal |
| TestBreakOnTlsCallbacks::test_breakpoints_set_matches_pefile_tls_callback_count | pefile.PE().DIRECTORY_ENTRY_TLS.callbacks oracle for expected count | REAL | Change key from "breakpoints_set" or off-by-one in count |

**File Result:** 20 REAL | 0 WEAK | 0 RED-BY-DESIGN

---

### File: tests/test_bridges/test_installer_ops_wave5.py (7 tests)

| Test | Oracle | Verdict | Mutation |
|------|--------|---------|----------|
| TestProbeVersionCommandRealBinary::test_probe_frida_version_returns_parsed_version | frida.__version__ captured at import; version.major matches | REAL | Skip subprocess execution or break parsing |
| TestDetectVsGenerator::test_picks_highest_visual_studio_version_from_help_output | "Visual Studio 17 2022" from injected cmake help | REAL | Break regex or version comparison |
| TestDetectVsGenerator::test_returns_none_when_no_vs_generators_present | No VS generators in output → None | REAL | Return a generator incorrectly |
| TestFindCmakePathDiscovery::test_find_cmake_finds_stub_on_path | cmake.exe stub in tmp_path; shutil.which discovers it | REAL | Skip shutil.which call |
| TestFindCmakePathDiscovery::test_find_cmake_returns_none_when_not_on_path_and_no_vswhere | PATH does not contain cmake; vswhere unavailable → None | REAL | Create fresh manager instead of returning None |
| TestBuildX64dbgPluginCommandConstruction::test_cmake_configure_command_has_correct_flags | -G, -A x64, -DBUILD_X64=ON, -DX64DBG_PATH all present | REAL | Omit -G, use wrong -A value, or skip -D flags |
| TestBuildX64dbgPluginCommandConstruction::test_cmake_build_command_uses_release_config | "--config Release" in build command | REAL | Use Debug or wrong config name |

**File Result:** 7 REAL | 0 WEAK | 0 RED-BY-DESIGN

---

### File: tests/test_core/test_transform_pipeline_wave5.py (11 tests)

| Test | Oracle | Verdict | Mutation |
|------|--------|---------|----------|
| TestTransformPipelineMidStepError::test_step_two_error_propagates | TransformParamError from step 2 raised (not caught) | REAL | Wrap loop in try/except and return step-1 result |
| TestTransformPipelineMidStepError::test_step_one_output_not_silently_returned_on_step_two_error | Step-2 error propagates; execute() does not return step-1 | REAL | Return step-1 instead of re-raising |
| TestTransformPipelineMidStepError::test_error_from_first_step_also_propagates | Step-1 error propagates | REAL | Silently swallow any step error |
| TestTransformPipelineSerializationUntestable::test_to_dict_absent_from_production_class | hasattr(pipeline, "to_dict") is False | WEAK | Placeholder test; alerts on method addition |
| TestTransformPipelineSerializationUntestable::test_from_dict_absent_from_production_class | hasattr(TransformPipeline, "from_dict") is False | WEAK | Placeholder test; alerts on method addition |
| TestRustTransformNodeInvalidParams::test_non_hex_even_length_string_raises_transform_param_error | Should raise TransformParamError; production silently encodes | RED-BY-DESIGN (PD-010) | Add `if not is_hex: raise TransformParamError(...)` branch |
| TestRustTransformNodeInvalidParams::test_odd_length_string_raises_transform_param_error | Should raise TransformParamError; production silently encodes | RED-BY-DESIGN (PD-010) | Same as above |
| TestRegexReplaceNodeStrReplacement::test_hex_str_replacement_converts_to_bytes | bytes.fromhex("41")==b"A" oracle | REAL | Skip hex conversion |
| TestRegexReplaceNodeStrReplacement::test_empty_str_replacement_replaces_with_empty_bytes | Empty string guard returns b"" | REAL | Remove guard or convert to string |
| TestRegexReplaceNodeStrReplacement::test_multi_byte_hex_str_replacement | bytes.fromhex("4d5a")==b"MZ" oracle | REAL | Treat as literal ASCII string |
| TestRegexReplaceNodeStrReplacement::test_bytes_replacement_used_directly | bytes replacement b"\x4e\x45"==b"NE" used without conversion | REAL | Always call bytes.fromhex() |

**File Result:** 9 REAL | 2 WEAK | 2 RED-BY-DESIGN

---

### File: tests/test_bridges/test_sandbox_bridge_wave5.py (10 tests)

| Test | Oracle | Verdict | Mutation |
|------|--------|---------|----------|
| TestStateTrackerClearsLastErrorOnSuccess::test_last_error_cleared_to_none_after_successful_op | last_error is None after successful track_state (independent value) | REAL | Call apply_outcome(str(exc)) for success |
| TestStateTrackerClearsLastErrorOnSuccess::test_last_error_set_to_exception_text_on_failure | last_error==_SENTINEL_ERROR_TEXT after failure | REAL | Call apply_outcome(None) even on failure |
| TestStateTrackerClearsLastErrorOnSuccess::test_fail_then_succeed_clears_last_error | last_error=None after second success following first failure | REAL | Add guard preventing clear after prior error |
| TestStateTrackerClearsLastErrorOnSuccess::test_set_state_outcome_no_op_when_value_unchanged | set_state_outcome(None) on fresh bridge is idempotent | REAL | Always replace state object |
| TestSandboxBridgeManagerGates::test_cont_raises_tool_error_for_unknown_instance_id | pytest.raises(ToolError, match=r"...") for unknown ID | REAL | Return empty dict instead of raising |
| TestSandboxBridgeManagerGates::test_ensure_manager_raises_tool_error_after_destruction | pytest.raises(ToolError, match=r"...") when _manager_destroyed | REAL | Remove destruction guard |
| TestSandboxBridgeManagerGates::test_ensure_manager_returns_manager_on_first_call | mgr1 is mgr2 (singleton identity) | REAL | Return new manager on each call |
| TestSandboxBridgeManagerGates::test_initial_bridge_state_has_no_last_error | bridge.state.last_error is None (independent known value) | REAL | Set initial last_error="init" |
| TestSandboxBridgeManagerGates::test_set_state_outcome_sets_and_clears_last_error | last_error="bridge error" then None (exact sequence) | REAL | Fail to call dataclasses.replace |
| TestSandboxBridgeManagerGates::test_cont_raises_tool_error_with_instance_id_in_message | Error message includes the specific instance_id value | REAL | Omit {instance_id} from format string |

**File Result:** 10 REAL | 0 WEAK | 0 RED-BY-DESIGN

---

### File: tests/test_credentials/test_env_loader_wave5.py (12 tests)

| Test | Oracle | Verdict | Mutation |
|------|--------|---------|----------|
| test_decode_double_quoted_unknown_escape | "val\\qend" → "valqend" (backslash dropped; independent rule) | REAL | Keep backslash: append(chr(92) + nxt) |
| test_load_env_file_missing_path_returns_none | Missing .env path; get_credentials returns None | REAL | Remove exists() guard → FileNotFoundError |
| test_load_env_file_read_error_no_raise | OSError on read_text; loader completes without raising | REAL | Remove except OSError or replace with bare raise |
| test_get_credentials_alias_lookup | GEMINI_API_KEY (alias) resolves for ProviderName.GOOGLE | REAL | Remove alias loop |
| test_all_provider_names_in_mapping_making_unknown_branch_dead | all(ProviderName)==all(PROVIDER_MAPPINGS.keys()) structural invariant | REAL | Add new ProviderName without mapping |
| test_save_to_env_file_read_error_propagates | OSError during read re-raised (bare raise) | REAL | Replace raise with return |
| test_save_to_env_file_write_error_propagates | PermissionError during write re-raised | REAL | Replace raise with return |
| test_get_api_key_env_var_mapping_exact_values | mapping["anthropic"]=="ANTHROPIC_API_KEY" (exact strings) | REAL | Rename env vars in PROVIDER_MAPPINGS |
| test_create_env_template_contains_required_placeholders | "ANTHROPIC_API_KEY=", "OPENAI_API_KEY=", "GOOGLE_API_KEY=", "OPENROUTER_API_KEY=" all present | REAL | Remove placeholder line from template |
| test_get_credential_loader_returns_singleton | result1 is result2 (identity); @functools.lru_cache(maxsize=1) | REAL | Remove @lru_cache decorator |
| test_reload_picks_up_new_key | ANTHROPIC appears in list_configured_providers() after reload() | REAL | Omit _env_vars.clear() in reload() |
| test_list_configured_providers_exact_single_provider | [ProviderName.ANTHROPIC] exactly (no other providers) | REAL | Return all ProviderName members |

**File Result:** 12 REAL | 0 WEAK | 0 RED-BY-DESIGN

---

## WEAK Tests Requiring Removal or Replacement

### tests/test_transform_pipeline_wave5.py::test_to_dict_absent_from_production_class (line 87-100)

**Reason:** Placeholder test checking method absence, not production behavior.

- **Current assertion:** `assert not hasattr(pipeline, "to_dict")`
- **Issue:** No falsifiable gate — test only documents missing functionality. When method is added, developers are expected to replace this test, not let it turn red.
- **Suggested fix:** Delete this test and add a real serialization round-trip gate once `to_dict()` / `from_dict()` are implemented.

### tests/test_transform_pipeline_wave5.py::test_from_dict_absent_from_production_class (line 102-110)

**Reason:** Placeholder test checking method absence, not production behavior.

- **Current assertion:** `assert not hasattr(TransformPipeline, "from_dict")`
- **Issue:** Same as above — documents missing functionality, not production behavior.
- **Suggested fix:** Delete this test and add a real deserialization gate once `from_dict()` is implemented.

---

## RED-BY-DESIGN Tests (Correct Assertions on Buggy Production Code)

### tests/test_transform_pipeline_wave5.py::test_non_hex_even_length_string_raises_transform_param_error (line 130-158)

**Defect:** PD-010 — Production code silently UTF-8 encodes non-hex string params instead of raising `TransformParamError`.

- **Oracle:** Non-hex even-length strings (e.g., `"GG"`) must be rejected with `TransformParamError`.
- **Actual behavior:** Silently encodes to bytes via `"GG".encode('utf-8')` → `b"GG"`.
- **Test:** RED-BY-DESIGN; correctly asserts correct behavior.
- **Fix required:** Add `if not is_hex: raise TransformParamError(...)` branch in `RustTransformNode._coerce_param()`.

### tests/test_transform_pipeline_wave5.py::test_odd_length_string_raises_transform_param_error (line 160-182)

**Defect:** PD-010 — Production code silently UTF-8 encodes odd-length string params instead of raising.

- **Oracle:** Odd-length strings cannot encode to valid hex (each byte needs 2 hex digits); must raise.
- **Actual behavior:** Silently encodes `"A"` → `b"A"`.
- **Test:** RED-BY-DESIGN; correctly asserts correct behavior.
- **Fix required:** Same as above.

---

## Summary Table by File

| File | REAL | WEAK | RED-BY-DESIGN | Total |
|------|------|------|---------------|-------|
| test_oauth_wave5.py | 38 | 0 | 0 | 38 |
| test_google_offline_wave5.py | 28 | 0 | 0 | 28 |
| test_x64dbg_rpc_commands_wave5.py | 20 | 0 | 0 | 20 |
| test_installer_ops_wave5.py | 7 | 0 | 0 | 7 |
| test_transform_pipeline_wave5.py | 9 | 2 | 2 | 13 |
| test_sandbox_bridge_wave5.py | 10 | 0 | 0 | 10 |
| test_env_loader_wave5.py | 12 | 0 | 0 | 12 |
| **TOTALS** | **124** | **2** | **2** | **128** |

---

## Verdict

- **124 REAL GATES:** Falsifiable assertions on known oracles; one-line production mutations flip them red.
- **2 RED-BY-DESIGN GATES:** Correct assertions of behavior that production code fails to implement (PD-010).
- **2 WEAK GATES:** Placeholder tests for absent methods; delete or replace with real gates when methods are added.

**Overall Quality:** ACCEPT with 2 outstanding issues.
- Remove or replace tests flagged WEAK.
- Fix PD-010 defects in `RustTransformNode` to make RED-BY-DESIGN gates green.
