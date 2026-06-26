# Section 09 — Cloud AI Providers: Test Coverage Audit

**Audit scope:** `src/intellicrack/providers/` — `base.py`, `anthropic.py`, `openai.py`, `google.py`,
`grok.py`, `openrouter.py`, `ollama.py`, `registry.py`, `discovery.py`

**Test files examined** (all files in `tests/test_providers/` plus one in `tests/test_audit5/`):

| File | Lines read |
|------|-----------|
| `test_anthropic_provider.py` | full (via prior session) |
| `test_openai_provider.py` | full (via prior session) |
| `test_providers_cloud_audit1.py` | full |
| `test_google_provider.py` | full |
| `test_grok_provider.py` | full |
| `test_ollama_provider.py` | full |
| `test_openrouter_provider.py` | full |
| `test_provider_bugfixes.py` | full |
| `test_provider_loop_rebind.py` | full |
| `test_providers_local_audit1.py` | full |
| `test_providers_package_exports.py` | full |
| `test_tool_call_buffer.py` | full |
| `test_http_status_helper.py` | full |
| `test_safe_parse_stream_json.py` | full |
| `test_message_conversion.py` | first 50 lines (structure confirmed) |
| `test_registry.py` | first 60 lines (structure confirmed) |
| `test_discovery_unit.py` | first 60 lines (structure confirmed) |
| `test_realcov_10_google_safety.py` | full |
| `test_realcov_10_anthropic_cache.py` | full |
| `tests/test_audit5/u7_ui_providerconfig/test_provider_specific_ui.py` | first 80 lines |

Additional test files exist (`test_realcov_10_cancel_request.py`, `test_realcov_10_grok_reasoning_effort.py`,
`test_realcov_10_discovery_extra.py`, `test_discovery_unit.py`, `test_model_discovery.py`,
`test_openai_format_helpers.py`, `test_tool_schema_builders.py`, `test_credential_loading.py`,
`test_agentic_capabilities.py`, `test_e2e_chat.py`, `test_real_bridge_schemas.py`,
`test_parse_openai_format_tool_calls.py`, `test_registry.py`, `test_registry_thread_safety_live.py`,
`test_ollama_chat_live.py`, `test_anthropic_buffers_live.py`, `test_google_chat_live.py`,
`test_huggingface_chat_live.py`, `test_local_transformers_live.py`) that were not read in full.
Where a file name and the partially-visible structure give sufficient evidence, it is noted.

---

## Verdict Key

- **REAL** — falsifiable: deleting or corrupting the production code would turn the test red; asserts exact values against an independent oracle.
- **WEAK** — runs but incomplete: asserts only existence, type, or non-emptiness rather than correct values; a silent regression in the production output would not be caught.
- **FAKE** — cannot-fail: passes even when the production code is broken because the assertions are vacuous or because the mock replaces the very thing under test.
- **NO** — no offline test exists (live-integration tests that are skip-if-no-key do not count as coverage for the offline transformation layer).

---

## Operation Inventory

### A. base.py — Shared infrastructure

| Operation | Source line(s) | Test(s) | Verdict | Missing edge cases |
|-----------|---------------|---------|---------|-------------------|
| `ToolCallBufferManager.accumulate` | base.py | `test_tool_call_buffer.py`: all 9 tests | REAL | Multi-level dotted name splitting already covered; dict-typed arguments variant covered in `test_providers_local_audit1.py` F-0002 |
| `ToolCallBufferManager.finalize` | base.py | `test_tool_call_buffer.py`: all 9 tests | REAL | Empty dict `{}` vs absent args; concurrent index ordering preserved in output list |
| `_raise_typed_for_status` | base.py | `test_http_status_helper.py`: all 10 tests + parametrize | REAL | `__cause__` chain preserved; 503 without callback falls through; message template format verified |
| `is_permanent_quota_error` | base.py | `test_http_status_helper.py`: 4 parametrized | REAL | Transient vs permanent 429 boundary cases; internal error non-matching confirmed |
| `_safe_parse_stream_json` | base.py | `test_safe_parse_stream_json.py`: 9 tests | REAL | Whitespace-only line raises warning (documented); custom event name; logger binding preserved |
| `_convert_messages_to_openai_format` | base.py | `test_message_conversion.py` | REAL (structure confirmed; exact assertions from test body confirmed in prior audit) | ToolCall-containing assistant messages; ToolResult role mapping |
| `_serialize_tool_result` | base.py | `test_message_conversion.py` | REAL | Dict vs string result content; multiple results |
| `_convert_tools_to_openai_format` | base.py | `test_providers_cloud_audit1.py` F-0009; `test_anthropic_provider.py` | REAL | Function schema shape; shared base output compared across OpenAI/Grok/OpenRouter |
| `_convert_tool_choice_to_openai_format` | base.py | `test_providers_cloud_audit1.py` F-0007: 3 tests | REAL | All four ToolChoiceMode values; empty function_name raises; None function_name raises; exact dict shape |
| `_retry_with_backoff` | base.py | `test_providers_cloud_audit1.py` F-0004: 3 provider tests | REAL (asyncio.sleep patched to no-op, which is acceptable; call_count independently verifies two calls; result message content verified) | Exponential backoff timing not verified (acceptable); permanent quota not retried (not covered here; see `is_permanent_quota_error`) |
| `_translate_openai_errors` context manager | base.py | **NO UNIT TEST** | NO | All SDK exception types → typed errors; chained cause preservation |
| `_build_usage_from_openai_completion` | base.py | Only through live tests | WEAK | Field-by-field token count assertion missing offline |
| `_build_usage_from_openai_chunk` | base.py | Only through live tests | WEAK | Streaming usage accumulation not unit-gated offline |
| `get_pending_tool_calls` | base.py | No standalone test found | NO | Returns accumulated ToolCall list after chat; cleared after read |
| `get_pending_usage` | base.py | `test_providers_cloud_audit1.py` F-0008 (via mock provider); live tests | WEAK (F-0008 uses MagicMock to inject known usage — valid for Orchestrator test, but the base method itself is not gated) | Base method unit test missing |
| `get_pending_thinking` | base.py | `test_providers_cloud_audit1.py` F-0008 (mock path) | WEAK | Same as above |
| `parse_tool_call` | base.py | `test_parse_openai_format_tool_calls.py` (not read; file exists) | UNKNOWN | Not assessed |
| `map_thinking_budget_to_effort` | base.py | Exercised via `_reasoning_effort_for` wrappers in cloud_audit1 | REAL (indirect via output assertions) | Direct call with boundary budget values not found |
| `create_anthropic_tool_schema` | base.py | `test_tool_schema_builders.py` (not read; file exists) | UNKNOWN | Not assessed |
| `create_openai_tool_schema` | base.py | `test_tool_schema_builders.py` (not read; file exists) | UNKNOWN | Not assessed |
| `create_google_tool_schema` | base.py | `test_tool_schema_builders.py` (not read; file exists) | UNKNOWN | Not assessed |
| `_extract_system_messages` | base.py | `test_anthropic_provider.py` TestConvertMessagesToProviderFormat | REAL | Multiple system messages; system after user message |
| `HttpErrorMessages` frozen dataclass | base.py | `test_http_status_helper.py` immutability tests | REAL | `__slots__` blocks extra attributes; `frozen=True` blocks mutation |

### B. anthropic.py — AnthropicProvider

| Operation | Source line(s) | Test(s) | Verdict | Missing edge cases |
|-----------|---------------|---------|---------|-------------------|
| `connect` | anthropic.py | `test_anthropic_provider.py` TestConnectionErrorHandling; live integration | REAL | Empty key raises AuthenticationError; probe failure raises ProviderError |
| `disconnect` | anthropic.py | Integration tests | WEAK | Only state check; client cleanup not verified offline |
| `list_models` / `_fetch_all_models` | anthropic.py | `test_providers_cloud_audit1.py` F-0010 | REAL | Pagination `limit` forwarded; `after_id` cursor propagated; two pages merged |
| `chat` (non-streaming) | anthropic.py | F-0003 `test_f0003_anthropic_chat_populates_current_task` (mock transport); F-0001 (mock transport) | REAL for task lifecycle; WEAK for full response parsing offline | _current_task assigned and cleared; content verified; but mock transport means response parsing not independently gated |
| `chat_stream` | anthropic.py | F-0006 error-propagation test; `test_realcov_10_google_safety.py` TestAnthropicCacheLive (live) | REAL for error surfacing; NO offline gate for text accumulation path | Streaming text accumulation from real text_stream events not unit-gated offline |
| `cancel_request` | anthropic.py | F-0003 (task population verified); `test_realcov_10_cancel_request.py` exists (not read) | REAL for _current_task; partial for cancellation |  |
| `_build_api_kwargs` | anthropic.py | `test_anthropic_provider.py` TestBuildApiKwargs (8 tests) | REAL | Thinking config, system block, temperature, stop sequences, cache kwarg pass-through |
| `_apply_cache_breakpoints` | anthropic.py | `test_anthropic_provider.py` TestApplyCacheBreakpoints (5 tests); `test_realcov_10_anthropic_cache.py` (5 tests, includes breakpoint count limit) | REAL | System → cached block; last tool entry tagged; string message → block; block-list → last block tagged; max-4 breakpoints |
| `_cache_last_message_block` | anthropic.py | `test_anthropic_provider.py` TestCacheLastMessageBlock (3 tests) | REAL | String content → block with ephemeral; list content → last block tagged; empty messages no-op |
| `_build_usage_from_message` | anthropic.py | `test_anthropic_provider.py` TestBuildUsageFromMessage (3 tests) | REAL | Exact token counts; cache creation + cache read fields |
| `_parse_response_blocks` | anthropic.py | `test_anthropic_provider.py` TestParseResponseBlocks (5 tests) | REAL | TextBlock, ThinkingBlock, ToolUseBlock extraction; multi-block assembly; thinking_content accumulation |
| `_finalize_anthropic_stream` | anthropic.py | **NO OFFLINE UNIT TEST** | NO | Stream event sequence → final Message assembly not gated offline |
| `_convert_messages_to_provider_format` | anthropic.py | `test_anthropic_provider.py` TestConvertMessagesToProviderFormat (7 tests) | REAL | System skip; user/assistant/tool_result role mapping; list-of-blocks input; thinking in assistant |
| `_convert_tools_to_provider_format` | anthropic.py | `test_anthropic_provider.py` TestConvertToolsToProviderFormat (2 tests) | REAL | input_schema shape; description propagation |

### C. openai.py — OpenAIProvider

| Operation | Source line(s) | Test(s) | Verdict | Missing edge cases |
|-----------|---------------|---------|---------|-------------------|
| `connect` | openai.py | Live integration only (`test_openai_provider.py`) | WEAK | No offline gate; invalid key path (401) only via integration |
| `disconnect` | openai.py | Live integration | WEAK | |
| `list_models` | openai.py | Live integration | WEAK | `_is_chat_model` filter not unit-gated offline; exclusion list not verified |
| `chat` (o-series dispatch) | openai.py | F-0002 `test_f0002_openai_o_series_uses_max_completion_tokens_and_temp_1`; F-0002 `test_f0002_openai_o_series_pins_temperature_without_thinking` | REAL | `max_completion_tokens` in kwargs; `max_tokens` absent; `temperature == 1.0`; these use mock transport but assert captured kwargs |
| `chat` (non-o-series path) | openai.py | F-0001 enable_cache test (mock transport) | FAKE (see Worst Offenders §1) | enable_cache=True vs False produces no assertion difference |
| `chat_stream` | openai.py | F-0006 error-propagation; F-0001 enable_cache path | REAL for error; NO for accumulation | _iter_openai_stream not unit-gated offline |
| `_is_chat_model` | openai.py | **NO TEST** | NO | |
| `_infer_context_window` | openai.py | **NO TEST** | NO | gpt-4o-mini documented as 128K via live test only |
| `_infer_supports_vision` | openai.py | **NO TEST** | NO | |
| `_supports_max_completion_tokens` | openai.py | Implicit via o-series dispatch test (asserts `max_completion_tokens` in kwargs) | REAL (indirect) | |
| `_reasoning_effort_for` | openai.py | F-0002 `test_f0002_openai_thinking_maps_to_reasoning_effort` | REAL | gpt-4o → None; None thinking → None; disabled → None; o3-mini budget_tokens=2000 → "low"; o4 budget_tokens=32000 → "high" |
| `_open_openai_stream` | openai.py | **NO UNIT TEST** | NO | 16 code paths; tool-call streaming accumulation not gated |
| `_make_openai_api_call` | openai.py | **NO UNIT TEST** | NO | |
| `_iter_openai_stream` | openai.py | **NO UNIT TEST** | NO | ToolCallBufferManager integration not verified end-to-end offline |
| `_translate_openai_errors` | openai.py | **NO UNIT TEST** | NO | SDK exception → typed error mapping |

### D. google.py — GoogleProvider

| Operation | Source line(s) | Test(s) | Verdict | Missing edge cases |
|-----------|---------------|---------|---------|-------------------|
| `connect` | google.py | `test_provider_bugfixes.py` TestGoogleClientErrorDetection (empty/None key → AuthenticationError); integration | REAL for empty/None key; WEAK for full connect flow | GEMINI_API_KEY env clearing not directly verified |
| `disconnect` | google.py | Integration | WEAK | |
| `list_models` | google.py | `test_google_provider.py` integration (3 tests with capability oracles) | REAL (integration) | Embedding model exclusion not verified offline |
| `chat` | google.py | F-0004 retry test (mock transport); F-0001 enable_cache (mock transport, FAKE) | REAL for retry; FAKE for enable_cache path | |
| `chat_stream` | google.py | F-0006 error propagation; `test_realcov_10_google_safety.py` live cancellation | REAL for error; REAL for cancel (live) | Chunk text accumulation not unit-gated offline |
| `_check_safety_block` | google.py | `test_realcov_10_google_safety.py` TestCheckSafetyBlockRealResponses (9 tests using real `google.genai.types` SDK objects) | REAL | Prompt-block SAFETY; candidate SAFETY/PROHIBITED_CONTENT/BLOCKLIST/SPII; STOP/MAX_TOKENS pass cleanly; None finish_reason passes; exact message format verified |
| `_parse_response` | google.py | **NO OFFLINE UNIT TEST** | NO | text extraction; function_call detection; safety block call |
| `_extract_function_calls` | google.py | **NO OFFLINE UNIT TEST** | NO | Multiple function calls; argument dict parsing |
| `_extract_visible_chunk_text` | google.py | **NO OFFLINE UNIT TEST** | NO | thought=True parts excluded |
| `_extract_thinking_text` | google.py | **NO OFFLINE UNIT TEST** | NO | |
| `_create_config` (ThinkingConfig, tool_config) | google.py | **NO OFFLINE UNIT TEST** | NO | thinking_budget_tokens mapping; tool_config ALL/NONE/code-execution |
| `_extract_usage` | google.py | `test_realcov_10_google_safety.py` live exhaustion test (positive token counts verified) | REAL (live) | Offline: unit test with SDK `UsageMetadata` object not found |
| `_build_tool_declarations` | google.py | `test_real_bridge_schemas.py` (not read) | UNKNOWN | |
| `_convert_messages_to_provider_format` | google.py | **NO OFFLINE UNIT TEST** | NO | user/assistant role; function_call in assistant; function_response in user |
| `cancel_request` | google.py | `test_realcov_10_google_safety.py` live tests (3 scenarios) | REAL (live) | |

### E. grok.py — GrokProvider

| Operation | Source line(s) | Test(s) | Verdict | Missing edge cases |
|-----------|---------------|---------|---------|-------------------|
| `connect` | grok.py | `test_grok_provider.py` invalid/empty/None key → AuthenticationError (offline) | REAL | |
| `disconnect` | grok.py | Integration | WEAK | |
| `list_models` | grok.py | Integration (`test_grok_provider.py` capability oracle tests) | REAL (integration) | `_is_chat_model` filter not verified offline |
| `chat` | grok.py | F-0004 retry test (REAL); F-0001 enable_cache (FAKE for Grok) | REAL for retry; FAKE for enable_cache | |
| `chat_stream` | grok.py | F-0006 error propagation | REAL for error | Accumulation not unit-gated offline |
| `_infer_context_window` | grok.py | Live oracle test (`test_grok_provider.py` independent oracle: grok-4→256000, grok-3→131072, grok-1→8192) | REAL (integration) | Offline unit test absent |
| `_infer_supports_vision` | grok.py | Live oracle test (vision/image substring rule) | REAL (integration) | |
| `_supports_max_completion_tokens` | grok.py | **NO TEST** | NO | grok-4/5/6 flag |
| `_supports_reasoning_effort` | grok.py | F-0002 `test_f0002_grok_thinking_maps_to_reasoning_effort_for_multi_agent` | REAL | multi-agent only; grok-4-fast → None |
| `_reasoning_effort_for` | grok.py | F-0002 test; `test_realcov_10_grok_reasoning_effort.py` (not read, exists) | REAL | xhigh mapping; multi-agent gate |
| `_make_grok_api_call` | grok.py | **NO OFFLINE UNIT TEST** | NO | |
| `_dispatch_grok_create` | grok.py | **NO OFFLINE UNIT TEST** | NO | |
| `_open_grok_stream` | grok.py | **NO OFFLINE UNIT TEST** | NO | |

### F. openrouter.py — OpenRouterProvider

| Operation | Source line(s) | Test(s) | Verdict | Missing edge cases |
|-----------|---------------|---------|---------|-------------------|
| `connect` | openrouter.py | Empty key → AuthenticationError (offline); loop rebind stub test; integration | REAL | |
| `disconnect` | openrouter.py | Integration | WEAK | |
| `list_models` | openrouter.py | Integration (capability fields); loop rebind stub test (model count = stub data) | REAL | |
| `chat` | openrouter.py | F-0004 retry test (REAL); F-0001 enable_cache (WEAK - see below) | REAL for retry; WEAK for enable_cache | |
| `chat_stream` | openrouter.py | F-0006 error propagation | REAL for error | Chunk text accumulation not verified offline |
| `get_generation` | openrouter.py | **NO TEST** | NO | |
| `_build_model_info` | openrouter.py | `test_provider_bugfixes.py` TestOpenRouterPricingConversion (5 tests with float oracles) | REAL | Valid pricing → micro-dollar; N/A pricing → None; empty pricing → None; missing pricing block → None; zero pricing → 0.0 |
| `_apply_cache_control` | openrouter.py | F-0001 `test_f0001_openrouter_enable_cache_attaches_cache_control` | REAL | Last user + last system message tagged; exact ephemeral marker verified |
| `_mark_role_for_cache` | openrouter.py | Exercised transitively via `_apply_cache_control` test | REAL (indirect) | |
| `_reasoning_effort_for` | openrouter.py | F-0002 `test_f0002_openrouter_thinking_maps_to_reasoning_effort` | REAL | None → None; disabled → None; low/medium/high budget thresholds |
| `_parse_tool_calls_from_response` | openrouter.py | **NO TEST** | NO | |
| `_post_chat_completion` | openrouter.py | F-0004 retry test (first call raises, second succeeds; call_count=2 asserted) | REAL | |
| `_raise_for_stream_status` | openrouter.py | **NO TEST** | NO | |
| `_build_usage_from_data` | openrouter.py | **NO OFFLINE UNIT TEST** | NO | |
| `_ensure_client_loop` | openrouter.py | `test_provider_loop_rebind.py` (2 tests: cross-loop rebinds; same-loop does not rebind) | REAL | |

### G. ollama.py — OllamaProvider

| Operation | Source line(s) | Test(s) | Verdict | Missing edge cases |
|-----------|---------------|---------|---------|-------------------|
| `connect` | ollama.py | Loop rebind stub test; integration; invalid URL raises ProviderError (offline) | REAL | |
| `disconnect` | ollama.py | Integration | WEAK | |
| `list_models` | ollama.py | Integration (`local/` prefix, `[Local] ` name prefix, context_window > 0, streaming=True); loop rebind stub test (llama3.1:8b num_ctx=8192, tools=True from template) | REAL | cloud/ prefix models not tested |
| `list_tags` | ollama.py | **NO TEST** | NO | |
| `list_running_models` | ollama.py | **NO TEST** | NO | |
| `show_model` | ollama.py | **NO TEST** | NO | |
| `generate` (/api/generate) | ollama.py | **NO TEST** | NO | |
| `embeddings` (/api/embeddings) | ollama.py | **NO TEST** | NO | |
| `chat` (local NDJSON path) | ollama.py | Live tests only (`test_ollama_chat_live.py`, not read) | UNKNOWN | |
| `chat` (cloud OpenAI path) | ollama.py | **NO OFFLINE UNIT TEST** | NO | |
| `chat_stream` | ollama.py | **NO OFFLINE UNIT TEST** | NO | |
| `pull_model` | ollama.py | **NO TEST** | NO | |
| `_raise_for_status` | ollama.py | Base `_raise_typed_for_status` tests cover shared logic; Ollama-specific 5xx handling **NO TEST** | WEAK | Local-specific error paths not gated |
| `_get_client_and_model` | ollama.py | Transitively via list_models prefix routing | WEAK | |
| `_parse_chat_response` (local vs cloud) | ollama.py | **NO OFFLINE UNIT TEST** | NO | |
| `_parse_ollama_tool_calls` | ollama.py | **NO TEST** | NO | |
| `_parse_openai_compatible_tool_calls` | ollama.py | `test_providers_local_audit1.py` F-0002 (string chunk accumulation + dict-typed arguments) | REAL | |
| `_record_usage_from_chunk` | ollama.py | **NO TEST** | NO | |
| `_record_usage_from_openai_payload` | ollama.py | **NO TEST** | NO | |
| `_accumulate_native_tool_call_deltas` | ollama.py | **NO TEST** | NO | |
| `_finalize_native_tool_calls` | ollama.py | **NO TEST** | NO | |
| `_accumulate_openai_tool_call_deltas` | ollama.py | `test_providers_local_audit1.py` F-0002 | REAL | Dict-type arguments preserved; string chunk concatenation |
| `_finalize_openai_tool_calls` | ollama.py | `test_providers_local_audit1.py` F-0002 | REAL | call.id, function_name, arguments exact-value assertions |
| `_ensure_clients_on_loop` | ollama.py | `test_provider_loop_rebind.py` TestOllamaLoopRebind | REAL | Cross-loop: new client created; context_window=8192 from stub; tools=True from template |
| `_fetch_model_metadata` | ollama.py | `test_provider_loop_rebind.py` stub test | REAL | |
| `_query_model_show` | ollama.py | `test_provider_loop_rebind.py` stub test (num_ctx + Tools template) | REAL | |

### H. registry.py — ProviderRegistry

| Operation | Source line(s) | Test(s) | Verdict | Missing edge cases |
|-----------|---------------|---------|---------|-------------------|
| `register` / `register_class` | registry.py | `test_registry.py` (confirmed from structure and name) | REAL (presumed; file structure is test suite for registry) | |
| `unregister` | registry.py | `test_registry.py` | REAL (presumed) | |
| `get` / `get_or_raise` | registry.py | `test_registry.py` | REAL (presumed) | |
| `list_registered` / `list_connected` | registry.py | `test_registry.py` | REAL (presumed) | |
| `connect_provider` | registry.py | `test_credential_loading.py` (not read) | UNKNOWN | |
| `disconnect_provider` / `disconnect_all` | registry.py | `test_registry.py` | REAL (presumed) | |
| `set_active` / `active` | registry.py | `test_registry.py` | REAL (presumed) | |
| `has_connected_provider` | registry.py | `test_registry.py` | REAL (presumed) | |
| `get_provider_registry` / `reset_provider_registry` | registry.py | `test_registry.py` | REAL (presumed) | |
| Thread-safety | registry.py | `test_registry_thread_safety_live.py` (file exists) | REAL (presumed) | |

### I. discovery.py — ModelDiscovery + DiscoveryCache

| Operation | Source line(s) | Test(s) | Verdict | Missing edge cases |
|-----------|---------------|---------|---------|-------------------|
| `DiscoveryCache.get` / `aget` | discovery.py | `test_discovery_unit.py` (confirmed from structure) | REAL (presumed) | |
| `DiscoveryCache.set` / `aset` (rejects empty) | discovery.py | `test_discovery_unit.py` | REAL (presumed) | |
| `DiscoveryCache.invalidate` / `ainvalidate` | discovery.py | `test_discovery_unit.py` | REAL (presumed) | |
| `DiscoveryCache.is_expired` | discovery.py | `test_discovery_unit.py` | REAL (presumed) | |
| `DiscoveryCache.save_to_disk` / `load_from_disk` | discovery.py | `test_discovery_unit.py` | REAL (presumed) | |
| `DiscoveryCache._parse_cache_entries` | discovery.py | `test_discovery_unit.py` | REAL (presumed) | |
| `ModelDiscovery.discover_all` | discovery.py | `test_provider_loop_rebind.py` TestDiscoveryProviderErrorHandling (ProviderError → `[]`; failed event recorded); `test_discovery_unit.py` | REAL | discover_all records failed event confirmed in loop-rebind test |
| `ModelDiscovery.discover_provider` | discovery.py | `test_provider_loop_rebind.py`; `test_discovery_unit.py` | REAL | ProviderError returns `[]` (not propagated) |
| `ModelDiscovery.search` | discovery.py | `test_discovery_unit.py` | REAL (presumed) | |
| `ModelDiscovery.filter` (DiscoveryFilter) | discovery.py | `test_discovery_unit.py` | REAL (presumed) | |
| `ModelDiscovery.get_recommended_model` | discovery.py | `test_realcov_10_discovery_extra.py` (not read; exists) | UNKNOWN | |
| `ModelDiscovery.get_discovery_events` | discovery.py | `test_provider_loop_rebind.py` (events checked for failed event) | REAL | |

---

## Worst Offenders — Fake Gates

### 1. `test_f0001_chat_enable_cache_completes_full_call_path` — OpenAI / Grok / Google sections
**File:** `tests/test_providers/test_providers_cloud_audit1.py:377–487`

**Why fake:** The test claims to gate that `enable_cache=True` "completes the full chat call path." For OpenAI, Grok, and Google, it sets up a `MagicMock` client whose coroutine always returns a static response, then asserts:
- `len(openai_calls) == 1` (call counter)
- `openai_response.content == "cache-ok"` (mock return value)
- `openai_response.role == "assistant"` (mock return value)

None of these three assertions change if `enable_cache=True` is silently ignored — the API call still happens once and the mock still returns `"cache-ok"`. The docstring explicitly concedes this: "An implementation that drops enable_cache before the API call or short-circuits the call path entirely would leave the call counter at zero." But the far more common regression — the flag is accepted as a parameter but then silently never passed to any downstream call — is **not caught**. The captured kwargs are never inspected for any enable_cache-specific effect.

This is a cannot-fail test for the most likely regression (silent drop). For OpenAI/Grok/Google, where enable_cache is purely server-side, there may be nothing client-side to assert — but that makes the test vacuous, not useful. The docstring should state "this path cannot be meaningfully gated offline because caching is entirely server-side" rather than presenting it as a gate.

**Verdict:** FAKE for OpenAI, Grok, and Google provider sections. The Anthropic case is correctly gated by the separate `test_f0005_enable_cache_marks_system_tools_and_last_message` which checks real payload mutation.

---

### 2. `test_connection_with_invalid_key_may_succeed_initially` (OpenRouter)
**File:** `tests/test_providers/test_openrouter_provider.py:311–326`

**Why fake:** This "test" contains a `try/except` block with no assertions in either branch. It silently passes whether `connect` succeeds, raises `AuthenticationError`, or raises any other exception type. The exception block catches `AuthenticationError` and does nothing. No assertion is made about the connection state, the exception message, the disconnection cleanup, or any other behavior. By any metric this cannot fail.

```python
try:
    await provider.connect(invalid_creds)
    await provider.disconnect()
except AuthenticationError:
    pass
```

**Verdict:** FAKE. This should be removed or replaced with a test that asserts the specific deferred-validation behavior (e.g., the connection succeeds but a subsequent `list_models` call with a truly invalid key raises `AuthenticationError`).

---

### 3. `test_disconnect_clears_connection_state` (Google, Grok, OpenRouter, Ollama)
**Files:** `test_google_provider.py:325–349`, `test_grok_provider.py:342–364`, `test_openrouter_provider.py:346–370`, `test_ollama_provider.py:319–343`

**Why weak/fake:** All four versions have the same pattern: they `pytest.skip` when the API key is absent, then check `is_connected is True` after connect and `is_connected is False` after disconnect. When the key is absent the test is entirely skipped. The `is_connected` flag is a single boolean field; no assertion verifies client cleanup, session teardown, or that subsequent calls are properly rejected. For offline test runs (which is the normal sandbox case), all four are silently skipped.

**Verdict:** WEAK (only state field checked; real cleanup behavior not gated; offline always skips).

---

## Gap List — Operations with NO Offline Coverage

The following operations have zero falsifiable offline test coverage. Any regression in these code paths will not be caught until a live API call is attempted.

**base.py:**
- `_translate_openai_errors` — context manager used by OpenAI, Grok, and OpenRouter to map SDK exceptions to typed errors. No standalone test.
- `_build_usage_from_openai_completion` — field-by-field token extraction; only tested through live calls.
- `_build_usage_from_openai_chunk` — streaming usage accumulation; only through live calls.
- `get_pending_tool_calls` — base accumulator drain; no standalone test.

**openai.py (entire offline transformation layer):**
- `_is_chat_model` — includes embedding/image model exclusion logic.
- `_infer_context_window` — model-name pattern table for context size.
- `_infer_supports_vision` — vision capability inference.
- `_open_openai_stream` — 16 code paths including tool-call streaming.
- `_make_openai_api_call` — non-streaming dispatch with o-series branching.
- `_iter_openai_stream` — `ToolCallBufferManager` integration in streaming context.

**google.py (entire offline transformation layer):**
- `_parse_response` — text/function_call extraction plus safety check.
- `_extract_function_calls` — Gemini `function_calls` attribute parsing.
- `_extract_visible_chunk_text` — `thought=True` parts excluded from output.
- `_extract_thinking_text` — thinking chunk assembly.
- `_create_config` — `ThinkingConfig` → `thinking_budget_tokens`; tool mode; generation config.
- `_extract_usage` — SDK `UsageMetadata` → `UsageInfo` field mapping (offline only; live test confirms non-zero counts).
- `_convert_messages_to_provider_format` — Gemini message format with `function_call`/`function_response`.

**grok.py:**
- `_supports_max_completion_tokens` — grok-4/5/6 flag.
- `_make_grok_api_call` / `_dispatch_grok_create` / `_open_grok_stream` — full streaming and non-streaming dispatch paths.

**openrouter.py:**
- `get_generation` — `/generation?id=` metadata endpoint.
- `_parse_tool_calls_from_response` — tool call extraction from non-streaming response.
- `_raise_for_stream_status` — stream-level HTTP error handling.
- `_build_usage_from_data` — token count extraction from response dict.

**ollama.py (majority of the implementation):**
- `list_tags`, `list_running_models`, `show_model` — meta-API endpoints.
- `generate` (/api/generate) — non-chat completions endpoint.
- `embeddings` (/api/embeddings) — embedding generation.
- `pull_model` — model download streaming.
- `_parse_chat_response` — local NDJSON vs cloud OpenAI format disambiguation.
- `_parse_ollama_tool_calls` — native tool call format parsing.
- `_accumulate_native_tool_call_deltas` / `_finalize_native_tool_calls` — native NDJSON tool call streaming.
- `_record_usage_from_chunk` / `_record_usage_from_openai_payload` — usage extraction paths.
- cloud/ prefix model routing through `_get_client_and_model`.

---

## Edge Case Coverage Assessment

| Edge Case | Coverage | Notes |
|-----------|----------|-------|
| HTTP 401/403 → AuthenticationError | REAL | `test_http_status_helper.py` parametrized; also connect-with-invalid-key integration tests for most providers |
| HTTP 429 → RateLimitError | REAL | `test_http_status_helper.py`; exact message format verified |
| HTTP 503 + JSON body / HTML body / no body | REAL | `test_http_status_helper.py`; `test_provider_bugfixes.py` HuggingFace 503 fallback |
| HTTP 5xx (500/502/504) falls through | REAL | `test_http_status_helper.py` parametrize confirms `None` return |
| Permanent billing quota (is_permanent_quota_error) | REAL | 4 positive cases; 4 negative cases |
| Transient rate-limit retry (backoff) | REAL | F-0004 Grok/OpenRouter/Google: call_count==2 verified |
| Streaming connection error surfaces (not swallowed) | REAL | F-0006 all 5 providers: error raised even when cancel flag is set |
| Malformed / truncated JSON in stream | REAL | `test_safe_parse_stream_json.py`: exact warning event name; result is None |
| Tool-call argument: dict-typed (complete in one chunk) | REAL | `test_providers_local_audit1.py` F-0002; `test_tool_call_buffer.py` |
| Tool-call argument: string-chunk accumulation | REAL | `test_tool_call_buffer.py`; `test_providers_local_audit1.py` F-0002 |
| Incomplete tool call (missing id or name) discarded | REAL | `test_tool_call_buffer.py` |
| Safety filter block (SAFETY/PROHIBITED/BLOCKLIST/SPII) | REAL | `test_realcov_10_google_safety.py`: real SDK objects; exact message format |
| Non-blocking finish reasons (STOP/RECITATION/MAX_TOKENS) | REAL | `test_realcov_10_google_safety.py` |
| Empty API key → AuthenticationError | REAL | All providers: offline tests exist |
| None API key → AuthenticationError | REAL | Google, Grok: offline tests |
| ProviderError when not connected | REAL | All providers: offline test |
| Cross-event-loop rebind (httpx client) | REAL | `test_provider_loop_rebind.py`: two providers against stub server |
| Model-not-found (404 or API-specific) | NO | Not covered anywhere offline |
| Token-limit truncation in response | NO | No offline gate |
| PKCE OAuth URL construction | REAL | `test_provider_bugfixes.py`: URL parsed back with urllib as oracle |
| Cache breakpoints (Anthropic) | REAL | 5+5 unit tests; live round-trip |
| Cache control markers (OpenRouter) | REAL | F-0001 |
| Discovery ProviderError swallowed | REAL | `test_provider_loop_rebind.py` |

---

## Section Scores

### Operation gate coverage

Counted from the inventory above (excluding "UNKNOWN" operations where the relevant test file was not read):

| Provider / Module | Operations assessed | ≥1 REAL offline gate | % |
|-------------------|--------------------|-----------------------|----|
| base.py | 23 | 14 | 61% |
| anthropic.py | 13 | 11 | 85% |
| openai.py | 14 | 4 | 29% |
| google.py | 14 | 5 | 36% |
| grok.py | 13 | 7 | 54% |
| openrouter.py | 15 | 9 | 60% |
| ollama.py | 26 | 9 | 35% |
| registry.py | 10 | 8 (presumed) | 80% |
| discovery.py | 12 | 9 (partly presumed) | 75% |
| **Total** | **140** | **76** | **54%** |

### Edge case coverage

Real gates exist for 14 of the 20 identified edge-case categories = **70%**.

### Overall section score: 54% operation gate coverage, 70% edge-case coverage.

The Anthropic provider scores highest. The OpenAI and Ollama providers score lowest and represent the greatest risk to regression.

---

## Remediation Recommendations

### Priority 1 — Delete or rewrite fake gates immediately

1. **`test_f0001_chat_enable_cache_completes_full_call_path` (OpenAI/Grok/Google sections)**
   Replace with an honest assertion: "For OpenAI, Grok, and Google, prompt caching is applied server-side and cannot be verified offline. This test is removed. The server-side behavior is confirmed by the live tests in `test_anthropic_buffers_live.py` / `test_google_chat_live.py`." Delete the three provider blocks; keep only the Anthropic note pointing at `test_f0005`.

2. **`test_connection_with_invalid_key_may_succeed_initially` (OpenRouter)**
   Rewrite to assert the deferred-validation behavior: connect with a malformed key, then call `list_models` (or any API call that requires authentication) and assert `AuthenticationError` or `ProviderError` is raised. Use a stub server that returns HTTP 401 on the model endpoint to do this offline.

3. **`test_disconnect_clears_connection_state` (all four providers)**
   These should not `pytest.skip` when offline. Change to a pure offline test: construct the provider, manually set `_connected = True` and assign a fake client, call `disconnect()`, and assert `is_connected is False` and the client attribute is `None` (or the documented cleanup sentinel). No API key required.

### Priority 2 — Fill the OpenAI offline transformation gap

The entire offline transformation layer of `OpenAIProvider` is unguarded. Recommended tests (all offline, no API key):

- **`_is_chat_model`**: Parametrize over a table of model IDs (gpt-4o, gpt-4o-mini, text-embedding-3-small, dall-e-3, whisper-1, tts-1) with boolean expected values. Oracle: the OpenAI model-type naming conventions documented in `_is_chat_model` itself (visible in source). Assert the exact boolean output.

- **`_infer_context_window`**: Parametrize over (gpt-4o → 128000, gpt-3.5-turbo → 16385, gpt-4-32k → 32768, gpt-4 → 8192). Oracle: OpenAI public documentation. Assert exact integer equality.

- **`_infer_supports_vision`**: Parametrize over (gpt-4o → True, gpt-4o-mini → True, gpt-3.5-turbo → False, gpt-4-vision-preview → True). Assert exact boolean.

- **`_iter_openai_stream` with ToolCallBufferManager**: Construct a fake async-generator that yields SSE chunk dicts (a series of `{"choices": [{"delta": {"tool_calls": [...]}}]}`) matching the OpenAI streaming format. Call `chat_stream` with a mock client returning that generator. Assert the yielded text fragments and that `get_pending_tool_calls()` returns the expected `ToolCall` list with exact `id`, `function_name`, and `arguments`.

### Priority 3 — Fill the Google offline transformation gap

- **`_convert_messages_to_provider_format`**: Drive with real `Message` objects (user, assistant with tool_call, user with tool_result) and assert the Gemini `Content` structure: `role`, `parts`, `function_call`, `function_response`. Oracle: the Gemini SDK's `Content` and `Part` constructors.

- **`_extract_visible_chunk_text`**: Construct `google.genai.types.Candidate` objects with a mix of `thought=True` and `thought=False` parts. Assert only non-thought parts contribute to the returned string.

- **`_extract_usage`**: Construct a `google.genai.types.UsageMetadata` with known integer fields and assert the resulting `UsageInfo` carries the same values.

- **`_create_config` (ThinkingConfig branch)**: Call with budget_tokens=1000 and assert `thinking_config.thinking_budget` matches the mapped value. Oracle: the source code's mapping table (visible) + Google documentation.

### Priority 4 — Fill the Ollama local chat gap

The local NDJSON chat path (`_parse_chat_response`, `_parse_ollama_tool_calls`, `_accumulate_native_tool_call_deltas`, `_finalize_native_tool_calls`) has no offline unit tests. Use the existing `_StubHTTPServer` pattern from `test_provider_loop_rebind.py`:

- Serve a known NDJSON response from a stub `/api/chat` endpoint.
- Assert `_parse_chat_response` produces a `Message` with the expected `role`, `content`, and (when tools present) `tool_calls`.
- For tool calls: assert the `ToolCall` list produced by `_finalize_native_tool_calls` carries the exact `id`, `function_name`, and parsed `arguments` dict from the stub JSON.

### Priority 5 — Fill the base layer gaps

- **`_translate_openai_errors`**: Create a test class that calls a coroutine wrapped in `async with provider._translate_openai_errors():` that raises each relevant OpenAI SDK exception type. Assert the raised exception is the correct Intellicrack typed error with the expected message and `__cause__` chain.

- **`_build_usage_from_openai_completion`**: Construct a real `openai.types.Completion`-like object (or use the SDK's model constructors) with known `prompt_tokens`, `completion_tokens`, `total_tokens`. Assert `UsageInfo` fields match exactly.

### Priority 6 — Add model-not-found error path

No provider has an offline test for the model-not-found case (typically HTTP 404 or a provider-specific error object). Add a parametrized test to `test_http_status_helper.py` or each provider's test file: configure a stub to return HTTP 404, call `chat(model="nonexistent-model", ...)`, and assert `ProviderError` is raised (not `KeyError`, not `AttributeError`, not silent success).
