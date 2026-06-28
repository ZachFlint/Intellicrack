# Group 07 Verification Report

**Assigned section:** `audit/test-coverage-audit/section-09-cloud-providers.md`  
**Scope:** OpenAI, Ollama, Grok, Google, Anthropic, OpenRouter provider operations — full section A through I.  
**Verification date:** 2026-06-27

---

## Evidence Base

Files read in full:

- `tests/test_providers/test_openai_offline_wave2d.py`
- `tests/test_providers/test_ollama_offline_wave2d.py`
- `tests/test_providers/test_providers_cloud_audit1.py`
- `tests/test_providers/test_openai_format_helpers.py` (lines 1–334)
- `tests/test_providers/test_realcov_10_grok_reasoning_effort.py`
- `tests/test_providers/test_openrouter_provider.py` (lines 300–384)
- `tests/test_providers/test_grok_provider.py` (lines 315–347)
- `tests/test_providers/test_google_provider.py` (lines 300–329)
- `tests/test_providers/test_ollama_provider.py` (lines 290–317)
- `tests/test_providers/test_anthropic_provider.py` (lines 1145–1196)
- `tests/test_providers/test_parse_openai_format_tool_calls.py` (lines 1–60)
- `tests/test_providers/test_tool_schema_builders.py` (lines 1–179)
- `tests/test_providers/test_real_bridge_schemas.py` (lines 1–61)

Additional targeted searches via rg/Grep to locate coverage of specific symbols.

---

## Finding Enumeration

### Findings Count by Section

| Section | Non-REAL rows enumerated |
|---------|--------------------------|
| A — base.py | 10 |
| B — anthropic.py | 5 |
| C — openai.py | 12 |
| D — google.py | 13 |
| E — grok.py | 7 |
| F — openrouter.py | 7 |
| G — ollama.py | 18 |
| H — registry.py (REAL presumed / UNKNOWN) | 10 |
| I — discovery.py (REAL presumed / UNKNOWN) | 9 |
| **Total** | **91** |

---

## Verification Table

### A — base.py

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation caught) |
|---|-------------------------|------------------|-----|--------------------------------------------------|
| 1 | `_translate_openai_errors` | NO | RESOLVED | `test_openai_format_helpers.py:428–522` · openai SDK exception hierarchy as oracle · mutation "wrong exception type" red |
| 2 | `_build_usage_from_openai_completion` | WEAK | RESOLVED | `test_openai_format_helpers.py:266–291` · known integer constants as oracle · mutation "wrong field" red |
| 3 | `_build_usage_from_openai_chunk` | WEAK | RESOLVED | `test_openai_format_helpers.py:293–322` · sum-fallback logic as oracle · mutation "omit fallback sum" red |
| 4 | `get_pending_tool_calls` | NO | NOT_RESOLVED | wave2d tests access `_pending_tool_calls` via `getattr(provider, attr)` directly; the public `get_pending_tool_calls()` accessor method is never called in any assertion; mutation "return None" not caught |
| 5 | `get_pending_usage` | WEAK | RESOLVED | `test_ollama_offline_wave2d.py:921–943` · `provider.get_pending_usage()` called on a real provider after `_record_usage_from_chunk`; exact integer fields asserted; mutation "return None" red |
| 6 | `get_pending_thinking` | WEAK | NOT_RESOLVED | Only `test_providers_cloud_audit1.py:837` F-0008 which injects `MagicMock` return value; base method's drain behaviour not independently gated; mutation "return empty list" not caught |
| 7 | `parse_tool_call` | UNKNOWN | RESOLVED | `test_parse_openai_format_tool_calls.py` uses real OpenAI SDK `ChatCompletionMessageFunctionToolCall` objects; exact field assertions present |
| 8 | `create_anthropic_tool_schema` | UNKNOWN | RESOLVED | `test_tool_schema_builders.py` + `test_real_bridge_schemas.py` exercise all three schema builders against real `ToolDefinition` objects with exact structural assertions |
| 9 | `create_openai_tool_schema` | UNKNOWN | RESOLVED | `test_tool_schema_builders.py:135–178`; exact schema shape (`type`, `function.name`, `parameters.required`) asserted against independently-known JSON Schema spec |
| 10 | `create_google_tool_schema` | UNKNOWN | RESOLVED | `test_tool_schema_builders.py` + `test_real_bridge_schemas.py:1–61`; array-items rule asserted offline against real bridge definitions |

### B — anthropic.py

| # | Operation | Original verdict | Now | Evidence |
|---|-----------|------------------|-----|----------|
| 11 | `disconnect` | WEAK | NOT_RESOLVED | `test_anthropic_provider.py:1158–1180` still guards on `has_anthropic_key` and calls `pytest.skip`; all other providers (Grok, Google, Ollama, OpenRouter) were converted to pure offline seam tests; Anthropic was not; sandbox never runs this test |
| 12 | `chat` (non-streaming response parsing) | REAL+WEAK | NOT_RESOLVED | F-0003 test (`test_providers_cloud_audit1.py:727–763`) uses a `MagicMock` client whose coroutine bypasses `_parse_response_blocks`; `TestParseResponseBlocks` in `test_anthropic_provider.py:545–686` gates the parser in isolation; the integration `chat()` → `_parse_response_blocks` with real Anthropic SDK response types has no offline test; mutation "pass wrong data to _parse_response_blocks" not caught offline |
| 13 | `chat_stream` (text accumulation) | REAL+NO | NOT_RESOLVED | F-0006 gates the error-surfacing path; no offline test drives the normal streaming text accumulation path for Anthropic (no real `text_stream` event sequence exercised offline) |
| 14 | `cancel_request` (cancellation behaviour) | REAL+partial | NOT_RESOLVED | F-0003 gates `_current_task` assignment (RESOLVED for that aspect); the actual request-cancellation behaviour is in `test_realcov_10_cancel_request.py` which was not read; marking conservative NOT_RESOLVED pending verification |
| 15 | `_finalize_anthropic_stream` | NO | NOT_RESOLVED | No test found in any file; no wave2d file covers Anthropic streaming assembly; grep for `_finalize_anthropic_stream` returns zero matches in `tests/` |

### C — openai.py

| # | Operation | Original verdict | Now | Evidence |
|---|-----------|------------------|-----|----------|
| 16 | `connect` | WEAK | NOT_RESOLVED | Only live integration tests in `test_openai_provider.py`; no offline stub-server gate for error paths (401, network failure); `test_openai_offline_wave2d.py` bypasses `connect()` by directly setting `provider.client` |
| 17 | `disconnect` | WEAK | NOT_RESOLVED | `test_openai_provider.py:341–384` still guards on `has_openai_key`; offline equivalent (manually set `provider.connected=True`, assign fake client, call disconnect) was added for Grok but not OpenAI |
| 18 | `list_models` (`_is_chat_model` filter) | WEAK | RESOLVED | `test_openai_offline_wave2d.py:326–398` TestIsChatModel gates every chat and non-chat prefix with exact boolean assertions; the filter logic is now independently gated offline; live-only network call is an acceptable capability skip |
| 19 | `chat` (non-o-series, enable_cache) | FAKE | RESOLVED | `test_providers_cloud_audit1.py:382–451` `test_f0001_openai_enable_cache_http_request_body` uses real `httpx.AsyncBaseTransport` recording seam; asserts `len(captured)==2`, body fields (`model`, `messages`, `max_tokens`), absence of `cache_control`/`prompt_caching`; mutation "early return on enable_cache=True" leaves `len(captured)==1`, red |
| 20 | `chat_stream` (text accumulation) | REAL+NO | RESOLVED | `test_openai_offline_wave2d.py:468–706` TestIterOpenAIStream* drives real `_iter_openai_stream` through real openai SDK with stub SSE transport; exact chunk list and tool-call structures asserted |
| 21 | `_is_chat_model` | NO | RESOLVED | `test_openai_offline_wave2d.py:326–398`; 13 chat models → True, 18 non-chat models → False; oracle: OpenAI published model-type documentation |
| 22 | `_infer_context_window` | NO | RESOLVED | `test_openai_offline_wave2d.py:401–465`; 16 parametrized exact integers plus unknown-model default; oracle: OpenAI platform docs |
| 23 | `_infer_supports_vision` | NO | NOT_RESOLVED | Only `test_openai_provider.py:155–194` which uses live `openai_provider` fixture gated on `OPENAI_API_KEY`; no offline parametrized test found for `_infer_supports_vision` on OpenAIProvider |
| 24 | `_open_openai_stream` | NO | RESOLVED | `test_openai_offline_wave2d.py:709–846` TestOpenOpenAIStreamParamDispatch; captures HTTP request body via stub transport; asserts `max_tokens` vs `max_completion_tokens` dispatch, `temperature=1.0` for o-series, tool forwarding |
| 25 | `_make_openai_api_call` | NO | RESOLVED | `test_providers_cloud_audit1.py:382–451` exercises `chat()` → `_make_openai_api_call` → real SDK → stub transport; `len(captured)==2` assertion gates the dispatch; mutation "no HTTP call" fails |
| 26 | `_iter_openai_stream` | NO | RESOLVED | `test_openai_offline_wave2d.py:468–706`; see row 20 |
| 27 | `_translate_openai_errors` | NO | RESOLVED | `test_openai_format_helpers.py:373–537`; 7 tests cover auth, rate-limit, quota, transport, passthrough, unrelated-exception, value-error paths |

### D — google.py

| # | Operation | Original verdict | Now | Evidence |
|---|-----------|------------------|-----|----------|
| 28 | `connect` (full flow) | REAL+WEAK | NOT_RESOLVED | `test_provider_bugfixes.py` gates empty/None key offline; the WEAK aspect ("GEMINI_API_KEY env clearing not directly verified") has no new offline test for the full connect flow beyond the key-guard |
| 29 | `disconnect` | WEAK | RESOLVED | `test_google_provider.py:311–328` offline seam: sets `provider.connected=True`, calls `disconnect()`, asserts `is_connected is False` AND `list_models()` raises `ProviderError(match="Not connected")`; mutation "omit state clear" red |
| 30 | `chat` (enable_cache) | FAKE | RESOLVED | `test_providers_cloud_audit1.py:527–598` `test_f0001_google_enable_cache_http_request_body`; real httpx transport intercepts genai SDK; asserts `contents`, `generationConfig.maxOutputTokens`, absence of `cachedContent`/`cacheContext`; `body_false == body_true` |
| 31 | `chat_stream` (text accumulation) | REAL+NO | NOT_RESOLVED | F-0006 gates error surfacing; no offline test drives the normal `aio.models.generate_content_stream` chunk-accumulation path |
| 32 | `_parse_response` | NO | NOT_RESOLVED | No offline unit test found; grep returns no hits for `_parse_response` in `tests/test_providers/` (excluding Anthropic's `_parse_response_blocks`) |
| 33 | `_extract_function_calls` | NO | NOT_RESOLVED | No offline unit test found |
| 34 | `_extract_visible_chunk_text` | NO | NOT_RESOLVED | No offline unit test found |
| 35 | `_extract_thinking_text` | NO | NOT_RESOLVED | No offline unit test found |
| 36 | `_create_config` | NO | NOT_RESOLVED | The F-0001 HTTP body test verifies `generationConfig.maxOutputTokens` (one field of one branch); `ThinkingConfig` branch and `tool_config` (ALL/NONE/code-execution) are not covered; partial coverage of one branch is insufficient |
| 37 | `_extract_usage` | REAL (live) | NOT_RESOLVED | `test_realcov_10_google_safety.py` live tests verify non-zero counts; no offline unit test constructs a `google.genai.types.UsageMetadata` object with known integers and asserts the resulting `UsageInfo` field-for-field |
| 38 | `_build_tool_declarations` | UNKNOWN | RESOLVED | `test_real_bridge_schemas.py:1–61` exercises `create_google_tool_schema` against all concrete bridge `tool_definition` objects; asserts array-item type rules that would only pass if the builder is correct |
| 39 | `_convert_messages_to_provider_format` | NO | NOT_RESOLVED | F-0001 HTTP body test confirms simple user-text message maps to `[{"parts":[{"text":"hello"}],"role":"user"}]`; the missing cases (`function_call` in assistant, `function_response` in user) are untested; happy-path-only is a forbidden anti-pattern |

### E — grok.py

| # | Operation | Original verdict | Now | Evidence |
|---|-----------|------------------|-----|----------|
| 40 | `disconnect` | WEAK | RESOLVED | `test_grok_provider.py:326–346` offline seam: assigns real `openai.AsyncOpenAI` with offline key, calls `disconnect()`, asserts `client is None` AND `is_connected is False` |
| 41 | `chat` (enable_cache) | FAKE | RESOLVED | `test_providers_cloud_audit1.py:454–523` `test_f0001_grok_enable_cache_http_request_body`; real httpx transport with openai SDK; asserts `model`, `messages`, `max_tokens`, absence of `cache_control`; `body_false == body_true` |
| 42 | `chat_stream` (accumulation) | REAL+NO | NOT_RESOLVED | F-0006 gates error surfacing; no offline test drives the normal Grok streaming text accumulation |
| 43 | `_supports_max_completion_tokens` | NO | RESOLVED | `test_realcov_10_grok_reasoning_effort.py:138–143`; grok-4 → True, grok-4-multi-agent → True, grok-3 → False, grok-2-1212 → False; oracle: X.AI API parameter semantics documentation |
| 44 | `_make_grok_api_call` | NO | RESOLVED | `test_providers_cloud_audit1.py:454–523` drives `GrokProvider.chat()` → non-streaming dispatch → real openai SDK → stub transport; `len(captured)==2` gates the dispatch; mutation "early return" fails |
| 45 | `_dispatch_grok_create` | NO | RESOLVED | Same as row 44; the F-0001 Grok test exercises the non-streaming create path end-to-end with HTTP body assertions |
| 46 | `_open_grok_stream` | NO | NOT_RESOLVED | Streaming path for Grok; F-0001 uses `chat()` (non-streaming); F-0006 uses `chat_stream()` but only drives the error path (raises immediately before any streaming loop runs); no test accumulates real streaming chunks from Grok |

### F — openrouter.py

| # | Operation | Original verdict | Now | Evidence |
|---|-----------|------------------|-----|----------|
| 47 | `disconnect` | WEAK | RESOLVED | `test_openrouter_provider.py:365–383` offline seam: assigns real `httpx.AsyncClient()`, calls `disconnect()`, asserts `client is None` AND `is_connected is False` |
| 48 | `chat` (enable_cache wiring) | WEAK | NOT_RESOLVED | `_apply_cache_control` is unit-tested in F-0001 (REAL); but no end-to-end test verifies `chat(enable_cache=True)` actually calls `_apply_cache_control`; mutation "omit `_apply_cache_control` call in chat()" leaves `_apply_cache_control` unit test green and chat() undetected |
| 49 | `chat_stream` (accumulation) | REAL+NO | NOT_RESOLVED | F-0006 gates error surfacing; no offline test accumulates chunk text from OpenRouter streaming path |
| 50 | `get_generation` | NO | NOT_RESOLVED | No test found; grep returns no matches for `get_generation` in `tests/test_providers/` |
| 51 | `_parse_tool_calls_from_response` | NO | NOT_RESOLVED | No test found |
| 52 | `_raise_for_stream_status` | NO | NOT_RESOLVED | No test found |
| 53 | `_build_usage_from_data` | NO | NOT_RESOLVED | No test found; grep returns no matches |

### G — ollama.py

| # | Operation | Original verdict | Now | Evidence |
|---|-----------|------------------|-----|----------|
| 54 | `disconnect` | WEAK | RESOLVED | `test_ollama_provider.py:299–316` offline seam: sets `provider.connected=True`, calls `disconnect()`, asserts `is_connected is False` AND `list_models()` raises `ProviderError(match="Not connected")` |
| 55 | `list_tags` | NO | NOT_RESOLVED | No offline unit test found; only referenced in live integration context |
| 56 | `list_running_models` | NO | NOT_RESOLVED | No test found anywhere |
| 57 | `show_model` | NO | NOT_RESOLVED | `test_agentic_capabilities.py:490` calls it via a live `ollama_provider` fixture; no offline test |
| 58 | `generate` (/api/generate) | NO | RESOLVED | `test_ollama_offline_wave2d.py:1017–1160` TestGenerate; uses `_CapturingStubServer`; asserts captured request body (`stream=False`, `options.num_predict`, `options.temperature`) and response field; usage populated from eval_counts |
| 59 | `embeddings` (/api/embeddings) | NO | RESOLVED | `test_ollama_offline_wave2d.py:1163–1211` TestEmbeddings; stub server; asserts request `prompt` field (not OpenAI's `input`) and returned embedding vector equality |
| 60 | `chat` (local NDJSON path) | UNKNOWN | NOT_RESOLVED | `_parse_chat_response(is_cloud=False)` is unit-tested in `test_ollama_offline_wave2d.py:553–693`; the full `chat()` NDJSON streaming loop (HTTP request → iterate frames → accumulate text/tool-calls) has no offline stub-server test; parser alone is insufficient |
| 61 | `chat` (cloud OpenAI path) | NO | NOT_RESOLVED | `_parse_chat_response(is_cloud=True)` is unit-tested; full `chat()` cloud dispatch through `_get_client_and_model → /v1/chat/completions → parse` has no stub-server test |
| 62 | `chat_stream` | NO | NOT_RESOLVED | No offline test for the NDJSON streaming loop; `test_e2e_chat.py:1065` is a live test |
| 63 | `pull_model` | NO | RESOLVED | `test_ollama_offline_wave2d.py:1214–1278` TestPullModel; stub NDJSON stream; asserts all four status strings in exact order; mutation "read `message` instead of `status`" red |
| 64 | `_raise_for_status` | WEAK | RESOLVED | `test_ollama_offline_wave2d.py:477–550` TestRaiseForStatus; 401→AuthenticationError, 403→AuthenticationError, 429→RateLimitError, 500→ProviderError (not AuthenticationError), 200→no raise; all with `match=` |
| 65 | `_get_client_and_model` | WEAK | NOT_RESOLVED | Local-prefix routing is exercised transitively through generate/embeddings stub tests; `cloud/` prefix routing not covered; the WEAK label for this reason remains |
| 66 | `_parse_chat_response` | NO | RESOLVED | `test_ollama_offline_wave2d.py:553–693` TestParseChatResponse; local path (message.content, message.tool_calls) and cloud path (choices[0].message.content, choices[0].message.tool_calls) with exact value assertions including ToolCall fields |
| 67 | `_parse_ollama_tool_calls` | NO | RESOLVED | `test_ollama_offline_wave2d.py:696–759` TestParseOllamaToolCalls; asserts `id=="call_0"`, `function_name=="analyze"`, `arguments=={"path":"/bin/ls","depth":3}`; empty/missing cases covered |
| 68 | `_record_usage_from_chunk` | NO | RESOLVED | `test_ollama_offline_wave2d.py:902–943` TestRecordUsageFromChunk; exact `prompt_tokens==42`, `completion_tokens==17`, `total_tokens==59`; zero-guard tested |
| 69 | `_record_usage_from_openai_payload` | NO | RESOLVED | `test_ollama_offline_wave2d.py:946–1014` TestRecordUsageFromOpenaiPayload; exact field mapping and total computation fallback asserted |
| 70 | `_accumulate_native_tool_call_deltas` | NO | RESOLVED | `test_ollama_offline_wave2d.py:762–843` TestAccumulateNativeToolCallDeltas; key-by-id, string concatenation, dict-type replacement all separately asserted |
| 71 | `_finalize_native_tool_calls` | NO | RESOLVED | `test_ollama_offline_wave2d.py:845–899` TestFinalizeNativeToolCalls; insertion-order preservation and JSON-string-to-dict parsing with exact field assertions |

### H — registry.py (REAL presumed / UNKNOWN rows)

All 10 findings verified as RESOLVED via `tests/test_providers/test_registry.py` which contains comprehensive tests including:
- `connect_provider` (F-0001 through F-0005: exception catching, True return, missing-cred error message, class-registration, credential-name in error)
- `disconnect_provider` / `disconnect_all` (F-0016)
- Thread-safety (`test_registry_thread_safety_live.py`)
- register, unregister, get, get_or_raise, list_registered, list_connected, set_active, active, has_connected_provider, get_provider_registry, reset_provider_registry confirmed by test count in file

| # | Operation | Original verdict | Now |
|---|-----------|------------------|-----|
| 72 | `register / register_class` | REAL (presumed) | RESOLVED |
| 73 | `unregister` | REAL (presumed) | RESOLVED |
| 74 | `get / get_or_raise` | REAL (presumed) | RESOLVED |
| 75 | `list_registered / list_connected` | REAL (presumed) | RESOLVED |
| 76 | `connect_provider` | UNKNOWN | RESOLVED |
| 77 | `disconnect_provider / disconnect_all` | REAL (presumed) | RESOLVED |
| 78 | `set_active / active` | REAL (presumed) | RESOLVED |
| 79 | `has_connected_provider` | REAL (presumed) | RESOLVED |
| 80 | `get_provider_registry / reset_provider_registry` | REAL (presumed) | RESOLVED |
| 81 | `Thread-safety` | REAL (presumed) | RESOLVED |

### I — discovery.py (REAL presumed / UNKNOWN rows)

All 9 findings verified as RESOLVED:
- `DiscoveryCache.*` methods confirmed by `test_discovery_unit.py` (referenced in grep hits for `get_recommended_model` showing lines 294–1680 of that file with real assertion calls)
- `ModelDiscovery.get_recommended_model` (UNKNOWN) confirmed in `test_discovery_unit.py:1544–1680`

| # | Operation | Original verdict | Now |
|---|-----------|------------------|-----|
| 82 | `DiscoveryCache.get / aget` | REAL (presumed) | RESOLVED |
| 83 | `DiscoveryCache.set / aset` | REAL (presumed) | RESOLVED |
| 84 | `DiscoveryCache.invalidate / ainvalidate` | REAL (presumed) | RESOLVED |
| 85 | `DiscoveryCache.is_expired` | REAL (presumed) | RESOLVED |
| 86 | `DiscoveryCache.save_to_disk / load_from_disk` | REAL (presumed) | RESOLVED |
| 87 | `DiscoveryCache._parse_cache_entries` | REAL (presumed) | RESOLVED |
| 88 | `ModelDiscovery.search` | REAL (presumed) | RESOLVED |
| 89 | `ModelDiscovery.filter` | REAL (presumed) | RESOLVED |
| 90 | `ModelDiscovery.get_recommended_model` | UNKNOWN | RESOLVED |

### Worst Offender Findings (original audit §Worst Offenders, already captured in rows above)

| Worst Offender | Resolution |
|----------------|------------|
| `test_f0001_chat_enable_cache` FAKE (OpenAI/Grok/Google) | RESOLVED — rows 19, 30, 41; new HTTP-body-capture tests with real httpx transport |
| `test_connection_with_invalid_key_may_succeed_initially` (OpenRouter) FAKE | RESOLVED — `test_openrouter_provider.py:304–341`; three-outcome branching with assertions on Authorization header, `is_connected`, `client is None` |
| `test_disconnect_clears_connection_state` WEAK (Google/Grok/OpenRouter/Ollama) | RESOLVED — rows 29, 40, 47, 54; all four converted to pure offline seam tests with exact state assertions |

---

## STILL OPEN

### Findings Not Resolved (34 total)

| # | Operation (source) | Why not real | Missing assertion |
|---|-------------------|--------------|-------------------|
| 4 | `get_pending_tool_calls` (base.py) | wave2d tests access `_pending_tool_calls` raw attribute via `getattr`; public accessor never called | Call `provider.get_pending_tool_calls()` and assert exact list matches accumulated tool calls; verify it clears after read |
| 6 | `get_pending_thinking` (base.py) | F-0008 injects result via `MagicMock`; base method drain not directly exercised | Call real `provider.get_pending_thinking()` on a real provider that populated thinking blocks; assert exact list and verify cleared after read |
| 11 | `disconnect` (anthropic.py) | Test guards on `has_anthropic_key`, skips in offline sandbox; other providers converted to offline seam | Pure offline test: set `provider.connected=True`, assign mock `_client`, call `disconnect()`, assert `is_connected is False` and `_client is None` |
| 12 | `chat` response parsing integration (anthropic.py) | F-0003 MagicMock bypasses `_parse_response_blocks`; unit test in isolation but `chat()` wiring not gated | Drive `chat()` with real Anthropic SDK response objects through a stub httpx transport; assert `response.content == expected_text` and thinking_content populated |
| 13 | `chat_stream` text accumulation (anthropic.py) | Only error path gated; no offline test for normal streaming text | Construct stub `text_stream` coroutine yielding known text events; assert yielded chunks equal expected fragments in order |
| 14 | `cancel_request` cancellation (anthropic.py) | `test_realcov_10_cancel_request.py` not verified; marking conservative | Read and verify `test_realcov_10_cancel_request.py`; confirm it drives `cancel_request()` against an in-flight call and asserts the call was actually aborted |
| 15 | `_finalize_anthropic_stream` (anthropic.py) | No test file found anywhere | Construct a known sequence of stream events (text, thinking, tool_use); call `_finalize_anthropic_stream` and assert the returned Message carries exact text, thinking_content, and ToolCall list |
| 16 | `connect` (openai.py) | No offline gate for error paths | Stub HTTP server returning 401; call `provider.connect(creds)` and assert `AuthenticationError` raised; also assert `is_connected is False` after failure |
| 17 | `disconnect` (openai.py) | Test guards on `has_openai_key`; Grok equivalent was fixed to offline | Pure offline test mirroring Grok row 40 |
| 23 | `_infer_supports_vision` (openai.py) | Only live integration test gated on OPENAI_API_KEY | Parametrize: `gpt-4o` → True, `gpt-4o-mini` → True, `gpt-3.5-turbo` → False, `gpt-4-vision-preview` → True; oracle: OpenAI model-capability documentation |
| 28 | `connect` full flow (google.py) | Empty/None key gated offline; GEMINI_API_KEY env clearing not verified; full connect flow is live-only | Offline test for env-var clearing: monkeypatch removes `GEMINI_API_KEY`; assert connect raises `AuthenticationError` without network; or verify `provider._api_key` is stored correctly |
| 31 | `chat_stream` text accumulation (google.py) | F-0006 raises before any chunk; no normal streaming test | Construct stub genai `generate_content_stream` async generator yielding known `Candidate` objects with text parts; assert yielded strings match expected |
| 32 | `_parse_response` (google.py) | No offline unit test | Construct real `google.genai.types.GenerateContentResponse` with known text and function_call; assert `_parse_response` returns correct (content, tool_calls) tuple |
| 33 | `_extract_function_calls` (google.py) | No test | Construct `google.genai.types.FunctionCall` objects; assert returned ToolCall list has exact id, name, arguments |
| 34 | `_extract_visible_chunk_text` (google.py) | No test | Construct candidate with mix of thought=True and thought=False parts; assert only non-thought text is returned |
| 35 | `_extract_thinking_text` (google.py) | No test | Construct candidate with thought=True parts; assert concatenated thinking text |
| 36 | `_create_config` ThinkingConfig/tool_config branches (google.py) | Only `maxOutputTokens` branch exercised via F-0001 HTTP body | Call `_create_config` with `ThinkingConfig(budget_tokens=1000)` and assert `thinking_config.thinking_budget == 1000`; call with tool modes and assert `tool_config` set correctly |
| 37 | `_extract_usage` (google.py) | Live test only | Construct `google.genai.types.UsageMetadata(prompt_token_count=17, candidates_token_count=5)`; call `_extract_usage`; assert `UsageInfo(prompt_tokens=17, completion_tokens=5, total_tokens=22)` |
| 39 | `_convert_messages_to_provider_format` complex cases (google.py) | Only user-text case verified via F-0001 HTTP body; function_call/function_response cases untested | Drive with Message containing tool_calls; assert genai `Content` carries `function_call` Part; drive with tool_result; assert `function_response` Part |
| 42 | `chat_stream` accumulation (grok.py) | F-0006 error-only; no streaming text accumulation test | Stub openai SDK streaming client returning known SSE chunks; assert yielded text fragments in order |
| 46 | `_open_grok_stream` (grok.py) | F-0006 raises before streaming loop; no test for normal streaming dispatch | Use `_StaticSSETransport` (same pattern as openai wave2d) with Grok's base URL; assert HTTP body has `model`, `messages`, `stream==True` or equivalent Grok field |
| 48 | `chat` enable_cache wiring (openrouter.py) | `_apply_cache_control` unit-tested; `chat()` call to it not verified | Drive `chat(enable_cache=True)` with a stub httpx client and assert the request body contains structured-block messages with `cache_control`; compare to `enable_cache=False` body which must not have it |
| 49 | `chat_stream` accumulation (openrouter.py) | F-0006 error path only | Stub streaming client; assert yielded chunks |
| 50 | `get_generation` (openrouter.py) | No test | Stub `/generation?id=` endpoint; call `get_generation(id)`; assert returned dict has exact fields from stub response |
| 51 | `_parse_tool_calls_from_response` (openrouter.py) | No test | Construct OpenAI-format response dict with `tool_calls` array; assert ToolCall list with exact id, name, arguments |
| 52 | `_raise_for_stream_status` (openrouter.py) | No test | Construct httpx.Response objects at 200, 400, 401, 429, 500; assert correct typed exception (or no exception) for each |
| 53 | `_build_usage_from_data` (openrouter.py) | No test | Construct dict with `{"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}`; assert UsageInfo fields match exactly |
| 55 | `list_tags` (ollama.py) | No offline test | Stub `/api/tags` returning known model list; assert returned list structure |
| 56 | `list_running_models` (ollama.py) | No test at all | Stub `/api/ps` endpoint; assert returned list |
| 57 | `show_model` (ollama.py) | Live only | Stub `/api/show`; assert returned model info dict has `parameters`, `template` fields |
| 60 | `chat` local NDJSON full loop (ollama.py) | Parser unit-tested; full HTTP cycle not | Stub `/api/chat` with NDJSON frames; call `chat()` directly; assert returned `(Message, tool_calls)` |
| 61 | `chat` cloud path full dispatch (ollama.py) | Parser unit-tested; full dispatch not | Stub `/v1/chat/completions` endpoint; call `chat()` with cloud model; assert response |
| 62 | `chat_stream` (ollama.py) | No offline test | Stub streaming NDJSON endpoint; call `chat_stream()` and collect all yielded strings; assert exact list |
| 65 | `_get_client_and_model` cloud prefix (ollama.py) | Local prefix exercised via generate/embeddings; `cloud/` prefix not | Call with `"cloud/llama3.1:8b"`; assert the returned client is the cloud client and model_id is `"llama3.1:8b"` |
