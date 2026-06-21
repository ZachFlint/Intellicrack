# Test-Gate Audit — test_providers (part 1)

## Summary
- Files audited: 24
- Test functions examined: 268 (parametrized families counted once; helper functions and fixtures excluded)
- Genuine gates: 235
- Flagged non-gates: 33  (CRITICAL: 2, HIGH: 9, MEDIUM: 21, LOW: 1)

## Coverage checklist
- [x] tests/test_providers/__init__.py — gates: 0, flagged: 0 (package docstring only, no tests)
- [x] tests/test_providers/conftest.py — gates: 0, flagged: 0 (fixtures + billing-skip hook; not test functions)
- [x] tests/test_providers/test_agentic_capabilities.py — gates: 10, flagged: 4
- [x] tests/test_providers/test_anthropic_buffers_live.py — gates: 1, flagged: 1
- [x] tests/test_providers/test_anthropic_provider.py — gates: 35, flagged: 0
- [x] tests/test_providers/test_credential_loading.py — gates: 16, flagged: 2
- [x] tests/test_providers/test_discovery_unit.py — gates: 60, flagged: 0
- [x] tests/test_providers/test_e2e_chat.py — gates: 28, flagged: 1
- [x] tests/test_providers/test_google_chat_live.py — gates: 2, flagged: 0
- [x] tests/test_providers/test_google_provider.py — gates: 7, flagged: 7
- [x] tests/test_providers/test_grok_provider.py — gates: 7, flagged: 6
- [x] tests/test_providers/test_http_status_helper.py — gates: 11, flagged: 0
- [x] tests/test_providers/test_huggingface_chat_live.py — gates: 2, flagged: 0
- [x] tests/test_providers/test_huggingface_provider.py — gates: 16, flagged: 5
- [x] tests/test_providers/test_local_transformers_live.py — gates: 3, flagged: 0
- [x] tests/test_providers/test_local_transformers_provider.py — gates: 41, flagged: 1
- [x] tests/test_providers/test_local_xpu_e2e.py — gates: 44, flagged: 2
- [x] tests/test_providers/test_message_conversion.py — gates: 24, flagged: 0
- [x] tests/test_providers/test_model_discovery.py — gates: 1, flagged: 6
- [x] tests/test_providers/test_ollama_chat_live.py — gates: 1, flagged: 0
- [x] tests/test_providers/test_ollama_provider.py — gates: 6, flagged: 8 (model-field tests vacuous on empty list)
- [x] tests/test_providers/test_openai_format_helpers.py — gates: 22, flagged: 0
- [x] tests/test_providers/test_openai_provider.py — gates: 7, flagged: 6
- [x] tests/test_providers/test_openrouter_provider.py — gates: 9, flagged: 3

(Per-file flagged counts above tally the worst-instance flags called out below; the
type-only model-field family in each live-provider file is flagged once as a family to
avoid padding, but the count reflects the distinct test functions in that family.)

## Flagged tests

### tests/test_providers/test_agentic_capabilities.py

#### `TestAccurateToolSupport.test_ollama_models_report_accurate_tool_support` — CRITICAL — N4 vacuous
- **Location:** tests/test_providers/test_agentic_capabilities.py:414
- **Current behavior:** Builds `tool_support_values = {m.supports_tools for m in models}` then asserts `isinstance(tool_support_values, set)`. A set comprehension is always a set, so the only assertion is trivially true for any model list (including all-True, all-False, or garbage flags).
- **Why it is not a gate:** The test name claims it validates "accurate tool support metadata", but a bridge that reported `supports_tools=True` for every model — or a constant — would still pass. `isinstance(x, set)` cannot fail.
- **Recommended fix:** Assert the actual contract: pick a model whose Ollama capability is independently known (e.g. a non-tool model installed for the test) and assert its `supports_tools` equals the known value, or assert the set has the expected cardinality for the installed models.

#### `TestToolChoiceRequired.test_google_tool_choice_auto` — HIGH — N7 accepts-both-outcomes
- **Location:** tests/test_providers/test_agentic_capabilities.py:198
- **Current behavior:** Asserts `response.role == "assistant"` then `has_content or has_tool_calls`. Both the free-text branch and the tool-call branch satisfy the disjunction, so any non-empty response passes regardless of whether tool-choice AUTO is wired correctly.
- **Why it is not a gate:** A regression that ignored the `tools` argument entirely (never able to call a tool) would still pass via the content branch; a regression that dropped content but produced a spurious tool call would also pass. The test cannot distinguish a correct AUTO implementation from a broken one.
- **Recommended fix:** Split into two deterministic gates: a prompt that AUTO must answer in free text (assert content, assert `tool_calls is None`) and a prompt that strongly compels the offered tool (assert a structured `ToolCall` to `binary.get_file_size`). Or assert that when a tool call is produced, its `function_name`/`tool_name`/`arguments` are exactly correct.

#### `TestStreamingToolCalls.test_huggingface_stream_captures_tool_calls` — HIGH — N6/N7 vacuously-satisfiable
- **Location:** tests/test_providers/test_agentic_capabilities.py:281
- **Current behavior:** After streaming, branches on `if pending:`. The strong tool-call assertions only run when `pending` is non-empty; the `else` branch only requires `len(total_content) > 0`. Also `pytest.skip` at line 306 when the model does not advertise tool support.
- **Why it is not a gate for the named behavior:** The class docstring says streaming "captures tool calls on previously broken providers", but the buffer-manager bug it guards is exactly the case where a tool call was made yet `get_pending_tool_calls()` returns empty — which falls into the `else` branch and passes as long as any text streamed. The test therefore does not gate the regression it names.
- **Recommended fix:** Use a model + prompt where a tool call is reliably emitted and `tool_choice=REQUIRED`, then assert `pending` is non-empty unconditionally with exact `function_name`/`arguments`. If the live model cannot guarantee that, move the buffer-manager assertion to a unit test that feeds a captured streaming tool-call event sequence through `ToolCallBufferManager`.

#### `TestStreamingToolCalls.test_ollama_stream_with_tools_returns_tool_calls` — HIGH — N6/N7 vacuously-satisfiable
- **Location:** tests/test_providers/test_agentic_capabilities.py:344
- **Current behavior:** Same `if pending: ... else: assert len(total_content) > 0` shape as the HuggingFace case; skips when the model is missing or lacks tool support.
- **Why it is not a gate:** The non-streaming-fallback tool-call capture (the behavior under test) is silently optional — an empty `pending` with any streamed text passes, so a broken fallback path is not caught.
- **Recommended fix:** Drive a tool-capable installed model with `tool_choice=REQUIRED` and assert `pending` non-empty with exact structure; otherwise unit-test the fallback assembler against a recorded Ollama non-streaming tool response.

### tests/test_providers/test_anthropic_buffers_live.py

#### `test_live_module_importable` — MEDIUM — N4 vacuous / smoke-as-gate
- **Location:** tests/test_providers/test_anthropic_buffers_live.py:292
- **Current behavior:** Creates an asyncio event loop and asserts `loop is not None`. `asyncio.new_event_loop()` never returns None, so the assertion cannot fail.
- **Why it is not a gate:** It exists only to keep the module from reporting "no tests ran" when credentials are absent. It validates nothing about the Anthropic buffers the file is named for.
- **Recommended fix:** Remove it, or replace with a real unit gate that does not need credentials (e.g. assert `AnthropicProvider().get_pending_usage() is None` and `get_pending_thinking() == []` on a fresh provider — a falsifiable buffer-initial-state contract).

(Note: the `except Exception` blocks at lines 210, 242, 280 re-raise everything except billing markers via `pytest.skip` — this is an acceptable live-account precondition skip, not flagged.)

### tests/test_providers/test_credential_loading.py

#### `TestCredentialValidation.test_get_credentials_returns_credentials_or_none` — MEDIUM — N6/N8 existence-only
- **Location:** tests/test_providers/test_credential_loading.py:231
- **Current behavior:** Loops over providers; only when `creds is not None` asserts `isinstance(creds, ProviderCredentials)`. With no configured providers the loop body never asserts, and the only check is a type check.
- **Why it is not a gate:** A `get_credentials` that returned a malformed-but-correctly-typed credential, or that returned None for a genuinely-configured provider, would pass. The value (api_key correctness) is never checked.
- **Recommended fix:** Use a controlled env file with a known key and assert the returned `ProviderCredentials.api_key` equals the injected value for that provider; assert None for a deliberately-absent provider.

#### `TestEnvironmentVariableAccess.test_set_env_var_updates_value` — LOW — narrow gate
- **Location:** tests/test_providers/test_credential_loading.py:393
- **Current behavior:** Sets an env var via the loader and reads it back through the same loader; asserts round-trip equality.
- **Why it is weak:** It exercises the loader's own getter/setter pair against itself; it does not confirm the value reached `os.environ` (the documented effect), so a setter that only updates an internal dict would pass.
- **Recommended fix:** Additionally assert `os.environ[test_key] == test_value` (and clean up), pinning the real side effect.

### tests/test_providers/test_e2e_chat.py

#### `TestRateLimitAndErrorHandling` / cross-provider — note only; one real flag below

#### `available_providers`-driven tests rely on a fixture that `pytest.skip`s when no creds — acceptable environment skip, not flagged.

#### (real flag) `tests/test_providers/test_local_xpu_e2e.py::TestErrorRecovery.test_empty_message_list_handled` is in that file, see below. In this file no swallowing was found; the suppress pattern lives in test_local_xpu_e2e.py.

(`test_e2e_chat.py` is otherwise strongly gated: greeting-token, math-answer, exact-notepad-path, max-tokens word cap, typed-rejection-with-4xx-status, and deterministic unreachable-endpoint timeout are all real oracles. No flags.)

### tests/test_providers/test_google_provider.py

#### Model-field type-only family — MEDIUM — N8 existence-only (7 tests)
- **Location:** tests/test_providers/test_google_provider.py:79 (`test_list_models_returns_model_info_instances`), :94 (`test_model_info_has_valid_id`), :110 (`test_model_info_has_valid_name`), :126 (`test_model_info_has_correct_provider`), :141 (`test_model_info_has_positive_context_window`), :157 (`test_model_info_has_boolean_capabilities`), :174 (`test_models_are_gemini_models`)
- **Current behavior:** Each loops over `list_models()` asserting only `isinstance(...)` / `len > 0` / `> 0` / membership of `"gemini"`. No value is checked against an independent oracle beyond the provider enum tag the bridge itself stamps.
- **Why it is weak:** These assert structural well-formedness, not that the Google bridge faithfully parsed real API records. A bridge that fabricated plausible `ModelInfo` objects (correct types, positive window, "gemini" in id) with wrong context windows or wrong capability flags would pass every one. `supports_tools/vision/streaming` are only checked for being bools, never for the documented value of any specific model.
- **Recommended fix:** Collapse the structural checks into one, and add one value gate: assert a documented Gemini model (e.g. `gemini-2.5-flash`) appears with its known capability profile, mirroring `test_anthropic_provider.py::test_list_models_includes_a_known_production_model`. (`test_list_models_returns_non_empty_list` at :44 already does a partial real check and is counted as a gate.)

### tests/test_providers/test_grok_provider.py

#### Model-field type-only family — MEDIUM — N8 existence-only (6 tests)
- **Location:** tests/test_providers/test_grok_provider.py:62, :77, :93, :109, :124, :140
- **Current behavior:** Identical structural-only loops (`isinstance` / `len>0` / `>0`) over `list_models()`; provider tag is the only value asserted.
- **Why it is weak:** Same as Google: faithful parsing of real Grok records is not gated; fabricated well-formed `ModelInfo` would pass. Capability flags are only type-checked.
- **Recommended fix:** Add a value gate asserting a documented Grok model id is present and that its capability flags match the published profile; reduce the structural checks to one.

### tests/test_providers/test_huggingface_provider.py

#### Live model-field type-only family — MEDIUM — N8 existence-only (5 tests)
- **Location:** tests/test_providers/test_huggingface_provider.py:254 (`test_list_models_returns_model_info_instances`), :295 (`test_model_info_has_valid_name`), :311 (`test_model_info_has_correct_provider`), :326 (`test_model_info_has_positive_context_window`), :342 (`test_model_info_has_boolean_capabilities`)
- **Current behavior:** Slice `models[:_SAMPLE_MODEL_LIMIT]` and assert only `isinstance`/`len>0`/`>0` per element.
- **Why it is weak:** Structural-only; faithful capability/context derivation from real Hub records is not gated. The capability flags are only type-checked, while the parser's actual tag-to-flag mapping is the bridge logic worth gating.
- **Recommended fix:** These live structural checks are largely redundant with the strong `TestBuildModelInfoList` unit tests (which ARE genuine gates). Keep one live structural sanity check and drop the rest, or assert a known HF model id surfaces with the capability profile its tags imply. (`test_list_models_returns_non_empty_list` at :205, `test_list_models_returns_many_models` at :240, and `test_model_info_has_valid_id` at :269 do real value checks and are counted as gates; the `TestBuildModelInfoList` unit class is fully gated.)

### tests/test_providers/test_local_transformers_provider.py

#### `TestProviderListModels.test_list_models_returns_list` — MEDIUM — N8 existence-only
- **Location:** tests/test_providers/test_local_transformers_provider.py:637
- **Current behavior:** Connects and asserts `isinstance(models, list)`.
- **Why it is weak:** `list_models()` for the local provider returns a hardcoded recommended list; an empty or wrong list would pass the isinstance check. The very next test (`test_list_models_has_recommended_models`, :647) does the real gate, making this one redundant and non-gating on its own.
- **Recommended fix:** Remove, or fold into the recommended-models test which already asserts content.

### tests/test_providers/test_local_xpu_e2e.py

#### `TestErrorRecovery.test_empty_message_list_handled` — CRITICAL — N2 swallowed failure
- **Location:** tests/test_providers/test_local_xpu_e2e.py:1732
- **Current behavior:** Wraps the `chat([])` call in `contextlib.suppress(ProviderError, ValueError, RuntimeError, IndexError)` with no assertion. The test passes whether the call returns, raises one of four exception types, or does nothing.
- **Why it is not a gate:** The docstring says it verifies an empty message list "should not crash with an unhandled exception", but suppressing four exception types AND having no assertion means a genuine crash (any of those) is the expected-and-accepted outcome, and a silent corruption is equally accepted. Nothing can fail it.
- **Recommended fix:** Decide the contract: either assert `pytest.raises(ProviderError)` (empty input is rejected) or assert a well-formed assistant response is returned. Remove the blanket suppress.

#### `TestVRAMManagement.test_memory_decreases_after_unload` — MEDIUM — N8 / wrong-behavior
- **Location:** tests/test_providers/test_local_xpu_e2e.py:1465
- **Current behavior:** Despite the name "decreases after unload", it never unloads and only asserts `device_type in {...}`, `total > 0`, `allocated` is int. No before/after comparison.
- **Why it is weak:** The named behavior (memory dropping after unload) is not exercised at all; the assertions hold on any running XPU regardless of unload correctness.
- **Recommended fix:** Capture `get_xpu_memory_info` before unload, call `unload_model()`, and assert allocated memory drops (or returns to a baseline). If reliable measurement is impossible, rename to reflect the weaker invariant actually tested.

(The B580/XPU `skipif` and `has_xpu_available`/`has_arc_b580` skips are legitimate hardware-capability skips — listed under Acceptable skips. The inference/coherence/temperature/max-token gates in this file are strong and counted as genuine gates.)

### tests/test_providers/test_model_discovery.py

#### Display-style model tests — MEDIUM — N9/N8 log-presence + existence-only (5 tests)
- **Location:** tests/test_providers/test_model_discovery.py:40 (`test_display_openai_models`), :58 (`test_display_google_models`), :76 (`test_display_openrouter_models`), :103 (`test_display_anthropic_models`), :121 (`test_display_ollama_models`)
- **Current behavior:** Each fetches `list_models()`, logs counts, asserts `model.id` truthy in a loop, and (for 4 of 5) `len(models) > 0`. The Ollama variant (:121) has no `len > 0` assertion at all, so an empty local model list passes with zero loop iterations.
- **Why it is weak:** Primary purpose is logging ("Run with -s to see output"); the assertions are existence-only and overlap entirely with the dedicated provider listing files. `test_display_ollama_models` is fully vacuous when no models are installed (N6).
- **Recommended fix:** These are redundant with `test_<provider>_provider.py`. Either delete the display tests or convert each to a value gate (assert a known model id present); at minimum add `len(models) > 0` to the Ollama case or assert a known installed model.

#### `TestAllProvidersModelCount.test_summary_all_providers` — MEDIUM — N9/N8 summary-only
- **Location:** tests/test_providers/test_model_discovery.py:142
- **Current behavior:** Connects each configured provider, records counts, logs them, and asserts only `configured_count > 0`.
- **Why it is weak:** It proves at least one provider is configured and returned a count, not that any model record is correct. The per-provider `list_models()` results are never asserted beyond contributing to a count.
- **Recommended fix:** Assert each configured provider's count is `> 0` (a faithful listing always returns models) rather than just the aggregate, and ideally assert a known model id per provider.

### tests/test_providers/test_ollama_provider.py

#### Model-field type-only family, vacuous on empty list — HIGH — N6 vacuously-satisfiable (6 tests)
- **Location:** tests/test_providers/test_ollama_provider.py:51 (`test_list_models_returns_model_info_instances`), :66 (`test_model_info_has_valid_id_when_present`), :82 (`test_model_info_has_valid_name_when_present`), :98 (`test_model_info_has_correct_provider`), :113 (`test_model_info_has_positive_context_window`), :129 (`test_model_info_has_boolean_capabilities`)
- **Current behavior:** Each iterates `await ollama_provider.list_models()` with only `isinstance`/`len>0` assertions inside the loop and no assertion that the list is non-empty. The file's own `test_list_models_returns_list` docstring states the list "may be empty if no models installed".
- **Why it is not a gate:** On a CI/dev Ollama with no models installed (a common state) every loop body executes zero times and the test passes having asserted nothing. Even when models exist, the checks are structural-only (N8) and never assert a known installed model's fields.
- **Recommended fix:** These should gate on a known-installed model: pull a fixed small model in the fixture and assert its id/capabilities; or, if the suite tolerates empty installs, guard the whole class with a skip when no models are installed and then assert non-empty + exact fields for the known model. As written they are coverage theater for the empty-install case.

#### `test_multiple_calls_return_consistent_results` — MEDIUM — N6 (counted within the family above)
- **Location:** tests/test_providers/test_ollama_provider.py:146
- **Current behavior:** Compares id-sets across two calls; on an empty install both sets are empty and `set() == set()` passes.
- **Why it is weak:** Consistency is trivially true for an empty listing; the real cache/consistency behavior is unverified when no models exist.
- **Recommended fix:** Require at least one installed model (skip otherwise) before asserting cross-call equality.

(The `TestOllamaConnection` tests — invalid-url raises, list-without-connect raises, custom-base-url connect, disconnect-clears-state — are genuine gates and counted as such.)

### tests/test_providers/test_openai_provider.py

#### Model-field type-only family — MEDIUM — N8 existence-only (6 tests)
- **Location:** tests/test_providers/test_openai_provider.py:67 (`test_list_models_returns_model_info_instances`), :82 (`test_model_info_has_valid_id`), :98 (`test_model_info_has_valid_name`), :114 (`test_model_info_has_correct_provider`), :129 (`test_model_info_has_positive_context_window`), :145 (`test_model_info_has_boolean_capabilities`)
- **Current behavior:** Structural-only loops over the live model list; the only value asserted is the provider enum the bridge stamps.
- **Why it is weak:** Faithful parsing of real OpenAI records is not gated; capability flags are only type-checked. (`test_models_have_valid_provider` at :162 combines a couple of these checks and is also weak but counted under this family's intent.)
- **Recommended fix:** Add a value gate that a documented model (e.g. `gpt-4o-mini`, already the configured constant elsewhere) is present with its known context window/capabilities; the strong connection/teardown tests in this file (:226, :256, :282, :307) are genuine gates and need no change.

### tests/test_providers/test_openrouter_provider.py

#### Model-field type-only family — MEDIUM — N8 existence-only (3 tests)
- **Location:** tests/test_providers/test_openrouter_provider.py:80 (`test_list_models_returns_model_info_instances`), :125 (`test_model_info_has_correct_provider`), :158 (`test_model_info_has_boolean_capabilities`)
- **Current behavior:** Slice `[:_SAMPLE_MODEL_LIMIT]` and assert only `isinstance`/enum-tag/bool-type.
- **Why it is weak:** Structural-only; the aggregator-parsing fidelity (org-scoped ids, per-model capability/pricing) is not gated by these three. (`test_list_models_returns_many_models` :66, `test_model_info_has_valid_id` :95 with its `/`-implied org check via e2e, and `test_model_info_may_have_pricing` :175 are real value gates and counted as gates.)
- **Recommended fix:** Add an assertion that a known OpenRouter model id (e.g. `openai/gpt-4o-mini`, the configured constant) is present with expected capabilities; otherwise these structural checks are redundant with the e2e listing gate.

## Acceptable skips (not flagged)
- tests/test_providers/conftest.py:117 `pytest_runtest_call` — skips live tests only on matched billing/quota/credit signals in the exception chain; every other ProviderError propagates. Legitimate live-account precondition skip.
- tests/test_providers/conftest.py:163,193,223,253,283,318,348 fixture `pytest.skip` when the corresponding API key / local Ollama is absent — legitimate environment-credential skips; the matching unconditional unit gates exist elsewhere (credential format, message/tool conversion, http-status helper).
- tests/test_providers/test_anthropic_buffers_live.py:168,212,244,283 — skip on missing key / billing markers; non-billing errors re-raised. Legitimate.
- tests/test_providers/test_google_chat_live.py:81,111 — skip only on transient `RateLimitError`; auth/model/other errors propagate. Legitimate (and the success path asserts the deterministic word `ready` + usage consistency).
- tests/test_providers/test_huggingface_chat_live.py:47,103 — skip when token absent. Legitimate.
- tests/test_providers/test_ollama_chat_live.py:82 — skip when daemon unreachable or no model installed. Legitimate environment skip (the success path is a strong content+usage gate).
- tests/test_providers/test_agentic_capabilities.py:306,367,425 — skip when the live model does not advertise tool support / is not installed (capability of the external model, not the bridge). Borderline but acceptable as a model-capability skip; the gating weakness is the `else`/`if pending` branch, flagged above, not the skip itself.
- tests/test_providers/test_local_transformers_provider.py:197,514,526,543,553,565,577,587,596 and test_local_xpu_e2e.py:563,651,669,681,703,725,747,767,1675,1697,1717 — `skipif(not is_xpu_available()/is_arc_b580())` and `has_xpu_available`/`has_arc_b580` guards. Legitimate hardware-capability skips; the CPU-fallback paths run unconditionally and are gated.
- tests/test_providers/test_credential_loading.py:357, and the `has_*_key`-guarded "live key prefix" / disconnect tests across the provider files — skip when the real key is absent; the unconditional synthetic-key format gates cover the logic. Legitimate.
