# Test-Gate Audit — test_providers (part 2)

## Summary
- Files audited: 22
- Test functions examined: 215
- Genuine gates: 192
- Flagged non-gates: 23  (CRITICAL: 6, HIGH: 1, MEDIUM: 16, LOW: 0)

## Coverage checklist
- [x] tests/test_providers/test_parse_openai_format_tool_calls.py — gates: 8, flagged: 0
- [x] tests/test_providers/test_provider_bugfixes.py — gates: 9, flagged: 13
- [x] tests/test_providers/test_provider_loop_rebind.py — gates: 5, flagged: 0
- [x] tests/test_providers/test_providers_cloud_audit1.py — gates: 19, flagged: 2
- [x] tests/test_providers/test_providers_local_audit1.py — gates: 17, flagged: 0
- [x] tests/test_providers/test_providers_package_exports.py — gates: 3, flagged: 0
- [x] tests/test_providers/test_real_bridge_schemas.py — gates: 4, flagged: 0
- [x] tests/test_providers/test_realcov_10_anthropic_cache.py — gates: 7, flagged: 0
- [x] tests/test_providers/test_realcov_10_cancel_request.py — gates: 2, flagged: 0
- [x] tests/test_providers/test_realcov_10_discovery_extra.py — gates: 12, flagged: 0
- [x] tests/test_providers/test_realcov_10_google_safety.py — gates: 11, flagged: 0
- [x] tests/test_providers/test_realcov_10_grok_reasoning_effort.py — gates: 13, flagged: 0
- [x] tests/test_providers/test_realcov_11_gpu_pci.py — gates: 13, flagged: 0
- [x] tests/test_providers/test_realcov_11_huggingface_logic.py — gates: 16, flagged: 0
- [x] tests/test_providers/test_realcov_11_local_transformers_logic.py — gates: 22, flagged: 0
- [x] tests/test_providers/test_realcov_11_model_loader.py — gates: 27, flagged: 0
- [x] tests/test_providers/test_realcov_11_xpu_utils.py — gates: 14, flagged: 0
- [x] tests/test_providers/test_registry.py — gates: 39, flagged: 1
- [x] tests/test_providers/test_registry_thread_safety_live.py — gates: 1, flagged: 0
- [x] tests/test_providers/test_safe_parse_stream_json.py — gates: 9, flagged: 0
- [x] tests/test_providers/test_tool_call_buffer.py — gates: 10, flagged: 0
- [x] tests/test_providers/test_tool_schema_builders.py — gates: 29, flagged: 0

## Flagged tests

### tests/test_providers/test_provider_bugfixes.py

#### `TestAsyncCacheDiscovery.test_init_model_discovery_is_coroutine` — MEDIUM — N8
- **Location:** tests/test_providers/test_provider_bugfixes.py:49
- **Current behavior:** Imports `intellicrack.main.init_model_discovery` and asserts only `inspect.iscoroutinefunction(func)`.
- **Why it is not a gate:** Asserts a function attribute (is-coroutine), not behavior. A regression that makes the coroutine return the wrong tuple, fail to populate state, or raise on await would not turn this red. The very next test (`test_init_model_discovery_returns_discovery_and_cache_path`) is the real gate; this one only checks the decorator/async keyword survives.
- **Recommended fix:** Delete it (subsumed by the awaiting test on line 62) or fold the `iscoroutinefunction` assert into that test as a precondition.

#### `TestOAuthFlowValidation.test_oauth_configs_returns_none_for_missing_provider` — CRITICAL — N4
- **Location:** tests/test_providers/test_provider_bugfixes.py:120
- **Current behavior:** Calls `OAUTH_CONFIGS.get(object())` and asserts the result is `None`.
- **Why it is not a gate:** `OAUTH_CONFIGS` is a plain dict; this exercises `dict.get` returning `None` for an absent sentinel key. No Intellicrack OAuth-validation code path runs. It would pass for any dict-shaped object on earth and cannot fail unless the stdlib dict breaks.
- **Recommended fix:** Replace with a test that drives `start_oauth_flow` (the fix under test) with an invalid provider and asserts it surfaces the validation error, exercising real OAuth-config-lookup code.

#### `TestCredentialSourceDetectorPath.test_env_path_resolves_relative_to_module` — MEDIUM — N9
- **Location:** tests/test_providers/test_provider_bugfixes.py:131
- **Current behavior:** Computes `Path(provider_config.__file__).resolve().parents[3]` and asserts `pyproject.toml` exists there.
- **Why it is not a gate:** This asserts a property of the repository layout (a `pyproject.toml` sits 4 levels above the module file), not the production path-resolution logic in `CredentialSourceDetector`. The detector's actual env-path resolution code never executes. A real defect in the detector's path computation would not fail this.
- **Recommended fix:** Instantiate `CredentialSourceDetector`, invoke the method that resolves the env path, and assert the resolved path equals the expected project-root-relative location it computes internally.

#### `TestCredentialSourceDetectorPath.test_credential_source_detector_instantiation` — CRITICAL — N8
- **Location:** tests/test_providers/test_provider_bugfixes.py:137
- **Current behavior:** Constructs `CredentialSourceDetector(tmp_path / "config.json")` and asserts `detector is not None`.
- **Why it is not a gate:** Construction-only smoke test; `detector` can never be `None` after a successful constructor call. No detection behavior is asserted. Cannot fail unless the constructor raises.
- **Recommended fix:** Call a real detection method (e.g. detect the credential source for a known env/file state set up in `tmp_path`) and assert the classified source value.

#### `TestHuggingFaceJsonDecode.test_malformed_json_raises_decode_error` — CRITICAL — N4
- **Location:** tests/test_providers/test_provider_bugfixes.py:151
- **Current behavior:** Builds `httpx.Response(200, content=b"not json")` and asserts `response.json()` raises `json.JSONDecodeError`.
- **Why it is not a gate:** Tests the behavior of `httpx`/the stdlib JSON parser, not any Intellicrack HuggingFace code. The provider's own malformed-response handling (the actual fix) never runs. Passes regardless of whether the HuggingFace provider correctly wraps the error.
- **Recommended fix:** Drive `HuggingFaceProvider`'s response-handling path with a malformed body (as `test_realcov_11_huggingface_logic.py::TestExtract503Message` does for 503) and assert the provider raises the typed `ProviderError`.

#### `TestHuggingFaceJsonDecode.test_html_response_raises_decode_error` — CRITICAL — N4
- **Location:** tests/test_providers/test_provider_bugfixes.py:157
- **Current behavior:** Same as above with `b"<html>Error</html>"`; asserts `response.json()` raises.
- **Why it is not a gate:** Tests httpx/stdlib, not Intellicrack. No provider code under test.
- **Recommended fix:** Same as above — exercise the provider's HTML-response handling and assert the wrapped error.

#### `TestHuggingFaceJsonDecode.test_valid_json_parses_correctly` — MEDIUM — N4
- **Location:** tests/test_providers/test_provider_bugfixes.py:165
- **Current behavior:** Asserts `httpx.Response(200, content=b'{"ok":true}').json() == {"ok": True}`.
- **Why it is not a gate:** Verifies httpx parses valid JSON; no Intellicrack code involved.
- **Recommended fix:** Remove, or route a valid HuggingFace response body through the provider's parser and assert the normalized result.

#### `TestHuggingFaceJsonDecode.test_provider_error_wraps_decode_error` — MEDIUM — N4/N10
- **Location:** tests/test_providers/test_provider_bugfixes.py:172
- **Current behavior:** The test itself catches `JSONDecodeError` and manually builds `ProviderError(...)`, sets `wrapped.__cause__ = exc`, then asserts the cause it just set is a `JSONDecodeError`.
- **Why it is not a gate:** The wrapping is performed by the test body, not by production code. It asserts data it injected. The provider's real error-wrapping logic is never invoked.
- **Recommended fix:** Call the actual provider method that wraps decode failures and assert `exc.__cause__` is a `JSONDecodeError` on the exception the provider raised.

#### `TestGoogleClientErrorDetection.test_client_error_class_is_importable` — CRITICAL — N8
- **Location:** tests/test_providers/test_provider_bugfixes.py:206
- **Current behavior:** Asserts `ClientError is not None` (imported at module top from `google.genai.errors`).
- **Why it is not a gate:** Import-existence check of a third-party class; `ClientError` is a module-level import that cannot be `None` if the import succeeded (the file would fail to import otherwise). Tests nothing about Intellicrack's credential-validation fix.
- **Recommended fix:** Remove; the two preceding `connect`-with-empty/None-key tests (lines 191, 199) are the real gates for fix #6.

#### `TestOpenRouterPricingConversion.test_valid_numeric_string_converts` — MEDIUM — N4
- **Location:** tests/test_providers/test_provider_bugfixes.py:215
- **Current behavior:** Computes `float("0.000015") * 1_000_000` inside the test and asserts it is ~15.0.
- **Why it is not a gate:** Pure arithmetic on stdlib `float`; no OpenRouter pricing-conversion code runs. Tautological.
- **Recommended fix:** Call the real OpenRouter pricing helper with a model record and assert the micro-dollar field it produces.

#### `TestOpenRouterPricingConversion.test_na_string_raises_value_error` — MEDIUM — N4
- **Location:** tests/test_providers/test_provider_bugfixes.py:222
- **Current behavior:** Asserts `float("N/A")` raises `ValueError`.
- **Why it is not a gate:** Tests stdlib `float()`; no Intellicrack code. Cannot fail unless Python changes.
- **Recommended fix:** Feed `"N/A"` pricing into the real OpenRouter converter and assert it nullifies/handles the field rather than crashing.

#### `TestOpenRouterPricingConversion.test_empty_string_raises_value_error` — MEDIUM — N4
- **Location:** tests/test_providers/test_provider_bugfixes.py:228
- **Current behavior:** Asserts `float("")` raises `ValueError`.
- **Why it is not a gate:** Stdlib behavior; no production code. Tautological.
- **Recommended fix:** Same as above — exercise the real converter with an empty pricing field.

#### `TestOpenRouterPricingConversion.test_none_raises_type_error` / `test_pricing_pattern_nullifies_bad_input` / `test_pricing_pattern_converts_valid_input` — MEDIUM — N4/N10
- **Location:** tests/test_providers/test_provider_bugfixes.py:234, 241, 251
- **Current behavior:** `test_none_raises_type_error` asserts `float(None)` raises `TypeError`. The two `test_pricing_pattern_*` tests re-implement the production try/except (`try: float(val)*MULT except (ValueError, TypeError): None`) inside the test body and assert on that inline re-implementation.
- **Why it is not a gate:** The first tests stdlib `float()`. The latter two are textbook tautologies (N4): they re-create the function-under-test's logic in the test and compare it to itself; the real OpenRouter pricing code is never called, so a defect there cannot fail them.
- **Recommended fix:** Collapse all three into a single test that drives the actual OpenRouter pricing-conversion helper with valid, `"N/A"`, empty, and `None` inputs and asserts the helper's returned values.

### tests/test_providers/test_providers_cloud_audit1.py

#### `test_f0001_chat_signatures_accept_enable_cache_and_thinking` — MEDIUM — N8
- **Location:** tests/test_providers/test_providers_cloud_audit1.py:378
- **Current behavior:** Iterates the five cloud provider classes and asserts `"enable_cache"` and `"thinking"` are present in `inspect.signature(cls.chat).parameters`.
- **Why it is not a gate:** Signature-presence check only. A provider could accept the parameters and silently ignore them (the exact bug class the audit names — "callers were silently dropping these knobs") and this test would still pass. It gates the parameter names, not the behavior. The companion tests (`test_f0001_openrouter_enable_cache_attaches_cache_control`, `test_f0005_*`) are the behavioral gates.
- **Recommended fix:** Keep only if treated as a cheap signature guard; the real protection must be per-provider behavioral assertions that `enable_cache=True`/`thinking=...` actually mutate the outgoing request (already present for OpenRouter/Anthropic; extend to OpenAI/Grok/Google rather than relying on the signature check).

#### `test_f0004_providers_use_retry_with_backoff_in_chat_path` — MEDIUM — N9
- **Location:** tests/test_providers/test_providers_cloud_audit1.py:890
- **Current behavior:** Reads `inspect.getsource()` of `GrokProvider.chat`, `OpenRouterProvider.chat`, and `_run_google_chat` and asserts the literal substring `"_retry_with_backoff"` appears in each.
- **Why it is not a gate:** Source-text presence proxy. The string could appear in a comment, a docstring, or a dead branch and the test passes; conversely a working retry implemented via a differently named helper would fail. It does not prove a transient failure actually triggers a backoff/retry. This is a string-presence proxy for behavior (N9).
- **Recommended fix:** Drive each provider's `chat` with a fake client that raises a retryable error on the first call and succeeds on the second, and assert the call was retried (two invocations, successful result) — proving the backoff wrapper is wired into the live path.

### tests/test_providers/test_registry.py

#### `TestF0005NameToClassMapping.test_register_class_recorded_alongside_instance` — MEDIUM — N8
- **Location:** tests/test_providers/test_registry.py:592
- **Current behavior:** Registers an instance, unregisters it, asserts `unregister(...) is True`, then re-registers a class and asserts `reg.list_registered() == []`. A comment states it deliberately avoids asserting the private class mapping.
- **Why it is not a gate:** The test name claims to verify that `register()` records the concrete class alongside the instance, but it never asserts that the class was recorded. `register_class` (per source line 103) does not add to `list_registered` (that tracks instances), so the final `== []` assertion is just confirming `register_class` alone does not register an instance — unrelated to the claimed "class recorded by register()" behavior. The class-mapping recording that fix F-0005 introduced is left unverified by this test. (`test_register_class_constructs_on_demand` on line 581 is the genuine gate for construction-on-demand.)
- **Recommended fix:** Assert the observable consequence of the class mapping: after `register(instance)` then `unregister`, that the registry can still construct from the remembered class via `connect_provider` — or that `register` followed by `connect_provider` (without an explicit instance) succeeds, which exercises the `_provider_classes` mapping set in `register()` (source line 100).

## Acceptable skips (not flagged)
- tests/test_providers/test_registry_thread_safety_live.py:23 `test_get_provider_registry_thread_safe_singleton` — gated on `INTELLICRACK_LOCAL_TESTS=1`; a deliberate live/threaded opt-in harness, and the test itself is a real gate (32-thread barrier, id-equality on the singleton) when enabled.
- tests/test_providers/test_providers_cloud_audit1.py:193, 916, 951 — live OpenAI/Anthropic tests gated on real API keys; legitimate credential-environment skips, and the offline unit tests cover the same conversion/wiring logic.
- tests/test_providers/test_realcov_10_anthropic_cache.py:186, test_realcov_10_cancel_request.py:96/134, test_realcov_10_google_safety.py:366, test_realcov_10_grok_reasoning_effort.py:168, test_realcov_11_huggingface_logic.py:401 — `@pytest.mark.integration` live tests gated on credentials; the `_skip_if_account_unavailable` helpers skip only on genuine billing/quota/eligibility conditions (re-raising otherwise), which is a legitimate environment-capability skip, not masking of a capability defect. Each has offline real-logic counterparts that gate the parsing/transformation.
- tests/test_providers/test_realcov_10_anthropic_cache.py:235 `test_repeated_cached_prompt_reports_cache_read` — `pytest.skip` when the live API returns no usage metadata; acceptable since usage reporting is a provider-side condition outside Intellicrack's control, and the breakpoint-construction logic is fully gated by the offline `TestApplyCacheBreakpoints` class.
- tests/test_providers/test_realcov_11_gpu_pci.py and test_realcov_11_xpu_utils.py — numerous `pytest.skip` on `not _IS_WINDOWS` / `not is_xpu_available()` / no-GPU-present; these are genuine hardware/OS-capability skips (cfgmgr32 is Windows-only; XPU requires Intel hardware), explicitly the legitimate category. The off-platform branches still assert exact behavior (empty list, zero BAR, RuntimeError).
- tests/test_providers/test_realcov_11_model_loader.py:384 `test_raises_runtime_error_when_xpu_unavailable` — skips when XPU is present; legitimate, since the error path under test is "XPU absent". Real gate (asserts RuntimeError + message) when XPU is genuinely unavailable.
- tests/test_providers/test_realcov_11_local_transformers_logic.py / huggingface_logic.py — `pytest.skip` on absent live models / no servable router model; legitimate environment skips that never produce a false pass, and the deterministic parsing logic is gated offline.
