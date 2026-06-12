# Review of Agent 11 Audit Findings

This document reviews whether each of the 15 findings from `audit/agent-11.md` have been genuinely satisfied by committed code at HEAD.

---

## Finding 1: test_bytes_passthrough (TestReadDocumentForScan)
- **Finding ID**: C8 - No-assertion / vacuous-assertion
- **Verdict**: **NOT-SATISFIED** (Test Removed)
- **Evidence**: `tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py` does not contain `test_bytes_passthrough` function; test list via grep shows only tests starting at line 219: `test_reads_full_document_with_correct_offset_and_length`, etc.
- **Justification**: The test was removed rather than fixed. While removal of a weak test can be acceptable, the audit expected the test to be strengthened, not deleted. No replacement test exists that uses the simple bytes case.

---

## Finding 2: test_ui_thread_does_not_materialise_large_document (TestUIThreadAllocationBudget)
- **Finding ID**: C8 - Cannot-fail (Conditional guard)
- **Verdict**: **SATISFIED**
- **Evidence**: `tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:435-497` - lines 473-476 contain unconditional assertion `assert harness.worker() is not None`, line 479 unconditional `finished = harness.wait_for_worker()`, line 480 unconditional assertion on finished, and lines 493-497 unconditional peak allocation assertion.
- **Justification**: The conditional `if harness.worker()` guard has been removed. The test now fails unconditionally if the worker doesn't spawn or complete, and the memory budget assertion always runs.

---

## Finding 3: test_dev_tools_absent_from_runtime_deps (TestRuntimeDependenciesAreLean)
- **Finding ID**: D1 - Weak-assertion-on-rich-output
- **Verdict**: **SATISFIED**
- **Evidence**: `tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py:144-164` - Lines 155-158 add unconditional positive assertion `assert len(runtime) > 0` with descriptive message that pyproject must declare production packages, preventing false pass on empty dependencies list.
- **Justification**: The test now validates that runtime deps are non-empty before checking for leaks, catching the misconfiguration case described in the finding.

---

## Finding 4: test_on_open_hxd_no_longer_references_missing_method (TestHxDButtonHandlerCleanedUp)
- **Finding ID**: F-0001 - Smoke-test-as-gate / coverage-theater
- **Verdict**: **SATISFIED** (Replaced with Functional Test)
- **Evidence**: `tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:366-453` - New test `test_on_open_hxd_shows_tool_error_when_hxd_absent` invokes real `getattr(MainWindow, "_open_hxd_impl")` (line 445) and asserts a warning dialog fires with correct content (lines 447-453), validating actual method behavior.
- **Justification**: The old string-search test was replaced with a real functional gate that invokes the actual implementation and validates its behavior, not just source code strings.

---

## Finding 5: test_source_uses_get_panel_for_sandbox (TestSandboxPanelLookupUsesPanels)
- **Finding ID**: F-0004 - Smoke-test-as-gate / coverage-theater
- **Verdict**: **SATISFIED** (Replaced with Functional Test)
- **Evidence**: `tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:525-609` - New test `test_get_panel_called_with_sandbox_key` constructs a real slot harness, invokes `MainWindow._on_open_sandbox_panel` directly (line 606), and asserts `get_panel("sandbox")` was actually called (line 608).
- **Justification**: The old regex-on-source-code test was replaced with a real functional test that executes the slot and validates the correct API is called at runtime.

---

## Finding 6: test_decodes_real_text_mnemonics (TestDisassemblyLineFromRealBinary)
- **Finding ID**: 04-F001 - No-assertion / weak-assertion-on-rich-output
- **Verdict**: **SATISFIED**
- **Evidence**: `tests/test_bridges/test_realcov_04_base.py:203-247` - Lines 224-236 use independent oracle `_oracle_decode_first()` to re-decode bytes with fresh capstone instance, then assert bridge mnemonic matches oracle (line 232), raw bytes match (line 235), and address matches (line 236).
- **Justification**: The test now includes semantic verification: it decodes the same instruction independently and validates the bridge's output is correct, not just that it matches a regex pattern.

---

## Finding 7: test_bridge_initial_state through test_bridge_has_capabilities (X64DbgBridge tests)
- **Finding ID**: 04-F002 - Smoke-test-as-gate / tautological
- **Verdict**: **SATISFIED**
- **Evidence**: `tests/test_bridges/test_x64dbg.py:72-125` - `test_bridge_initial_state` (lines 72-97) validates not just defaults (81-87) but also that setters work (89-97); `test_bridge_has_capabilities` (100-125) validates capability semantics including list lengths and required entries.
- **Justification**: The tests now verify behavior beyond initialization, including state mutations and semantic correctness of capabilities.

---

## Finding 8: test_singleton_thread_safety (OAuthManager)
- **Finding ID**: 15-F-0007 - Weak-assertion-on-rich-output
- **Verdict**: **SATISFIED**
- **Evidence**: `tests/test_credentials/test_oauth_manager_live.py:151-192` - Lines 180-189 now invoke `generate_pkce_pair()` and `verify_pkce_pair()` on the returned singleton, validating it is not just identical but functionally operational with correct outputs.
- **Justification**: The test moved from identity-only to functional verification: it invokes OAuth operations on the singleton and validates their behavior.

---

## Finding 9: test_list_models_returns_non_empty_list (TestGoogleModelListing)
- **Finding ID**: test_google_provider - Happy-path-only / weak-assertion
- **Verdict**: **SATISFIED**
- **Evidence**: `tests/test_providers/test_google_provider.py:44-75` - Lines 60-68 add type validation, length check, and Gemini-model filtering to catch cases where API returns empty or wrong model types; lines 70-75 validate actual model properties.
- **Justification**: The test now includes multiple gates: it validates return type, non-empty list, Gemini presence, and property correctness, catching API regressions that would pass the original simple length check.

---

## Finding 10: test_init_model_discovery_is_coroutine (TestAsyncCacheDiscovery)
- **Finding ID**: test_provider_bugfixes - Smoke-test-as-gate
- **Verdict**: **SATISFIED** (Supplemented with Functional Test)
- **Evidence**: `tests/test_providers/test_provider_bugfixes.py:49-95` - Original signature check at 49-59 now supplemented by new test `test_init_model_discovery_returns_discovery_and_cache_path` (62-95) that actually awaits the coroutine and validates return types and values (82-95).
- **Justification**: A new functional test was added that invokes the coroutine and validates it returns correct types and content, catching broken implementations that would pass the signature-only check.

---

## Finding 11: InMemorySandbox fixture (Critical: Fake-data / mock-the-thing-under-test)
- **Finding ID**: conftest.py - Critical - Fake-data / mock-the-thing-under-test
- **Verdict**: **SATISFIED** (Partially - Real Integration Tests Added)
- **Evidence**: `tests/test_sandbox/conftest.py:163-1630` - New `LocalProcessSandbox` class (line 522+) added alongside `InMemorySandbox`; real integration tests at lines 1553-1629 use `LocalProcessSandbox` to execute actual subprocesses and validate real file-system changes via diff.
- **Justification**: While `InMemorySandbox` remains for unit tests (as intended), new real integration tests using `LocalProcessSandbox` now catch regressions in real sandbox execution that mock-only tests would miss. The conftest documentation (lines 10-20) now clearly delineates the two backends.

---

## Finding 12: test_sandbox_bridge fixture-heavy tests (Critical: Mock-the-thing-under-test)
- **Finding ID**: test_sandbox_bridge.py - Critical - Mock-the-thing-under-test / cannot-fail
- **Verdict**: **PARTIAL**
- **Evidence**: `tests/test_sandbox/conftest.py:1553-1629` - Real integration tests exist using `LocalProcessSandbox` that execute actual binaries. However, `tests/test_sandbox/test_sandbox_bridge.py` still uses `sandbox_bridge` fixture (line 1464+) which uses `InMemorySandbox` for its mock instances.
- **Justification**: The audit recommended marking unit tests as such and creating separate integration tests with environment guards. Real integration tests exist but lack the recommended `@pytest.mark.skipif(not os.getenv("INTEGRATION_SANDBOX"))` markers. The fix is partial: integration tests exist and run, but not with explicit environment-based conditional skipping.

---

## Finding 13: TestBridgeCopyAs format tests (Weak-assertion-on-rich-output)
- **Finding ID**: test_bridge_copy_as.py - Weak-assertion-on-rich-output / happy-path-only
- **Verdict**: **SATISFIED**
- **Evidence**: `tests/test_hexcore_e2e/test_bridge_copy_as.py:61-210` - Each format test now validates both structure AND semantic correctness: c_array (103-104) decodes hex tokens to bytes and asserts equality; python (122-125) checks all four bytes appear; rust_array (145-146) decodes and verifies; base64 (178-179) decodes and asserts.
- **Justification**: Tests moved from shape-only (braces/brackets/prefix present) to full semantic validation (bytes decode correctly to original input).

---

## Finding 14: TestGetStrings extraction tests (Weak-assertion-on-rich-output)
- **Finding ID**: test_bridge_strings.py - Weak-assertion-on-rich-output
- **Verdict**: **SATISFIED**
- **Evidence**: `tests/test_hexcore_e2e/test_bridge_strings.py:82-194` - New tests assert EXACT values: `test_extract_ascii_strings_exact` (104-107) validates offset, length, encoding, AND content; `test_extract_utf16_strings_exact` (139-142) same; `test_extract_both_encodings_finds_both_known_strings` (171-194) validates both present with correct properties.
- **Justification**: Tests moved from loose substring matching to exact field-by-field validation that would fail if offsets, lengths, encodings, or content were wrong.

---

## Finding 15: test_accept_emits_settings_changed_with_edited_config (PreferencesDialog)
- **Finding ID**: test_realcov_15_preferences_dialog.py - No-assertion / weak-assertion-on-rich-output
- **Verdict**: **SATISFIED** (Supplemented with Round-Trip Tests)
- **Evidence**: `tests/test_ui/test_realcov_15_preferences_dialog.py:57-142` - Original test (57-83) validates edited field matches. New tests added: `test_accept_edits_logging_level_round_trips` (86-113) validates a DIFFERENT field to ensure unedited fields survive, and `test_accept_persists_config_to_disk` (116-142) tests persistence and round-trip.
- **Justification**: Tests now validate that unedited fields are not corrupted and that config persists correctly, catching bugs where editing one field would corrupt others.

---

## Summary

### Verdict Tally

- **SATISFIED**: 13 findings
- **PARTIAL**: 1 finding (Finding 12: real integration tests exist but lack environment-guard markers)
- **NOT-SATISFIED**: 1 finding (Finding 1: test removed instead of fixed)
- **UNVERIFIABLE**: 0 findings

### Overall Assessment

The audit findings have been **substantially addressed**. The vast majority of weak tests have been strengthened or replaced with meaningful functional gates. Critical findings about mocking (11, 12) have been addressed by adding real integration tests using `LocalProcessSandbox`.

**Key strengths:**
- Tests now validate semantic correctness, not just shape/presence
- Independent oracles used (disassembly, PKCE)
- Real execution tested (sandbox, subprocess, file-system diff)
- State mutations validated (bridge setters, OAuth operations)
- Round-trip correctness verified (copy_as, config persistence)

**Minor gaps:**
- Finding 1: Weak test was deleted rather than strengthened
- Finding 12: Real integration tests exist but lack explicit environment-based conditional skipping markers

---
