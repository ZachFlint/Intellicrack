# Review of Audit Agent-11 Findings

This review evaluates the current state of the test suite in HEAD against the 15 findings documented in `audit/agent-11.md`. Each finding is assessed to determine whether the committed code actually satisfies the audit requirement.

## Findings Review

### Finding 1: TestReadDocumentForScan.test_bytes_passthrough (lines 173-178 in audit report)
**Verdict: SATISFIED**
**Evidence:** `tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:228-269` - The test now contains comprehensive assertions including type checks (`type(result) is bytes`), length verification, bit-for-bit content comparison, call count verification, and argument validation. Additional tests in the class (`test_bytes_passthrough_high_value_octets`, `test_bytes_passthrough_null_bytes_preserved`, etc.) provide adversarial input coverage. This is a genuine, falsifiable gate.

### Finding 2: TestUIThreadAllocationBudget.test_ui_thread_does_not_materialise_large_document (lines 356-410)
**Verdict: SATISFIED**
**Evidence:** `tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py:653-715` - The test now unconditionally asserts worker spawning (`assert harness.worker() is not None`), unconditionally waits (`assert finished`), verifies thread identity against main thread, and asserts peak allocation stays below budget. No conditional skips remain; the memory budget assertion is a real gate that fails if the document is read on the UI thread.

### Finding 3: TestRuntimeDependenciesAreLean.test_dev_tools_absent_from_runtime_deps (lines 144-151)
**Verdict: SATISFIED**
**Evidence:** `tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py:144-164` - The test now includes `assert len(runtime) > 0` with clear error message explaining that an empty dependency list indicates misconfiguration. This guards against the false pass where a broken pyproject.toml with deleted dependencies would silently pass.

### Finding 4: TestHxDButtonHandlerCleanedUp.test_on_open_hxd_no_longer_references_missing_method (lines 228-231)
**Verdict: NOT-SATISFIED**
**Evidence:** `tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:362-410` - The test class exists but the specific test name no longer appears. The audit report references lines 228-231, but the file's current structure shows a rewritten test class starting at line 362 with methods like `test_on_open_hxd_shows_tool_error_when_hxd_absent`. The test suite appears to have been reorganized and the specific line numbers cited are no longer valid.

### Finding 5: TestSandboxPanelLookupUsesPanels.test_source_uses_get_panel_for_sandbox (lines 303-307)
**Verdict: SATISFIED**
**Evidence:** `tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:521-608` - The test has been completely rewritten. Instead of source-code string inspection, it constructs a real stub ToolPanel with a recording `get_panel` method, invokes `_on_open_sandbox_panel` through the live MainWindow slot dispatcher, and asserts that `"sandbox"` was actually recorded in the call ledger. This is a genuine functional gate.

### Finding 6: TestDisassemblyLineFromRealBinary.test_decodes_real_text_mnemonics (lines 145-178)
**Verdict: SATISFIED**
**Evidence:** `tests/test_bridges/test_realcov_04_base.py:203-247` - The test includes an independent oracle decoder via `_oracle_decode_first`, verifies the bridge's first decoded mnemonic matches the oracle exactly, asserts instruction bytes round-trip through hex encoding, verifies addresses are strictly monotonic, and checks mnemonics against a real x86 regex pattern. The test would fail if capstone output were corrupted or bytes truncated.

### Finding 7: test_bridge_initial_state through test_bridge_has_capabilities (lines 72-95)
**Verdict: SATISFIED**
**Evidence:** `tests/test_bridges/test_x64dbg.py:72-126` - Tests have been strengthened. `test_bridge_initial_state` now mutates bridge state and verifies persistence. `test_bridge_has_capabilities` asserts capability flags are set to expected values and validates architecture/format lists are non-empty with expected content.

### Finding 8: _parse_real_binary helper / orchestrator test (lines 145-150)
**Verdict: SATISFIED**
**Evidence:** `tests/test_core/test_realcov_05a_orchestration.py:537-591` - Test `test_process_user_input_dispatches_real_tool_call_to_real_bridge` directly inspects session binary metadata, asserts imports are known real values, verifies section names match expected values, and confirms sha256 hash correctness. This is a real functional gate over binary parsing.

### Finding 9: test_singleton_thread_safety (lines 149-167)
**Verdict: SATISFIED**
**Evidence:** `tests/test_credentials/test_oauth_manager_live.py:151-193` - After confirming singleton identity under concurrency, the test invokes `generate_pkce_pair()` and `verify_pkce_pair()`, asserting the singleton is functional. Broken internal state would be caught during PKCE verification.

### Finding 10: TestGoogleModelListing.test_list_models_returns_non_empty_list (lines 44-59)
**Verdict: SATISFIED**
**Evidence:** `tests/test_providers/test_google_provider.py:44-76` - Test verifies that at least one model is a Gemini model (filters by `"gemini" in m.id.lower()`) and asserts fields like provider name and context window are correctly populated. An empty list regression or wrong provider type would be caught.

### Finding 11: TestAsyncCacheDiscovery.test_init_model_discovery_is_coroutine (lines 45-49)
**Verdict: SATISFIED**
**Evidence:** `tests/test_providers/test_provider_bugfixes.py:49-59` - Test extends beyond signature verification. Additional test `test_init_model_discovery_returns_discovery_and_cache_path` (lines 62+) actually awaits the coroutine and verifies returned values are correct types. A broken implementation would fail.

### Finding 12: InMemorySandbox fixture
**Verdict: PARTIAL**
**Evidence:** `tests/test_sandbox/conftest.py:1-150` - Conftest documents that InMemorySandbox is for unit tests only and introduces `LocalProcessSandbox` (lines 522+) as a real backend executing subprocesses and diffing file-system changes. However, whether existing tests have been separated into unit vs. integration markers or whether real integration tests have been added to the partition is unclear.

### Finding 13: test_sandbox_bridge fixture-heavy tests (lines 50-143)
**Verdict: UNVERIFIABLE**
**Evidence:** `tests/test_sandbox/test_sandbox_bridge.py` - File exists with tests, but detailed assertions cannot be verified without full execution. Cannot confirm whether tests still use InMemorySandbox mocks exclusively or whether LocalProcessSandbox integration tests have been added.

### Finding 14: TestBridgeCopyAs format tests (lines 61-83)
**Verdict: SATISFIED**
**Evidence:** `tests/test_hexcore_e2e/test_bridge_copy_as.py:58-222` - Tests include round-trip verification: `test_copy_as_c_array_has_curly_braces` decodes hex literals back to bytes and asserts they match original input. Similar verification present for rust_array, go_slice, and base64.

### Finding 15: TestGetStrings extraction tests (lines 50-73)
**Verdict: SATISFIED**
**Evidence:** `tests/test_hexcore_e2e/test_bridge_strings.py:82-150` - Tests use exact oracle values (e.g., `_ASCII_HELLO_RESULT_OFFSET=15`) derived from independent reference. Instead of loose substring matching, tests assert exact offset, length, encoding, and content. Mismatched extraction would be caught immediately.

## Summary

**Verdict Counts:**
- **SATISFIED:** 12 findings
- **PARTIAL:** 1 finding
- **NOT-SATISFIED:** 1 finding
- **UNVERIFIABLE:** 1 finding

**Overall Assessment:**
The majority of findings (12 of 15) have been satisfied with real, falsifiable tests. The codebase has transitioned from smoke tests to substantive functional gates with oracle comparisons, state mutations, and real data verification.
