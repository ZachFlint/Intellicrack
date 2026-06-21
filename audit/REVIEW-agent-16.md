# Review of Agent 16 Audit Findings

This document verifies each finding in `audit/agent-16.md` against the committed code at HEAD.

## Finding Verification

### F-0001: TestBridgeDisplayMode class (lines 42-69)

**Verdict: SATISFIED**

**Evidence:** `tests/test_hexcore_e2e/test_bridge_display.py:42-88`

The tests now include exact value assertions. Line 49: `assert mode == "hex8"`, line 68: `assert mode == "float32"`, line 78: `assert mode == "binary"`, line 88: `assert mode == "dec_u32"`. Each test sets a mode, retrieves it, and asserts the exact value matches. These are genuine gates that would fail if the mode state-tracking regressed.

---

### F-0002: TestBridgeHighlights class (lines 94-177)

**Verdict: PARTIAL**

**Evidence:** `tests/test_hexcore_e2e/test_bridge_display.py:94-177`

The highlight rule tests verify rule presence but not properties. Line 125 asserts the added rule ID is in the list: `assert rule_id in ids`, but does not inspect the returned rule dict to verify condition_type, condition_params, or color. The audit requirement is to assert on all rule properties after retrieval. Tests verify ID presence and removal but skip the property validation against the actual rule object returned by list_highlight_rules().

---

### F-0003: test_validate_javascript_temp_logs_unlink_then_cleaned_only_on_success (line 364-376)

**Verdict: SATISFIED**

**Evidence:** `tests/test_audit3/core/test_script_gen.py:436-456`

The old conditional test is replaced by `test_validate_javascript_emits_cleanup_after_unlink_attempt_on_real_run()`. This test unconditionally asserts cleanup occurred (lines 453-456): no `if` condition that could skip the assertion. The test calls `_require_node()` before the core call (line 446) to skip early if node is unavailable, not after assertion failure. Cleanup is independent of node's verdict, so both success and failure paths must emit the logs unconditionally.

---

### F-0004: test_validate_javascript_unlink_failure_skips_cleaned_log (line 378-388)

**Verdict: SATISFIED**

**Evidence:** `tests/test_audit3/core/test_script_gen.py:481-527`

Replaced by `test_validate_javascript_unlink_failure_suppresses_cleaned_log()`, which drives real production code against real filesystem failures. Instead of mocking `Path.unlink`, it creates a real read-only file (line 503: `Path(path).chmod(stat.S_IREAD)`) and lets the real production cleanup fail. The test then asserts the failure was logged (line 525: `assert "temp_file_unlink_failed" in events`). No mock of the operation under test; the unlink failure is real.

---

### F-0005: TestApplyPipelineSingleStep (lines 86-141)

**Verdict: PARTIAL**

**Evidence:** `tests/test_hexcore_e2e/test_bridge_transforms_deep.py:84-138`

The class includes exact output tests (line 118: `assert result == "00000000"`), but the first test `test_single_xor_step_returns_hex_string` (84-101) only asserts length: `assert len(result) == 8`. This weak assertion would pass even if the pipeline returned garbage data of the correct length. The second test provides a gate with exact output, but the first test itself remains a weak assertion that could be fooled by incorrect implementations.

---

### F-0006: Memory estimation tests (lines 116-199 in original audit)

**Verdict: SATISFIED**

**Evidence:** `tests/test_providers/test_local_transformers_provider.py:210-318`

Replaced with concrete tests using independently-known parameter counts. `test_estimate_phi3_mini_fp16_matches_known_param_size()` (line 225-226): `assert memory == expected` and `assert expected == 9_880_000_000`. The expected value is computed from published parameter counts (3.8B) and IEEE half-precision byte sizes (2 bytes/param), not from the estimator's output. `test_estimate_int8_is_exactly_half_of_fp16()` (line 271): `assert int8_memory * 2 == fp16_memory` verifies the precise 2:1 theoretical ratio. These tests would fail immediately if the estimator broke.

---

### F-0007: test_network_monitor_source_captures_live_endpoints (lines 299-346)

**Verdict: SATISFIED**

**Evidence:** `tests/test_audit7/sandbox_windows/test_realcov_12b_inline_monitors.py:299-346`

The test now has an unconditional assertion that records were captured (line 322): `assert records, f"no network records parsed..."`. The conditional skip at lines 330-343 occurs AFTER checking that at least one record exists. If a loopback connection is held open and the system is networked, the monitor MUST capture records. The skip only applies when no TCP endpoints are found AND the system is network-isolated (cannot expose loopback TCP), not when records are simply missing on a networked host.

---

### F-0008: Live Google Chat integration tests (lines 52-179)

**Verdict: SATISFIED**

**Evidence:** `tests/test_providers/test_google_chat_live.py:64-117`

The helper functions `_run_chat_and_verify()` and `_run_stream_and_verify()` now include deterministic content assertions. Line 85: `assert "ready" in message.content.strip().lower(), f"..."` verifies the API returned content matching the deterministic prompt. RateLimitError (transient) is caught and skipped (line 80-81), but AuthenticationError and ProviderError propagate as failures. Streaming test (line 115) asserts the exact concatenated text contains "ready". These are real gates that would fail if the API returned garbage or the provider broke.

---

### F-0009: test_auto_detect_raw_bytes_raises_unsupported (inferred from line 196-200)

**Verdict: SATISFIED**

**Evidence:** `tests/test_core/test_realcov_07a_disassembler.py:196-212`

The test properly asserts the specific exception type and its properties. Line 210-211: `with pytest.raises(UnsupportedArchitectureError) as exc_info:`. Line 212: `assert exc_info.value.arch == "unknown"`. The error message content (though not explicitly shown in the excerpt) is implicit in the exception class name. The test verifies the exact exception type, not just "an exception".

---

### F-0010: test_type_names_are_deduplicated_and_sorted (lines 128-138)

**Verdict: SATISFIED**

**Evidence:** `tests/test_ui/test_realcov_13b_hex_pattern_code_editor.py:128-138`

The test assertion on line 138 is correct. Input `["u32", "u32", "u16", "u8", "u16"]` is deduplicated to `{"u32", "u16", "u8"}` and sorted alphabetically. Python string sorting compares lexicographically: "u16" < "u32" because '1' < '3', and "u32" < "u8" because '3' < '8'. The expected list `["u16", "u32", "u8"]` is the correct sorted order. The production code (line 69 of `pattern_code_editor.py`): `self._model.setStringList(sorted(set(names)))` performs exactly this operation. The audit finding's claim that u8 should come before u16 is incorrect; it is alphabetically after. The test is a genuine gate verifying deduplication and sorting occur.

---

## Tally

| Verdict       | Count |
|---------------|-------|
| SATISFIED     | 8     |
| PARTIAL       | 2     |
| NOT-SATISFIED | 0     |
| UNVERIFIABLE  | 0     |

**Total findings reviewed: 10**
**8 satisfied, 2 partially satisfied.**

**Partial findings:**
- F-0002 (Highlights): tests verify rule presence but not returned rule properties (condition_type, condition_params, color)
- F-0005 (Transforms): first test in class only checks length, not value; later tests check exact output
