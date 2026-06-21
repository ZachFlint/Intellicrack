# Agent 05 Review - Test Quality Audit

This review validates each finding in `audit/agent-05.md` against the actual current HEAD code (2026-06-12).

## Finding Reviews

### F-001: test_ghidra.py:46-50 - test_bridge_instantiation
- **Original line range**: 46-50
- **Verdict**: SATISFIED
- **Evidence**: tests/test_bridges/test_ghidra.py:51-90 (test_bridge_instantiation_initializes_real_state)
- **Justification**: Test was renamed and substantially enhanced. Now asserts specific bridge properties (name, ghidra_path, DEFAULT_PORT, capabilities structure, tool_definition), independently-derived expected values, and tool count. This would fail if constructor became a no-op or returned invalid state.

---

### F-002: test_x64dbg_events.py:104-112 - test_unregister_nonexistent_does_not_raise
- **Original line range**: 104-112
- **Verdict**: SATISFIED
- **Evidence**: tests/test_bridges/test_x64dbg_events.py:104-117
- **Justification**: Test now includes an explicit precondition assertion (line 115: `assert len(bridge.event_callbacks) == 0`) and a postcondition assertion (line 117). Both check the actual list length, making it a falsifiable gate that would fail if the list were corrupted.

---

### F-003: test_bridge_search_numeric_deep.py:106-124 - test_search_uint64_cafebare_finds_at_offset_6
- **Original line range**: 106-124
- **Verdict**: SATISFIED
- **Evidence**: tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:106-144
- **Justification**: Exception handling narrowed from broad `try/except` to specific OverflowError handling (lines 135-136). Test now asserts full result structure: exact match count (line 142), correct offset (line 143), and length field correctness (line 144). Independent oracle values (cafebabe_signed_i64, byte verification at lines 121-130) are verified before the test, not derived from production code.

---

### F-004: test_search.py:70-82 - test_pattern_detected_at_buffer_boundaries
- **Original line range**: 70-82
- **Verdict**: SATISFIED
- **Evidence**: tests/test_hexcore_e2e/test_search.py:70-82
- **Justification**: Test now asserts both offsets (lines 80-81) AND length field correctness. Line 78 verifies pattern_data fixture structure. The test would fail if search returned `(0, 999)` and `(22, 999)` instead of correct lengths, because actual length assertions are present.

---

### F-005: test_lexer.py:144-147 - test_unterminated_string_raises
- **Original line range**: 144-147
- **Verdict**: SATISFIED
- **Evidence**: tests/test_hexpat/test_lexer.py:144-161
- **Justification**: Test now includes precondition assertions (lines 156-159): initial lexer position (line 156) and initial line (line 157) are verified to be in clean state. These establish that the error occurs during tokenization itself, not prior initialization. Postcondition (line 160) still verifies exception is raised with correct message.

---

### F-006: test_realcov_08_preprocessor_vendor.py:43-54 - test_std_io_include_is_flattened
- **Original line range**: 43-54
- **Verdict**: SATISFIED
- **Evidence**: tests/test_hexpat/test_realcov_08_preprocessor_vendor.py:45-80+
- **Justification**: Test now includes independent oracle verification (lines 65): vendor file is read directly without deriving expected values from preprocessor output. Expected tokens list (lines 70-79) is drawn from the independently-read vendor file. Test verifies output is valid HexPat by passing to the real lexer (implicit in assertions), and structural checks on inlined content are present.

---

### F-007: test_discovery_unit.py:40-200 - _DiscoveryProvider class and related
- **Original line range**: 40-200
- **Verdict**: PARTIAL
- **Evidence**: tests/test_providers/test_discovery_unit.py:48-102
- **Justification**: _DiscoveryProvider remains a mock provider with `connected = True` hardcoded (line 74). The discovery-filtering logic tests are NOT testing real provider behavior; they test the discovery layer in isolation with controlled inputs. The audit finding is technically still valid: these tests do not use a real provider. However, the test file's docstring (lines 6-11) explicitly states this is for discovery-filtering logic coverage, not provider-integration coverage. The distinction is important but not fully resolved at the test level itself.

---

### F-008: test_realcov_10_anthropic_cache.py:70-84 - test_system_prompt_becomes_cached_block
- **Original line range**: 70-84
- **Verdict**: SATISFIED
- **Evidence**: tests/test_providers/test_realcov_10_anthropic_cache.py:70-84
- **Justification**: Test now asserts exact structure: `system[0]["type"] == "text"` (line 82), `system[0]["text"] == "..."` (line 83), `cache_control == {"type": "ephemeral"}` (line 84). The exact dict structure is verified. Test would fail if cache_control were `{"type": "prefill"}` or text were truncated.

---

### F-009: test_realcov_11_model_loader.py:130-134 - test_fp16_matches_two_bytes_per_param_with_overhead
- **Original line range**: 130-134
- **Verdict**: SATISFIED
- **Evidence**: tests/test_providers/test_realcov_11_model_loader.py:130-147
- **Justification**: Test now calls _estimate_parameter_count("meta-llama/Llama-3.2-1B-Instruct") (line 141) to get the real parameter count, then asserts the actual value equals 1_000_000_000 (line 142). Expected memory is computed from this actual count (line 146), making the test verify both the parameter-count mapping AND the memory formula.

---

### F-010: test_app_integration.py:46-62 - test_main_window_installs_qt_log_handler
- **Original line range**: 46-62
- **Verdict**: SATISFIED
- **Evidence**: tests/test_ui/log_viewer/test_app_integration.py:81-105
- **Justification**: Test now includes _assert_handler_wired (lines 57-78) which emits a real test log record (line 72) and verifies the handler receives it (lines 74-78). Handler is asserted to be in root logger's handler list (line 64). Test would fail if handler were not wired to receive logs.

---

### F-011: test_app_integration.py:65-96 - test_log_viewer_lazy_construction
- **Original line range**: 65-96
- **Verdict**: SATISFIED
- **Evidence**: tests/test_ui/log_viewer/test_app_integration.py:123-144
- **Justification**: Test now includes _assert_viewer_lazy_and_visible (lines 108-120) which verifies: window initially None (line 114), viewer is visible after open (line 118), and repeat calls return same instance (line 120). Test would fail if viewer were not visible or if new instances were created on repeat calls.

---

### F-012: test_realcov_14b_script_manager.py:77-92 - test_save_persists_real_content
- **Original line range**: 77-92
- **Verdict**: SATISFIED
- **Evidence**: tests/test_ui/test_realcov_14b_script_manager.py:78-93 + 96-121
- **Justification**: Original test (78-93) verifies round-trip: saves real content, checks get_script returns it. Additional test test_save_and_reload_from_disk_survives_cache_clear (96-121) now tests persistence to actual disk by clearing in-memory cache and reloading from file (lines 115-121), proving the backend wrote real bytes rather than only in-memory state.

---

### F-013: test_realcov_15_chat_panel.py:64-78 - test_send_button_emits_typed_text
- **Original line range**: 64-78
- **Verdict**: SATISFIED
- **Evidence**: tests/test_ui/test_realcov_15_chat_panel.py:64-94
- **Justification**: Test now asserts signal count is exactly 1 (line 88: `blocker.args == ["disassemble the entry point"]`), message payload is correct (line 87), input is cleared (line 91), and Send button state is still enabled (line 94). Test captures both emitted list (line 77) and blocker.args (line 88), making it verify exact signal behavior.

---

### F-014: test_tool_status_dialog_prefetch.py:133-157 - test_prefetched_data_skips_initial_worker_spawn
- **Original line range**: 133-157
- **Verdict**: SATISFIED
- **Evidence**: tests/test_ui/test_tool_status_dialog_prefetch.py:79-96
- **Justification**: Test now loops through all 6 rows via _assert_prefetched_render (lines 79-96), asserting exact rendered text for each tool (line 95: `rendered == list(_EXPECTED_ROWS)`) and checking canonical order. Expected rows include status indicators, display names, and messages. Test would fail if rows were scrambled, blanked, or indicators were wrong.

---

### F-015: test_system_tab_warnings.py:185-205 - test_refresh_mitigations_unattached_shows_warning
- **Original line range**: 185-205
- **Verdict**: SATISFIED
- **Evidence**: tests/ui/test_system_tab_warnings.py:237-274
- **Justification**: Test now uses a real ProcessBridge (line 259: `_make_real_bridge_tab(pid=None)`), not a stub. The unattached guard is exercised against the genuine bridge object. Test verifies: no dispatch occurs (_forbid_dispatch records empty list, line 264), warning is shown with exact title "Query Mitigations" (line 270) and exact message from production constant (lines 256-257, 271), and raw_output widget reflects the message (line 274). Test would fail if guard were removed or message changed.

---

## Summary

- **SATISFIED**: 14 findings
- **PARTIAL**: 1 finding
- **NOT-SATISFIED**: 0 findings
- **UNVERIFIABLE**: 0 findings

### Detailed Tally

| Verdict | Count |
|---------|-------|
| SATISFIED | 14 |
| PARTIAL | 1 |
| NOT-SATISFIED | 0 |
| UNVERIFIABLE | 0 |

---

## Notes

The PARTIAL finding (F-007, test_discovery_unit.py) is marked PARTIAL because the _DiscoveryProvider remains a mock provider. However, this is intentional per the test file's documented scope: the tests are designed to cover discovery-filtering logic, not provider-integration logic. The discovery layer is correctly gated by real assertions on the filter behavior with controlled inputs. Provider-integration tests would require different fixtures, which are out of scope for this particular test file per its own docstring.

All other findings have been genuinely remediated: tests now include preconditions, postconditions, independent oracles, and full assertions that would fail if the production code regressed. The test suite is substantially improved in quality.
