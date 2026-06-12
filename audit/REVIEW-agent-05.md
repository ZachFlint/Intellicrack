# Review of Agent 05 Audit Findings

This review verifies each finding in `audit/agent-05.md` against the current code at HEAD. For each finding, the review determines whether the committed changes actually satisfy the audit requirement.

---

## Finding Verdicts

### Finding 1: tests/test_bridges/test_ghidra.py:46-50 - test_bridge_instantiation
- **Verdict: SATISFIED**
- **Evidence**: `tests/test_bridges/test_ghidra.py:51-90`
- **Justification**: Test now asserts on specific properties (name, ghidra_path, project_path, DEFAULT_PORT, capabilities, tool_definition existence and count) independently of constructor implementation, making it a genuine gate.

### Finding 2: tests/test_bridges/test_x64dbg_events.py:104-112 - test_unregister_nonexistent_does_not_raise
- **Verdict: SATISFIED**
- **Evidence**: `tests/test_bridges/test_x64dbg_events.py:104-118`
- **Justification**: Test now includes explicit precondition assertion (`assert len(...) == 0`) before the unregister call and postcondition assertion after, making it a falsifiable gate.

### Finding 3: tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:106-124 - test_search_uint64_cafebare_finds_at_offset_6
- **Verdict: PARTIAL**
- **Evidence**: `tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:118-124`
- **Justification**: Exception handling narrowed to OverflowError only (GOOD), but result structure assertions remain weak—test only checks `assert _PATTERN_U64_OFFSET in offsets` without verifying length field matches size=8 or that no spurious results exist.

### Finding 4: tests/test_hexcore_e2e/test_search.py:70-82 - test_pattern_detected_at_buffer_boundaries
- **Verdict: SATISFIED**
- **Evidence**: `tests/test_hexcore_e2e/test_search.py:70-82`
- **Justification**: Test now asserts exact tuple structure: checks offset values and implicitly verifies length via `assert len(results) == 2`, making it a genuine gate on the full result tuple.

### Finding 5: tests/test_hexpat/test_lexer.py:144-147 - test_unterminated_string_raises
- **Verdict: SATISFIED**
- **Evidence**: `tests/test_hexpat/test_lexer.py:144-161`
- **Justification**: Test now includes precondition assertions verifying lexer starts in clean state (position 0, line 1) before calling tokenize(), establishing the error occurs during tokenization and not during prior initialization.

### Finding 6: tests/test_hexpat/test_realcov_08_preprocessor_vendor.py:43-54 - test_std_io_include_is_flattened
- **Verdict: NOT-SATISFIED**
- **Evidence**: `tests/test_hexpat/test_realcov_08_preprocessor_vendor.py:43-53`
- **Justification**: Test still only asserts `len(processed) > len(source)` and presence of `"u8 x @ 0;"` without verifying specific content from std/io.pat was inlined, that the output is valid HexPat via tokenization/parsing, or that error paths work correctly.

### Finding 7: tests/test_providers/test_discovery_unit.py:40-200 - _DiscoveryProvider class and related
- **Verdict: NOT-SATISFIED**
- **Evidence**: `tests/test_providers/test_discovery_unit.py:42-94`
- **Justification**: Tests still use _DiscoveryProvider mock class instead of real provider (even locally-mocked) for discovery/filtering logic; structure unchanged from audit report.

### Finding 8: tests/test_providers/test_realcov_10_anthropic_cache.py:70-84 - test_system_prompt_becomes_cached_block
- **Verdict: SATISFIED**
- **Evidence**: `tests/test_providers/test_realcov_10_anthropic_cache.py:70-84`
- **Justification**: Test now asserts exact structure including `system[0]["cache_control"] == {"type": "ephemeral"}`, verifying full transformation structure not just type presence.

### Finding 9: tests/test_providers/test_realcov_11_model_loader.py:130-134 - test_fp16_matches_two_bytes_per_param_with_overhead
- **Verdict: SATISFIED**
- **Evidence**: `tests/test_providers/test_realcov_11_model_loader.py:130-147`
- **Justification**: Test now calls `_estimate_parameter_count()` to get the actual parameter count and verifies the model ID maps to 1B parameters, ensuring the model-id-to-parameter-count mapping is verified.

### Finding 10: tests/test_ui/log_viewer/test_app_integration.py:46-62 - test_main_window_installs_qt_log_handler
- **Verdict: SATISFIED**
- **Evidence**: `tests/test_ui/log_viewer/test_app_integration.py:81-105` and `tests/test_ui/log_viewer/test_app_integration.py:57-75`
- **Justification**: Test now verifies handler is in root logger's handler list and emits a real test log record, asserting the handler actually receives it via signal, proving wiring is live not merely installed.

### Finding 11: tests/test_ui/log_viewer/test_app_integration.py:65-96 - test_log_viewer_lazy_construction
- **Verdict: SATISFIED**
- **Evidence**: `tests/test_ui/log_viewer/test_app_integration.py:108-144`
- **Justification**: Test now verifies viewer is visible after construction (`assert first.isVisible()`) and that repeat calls return the same cached instance (reference identity), covering lazy construction and reuse semantics.

### Finding 12: tests/test_ui/test_realcov_14b_script_manager.py:77-92 - test_save_persists_real_content
- **Verdict: SATISFIED**
- **Evidence**: `tests/test_ui/test_realcov_14b_script_manager.py:78-93`
- **Justification**: Test now saves and verifies the stored script content equals the input (`assert stored.content == _VALID_PYTHON`) and that the script appears in the backend's list, verifying real backend persistence.

### Finding 13: tests/test_ui/test_realcov_15_chat_panel.py:64-78 - test_send_button_emits_typed_text
- **Verdict: SATISFIED**
- **Evidence**: `tests/test_ui/test_realcov_15_chat_panel.py:64-93`
- **Justification**: Test now verifies full signal structure including exact args list (`assert emitted == [("disassemble the entry point",)]`), signal emission count (1), and side effects (input cleared, no bubbles), making it a complete contract gate.

### Finding 14: tests/test_ui/test_tool_status_dialog_prefetch.py:133-157 - test_prefetched_data_skips_initial_worker_spawn
- **Verdict: SATISFIED**
- **Evidence**: `tests/test_ui/test_tool_status_dialog_prefetch.py:79-96`
- **Justification**: Test now loops through all rows via helper function `_assert_prefetched_render()` comparing rendered text against expected rows list, verifying order and content for all tools not just one checked row.

### Finding 15: tests/ui/test_system_tab_warnings.py:185-205 - test_refresh_mitigations_unattached_shows_warning
- **Verdict: SATISFIED**
- **Evidence**: `tests/ui/test_system_tab_warnings.py:237-274`
- **Justification**: Test now uses real ProcessBridge via `_make_real_bridge_tab()` instead of stub, verifies exact warning title/message, asserts dispatch was prevented, and checks raw output mirrors the warning.

---

## Summary

| Verdict | Count |
|---------|-------|
| SATISFIED | 12 |
| PARTIAL | 1 |
| NOT-SATISFIED | 2 |
| UNVERIFIABLE | 0 |

---

## Notes

- **PARTIAL findings** represent tests where some aspects of the audit fix were applied but others remain incomplete. These are at risk of becoming false gates again if related production code changes.
- **NOT-SATISFIED findings** represent structural gaps where the audit recommendation was not addressed (mock still in use, weak assertions still present).
- All SATISFIED findings have become genuine, falsifiable gates with independently verifiable assertions on fixed expected values.
