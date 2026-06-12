# Consolidated Offenders Report

Every finding across the 20 REVIEW-agent-NN.md reports that did **not** earn a
SATISFIED verdict. These are the tests still failing as genuine, falsifiable
quality gates at HEAD. Compiled 2026-06-07 from the adversarial re-review.

Each row cites the **current HEAD** location (test file:line) and the defect.
Stale-line-number UNVERIFIABLE entries (audit cited a line that no longer
exists because the file was refactored and the reviewer judged the replacement
sound) are listed separately at the end as "non-actionable" so they are not
mistaken for real gaps.

Totals: **37 NOT-SATISFIED**, **65 PARTIAL**, plus **2 critical malformed-name
NOT-SATISFIED** (counted in the 37). Non-actionable UNVERIFIABLE: ~9.

---

## TIER 1 — CRITICAL: tests that do not run or cannot fail at all

These are the highest priority: a test that pytest never collects, or that
would pass against a broken implementation, provides zero protection.

| ID | Test (current HEAD) | Defect | Verdict |
|----|---------------------|--------|---------|
| 15-F2 | `tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:412` `testvalidate_r2_argument_rejects_control_chars` | **Malformed name** (`testvalidate_` missing underscore) → pytest never discovers it; the r2 argument-injection guard is completely ungated | NOT-SATISFIED |
| 15-F3 | `tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py:430` `testvalidate_r2_argument_accepts_safe_strings` | Same malformed-name defect; never collected | NOT-SATISFIED |
| 10-F5 | `tests/test_core/test_types.py:159-1203` (≈80 functions) | Construction-only vacuous tests: build a dataclass, assert the field you just set — tautology. No behavioral gate across the entire file | PARTIAL (critical) |
| 08-F23 | `tests/test_core/test_session_audit6.py:145` `test_session_has_set_tool_state` | `hasattr` smoke test only; passes against a stub | NOT-SATISFIED |
| 08-F24 | `tests/test_core/test_session_audit6.py:205-209` `test_session_has_add_tag` | `hasattr` smoke test only | NOT-SATISFIED |
| 12-F7 | `tests/test_ui/test_process_panel.py:352-355` `test_tool_definition_count` | Bare `len(...) == 54` count; a dummy stub satisfies it | NOT-SATISFIED |
| 15-F5 | `tests/test_hexcore_e2e/test_bridge_new_capabilities.py:355-367` `test_search_text_encoded_available_on_document` | `assert hasattr(doc, "search_text_encoded")` only; never calls the method | NOT-SATISFIED |

---

## TIER 2 — Mock-the-thing-under-test

The production code path that the test claims to gate is replaced by a stub, so
a regression in the real code is invisible.

| ID | Test (current HEAD) | Defect | Verdict |
|----|---------------------|--------|---------|
| 18-F0001 | `tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:237-239,306-344` | `GuestAgentClient` patched with `_RecordingAgent` factory; real client never runs | NOT-SATISFIED |
| 18-F0002 | `…/test_start_calls_agent_connect.py:350-380` (`:368`) | Same `_RecordingAgent` substitution; only the stub's canned `False` is tested | NOT-SATISFIED |
| 18-F0003 | `…/test_start_calls_agent_connect.py:382-408` (`:365`) | Same; only a pre-injected `OSError` is exercised, not real socket errors | NOT-SATISFIED |
| 13-F1 | `tests/…/test_availability_caching.py:183-196` `test_cached_success_stored_in_dict` | `patch.object(manager,"_probe_type",new_callable=AsyncMock)` — caches the mock result | NOT-SATISFIED |
| 13-F2 | `tests/…/test_availability_caching.py:80-106` `test_probe_called_once_per_type_across_five_calls` | `_probe_type` replaced by `fake_probe` returning `True` | NOT-SATISFIED |
| 13-F3 | `tests/…/test_availability_caching.py:108-122` `test_successful_result_returned_consistently` | Same `fake_probe` substitution | NOT-SATISFIED |
| 04-F1 | `tests/test_audit4/c6_hex_hashing/test_hashing.py:225-248` `message_box_yes` | `monkeypatch.setattr(QMessageBox.question, …)` returns hardcoded `Yes`; repair flow unverified | NOT-SATISFIED |
| 04-F2 | `tests/test_audit4/c6_hex_hashing/test_hashing.py:115-141` `StubPeDocument` | `repair_pe_checksum`/`verify_pe_checksum` hardcode `0xC0FFEE42` instead of real PE checksum | NOT-SATISFIED |
| 04-F3 | `tests/test_audit4/c9_hex_disassembly_debounce/test_follow_cursor_debounce.py:159-170` `_DebouncingHarness` | Overrides `_on_disassemble` to record offsets; bridge dispatch short-circuited | NOT-SATISFIED |
| 04-F5 | `tests/test_audit7/sandbox_windows/test_memory_dump_target_pid.py:52-115` `_RecordingSandbox` | `run_command` replaced by regex-driven handler that fabricates a minidump file; real PowerShell never runs | NOT-SATISFIED |
| 08-F13 | `tests/test_scripts/test_commit_message.py:329-348` `TestCountTokensFallback` | Monkeypatches `client.models.count_tokens` to raise; no real Gemini error path | NOT-SATISFIED |
| 05-F7 | `tests/test_providers/test_discovery_unit.py:42-94` `_DiscoveryProvider` | Discovery/filtering logic tested against a mock provider class, not a real provider | NOT-SATISFIED |
| 09 | `tests/test_bridges/test_sandbox_bridge.py:443-484` `test_valid_yaml_list_rules_passed_to_behaviors` | YAML parse is real but `analysis.match_behaviors` is patched with a capture fn | PARTIAL |
| 12-F1 | `tests/test_audit4/c16_hex_panel_selection_dispatch/test_selection_dispatch.py:543-589` `TestCopyAsClipboardError` | Mocks `show_warning` (the thing under test) + `QApplication`; asserts only call count | PARTIAL |
| 11-F12 | `tests/test_sandbox/test_sandbox_bridge.py` (fixture) / `conftest.py:1553-1629` | Real `LocalProcessSandbox` integration tests exist but bridge tests still use `InMemorySandbox`; integration tests lack `@pytest.mark.skipif(INTEGRATION_SANDBOX)` markers | PARTIAL |

---

## TIER 3 — Weak / wrong assertions (test passes when it should fail)

| ID | Test (current HEAD) | Defect | Verdict |
|----|---------------------|--------|---------|
| 02 | `tests/test_ui/log_viewer/test_realcov_15_window_real_logs.py:150` `test_window_level_filter_over_real_records` | Returns `visible_levels <= {"ERROR","CRITICAL"}` — empty set passes; must be `==` and assert INFO absent | NOT-SATISFIED |
| 08-F20 | `tests/test_ui/test_realcov_13b_hex_sections.py:122` `test_min_length_is_enforced` | Asserts `len(...) >= 1` instead of `>= 6` (the real `_MIN_STRING_LEN`) | NOT-SATISFIED |
| 02 | `tests/test_audit3/sandbox/test_clipboard_monitor.py:385-409` `test_smoke_script_logs_clipboard_change` | Asserts only file exists + non-empty; no log-record structure (timestamp/operation/fields) | NOT-SATISFIED |
| 05-F6 | `tests/test_hexpat/test_realcov_08_preprocessor_vendor.py:43-53` `test_std_io_include_is_flattened` | Only `len(processed) > len(source)` + one substring; no verification std/io.pat content inlined or output valid | NOT-SATISFIED |
| 08-F8 | `tests/test_providers/test_openai_provider.py:226-227` `test_connection_with_invalid_key_raises_error` | Asserts only that *some* `AuthenticationError` raised; no message/status, no real API call | NOT-SATISFIED |
| 08-F9 | `tests/test_providers/test_openai_provider.py:236-237` `test_connection_with_empty_key_raises_error` | Same; no validation-flow check | NOT-SATISFIED |
| 08-F12 | `tests/test_scripts/test_commit_message.py:181-184` `TestEstimateTokens` | `_estimate_tokens("x"*3000)==1000` re-implements the `/3` the function does — tautology; needs independent token counter | NOT-SATISFIED |
| 17 | `tests/test_ui/log_viewer/test_model.py:154-169` `test_background_role_tints_warn_error_critical_only` | Only `isinstance(bg, QColor)`; missing exact RGB asserts (`QColor(60,48,16)` WARN, `(70,24,24)` ERROR, `(70,16,56)` CRIT) | NOT-SATISFIED |
| 01-F1 | `tests/test_audit4/b2_process_tab/test_process_tab.py:207-226` `test_inject_warns_when_no_process_attached` | Asserts only `len(warning_calls) > 0`; no title/message content, no "bridge not dispatched" check | NOT-SATISFIED |
| 05-F3 | `tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:118-124` `test_search_uint64_cafebare_finds_at_offset_6` | Exception narrowed (good) but result asserts only `offset in offsets`; no length==8, no spurious-result exclusion | PARTIAL |
| 17 | `tests/test_ui/log_viewer/test_model.py:79-95` `test_column_data_for_display_role` | Checks `'"widget"' in extras_text`; should `json.loads` and assert full dict | PARTIAL |
| 12-F8 | `tests/test_ui/test_process_panel.py:363-373` `test_function_names_map_to_methods` | `hasattr` only; doesn't verify callable / signature | PARTIAL |
| 08-F10 | `tests/test_providers/test_openai_provider.py:245-246` `test_list_models_without_connection_raises_error` | Doesn't assert `is_connected is False` before call | PARTIAL |
| 08-F11 | `tests/test_providers/test_openai_provider.py:250-272` `test_disconnect_clears_connection_state` | Checks bool flag only; no post-disconnect `list_models()` to confirm teardown | PARTIAL |
| 08-F16 | `tests/test_providers/test_realcov_10_google_safety.py:80-81` `test_candidate_safety_finish_reason_raises` | Doesn't verify `candidates[0].finish_reason` was the inspected field | PARTIAL |
| 08-F18 | `tests/test_hexcore_e2e/test_bridge_pe_checksum.py:98-99` `test_no_document_raises` | Doesn't assert `current_document is None` before call | PARTIAL |
| 08-F27 | `tests/test_hexcore_e2e/test_realcov_09b_stdlib_realbin.py:325-326` `test_parse_int_invalid_raises_runtime_error` | Doesn't assert error message contains "invalid"; any cause passes | PARTIAL |
| 10-F6 | `tests/test_providers/test_anthropic_provider.py:44-240` | Silent `pytest.skip` when no key; generic `isinstance(model.id,str)` not known IDs; invalid-key test uses hand-crafted fake | PARTIAL |

---

## TIER 4 — Tautological / circular oracle (test derives expected from code under test)

| ID | Test (current HEAD) | Defect | Verdict |
|----|---------------------|--------|---------|
| 03 | `tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py:220-231` `test_resolved_reg_exe_path_is_allowlist_safe` | Asserts the constant passes its own allowlist check — wrong same way if constant wrong | PARTIAL |
| 03 | `…/test_anti_evasion_identity.py:430-453` `test_identity_helper_returns_expected_tuple` | Expected values derived from test params, not independent | PARTIAL |
| 03 | `…/test_anti_evasion_identity.py:455-478` `test_smbios_type1_matches_identity_helper` | Compares two methods of same class (both can be wrong identically) | PARTIAL |
| 03 | `…/test_anti_evasion_identity.py:480-502` `test_registry_writes_use_profile_identity` | Compares registry writes against `_anti_evasion_identity()` (same source) | PARTIAL |
| 03 | `…/test_anti_evasion_identity.py:504-564` `test_switching_profiles_yields_consistent_strings_everywhere` | Same-implementation comparison | PARTIAL |

---

## TIER 5 — Static/structural checks instead of behavioral gates

| ID | Test (current HEAD) | Defect | Verdict |
|----|---------------------|--------|---------|
| 03 | `tests/test_bridges/test_x64dbg_audit6.py:474-478` `test_constant_not_exposed` | Confirms constant gone; no functional check | PARTIAL |
| 03 | `tests/test_bridges/test_x64dbg_audit6.py:480-487` `test_source_inlines_false_for_inherit_handle` | Source-regex match only | PARTIAL |
| 03 | `tests/test_bridges/test_x64dbg_audit6.py:592-607` `test_return_annotation_is_processinfo` | Inspects annotation, not behavior | PARTIAL |
| 03 | `tests/test_bridges/test_x64dbg_audit6.py:808-814` `test_constant_has_expected_entries` | Static constant check, not rejection logic | PARTIAL |
| 08-F25 | `tests/test_core/test_session_audit6.py:332-334` `test_hex_document_full_protocol_body_is_declarative` | AST parse of protocol; no runtime compliance check | PARTIAL |
| 08-F5 | `tests/test_bridges/test_ghidra_audit6.py:1145-1162` `test_create_bridge_script_oserror_raises_toolerror` | Still patches `Path.write_text` globally (scoped by filename) rather than isolating the error path | PARTIAL |

---

## TIER 6 — Dataclass construction-only tests (Frida bridge)

11 tests in `tests/test_bridges/test_frida_bridge.py` that build a dataclass and
assert field assignment — test the definition, not bridge integration. All PARTIAL.

`:97 test_symbol_info_full`, `:113 test_symbol_info_none_optionals`,
`:127 test_crash_info_construction`, `:145 test_child_process_info_full`,
`:163 test_child_process_info_none_optionals`, `:178 test_stalker_event_call`,
`:192 test_stalker_event_exec_no_destination`, `:203 test_stalker_trace_with_events`,
`:221 test_stalker_trace_empty`, `:228 test_frida_device_info`,
`:236 test_api_resolver_match`.

---

## TIER 7 — Missing edge / negative cases (gate exists but incomplete)

| ID | Test (current HEAD) | Missing coverage | Verdict |
|----|---------------------|------------------|---------|
| 03 | `tests/test_core/test_config.py:138,166,180,187,193` (5 tests) | No negative cases (disabled provider/tool → False; unknown behavior) | PARTIAL |
| 03 | `tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:383-415` `test_add_highlight_routes_through_bridge` | Mock recorder; doesn't verify `widget.rules` actually updated | PARTIAL |
| 03 | `…/test_highlighting_route.py:418-448` `test_remove_highlight_routes_through_bridge` | Doesn't verify rule removed from `widget.rules` | PARTIAL |
| 03 | `tests/test_hexcore_e2e/test_bridge_va_mapping.py:79-91` `test_set_va_base_returns_true` | Doesn't verify mapping appears in `list_va_mappings` | PARTIAL |
| 03 | `…/test_bridge_va_mapping.py:162-173` `test_auto_detect_pe_va_mappings` | Doesn't verify exact ImageBase / section-to-VA | PARTIAL |
| 03 | `…/test_bridge_va_mapping.py:175-187` `test_auto_detect_elf_va_mappings` | Doesn't verify VA == PT_LOAD p_vaddr | PARTIAL |
| 03 | `tests/test_hexcore_e2e/test_hexpat_control_flow.py:26,37,63,264,274` (5 tests) | Count-only asserts; no field names/values, no sentinel exclusion, no accumulated value | PARTIAL |
| 08-F1 | `tests/test_audit3/bridges/test_realcov_04_installer.py:173-174` `test_missing_executable_reports_failure` | Mocks network boundary; real network-error path unverified | NOT-SATISFIED |
| 08-F2 | `tests/test_audit3/bridges/test_realcov_04_installer.py:220-221` `test_present_executable_passes_exe_search` | Mocks network; asserts only substring "version" | NOT-SATISFIED |
| 08-F3 | `tests/test_audit5/u2_bridges_frida/test_frida_bridge_audit5.py:558-568` `test_f0014_message_waiter_does_not_capture_loop_at_construction` | Timing-only; doesn't prove loop-independence was the cause | NOT-SATISFIED |
| 08-F14 | `tests/test_scripts/test_commit_message.py:370` `test_throttle_prevents_rapid_calls` | `elapsed >= interval*0.8` — 20% tolerance hides off-by-one | PARTIAL |
| 08-F17 | `tests/test_providers/test_realcov_10_google_safety.py:152-154` `test_cancel_during_stream_stops_without_error` | Only cancel-after-first-chunk; no pre-chunk / post-exhaustion | PARTIAL |
| 08-F21 | `tests/test_core/test_session_audit6.py:130` `test_auto_save_loop_survives_exception_and_resumes` | `save_attempts >= 2` only; no multi-failure / interval check | PARTIAL |
| 13-F4 | `tests/…/test_script_gen.py:343-355` `test_script_get_extension` | Weak enum assert (mitigated by new disk-write test at :358-387) | PARTIAL |
| 13-F7 | `tests/…/test_log_parsers.py:127-177` | No malformed input: escaped pipes, special chars, missing fields, non-ASCII | PARTIAL |
| 15-F6 | `tests/test_ui/log_viewer/test_proxy.py:59-63` `test_min_level_filter` | Asserts `rowCount()==1` but not *which* record survived | PARTIAL |
| 18-F0008 | `tests/test_bridges/test_schemas.py:155-165` `test_build_schema_property_basic` | JSON-serializable but not validated against JSON Schema meta-schema | PARTIAL |
| 18-F0009 | `tests/test_bridges/test_schemas.py:199-203` `test_build_schema_parameters_empty` | No meta-schema / real-provider acceptance check | PARTIAL |
| 18-F0011 | `tests/test_ui/test_icon_manager.py:97-110` `test_all_mapped_icons_load` | Loads (non-null) but no dimension / hash / corruption check | PARTIAL |
| 18-F0013 | `tests/test_bridges/test_realcov_02b_named_pipe_real.py:357-373` `test_real_connect_missing_pipe_raises_with_error_code` | Needs confirmation of exact "error 2" message assertion | PARTIAL |
| 18-F0014 | `tests/test_hexcore_e2e/test_hex_document_state.py` | Missing: callback that raises; callback that mutates state mid-dispatch | PARTIAL |
| 18-F0015 | `tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py:52-106` | Missing: undefined type refs; circular type refs; registry isolation | PARTIAL |
| 19-F12 | `tests/test_audit7/…/test_realcov_12a_base_contract.py:59-126` | Missing: `stop()` on `state="failed"`; method-sequence ordering | PARTIAL |
| 01-F11 | `tests/test_audit7/ui_panels_process/test_threads_auto_refresh.py:217-252` `test_toggling_on_starts_timer_and_increments_call_count` | Interval not verified here (separate `:338` test covers 3000ms) | PARTIAL |
| 02 | `tests/test_ui/test_hxd_panel.py:23-107` (construction) | Smoke/tautological; no real executability or process spawn | PARTIAL |
| 02 | `tests/test_ui/test_hxd_panel.py:119-153` (fileloading preconditions) | Tautologies + conditional `if hxd_exe is not None` guards skip validation | NOT-SATISFIED |
| 02 | `tests/test_ui/test_hxd_panel.py:157-213` (lifecycle) | State-init checks; no cleanup verification (process None, container cleared) | NOT-SATISFIED |
| 02 | `tests/test_ui/test_hxd_panel.py:216-251` (toolbar) | Smoke/tautological; no runtime label-update check | PARTIAL |
| 04-F10 | `tests/test_sandbox/test_analysis.py:73-104` `_ExampleGenerators` | Synthetic RFC-5737 IPs only; no real malware-traffic fixtures | PARTIAL |
| 11-F1 | `tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py` `test_bytes_passthrough` | Weak test deleted rather than strengthened; no bytes-case replacement | NOT-SATISFIED |
| 19-F1 | `tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py` `test_agent_connect_invoked_during_start` | Original removed; replaced with real socket tests (borderline — reviewer flagged "not fixed in place") | NOT-SATISFIED |

---

## NON-ACTIONABLE (stale audit line numbers — reviewer judged replacement sound)

Do not schedule fixes for these; verify-only if desired.

- **01-F14** `test_process_bridge.py:604 test_list_processes_detailed_self_arch` — cited line absent; class tests at ~516-556 are sound. UNVERIFIABLE.
- **04-F8** `test_anthropic_key_format_validation` — test never existed. UNVERIFIABLE.
- **15-F1** `test_disassembler.py:86` — audit cited a non-existent test (line 86 is a docstring). UNVERIFIABLE.
- **17** `test_realcov_06_elevation_windows.py:149` — refactored; current tests at 241-363 sound. UNVERIFIABLE.
- **17** `test_bridge_sandbox.py:29 _run` — a helper, not a test. UNVERIFIABLE.
- **19-F13/14/15/17/18** — `test_handler.py`, `test_tail_reader.py`, `test_app_embedded_tools.py`, `test_graph_view.py`, `test_xpu_status.py`: audit itself marked "pending full review"; needs a fresh read to confirm, not necessarily a fix.

---

## Summary by theme (actionable only)

| Theme | Count | Lead examples |
|-------|-------|---------------|
| Malformed name / never collected | 2 | 15-F2, 15-F3 |
| `hasattr`/count smoke as gate | 5 | 08-F23/F24, 12-F7, 15-F5, 12-F8 |
| Mock-the-thing-under-test | 15 | 18-F0001-3, 13-F1-3, 04-F1/2/3/5 |
| Weak / wrong assertion | 17 | 02 window-filter `<=`, 08-F20 len, 17 RGB |
| Tautological / circular oracle | 5 | 03 anti_evasion (×5) |
| Static-structure instead of behavior | 6 | 03 x64dbg_audit6 (×4) |
| Dataclass construction-only | 11 | frida_bridge (×11) |
| Missing edge/negative cases | ~30 | config getters, hxd_panel, schemas |
| Vacuous construction file | 1 (≈80 fns) | 10-F5 test_types.py |
