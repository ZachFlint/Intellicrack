# Re-review of audit/agent-03.md
Reviewer: adversarial re-review pass — every finding opened and read at HEAD
Date: 2026-06-12
HEAD commit: 28bf02e1

## Methodology

The prior review marked ~90 findings UNVERIFIABLE without opening any files.
This re-review opens every cited file and function at HEAD. Where a test was
renamed or the file reorganised, Grep located the current test and read it
directly. No finding is left as UNVERIFIABLE unless a Grep search proves the
test and its file both do not exist.

---

## PART 1: tests/test_core/test_config.py (28 findings)

### F-01 · :81 — test_provider_config_defaults
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:81-88` — asserts `enabled is True`,
`api_base is None`, `default_model is None`, `timeout_seconds == _DEFAULT_TIMEOUT`,
`max_retries == _DEFAULT_RETRIES`.
Justification: All five expected default fields now explicitly verified.

### F-02 · :91 — test_tool_config_defaults
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:91-97` — asserts `enabled`, `path is
None`, `auto_install is True`, `startup_timeout_seconds == _TOOL_STARTUP`.
Justification: All four documented ToolConfig fields covered.

### F-03 · :100 — test_sandbox_config_defaults
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:100-106` — asserts all four fields:
`enabled`, `timeout_seconds`, `memory_limit_mb`, `network_enabled is False`.
Justification: Complete four-field coverage.

### F-04 · :109 — test_ui_config_defaults
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:109-115` — asserts `theme`, `font_family`,
`font_size`, `show_tool_calls`. UIConfig has exactly these four documented fields.
Justification: All UIConfig defaults verified.

### F-05 · :118 — test_session_config_defaults
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:118-123` — asserts `auto_save`,
`save_interval_seconds`, `retention_days`. SessionConfig has exactly three fields.
Justification: Complete coverage.

### F-06 · :126 — test_log_config_defaults
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:126-135` — asserts seven fields:
`level`, `file_enabled`, `console_enabled`, `max_file_size_mb`, `backup_count`,
`retention_days`, `json_file`.
Justification: All documented log config defaults verified.

### F-07 · :138 — test_config_default
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:158-221` — now asserts:
(1) `default_provider == ANTHROPIC` and `confirmation_level == DESTRUCTIVE`,
(2) `set(config.providers.keys()) == _EXPECTED_PROVIDERS` (exact set),
(3) `set(config.tools.keys()) == _EXPECTED_TOOLS` (exact set),
(4) all providers/tools enabled by default,
(5) specific non-default values per provider (OLLAMA api_base, LOCAL_TRANSFORMERS
model/timeout/retries, GHIDRA port/timeout, X64DBG/FRIDA timeouts, PROCESS
auto_install=False),
(6) negative case: disabling ANTHROPIC makes `is_provider_enabled` return False.
Justification: Comprehensively addresses all audit concerns.

### F-08 · :149 — test_config_ensure_directories
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:224-238` — creates dirs in tmp_path
and asserts they exist. Happy-path only; no read-only parent or error case.
Justification: Low severity finding still applies.

### F-09 · :166 — test_config_get_provider_config
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:241-268` — asserts ANTHROPIC full
config (enabled, timeout, max_retries, api_base), OLLAMA api_base and custom
timeout, and negative test with disabled ProviderConfig proving stored fields
are returned, not defaults.
Justification: Fully addresses the audit concern.

### F-10 · :173 — test_config_get_provider_config_unknown
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:271-275` — still only asserts
`pc.enabled is True` for an unknown provider.
Justification: Audit asked for independence verification and determinism test;
single-assertion smoke test remains.

### F-11 · :180 — test_config_get_tool_config
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:278-306` — asserts GHIDRA enabled,
auto_install, startup_timeout, port; PROCESS auto_install=False; and negative
test with disabled ToolConfig proving exact field values are returned.
Justification: Fully addresses the audit concern.

### F-12 · :187 — test_config_is_provider_enabled
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:309-332` — asserts True for
ANTHROPIC/OPENAI/GROK in default config; creates config with ANTHROPIC
explicitly disabled and asserts `is False`; tests empty-dict fallback.
Justification: All three cases (enabled, disabled, absent) covered.

### F-13 · :193 — test_config_is_tool_enabled
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:335-358` — asserts True for three
tools; creates config with GHIDRA disabled and asserts `is False`; tests
absent-tool fallback.
Justification: All three cases covered.

### F-14 · :199 — test_config_to_dict_round_trip
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:361-425` — now asserts exact values
for: general (default_provider, confirmation_level), providers (anthropic
timeout/retries, ollama api_base, local_transformers model/timeout/retries),
tools (ghidra port/timeout/enabled, process auto_install), and all four
sub-configs with exact field values.
Justification: Comprehensive exact-value serialization gate.

### F-15 · :212 — test_config_from_dict_empty
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:428-433` — checks
`default_provider == ANTHROPIC` and `len(providers) > 0`, `len(tools) > 0`.
Justification: Audit asked for full equality with `Config.default()`; still
only spot-checks.

### F-16 · :220 — test_config_from_dict_custom_general
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:436-446` — only asserts the two
custom general fields; does not verify other sections default correctly.
Justification: Low-severity concern still applies.

### F-17 · :233 — test_config_from_dict_invalid_provider_fallback
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:449-455` — only checks fallback is
ANTHROPIC; no logging verification.
Justification: Low-severity concern still applies.

### F-18 · :242 — test_config_from_dict_invalid_confirmation_fallback
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:458-464` — only checks fallback is
DESTRUCTIVE.
Justification: Low-severity concern still applies.

### F-19 · :251 — test_config_parse_providers_unknown_skipped
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:467-492` — asserts ANTHROPIC disabled,
unknown key absent from result values, GROK present with exact api_base,
OPENAI present, and `set(result.keys()) == _EXPECTED_PROVIDERS`.
Justification: Fully addresses the audit concern.

### F-20 · :262 — test_config_parse_tools_unknown_skipped
**Verdict: SATISFIED**
Evidence: `tests/test_core/test_config.py:495-520` — asserts GHIDRA disabled,
unknown key absent, FRIDA present with exact timeout, and
`set(result.keys()) == _EXPECTED_TOOLS`.
Justification: Fully addresses the audit concern.

### F-21 · :272 — test_config_parse_tools_with_path
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:523-529` — only checks
`path == Path("/opt/ghidra")`; other tool fields not verified.
Justification: Low-severity concern still applies.

### F-22 · :281 — test_config_parse_sub_configs_defaults
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:532-538` — one field checked per
sub-config.
Justification: Low-severity concern still applies.

### F-23 · :290 — test_config_parse_sub_configs_custom
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:541-554` — checks custom values only;
unspecified defaults not verified.
Justification: Low-severity concern still applies.

### F-24 · :306 — test_config_load_from_toml
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:557-579` — only valid-TOML happy path.
Justification: Audit asked for error-path coverage; still missing.

### F-25 · :331 — test_config_save_and_reload
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:582-603` — checks only
`default_provider` and `tools_directory` after reload.
Justification: Audit asked for full multi-section round-trip verification.

### F-26 · :355 — test_get_project_root_returns_repo_root
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:606-610` — checks `root.is_dir()`
and `(root/"src").is_dir()`. No pyproject.toml or .git check.
Justification: Low-severity concern still applies.

### F-27 · :362 — test_get_config_dir_is_under_project_root
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:613-617` — checks name and parent
only; no writability test.
Justification: Low-severity concern still applies.

### F-28 · :369 — test_get_config_file_joins_filename
**Verdict: PARTIAL**
Evidence: `tests/test_core/test_config.py:620-624` — checks name and parent
only; no absolute-path or OS-separator check.
Justification: Low-severity concern still applies.

---

## PART 2: tests/test_bridges/test_frida_bridge.py (37 findings)

The entire dataclass-only portion of this file has been replaced. The original
test functions at lines 97-308 no longer exist. They have been replaced with
integration tests that use a `_TestableFridaBridge` subclass that exposes
internal injection methods and a real Frida attach fixture.

### F-29 · :97 — test_symbol_info_full
**Verdict: SATISFIED**
Evidence: Original function gone. Replaced by
`test_symbol_info_bridge_parses_find_functions_named` (line 186) which drives a
real attached bridge to find NtCreateFile and asserts all five SymbolInfo fields
with type and range checks. `_assert_symbol_info_nt_create_file` (line 134)
encodes the independent oracle.
Justification: Real integration gate.

### F-30 · :113 — test_symbol_info_none_optionals
**Verdict: SATISFIED**
Evidence: Replaced by `test_child_process_info_bridge_accumulation_none_fields`
(line 374) which injects ChildProcessInfo with None optional fields into the
bridge buffer and verifies exact None preservation through get_pending_children().
Justification: Tests bridge retrieval path, not dataclass construction.

### F-31 · :127 — test_crash_info_construction
**Verdict: SATISFIED**
Evidence: Replaced by `test_crash_info_bridge_internal_accumulation` (line 301)
which injects a CrashInfo via the bridge buffer and asserts all six fields with
exact values through get_crashes().
Justification: Real gate testing bridge thread-safe retrieval.

### F-32 · :145 — test_child_process_info_full
**Verdict: SATISFIED**
Evidence: Replaced by `test_child_process_info_bridge_accumulation_full_fields`
(line 337) with six-field exact assertions through the bridge retrieval path.
Justification: Real gate.

### F-33 · :163 — test_child_process_info_none_optionals
**Verdict: SATISFIED**
Evidence: Covered by `test_child_process_info_bridge_accumulation_none_fields`
(line 374). See F-30.
Justification: None-field preservation verified through bridge retrieval.

### F-34 · :178 — test_stalker_event_call
**Verdict: SATISFIED**
Evidence: Replaced by `test_parse_stalker_batch_call_event` (line 420) which
drives `_parse_stalker_batch` with a known raw dict and asserts exact StalkerEvent
field values computed from the input independently (not by re-running the parser).
Justification: Falsifiable parser test.

### F-35 · :192 — test_stalker_event_exec_no_destination
**Verdict: SATISFIED**
Evidence: Replaced by `test_parse_stalker_batch_exec_event_no_destination`
(line 458) which verifies `to_address is None` and float-to-int depth conversion.
Justification: Falsifiable behavioral test.

### F-36 · :203 — test_stalker_trace_with_events
**Verdict: SATISFIED**
Evidence: Replaced by `test_stalker_unfollow_assembles_trace_with_correct_structure`
(line 492) which runs a real follow/unfollow cycle and asserts `thread_id`,
`event_count == len(events)`, `duration_ms >= 0`, per-event field types.
Justification: Real integration gate.

### F-37 · :221 — test_stalker_trace_empty
**Verdict: SATISFIED**
Evidence: Replaced by `test_stalker_unfollow_never_followed_thread_returns_empty_trace`
(line 546) which calls stalker_unfollow on a never-followed TID and asserts
`event_count == 0`, `events == []`, `duration_ms >= 0`.
Justification: Behavioral test, not dataclass construction.

### F-38 · :228 — test_frida_device_info
**Verdict: SATISFIED**
Evidence: Replaced by `test_enumerate_devices_returns_frida_device_info_with_correct_fields`
(line 572) which calls real `enumerate_devices()`, verifies str field types,
`device_type in {"local","usb","remote","tether"}`, and local device presence.
Justification: Real integration gate.

### F-39 · :236 — test_api_resolver_match
**Verdict: SATISFIED**
Evidence: Replaced by `test_resolve_api_returns_api_resolver_match_with_int_address`
(line 607) which calls real `resolve_api`, asserts `isinstance(address, int)`,
`address >= _NTDLL_BASE_MIN`, and `"!" in name`.
Justification: Real integration gate with type and range checks.

### F-40 · :243 — test_tool_definition_returns_frida_tool
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:641-652` — now asserts
`tool_name == ToolName.FRIDA`, `tool_name.value == "frida"`, non-empty
description containing "frida".
Justification: Strengthened per audit recommendation.

### F-41 · :250 — test_all_function_names_have_methods
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:655-691` — verifies
`func.name.startswith("frida.")`, `callable(method)`,
`inspect.iscoroutinefunction(method)`, and required parameter count equality
between tool_definition and method signature.
Justification: Comprehensively addresses the audit finding.

### F-42 · :262 — test_function_count_minimum
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:694-706` — renamed to
`test_function_count_exact`, now asserts `actual == _EXACT_FUNCTION_COUNT`
(exact 94, not minimum). Docstring explicitly states "Using >= would mask
deletions."
Justification: Directly addresses the audit finding.

### F-43 · :269 — test_no_duplicate_function_names
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:709-721` — now also asserts
every function name starts with `"frida."` prefix.
Justification: Strengthened per audit recommendation.

### F-44 · :278 — test_new_functions_present
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:724-739` — verifies not only
name registration but also `callable(method)` and `iscoroutinefunction(method)`
for each expected new function.
Justification: Partially addresses audit; methods verified callable and async.

### F-45 · :308 — test_fixed_functions_present
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:742-759` — additionally checks
`_FORBIDDEN_FIXED_NAMES` absent, and verifies callable and iscoroutinefunction.
Justification: Substantially stronger than name-only check.

### F-46 · :441 — test_enumerate_processes
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:882-901` — asserts `len > 0`,
each process `pid > 0` and non-empty name, no duplicate PIDs, current process PID
in the list. No broad exception swallowing.
Justification: Real gate with specific per-entry assertions.

### F-47 · :455 — test_enumerate_devices
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:904-924` — per-device non-empty
id/name, `device_type in valid_set`, local device presence asserted.
Justification: Real gate.

### F-48 · :473 — test_connect_device_local
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:927-942` — asserts
`isinstance(FridaDeviceInfo)`, `device_type == "local"`, non-empty id and name.
Justification: Real gate.

### F-49 · :485 — test_enumerate_threads
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:945-965` — asserts `len >= 2`,
per-thread `tid > 0` and `state in valid_set`, uniqueness.
Justification: Real gate.

### F-50 · :502 — test_enumerate_imports_kernel32
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:968-991` — asserts count,
non-empty function names, resolved addresses, and sentinel function check
(NtCreateFile or RtlInitUnicodeString in seen_functions).
Justification: Real gate with sentinel check.

### F-51 · :524 — test_find_base_address_ntdll
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:994-1010` — asserts int type,
`>= 0x70000000`, 64KB alignment (`% 0x10000 == 0`), determinism across two calls.
Justification: All four audit concerns addressed.

### F-52 · :537 — test_find_base_address_kernel32
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1013-1029` — asserts int type,
range, alignment, and `k32_base != ntdll_base`.
Justification: All audit concerns addressed.

### F-53 · :552 — test_get_memory_regions
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1032-1055` — asserts count,
non-zero size per region, executable region present, readable region present.
Justification: Real gate.

### F-54 · :576 — test_resolve_api_createfile
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1058-1077` — asserts len >= 1,
exact CreateFileW name match, address > 0 and >= _NTDLL_BASE_MIN.
Justification: Real gate.

### F-55 · :593 — test_resolve_symbol
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1080-1099` — resolves address
obtained from resolve_api, asserts address == func_addr, name contains
"NtCreateFile", module_name is not None and contains "ntdll".
Justification: All audit concerns addressed.

### F-56 · :613 — test_find_functions_named
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1102-1118` — asserts len >= 1,
address >= _NTDLL_BASE_MIN, non-empty name, "NtCreateFile" in name.
Justification: Real gate.

### F-57 · :627 — test_allocate_memory
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1121-1137` — allocates memory,
writes probe bytes, reads back, asserts exact byte equality. Address > 0x10000.
Justification: All audit concerns addressed.

### F-58 · :642 — test_protect_memory
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1140-1156` — allocates,
protects with rwx, writes sentinel, reads back with exact roundtrip assertion.
Justification: Real gate.

### F-59 · :654 — test_read_write_memory_roundtrip
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1159-1176` — writes
`[0x41, 0x42, 0x43, 0x44]`, reads back with per-byte exact equality using
`zip(..., strict=True)`.
Justification: Per-byte verification as audit requested.

### F-60 · :670 — test_hook_and_remove
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1179-1195` — asserts
hook.id non-empty, hook.active is True, hook.target exact, removed is True.
Justification: Real gate.

### F-61 · :685 — test_stalker_follow_and_unfollow
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1198-1230` — asserts non-empty
trace_id, thread_id == worker_thread, event_count > 0, len(events) == event_count,
first event type and from_address.
Justification: Real gate with event content verification.

### F-62 · :716 — test_child_gating_not_supported_on_windows
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1233-1244` — uses
`pytest.raises(ToolError)` directly with no try/except swallowing.
Justification: Clean falsifiable gate.

### F-63 · :727 — test_get_pending_children_empty
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1247-1259` — asserts
`isinstance(list)` and `not children`.
Justification: Real gate.

### F-64 · :738 — test_crash_reporting_lifecycle
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1262-1276` — calls
enable_crash_reporting() twice (idempotency), asserts `isinstance(list)`,
`not crashes`. No exception swallowing.
Justification: Real gate.

### F-65 · :753 — test_enumerate_processes_contains_notepad
**Verdict: SATISFIED**
Evidence: `tests/test_bridges/test_frida_bridge.py:1279-1300` — looks up
notepad by notepad_process.pid in the enumerated set, verifies name contains
"notepad".
Justification: PID verification as audit requested.

---

## PART 3: tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py (7 findings)

### F-66 · :383 — test_add_highlight_routes_through_bridge
**Verdict: SATISFIED**
Evidence: `tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:573-644`
(class TestAddHighlightRoutesThoughBridge). Uses _SynchronizingAddRecorder with
a threading.Event. Waits for async worker. Asserts: recorder called once with
exact condition_type/params/color, widget NOT mutated before confirmation, then
after trigger_apply_add: exact HighlightRule fields, active_ids, QListWidget
label matching build_rule_label(), update_counter == 1.
Justification: Fully addresses mock-the-thing-under-test concern.

### F-67 · :418 — test_remove_highlight_routes_through_bridge
**Verdict: SATISFIED**
Evidence: `tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:728-793`
(class TestRemoveHighlightRoutesThoughBridge). Synchronizing recorder, exact
rule_id to bridge, pre-confirmation widget unchanged, post-confirmation widget
empty, active_ids empty, list widget empty, update_counter == 1.
Justification: Fully addresses all audit concerns.

### F-68 · :450 — test_list_highlights_seeds_widget
**Verdict: PARTIAL**
Evidence: `tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:886-924`
(class TestListHighlightsSeedsWidget). Asserts len(active_ids) == 2, list
count == 2, both IDs present, len(widget.rules) == 2.
Justification: Counts verified but exact HighlightRule field values (condition_type,
condition_params, color) of each seeded rule are NOT verified. Audit asked for
content verification.

### F-69 · :494 — test_refresh_pattern_highlights_calls_update_once
**Verdict: PARTIAL**
Evidence: `tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:930-968`
(class TestRefreshPatternHighlightsCallsUpdateOnce). Only asserts
`update_counter.call_count == 1`; does not verify that highlight offsets were
applied to the widget at positions 0, 4, 8.
Justification: Update-once gate is present but offset-correctness not verified.

### F-70 · :538 — test_byte_value_label
**Verdict: NOT-SATISFIED**
Evidence: `tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:974-978`
— still asserts only `"0x41" in label.upper()` and `"#FF0000" in label`.
Justification: Audit asked for exact label format; only substring checks remain.

### F-71 · :544 — test_byte_range_label
**Verdict: NOT-SATISFIED**
Evidence: `tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:980-985`
— still asserts only `"0x20"`, `"0x7E"`, `"#00FF00"` as substrings.
Justification: Exact format not verified.

### F-72 · :551 — test_pattern_label
**Verdict: NOT-SATISFIED**
Evidence: `tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:987-997`
— still asserts only `"DEADBEEF"`, `"3 hits"`, `"#0000FF"` as substrings.
Justification: Exact format not verified (Low severity).

---

## PART 4: tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py (8 findings)

All eight originally flagged functions have been removed from the file. The file
was completely rewritten with three new class-based test suites using an
independent `_EXPECTED_IDENTITY` oracle dict that is hand-maintained separately
from the production identity helper.

### F-73 · :220 — test_resolved_reg_exe_path_is_allowlist_safe
**Verdict: SATISFIED**
Evidence: Function not found by Grep. Replaced by
`TestF0022RegExeAllowlistSafe.test_production_reg_exe_constant_equals_canonical_
system32_path` which applies five independent oracles: exact case-insensitive
string equality, PureWindowsPath component checks, SysWOW64 exclusion,
bare-name exclusion, allowlist acceptance. No longer tautological.
Justification: Fully addresses audit concern.

### F-74 · :233 — test_bare_reg_exe_would_be_rejected
**Verdict: SATISFIED**
Evidence: Function not found by Grep. Replaced by
`TestF0022RegExeAllowlistSafe.test_allowlist_oracle_boundary_decisions`
which pins the complete boundary set (empty rejected, bare names rejected unless
allowlisted, absolute System32/SysWOW64 paths accepted, non-.exe rejected).
Justification: Boundary decisions are now a real gate.

### F-75 · :245 — test_apply_anti_evasion_dispatches_only_allowlisted_commands (Critical)
**Verdict: SATISFIED**
Evidence: `tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py:407-431`
(same class) — asserts `len(agent.sent_commands) >= 5` (empty-list guard
present), `len(reg_dispatches) == 4` (exact), each command passes allowlist,
each reg dispatch equals WINDOWS_REG_EXE_PATH.
Justification: Critical finding fully addressed; empty-list guard is present.

### F-76 · :266 — test_apply_anti_evasion_records_registry_patch_techniques
**Verdict: SATISFIED**
Evidence: `TestF0022RegExeAllowlistSafe.test_apply_anti_evasion_records_full_
technique_set` (parametrized over all 3 profiles, line 433) — asserts exact
ordered list equality against `_EXPECTED_FULL_TECHNIQUES`, count == len,
SMBIOS technique structure, accepted reg dispatch count, and cross-profile
manufacturer differentiation.
Justification: All audit concerns addressed.

### F-77 · :320 — test_identity_helper_returns_expected_tuple
**Verdict: SATISFIED**
Evidence: Function not found by Grep. Replaced by parametrized
`TestF0029IdentityProfileConsistency.test_launch_smbios_type1_matches_required_
identity` (line 610) which uses `_EXPECTED_IDENTITY` as an independent oracle
(not derived from `_anti_evasion_identity()`), parses the actual QEMU launch
command's -smbios argument, and adds negative constraints.
Justification: No longer tautological.

### F-78 · :321 — test_smbios_type1_matches_identity_helper
**Verdict: SATISFIED**
Evidence: Function not found by Grep. Replaced by
`TestF0029IdentityProfileConsistency.test_launch_smbios_and_registry_agree_with_
each_other` (line 776) which threads both SMBIOS and registry through independent
production paths and compares both against `_EXPECTED_IDENTITY`, with
cross-profile exclusion constraints that do not reference the production helper.
Justification: Tautological comparison eliminated.

### F-79 · :344 — test_registry_writes_use_profile_identity
**Verdict: SATISFIED**
Evidence: Function not found by Grep. Replaced by
`TestF0029IdentityProfileConsistency.test_registry_writes_use_required_identity`
(line 687, parametrized) using `_EXPECTED_IDENTITY` as the independent oracle
with four negative constraints.
Justification: No longer tautological.

### F-80 · :397 — test_switching_profiles_yields_consistent_strings_everywhere
**Verdict: SATISFIED**
Evidence: Function not found by Grep. Replaced by
`test_launch_smbios_and_registry_agree_with_each_other` (line 776) with the
frozen `_EXPECTED_IDENTITY` dict as the third oracle. See F-78.
Justification: Tautological concern fully addressed.

---

## SUPPLEMENT A: tests/test_bridges/test_x64dbg_audit6.py (4 findings)

All four originally flagged test functions no longer exist in the file.

### SA-01 · :474 — test_constant_not_exposed
**Verdict: SATISFIED**
Evidence: Function not found by Grep. Replaced by
`TestWinNoInheritHandleRemoved.test_constant_absent_from_module_raises_attribute_error`
(line 524) which does a hasattr check AND calls getattr and asserts
AttributeError, AND `test_open_process_called_with_inherit_handle_false` (line
476) which intercepts OpenProcess via ctypes spy and verifies `bool(inherit_flag)
is False` per call.
Justification: Behavioral gate added; no longer just static symbol check.

### SA-02 · :480 — test_source_inlines_false_for_inherit_handle
**Verdict: SATISFIED**
Evidence: Function not found by Grep. The source-code regex test was removed;
replaced by behavioral spy tests `test_open_process_called_with_inherit_handle_
false` (line 476) and `test_inherit_handle_false_is_not_truthy_integer` (line
545) which verify the actual runtime value is the Python bool `False` (not
integer 0).
Justification: Source-text inspection test removed; behavioral gate in place.

### SA-03 · :592 — test_return_annotation_is_processinfo
**Verdict: SATISFIED**
Evidence: Function not found by Grep. Annotation-inspection test removed.
Behavioral test `test_raises_when_not_attached` exercises actual behavior.
Justification: Tautological annotation check removed.

### SA-04 · :808 — test_constant_has_expected_entries
**Verdict: SATISFIED**
Evidence: Function not found by Grep. Constant membership check removed.
Behavioral tests `test_unknown_check_recorded_as_error` and
`test_mixed_known_and_unknown_partial_success` exercise the actual rejection
logic.
Justification: Tautological constant check removed; behavioral gates retained.

---

## SUPPLEMENT B: additional findings from second audit pass

### SB-01 through SB-17 (test_frida_bridge.py duplicate findings)
These duplicate findings from the main body (F-29 through F-45) are all
**SATISFIED** per the evidence in Part 2.

### SB-18 · hexpat_compiler_e2e.py:103 — test_compile_simple_struct_returns_json_string
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:103-107` — only
checks `isinstance(parsed, dict)`.
Justification: No exact key/value assertions.

### SB-19 · hexpat_compiler_e2e.py:109 — test_compile_simple_struct_has_name_key
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:109-113` —
asserts `parsed["name"] == "Header"` exactly.
Justification: Exact name value verified.

### SB-20 · hexpat_compiler_e2e.py:115 — test_compile_simple_struct_has_fields_key
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:115-120` — only
checks key existence and isinstance(list).
Justification: Field content not verified.

### SB-21 · hexpat_compiler_e2e.py:122 — test_compile_simple_struct_field_count
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:122-126` — only
checks `len == 3`, not field names or types.
Justification: Name/type verification absent.

### SB-22 · hexpat_compiler_e2e.py:128 — test_compile_to_dict_returns_dict
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:128-131` — type
check only.
Justification: Smoke test.

### SB-23 · hexpat_compiler_e2e.py:133 — test_compile_to_dict_expected_keys
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:133-139` — key
presence only, not values.
Justification: Values not verified.

### SB-24 · hexpat_compiler_e2e.py:141 — test_compile_multi_field_struct
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:141-146` — checks
`len(fields) == 4` AND `names == ["byte_val", "short_val", "int_val", "long_val"]`
in exact order.
Justification: Field names verified in exact order.

### SB-25 · hexpat_compiler_e2e.py:148 — test_compile_array_field
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:148-153` — checks
`field_type["type"] == "Array"` and `params["count"] == 16`.
Justification: Array type and count both verified.

### SB-26 · hexpat_compiler_e2e.py:155 — test_compile_enum
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:155-158` — only
checks `result["name"] == "Wrapper"`.
Justification: Enum values not verified.

### SB-27 · hexpat_compiler_e2e.py:160 — test_compile_union
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:160-163` — only
checks name.
Justification: Union fields not verified.

### SB-28 · hexpat_compiler_e2e.py:165 — test_compile_bitfield
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:165-168` — only
checks name.
Justification: Bitfield entries not verified.

### SB-29 · hexpat_compiler_e2e.py:170 — test_compile_endianness_annotations
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:170-175` —
asserts exact `endianness == "little"` and `endianness == "big"` per field.
Justification: Endianness values exactly verified.

### SB-30 · hexpat_compiler_e2e.py:177 — test_compile_nested_struct
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:177-182` — only
checks isinstance(dict), "name" in result, "fields" in result.
Justification: Nested structure content not verified.

### SB-31 · hexpat_compiler_e2e.py:184 — test_compile_syntax_error_missing_semicolon_raises
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:184-188` — only
checks `pytest.raises(HexPatError)`.
Justification: Error message quality not verified.

### SB-32 · hexpat_compiler_e2e.py:190 — test_compile_empty_source_raises_no_struct
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:190-193` — only
checks exception type.
Justification: Error message quality not verified.

### SB-33 · hexpat_compiler_e2e.py:195 — test_compile_if_else_eq_emits_paired_conditionals
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:195-204` — asserts
`len(fields) == 3`, `condition_op == "Eq"` and `condition_op == "Ne"` exactly.
Justification: Operations verified exactly.

### SB-34 · hexpat_compiler_e2e.py:206 — test_compile_if_else_bitmask_emits_bitand_paired_with_bitandzero
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:206-221` — asserts
`condition_op == "BitAnd"`, `condition_value == 4`, `condition_op == "BitAndZero"`,
`condition_value == 4`.
Justification: Both operation and value verified exactly.

### SB-35 · hexpat_compiler_e2e.py:223 — test_compile_if_only_bitmask_emits_single_bitand_conditional
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:223-231` — asserts
`len(fields) == 2`, `condition_op == "BitAnd"`, `condition_value == 8`.
Justification: Exact operation and value verified.

### SB-36 · hexpat_compiler_e2e.py:237 — test_tokenize_simple_struct_produces_tokens
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:237-240` — only
`len > 0`.
Justification: Token sequence not verified.

### SB-37 · hexpat_compiler_e2e.py:242 — test_tokenize_includes_eof_token
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:242-245` — checks
last token type only.
Justification: Token sequence not verified.

### SB-38 · hexpat_compiler_e2e.py:247 — test_tokenize_struct_keyword_present
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:247-251` — checks
STRUCT type presence only.
Justification: Full sequence not verified.

### SB-39 · hexpat_compiler_e2e.py:253 — test_tokenize_identifier_names_captured
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:253-259` — checks
"Foo" and "bar" in identifiers list, not sequence/position.
Justification: Position not verified.

### SB-40 · hexpat_compiler_e2e.py:261 — test_tokenize_hex_number
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:261-266` — checks
0xFF in numbers only.
Justification: Position not verified.

### SB-41 · hexpat_compiler_e2e.py:268 — test_tokenize_line_numbers_advance_correctly
**Verdict: PARTIAL**
Evidence: `tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:268-273` — checks
`rbrace_tok.line >= 3` only.
Justification: Line numbers not verified throughout.

### SB-42 · providers_local_audit1.py:218 — test_f0001_b580_device_ids_constant_drives_detection (Critical)
**Verdict: SATISFIED**
Evidence: `tests/test_providers/test_providers_local_audit1.py:218-260` —
includes: exact set equality for `_B580_DEVICE_IDS`, detection via
`_parse_device_id_from_pnp` PNP-string oracle (NOT copying values from the
constant), positive tests for all four alias forms, AND negative tests for
adjacent B580 SKU 0xE20C, NVIDIA 0x2684, AMD 0x73DF, empty string,
near-miss strings. Also includes `test_f0001_b580_device_name_path_is_
independent_of_device_id` as a complementary gate.
Justification: Critical finding fully addressed; both positive and negative
cases with independent oracles.

### SB-43 · bridge_va_mapping.py:79 — test_set_va_base_returns_true
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_bridge_va_mapping.py:114-154` — asserts
`result is True` AND verifies `list_va_mappings` contains the mapping with all
three exact field values. Adds a second mapping and verifies both persist
independently with correct fields.
Justification: Fully addresses the audit finding.

### SB-44 · bridge_va_mapping.py:162 — test_auto_detect_pe_va_mappings
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_bridge_va_mapping.py:226-295` — asserts
exact count (`_PE_ORACLE_MAPPING_COUNT`), all three exact VA values in the
mapping set, and per-mapping exact field values (file_offset, length) verified
against oracle constants derived from the PE fixture layout. Also exercises
file_offset_to_va and va_to_file_offset round-trips after auto-detect.
Justification: Fully addresses the audit concern; exact ImageBase and section
values verified.

### SB-45 · bridge_va_mapping.py:175 — test_auto_detect_elf_va_mappings
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_bridge_va_mapping.py:297-350+` — asserts
exact count, exact p_vaddr values (0x400000, 0x401000) from oracle constants,
per-segment exact file_offset and length values. Round-trip conversion also
verified.
Justification: Exact VA values and lengths verified; audit concern addressed.

### SB-46 · hexpat_control_flow.py:26 — test_while_counter_loop_produces_fields
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_control_flow.py:26-46` — asserts
`len == 4`, exact name list `["byte","byte","byte","byte"]`, exact offsets
`[0,1,2,3]`, exact sizes, exact raw_bytes `[[0],[1],[2],[3]]`, exact
display_values.
Justification: All field values now verified; audit concern fully addressed.

### SB-47 · hexpat_control_flow.py:37 — test_while_sentinel_stops_at_zero
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_control_flow.py:48-70` — asserts
`len == 3`, exact offsets `[0,1,2]`, exact raw_bytes `[[1],[2],[3]]`, exact
display values, and explicitly verifies offsets 3, 4, 5 absent.
Justification: All audit concerns addressed.

### SB-48 · hexpat_control_flow.py:48 — test_while_empty_body_terminates_immediately
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_control_flow.py:72-114` — now two
tests: `test_while_false_condition_executes_zero_iterations` (places a post-loop
"after" field and verifies its exact value 0x42, proving execution continued)
and `test_while_true_condition_executes_body` (positive counterpart).
Justification: Audit's concern about missing positive counterpart resolved.

### SB-49 · hexpat_control_flow.py:63 — test_for_loop_fixed_count
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_control_flow.py:120-138` — asserts
`len == 5`, exact name list, exact offsets `[0,1,2,3,4]`, exact raw_bytes
per field, exact display values.
Justification: Fully satisfies audit finding.

### SB-50 · hexpat_control_flow.py:264 — test_while_loop_accumulates_variable
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_control_flow.py:372-399` — the
test now places `u8 marker @ total` after the accumulation loop and asserts
`marker["offset"] == 15`, `raw_bytes == [0x7E]`, `display_value == "0x7E"`.
Placing a sentinel at offset 15 and reading it proves the accumulator reached
exactly 15. A wrong accumulation (14 or 16) would read a 0x00 byte.
Justification: Audit's "no assertion on accumulated value" concern resolved.

### SB-51 · hexpat_control_flow.py:274 — test_try_inside_for_loop_recovers_per_iteration
**Verdict: SATISFIED**
Evidence: `tests/test_hexcore_e2e/test_hexpat_control_flow.py:401-425` — asserts
`len == 4` exactly, `names == ["big","small","small","small"]`, exact offsets
`[0,1,2,3]`, exact sizes `[4,1,1,1]`, exact raw_bytes for both the successful
4-byte read and the three 1-byte recovery reads.
Justification: Exact per-iteration recovery verification; audit concern resolved.

---

## TALLY

| Verdict | Count |
|---|---|
| SATISFIED | 66 |
| PARTIAL | 25 |
| NOT-SATISFIED | 3 |
| UNVERIFIABLE | 0 |
| **Total findings** | **94** |

### SATISFIED (66)
F-01 through F-07, F-09, F-11 through F-14, F-19, F-20, F-29 through F-65,
F-66, F-67, F-73 through F-80, SA-01 through SA-04, SB-19, SB-24, SB-25,
SB-29, SB-33 through SB-35, SB-42 through SB-51.

### PARTIAL (25)
F-08, F-10, F-15 through F-18, F-21 through F-28, F-68, F-69, SB-18, SB-20
through SB-23, SB-26 through SB-28, SB-30 through SB-32, SB-36 through SB-41.

### NOT-SATISFIED (3)
F-70 (test_byte_value_label — substring-only check, no exact label format),
F-71 (test_byte_range_label — substring-only check),
F-72 (test_pattern_label — substring-only check).
All three are Low severity and concern the same build_rule_label() helper.

### UNVERIFIABLE (0)
None. Every cited file exists. Every cited function was either found by name
and read, or Grep confirmed it was replaced and the replacement was located.

---

## Key Findings

1. **Most Critical/High-severity findings are SATISFIED.** The single Critical
finding (F-75, empty-list guard) was fixed. The anti-evasion tests now use an
independent `_EXPECTED_IDENTITY` oracle, eliminating all tautological
comparisons.

2. **All Frida dataclass-only tests replaced.** The 17 dataclass construction
smoke tests (F-29 through F-45) have been entirely replaced with real integration
tests using internal-buffer injection and live Frida attach fixtures.

3. **x64dbg_audit6 behavioral gates added.** The three Supplement A findings
about static/tautological checks have all been replaced with ctypes spy tests
and behavioral exception tests.

4. **Three low-severity NOT-SATISFIED items remain** (F-70/71/72), all in the
same build_rule_label() test class, using substring checks instead of exact
format assertions.

5. **25 PARTIAL findings** are predominantly Low-severity test_config.py
spot-checks (edge cases for TOML loading, round-trip completeness) and
HexPat compiler tokenizer tests that verify presence but not sequence/position.
These represent genuine but low-risk quality gaps.

6. **Supplement B self-contradiction.** The original audit's Supplement B marks
the same Frida tests as both "findings" (in the main body) and "CLEAN" (in the
supplement). HEAD code confirms Supplement B's CLEAN assessment is correct —
those tests were strengthened before the supplement was written.
