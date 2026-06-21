# Test-Gate Audit — test_bridges (part 2)

## Summary
- Files audited: 19
- Test functions examined: 318 (parametrized cases counted once per function)
- Genuine gates: 296
- Flagged non-gates: 22  (CRITICAL: 3, HIGH: 0, MEDIUM: 14, LOW: 5)

## Coverage checklist
- [x] tests/test_bridges/test_process_win32.py — gates: 12, flagged: 5
- [x] tests/test_bridges/test_realcov_01_hex_editor_pe_real.py — gates: 13, flagged: 0
- [x] tests/test_bridges/test_realcov_01_pe_format_real_binaries.py — gates: 18, flagged: 0
- [x] tests/test_bridges/test_realcov_02a_x64dbg.py — gates: 6, flagged: 0
- [x] tests/test_bridges/test_realcov_02b_named_pipe_real.py — gates: 6, flagged: 0
- [x] tests/test_bridges/test_realcov_03a_frida_modules.py — gates: 6, flagged: 0
- [x] tests/test_bridges/test_realcov_03b_ghidra.py — gates: 30, flagged: 0
- [x] tests/test_bridges/test_realcov_03c_cutter.py — gates: 27, flagged: 1
- [x] tests/test_bridges/test_realcov_04_base.py — gates: 11, flagged: 0
- [x] tests/test_bridges/test_sandbox_bridge.py — gates: 75, flagged: 4
- [x] tests/test_bridges/test_schemas.py — gates: 45, flagged: 0
- [x] tests/test_bridges/test_win32_types.py — gates: 39, flagged: 3
- [x] tests/test_bridges/test_x64dbg.py — gates: 22, flagged: 3
- [x] tests/test_bridges/test_x64dbg_api_coverage.py — gates: 7, flagged: 0
- [x] tests/test_bridges/test_x64dbg_audit6.py — gates: 62, flagged: 1
- [x] tests/test_bridges/test_x64dbg_audit7_f0001.py — gates: 37, flagged: 0
- [x] tests/test_bridges/test_x64dbg_events.py — gates: 11, flagged: 2
- [x] tests/test_bridges/test_x64dbg_new_methods.py — gates: 38, flagged: 0
- [x] tests/test_bridges/test_win32_types.py (consumer-constant class) — counted above

## Flagged tests

### tests/test_bridges/test_process_win32.py

#### `test_get_mitigation_policy_returns_keys` — MEDIUM — existence-only (N8)
- **Location:** tests/test_bridges/test_process_win32.py:77
- **Current behavior:** Calls `get_mitigation_policy(self_pid)` and asserts the returned dict merely *contains* the keys `dep`, `aslr`, `cfg`, `sehop_via_options_mask`. The actual values (bool/int derived from the real `GetProcessMitigationPolicy` Win32 call) are never asserted.
- **Why it is not a gate:** If the bridge mis-decoded the policy bitfields (e.g. returned the wrong flag, inverted a bool, or hard-coded `{"dep": None, ...}`) the dict would still carry the keys and the test would pass. The claimed behaviour — that the bridge faithfully reports the process's mitigation policy — is not verified.
- **Recommended fix:** Independently query `GetProcessMitigationPolicy` (or compute DEP/ASLR for the current Python process, which is a known-stable value) and assert the bridge's `dep`/`aslr`/`cfg` values equal that oracle, not just that the keys exist.

#### `test_get_extension_policy_returns_dict` — MEDIUM — existence-only (N8)
- **Location:** tests/test_bridges/test_process_win32.py:91
- **Current behavior:** Asserts only that `get_extension_policy` returns a dict containing the key `disable_extension_points`.
- **Why it is not a gate:** The decoded value of the flag is never checked, so a wrong-offset or constant-returning implementation passes. For the current process the extension-point policy is a known, stable value that could be asserted.
- **Recommended fix:** Assert the exact boolean value of `disable_extension_points` for the self process (independently derived from `GetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy)`).

#### `test_enumerate_handles_for_self_nonempty` — MEDIUM — existence-only (N8)
- **Location:** tests/test_bridges/test_process_win32.py:115
- **Current behavior:** Asserts the handle list is non-empty and that the first entry has the keys `pid`, `handle_value`, `granted_access`, `object_type_index`. No field *value* is validated.
- **Why it is not a gate:** A bridge that returned garbage handle_value/granted_access (or copied the wrong process's handles) would still produce key-bearing dicts and pass. The test proves the shape, not that the enumeration reflects the real handle table. Note `pid` filtering is also not asserted to equal `os.getpid()` for the filtered call.
- **Recommended fix:** Plant a known handle (e.g. open an event/file in the test, capturing its `HANDLE` value), then assert that exact `handle_value` with `pid == os.getpid()` appears in the enumeration, and that `granted_access` matches the access the test requested.

#### `test_time_thread_wait_returns_result_dict` — MEDIUM — accepts-both / existence-only (N7/N8)
- **Location:** tests/test_bridges/test_process_win32.py:143
- **Current behavior:** Waits 10 ms on the current thread and asserts the result dict has `result`/`elapsed_us` keys, `elapsed_us` is an int, and `result` is one of `{"signaled","timeout","failed","other"}` or starts with `"other_"`.
- **Why it is not a gate:** The current thread is running and never signalled, so the only correct outcome is `"timeout"`; yet the assertion accepts `signaled`, `failed`, `other`, or any `other_*` string. A bridge that mis-mapped `WAIT_TIMEOUT` to "failed" or returned a wrong sentinel would still pass. This is an accepts-all-outcomes assertion on an output whose correct value is known.
- **Recommended fix:** Assert `result["result"] == "timeout"` for the unsignalled self-thread wait, and add a positive case (signal an event/exit a thread) asserting `"signaled"`.

#### `test_enumerate_heaps_for_self` — MEDIUM — vacuously-satisfiable conditional (N6)
- **Location:** tests/test_bridges/test_process_win32.py:188
- **Current behavior:** Asserts the result is a list; the key checks on the first heap entry are guarded by `if heaps:`.
- **Why it is not a gate:** Every Win32 process always has at least one heap, so an implementation that returned `[]` (heap walk broken) would silently skip all field assertions and the test would pass on the `isinstance(list)` check alone. The conditional removes the only meaningful assertions when the real operation regresses to empty.
- **Recommended fix:** Assert `heaps` is non-empty (the process heap always exists) unconditionally, then validate the `id`/`flags`/`blocks` fields, and ideally assert the process default heap id (`GetProcessHeap`) appears.

### tests/test_bridges/test_realcov_03c_cutter.py

#### `test_relocations_real` — MEDIUM — existence-only (N8)
- **Location:** tests/test_bridges/test_realcov_03c_cutter.py:490
- **Current behavior:** Calls `get_relocations()` and asserts only `isinstance(relocations, list)`.
- **Why it is not a gate:** kernel32.dll carries a populated `.reloc` table, so the real result should be non-empty with structured entries. A bridge that always returned `[]`, or returned malformed relocation records, would pass this isinstance-only check. The test's name claims relocations are validated "on real PEs" but no relocation content is asserted.
- **Recommended fix:** Assert `relocations` is non-empty for kernel32 and validate each entry's address/type fields against the real reloc directory (cross-checked with pefile's `DIRECTORY_ENTRY_BASERELOC`).

### tests/test_bridges/test_sandbox_bridge.py

#### `test_diff_wraps_unexpected_exception` — MEDIUM — mock-the-thing-under-test (N5)
- **Location:** tests/test_bridges/test_sandbox_bridge.py:291
- **Current behavior:** Patches `_get_analysis_module` to return a `MagicMock` whose `diff_reports` raises `MemoryError`, then asserts the bridge re-raises as `ToolError` containing "Failed to diff reports" / "oom".
- **Why it is not a gate:** Both the analysis module and the instance/report are mocks, so the test only proves the bridge's try/except wrapper text, not that `diff` produces a correct diff against real reports. It gates the error string, not the diff capability. (The error-wrapping intent is partly legitimate, but the sibling tests F0002 drive the *real* analysis functions with malformed real reports, making this mock-driven variant redundant and weaker.)
- **Recommended fix:** Drive `diff` with two real `ExecutionReport` instances whose contents force a genuine failure in the real `diff_reports` (as the F0002 tests do for other methods), so the exception originates in production code rather than a configured mock.

#### `test_detect_behaviors_wraps_unexpected_exception` — MEDIUM — mock-the-thing-under-test (N5)
- **Location:** tests/test_bridges/test_sandbox_bridge.py:320
- **Current behavior:** Patches `_get_analysis_module` so `match_behaviors` raises `ZeroDivisionError`, asserts the bridge wraps it as `ToolError` with "Failed to detect behaviors" / "oops".
- **Why it is not a gate:** The behaviour-matching engine is mocked away; the assertion only proves the wrapper string. The real `detect_behaviors` capability (rule matching) is covered well elsewhere (F0003), so this case gates only the error-text path on a fully synthetic failure.
- **Recommended fix:** Trigger the failure from real `match_behaviors` by feeding a malformed real `ExecutionReport` (mirroring `test_extract_iocs_wraps_real_keyerror_from_bad_network_activity`), so the production code path raises.

#### `test_accepts_files_target` / `test_accepts_memory_target` — MEDIUM — self-fulfilling data (N10)
- **Location:** tests/test_bridges/test_sandbox_bridge.py:727, tests/test_bridges/test_sandbox_bridge.py:751
- **Current behavior:** Wire `instance.sandbox.yara_scan` (AsyncMock) to return `[]`, then assert `result["match_count"] == 0` and `result["matches"] == []`.
- **Why it is not a gate:** The empty match list is injected by the test's own mock; the bridge merely passes it through. The assertion that count==0 only confirms `len([])==0` of test-supplied data — a broken scan-result transformation that, say, dropped real matches would not be caught because there are no real matches to drop. These two cases only meaningfully gate that the valid `scan_target` values are *not rejected* (the negative cases at 692/711 already gate the validation), so the count/matches assertions add no real coverage.
- **Recommended fix:** Return a non-empty mock match list with distinguishing fields and assert the bridge's transformed output preserves those fields and that `match_count == len(matches)` with a value > 0, so a transform regression (dropping/renaming match fields) is caught.

### tests/test_bridges/test_win32_types.py

#### `test_context64_has_rip_rsp` / `test_context32_has_eip_esp` — MEDIUM — existence-only (N8)
- **Location:** tests/test_bridges/test_win32_types.py:354, tests/test_bridges/test_win32_types.py:362
- **Current behavior:** Instantiate `CONTEXT64()` / `CONTEXT32()` and assert via `hasattr` that a handful of register fields are present.
- **Why it is not a gate:** `hasattr` on a ctypes Structure only proves the field name was declared; it does not verify the field's `_fields_` offset or type. A wrong offset/type in the CONTEXT layout (which is the realistic failure mode that would corrupt register reads) would still pass because the attribute still exists. The test name claims field verification but verifies only presence.
- **Recommended fix:** Assert `ctypes.sizeof(CONTEXT64)`/`CONTEXT32` equals the documented structure size and assert the byte offset of `Rip`/`Eip` (via the field descriptor's `.offset`) matches the known Win32 layout, so an offset regression trips the gate.

#### `test_memory_basic_information_has_all_fields` — MEDIUM — existence-only (N8)
- **Location:** tests/test_bridges/test_win32_types.py:370
- **Current behavior:** Instantiates `MEMORY_BASIC_INFORMATION()` and `hasattr`-checks its seven fields.
- **Why it is not a gate:** Same as above — presence of the attribute does not prove the field offset/type, and a mis-laid-out MBI (the realistic regression) would still satisfy `hasattr`. The `protection_to_string`/`state_to_string` tests cover the decoders, but this structure-layout test does not actually constrain the layout.
- **Recommended fix:** Assert `ctypes.sizeof(MEMORY_BASIC_INFORMATION)` equals the documented size for the build's pointer width and assert the offset of `Protect`/`State`/`RegionSize` against the known layout.

#### `TestDllHelperCaching::test_get_*_returns_non_none` (5 cases) — LOW — existence-only smoke (N8)
- **Location:** tests/test_bridges/test_win32_types.py:386, :394, :402, :410, :418, :426
- **Current behavior:** Assert each `get_kernel32()`/`get_ntdll()`/... returns non-None.
- **Why it is not a gate:** `WinDLL("kernel32")` essentially cannot return None on Windows; a broken helper would raise rather than return None, so the "is not None" assertion can never fail meaningfully. (The paired `_cached` tests at :390/:398/... *do* gate the lru-cache identity, so those are genuine.)
- **Recommended fix:** Fold the non-None check into the caching test or strengthen it: assert the returned object actually resolves a known exported symbol (e.g. `get_kernel32().GetCurrentProcessId()` returns the current PID) so a wrong-DLL handle is caught.

### tests/test_bridges/test_x64dbg.py

#### `test_bridge_instantiation` — CRITICAL — vacuous (N4)
- **Location:** tests/test_bridges/test_x64dbg.py:66
- **Current behavior:** `bridge = X64DbgBridge(); assert bridge is not None`.
- **Why it is not a gate:** `X64DbgBridge()` can never return None; if the constructor were broken it would raise (failing collection/other tests), so this assertion is unfalsifiable. It protects nothing.
- **Recommended fix:** Delete; instantiation is already exercised by every other test in the file. If a smoke check is desired, assert a concrete post-construction invariant (e.g. default capabilities) instead of `is not None`.

#### `test_breakpoint_info_fields` — MEDIUM — existence-only (N8)
- **Location:** tests/test_bridges/test_x64dbg.py:134
- **Current behavior:** Asserts the `BreakpointInfo` dataclass field-name set is a superset of `{id, address, bp_type, enabled, hit_count}`.
- **Why it is not a gate:** Checks only that field *names* exist on the dataclass; it never constructs a `BreakpointInfo` nor verifies field types/defaults/behaviour. A field whose type or semantics regressed would still pass. The behavioural breakpoint tests in this file already construct and round-trip `BreakpointInfo`, making this names-only check redundant and non-gating.
- **Recommended fix:** Delete (covered by the construct-and-retrieve tests), or assert a constructed instance's field values/types rather than the name set.

#### `test_disassemble_requires_capstone` — CRITICAL — vacuous conditional (N1/N6)
- **Location:** tests/test_bridges/test_x64dbg.py:374
- **Current behavior:** The entire body runs only inside `if get_capstone() is None:`. When capstone is present (the normal CI/dev environment, where capstone is a dependency) the test executes **no assertion at all** and passes.
- **Why it is not a gate:** In every environment where capstone is installed this is a no-assertion test (always green regardless of bridge behaviour). Even when capstone is absent it only asserts an empty list, which the rich `test_disassemble_real_exported_function` already covers more strongly. The conditional makes the assertion vanish exactly when the real disassembly path exists.
- **Recommended fix:** Either remove the conditional and use `pytest.importorskip("capstone")`-style skip on the *absent* case while making the present case assert real disassembly, or delete it as redundant with `test_disassemble_real_exported_function`.

### tests/test_bridges/test_x64dbg_audit6.py

#### `test_step_does_not_use_fixed_sleep` — LOW — source-string proxy (N9)
- **Location:** tests/test_bridges/test_x64dbg_audit6.py:3629
- **Current behavior:** Reads the source text of `step_into`/`step_over`/`step_out` with `inspect.getsource` and asserts the literal `"asyncio.sleep"` does not appear.
- **Why it is not a gate:** It gates a source-text property, not behaviour. A regression that reintroduced a fixed delay via `time.sleep`, a helper, or `await asyncio.sleep` reached through an alias would pass; conversely a harmless comment containing the literal would falsely fail. The behavioural sibling `test_step_resolves_on_paused_event` / `test_step_times_out_when_no_pause_arrives` already prove the event-driven wait, so this string check is a weak supplement.
- **Recommended fix:** Keep the behavioural event/timeout tests as the gate; if a "no fixed delay" guarantee is wanted, assert it by timing — e.g. that the step resolves promptly once the paused event fires rather than after a fixed interval — instead of scanning source text.

### tests/test_bridges/test_x64dbg_events.py

#### `test_handle_event_with_no_callbacks` — CRITICAL — no-assert (N1)
- **Location:** tests/test_bridges/test_x64dbg_events.py:183
- **Current behavior:** Dispatches a breakpoint event to a bridge with no callbacks and makes no assertion ("did not raise").
- **Why it is not a gate:** No assertion exists; the test passes as long as `_handle_event` does not throw. A regression that, say, failed to update a registered breakpoint's hit count, or mishandled the no-callback path while still not raising, would pass. It protects only against an exception, not against correct no-op behaviour.
- **Recommended fix:** Register a breakpoint at the event address and assert its `hit_count` increments even with zero *user* callbacks (proving the internal hit-counting path runs), or at minimum assert the callback list is unchanged and no state was corrupted.

#### `test_unknown_event_does_not_crash` — CRITICAL — no-assert (N1)
- **Location:** tests/test_bridges/test_x64dbg_events.py:227
- **Current behavior:** Dispatches `{"event": "unknown_event"}` and makes no assertion.
- **Why it is not a gate:** "Does not crash" with no assertion is unfalsifiable beyond an exception. A regression that mis-routed an unknown event (e.g. incremented an unrelated counter or invoked callbacks with a wrong type) would not be caught.
- **Recommended fix:** Register a callback and assert it *is* invoked with `event_type == "unknown_event"` (the dispatcher forwards all events), and that no breakpoint/watchpoint hit counts changed — turning the "graceful handling" claim into a real assertion.

## Acceptable skips (not flagged)

- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:136 — module-level `skipif(not _hexcore_available())`: legitimately skips when the optional Rust `intellicrack_hexcore` backend is not built; `open_file` genuinely cannot run without it, so this is an environment-capability skip, not masking a core bridge defect that could otherwise be exercised.
- tests/test_bridges/test_realcov_01_hex_editor_pe_real.py:299 `test_ntdll_exports_native_syscalls` — skips only if ntdll.dll is absent from the resolved real DLL set; that is a fixture-availability skip and the kernel32 export test still hard-gates the export path.
- tests/test_bridges/test_realcov_03c_cutter.py:53 / :79 — `is_available()`/`EXPECT_RIZIN_BACKEND` skips when rizin/radare2 is not on PATH; the external tool is genuinely required and the `EXPECT_RIZIN_BACKEND` enforcement path converts the skip into a hard failure in CI, so this is a correct environment-capability skip.
- tests/test_bridges/test_realcov_03c_cutter.py:135 `_first_real_text_function` / :516 `test_xrefs_to_real_callee` — skip only when real analysis genuinely produced no sized functions / no inbound xrefs in the scanned set; these are data-shape skips on real engine output, not masking a missing capability.
- tests/test_bridges/test_realcov_03a_frida_modules.py:46 — `importorskip("frida")` plus `spawns_process`/Windows markers: frida and a spawnable process are real environment prerequisites; the sandbox harness runs them, so skipping elsewhere is legitimate.
- tests/test_bridges/test_realcov_02b_named_pipe_real.py:60 — Windows-only `skipif` for kernel named pipes: a genuine OS-capability gate.
- tests/test_bridges/test_x64dbg.py:383 / :402 / :550, test_x64dbg_audit6.py:2173 — `get_capstone()/get_keystone()`-absent or `importorskip("capstone")` skips on the disassemble/assemble *real-memory* tests: the engines are genuine optional native deps; the rich real-disassembly assertions still gate behaviour when present. (Distinct from the flagged `test_disassemble_requires_capstone`, whose problem is the no-assert present-case path, not the skip.)
- Numerous `skipif(sys.platform != "win32")` across test_process_win32.py, test_x64dbg*.py, test_win32_types.py — Win32 APIs are the thing under test; non-Windows skip is a correct platform-capability gate.
- tests/test_bridges/test_x64dbg_audit6.py:2056/2216/2257/2305/2351, :3260/:3268 — Windows-only branch skips inside otherwise cross-platform regression tests; legitimate platform gates.

## Notes on mock-heavy files judged as genuine gates
- tests/test_bridges/test_sandbox_bridge.py and the x64dbg `_FakePipeClient`-based suites (audit6/audit7) substitute only the *transport boundary* (the OS named pipe / the SandboxManager lookup), while the bridge's own command construction, response parsing, post-condition verification, error classification, and state tracking run as real production code and are asserted on exact values. These are integration gates against the real bridge logic and are NOT flagged as N5 — the unit under test (the bridge method) is not itself mocked. Only the four sandbox cases above (which mock the actual analysis function the test names, or assert test-injected empty data) cross into N5/N10.
