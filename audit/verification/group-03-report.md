# Group 03 Verification Report — X64DbgBridge

**Auditor:** GROUP 03 adversarial verifier  
**Source:** `audit/test-coverage-audit/section-03-debugger-bridges.md`, X64DbgBridge subsystem only (lines ~22–144)  
**Scope:** Every non-REAL row in the X64Dbg Operation Inventory table (§1). FridaBridge is excluded (GROUP 04).  
**Method:** Enumerate independently from the table; search `tests/` for new gates; apply the three-part rubric strictly.

---

## Enumeration Notes

The audit source listed `test_x64dbg_audit7_f0001.py` in its inspected-files header (line ~14) and its inventory table
rated `trace_into`, `trace_over`, `step_count`, `animate_start`, and `animate_stop` as REAL (citing that file).
The wave-2b test files (`test_x64dbg_wave2b_*.py`) are entirely new (untracked in git). The file
`test_x64dbg_audit6.py` is modified (staged) and contains at least one new test function
(`test_get_threads_populates_start_address_and_pc`, line 2046) added as part of remediation.

PD-002 (`set_thread_context` drops dr0–dr3) is a **ProcessBridge** defect; `set_thread_context` does not appear
in the X64Dbg inventory table and is therefore outside this group's scope.

---

## Findings Table

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation) |
|---|------------------------|-----------------|-----|------------------------------------------|
| 1 | `initialize(tool_path)` (x64dbg.py:2051) | WEAK | NOT_RESOLVED | No new gate added; wave-2b does not cover it; direct test of init logic (non-existent path, path-without-DLL) still missing |
| 2 | `load(path, args)` (x64dbg.py:2734) | NO COVERAGE | NOT_RESOLVED | No test anywhere in `tests/` — wave-2b silent on this |
| 3 | `attach(pid)` (x64dbg.py:2849) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 4 | `detach()` (x64dbg.py:2974) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 5 | `spawn(path, args)` (x64dbg.py:4400) | WEAK | NOT_RESOLVED | Wave-2b does not add a success-path gate; ToolError-only path remains the sole coverage |
| 6 | `shutdown()` (x64dbg.py:9169) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 7 | `remove_breakpoint(address)` (x64dbg.py:3341) | WEAK | RESOLVED | `test_x64dbg_wave2b_breakpoints.py::TestRemoveBreakpointCommandFraming::test_bp_remove_issued_with_exact_address` — oracle: `_BP_ADDR = 0x401000` constant; asserts `("bp_remove", {"address": _BP_ADDR}) in fake.sent`; mutation: sending hex-string address → dict-equality fails |
| 8 | `set_watchpoint(...)` (x64dbg.py:3412) | WEAK | RESOLVED | `test_x64dbg_wave2b_breakpoints.py::TestSetWatchpointCommandFraming::test_write_watch_type_maps_to_w_access` — oracle: access-type map `{"write": "w", "read": "r", "execute": "x"}`; mutation: removing type_map → access defaults to "rw" → exact-equality fails |
| 9 | `remove_watchpoint(id)` (x64dbg.py:3456) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_breakpoints.py::TestRemoveWatchpoint::test_wp_remove_issued_with_watchpoint_address` — oracle: `_WP_ADDR = 0x500000`; mutation: sending id instead of address → params assertion fails |
| 10 | `get_registers()` (x64dbg.py:3527) | FAKE GATE | RESOLVED | `test_x64dbg_wave2b_registers.py::TestGetRegisters::test_parses_hex_string_and_int_values` line ~276 — oracle: `_RAX_VALUE = 0xDEAD_BEEF`, `_RIP_VALUE`, `_CS_VALUE`, `_SS_VALUE`; asserts `state.rax == _RAX_VALUE`; mutation: return zeroed RegisterState → value assertions fail |
| 11 | `set_register(name, value)` (x64dbg.py:3623) | FAKE GATE | RESOLVED | `test_x64dbg_wave2b_registers.py::TestSetRegister::test_emits_reg_set_with_register_key_not_name` line ~368 — oracle: param key `"register"` (not `"name"`); mutation: using `"name"` key → exact-dict assertion fails |
| 12 | `get_memory_regions()` (x64dbg.py:3881) | WEAK | NOT_RESOLVED | No new test added in any remediation file; pre-existing `test_memory_protection_changes` (test_x64dbg.py:472) was inspected by auditor and still rated WEAK; missing: a non-platform-gated field-level assertion |
| 13 | `get_stack_trace()` (x64dbg.py:4173) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 14 | `get_threads()` (x64dbg.py:5216) | WEAK | RESOLVED | `test_x64dbg_audit6.py:2046` (`test_get_threads_populates_start_address_and_pc`) — oracle: `{"running","suspended","terminated"}` state set + `start_address != 0`; also `test_realcov_02a_x64dbg.py:188` asserts `GetCurrentThreadId() in thread_ids`; mutation: not populating `state` → set intersection fails; not populating `start_address` → `any(...!=0)` fails |
| 15 | `execute_til_return()` (x64dbg.py:5964) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_trace.py::TestExecuteTilReturn::test_sends_erun_via_exec_rpc` line ~471 — oracle: `"erun"` command string; mutation: substituting `"rtr"` → exact-string assertion fails |
| 16 | `skip_instruction()` (x64dbg.py:5974) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_trace.py::TestSkipInstruction::test_one_byte_nop_advances_rip_by_one` line ~590 — oracle: NOP opcode 0x90 = 1 byte → `new_ip = _SKIP_IP + 1`; mutation: using `len("90")=2` instead of `len(bytes.fromhex("90"))=1` → wrong new_ip fails |
| 17 | `set_ip(address)` (x64dbg.py:6006) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_trace.py::TestSetIp::test_64bit_mode_sends_rip_exec_command` line ~763 — oracle: exec command `f"rip={hex(target)}"`; mutation: using `"eip"` for 64-bit target → assertion fails |
| 18 | `get_labels(start, end)` (x64dbg.py:6064) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 19 | `get_comments(start, end)` (x64dbg.py:6142) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 20 | `set_breakpoint_on_api(module, fn)` (x64dbg.py:6302) | WEAK | RESOLVED | `test_x64dbg_wave2b_breakpoints.py::TestSetBreakpointOnApi::test_resolved_path_drives_eval_then_bp_set` line ~695 — oracle: expression `GetProcAddress(kernel32,"CreateFileW")`; mutation: wrong expression format → eval_calls assertion fails; also verifies bp_set address matches eval return |
| 21 | `trace_start(...)` (x64dbg.py:6720) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_trace.py::TestTraceStart` — oracle: `"StartRunTrace"`, `"TraceSetLog"`, `"TraceSetCondition"` command strings and their order; mutation: misspelling any command → exact-string assertion fails |
| 22 | `trace_stop()` (x64dbg.py:6744) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_trace.py::TestTraceStop::test_sends_stop_run_trace_command` — oracle: `"StopRunTrace"`; mutation: using `"StopTrace"` → fails |
| 23 | `set_exception_config(code, handling)` (x64dbg.py:6754) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 24 | `get_module_imports(module_name)` (x64dbg.py:6903) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_patch.py::TestGetModuleImports::test_sends_mod_imports_with_name_and_parses_result` — oracle: `_IMPORT_IAT_RVA = "0x1234"`, `_IMPORT_NAME = "CreateFileW"`; mutation: wrong param key `"module"` vs `"name"` → params assertion fails |
| 25 | `find_references(address)` (x64dbg.py:6918) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 26 | `find_string_references(module)` (x64dbg.py:6936) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 27 | `find_intermodular_calls(module)` (x64dbg.py:6954) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_patch.py::TestFindIntermodularCalls::test_ref_search_framing_and_references_returned` — oracle: `{"module": _MODULE_NAME, "type": "intermodular"}`; mutation: using `"type": "cross_module"` → params assertion fails |
| 28 | `get_function_cfg(address, max_blocks)` (x64dbg.py:6972) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 29 | `clear_database()` (x64dbg.py:7030) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 30 | `get_patches()` (x64dbg.py:7049) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_patch.py::TestGetPatches::test_sends_patch_list_and_returns_parsed_records` — oracle: `_PATCH_OLD_BYTE = "0x55"`, `_PATCH_NEW_BYTE = "0x90"`; mutation: wrong RPC name → AssertionError in responder |
| 31 | `restore_patch(address)` (x64dbg.py:7070) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_patch.py::TestRestorePatch::test_sends_patch_restore_with_hex_address` — oracle: `hex(_PATCH_ADDR)`; mutation: decimal address encoding → exact-dict assertion fails |
| 32 | `export_patches(path)` (x64dbg.py:7092) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_patch.py::TestExportPatches::test_sends_savedata_command_with_quoted_path` — oracle: `f'savedata "{_EXPORT_PATH}"'`; mutation: missing quotes → exact-string fails |
| 33 | `get_seh_chain()` (x64dbg.py:7319) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_registers.py::TestGetSehChain::test_returns_parsed_entry_dicts` — oracle: `_SEH_HANDLER_0 = "0x401000"`, `_SEH_NEXT_0 = "0xFFFFFFFF"`; mutation: returning dict instead of list → `len(entries)` fails |
| 34 | `read_peb()` (x64dbg.py:7340) | FAKE GATE | RESOLVED | `test_x64dbg_wave2b_registers.py::TestReadPeb::test_returns_exact_peb_fields` line ~411 — oracle: `_PEB_ADDRESS = "0x7FFE0000"`, `_PEB_BEING_DEBUGGED = 0`, `_PEB_NT_GLOBAL_FLAG = 0x70`; mutation: returning `{}` → all field assertions fail; also confirms `("peb_read", None) in fake.sent` |
| 35 | `read_teb(tid)` (x64dbg.py:7368) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_registers.py::TestReadTeb::test_no_tid_sends_null_params` + `test_with_tid_forwards_tid_in_params` — oracle: `_TEB_STACK_BASE`, `_TEB_THREAD_ID`, `_TEB_TID_ARG`; mutation: dropping tid param → exact-params assertion fails |
| 36 | `get_pe_directories(module_name)` (x64dbg.py:7393) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_registers.py::TestGetPeDirectories::test_forwards_module_name_and_returns_entries` — oracle: `_PE_DIR_EXPORT_RVA = 0x1000`, `_PE_DIR_EXPORT_SIZE = 0x200`; mutation: using wrong param key `"module_name"` vs `"module"` → params assertion fails |
| 37 | `remove_watch(index)` (x64dbg.py:7439) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 38 | `get_watches()` (x64dbg.py:7461) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 39 | `set_logging_breakpoint(address, log_text)` (x64dbg.py:7482) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_breakpoints.py::TestSetLoggingBreakpoint::test_three_exec_commands_emitted_when_non_stopping` — oracle: `f"bp {hex(_BP_ADDR)}"`, `f'SetBreakpointLog {hex(_BP_ADDR)}, "..."'`, `f"SetBreakpointFastResume {hex(_BP_ADDR)}, 1"`; mutation: removing fast-resume command → count assertion fails |
| 40 | `configure_breakpoint(...)` (x64dbg.py:7500) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_breakpoints.py::TestConfigureBreakpoint` — oracle: exact `bpcond`, `SetBreakpointLog`, `SetBreakpointCommand`, `SetBreakpointFastResume` command strings; mutation: misspelling any command name → exact-string assertion fails |
| 41 | `set_dll_breakpoint(dll_name, event)` (x64dbg.py:7532) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_breakpoints.py::TestSetDllBreakpoint` — oracle: `f'LibrarianSetBreakPoint "{_DLL_NAME}"'` and `f'LibrarianSetBreakPoint "{_DLL_NAME}", unload'`; mutation: missing quotes or wrong suffix → exact-string assertion fails |
| 42 | `trace_into(condition, max_steps)` (x64dbg.py:7549) | NO COVERAGE | RESOLVED | `test_x64dbg_audit7_f0001.py::TestTraceAndAnimateVerification::test_trace_into_success` line ~593 — oracle: `{"paused": False}` status; asserts `result["verified"] is True`; failure counterpart asserts `ToolError(match="trace_into verification failed")`; mutation: ignoring `paused` field → verified never True → success test fails |
| 43 | `trace_over(condition, max_steps)` (x64dbg.py:7597) | NO COVERAGE | RESOLVED | `test_x64dbg_audit7_f0001.py::TestTraceAndAnimateVerification::test_trace_over_success` line ~640 — same oracle/mutation pattern as trace_into |
| 44 | `get_trace_record(address, size)` (x64dbg.py:7642) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_trace.py::TestGetTraceRecord::test_returns_parsed_hit_count_from_canned_response` — oracle: `_HIT_COUNT = 42`; asserts `result["hitCount"] == 42`; mutation: reading wrong key → returns 0 → fails |
| 45 | `step_count(count, step_type)` (x64dbg.py:7667) | NO COVERAGE | RESOLVED | `test_x64dbg_audit7_f0001.py::TestTraceAndAnimateVerification::test_step_count_success` line ~687 — oracle: `{"paused": True}` status after budget exhausted; asserts `result["verified"] is True`; mutation: ignoring paused field → fails |
| 46 | `analyze_entropy(address, size, block_size)` (x64dbg.py:7808) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 47 | `yara_scan(rule_text, rule_path)` (x64dbg.py:7899) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 48 | `script_load(path)` (x64dbg.py:7997) | WEAK | NOT_RESOLVED | No new gate; test_x64dbg_audit6.py:1575 still only checks that a debug-log event named `x64dbg_command_queued` is emitted; the `sent` list on a fake pipe is never checked; missing: assert `("exec", {"command": ...}) in fake.sent` with the script path embedded |
| 49 | `script_run()` (x64dbg.py:8038) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 50 | `script_cmd(line)` (x64dbg.py:8074) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 51 | `script_abort()` (x64dbg.py:8114) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 52 | `get_handles()` (x64dbg.py:8259) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_registers.py::TestGetHandles::test_parse_handle_buffer_filters_by_pid` (Windows-only) — oracle: `_HANDLE_GRANTED_ACCESS = 0x001F_0001`, `_HANDLE_TYPE_INDEX = 0x25`, `_HANDLE_VALUE = 0x14`; mutation: removing PID filter → both entries returned → `len(result)==1` fails |
| 53 | `close_handle(handle)` (x64dbg.py:8377) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 54 | `detect_anti_debug()` (x64dbg.py:8390) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_patch.py::TestDetectAntiDebug::test_nt_global_flag_mask_detected` — oracle: `(0x70 & 0x70) != 0` is `True`; asserts `result["checks"]["nt_global_flag_set"] is True`; mutation: using mask `0xFF00` → `0x70 & 0xFF00 == 0` → assertion fails |
| 55 | `reconstruct_imports(oep, output_path)` (x64dbg.py:8593) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_patch.py::TestReconstructImports::test_scylla_reconstruct_rpc_framing` — oracle: `hex(_OEP) = "0x401000"` (not decimal); mutation: decimal OEP → params assertion fails; fallback test confirms three script commands |
| 56 | `goto_address(address)` (x64dbg.py:8657) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_trace.py::TestGotoAddress::test_emits_goto_rpc_with_hex_address_param` — oracle: `("goto", {"address": hex(_GOTO_ADDR)})`; mutation: renaming RPC to `"navigate"` → AssertionError in responder |
| 57 | `get_tls_callbacks(module_name)` (x64dbg.py:8670) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_registers.py::TestGetTlsCallbacks::test_enumerates_two_callbacks_until_null_terminator` — oracle: `_TLS_CB0_VA = 0x1_4000_3000`, `_TLS_CB1_VA = 0x1_4000_4000`; mutation: reading callback-array VA from offset 24 instead of 20 → reads 0 → returns empty list → `len(result)==2` fails |
| 58 | `break_on_tls_callbacks(module_name)` (x64dbg.py:8708) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 59 | `get_resources(module_name)` (x64dbg.py:8726) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 60 | `get_privileges()` (x64dbg.py:8924) | NO COVERAGE | RESOLVED | `test_x64dbg_wave2b_registers.py::TestGetPrivileges::test_privilege_names_start_with_se` (Windows-only) — oracle: Windows privilege name prefix `"Se"` (OS spec); mutation: not calling `LookupPrivilegeNameW` → empty names → `startswith("Se")` fails |
| 61 | `adjust_privilege(name, enable)` (x64dbg.py:9034) | NO COVERAGE | NOT_RESOLVED | No test anywhere — wave-2b silent on this |
| 62 | `_coerce_address(value)` (x64dbg.py:392-416) | NO COVERAGE | NOT_RESOLVED | Hex-string path exercised indirectly via `test_x64dbg_wave2b_breakpoints.py::test_bp_list_hex_address_string_parsed` but the documented `bool → None` edge case and non-parseable input remain without any direct unit test |
| 63 | `_x64dbg_error_code(exc)` (x64dbg.py:378-389) | WEAK | NOT_RESOLVED | No direct test added; still only exercised as a side-effect of broader tests; missing: assert missing-key and non-string-value inputs produce specific codes |

---

## STILL OPEN (29 NOT_RESOLVED)

1. **`initialize(tool_path)`** (x64dbg.py:2051) :: WEAK — initialization logic still indirectly reached at best :: missing: `_install_fake_pipe` after calling `bridge.initialize(path)` with a non-existent path; assert `ToolError("plugin_unavailable")` raised; assert a valid path sets `bridge._x64dbg_path`

2. **`load(path, args)`** (x64dbg.py:2734) :: NO COVERAGE — zero tests :: missing: assert `ToolError` with message containing `"not running"` when called without an attached process; assert the subprocess spawn call is made with the exact path

3. **`attach(pid)`** (x64dbg.py:2849) :: NO COVERAGE — zero tests :: missing: assert `ToolError("invalid pid")` for PID 0; assert `bridge.attached_pid == pid` after attaching to current process; assert `bridge.is_64bit` matches platform

4. **`detach()`** (x64dbg.py:2974) :: NO COVERAGE — zero tests :: missing: assert `bridge.attached_pid is None` after detach; assert `ToolError` if called without an attached process

5. **`spawn(path, args)`** (x64dbg.py:4400) :: WEAK — only ToolError on missing plugin :: missing: success path asserts `bridge.attached_pid` and `bridge._process is not None` after a real (or fake-pipe) spawn

6. **`shutdown()`** (x64dbg.py:9169) :: NO COVERAGE — zero tests :: missing: assert state cleanup (`bridge._pipe_client is None`, `bridge._process is None`, `bridge.attached_pid is None`) after shutdown; assert cleanup-phase exception does not propagate silently

7. **`get_memory_regions()`** (x64dbg.py:3881) :: WEAK — no new test added post-audit :: `test_memory_protection_changes` (test_x64dbg.py:472) was acknowledged by the original auditor and still rated WEAK due to platform gating; missing: assert `MemoryRegion.base_address > 0`, `MemoryRegion.size > 0`, and `"r" in protection` on at least one region without relying solely on Windows VirtualProtect

8. **`get_stack_trace()`** (x64dbg.py:4173) :: NO COVERAGE — zero tests :: missing: fake-pipe test returning stack frame list; assert `frame["return_address"]` and `frame["module"]` fields exactly

9. **`get_labels(start, end)`** (x64dbg.py:6064) :: NO COVERAGE — zero tests :: missing: `("label_list", {"start": hex(start), "end": hex(end)}) in fake.sent`; assert returned entries have `"address"` and `"text"` keys

10. **`get_comments(start, end)`** (x64dbg.py:6142) :: NO COVERAGE — zero tests :: missing: same pattern as get_labels via `comment_list` RPC

11. **`set_exception_config(code, handling)`** (x64dbg.py:6754) :: NO COVERAGE — zero tests :: missing: assert `exec` command sent with the correct exception code and handling string; assert `"pass"` vs `"break"` handling mapping

12. **`find_references(address)`** (x64dbg.py:6918) :: NO COVERAGE — zero tests :: missing: assert `ref_search` RPC with `{"address": hex(address)}`; assert returned list contains `{"from": ..., "to": ...}` entries

13. **`find_string_references(module)`** (x64dbg.py:6936) :: NO COVERAGE — zero tests :: missing: assert `ref_search` or `string_refs` RPC with module name; assert returned entries have `address` and `string` fields

14. **`get_function_cfg(address, max_blocks)`** (x64dbg.py:6972) :: NO COVERAGE — zero tests :: missing: assert `cfg_get` RPC; assert returned dict has `"blocks"` list with `"start"` and `"end"` per block

15. **`clear_database()`** (x64dbg.py:7030) :: NO COVERAGE — zero tests :: missing: assert `db_clear` RPC; assert `result["success"] is True`

16. **`remove_watch(index)`** (x64dbg.py:7439) :: NO COVERAGE — zero tests :: missing: assert `wp_remove` or `watch_remove` RPC with the watch index; assert entry removed from local registry

17. **`get_watches()`** (x64dbg.py:7461) :: NO COVERAGE — zero tests :: missing: assert `watch_list` RPC; assert entries have `"expression"`, `"value"`, `"type"` fields

18. **`analyze_entropy(address, size, block_size)`** (x64dbg.py:7808) :: NO COVERAGE — zero tests :: missing: assert entropy values returned for known patterns (e.g. all-zero bytes → 0.0 entropy); assert recoverable read failure on unreadable page skips block rather than aborting

19. **`yara_scan(rule_text, rule_path)`** (x64dbg.py:7899) :: NO COVERAGE — zero tests :: missing: assert `yara_scan` RPC framing; assert `ToolError` with "yara not available" when yara not installed; assert empty rule raises `ToolError`

20. **`script_load(path)`** (x64dbg.py:7997) :: WEAK — log-event check only :: missing: `("exec", {"command": f"scriptload \"{path}\""}) in fake.sent`; current test (test_x64dbg_audit6.py:1575) only verifies a log event name, not the actual command sent to x64dbg

21. **`script_run()`** (x64dbg.py:8038) :: NO COVERAGE — zero tests :: missing: assert `"scriptrun"` exec command

22. **`script_cmd(line)`** (x64dbg.py:8074) :: NO COVERAGE — zero tests :: missing: assert exec command contains the exact script line

23. **`script_abort()`** (x64dbg.py:8114) :: NO COVERAGE — zero tests :: missing: assert `"scriptabort"` exec command; assert `result["success"] is True`

24. **`close_handle(handle)`** (x64dbg.py:8377) :: NO COVERAGE — zero tests :: missing: assert `handle_close` or `CloseHandle` exec command with the handle value

25. **`break_on_tls_callbacks(module_name)`** (x64dbg.py:8708) :: NO COVERAGE — zero tests :: missing: assert `get_tls_callbacks` is called; assert `set_breakpoint` is issued for each callback address; assert empty callback list returns `{"success": True, "count": 0}`

26. **`get_resources(module_name)`** (x64dbg.py:8726) :: NO COVERAGE — zero tests :: missing: assert `resource_list` or `res_enum` RPC with module; assert recursive resource tree entries have `"type"`, `"id"`, `"language"` fields

27. **`adjust_privilege(name, enable)`** (x64dbg.py:9034) :: NO COVERAGE — zero tests :: missing: Windows-only live test; assert `ToolError` for unknown privilege name with exact message; assert `result["enabled"] == enable` after successful adjustment

28. **`_coerce_address(value)`** (x64dbg.py:392-416) :: NO COVERAGE (edge cases) :: hex-string path exercised indirectly; missing: `assert _coerce_address(True) is None` (documented bool-input contract); `assert _coerce_address(None) is None`; `assert _coerce_address("not_hex") is None`

29. **`_x64dbg_error_code(exc)`** (x64dbg.py:378-389) :: WEAK — only exercised as side-effect :: missing: `assert _x64dbg_error_code(ToolError("pipe disconnected")) == "pipe_disconnected"`; `assert _x64dbg_error_code(ToolError({})) == "unknown"` (missing-string-value path)

---

## Quality Assessment of Resolved Gates

All 34 resolved findings meet the rubric:
- Assertions check exact values (field values, command strings, param dicts) — not `len > 0` or `is not None`.
- Every oracle is an independent constant defined before calling the production code.
- No `MagicMock`, no `patch()`, no inline suppression. Fake pipes are hand-rolled in-process classes.
- Every "not-attached" ToolError test uses `match=` (e.g. `match="not attached"`, `match="trace_into verification failed"`).
- Platform-gated tests (`sys.platform != "win32"`) use legitimate capability skips — the sandbox is Windows so these execute.
- All fake-pipe tests are deterministic: no sleep, no shared mutable state, no network.
