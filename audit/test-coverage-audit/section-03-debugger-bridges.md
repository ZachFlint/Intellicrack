# Section 03 — Debugger & Instrumentation Bridges: Test Coverage Audit

**Sources audited:**
- `src/intellicrack/bridges/x64dbg.py` (~9 200 lines, 120+ async operations)
- `src/intellicrack/bridges/frida_bridge.py` (~7 100 lines, 120+ async operations)

**Test files inspected:**
- `tests/test_bridges/test_x64dbg.py`
- `tests/test_bridges/test_x64dbg_api_coverage.py`
- `tests/test_bridges/test_x64dbg_audit6.py`
- `tests/test_bridges/test_x64dbg_audit7_f0001.py`
- `tests/test_bridges/test_x64dbg_events.py`
- `tests/test_bridges/test_x64dbg_new_methods.py`
- `tests/test_bridges/test_realcov_02a_x64dbg.py`
- `tests/test_bridges/test_frida_bridge.py`
- `tests/test_bridges/test_realcov_03a_frida_modules.py`
- `tests/test_audit5/u2_bridges_frida/test_frida_bridge_audit5.py`
- `tests/test_audit7/ui_panels_process/test_realcov_14a_x64dbg_panel.py` (X64Dbg UI panel, out of scope for bridge itself)

---

## 1. Operation Inventory — X64DbgBridge (`x64dbg.py`)

| Operation | Source line(s) | Test file:line | Verdict | Missing edges |
|-----------|---------------|----------------|---------|---------------|
| `initialize(tool_path)` | x64dbg.py:2051 | test_x64dbg_api_coverage.py:56-88 (indirect) | WEAK — not directly called; initialization logic untested | Non-existent path, path without plugin DLL, Windows vs. non-Windows |
| `is_available()` | x64dbg.py:2231 | test_x64dbg.py:281-301 | REAL — None path + nonexistent path both tested | Real installation path never tested |
| `load(path, args)` | x64dbg.py:2734 | NONE | NO COVERAGE | All paths |
| `attach(pid)` | x64dbg.py:2849 | NONE | NO COVERAGE | Invalid PID, already-attached, architecture detection failure |
| `detach()` | x64dbg.py:2974 | NONE | NO COVERAGE | Process crash during detach, state cleanup |
| `spawn(path, args)` | x64dbg.py:4400 | test_x64dbg_api_coverage.py:56-88 (ToolError only) | WEAK — only confirms ToolError on missing plugin | Real spawn, Windows path quirks |
| `shutdown()` | x64dbg.py:9169 | NONE (audit6 F-0011 via audit6 test description but no actual test asserting behavior) | NO COVERAGE | Cleanup-phase exception propagation, state reset |
| `step_into()` | x64dbg.py:3097 | test_x64dbg_api_coverage.py:56-88 | REAL (error classification gate) — checks `x64dbg_error_code == "plugin_unavailable"` and `command == "step_into"` | No real step; async Future waiter from F-0004 not exercised end-to-end |
| `step_over()` | x64dbg.py:3113 | test_x64dbg_api_coverage.py:56-88 | REAL (error classification gate) | Same as step_into |
| `step_out()` | x64dbg.py:3128 | test_x64dbg_api_coverage.py:56-88 | REAL (error classification gate) | Same |
| `run()` | x64dbg.py:2989 | test_x64dbg_api_coverage.py:56-88 | REAL (error classification gate) | |
| `pause()` | x64dbg.py:2994 | test_x64dbg_api_coverage.py:56-88 | REAL (error classification gate) | |
| `stop()` | x64dbg.py:2999 | test_x64dbg_api_coverage.py:56-88 | REAL (error classification gate) | |
| `set_breakpoint(address, type, condition)` | x64dbg.py:3143 | test_x64dbg_audit6.py:1261-1346 | REAL — fake pipe, verification path, absent path, protocol-violation path all gated | Conditional breakpoint (`bpcond`) path partially via audit6 F-0026 |
| `remove_breakpoint(address)` | x64dbg.py:3341 | test_x64dbg_api_coverage.py:100-116 | WEAK — only checks ToolError; success path is manual dict insert then dict read (tautology) | Actual removal confirmed by debugger |
| `get_breakpoints()` | x64dbg.py:3359 | test_x64dbg.py:148-199 | REAL — id, bp_type, enabled field checks | Empty list; plugin merge path |
| `set_watchpoint(...)` | x64dbg.py:3412 | test_x64dbg_api_coverage.py:119-131 | WEAK — only ToolError path; no success-path coverage | All |
| `remove_watchpoint(id)` | x64dbg.py:3456 | NONE | NO COVERAGE | All |
| `get_watchpoints()` | x64dbg.py:3480 | test_x64dbg.py:213-235 | REAL — id, size, watch_type field checks | Empty list |
| `get_registers()` | x64dbg.py:3527 | test_x64dbg_api_coverage.py:133-143 | FAKE GATE — only checks ToolError; if get_registers() returned garbage data after connection fix this test still passes | Real register values never verified |
| `set_register(name, value)` | x64dbg.py:3623 | test_x64dbg_api_coverage.py:133-143 | FAKE GATE — only ToolError path | Real write + read-back |
| `read_memory(address, size)` | x64dbg.py:3706 | test_x64dbg.py:330-345 | REAL — exact byte comparison against planted marker | Oversized read, partial read at region boundary |
| `write_memory(address, data)` | x64dbg.py:3749 | test_x64dbg.py:452-467 | REAL — write+read-back roundtrip | Cross-region write |
| `allocate_memory(size, protection)` | x64dbg.py:3792 | test_x64dbg_new_methods.py:363-419 | REAL — allocate, write, read-back, free roundtrip; multiple protection variants | Failed allocation |
| `free_memory(address)` | x64dbg.py:3848 | test_x64dbg_api_coverage.py:159-177 | REAL — allocate then free, `assert success is True` | Double-free, invalid address |
| `get_memory_regions()` | x64dbg.py:3881 | test_x64dbg.py:427-437 | WEAK — `assert len(memory_map) > 0` only; no protection/base/size field checks | Specific region coverage |
| `disassemble_at(address, count)` | x64dbg.py:4058 | test_x64dbg.py:360-400 | REAL — resolves kernel32!Sleep, verifies mnemonic non-empty, decoded bytes match live memory, monotonic addresses | capstone-unavailable path only skips; no structural failure test |
| `assemble_at(address, instruction)` | x64dbg.py:4141 | test_x64dbg.py:510-533 | REAL — assembles `nop`, asserts `b"\x90"`, writes to live buffer, reads back | keystone-unavailable path only skips |
| `get_stack_trace()` | x64dbg.py:4173 | NONE | NO COVERAGE | All |
| `scan_memory(pattern)` | x64dbg.py:4270 | test_x64dbg_new_methods.py:270-359, test_x64dbg.py:404-421 | REAL — planted marker found at known address; wildcard; hex string; too-short and empty raise tested | Cross-region wildcard boundary (F-0005 intent; audit6 E has coverage description but no explicit E-test in reviewed files) |
| `run_command(command)` | x64dbg.py:4388 | test_x64dbg_api_coverage.py:146-155 | REAL — "x64dbg not running" ToolError asserted | Connected path |
| `evaluate_expression(expression)` | x64dbg.py:4866 | test_x64dbg_audit6.py:1139-1208 | REAL — hex string, int, unparseable string, None, bool all tested via fake pipe | |
| `get_modules()` | x64dbg.py:5096 | tests/test_bridges/test_realcov_02a_x64dbg.py:104-141 | REAL — kernel32.dll/ntdll.dll base address verified against GetModuleHandleW, entry point within image | |
| `get_threads()` | x64dbg.py:5216 | test_x64dbg_api_coverage.py:180-204 | WEAK — `assert len(threads) > 0` only | Thread field validation (TID, state, start_address) |
| `get_process_info()` | x64dbg.py:5224 | test_x64dbg_audit6.py:656-758 | REAL — raises when detached; returns ProcessInfo with correct pid, threads, modules when stub provided | Real process walk |
| `find_pattern(pattern)` | x64dbg.py:5257 | test_x64dbg_new_methods.py:205-267 | REAL — planted bytes found at exact address; compact hex; wildcard | Multi-region wraparound |
| `run_to(address)` | x64dbg.py:5417 | test_x64dbg_audit6.py:1349-1417 | REAL — verified:True when IP matches; raises when IP never matches; verified:False when reg_get unknown | |
| `execute_til_return()` | x64dbg.py:5964 | NONE | NO COVERAGE | All |
| `skip_instruction()` | x64dbg.py:5974 | NONE | NO COVERAGE | All |
| `set_ip(address)` | x64dbg.py:6006 | NONE | NO COVERAGE | All |
| `set_label(address, text)` | x64dbg.py:6020 | test_x64dbg_audit7_f0001.py:144-199 | REAL — readback verified, mismatch raises, unknown plugin surfaces verified:False | |
| `get_labels(start, end)` | x64dbg.py:6064 | NONE | NO COVERAGE | All |
| `set_comment(address, text)` | x64dbg.py:6098 | test_x64dbg_audit7_f0001.py (omitted here, verified present) | REAL — readback gate | |
| `get_comments(start, end)` | x64dbg.py:6142 | NONE | NO COVERAGE | All |
| `enable_breakpoint(address)` | x64dbg.py:6176 | test_x64dbg_audit7_f0001.py | REAL — bp_list enabled-state verified | |
| `disable_breakpoint(address)` | x64dbg.py:6239 | test_x64dbg_audit7_f0001.py | REAL | |
| `set_breakpoint_on_api(module, fn)` | x64dbg.py:6302 | test_x64dbg_audit6.py (E section via description) | WEAK — coverage claimed via monkeypatching; not independently verified from tested file sections | Real API resolution |
| `dump_memory_to_file(address, size, path)` | x64dbg.py:6369 | test_x64dbg_new_methods.py:426-445 | REAL — planted bytes, asserts bytes_written, reads file back | |
| `get_module_sections(module_name)` | x64dbg.py:6462 | test_x64dbg_new_methods.py:453-498 | REAL — pefile oracle, .text characteristics==0x60000020, virtual_size match | |
| `get_module_exports(module_name)` | x64dbg.py:6624 | test_x64dbg_new_methods.py:500+ | REAL — verified against GetProcAddress for well-known kernel32 exports | |
| `get_entry_point(module_name)` | x64dbg.py:6654 | test_realcov_02a_x64dbg.py:144+ | REAL — consistent with get_modules base | |
| `trace_start(...)` | x64dbg.py:6720 | NONE | NO COVERAGE | All |
| `trace_stop()` | x64dbg.py:6744 | NONE | NO COVERAGE | All |
| `set_exception_config(code, handling)` | x64dbg.py:6754 | NONE | NO COVERAGE | All |
| `patch_instruction(address, instruction)` | x64dbg.py:6771 | test_x64dbg_audit6.py:1451-1471 | REAL — verified:False when not attached, patched_bytes None | With real write verification when attached |
| `nop_range(address, size)` | x64dbg.py:6818 | test_x64dbg_audit6.py:1429-1449 | REAL — verified:False when not attached, size/address checks | With real write verification when attached |
| `get_module_imports(module_name)` | x64dbg.py:6903 | NONE | NO COVERAGE | All |
| `find_references(address)` | x64dbg.py:6918 | NONE | NO COVERAGE | All |
| `find_string_references(module)` | x64dbg.py:6936 | NONE | NO COVERAGE | All |
| `find_intermodular_calls(module)` | x64dbg.py:6954 | NONE | NO COVERAGE | All |
| `get_function_cfg(address, max_blocks)` | x64dbg.py:6972 | NONE | NO COVERAGE | All |
| `save_database()` | x64dbg.py:6988 | test_x64dbg_audit6.py:1483-1525 | REAL — fallback path on unknown_command confirmed; pipe-disconnect propagates | |
| `load_database()` | x64dbg.py:7011 | test_x64dbg_audit6.py (F-0028 section) | REAL | |
| `clear_database()` | x64dbg.py:7030 | NONE | NO COVERAGE | All |
| `get_patches()` | x64dbg.py:7049 | NONE | NO COVERAGE | All |
| `restore_patch(address)` | x64dbg.py:7070 | NONE | NO COVERAGE | All |
| `export_patches(path)` | x64dbg.py:7092 | NONE | NO COVERAGE | All |
| `suspend_thread(tid)` | x64dbg.py:7105 | test_x64dbg_audit7_f0001.py, test_x64dbg_audit6.py:1543+ | REAL — thread_detail state verified; debug log gated | |
| `resume_thread(tid)` | x64dbg.py:7163 | test_x64dbg_audit7_f0001.py | REAL | |
| `switch_thread(tid)` | x64dbg.py:7219 | test_x64dbg_audit7_f0001.py | REAL | |
| `set_thread_name(tid, name)` | x64dbg.py:7262 | test_x64dbg_audit7_f0001.py | REAL | |
| `get_seh_chain()` | x64dbg.py:7319 | NONE | NO COVERAGE | All |
| `read_peb()` | x64dbg.py:7340 | test_x64dbg_audit6.py:832-849 | FAKE GATE — only checks tool definition's `returns` field for "address" keyword; no data-flow coverage | Real PEB read from live process |
| `read_teb(tid)` | x64dbg.py:7368 | NONE | NO COVERAGE | All |
| `get_pe_directories(module_name)` | x64dbg.py:7393 | NONE | NO COVERAGE | All |
| `add_watch(expression)` | x64dbg.py:7417 | test_x64dbg_audit7_f0001.py | REAL — watch_list readback verified | |
| `remove_watch(index)` | x64dbg.py:7439 | NONE | NO COVERAGE | All |
| `get_watches()` | x64dbg.py:7461 | NONE | NO COVERAGE | All |
| `set_logging_breakpoint(address, log_text)` | x64dbg.py:7482 | NONE | NO COVERAGE | All |
| `configure_breakpoint(...)` | x64dbg.py:7500 | NONE | NO COVERAGE | All |
| `set_dll_breakpoint(dll_name, event)` | x64dbg.py:7532 | NONE | NO COVERAGE | All |
| `trace_into(condition, max_steps)` | x64dbg.py:7549 | NONE | NO COVERAGE | All |
| `trace_over(condition, max_steps)` | x64dbg.py:7597 | NONE | NO COVERAGE | All |
| `get_trace_record(address, size)` | x64dbg.py:7642 | NONE | NO COVERAGE | All |
| `step_count(count, step_type)` | x64dbg.py:7667 | NONE | NO COVERAGE | All |
| `animate_start(step_type)` | x64dbg.py:7715 | test_x64dbg_audit7_f0001.py | REAL — is_running status poll verified | |
| `animate_stop()` | x64dbg.py:7759 | test_x64dbg_audit7_f0001.py | REAL | |
| `analyze_entropy(address, size, block_size)` | x64dbg.py:7808 | NONE | NO COVERAGE | Chunked read across unreadable page (F-0021) |
| `yara_scan(rule_text, rule_path)` | x64dbg.py:7899 | NONE | NO COVERAGE | No yara installed, empty rule, file not found, real match |
| `script_load(path)` | x64dbg.py:7997 | test_x64dbg_audit6.py:1575-1595 | WEAK — only checks debug log name; no verification of what was sent to debugger | Real script load result |
| `script_run()` | x64dbg.py:8038 | NONE | NO COVERAGE | All |
| `script_cmd(line)` | x64dbg.py:8074 | NONE | NO COVERAGE | All |
| `script_abort()` | x64dbg.py:8114 | NONE | NO COVERAGE | All |
| `plugin_load(path)` | x64dbg.py:8151 | test_x64dbg_audit7_f0001.py | REAL — plugin_list presence verified | |
| `plugin_unload(name)` | x64dbg.py:8195 | test_x64dbg_audit7_f0001.py | REAL | |
| `plugin_list()` | x64dbg.py:8237 | test_x64dbg_audit7_f0001.py | REAL | |
| `get_handles()` | x64dbg.py:8259 | NONE | NO COVERAGE | All |
| `close_handle(handle)` | x64dbg.py:8377 | NONE | NO COVERAGE | All |
| `detect_anti_debug()` | x64dbg.py:8390 | NONE | NO COVERAGE | All |
| `patch_anti_debug(checks)` | x64dbg.py:8412 | test_x64dbg_audit6.py:852-1049 | REAL — 64-bit/32-bit offsets, PEB missing, malformed address, read_peb failure, unsupported check, mixed known/unknown | |
| `reconstruct_imports(oep, output_path)` | x64dbg.py:8593 | NONE | NO COVERAGE | All |
| `get_status()` | x64dbg.py:8633 | test_x64dbg_audit6.py:1217-1252 | REAL — dict returned verbatim; list payload raises | |
| `goto_address(address)` | x64dbg.py:8657 | NONE | NO COVERAGE | All |
| `get_tls_callbacks(module_name)` | x64dbg.py:8670 | NONE | NO COVERAGE | All |
| `break_on_tls_callbacks(module_name)` | x64dbg.py:8708 | NONE | NO COVERAGE | All |
| `get_resources(module_name)` | x64dbg.py:8726 | NONE | NO COVERAGE | Real resource tree walk (F-0019) |
| `get_privileges()` | x64dbg.py:8924 | NONE | NO COVERAGE | All |
| `adjust_privilege(name, enable)` | x64dbg.py:9034 | NONE | NO COVERAGE | All |
| `_classify_legacy_error(message)` | x64dbg.py:348-375 | test_x64dbg_audit6.py:1055-1131 | REAL — pipe/unknown/real-error classifications via fake pipe, structured code override | |
| `_coerce_address(value)` | x64dbg.py:392-416 | NONE | NO COVERAGE | bool input, hex string, decimal string, None, non-parseable |
| `_x64dbg_error_code(exc)` | x64dbg.py:378-389 | NONE (exercised indirectly) | WEAK — no direct test | Missing key, non-string value |
| `register_event_callback` | x64dbg.py:2413 | test_x64dbg_events.py:64-88 | REAL | |
| `unregister_event_callback` | x64dbg.py:2428 | test_x64dbg_events.py:90-116 | REAL — non-existent no-op tested | |
| `_handle_event` (dispatch) | x64dbg.py (internal) | test_x64dbg_events.py:119-285 | REAL — callback invocation, isolation, hit-count, unknown-event forwarding | Concurrent dispatch race |
| `_read_unicode_string_from_params` | x64dbg.py:687 | test_x64dbg_audit6.py:589-648 | REAL — well-formed, odd length, length>MaximumLength | Zero-length, null buffer pointer |
| tool_definition schema | x64dbg.py:1010 | test_x64dbg.py:238-277, test_x64dbg_new_methods.py:75-202 | REAL — tool name, function count >= 104, every function maps to callable method | |

---

## 2. Operation Inventory — FridaBridge (`frida_bridge.py`)

| Operation | Source line(s) | Test file:line | Verdict | Missing edges |
|-----------|---------------|----------------|---------|---------------|
| `initialize(tool_path)` | frida_bridge.py:1190 | test_frida_bridge.py:162-183 (fixture) | REAL — real frida.get_local_device() invoked | frida not installed path |
| `is_available()` | frida_bridge.py:1342 | NONE | NO COVERAGE | All |
| `attach(pid, cancellable_id)` | frida_bridge.py:1356 | test_frida_bridge.py:162-183 (fixture) | REAL — attaches to real notepad | Invalid PID, process crash, permission denied |
| `attach_by_name(name, cancellable_id)` | frida_bridge.py:1444 | NONE | NO COVERAGE | All |
| `spawn(path, args, ...)` | frida_bridge.py:1523 | NONE | NO COVERAGE | All |
| `resume()` | frida_bridge.py:1650 | NONE | NO COVERAGE | Not spawned |
| `detach(kill_spawned)` | frida_bridge.py:1674 | test_frida_bridge.py:169-183 (fixture teardown) | WEAK — only exercised in fixture teardown with ToolError suppressed | kill_spawned=True path, double-detach |
| `read_memory(address, size)` | frida_bridge.py:1748 | test_frida_bridge.py:1234-1251 | REAL — byte-by-byte roundtrip | Non-integer inputs raises (audit5 test_f0015), page fault |
| `write_memory(address, data)` | frida_bridge.py:1793 | test_frida_bridge.py:1234-1251 | REAL — write then read-back | Non-integer address raises |
| `get_memory_regions(protection)` | frida_bridge.py:1827 | test_frida_bridge.py:1107-1130 | REAL — count >= 20, has executable+readable regions | Win32-constant leakage caught via audit5 test_f0018 |
| `scan_memory(pattern, module_name)` | frida_bridge.py:1890 | test_frida_bridge_audit5.py:327-351 | REAL — hex+wildcard accepted; malformed raises ToolError | |
| `enumerate_modules()` | frida_bridge.py:2051 | test_realcov_03a_frida_modules.py:116-141 | REAL — ntdll/kernel32 present, base in high range, 64KB-aligned, unique bases | |
| `enumerate_exports(module_name)` | frida_bridge.py:2107 | test_realcov_03a_frida_modules.py:145-165 | REAL — count >= 100, named exports present, addresses >= base | |
| `hook_function(target, on_enter, on_leave)` | frida_bridge.py:2173 | test_frida_bridge.py:1254-1270 | REAL — active, id, target field checked | Default no-console.log via audit5 test_f0005 |
| `remove_hook(hook_id)` | frida_bridge.py:2271 | test_frida_bridge.py:1254-1270 | REAL — returns True | |
| `get_hooks()` | frida_bridge.py:2290 | NONE | NO COVERAGE | All |
| `execute_script(script)` | frida_bridge.py:2301 | NONE | NO COVERAGE | Real execution; timeout raises (audit5 test_f0021 covers _execute_script_and_wait, not this public method) |
| `execute_persistent_script(script_code)` | frida_bridge.py:2328 | test_frida_bridge.py:913-938 (fixture) | REAL — used to create worker thread with real JS | |
| `unload_script(script_id)` | frida_bridge.py:2370 | test_frida_bridge_audit5.py:426-444 | REAL — secondary registries reaped | |
| `unload_all_scripts()` | frida_bridge.py:2716 | NONE | NO COVERAGE | All |
| `set_message_handler(handler)` | frida_bridge.py:2722 | NONE | NO COVERAGE | All |
| `intercept_return(target, return_value)` | frida_bridge.py:2387 | NONE | NO COVERAGE | All |
| `call_function(address, args, ...)` | frida_bridge.py:2411 | test_frida_bridge_audit5.py:354-374 | REAL — pointer truncation guarded; non-int address/bool raises | |
| `enumerate_imports(module_name)` | frida_bridge.py:2877 | test_frida_bridge.py:1043-1066 | REAL — count >= 10, function names present, resolved count | |
| `enumerate_threads()` | frida_bridge.py:2947 | test_frida_bridge.py:1021-1040 | REAL — count >= 2, TIDs positive, unique, valid state values | |
| `allocate_memory(size)` | frida_bridge.py:3009 | test_frida_bridge.py:1196-1212 | REAL — address > 0x10000, write+read roundtrip | Non-stop after address capture (audit5 test_f0022) |
| `protect_memory(address, size, protection)` | frida_bridge.py:3079 | test_frida_bridge.py:1215-1231 | REAL — returns True, write+read after protect | Invalid protection string rejects |
| `find_base_address(module_name)` | frida_bridge.py:3139 | test_frida_bridge.py:1069-1104 | REAL — high range, 64KB-aligned, deterministic | Module not found path: test_realcov_03a (ToolError) but no message check |
| `resolve_symbol(address)` | frida_bridge.py:3179 | test_frida_bridge.py:1155-1174 | REAL — address match, NtCreateFile in name, ntdll module | Unresolved raises ToolError (audit5 test_f0011) |
| `find_functions_named(name)` | frida_bridge.py:3245 | test_frida_bridge.py:1177-1193 | REAL — address in system DLL range | |
| `resolve_api(query, resolver_type)` | frida_bridge.py:3308 | test_frida_bridge.py:1133-1152 | REAL — CreateFileW found, address >= system range, '!' separator | |
| `replace_function(target, replacement_code, ...)` | frida_bridge.py:3371 | test_realcov_03a_frida_modules.py:181-211 | REAL — address matches export, active, id; invalid convention raises | |
| `enumerate_processes()` | frida_bridge.py:3462 | test_frida_bridge.py:957-976 | REAL — positive PIDs, unique, current PID present | |
| `stalker_follow(thread_id, events, limit)` | frida_bridge.py:3930 | test_frida_bridge.py:1273-1306 | REAL — non-empty trace ID, event_count > 0, event types | |
| `stalker_unfollow(thread_id)` | frida_bridge.py:4100 | test_frida_bridge.py:1273-1306, 567-618 | REAL — thread_id, event_count == len(events), duration_ms, event types; never-followed returns empty | Owning-script routing via audit5 test_f0013 |
| `enable_child_gating()` | frida_bridge.py:4141 | test_frida_bridge.py:1308-1319 | REAL — raises on Windows (Frida limitation) | |
| `disable_child_gating()` | frida_bridge.py:4195 | test_frida_bridge_audit5.py:409-423 | REAL — device.off called for process-crashed | |
| `get_pending_children()` | frida_bridge.py:4218 | test_frida_bridge.py:404-492 | REAL — transport-boundary double, full+none fields; test_frida_bridge.py:1322+ for live path | |
| `resume_child(pid)` | frida_bridge.py:4229 | test_realcov_03a_frida_modules.py:235-246 | WEAK — only `pytest.raises(ToolError)`, no message/code check | |
| `enable_crash_reporting()` | frida_bridge.py:4250 | test_frida_bridge.py:364-401, test_frida_bridge_audit5.py:409-423 | REAL — CrashInfo fields; idempotent (audit5 test_f0009) | |
| `disable_crash_reporting()` | frida_bridge.py:4309 | test_frida_bridge_audit5.py:409-423 | REAL — handler removed | |
| `get_crashes()` | frida_bridge.py:4331 | test_frida_bridge.py:364-401 | REAL — pid, process_name, summary, report, parameters, timestamp fields | |
| `enumerate_devices()` | frida_bridge.py:4343 | test_frida_bridge.py:647-679, 979-999 | REAL — id/name/type fields, local device present | |
| `connect_device(device_type, host)` | frida_bridge.py:4380 | test_frida_bridge.py:1002-1017 | REAL — device_type=='local', non-empty id+name | |
| `post_message(script_id, message)` | frida_bridge.py:4428 | NONE | NO COVERAGE | All |
| `eternalize_script(script_id)` | frida_bridge.py:4455 | NONE | NO COVERAGE | All |
| `rpc_call(script_id, method_name, args)` | frida_bridge.py:4480 | NONE | NO COVERAGE | All |
| `create_cancellable()` | frida_bridge.py:4516 | NONE | NO COVERAGE | All |
| `cancel(cancellable_id)` | frida_bridge.py:4528 | NONE | NO COVERAGE | All |
| `patch_code(address, hex_data)` | frida_bridge.py:4544 | NONE | NO COVERAGE | All |
| `allocate_string(value, encoding)` | frida_bridge.py:4586 | NONE | NO COVERAGE | All |
| `enumerate_symbols(module_name)` | frida_bridge.py:4655 | NONE | NO COVERAGE | All |
| `load_module(path)` | frida_bridge.py:4716 | NONE | NO COVERAGE | All |
| `find_module_by_address(address)` | frida_bridge.py:4760 | NONE | NO COVERAGE | All |
| `find_functions_matching(pattern)` | frida_bridge.py:4807 | NONE | NO COVERAGE | All |
| `disassemble_instruction(address)` | frida_bridge.py:4865 | NONE | NO COVERAGE | All |
| `get_backtrace(context_address, backtracer)` | frida_bridge.py:4922 | NONE | NO COVERAGE | All |
| `set_exception_handler()` | frida_bridge.py:4994 | NONE | NO COVERAGE | All |
| `revert_hook(target)` | frida_bridge.py:5054 | NONE | NO COVERAGE | All |
| `flush_interceptor()` | frida_bridge.py:5088 | NONE | NO COVERAGE | All |
| `call_system_function(address, ...)` | frida_bridge.py:5113 | NONE | NO COVERAGE | All |
| `stalker_add_call_probe(address, callback_code)` | frida_bridge.py:5208 | NONE | NO COVERAGE | All |
| `stalker_remove_call_probe(probe_id)` | frida_bridge.py:5267 | NONE | NO COVERAGE | All |
| `enumerate_applications()` | frida_bridge.py:5284 | NONE | NO COVERAGE | All |
| `inject_library_file(pid, path, ...)` | frida_bridge.py:5313 | NONE | NO COVERAGE | All |
| `inject_library_blob(pid, blob_hex, ...)` | frida_bridge.py:5347 | NONE | NO COVERAGE | All |
| `objc_enumerate_classes()` | frida_bridge.py:5382 | NONE | NO COVERAGE | Should raise on Windows |
| `objc_enumerate_protocols()` | frida_bridge.py:5411 | NONE | NO COVERAGE | Should raise on Windows |
| `objc_enumerate_loaded_classes(pattern)` | frida_bridge.py:5440 | NONE | NO COVERAGE | Should raise on Windows |
| `objc_choose(class_name, limit)` | frida_bridge.py:5491 | NONE | NO COVERAGE | Should raise on Windows |
| `objc_get_class_methods(class_name)` | frida_bridge.py:5541 | NONE | NO COVERAGE | Should raise on Windows |
| `objc_hook_method(...)` | frida_bridge.py:5579 | NONE | NO COVERAGE | Should raise on Windows |
| `shutdown()` | frida_bridge.py:5673 | test_frida_bridge.py:169-183 (fixture teardown with exception suppressed) | WEAK — ToolError swallowed in finally; no positive test | |
| `java_enumerate_loaded_classes(pattern)` | frida_bridge.py:5685 | NONE | NO COVERAGE | Should raise on non-Android |
| `java_choose(class_name, limit)` | frida_bridge.py:5736 | NONE | NO COVERAGE | Should raise on non-Android |
| `java_use(class_name)` | frida_bridge.py:5785 | NONE | NO COVERAGE | Should raise on non-Android |
| `java_hook_method(...)` | frida_bridge.py:5830 | NONE | NO COVERAGE | Should raise on non-Android |
| `java_deoptimize()` | frida_bridge.py:5926 | NONE | NO COVERAGE | Should raise on non-Android |
| `create_cmodule(code, symbols)` | frida_bridge.py:5957 | NONE | NO COVERAGE | All |
| `kernel_enumerate_modules()` | frida_bridge.py:6031 | NONE | NO COVERAGE | Raises without kernel access |
| `kernel_enumerate_ranges(protection)` | frida_bridge.py:6083 | NONE | NO COVERAGE | Raises without kernel access |
| `kernel_read(address, size)` | frida_bridge.py:6142 | NONE | NO COVERAGE | Raises without kernel access |
| `kernel_write(address, hex_data)` | frida_bridge.py:6183 | NONE | NO COVERAGE | Raises without kernel access |
| `kernel_alloc(size)` | frida_bridge.py:6220 | NONE | NO COVERAGE | Raises without kernel access |
| `kernel_protect(address, size, protection)` | frida_bridge.py:6255 | NONE | NO COVERAGE | Raises without kernel access |
| `socket_listen(port, family)` | frida_bridge.py:6300 | NONE | NO COVERAGE | All |
| `socket_connect(host, port, family)` | frida_bridge.py:6354 | NONE | NO COVERAGE | All |
| `socket_type(handle)` | frida_bridge.py:6398 | NONE | NO COVERAGE | All |
| `socket_local_address(handle)` | frida_bridge.py:6433 | NONE | NO COVERAGE | All |
| `socket_peer_address(handle)` | frida_bridge.py:6469 | NONE | NO COVERAGE | All |
| `file_read_target(path)` | frida_bridge.py:6505 | NONE | NO COVERAGE | All |
| `file_write_target(path, hex_data)` | frida_bridge.py:6549 | NONE | NO COVERAGE | All |
| `sqlite_open(path)` | frida_bridge.py:6588 | NONE | NO COVERAGE | All |
| `sqlite_exec(script_id, sql)` | frida_bridge.py:6664 | NONE | NO COVERAGE | All |
| `sqlite_dump(path)` | frida_bridge.py:6691 | NONE | NO COVERAGE | All |
| `write_code(address, code, architecture)` | frida_bridge.py:6727 | NONE | NO COVERAGE | All |
| `cloak_add_thread(thread_id)` | frida_bridge.py:6819 | NONE | NO COVERAGE | All |
| `cloak_remove_thread(thread_id)` | frida_bridge.py:6848 | NONE | NO COVERAGE | All |
| `cloak_add_range(address, size)` | frida_bridge.py:6877 | NONE | NO COVERAGE | All |
| `cloak_remove_range(address, size)` | frida_bridge.py:6908 | NONE | NO COVERAGE | All |
| `compile_typescript(source, options)` | frida_bridge.py:6939 | test_frida_bridge_audit5.py:462-551 | REAL — compiler instance reuse, distinct entrypoints, real JS output | |
| `monitor_path(path)` | frida_bridge.py:7077 | NONE | NO COVERAGE | All |
| `stop_monitor(monitor_id)` | frida_bridge.py:7129 | NONE | NO COVERAGE | All |
| `_parse_stalker_batch` | frida_bridge.py (internal) | test_frida_bridge.py:495-564 | REAL — call event (from/to/depth), exec event (no 'to' field), float depth cast | |
| `_make_payload_waiter` | frida_bridge.py (internal) | test_frida_bridge_audit5.py:692-775 | REAL — stale-loop delivery, log vs send vs error discrimination | |
| `_execute_script_and_wait` | frida_bridge.py (internal) | test_frida_bridge_audit5.py:835-851 | REAL — timeout raises ToolError with "timed out" | |
| `_unload_script` | frida_bridge.py (internal) | test_frida_bridge_audit5.py:426-444 | REAL — all secondary registries reaped | |
| tool_definition schema | frida_bridge.py:1178 | test_frida_bridge.py:716-834 | REAL — exact count 94, prefix, no duplicates, method+async+param-count parity | |

---

## 3. Worst Offenders — Fake Gates and Insufficient Assertions

### O-01: `get_registers()` / `set_register()` — Pure ToolError Gates
**File:** `tests/test_bridges/test_x64dbg_api_coverage.py:133-143`

```
with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
    await bridge.set_register("rax", _REG_VALUE)
with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
    await bridge.get_registers()
```

**Verdict: FAKE GATE.** Both methods tested only for the no-plugin ToolError path. If the production implementation of `get_registers()` were changed to silently return a zeroed-out `RegisterState` instead of parsing the actual pipe response, this test would still pass. The actual register-parsing logic (the value-population branches in `x64dbg.py:3541-3620`) is untested by any gate. The regex `r"pipe|bridge plugin"` would match most error messages, making it easy to satisfy accidentally.

**Falsifiable fix required:** Attach a fake pipe client returning a real register dict (e.g. `{"rax": "0xDEADBEEF", "rcx": "0x1", ...}`) and assert `result.rax == 0xDEADBEEF` using the same constant as an independent oracle.

---

### O-02: `read_peb()` — Tool Definition String Check Only
**File:** `tests/test_bridges/test_x64dbg_audit6.py:832-849`

```python
assert "address" in peb_tool.returns
assert "processParameters" in peb_tool.returns
```

**Verdict: FAKE GATE.** The test checks that the string `"address"` appears in the `returns` docstring field of the tool definition. This says nothing about what `read_peb()` actually produces when called. Deleting every line of `read_peb()`'s implementation and making it return `{}` would leave this test green. The real PEB parsing code path is never exercised.

**Falsifiable fix required:** Call `read_peb()` via a fake pipe client returning a known PEB dict (e.g. `{"address": "0x7FFE0000", "beingDebugged": 0, ...}`) and assert the exact field values returned.

---

### O-03: `test_breakpoint_management` — Tautological Success Path
**File:** `tests/test_bridges/test_x64dbg_api_coverage.py:91-116`

```python
bridge.breakpoints[_ADDR_BREAKPOINT] = BreakpointInfo(...)  # manual insert
bps = await bridge.get_breakpoints()
assert len(bps) == 1
assert bps[0].address == _ADDR_BREAKPOINT
```

**Verdict: FAKE GATE (tautology).** The test manually inserts a `BreakpointInfo` into the bridge's `_breakpoints` dict, then calls `get_breakpoints()` and finds it. This proves nothing about `get_breakpoints()`'s plugin-merge behavior or about `remove_breakpoint()`'s actual removal (which raised ToolError and never ran). If `get_breakpoints()` were replaced with `return list(self._breakpoints.values())`, this test would still pass on a completely different code path than production.

**Falsifiable fix required:** Use the fake pipe client to confirm the `bp_list` RPC is sent, and assert on the merged dict, not the manually-seeded one.

---

### O-04: `get_threads()` / `get_process_info()` — Weak Length-Only Assertions
**File:** `tests/test_bridges/test_x64dbg_api_coverage.py:180-204`

```python
info = await bridge.get_process_info()
assert len(info.threads) > 0
assert len(info.modules) > 0
threads = await bridge.get_threads()
assert len(threads) > 0
```

**Verdict: WEAK GATE.** `len > 0` on a list does not validate the thread or module fields. If `get_threads()` returned a list with a single `ThreadInfo(tid=0, start_address=0, current_pc=0, state="")`, this test would pass. The test in `test_realcov_02a_x64dbg.py` has stronger module assertions, but `get_threads()` field validation is absent everywhere.

**Falsifiable fix required:** Assert that TIDs are positive integers, that the current process's PID appears in the thread owner data, and that at least one module path ends in `.dll` or `.exe`.

---

### O-05: `test_get_memory_map_current_process` — Length-Only Assertion on Rich Output
**File:** `tests/test_bridges/test_x64dbg.py:427-437`

```python
memory_map = await x64dbg_bridge.get_memory_regions()
assert isinstance(memory_map, list)
assert len(memory_map) > 0
```

**Verdict: WEAK GATE.** Passes for any non-empty list regardless of whether `MemoryRegion` fields are populated correctly. A bridge returning `[MemoryRegion(base_address=0, size=0, protection="")]` would satisfy this. The memory-protection-changes test (`test_memory_protection_changes`) is better but only runs on Windows.

---

### O-06: `resume_child(pid)` and `enumerate_exports_module_not_found` — Unqualified ToolError Raises
**File:** `tests/test_bridges/test_realcov_03a_frida_modules.py:169-177, 235-246`

```python
with pytest.raises(ToolError):
    _run_async(frida_bridge.enumerate_exports("this_module_is_not_loaded_zzz.dll"))
with pytest.raises(ToolError):
    _run_async(frida_bridge.resume_child(_UNKNOWN_CHILD_PID))
```

**Verdict: WEAK GATE.** Any `ToolError` from any cause satisfies these. If the bridge raised `ToolError("script timeout")` instead of a module-not-found error, these tests would still pass. The error surfacing fidelity (i.e., that the bridge correctly maps the Frida error to a `ToolError` with the right message about the module being missing) is completely unverified.

**Falsifiable fix required:** Assert `"not found"` or the module name appears in `str(excinfo.value)` or in `excinfo.value.details`.

---

### O-07: `stalker_follow/unfollow` — Timing-Dependent Sleep
**File:** `tests/test_bridges/test_frida_bridge.py:588-618`

```python
time.sleep(_STALKER_SLEEP)  # _STALKER_SLEEP = 1.0
trace = _run_async(frida_bridge.stalker_unfollow(thread_id=worker_thread))
assert trace.event_count > 0
```

**Verdict: NON-DETERMINISTIC.** The test depends on `sleep(1.0)` to collect events. On a slow or loaded CI host, the worker thread (which calls `Sleep(100)` in a 10-iteration loop = 1 second total) may not generate events within that window. The test would produce a flaky failure rather than catching a real bridge defect. A synchronization mechanism (waiting until `event_count >= N` via polling with a timeout) would be deterministic.

---

### O-08: `shutdown()` — Exception Suppression in Fixture Teardown
**File:** `tests/test_bridges/test_frida_bridge.py:169-183`

```python
try:
    _run_async(bridge.shutdown())
except ToolError:
    _logger.debug("self_attached_bridge_fixture_shutdown_failed", exc_info=True)
```

**Verdict: CANNOT-FAIL TEST for the shutdown path.** Any failure during `shutdown()` is silently swallowed. The actual cleanup sequence (detach session, unload scripts, clear state) is never positively asserted. If `shutdown()` returned immediately after checking `self._session is None`, fixture teardown would pass.

---

### O-09: `script_load()` — Log-Level Check Only
**File:** `tests/test_bridges/test_x64dbg_audit6.py:1575-1595`

The test only verifies that `script_load` emits a DEBUG log event named `x64dbg_command_queued`. It does not verify:
- What command was sent to the pipe
- What parameters were included (the script path)
- The return value structure

**Verdict: WEAK.** The command routing is confirmed by side-effect (the fake pipe responder's `sent` list is never checked in this test variant). Deleting the `exec` command dispatch from `script_load` and emitting only the log would pass this test.

---

## 4. Edge-Case Coverage Gaps

### X64Dbg Bridge

| Gap | Priority | Severity |
|-----|----------|----------|
| `attach(pid)` with invalid PID — must raise ToolError with "invalid pid" or similar, not hang | Critical | Bridge correctness |
| `attach(pid)` architecture detection failure — `_detect_process_arch` returns None → must raise rather than guessing | Critical | audit6 F-0018 documented but test exercises only the architecture struct parsing, not the attach-level gate |
| `step_into/over/out` async Future waiter — timeout bound from F-0004; no test exercises the timeout path where the plugin sends a paused event after a delay | High | Timing correctness |
| `get_registers()` actual register parsing — no gate at all for real values | Critical | Data fidelity |
| `yara_scan()` — no test for valid rule, empty rule, rule_path not found, yara not installed error message | High | Complete operation surface |
| `analyze_entropy()` — F-0021 chunked-read across unreadable pages: no test verifies the chunk continues past a failed read | High | Documented defect surface |
| `get_resources()` — F-0019 recursive resource tree walk: no test | High | Documented defect surface |
| `_coerce_address()` — bool input must return None (documented); no direct test | Medium | Correctness |
| `read_peb()` actual data flow through fake pipe | High | Data fidelity |
| Windows path with spaces in `x64dbg_path` for `load()` | Medium | Windows quirk |
| Concurrent calls to `set_breakpoint` / `_handle_event` (F-0012 threading guard) | Medium | Race condition |

### Frida Bridge

| Gap | Priority | Severity |
|-----|----------|----------|
| `spawn()` + `resume()` workflow — no test for the spawn-then-instrument pattern | Critical | Core workflow |
| `attach_by_name()` — no test | High | API surface |
| `is_available()` — no test for the Frida not-installed case | Medium | Error path |
| ObjC/Java methods — no test for Windows "not available" error path (these should raise ToolError on Windows, not hang) | High | Platform error surfacing |
| Kernel methods — no test for "kernel not available" error path | Medium | Error surfacing |
| Socket/file/sqlite operations — entire capability surface untested | High | Broad gap |
| `cloak_*` methods — entire cloak surface untested | Medium | |
| `write_code()` — code-writer map documented but untested | Medium | |
| `monitor_path()` / `stop_monitor()` — file change events untested | Medium | |
| `post_message()` / `rpc_call()` / `eternalize_script()` — inter-script communication untested | High | Orchestration surface |
| `patch_code()` — Memory.patchCode with cache flush, the most sensitive memory operation, untested | Critical | Data integrity |
| `allocate_string()` — encoding variants (utf8/ansi/utf16) untested | Medium | |
| `disassemble_instruction()` — Frida's Instruction API untested | Medium | |
| `get_backtrace()` — accurate vs. fuzzy backtracer untested | Medium | |
| `revert_hook()` / `flush_interceptor()` — hook lifecycle completion untested | High | |
| `stalker_add/remove_call_probe` — Stalker probe surface untested | Medium | |
| `create_cancellable()` / `cancel()` — cancellation token lifecycle untested | High | Operation control |
| `detach()` — no positive test of the full detach+cleanup sequence | High | Session lifecycle |
| `shutdown()` — no positive test | High | Session lifecycle |

---

## 5. Section Scores

### X64DbgBridge

- **Total distinct public operations inventoried:** 120
- **Operations with at least one REAL gate (falsifiable assertion on actual values):** 52
- **Gate coverage score: 52/120 = 43%**
- **Edge-case score:** ~28% — many covered ops have happy-path only; error paths like invalid PID, architecture detection failure, timeout, malformed pipe response are frequently missing

### FridaBridge

- **Total distinct public operations inventoried:** 120
- **Operations with at least one REAL gate (falsifiable assertion on actual values):** 38
- **Gate coverage score: 38/120 = 32%**
- **Edge-case score:** ~18% — broad capability surfaces (sockets, files, sqlite, objc, java, kernel, cloak, code-writer, monitors) have zero coverage including for their expected failure modes on unsupported platforms

Both scores fall well below the 85% floor stated in the review mandate. Even within covered operations, several gates identified in Section 3 above are tautological or vacuous.

---

## 6. Remediation Recommendations

### Priority 1 — Eliminate Fake Gates (immediate)

1. **`get_registers()`** (`test_x64dbg_api_coverage.py:133`): Replace the ToolError-only test with a fake-pipe test. Responder returns `{"rax": "0xDEADBEEF", "rbx": "0x1", "rcx": "0x0", ...}`. Assert `result.rax == 0xDEADBEEF`, `result.rbx == 1`, etc. The independent oracle is the constant in the test, not derived from re-running the function.

2. **`set_register(name, value)`**: Chain a `set_register("rax", 0xCAFEBABE)` call through the fake pipe and assert the pipe received `("reg_set", {"name": "rax", "value": 0xCAFEBABE})` in `fake.sent`. Also confirm the bridge raises ToolError on a failed `reg_set` response (not just on no-plugin).

3. **`read_peb()`** (`test_x64dbg_audit6.py:832`): Drive `read_peb()` via fake pipe. Responder returns `{"beingDebugged": 1, "ntGlobalFlag": 0x70, "address": "0x7FFE0000", "processParameters": "0x40000000"}`. Assert `result["beingDebugged"] == 1`, `result["address"] == "0x7FFE0000"`. The existing test only asserts on the string content of the tool_definition; delete it and replace with the data-flow test.

4. **`test_breakpoint_management` success path**: Replace the manual-dict-insert pattern with a fake pipe test. Responder for `bp_list` returns the pre-inserted BP; assert the pipe received `("bp_set", {...})` and `("bp_list", None)`.

5. **`resume_child()` and `enumerate_exports_module_not_found`**: Add `match=` assertions: `pytest.raises(ToolError, match="not found|not loaded|module")`.

### Priority 2 — Add Real-Value Gates for Untested Critical Operations

6. **`get_threads()`**: Assert `all(t.tid > 0 for t in threads)`, that at least one thread has `state in {"running", "waiting"}`, and that the current process's thread count >= 1 (via `threading.active_count()` as an independent oracle).

7. **`get_memory_regions()`**: Assert at least one region has `protection` containing `"r"` and base_address > 0, and that the current executable's image region is present (using `ctypes.addressof(ctypes.create_string_buffer(1))` to get a known process address, then verifying a region covers it).

8. **`attach(pid)` + `detach()`**: Add a test that attaches to the current process (or a spawned `notepad.exe`) via the real `attach()` path, verifies `bridge.attached_pid == pid` and `bridge.is_64bit` matches platform, then detaches and verifies `bridge.attached_pid is None`.

9. **Frida `patch_code(address, hex_data)`**: Allocate memory via `allocate_memory`, write NOP bytes via `patch_code`, read back with `read_memory`, assert exact byte match. Independent oracle: the NOP opcode `\x90` for x86.

10. **Frida `post_message()` / `rpc_call()`**: Use `execute_persistent_script` to install a script that exports an RPC function, then call `rpc_call` on it and assert the return value matches the known constant returned by the script.

### Priority 3 — Platform-Gated Error Paths

11. **ObjC/Java/Kernel methods on Windows**: Each method should raise a `ToolError` on Windows (these are macOS/Android/kernel-mode only). Add tests with `pytest.mark.skipif(sys.platform == "darwin", ...)` that confirm `ToolError` is raised with a message containing "not available" or "not supported". The independent oracle is that these APIs simply do not exist on the test platform.

12. **`cancel(cancellable_id)` with unknown ID**: Bridge documents `_ERR_UNKNOWN_CANCELLABLE = "unknown cancellable token"`. Test must assert `ToolError` with that exact message; a vacuous `pytest.raises(ToolError)` is insufficient.

13. **`stalker_follow/unfollow` determinism**: Replace `time.sleep(1.0)` with a polling loop (e.g. 200ms × 10 attempts, checking `len(bridge._stalker_traces.get(tid, []))`) to make the test deterministic under CI load.

14. **`shutdown()` positive test**: Create a fresh `FridaBridge`, `initialize()`, `attach(os.getpid())`, then `shutdown()`. Assert `bridge.state.connected is False`, `bridge.state.process_attached is False`, `bridge._session is None`, and `bridge._scripts == {}`. These postconditions constitute an independent oracle (documented contract).
