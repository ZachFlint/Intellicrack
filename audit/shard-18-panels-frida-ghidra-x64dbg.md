# Shard 18 — Large tool panels (Frida / Ghidra / x64dbg)

- **Files audited**: 3
- **Total LOC**: 8017 (claimed) / 6955 (measured by line count: 1950 + 2728 + 2277)
- **Generated**: 2026-05-22T00:00:00Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 15    |
| MEDIUM   | 39    |
| LOW      | 6     |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 3 (Frida 4, Ghidra 5, x64dbg 6 — see HIGH findings below)

All three panels properly use `from intellicrack.core.logging import get_logger` and define module-level `_logger = get_logger(__name__)`. No stdlib `logging`, no `print(...)`, no `contextlib.suppress`, no f-string log messages, no `# noqa`/`# type: ignore`. The Frida and x64dbg panels are generally well-instrumented at attach/detach/script/hook/breakpoint workflow milestones; Ghidra is well-instrumented for connect/binary load/analysis/decompile workflow milestones. The dominant remaining problems are:

1. Many `except ValueError:` blocks for user-input parsing surface only a `_console_output`/`_set_status` message but never call `_logger.warning(...)`; these are silent-failure HIGHs.
2. A large fraction of bridge invocations (especially in Frida memory ops and Ghidra read/refresh ops and x64dbg trace/db ops) have no *pre-call* log, even when post-call success/failure is logged via a generic handler. §2.3 requires *both* sides.
3. Several public methods (`load_binary`, `search_strings`, `show_xrefs`, `refresh_devices`, `log_message`) lack entry/exit logs despite doing real work.

---

## Findings by file

### src/intellicrack/ui/panels/frida_panel.py — LOC 1950

**Logger status**: `module-level _logger` (L50)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L38)

**Findings**:

#### HIGH — silent except blocks (§2.2)

- [HIGH] L1023-1025 — `except ValueError:` for `int(tid_text)` (stalker follow) only writes `self._console.appendPlainText(f"[-] Invalid thread ID: {tid_text}")`. No `_logger` call. Fix: add `_logger.warning("frida_stalker_follow_invalid_tid", input_text=tid_text)`.
- [HIGH] L1683-1686 — `except ValueError:` for `bytes.fromhex(hex_str.replace(" ", ""))` in `_on_write_memory` only writes `"[-] Invalid hex data"` to console. No `_logger` call. Fix: add `_logger.warning("frida_write_memory_invalid_hex", input_text=hex_str)`.
- [HIGH] L1711-1715 — `except ValueError:` for `bytes.fromhex(...)` in `_on_scan_memory` only writes `"[-] Invalid pattern"` to console. No `_logger` call. Fix: add `_logger.warning("frida_scan_memory_invalid_pattern", input_text=pattern_str)`.
- [HIGH] L2129-2133 — `except ValueError:` for `int(a.strip(), 0) for a in args_text.split(",")` in `_on_call_function` only writes `"[-] Invalid arguments"` to console. No `_logger` call. Fix: add `_logger.warning("frida_call_function_invalid_args", input_text=args_text)`.

#### MEDIUM — Unlogged bridge invocations (§2.3)

The following bridge calls have no surrounding (pre-call) log statement and the only logging is via the on_error console message and/or success callback that updates a table. Each merits at minimum a `_logger.debug` or `_logger.info` pre-call indicating intent, plus replacing the on_error lambda with a logged handler (currently many on_error lambdas only call `self._console.appendPlainText(...)` and do not log):

- [MEDIUM] L1176-1180 — `self._bridge.spawn(Path(path_str.strip()), spawn_args)` (`_on_spawn`): no pre-call log of intent / path / args, and `_on_spawn_success` (L1182-1195) does not log. Fix: add `_logger.info("frida_spawn_started", path=path_str.strip(), args=spawn_args)` before the `_run_async`, and `_logger.info("frida_spawned", pid=pid)` in `_on_spawn_success`.
- [MEDIUM] L1213-1217 — `self._bridge.resume()` in `_on_resume` and L1219-1232 `_on_resume_success`/`_on_resume_error`: no `_logger` call anywhere in the workflow. Fix: log start/success/failure.
- [MEDIUM] L1248-1254 — `self._bridge.intercept_return(target.strip(), ret_val)` (`_on_intercept_return`): no `_logger` call before or after; `on_success`/`on_error` lambdas write only to console. Fix: log started/success/failed.
- [MEDIUM] L1274-1278 — `self._bridge.replace_function(target.strip(), code.strip())` (`_on_replace_function`): no `_logger` call before or after. Fix: log started/success/failed with target.
- [MEDIUM] L1286-1290 — `self._bridge.get_hooks()` (`_on_refresh_hooks`): no pre-call log; `_on_refresh_hooks_error` is referenced (L1289) but if it also doesn't log, the path is silent.
- [MEDIUM] L1120-1124 — `self._bridge.enumerate_devices()` in public `refresh_devices`: only error path logs at `debug` level (L1123). No pre-call log; success path silent.
- [MEDIUM] L1403-1407 — `self._bridge.enumerate_modules()`: no pre-call log; on_error handler `_on_modules_error` (L1432-1439) writes only to console with NO `_logger` call.
- [MEDIUM] L1448-1452 — `self._bridge.enumerate_exports(module_name)`: no pre-call log; on_error lambda only writes to console.
- [MEDIUM] L1480-1484 — `self._bridge.enumerate_imports(module_name)`: no pre-call log; on_error lambda only writes to console.
- [MEDIUM] L1653-1657 — `self._bridge.read_memory(addr, size)`: no pre-call log; on_error lambda only writes to console.
- [MEDIUM] L1687-1691 — `self._bridge.write_memory(addr, data)`: significant state-mutating op on the target process. No pre-call log of address/size. on_error lambda only writes to console.
- [MEDIUM] L1697-1702 — `self._bridge.allocate_memory(size)`: no pre-call log; on_error lambda only writes to console.
- [MEDIUM] L1717-1721 — `self._bridge.scan_memory(pattern_bytes)`: no pre-call log; on_error handler `_on_scan_error` (L1741-1748) writes only to console with no `_logger` call.
- [MEDIUM] L1756-1760 — `self._bridge.get_memory_regions(protection)`: no pre-call log; on_error handler `_on_regions_error` (L1787-1794) writes only to console with no `_logger` call.
- [MEDIUM] L1806-1810 — `self._bridge.protect_memory(addr, size, protection)`: state-mutating op. No pre-call log; on_error lambda only writes to console.
- [MEDIUM] L1917-1921 — `self._bridge.find_base_address(module_name)`: no pre-call log; on_error lambda only writes to console.
- [MEDIUM] L1931-1935 — `self._bridge.resolve_symbol(addr)`: no pre-call log; on_error lambda only writes to console.
- [MEDIUM] L1955-1958 — `self._bridge.find_functions_named(name)`: no pre-call log; on_error lambda only writes to console.
- [MEDIUM] L1990-1992 — `self._bridge.resolve_api(query)`: no pre-call log; on_error lambda only writes to console.
- [MEDIUM] L2142-2146 — `self._bridge.call_function(addr, args, ...)`: significant target-process op. No pre-call log of address/args; on_error lambda only writes to console.
- [MEDIUM] L2152-2156 — `self._bridge.enable_child_gating()`: state mutation. No `_logger` call before or after.
- [MEDIUM] L2162-2166 — `self._bridge.disable_child_gating()`: state mutation. No `_logger` call before or after.
- [MEDIUM] L2172-2176 — `self._bridge.get_pending_children()`: on_error lambda only writes to console; no pre-call log.
- [MEDIUM] L2213-2217 — `self._bridge.resume_child(pid)`: target-process op; no pre-call log; on_error lambda only writes to console.
- [MEDIUM] L2223-2227 — `self._bridge.enable_crash_reporting()`: no pre-call log; on_error lambda only writes to console.
- [MEDIUM] L2233-2237 — `self._bridge.get_crashes()`: no pre-call log; on_error lambda only writes to console.

#### MEDIUM — Missing entry/exit logging on public methods (§2.1)

- [MEDIUM] L450-458 `set_bridge`: logs at L458 — OK.
- [MEDIUM] L468-474 `log_message`: public method, performs real work (writes to GUI console output). No `_logger` call. Fix: `_logger.debug("frida_console_message", length=len(message))`.
- [MEDIUM] L1115-1124 `refresh_devices`: public method orchestrating bridge call. No entry log; only error-path debug log via lambda. Fix: add `_logger.debug("frida_devices_refresh_started")` before `_run_async`.

#### LOW

- [LOW] L1024 — `self._console.appendPlainText(f"[-] Invalid thread ID: {tid_text}")` uses f-string in console output (not a logger call, so not a §1 violation). No fix required but note the duplicated pattern across many handlers — many silent-fail HIGHs in this file are reachable via this `console-only` idiom. Consider a helper that logs + console-prints in one call.

---

### src/intellicrack/ui/panels/ghidra_panel.py — LOC 2728

**Logger status**: `module-level _logger` (L67)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L47)

**Findings**:

#### HIGH — silent except blocks (§2.2)

- [HIGH] L980-984 — `except ValueError:` for hex address parse in `_on_get_data_type` only writes `"Invalid address"` to `self._dt_result_view`. No `_logger` call. Fix: add `_logger.warning("ghidra_get_data_type_invalid_address", input_text=addr_text)`.
- [HIGH] L1041-1045 — `except ValueError:` for hex address parse in `_on_set_data_type` only calls `_set_status("Invalid address")`. No `_logger` call. Fix: add `_logger.warning("ghidra_set_data_type_invalid_address", input_text=addr_text)`.
- [HIGH] L1145-1151 — `_parse_address` helper: `except (ValueError, TypeError):` returns None silently. Although a parsing helper, the silent swallow contradicts §2.2. Fix: at minimum `_logger.debug("ghidra_address_parse_failed", input_text=text, error_type=...)` before `return None`. Severity HIGH because the helper feeds every address-taking workflow; bad input always becomes a silent no-op at call sites that only check for None.
- [HIGH] L1993-1997 — `except ValueError:` for color hex parse in `_handle_set_color` only calls `_set_status("Invalid color hex value")`. No `_logger` call. Fix: add `_logger.warning("ghidra_set_color_invalid_hex", input_text=color_hex)`.
- [HIGH] L3091-3095 — `except json.JSONDecodeError as exc:` for script params JSON only calls `_set_status(f"Invalid JSON params: {exc}")`. No `_logger` call. Fix: add `_logger.warning("ghidra_script_params_invalid_json", error=str(exc))`.
- [HIGH] L3153-3157 — `except json.JSONDecodeError as exc:` for analyzer options JSON only calls `_set_status(...)`. No `_logger` call. Fix: add `_logger.warning("ghidra_analyzer_options_invalid_json", error=str(exc), line=exc.lineno, col=exc.colno)`.

#### MEDIUM — Unlogged bridge invocations (§2.3)

The Ghidra panel typically has good logging at major lifecycle milestones (connect/disconnect/analyze/load_binary/decompile/script/write_bytes) but most read/refresh operations are unlogged. All of the following bridge invocations lack pre-call logs, and many have on_error lambdas that only call `self._set_status(...)` without invoking `_logger`:

- [MEDIUM] L987-991 — `bridge.get_data_type(address)`: no pre-call log (post-call error logged in `_on_get_data_type_error` L1028).
- [MEDIUM] L1048-1051 — `bridge.set_data_type(address, type_name)`: state mutation. No pre-call log (post-call error logged at L1074).
- [MEDIUM] L1434-1438 — `bridge.undo()`: state mutation. No `_logger` call (on_success/on_error only call `_set_status`).
- [MEDIUM] L1445-1449 — `bridge.redo()`: state mutation. No `_logger` call.
- [MEDIUM] L1464-1468 — `bridge.search_bytes(pattern)`: no pre-call log (error logged at L1492).
- [MEDIUM] L1511-1515 — `bridge.import_debug_info(file_path)`: significant state mutation (PDB/DWARF import). No `_logger` call before or after.
- [MEDIUM] L1535-1543 — `bridge.diff_programs(file_path)`: no `_logger` call before or after.
- [MEDIUM] L1576-1579 — `bridge.create_overlay_space(name)`: state mutation. No `_logger` call.
- [MEDIUM] L1595-1599 — `bridge.get_functions(filter_text)`: no pre-call log (error logged at L1628).
- [MEDIUM] L1844-1848 — `bridge.create_function(addr, name)`: state mutation. No `_logger` call.
- [MEDIUM] L1918-1922 — `bridge.rename_function(address, new_name.strip())`: state mutation. No `_logger` call.
- [MEDIUM] L1930-1934 — `bridge.add_comment(address, cmt_text.strip(), "EOL")`: state mutation. No `_logger` call.
- [MEDIUM] L1944-1948 — `bridge.set_function_variable_type(...)`: state mutation. No `_logger` call.
- [MEDIUM] L1957-1960 — `bridge.get_stack_frame(address)`: no pre-call log.
- [MEDIUM] L1964-1967 — `bridge.get_function_body(address)`: no pre-call log.
- [MEDIUM] L1980-1983 — `bridge.get_calling_conventions()`: no pre-call log.
- [MEDIUM] L1998-2002 — `bridge.set_color(address, color_int)`: state mutation. No `_logger` call.
- [MEDIUM] L2011-2015 — `bridge.delete_function(address)`: state mutation (destructive). No `_logger` call before or after — should be logged at INFO with address.
- [MEDIUM] L2038-2042 — `bridge.edit_function_signature(...)`: state mutation. No `_logger` call.
- [MEDIUM] L2054-2058 — `bridge.get_imports()`: no pre-call log; on_error handler `_on_imports_refresh_error` (L2066) logs.
- [MEDIUM] L2100-2103 — `bridge.get_exports()`: no pre-call log (refresh ops).
- [MEDIUM] L2137-2141 — `bridge.search_strings(pattern)`: no pre-call log (error logged at L2167).
- [MEDIUM] L2179 (`show_xrefs`) — `bridge.get_xrefs_to(address)` / `bridge.get_xrefs_from(address)` at L2191-2199: public method `show_xrefs` invokes two unlogged bridge calls.
- [MEDIUM] L2258-2262 — `bridge.set_label(addr, name)`: state mutation. No `_logger` call.
- [MEDIUM] L2281-2285 — `bridge.get_labels(addr)`: no pre-call log.
- [MEDIUM] L2318-2322 — `bridge.create_bookmark(addr, category, comment, bm_type)`: state mutation. No `_logger` call.
- [MEDIUM] L2329-2333 — `bridge.get_bookmarks()`: no pre-call log.
- [MEDIUM] L2380-2384 — `bridge.define_structure(name, field_dicts)`: state mutation. No `_logger` call.
- [MEDIUM] L2391-2395 — `bridge.get_structures()`: no pre-call log.
- [MEDIUM] L2427-2431 — `bridge.apply_structure_at(addr, struct_name)`: state mutation. No `_logger` call.
- [MEDIUM] L2442-2446 — `bridge.get_memory_map()`: no pre-call log.
- [MEDIUM] L2481-2485 — `bridge.read_bytes(addr, length)`: no pre-call log.
- [MEDIUM] L2567-2571 — `bridge.create_memory_block(name, start, size, perms)`: significant state mutation. No `_logger` call.
- [MEDIUM] L2582-2586 — `bridge.get_segments()`: no pre-call log.
- [MEDIUM] L2617-2621 — `bridge.get_program_info()`: no pre-call log.
- [MEDIUM] L2668-2672 — `bridge.set_program_metadata(...)`: state mutation. No `_logger` call.
- [MEDIUM] L2690-2694 — `bridge.get_call_tree(addr, direction=direction, depth=depth)`: no pre-call log.
- [MEDIUM] L2746-2750 — `bridge.get_callers(addr)`: no pre-call log.
- [MEDIUM] L2775-2779 — `bridge.get_slice(addr)`: no pre-call log.
- [MEDIUM] L2816-2820 — `bridge.add_comment(addr, cmt_text, cmt_type)`: state mutation. No `_logger` call.
- [MEDIUM] L2831-2835 — `bridge.get_comments(addr)`: no pre-call log.
- [MEDIUM] L2844-2848 — `bridge.get_all_comments()`: no pre-call log (this is a bulk RPC and should be logged at INFO).
- [MEDIUM] L2901-2904 — `bridge.search_symbols(name, sym_type)`: no pre-call log.
- [MEDIUM] L2934-2937 — `bridge.create_namespace(name, parent)`: state mutation. No `_logger` call.
- [MEDIUM] L2945-2948 — `bridge.get_namespaces()`: no pre-call log.
- [MEDIUM] L2983-2986 — `bridge.create_equate(addr, value, name)`: state mutation. No `_logger` call.
- [MEDIUM] L2994-2997 — `bridge.get_equates()`: no pre-call log.
- [MEDIUM] L3021-3024 — `bridge.get_relocations()`: no pre-call log.
- [MEDIUM] L3055-3058 — `bridge.add_external_function(library, func_name, addr)`: state mutation. No `_logger` call.
- [MEDIUM] L3074-3079 — `bridge.execute_script(script)` (`_on_run_script`): Ghidra script execution is a significant workflow milestone (§2.4) and lacks a pre-call log. Fix: `_logger.info("ghidra_script_execution_started", script_size=len(script))` (compare to frida_panel.py L613 which gets this right).
- [MEDIUM] L3096-3101 — `bridge.execute_script_with_params(script, params)`: as above, lacks pre-call log.
- [MEDIUM] L3133-3137 — `bridge.set_decompiler_options(...)`: state mutation. No `_logger` call.
- [MEDIUM] L3163-3169 — `bridge.configure_analysis(analyzer_name, ...)`: state mutation. No `_logger` call.

#### MEDIUM — Missing entry/exit logging on public methods (§2.1)

- [MEDIUM] L1216-1235 `load_binary(binary_path: Path) -> bool`: public method that initiates a significant workflow. No entry log; success/error are logged in the callbacks (L1244, L1255). Fix: add `_logger.info("ghidra_load_binary_started", path=str(binary_path))` at start of method.
- [MEDIUM] L2126-2141 `search_strings(pattern: str)`: public method. No entry log; only error path logs.
- [MEDIUM] L2179-2200 `show_xrefs(address: int)`: public method that triggers two bridge calls and a UI update. No entry log.

#### LOW

- [LOW] L1654-1658 `ghidra_function_decompile_requested` log — duplicate context risk: the same function-click triggers four `_run_async` calls (decompile / disassemble / pcode / cfg) but only the decompile is explicitly logged at INFO. The other three rely on `_on_op_error` for failure logs. Consider one consolidated "ghidra_function_view_requested" with the operations as a tuple, or per-op debug logs.
- [LOW] L1438, L1448 — `_on_undo` / `_on_redo` `on_error` lambdas just call `_set_status(...)`. Errors should also log at warning so they appear in structured logs.

---

### src/intellicrack/ui/panels/x64dbg_panel.py — LOC 2277

**Logger status**: `module-level _logger` (L50)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L38)

**Findings**:

#### HIGH — silent except blocks (§2.2)

- [HIGH] L1957-1961 — `except ValueError:` in `_on_run_to` only writes `"[!] Invalid address: ..."` to console. No `_logger` call. Fix: add `_logger.warning("x64dbg_run_to_invalid_address", input_text=addr_text)`.
- [HIGH] L2008-2012 — `except ValueError:` in `_on_set_ip` only writes to console. No `_logger` call. Fix: add `_logger.warning("x64dbg_set_ip_invalid_address", input_text=addr_text)`.
- [HIGH] L2056-2060 — `except ValueError:` in `_on_add_watchpoint` only writes to console. No `_logger` call. Fix: add `_logger.warning("x64dbg_add_watchpoint_invalid_address", input_text=addr_text)`.
- [HIGH] L2094-2098 — `except (TypeError, ValueError):` in `_on_remove_watchpoint` silently re-enables the button and returns. No log, no UI feedback. Fix: add `_logger.warning("x64dbg_remove_watchpoint_invalid_id", input_text=str(addr_item.data(...)))`.
- [HIGH] L2205-2209 — `except ValueError:` in `_on_set_label` only writes to console. No `_logger` call. Fix: add `_logger.warning("x64dbg_set_label_invalid_address", input_text=addr_text)`.
- [HIGH] L2224-2228 — `except ValueError:` in `_on_set_comment_btn` only writes to console. No `_logger` call. Fix: add `_logger.warning("x64dbg_set_comment_invalid_address", input_text=addr_text)`.
- [HIGH] L2317-2321 — `except ValueError:` in `_on_free_memory` only writes to console. No `_logger` call. Fix: add `_logger.warning("x64dbg_free_memory_invalid_address", input_text=addr_text)`.
- [HIGH] L2403-2408 — `except ValueError:` in `_on_write_memory` (for `int(addr_text, 0)` / `bytes.fromhex(...)`) only writes `"[!] Invalid address or hex data"` to console. No `_logger` call. Fix: add `_logger.warning("x64dbg_write_memory_invalid_input", address_text=addr_text, data_text=data_text)`.
- [HIGH] L2423-2427 — `except ValueError:` in `_on_assemble` only writes to console. No `_logger` call. Fix: add `_logger.warning("x64dbg_assemble_invalid_address", input_text=addr_text)`.
- [HIGH] L2541-2545 — `except ValueError:` in `_on_set_exception_config` only writes to console. No `_logger` call. Fix: add `_logger.warning("x64dbg_exception_config_invalid_code", input_text=code_text)`.

#### MEDIUM — Unlogged bridge invocations (§2.3)

x64dbg's `_on_generic_error` (L1888-1899) provides a centralized warning log for failures, so most `on_error` paths are covered. However, *pre-call* logs are still missing for most operations, and the run/step/lifecycle operations are crucial debugger state transitions (§2.4):

- [MEDIUM] L1120-1126 — `self._bridge.run()` in `_on_run`: debugger state transition. Success path silent; only error path logged at L1139.
- [MEDIUM] L1148-1153 — `self._bridge.pause()`: debugger state transition. No pre-call or success log; only error at L1168.
- [MEDIUM] L1177-1182 — `self._bridge.stop()`: debugger state transition. No pre-call or success log; only error at L1196.
- [MEDIUM] L1205-1210 — `self._bridge.step_into()`: debugger state transition. No log.
- [MEDIUM] L1217-1222 — `self._bridge.step_over()`: debugger state transition. No log.
- [MEDIUM] L1229-1234 — `self._bridge.step_out()`: debugger state transition. No log.
- [MEDIUM] L1464-1468 — `self._bridge.get_module_sections(module_name)`: no pre-call log.
- [MEDIUM] L1504-1508 — `self._bridge.get_module_exports(module_name)`: no pre-call log.
- [MEDIUM] L1564-1568 — `self._bridge.set_register(reg_name, value)`: state mutation in target process. No pre-call log of register/value; only error path logged.
- [MEDIUM] L1617-1621 — `self._bridge.read_memory(address, size)`: no pre-call log.
- [MEDIUM] L1657-1661 — `self._bridge.run_command(cmd)`: arbitrary debugger command (significant). Only the command text is echoed to console at L1655; no `_logger.info(...)` of the command. Fix: log the command at info before dispatch.
- [MEDIUM] L1906-1909 — `self._bridge.detach()`: lifecycle transition. No pre-call or success log.
- [MEDIUM] L1928-1935 — `self._bridge.spawn(Path(file_path))`: process creation. No pre-call log (`_on_spawn_success` does log at L1945-1946 via console only, not `_logger`).
- [MEDIUM] L1962-1966 — `self._bridge.run_to(address)`: state transition. No pre-call log.
- [MEDIUM] L1972-1976 — `self._bridge.execute_til_return()`: state transition. No pre-call log.
- [MEDIUM] L1982-1986 — `self._bridge.skip_instruction()`: state mutation. No pre-call log.
- [MEDIUM] L2013-2017 — `self._bridge.set_ip(address)`: target-process state mutation. No pre-call log.
- [MEDIUM] L2032-2036 — `self._bridge.save_database()`: persistence operation. No pre-call log of intent.
- [MEDIUM] L2042-2046 — `self._bridge.load_database()`: persistence operation. No pre-call log of intent.
- [MEDIUM] L2068-2072 — `self._bridge.set_watchpoint(address, size, wp_type)`: state mutation. No pre-call log.
- [MEDIUM] L2099-2103 — `self._bridge.remove_watchpoint(wp_id)`: state mutation. No pre-call log.
- [MEDIUM] L2121-2125 — `self._bridge.yara_scan(rule_text=pattern)`: significant scan. No pre-call log.
- [MEDIUM] L2127-2131 — `self._bridge.find_pattern(pattern)`: significant scan. No pre-call log.
- [MEDIUM] L2159-2163 — `self._bridge.trace_start(condition=condition, log_text=log_text)`: significant trace. No pre-call log.
- [MEDIUM] L2169-2173 — `self._bridge.trace_stop()`: state transition. No pre-call log.
- [MEDIUM] L2180-2184 — `self._bridge.trace_into(condition=condition)`: state transition. No pre-call log.
- [MEDIUM] L2191-2195 — `self._bridge.trace_over(condition=condition)`: state transition. No pre-call log.
- [MEDIUM] L2210-2214 — `self._bridge.set_label(address, label_text)`: state mutation. No pre-call log.
- [MEDIUM] L2229-2233 — `self._bridge.set_comment(address, comment_text)`: state mutation. No pre-call log.
- [MEDIUM] L2285-2289 — `self._bridge.dump_memory_to_file(base, size, path)` (via `_on_dump_memmap_region`): significant operation that writes to disk indirectly through bridge. No pre-call log of destination path. (Also flagged in §2.3 as a file-write-via-bridge.)
- [MEDIUM] L2304-2308 — `self._bridge.allocate_memory(size, prot)`: state mutation. No pre-call log.
- [MEDIUM] L2322-2326 — `self._bridge.free_memory(address)`: state mutation. No pre-call log.
- [MEDIUM] L2362-2366 — `self._bridge.set_breakpoint_on_api(module, function)`: state mutation. No pre-call log.
- [MEDIUM] L2389-2393 — `self._bridge.dump_memory_to_file(address, size, path)` (second site): same finding as L2285.
- [MEDIUM] L2409-2413 — `self._bridge.write_memory(address, data)`: target-process state mutation. No pre-call log of address/byte_count.
- [MEDIUM] L2428-2432 — `self._bridge.patch_instruction(address, instr)`: target-process state mutation. No pre-call log.
- [MEDIUM] L2452-2456 — `self._bridge.nop_range(address, size)`: target-process state mutation. No pre-call log.
- [MEDIUM] L2473-2477 — `self._bridge.suspend_thread(tid)`: state mutation. No pre-call log.
- [MEDIUM] L2494-2498 — `self._bridge.resume_thread(tid)`: state mutation. No pre-call log.
- [MEDIUM] L2515-2519 — `self._bridge.switch_thread(tid)`: state mutation. No pre-call log.
- [MEDIUM] L2528-2532 — `self._bridge.evaluate_expression(expr)`: no pre-call log of expression.
- [MEDIUM] L2547-2551 — `self._bridge.set_exception_config(code, handling)`: state mutation. No pre-call log.

#### MEDIUM — Missing entry/exit logging on public methods (§2.1)

- [MEDIUM] L962-981 `debug_file(file_path: Path) -> bool`: public method. The "no-bridge" branch logs at L972, but the success path goes through `_run_async` and only the success callback logs at L990. No "started" log at entry. Fix: add `_logger.info("x64dbg_debug_file_started", path=str(file_path))` after L971.

#### LOW

- [LOW] L1697-1699 `_refresh_registers` `on_error=lambda _: _logger.warning("x64dbg_refresh_registers_failed")`: warning has no context (no error string). Same pattern at L1746, L1778, L1807, L1841, L1869, L2242, L2560, L2589 — consider passing through `error=str(e)` like the named handlers do. Marked LOW because they are "background refresh" failures and intentional context-light logs.
- [LOW] L1654-1655 — `self._console_output.appendPlainText(f">  {cmd}")` is a UI echo of the user's command. Not a logging violation, but the command itself should be logged separately to structured logs for forensic audit.
- [LOW] L1944, L1946 — `_on_spawn_success` updates status and console but never calls `_logger.info("x64dbg_spawned", pid=pid, path=path)`. The attach-success counterpart at L1098 does log; this should mirror it.

---

## Aggregate notes

- **Common silent-fail pattern**: All three panels rely heavily on a "user-input ValueError" pattern (`except ValueError: self._console.appendPlainText('[-] Invalid X'); return`) for hex addresses, sizes, hex byte strings, JSON params, and PIDs/TIDs. Some of these are logged at warning (good — see frida L1071, x64dbg L1079/1293/1344/etc.) but a large minority are silent. A panel-shared helper such as `self._invalid_input("event_name", input_text, console_msg)` would force consistency.
- **on_error lambda pattern is inconsistent**: All three panels mix three styles in their `on_error=...` arguments:
  1. lambda that only writes to console (no log) — silent-failure HIGH if the underlying except chain doesn't log either, otherwise MEDIUM as "unlogged bridge failure".
  2. lambda that calls a named handler which does log (good).
  3. lambda that calls `_logger.warning(...)` directly (good).
  Recommend standardizing on (3) for refresh-style background ops and (2) for user-initiated ops.
- **Pre-call logging is the dominant gap**: All three panels have decent post-call logging via named error/success handlers, but most bridge invocations lack a `_logger.debug/info(...)` at the call site. §2.3 says external/bridge calls must be logged on both sides. A simple `_run_async` wrapper that auto-logs `bridge_call_started`/`bridge_call_succeeded`/`bridge_call_failed` events would close almost all MEDIUM findings in this shard at once.
- **State-mutating operations under-logged**: Frida memory writes/protect, Ghidra rename/delete/set_color/edit_signature/write_bytes (write_bytes IS logged at L2540, good), x64dbg register/memory/instruction patching and watchpoint operations — all are significant target-process mutations that should be logged at INFO with full context (address, register, byte count) per §2.4. Currently only attach/detach/load/breakpoint/connect milestones are well-instrumented.
- **No actively bad patterns**: No stdlib `logging`, no f-string log calls, no `print(...)`, no `contextlib.suppress`, no `# noqa`/`# type: ignore`. The bones of the logging are correct — gaps are coverage, not correctness of style.
- **Audit difficulty**: All three files are large (~2-3kloc) but the structure is regular (panel section creators + `_on_*` handlers + `_apply_*` table-fillers). Findings were located by walking every `_bridge.`/`bridge.` call site and every `except` clause; line numbers in the report point to the bridge call line or the except line plus its short body. The high count of MEDIUM bridge findings reflects the dispatch pattern, not separate bugs — fixing the `_run_async` wrapper would resolve most of them simultaneously.
