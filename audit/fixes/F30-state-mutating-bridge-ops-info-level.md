# F30 — Promote state-mutating bridge operations to INFO level

## Fix description

Per §2.4, significant target-process state mutations (memory writes, code patches, register sets, breakpoint manipulation, hook installations, library injections, etc.) should be logged at **info** level (not debug), with full context including target address, byte count, source path, etc.

This is partly addressed by F03 (`run_bridge_coroutine_logged` wrapper) which auto-emits info events for state mutations. This file enumerates the specific call sites that need info-level treatment, both at the bridge (Python coroutine) layer and the panel (Qt slot) layer.

## Sites to fix (panel layer — use F03 with info level)

### `src/intellicrack/ui/panels/frida_panel.py` — Frida memory + injection ops

| Lines | Operation | Suggested info event |
|-------|-----------|----------------------|
| 1176-1180 | `spawn(path, args)` | `frida_spawn_started` / `frida_spawned` |
| 1213-1217 | `resume()` | `frida_resume_started` / `frida_resumed` |
| 1248-1254 | `intercept_return` | `frida_intercept_return` |
| 1274-1278 | `replace_function` | `frida_replace_function` |
| 1687-1691 | `write_memory(addr, data)` | `frida_memory_write` (addr=hex(addr), size=len(data)) |
| 1697-1702 | `allocate_memory(size)` | `frida_memory_allocate` |
| 1806-1810 | `protect_memory(addr, size, prot)` | `frida_memory_protect` |
| 2142-2146 | `call_function(addr, args)` | `frida_call_function` |
| 2152-2156 | `enable_child_gating()` | `frida_child_gating_enable` |
| 2162-2166 | `disable_child_gating()` | `frida_child_gating_disable` |
| 2223-2227 | `enable_crash_reporting()` | `frida_crash_reporting_enable` |

### `src/intellicrack/ui/panels/ghidra_panel.py` — Ghidra mutation ops

| Lines | Operation | Suggested info event |
|-------|-----------|----------------------|
| 1918-1922 | `rename_function(address, new_name)` | `ghidra_rename_function` |
| 1930-1934 | `add_comment(address, comment, "EOL")` | `ghidra_add_comment` |
| 1944-1948 | `set_function_variable_type(...)` | `ghidra_set_variable_type` |
| 2011-2015 | `delete_function(address)` (destructive) | `ghidra_delete_function` |
| 1998-2002 | `set_color(address, color_int)` | `ghidra_set_color` |
| 2038-2042 | `edit_function_signature(...)` | `ghidra_edit_signature` |
| 2380-2384 | `define_structure(name, fields)` | `ghidra_define_structure` |
| 2427-2431 | `apply_structure_at(addr, struct_name)` | `ghidra_apply_structure_at` |
| 2567-2571 | `create_memory_block(name, start, size, perms)` | `ghidra_create_memory_block` |
| 2668-2672 | `set_program_metadata(...)` | `ghidra_set_program_metadata` |
| 2258-2262 | `set_label(addr, name)` | `ghidra_set_label` |
| 2318-2322 | `create_bookmark(addr, category, comment, bm_type)` | `ghidra_create_bookmark` |
| 1048-1051 | `set_data_type(address, type_name)` | `ghidra_set_data_type` |
| 1844-1848 | `create_function(addr, name)` | `ghidra_create_function` |
| 3133-3137 | `set_decompiler_options(...)` | `ghidra_set_decompiler_options` |
| 3163-3169 | `configure_analysis(analyzer_name, ...)` | `ghidra_configure_analysis` |
| 3055-3058 | `add_external_function(library, name, addr)` | `ghidra_add_external_function` |
| 1576-1579 | `create_overlay_space(name)` | `ghidra_create_overlay_space` |
| 2934-2937 | `create_namespace(name, parent)` | `ghidra_create_namespace` |
| 2983-2986 | `create_equate(addr, value, name)` | `ghidra_create_equate` |
| 1511-1515 | `import_debug_info(file_path)` | `ghidra_import_debug_info` |
| 3074-3079 | `execute_script(script)` | `ghidra_execute_script_started` |
| 3096-3101 | `execute_script_with_params(script, params)` | `ghidra_execute_script_with_params_started` |
| 1434-1438 | `undo()` | `ghidra_undo` |
| 1445-1449 | `redo()` | `ghidra_redo` |

### `src/intellicrack/ui/panels/x64dbg_panel.py` — x64dbg state transitions + patches

| Lines | Operation | Suggested info event |
|-------|-----------|----------------------|
| 1120-1126 | `run()` | `x64dbg_run` |
| 1148-1153 | `pause()` | `x64dbg_pause` |
| 1177-1182 | `stop()` | `x64dbg_stop` |
| 1205-1210 | `step_into()` | `x64dbg_step_into` |
| 1217-1222 | `step_over()` | `x64dbg_step_over` |
| 1229-1234 | `step_out()` | `x64dbg_step_out` |
| 1564-1568 | `set_register(name, value)` | `x64dbg_set_register` (register, value) |
| 1657-1661 | `run_command(cmd)` | `x64dbg_run_command` (cmd=cmd) |
| 1906-1909 | `detach()` | `x64dbg_detach` |
| 1928-1935 | `spawn(path)` | `x64dbg_spawn` |
| 1962-1966 | `run_to(address)` | `x64dbg_run_to` |
| 1972-1976 | `execute_til_return()` | `x64dbg_execute_til_return` |
| 1982-1986 | `skip_instruction()` | `x64dbg_skip_instruction` |
| 2013-2017 | `set_ip(address)` | `x64dbg_set_ip` |
| 2032-2036 | `save_database()` | `x64dbg_save_database` |
| 2042-2046 | `load_database()` | `x64dbg_load_database` |
| 2068-2072 | `set_watchpoint(address, size, wp_type)` | `x64dbg_set_watchpoint` |
| 2099-2103 | `remove_watchpoint(wp_id)` | `x64dbg_remove_watchpoint` |
| 2210-2214 | `set_label(address, label_text)` | `x64dbg_set_label` |
| 2229-2233 | `set_comment(address, comment_text)` | `x64dbg_set_comment` |
| 2285-2289 | `dump_memory_to_file(base, size, path)` | `x64dbg_dump_memory_to_file` |
| 2304-2308 | `allocate_memory(size, prot)` | `x64dbg_allocate_memory` |
| 2322-2326 | `free_memory(address)` | `x64dbg_free_memory` |
| 2362-2366 | `set_breakpoint_on_api(module, function)` | `x64dbg_set_api_breakpoint` |
| 2389-2393 | `dump_memory_to_file(address, size, path)` (second site) | `x64dbg_dump_memory_to_file` |
| 2409-2413 | `write_memory(address, data)` | `x64dbg_write_memory` (address=hex(address), size=len(data)) |
| 2428-2432 | `patch_instruction(address, instr)` | `x64dbg_patch_instruction` |
| 2452-2456 | `nop_range(address, size)` | `x64dbg_nop_range` |
| 2473-2477 | `suspend_thread(tid)` | `x64dbg_suspend_thread` |
| 2494-2498 | `resume_thread(tid)` | `x64dbg_resume_thread` |
| 2515-2519 | `switch_thread(tid)` | `x64dbg_switch_thread` |
| 2547-2551 | `set_exception_config(code, handling)` | `x64dbg_set_exception_config` |

### `src/intellicrack/ui/panels/sandbox_panel.py` — sandbox lifecycle ops

Closed by F03 `run_bridge_coroutine_logged` rollout at info level. ~25 sites listed in F03.

## Acceptance criteria

- [ ] All listed state-mutation bridge calls emit info-level events with target context (address, size, name)
- [ ] State queries (read_memory, get_*) use debug level
- [ ] State mutations (write_memory, patch, rename, delete, set_*) use info level
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
- [ ] Sample integration: a single patching session should produce a coherent info-level audit trail in the JSON log
