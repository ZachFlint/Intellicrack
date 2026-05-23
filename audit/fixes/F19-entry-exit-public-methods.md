# F19 — Add entry/exit logs to public methods doing real work

## Fix description

Per §2.1, public methods that perform non-trivial work must log at entry (debug/info with context) AND at exit (debug/info with result summary). Trivial `@property` getters/setters and dunder methods are exempt.

Many files emit entry-only or exit-only logs; this fix closes the asymmetry.

## Fix template

```python
async def list_processes(self, *, current_filter: str | None = None) -> list[ProcessInfo]:
    """List visible processes."""
    _logger.debug("list_processes_started", current_filter=current_filter)
    try:
        results = await self._list_processes_impl(current_filter)
    except ToolError as exc:
        _logger.warning("list_processes_failed", error=str(exc))
        raise
    _logger.debug("list_processes_completed", count=len(results))
    return results
```

## Sites to fix

### `src/intellicrack/bridges/process.py` — missing exit-summary logs (~50 sites)

All `list_*`, `get_*`, `enumerate_*`, `read_*`, `query_*` methods emit a `*_started` debug at entry but never a `*_completed` debug with result cardinality.

Representative list (full list in `shard-03-bridges-process.md`):

| Method | Lines | Suggested exit kwarg |
|--------|-------|----------------------|
| `list_processes` | 1538-1592 | `count=len(results)` |
| `list_processes_detailed` | 1594-1646 | `count=len(results)` |
| `get_process_memory_mb` | 1648-1682 | `mb=result.mb` |
| `detect_architecture` | 1684-1725 | `arch=result.arch` |
| `read_memory` | 2118-2142 | `bytes_read=len(data)` |
| `get_memory_map` | 2292-2353 | `region_count=len(regions)` |
| `search_pattern` | 2355-2425 | `match_count=len(matches)` |
| `get_modules` | 2571-2640 | `module_count=len(modules)` |
| `get_threads` | 2642-2701 | `thread_count=len(threads)` |
| `get_handles` | 3404-3433 | `handle_count=len(handles)` |
| `enum_handles` | 3611-3638 | `handle_count=len(handles)` |
| `get_windows` | 3697-3765 | `window_count=len(windows)` |
| `read_peb` | 3921-3978 | `peb_base=..., process_parameters=...` |
| `read_teb` | 4217-4302 | `teb_base=..., last_error=...` |
| `get_heaps` | 4357-4403 | `heap_count=len(heaps)` |
| `get_thread_context` | 4409-4519 | `register_count=...` |
| `stack_walk` | 4628-4688 | `frame_count=len(frames)` |
| `get_mitigation_policies` | 5056-5121 | `policy_count=len(policies)` |
| `enumerate_system_processes` | 5182-5224 | `process_count=...` |
| `enumerate_handles` | 5226-5270 | `count=...` |
| `enumerate_heaps` | 5272-5339 | `count=...` |
| `enumerate_services` | 5341-5403 | `count=...` |
| `read_registry` | 5623-5671 | `value_type=..., value_size=...` |
| `get_environment` | 5841-5890 | `var_count=...` |
| `enumerate_com_servers` | 6114-6134 | `server_count=...` |
| `get_job_info` | 6710-6768 | `in_job=...` |
| `get_gui_resources` | 7130-7176 | `gdi_objects=..., user_objects=...` |
| `reg_read_value` | 7218-7255 | `type=..., size=...` |
| `reg_enum_keys` | 7257-7306 | `key_count=...` |
| `reg_enum_values` | 7308-7357 | `value_count=...` |
| `get_tls_values` | 7572-7618 | `slot_count=...` |
| `query_system_info` | 7684-7735 | `return_length=..., status=...` |

(Full list of ~52 sites in shard 03 report.)

### `src/intellicrack/bridges/ghidra.py` — missing entry logs on read-only `get_*` (~23 sites)

| Method | Line | Suggested kwarg |
|--------|-----:|-----------------|
| `get_function` | 2298 | `address=hex(address)` |
| `decompile` | 2392 | `address=hex(address)` |
| `disassemble` | 2493 | `address=hex(address), count=count` |
| `get_xrefs_to` | 2561 | `address=hex(address)` |
| `get_xrefs_from` | 2609 | `address=hex(address)` |
| `search_strings` | 2685 | `pattern=pattern, encoding=encoding` |
| `get_imports` | 3081 | (none) |
| `get_exports` | 3129 | (none) |
| `get_data_type` | 3176 | `address=hex(address)` |
| `get_labels` | 3379 | `address=hex(address), radius=radius` |
| `get_bookmarks` | 3515 | `category=category` |
| `get_structures` | 3837 | `filter_name=filter_name` |
| `get_memory_map` | 3931 | (none) |
| `get_call_graph` | 3973 | `address=hex(address), depth=depth` |
| `get_segments` | 4070 | (none) |
| `get_program_info` | 4115 | (none) |
| `get_relocations` | 5030 | (none) |
| `get_namespaces` | 5113 | (none) |
| `get_equates` | 5247 | (none) |
| `search_symbols` | 5286 | `name=name, symbol_type=symbol_type` |
| `get_calling_conventions` | 5531 | (none) |
| `get_all_comments` | 6018 | (none) |
| `get_program_tree` | 6069 | (none) |

### `src/intellicrack/bridges/frida_bridge.py` — ~35 public methods (asymmetric)

See shard 05 for the full list. Most need either an entry log (state mutations like `write_memory`, `protect_memory`, `inject_library_file`, `inject_library_blob`, `hook_function`, `replace_function`, `enable_child_gating`, `disable_child_gating`, `enable_crash_reporting`, `patch_code`, `allocate_string`, `revert_hook`, `flush_interceptor`, `call_system_function`, `java_hook_method`, `java_deoptimize`, `create_cmodule`, `kernel_enumerate_modules`, `kernel_enumerate_ranges`, `kernel_protect`, `socket_connect`, `socket_type`, `socket_local_address`, `socket_peer_address`, `file_read_target`, `file_write_target`, `sqlite_open`, `sqlite_exec`, `sqlite_dump`, `write_code`, `cloak_add_thread`, `cloak_remove_thread`, `cloak_add_range`, `cloak_remove_range`, `compile_typescript`, `monitor_path`) or an exit log (`enumerate_modules`, `enumerate_exports`, `enumerate_imports`, `enumerate_threads`, `enumerate_processes`, `enumerate_applications`, `enumerate_symbols`, `find_module_by_address`, `find_functions_matching`, `find_functions_named`, `find_base_address`, `resolve_symbol`, `resolve_api`, `get_memory_regions`, `read_memory`, `get_backtrace`, `disassemble_instruction`).

(Suggestion: rather than editing 35 sites individually, consider a `@log_op("event_name")` decorator that emits entry+exit logs automatically. See aggregate notes in shard 05.)

### `src/intellicrack/bridges/x64dbg.py` — debugger primitives (~12 sites)

| Method | Line | Notes |
|--------|-----:|-------|
| `is_available` | 2222-2234 | Add entry/exit debug |
| `detach` | 2929-2941 | Add entry info `x64dbg_process_detaching` |
| `set_breakpoint` | 3068-3135 | Add entry info `breakpoint_setting` |
| `remove_breakpoint` | 3258-3273 | Add entry info |
| `get_breakpoints` | 3275-3323 | Add entry/exit |
| `set_watchpoint` | 3325-3366 | Add entry info |
| `get_watchpoints` | 3392-3434 | Add entry/exit |
| `get_registers` | 3436-3530 | Add entry debug |
| `set_register` | 3532-3547 | Add entry info |
| `write_memory` | 3659-3699 | Add entry info `memory_writing` (size, addr) |
| `allocate_memory` | 3701-3754 | Add entry info |
| `free_memory` | 3756-3787 | Add result/outcome log |

### `src/intellicrack/bridges/hex_editor.py` — public methods (~14 sites)

Mostly missing entry-level logs on operations that have only exit logs:

| Method | Line | Notes |
|--------|-----:|-------|
| `open_file` | 1726-1777 | Add entry `open_file_started`, path=path |
| `save` | 2917-2963 | Add entry `save_started`, path=path |
| `save_to_sandbox` | 3161-3259 | Add entry + per-bridge-hop logs (sandbox bridge invocation) |
| `test_in_sandbox` | 3261-3333 | Add entry `sandbox_test_started` |
| `list_process_regions` | 5128-5156 | Add entry `list_process_regions_started`, pid=pid (promote exit to info) |
| `open_process_memory` | 5158-5213 | Add entry `open_process_memory_started`, pid/address/size |
| `export_annotated_pdf` | 6754-6800 | Add entry, promote exit to info |
| `_generate_pdf` | 8698-8766 | Wrap `pdf.output(output_path)` with entry+exit info |
| `scan_die_signatures` | 7311-7407 | Add entry `scan_die_started`, db_path=db_path |
| `scan_clamav_signatures` | 7520-7567 | Add entry `scan_clamav_started`, db_path |
| `scan_custom_signatures` | 7744-7815 | Add entry `scan_custom_signatures_started`, sig_file |
| `_resolve_patch_source` | 4641-4655 | Add log around `read_bytes` of user-supplied original_path |
| `import_patches_bps` | 7960-7992 | Add entry log naming source file |
| `import_patches_ups` | 8080-8112 | Same |

### Bridge UI panels — addressed by F03 helper rollout

The 150+ bridge-call entry-log gaps in `process_panel`, `frida_panel`, `ghidra_panel`, `x64dbg_panel`, `sandbox_panel`, `cutter_panel`, `cutter_tabs` are closed by adopting `run_bridge_coroutine_logged` (F03). This fix file lists the *bridge-side* asymmetry; the *panel-side* asymmetry is in F03.

### `src/intellicrack/core/hexpat/` — public pipeline methods

| File | Method | Line | Fix |
|------|--------|-----:|-----|
| `lexer.py` | `tokenize` | 43-52 | Add `_logger.debug("hexpat_lex_complete", token_count=len(self._tokens), file_path=self.file_path)` before return |
| `interpreter.py` | `execute` | 94-140 | Add entry/exit info logs |
| `interpreter.py` | `execute_file` | 142-159 | Add entry `hexpat_execute_file`, pattern_path/offset |
| `interpreter.py` | `execute_bytes` | 161-204 | Add entry/exit |
| `interpreter.py` | `can_compile_to_json` | 206-229 | Already addressed by F14 (silent except); add exit too |
| `interpreter.py` | `compile_to_json` | 231-260 | Add info entry + success exit log |
| `parser.py` | `parse` | 203-238 | Add entry `hexpat_parse_start`, file_path/token_count; exit `hexpat_parse_complete`, node_count/error_count |
| `pattern_registry.py` | `load_source` | 200-210 | Add `_logger.debug("pattern_source_load", path=str(metadata.file_path))` before read |
| `pattern_registry.py` | `match_file` | 142-187 | Add debug exit summary |
| `hexpat_compiler.py` | `compile` | 764-778 | Add info entry log |
| `hexpat_compiler.py` | `compile_to_dict` | 780-823 | Add debug entry log (combined with F14 fixes) |

### `src/intellicrack/core/` — other public entry points

| File | Method | Line | Fix |
|------|--------|-----:|-----|
| `transform_pipeline.py` | `TransformPipeline.execute` | 796-811 | Add entry/exit debug |
| `transform_pipeline.py` | `TransformPipeline.preview` | 813-828 | Add entry/exit debug |
| `transform_pipeline.py` | `RustTransformNode.process` | 298-340 | Add debug entry/exit |
| `hexpat/evaluator.py` | `HexPatEvaluator.evaluate` | 643-663 | Add entry/exit debug (program_node_count, data_size; result_count, pattern_count) |
| `hexpat/preprocessor.py` | `HexPatPreprocessor.process` | 98-208 | Add entry/exit debug |
| `hexpat/preprocessor.py` | `#include` success | 391 | Log on successful include resolution |
| `core/script_gen.py` | `ScriptGenerator.prepare_output_path` | 1377-1401 | Add debug `output_path_prepared` |

### `src/intellicrack/credentials/store.py`

| Method | Line | Fix |
|--------|-----:|-----|
| `validate` | 626 | Add entry/exit debug |
| `get_source` | 661 | Add entry/exit debug |

### `src/intellicrack/credentials/oauth.py`

| Method | Line | Fix |
|--------|-----:|-----|
| `close` | 641 | Add `_logger.debug("oauth_manager_closed")` |
| `build_authorization_url` | 680 | Add success debug log `authorization_url_built` |
| `run_authorization_flow` | 1190 | Add info entry log |
| `authorize_google` | 1267 | Add entry/exit logs |

### Sandbox public ops — addressed in F25

### UI app.py workflow milestones — addressed in F21

## Acceptance criteria

- [ ] All ~80 sites listed above have symmetric entry/exit logs
- [ ] Result-summary kwargs (count, size, success) included in exit logs
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
