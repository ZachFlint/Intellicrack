# Shard 21 — Remaining Unresolved Logging Findings

- **Source root**: `D:\Intellicrack\src\intellicrack\`
- **Compiled from**: shards 01-20 verification reports
- **Generated**: 2026-05-24
- **Verification basis**: 20 parallel verification passes against current source

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 12    |
| MEDIUM   | ~330  |
| LOW      | ~35   |

Shards 15 and 16 have 0 unresolved findings and are omitted from this document. All other shards have remaining items listed below in their original shard groupings for traceability.

The dominant remaining pattern is **missing entry-level logs** on public methods that perform external work (file I/O, native/Win32 calls, bridge invocations, subprocess spawns). Completion logs almost universally exist, but the corresponding "started" event is absent — operators see outcomes but not intent, preventing correlation when a call hangs.

---

## Shard 01 — `bridges/hex_editor.py`

### MEDIUM

- [MEDIUM] L1745-1765 — `open_file()`: exit log `file_opened` exists but no entry log for `open_file_started` operation. The file open at L1749 is not preceded by a starting event.
- [MEDIUM] L2931-2956 — `save()`: file write `self.document.save(saved_path)` at L2938/L2943 with no entry log. Exit log `file_saved` at L2956.
- [MEDIUM] L3180-3256 — `save_to_sandbox()`: bridge-to-bridge operation missing entry log such as `save_to_sandbox_started`. Bridge invocations at L3212-3230 have no per-call logging. Completion log exists at L3255.
- [MEDIUM] L3197-3200 — Inside `save_to_sandbox()`, `tempfile.mkstemp` and `self.document.save(tmp_path)` at L3199 unlogged. No context event before/after the temp-file I/O.
- [MEDIUM] L3281-3327 — `test_in_sandbox()` calls sandbox bridge's `run_binary` (L3308-3320) with no entry log. Exit log `sandbox_test_completed` exists at L3323.
- [MEDIUM] L5144-5155 — `list_process_regions()` calls `_hexcore_mod.HexDocument.list_process_memory_regions(pid)` (L5153) with only debug exit log. Should have info-level entry log.
- [MEDIUM] L5178-5212 — `open_process_memory()` attaches to process memory (L5198, native call). Only exit log at L5205 (`process_memory_opened`). No entry log.
- [MEDIUM] L6771-6796 — `export_annotated_pdf()` orchestrates PDF write via `_generate_pdf(...)` (L6785-6794). Only debug exit log at L6795. Should have info-level entry log and promote exit to info.
- [MEDIUM] L8764 — Inside `_generate_pdf()` helper, `pdf.output(output_path)` writes PDF to disk with no surrounding log statements. Per §2.3, file-write operations require before/after logging.
- [MEDIUM] L7341-7403 — `scan_die_signatures()` reads user-provided database via `Path(db_path).read_text(...)` at L7356. Exit log `die_scan_completed` at L7402. Missing entry log.
- [MEDIUM] L7538-7563 — `scan_clamav_signatures()` reads database via `path.read_text(...)` at L7545. No entry log before file read.
- [MEDIUM] L7751-7810 — `scan_custom_signatures()` reads user-supplied JSON via `Path(sig_file).read_text(...)` at L7756. Exit log `custom_sig_scan_completed` at L7809. Missing entry log.
- [MEDIUM] L4652-4654 — `_resolve_patch_source()` reads file via `Path(original_path).read_bytes` (L4654) with no log. Caller `import_patches` logs intent, but file-read side-effect invisible.
- [MEDIUM] L7976, L8098 — `import_patches_bps()` and `import_patches_ups()` read source files via `Path(original_path).read_bytes` with no entry logs. Exit logs exist (`bps_patch_imported` / `ups_patch_imported`).

---

## Shard 02 — `bridges/x64dbg.py`

### MEDIUM

- [MEDIUM] L3078 — `set_breakpoint()`: public method performing real work (external RPC bp_set + verification via bp_list) has no entry log; only exit log at L3144.
- [MEDIUM] L2932 — `detach()`: public method performing external debugger work (detach command) has only exit log at L2944; missing entry log before `await self._send_command(...)` at L2934.
- [MEDIUM] L3275 — `remove_breakpoint()`: public method performing real work (external RPC bp_remove) has no entry log; only exit log at L3289. Method starts with direct RPC call at L3284.
- [MEDIUM] L3292 — `get_breakpoints()`: public method merging remote breakpoint list with local state has no entry/exit logs except internal error recovery at L3310.
- [MEDIUM] L3342 — `set_watchpoint()`: public method performing external RPC (wp_set) has no entry log; only exit log at L3382. RPC at L3361-3368.
- [MEDIUM] L3409 — `get_watchpoints()`: public method merging remote watchpoint list has no entry/exit logs except internal error handling at L3427.
- [MEDIUM] L3675 — `write_memory()`: public method performing critical external Win32 call (WriteProcessMemory) has no entry log; only exit log at L3714. WriteProcessMemory at L3702-3708.
- [MEDIUM] L3717 — `allocate_memory()`: public method performing external Win32 call (VirtualAllocEx) has no entry log; only exit log at L3769. VirtualAllocEx at L3756-3762.
- [MEDIUM] L8590-8596 — `adjust_privilege()`: early-return paths for privilege lookup and token open failures return without preceding log statements. L8590-8591 returns `{"success": False, "error": f"Privilege {name!r} not found"}` without log; L8595-8596 returns `{"success": False, "error": "Failed to open process token"}` without log. Only entry log at L8557.
- [MEDIUM] L2300-2307 — `_start_debugger` Popen: subprocess spawn (x64dbg.exe via Popen) logged on intent at L2288 but no explicit post-spawn pid log in this bridge method (ProcessManager.register at L2310 logs internally elsewhere).

---

## Shard 03 — `bridges/process.py`

### MEDIUM (52 — missing exit logs on public read/enumerate methods)

All 52 MEDIUM findings remain unresolved. Pattern: entry-only or exit-only logging on public query/read/enumerate methods, never bidirectional. Representative samples:

- [MEDIUM] L1542 — `list_processes()`: entry log at L1557; no exit log with process count.
- [MEDIUM] L1598 — `list_processes_detailed()`: entry log at L1615; no exit log with result count.
- [MEDIUM] L1920 — `open_process()`: no entry log; exit log only at L1967 after state mutations.
- [MEDIUM] L1970 — `close()`: no entry log; exit log only when handle exists (L1980, inside if-block).
- [MEDIUM] L2131 — `read_memory()`: entry log at L2142; no exit log with bytes-read count.
- [MEDIUM] L2145 — `write_memory()`: no entry log; exit log only at L2175 after successful write.
- [MEDIUM] L2570 — `get_modules()`: entry log at L2582; no exit log with module count at L2640.
- (44 additional MEDIUM findings follow the same pattern across all public query/read/enumerate methods — see original shard-03-bridges-process.md for the full list.)

### LOW

- [LOW] L3119-3128 — `remove_privileges_changed_callback`: only logs on "not registered" (L3136); successful removal not logged.
- [LOW] L1483-1500 — `list()` dispatch shim: no logs.
- [LOW] L1502-1517 — `list_detailed()` dispatch shim: no logs.

---

## Shard 04 — `bridges/ghidra.py`

### MEDIUM (23 — all missing entry-level logs before try block on public read methods)

- [MEDIUM] L2302 — `get_function`: no entry-level log before try block. Missing `_logger.debug("ghidra_get_function_started", address=hex(address))`.
- [MEDIUM] L2396 — `decompile`: no entry-level log before try block.
- [MEDIUM] L2497 — `disassemble`: no entry-level log before try block. Missing entry log with address and count context.
- [MEDIUM] L2561 — `get_xrefs_to`: no entry-level log before try block.
- [MEDIUM] L2609 — `get_xrefs_from`: no entry-level log before try block.
- [MEDIUM] L2689 — `search_strings`: no entry-level log before try block. Missing entry log with pattern and encoding context.
- [MEDIUM] L3081 — `get_imports`: no entry-level log before try block.
- [MEDIUM] L3129 — `get_exports`: no entry-level log before try block.
- [MEDIUM] L3176 — `get_data_type`: no entry-level log before try block.
- [MEDIUM] L3379 — `get_labels`: no entry-level log before try block.
- [MEDIUM] L3515 — `get_bookmarks`: no entry-level log before try block.
- [MEDIUM] L3837 — `get_structures`: no entry-level log before try block.
- [MEDIUM] L3931 — `get_memory_map`: no entry-level log before try block.
- [MEDIUM] L3973 — `get_call_graph`: no entry-level log before try block.
- [MEDIUM] L4070 — `get_segments`: no entry-level log before try block.
- [MEDIUM] L4115 — `get_program_info`: no entry-level log before try block.
- [MEDIUM] L5030 — `get_relocations`: no entry-level log before try block.
- [MEDIUM] L5113 — `get_namespaces`: no entry-level log before try block.
- [MEDIUM] L5247 — `get_equates`: no entry-level log before try block.
- [MEDIUM] L5286 — `search_symbols`: no entry-level log before try block.
- [MEDIUM] L5531 — `get_calling_conventions`: no entry-level log before try block.
- [MEDIUM] L6018 — `get_all_comments`: no entry-level log before try block.
- [MEDIUM] L6069 — `get_program_tree`: no entry-level log before try block.

---

## Shard 05 — `bridges/frida_bridge.py` + `named_pipe_client.py`

### MEDIUM (61 — asymmetric entry/exit logging across public methods)

- [MEDIUM] frida_bridge.py:1656 — `read_memory()`: entry log at L1677 but no success-exit log. Only returns raw bytes without logging successful completion.
- [MEDIUM] frida_bridge.py:1697 — `write_memory()`: exit log at L1727 but no entry log. Should log intent before JS injection.
- [MEDIUM] frida_bridge.py:1954 — `enumerate_modules()`: exit-only debug log at L2006; no entry log.
- [MEDIUM] frida_bridge.py:2009 — `enumerate_exports()`: exit-only logs; no entry log.
- [MEDIUM] frida_bridge.py:2074 — `hook_function()`: exit log at L2168 but no entry log. Function replacement is significant.
- [MEDIUM] frida_bridge.py:2192 — `get_hooks()`: lacks entry/exit logging.
- [MEDIUM] frida_bridge.py:2199 — `execute_script()`: entry log at L2215 but no success-exit log.
- [MEDIUM] frida_bridge.py:2285 — `intercept_return()`: lacks exit logging.
- [MEDIUM] frida_bridge.py:2305 — `call_function()`: entry log at L2349 but no success-exit log.
- [MEDIUM] frida_bridge.py:2771 — `enumerate_imports()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:2840 — `enumerate_threads()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:2901 — `allocate_memory()`: exit log only; no entry log.
- [MEDIUM] frida_bridge.py:2970 — `protect_memory()`: exit debug log only; no entry log.
- [MEDIUM] frida_bridge.py:3029 — `find_base_address()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:3068 — `resolve_symbol()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:3133 — `find_functions_named()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:3195 — `resolve_api()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:3257 — `replace_function()`: exit info log but no entry log. Major state mutation.
- [MEDIUM] frida_bridge.py:3347 — `enumerate_processes()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:3850 — `enable_child_gating()`: exit info log but no entry log. Handler registration is meaningful lifecycle transition.
- [MEDIUM] frida_bridge.py:3903 — `disable_child_gating()`: exit info log but no entry log.
- [MEDIUM] frida_bridge.py:3957 — `enable_crash_reporting()`: exit info log but no entry log.
- [MEDIUM] frida_bridge.py:4356 — `patch_code()`: exit info log but no entry log. Code patching is operationally significant.
- [MEDIUM] frida_bridge.py:4397 — `allocate_string()`: exit info log but no entry log.
- [MEDIUM] frida_bridge.py:4465 — `enumerate_symbols()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:4569 — `find_module_by_address()`: entry info log but None-return branch (L4599) lacks exit log.
- [MEDIUM] frida_bridge.py:4613 — `find_functions_matching()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:4670 — `disassemble_instruction()`: entry info log but no success-exit log.
- [MEDIUM] frida_bridge.py:4725 — `get_backtrace()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:4849 — `revert_hook()`: exit-only info log; no entry log.
- [MEDIUM] frida_bridge.py:4882 — `flush_interceptor()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:4958 — `call_system_function()`: entry info log but no success-exit log.
- [MEDIUM] frida_bridge.py:5113 — `enumerate_applications()`: exit-only debug log; no entry log.
- [MEDIUM] frida_bridge.py:5140 — `inject_library_file()`: exit info log but no entry log. Injection is state mutation.
- [MEDIUM] frida_bridge.py:5173 — `inject_library_blob()`: exit info log but no entry log. State mutation worth pre-call logging.
- [MEDIUM] frida_bridge.py:5404 — `objc_hook_method()`: exit info log but no entry log.
- [MEDIUM] frida_bridge.py:5538 — `java_choose()`: entry info log but no success-exit log of match count.
- [MEDIUM] frida_bridge.py:5585 — `java_use()`: entry info log but no success-exit log of method-count.
- [MEDIUM] frida_bridge.py:5626 — `java_hook_method()`: exit info log but no entry log.
- [MEDIUM] frida_bridge.py:5716 — `java_deoptimize()`: exit info log but no entry log. Major JVM state mutation.
- [MEDIUM] frida_bridge.py:5746 — `create_cmodule()`: exit info log but no entry log. Loading inline C code is state mutation.
- [MEDIUM] frida_bridge.py:5815 — `kernel_enumerate_modules()`: entry info log but no success-exit log.
- [MEDIUM] frida_bridge.py:5866 — `kernel_enumerate_ranges()`: entry info log but no success-exit log.
- [MEDIUM] frida_bridge.py:6037 — `kernel_protect()`: entry info log but no success-exit log.
- [MEDIUM] frida_bridge.py:6135 — `socket_connect()`: entry info log but no success-exit log. Pattern inconsistency with socket_listen.
- [MEDIUM] frida_bridge.py:6177 — `socket_type()`: entry info log but no success-exit log.
- [MEDIUM] frida_bridge.py:6210 — `socket_local_address()`: entry info log but no success-exit log.
- [MEDIUM] frida_bridge.py:6244 — `socket_peer_address()`: entry info log but no success-exit log.
- [MEDIUM] frida_bridge.py:6278 — `file_read_target()`: entry info log but no success-exit log of bytes read.
- [MEDIUM] frida_bridge.py:6318 — `file_write_target()`: entry info log but no success-exit log of bytes written.
- [MEDIUM] frida_bridge.py:6356 — `sqlite_open()`: exit info log but no entry log.
- [MEDIUM] frida_bridge.py:6431 — `sqlite_exec()`: no entry log; success path has no exit log. SQL exec is operationally significant.
- [MEDIUM] frida_bridge.py:6456 — `sqlite_dump()`: entry info log but no success-exit log.
- [MEDIUM] frida_bridge.py:6490 — `write_code()`: exit info log but no entry log. Major state mutation for assembly writing.
- [MEDIUM] frida_bridge.py:6581 — `cloak_add_thread()`: exit debug log but no entry log.
- [MEDIUM] frida_bridge.py:6609 — `cloak_remove_thread()`: exit debug log but no entry log.
- [MEDIUM] frida_bridge.py:6637 — `cloak_add_range()`: exit debug log but no entry log.
- [MEDIUM] frida_bridge.py:6667 — `cloak_remove_range()`: exit debug log but no entry log.
- [MEDIUM] frida_bridge.py:6697 — `compile_typescript()`: exit info log but no entry log of compile intent.
- [MEDIUM] frida_bridge.py:6811 — `monitor_path()`: exit info log but no entry log of monitor creation intent.

### LOW

- [LOW] named_pipe_client.py:459 — `_reader_loop()` exception handler uses `_logger.warning()` instead of `_logger.exception()`, losing traceback context.

---

## Shard 06 — `bridges/installer.py`

### MEDIUM

- [MEDIUM] installer.py:730-734 — `_probe_python_package()`: subprocess call `await process_manager.run_tracked_async(...)` has no pre-call log statement. Should add `_logger.debug("python_package_probe_starting", ...)`.
- [MEDIUM] installer.py:823-828 — `get_version()`: subprocess call `await process_manager.run_tracked_async(...)` has no pre-call log statement. Should add `_logger.debug("tool_version_probe_starting", ...)`.
- [MEDIUM] installer.py:1153-1158 — `_install_frida()`: pip install failure path returns `InstallResult(success=False, ...)` without logging. Should add `_logger.warning("frida_pip_install_failed", ...)` before return.
- [MEDIUM] installer.py:1174-1179 — `_install_frida()`: version verify subprocess failure (non-zero returncode) returns without logging. Should add `_logger.warning("frida_version_verify_failed", ...)` before return.
- [MEDIUM] installer.py:1182-1187 — `_install_frida()`: unparseable version after install returns without logging. Should add `_logger.warning("frida_version_unparseable", ...)` before return.
- [MEDIUM] installer.py:1063 — `install_tool()`: finally block `await asyncio.to_thread(download_path.unlink, missing_ok=True)` has no log. Should add `_logger.debug("download_temp_unlinked", ...)`.
- [MEDIUM] installer.py:1316 — `_download_file()`: file open `file_handle = await asyncio.to_thread(temp_path.open, "wb")` has no pre-call log. Should add `_logger.debug("download_file_opened", ...)`.
- [MEDIUM] installer.py:1345 — `_download_file()`: failure cleanup `await asyncio.to_thread(temp_path.unlink, missing_ok=True)` has no log. Should add `_logger.debug("download_partial_removed", ...)`.
- [MEDIUM] installer.py:545 — `ToolInstaller.__init__()`: `self.tools_directory.mkdir(parents=True, exist_ok=True)` has no log. Should add `_logger.debug("tools_directory_ready", ...)`.
- [MEDIUM] installer.py:2089-2090 — `deploy_x64dbg_plugin_detailed()`: mkdir and copy operations have no pre-call log. Success bracketed by plugin_deployed at L2126-2130.

### LOW

- [LOW] installer.py:1804-1805 — `_cmake_timeout()`: except clause captures exception but log call uses `_logger.exception()` without capturing `as exc`. Should be `except ValueError as exc:` with `error=str(exc)` kwargs.

---

## Shard 07 — `bridges/base.py`, `credentials/*`, `main.py`

### HIGH

- [HIGH] `__init__.py`:86 — canonical logger pattern violation.

### MEDIUM

- [MEDIUM] env_loader.py — 4 file-I/O exception handling gaps.
- [MEDIUM] oauth.py — 3 missing HTTP entry logs.
- [MEDIUM] oauth.py — 2 missing browser-open logs.
- [MEDIUM] oauth.py — 3 missing public method entry/exit logs.
- [MEDIUM] store.py — 2 missing public method entry/exit logs.

### LOW

- [LOW] main.py:890, L902, L914, L926, L938, L950 — 6 DLL load sites missing log on cache miss; also missing try/except around DLL load.
- [LOW] additional downgraded cleanup exceptions across the shard.

---

## Shard 08 — `core/orchestrator.py`, `core/session.py`, `core/script_gen.py`

### MEDIUM

- [MEDIUM] session.py:158 — `Session.add_binary()` mutates `binaries` list and `active_binary_index` without log.
- [MEDIUM] session.py:168 — `Session.add_message()` appends to conversation without log.
- [MEDIUM] session.py:177 — `Session.add_patch()` mutates `patches` list without log.
- [MEDIUM] session.py:186 — `Session.add_bridge_analysis()` updates `bridge_analyses` dict without log.
- [MEDIUM] session.py:207 — `Session.set_tool_state()` mutates `tool_states` dict without log for lifecycle state changes.
- [MEDIUM] session.py:222 — `Session.clear_tool_state()` deletes from `tool_states` dict without log.
- [MEDIUM] session.py:237 — `Session.add_tag()` appends to `tags` list without log.
- [MEDIUM] session.py:258 — `Session.remove_tag()` deletes from `tags` list without log.
- [MEDIUM] session.py:1189 — `SessionManager.import_json()` performs three sequential blocking I/O operations (load JSON, check existing, save) without entry log identifying path or replace mode.
- [MEDIUM] session.py:1237 — `SessionManager._start_auto_save()` creates background task without logging lifecycle transition.

### LOW

- [LOW] orchestrator.py:969 — `load_session()` public method lacks entry-log; logs only on success (`session_loaded` at L1000).
- [LOW] orchestrator.py:1025 — `process_user_input()` main agent entry point lacks explicit entry log; only logs on error or cancellation.
- [LOW] orchestrator.py:2190 — `add_binary()` public method performs state mutation (appends to binaries, updates index) without entry log.
- [LOW] orchestrator.py:2456 — `get_typed_bridge()` success path returns bridge instance silently without any log statement.
- [LOW] orchestrator.py:2488 — `set_confirmation_level()` mutates `self._config.confirmation_level` with no log call.
- [LOW] orchestrator.py:2329 — `set_message_callback()` assigns callback without log (same for 5 other callback setters at L2337, L2345, L2353, L2364, L2375).
- [LOW] orchestrator.py:2515 — `configure_hooks()` registers hooks without logging.
- [LOW] script_gen.py:676 — `ScriptManager.__init__()` does not log construction (scripts_dir, validator setup).
- [LOW] script_gen.py:1392 — `ScriptGenerator.prepare_output_path()` calls `Path.mkdir(parents=True, exist_ok=True)` (filesystem mutation) without entry or exit log.

---

## Shard 09 — `core/hexpat/` frontend (interpreter, lexer, parser, registry, stdlib)

### MEDIUM

- [MEDIUM] interpreter.py:226 — `except HexPatError:` block in `can_compile_to_json()` swallows exception with no log before returning False. L226-227 shows `except HexPatError: return False`.
- [MEDIUM] interpreter.py:142 — public method `execute_file()` reads `.hexpat` file from disk at line 158 with no entry/exit log.
- [MEDIUM] interpreter.py:94 — public method `execute()` performs full pipeline with no entry log.
- [MEDIUM] interpreter.py:161 — public method `execute_bytes()` performs full pipeline with no entry/exit log.
- [MEDIUM] lexer.py:43 — public `tokenize()` method performs entire lex pass with no entry/exit log. Constructor logs init (L37-41) but `tokenize()` returns tokens with no exit log.
- [MEDIUM] pattern_registry.py:201 — public `load_source()` reads `.hexpat` file from disk with no entry log. Line 210 shows `return metadata.file_path.read_text(...)`.
- [MEDIUM] stdlib.py:1939 — `_file_open()` opens file with no entry log; except at L1940 wraps OSError without explicit log before re-raise.
- [MEDIUM] stdlib.py:1985 — `_file_read()` reads from file handle with no entry log; except at L1986 wraps without explicit log before re-raise.
- [MEDIUM] stdlib.py:2008 — `_file_write()` writes to file handle with no entry log; except at L2009 wraps without explicit log.
- [MEDIUM] stdlib.py:2030 — `_file_seek()` performs seek with no entry/exit log; except clause wraps without explicit log.
- [MEDIUM] stdlib.py:2049 — `_file_size()` calls `.seek()` and `.tell()` with no entry/exit log; except wraps without explicit log.
- [MEDIUM] stdlib.py:2072 — `_file_resize()` calls `.truncate()` with no entry/exit log; except wraps without explicit log.
- [MEDIUM] stdlib.py:2095 — `_file_flush()` calls `.flush()` with no entry/exit log; except wraps without explicit log.
- [MEDIUM] stdlib.py:2160 — `_file_create_directories()` calls `path.mkdir()` with no entry/exit log; except wraps without explicit log.

---

## Shard 10 — `core/hexpat/evaluator.py` + `core/` infra

### MEDIUM

- [MEDIUM] transform_pipeline.py:802 — `execute()` public method performs significant work (executing all pipeline steps, mutating data) with no entry/exit logging.
- [MEDIUM] transform_pipeline.py:819 — `preview()` public method iterates pipeline steps and captures intermediate outputs with no entry/exit logging.
- [MEDIUM] transform_pipeline.py:299 — `RustTransformNode.process()` invokes Rust `HexDocument.open_bytes()` (L322) and `doc.transform_data()` (L339) with no surrounding log statements. Cross-language external calls per §2.3.
- [MEDIUM] hexpat/evaluator.py:643 — `evaluate()` main public entry point iterates entire program AST and produces parsed-field output with no entry/exit logging. Constructor logs init (L361) but `evaluate()` itself has no bracket logs.
- [MEDIUM] hexpat/preprocessor.py:98 — `process()` public entry point does significant work (full preprocessing, include resolution, macro expansion, pragma extraction) with no entry/exit logging.
- [MEDIUM] hexpat/preprocessor.py:389 — Include file read at L389 `candidate.read_text(...)` succeeds silently with no log. Only failure case logged (L400-406). Every included pattern file should be auditable.

### LOW

- [LOW] core/logging.py:749 — `OperationTimer.__exit__` uses `.error()` when exception propagates; could use `.exception()` for traceback.
- [LOW] core/config.py:626-631 — mkdir logs info even for existing directories (could be conditional).
- [LOW] core/tools.py:201 — unknown_tool logged at error (could be warning per TRY400).
- [LOW] core/template_manager.py:289, 323, 382, 400 — `_logger.error()` before raise ValueError/FileNotFoundError (judgment call per TRY400).
- [LOW] core/hexpat/data_reader.py:148 — out_of_bounds logged at error (could be warning).
- [LOW] core/hexpat/preprocessor.py:725 — `extract_pragmas_fast()` missing entry/exit log.
- [LOW] core/hexpat/evaluator.py:2225-2226 — `_call_user_function` inconsistent signal logging (see L901-906, L928-933 for comparison).
- [LOW] Multiple evaluator.py sites (L980, L1276, L1353, L2076, L2087, L2120, L2954) — error before raise (TRY400 convention).

---

## Shard 11 — `providers/` cloud

### LOW

- [LOW] providers/base.py:519-520 — `except retryable_exceptions` block with `if attempt >= max_retries: raise` executes a silent re-raise without logging when retry budget is exhausted. Line 519-520 contains bare `raise` with no preceding log statement.

---

## Shard 12 — `providers/local_transformers.py` + small UI

### MEDIUM

- [MEDIUM] local_transformers.py:425 — `list_models()` public method lacks entry log documenting start of discovery. No `_logger.info("local_list_models_started", ...)` before real work begins.
- [MEDIUM] local_transformers.py:119 — `_fetch_model_config()` performs HTTP GET to HuggingFace but only logs on failure. No entry debug log before `client.get(url)` at L131.
- [MEDIUM] local_transformers.py:1451 — `unload_model()` public method lacks entry log. Logs exit at L1466 ("model_unloaded") but no entry log before cache removal at L1461.
- [MEDIUM] xpu_status.py:90 — `__init__` opens XPU status dialog with no info-level log of GUI milestone.
- [MEDIUM] preferences.py:654 — `_on_apply()` emits `settings_changed` signal (significant state mutation per §2.4) with no log before emission. Only file-save path logs at L663.
- [MEDIUM] preferences.py:159 — `_browse_tools()` mutates tool directory path selection with no log when user selects directory.

### LOW

- [LOW] chat.py:497 — `insert_context_text()` inserts context into chat but does not log the workflow milestone. Method calls `self._input.set_text(text)` at L507 with no log.
- [LOW] confirmation_dialog.py:198 — log call at L200 missing context kwargs; `tool` and `function` vars in scope.

---

## Shard 13 — `sandbox/qemu.py`, `sandbox/windows.py`

### MEDIUM

- [MEDIUM] qemu.py:2479 — `run_command()` public method performs file I/O (writes script, polls result) with no entry log. Only error/exit paths logged.
- [MEDIUM] qemu.py:2721 — `run_binary()` public method copies binary, resets logs, dispatches run_command with no entry log.
- [MEDIUM] qemu.py:2937 — `copy_to_sandbox()` performs file I/O with no entry log.
- [MEDIUM] qemu.py:2964 — `copy_from_sandbox()` performs file I/O with no entry log.
- [MEDIUM] qemu.py:2992 — `take_snapshot()` issues QMP savevm with no entry log; only success/failure at end.
- [MEDIUM] qemu.py:3015 — `restore_snapshot()` similar pattern, no entry log.
- [MEDIUM] qemu.py:3179 — `capture_screenshot()` issues screendump, polls PPM stability, converts to PNG with no entry log.
- [MEDIUM] qemu.py:3238 — `apply_anti_evasion()` runs many guest-agent commands with only success summary log at end, no entry log.
- [MEDIUM] qemu.py:3328 — `dump_memory()` issues QMP dump-guest-memory with no entry log.
- [MEDIUM] qemu.py:3384 — `extract_dropped_files()` dispatches guest-side xcopy/cp commands then builds zip with no entry log.
- [MEDIUM] qemu.py:3586 — `yara_scan()` compiles rules and scans with no entry log.
- [MEDIUM] qemu.py:1045 — `_subprocess_run([pwsh, ...])` for Get-WindowsOptionalFeature WHPX probe has no pre-call log; only exception path logs.
- [MEDIUM] qemu.py:1074 — `_subprocess_run([bcdedit, ...])` has no pre-call log.
- [MEDIUM] windows.py:1306 — `run_command()` writes trigger file, polls result, cleans up with no entry log.
- [MEDIUM] windows.py:1374 — `run_binary()` no entry log; only error paths log.
- [MEDIUM] windows.py:1527 — `copy_to_sandbox()` no entry log; only debug success.
- [MEDIUM] windows.py:1558 — `copy_from_sandbox()` no entry log.
- [MEDIUM] windows.py:1675 — `capture_screenshot()` builds and dispatches PowerShell script with no entry log.
- [MEDIUM] windows.py:1727 — `apply_anti_evasion()` dispatches MOF compilation and guest-side commands with no entry log.
- [MEDIUM] windows.py:1925 — `dump_memory()` builds and dispatches MiniDumpWriteDump PowerShell with no entry log.
- [MEDIUM] windows.py:2090 — `extract_dropped_files()` dispatches multiple xcopy commands with no entry log.
- [MEDIUM] windows.py:2177 — `yara_scan()` no entry log.

### LOW

- [LOW] _log_parsers.py:108 — File read at L109 is operationally significant but has no entry-time log; only failure path logs at L115.

---

## Shard 14 — `sandbox/analysis.py`, UI infra (session_manager, win32_embed, panel_dock,_screen_compat)

### MEDIUM

- [MEDIUM] session_manager.py:460 — `mkdir(parents=True, exist_ok=True)` called without surrounding log. `self.SESSIONS_DIR.mkdir(...)` with no `_logger` call before or after.
- [MEDIUM] session_manager.py:1322 — file write `Path(path).open("w")` lacks pre-intent log; only post-write success log present at L1325.
- [MEDIUM] session_manager.py:1000 — `session_file.unlink()` success path returns silently without confirming deletion. Pre-call log at L984 but success return at L1000 has no log.
- [MEDIUM] session_manager.py:1048 — `session_exported` logged at `debug` level for user-triggered data export; should be `info`.
- [MEDIUM] session_manager.py:912 — `session_load_requested` logged at `debug` level; should be `info` for business event.
- [MEDIUM] win32_embed.py:111-113 — `ctypes.WinDLL("user32", ...)` call in `_get_user32()` has no success log.
- [MEDIUM] win32_embed.py:62-98 — `_configure_user32()` completes all API annotations with no exit log.
- [MEDIUM] win32_embed.py:116-173 — `find_window_by_pid()` has no entry log and "not-found" path (L173) returns silently.
- [MEDIUM] win32_embed.py:222 — `_reparent_foreign_hwnd()` success path at L222 returns `True` with no success log.
- [MEDIUM] panel_dock.py:114 — `_save_geometry()` writes to QSettings with no log. Line 114 calls `settings.setValue()` without `_logger`.
- [MEDIUM] panel_dock.py:119 — `_restore_geometry()` reads from QSettings with no log. Line 119 calls `settings.value()` without `_logger`.
- [MEDIUM] panel_dock.py:109 — `_on_redock()` emits significant UI lifecycle signal with no log. Line 109 emits `reattach_requested` signal.

### LOW

- [LOW] panel_dock.py:130-131 — `closeEvent()` emits `reattach_requested` signal with no log.
- [LOW] _screen_compat.py:86 — `move_widget()` performs widget geometry mutation with no success log.

---

## Shard 17 — panels cutter/script/sandbox

### MEDIUM

- [MEDIUM] hxd_panel.py:262-264 — `start_tool()` method has silent failure when `waitForStarted()` returns False without logging. While `load_file()` logs this at L230 (`hxd_start_failed`), `start_tool()` silently returns False at L264. `if not self.process.waitForStarted(...): self.process = None; return False` with no log call.
- [MEDIUM] hxd_panel.py:238-239 and 269-270 — Exception handlers use `_logger.warning(..., error=str(e))` instead of `_logger.exception(...)`, dropping the traceback. `except (OSError, RuntimeError) as e: _logger.warning("hxd_...", error=str(e))` should use `.exception()`.
- [MEDIUM] script_manager.py:840 — File read operation (`Path(file_path).read_text()`) involving user-provided file path has no entry log before the read. Error path logs with `_logger.exception()` but entry log naming the path would improve traceability per §2.3.

---

## Shard 18 — panels frida/ghidra/x64dbg

### MEDIUM

- [MEDIUM] frida_panel.py:468 — `log_message()` public method performs real work (appends to console) with no entry/exit logging. Method definition at line 468 with only `self._console.appendPlainText(message)` and no `_logger` call.

---

## Shard 19 — hex_editor_widget + VNC + scripting/transforms/panel

### HIGH

- [HIGH] hex_editor_widget.py:1578 — `except ValueError:` swallows hex parse failure silently with fallback to UTF-8; no log statement. Lines 1576-1579 show `try: bytes.fromhex(...) except ValueError: data = text.encode("utf-8")` with no `_logger` call.
- [HIGH] _scripting.py:1191 — `execute_script` function missing critical security logs: no invocation log before compile/exec, no exception log in the `except BaseException` handler, no completion log. Lines 1189-1197 show the try/except for `compile` and `exec`, but there's no `_logger.info("script_invoked", ...)` before L1189, no `_logger.exception(...)` inside the except at L1191, and no `_logger.info("script_completed", ...)` before the return at L1212.
- [HIGH] _scripting.py:607 — `except LookupError as exc:` re-raises with new LookupError message but emits no log statement. Lines 606-609 show the try/except and raise, but there's no log call between the exception and the raise.
- [HIGH] _scripting.py:827 — `except LookupError as exc:` re-raises with new message but no log. Line 827 shows `raise LookupError(str(exc)) from exc` with no preceding log statement.
- [HIGH] panel.py:1113-1114 — `except (AttributeError, ValueError): pass` silent swallow. Lines 1113-1114 show bare `pass` with no log call in the except block for the `list_bookmarks()` call.

### MEDIUM

- [MEDIUM] hex_editor_widget.py:1417 — `_handle_hex_input` writes bytes to document via bridge call (L1441, L1449) with only failure-path warnings (L1444, L1452), no entry log or success indication.
- [MEDIUM] hex_editor_widget.py:1459 — `_handle_ascii_input` same asymmetry: writes via bridge at L1475/L1483 with only failure logs L1478/L1486, no entry or success logs.
- [MEDIUM] hex_editor_widget.py:1491 — `_do_delete` deletes bytes via `delete_fn(...)` at L1511/L1524 with only failure-path warnings (L1517, L1528), no success log.
- [MEDIUM] hex_editor_widget.py:1559 — `_do_paste` writes via `write_bytes`/`insert_bytes` at L1593/L1602 with only failure warnings (L1597, L1606), no success log.
- [MEDIUM] hex_editor_widget.py:1532 — `_do_undo` and `_do_redo` invoke bridge undo/redo at L1537/L1547 with no logging at all. Both methods have zero `_logger` calls; significant state mutations silent.
- [MEDIUM] vnc_widget.py:278 — `RFBClient.connect` missing entry log before `asyncio.open_connection` at L279-281; only logs on failure (L296) and success (L299-306).
- [MEDIUM] vnc_widget.py:447 — `request_framebuffer_update` sends VNC protocol message via `_writer.write` + `drain` at L456-457 with no log.
- [MEDIUM] vnc_widget.py:1578 — `send_pointer_event` sends protocol message via `_writer.write` + `drain` at L1579-1580 with no log.
- [MEDIUM] vnc_widget.py:1592 — `send_key_event` sends protocol message via `_writer.write` + `drain` at L1593-1594 with no log.
- [MEDIUM] vnc_widget.py:322 — `_negotiate_version` sends client version at L322 with no log. Line 321 logs server version; line 322 has no log before the client write.
- [MEDIUM] vnc_widget.py:356 — `_negotiate_security` and `_perform_vnc_auth` contain multiple unlogged wire writes: L356 (security selection), L394/L399 (auth response).
- [MEDIUM] vnc_widget.py:423 — `_client_init` sends ClientInit at L423 and pixel format at L429 with no logs.
- [MEDIUM] vnc_widget.py:1596 — `disconnect` lifecycle transition not logged on success; only OSError logs at L1604. No `_logger.info("vnc_disconnecting")` at entry or `_logger.info("vnc_disconnected")` after close on success path.
- [MEDIUM] _scripting.py:1057 — File write via `resolved.open("w", encoding="utf-8")` in `_resolve_user_print_path` has no surrounding log. Line 1057 opens a file with no log statement.
- [MEDIUM] _scripting.py:1107 — Sandbox temp directory creation via `Path(tempfile.mkdtemp(...))` at L1107 has no log.
- [MEDIUM] _scripting.py:1403 — `_on_load_script` opens and reads a file with only exception log at L1407; entry log missing, success log missing.
- [MEDIUM] _scripting.py:1433 — `script_save_failed` exception log missing `path=` context kwarg; path is not included in the error record. Line 1433 calls `_logger.exception("script_save_failed")` with no kwargs.
- [MEDIUM] _scripting.py:1335 — `worker.start()` in `_on_run_script` launches background script execution with no log statement. Line 1335 `worker.start()` has no log before or after; significant lifecycle transition.
- [MEDIUM] _transforms.py:905 — `except ValueError:` from `bytes.fromhex(key_hex)` validation has no log before showing user dialog. Lines 905-908 show the except and dialog with no log statement.
- [MEDIUM] _transforms.py:473 — `_run_single_transform` calls `self.document.transform_data(...)` with only failure log at L475, no entry log.
- [MEDIUM] _transforms.py:493 — `_on_transform_preview` invokes `_run_single_transform` with no entry log; no entry/exit logging around the preview operation.
- [MEDIUM] _transforms.py:813 — `_on_block_copy` invokes `self.document.copy_block(...)` with only failure log at L815, no entry log, no success log.
- [MEDIUM] panel.py:659 — `_on_save` missing entry log; only success log at L676. No log before the save attempt to record intent.
- [MEDIUM] panel.py:670 — `_on_save` OSError at L670 is caught and shown in dialog (L671) but not logged as an exception.
- [MEDIUM] panel.py:687 — `_on_save_as` OSError at L687 is caught and shown in dialog (L688) but not logged as an exception.
- [MEDIUM] panel.py:970 — `save` public method entry/success logging missing; only exception at L981.
- [MEDIUM] panel.py:809 — `set_bridge` attaches a bridge with no log statement. Line 820 `self._bridge = bridge` with no surrounding log.
- [MEDIUM] panel.py:822 — `set_state_holder` attaches state holder with no log statement. Line 828 `self.state_holder = state_holder` with no surrounding log.
- [MEDIUM] panel.py:713 — `goto_offset` navigates to an offset with no log statement. No log before the delegation call at L721-722.

### LOW

- [LOW] panel.py:752 — `_on_send_to_ai` success path never logs context push; only error debug logs at L773/L782. Line 787 emits the context but no log statement for the successful push.

---

## Shard 20 — hex editor submodules

### HIGH

- [HIGH] _base.py:655-656 — `except (ValueError, TypeError, OSError, RuntimeError, ImportError):` block returns formatted error string without logging the exception. `except (ValueError, TypeError, OSError, RuntimeError, ImportError) as exc: return f"Error: {exc}"` — no `_logger` call before return.
- [HIGH] _widgets.py:447-449 — `except ValueError:` silently sets error label without logging. `except ValueError as exc: self._result_label.setText(f"Error: {exc}"); return` — no log call.
- [HIGH] _data_inspector.py:327-328 — `except (AttributeError, TypeError, ValueError):` silently sets fallback value without logging. `except (AttributeError, TypeError, ValueError): doc_len = 0` — no log call.
- [HIGH] _data_inspector.py:337-338 — `except (AttributeError, ValueError, OverflowError):` silently sets error in UI without logging. `except (AttributeError, ValueError, OverflowError) as exc: self._decode_output.setPlainText(f"Error: {exc}")` — no log call, should use `.exception()` to preserve traceback.
- [HIGH] _hashing.py:144-147 — `except (RuntimeError, OSError, ValueError, AttributeError):` shows QMessageBox but does NOT log the exception. `except (RuntimeError, OSError, ValueError, AttributeError) as exc:` followed by `show_warning(...)` but no `_logger.warning/exception()` call.
- [HIGH] _hashing.py:265-266 — `except (RuntimeError, OSError, ValueError, AttributeError):` silently updates label without logging. `except (...) as exc: self._pe_checksum_status.setText(...)` — no log call.

### MEDIUM

- [MEDIUM] _pattern_editor.py:478-494 — File write operation at L481/L483 has no pre-write log indicating path/size before the write. `path.write_text(...)` with no `_logger.info("pattern_save_begin", ...)` before the write; only post-write success log at L494 and error log in except.
- [MEDIUM] _pattern_editor.py:509-529 — File read operation at L511 has no pre-read log indicating path before the read. `content = path.read_text(encoding="utf-8")` with no pre-read log; only error log at L515 and post-read success log at L529.
- [MEDIUM] _search.py:245-280 — `_on_search()` dispatches a worker with no entry log indicating search mode/query. Worker created and started at L270-280 with no `_logger.info("search_started", ...)` beforehand.
- [MEDIUM] _search.py:495-573 — `_on_numeric_search()` dispatches a worker with no entry log indicating search parameters.
- [MEDIUM] _sections.py:309-336 — `_populate_strings()` dispatches worker with no entry log indicating extraction parameters. `execute_strings_extraction` worker created and started at L327-336 with no `_logger.info("strings_extract_started", ...)` beforehand.
- [MEDIUM] _signatures.py:171 — Database read operation `Path(db_path).read_text()` in `_scan_die()` has no surrounding log.
- [MEDIUM] _signatures.py:261 — Database read operation `db_file.read_text()` in `_scan_clamav()` has no surrounding log.
- [MEDIUM] _signatures.py:388 — Database read operation `Path(db_path).read_text()` in `_scan_custom()` has no surrounding log.
- [MEDIUM] _signatures.py:529-555 — `_on_scan_signatures()` dispatches worker with no entry log indicating scan type/database.
- [MEDIUM] _process_memory.py:156-202 — Win32 API calls (`OpenProcess`, `VirtualQueryEx`, `CloseHandle`) in `_list_regions_ctypes()` have no pre-call logs. Direct ctypes calls at L167, L180, L197 with no surrounding entry/dispatch logs; only error log at L202.

---

## Cross-shard patterns

1. **Missing entry-level logs on public methods** is the single largest unresolved category (>250 findings). Pattern: completion log exists, intent log missing.
2. **Bridge-to-bridge invocations** in hex_editor.py lack per-hop logging despite final completion log.
3. **Worker dispatch** (QThread worker.start in hex editor submodules, scripting panel) consistently lacks entry logs identifying the dispatched operation.
4. **VNC protocol writes** (vnc_widget.py) are systematically unlogged across the wire-write API surface.
5. **frida_bridge.py** has 61 method-level entry/exit asymmetry findings — the single largest hotspot.
6. **HIGH violations** are concentrated in shard-19 (`hex_editor_widget`, `_scripting`, `panel`) and shard-20 (`_hashing`, `_data_inspector`, `_base`, `_widgets`) — all silent-exception or unlogged-exception swallows in UI submodules.
