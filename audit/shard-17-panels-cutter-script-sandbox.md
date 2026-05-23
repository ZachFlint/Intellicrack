# Shard 17 — Panel base + cutter/script/sandbox/misc panels

- **Files audited**: 13
- **Total LOC**: 7972
- **Generated**: 2026-05-22T22:56:03Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 4     |
| MEDIUM   | 38    |
| LOW      | 7     |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0 (only template-string literal inside `script_manager.py`)
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 2 (`hxd_panel.py` L73, `cutter_tabs.py` L593)

## Findings by file

### src/intellicrack/ui/panels/__init__.py — LOC 49

**Logger status**: missing (exempt — pure re-exports only, no executable logic)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. The file is a `__init__.py` containing only `from X import Y` re-exports and an `__all__` list. Exempt per §4 of the criteria.

---

### src/intellicrack/ui/panels/base_panel.py — LOC 281

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**: none. Logger is correctly defined at module level. `start_tool`, `stop_tool`, and `_run_async` all log with structured kwargs at debug level. No except blocks, no external calls, no string formatting in log messages. Toolbar-factory static methods are trivial widget builders that do not need logging.

---

### src/intellicrack/ui/panels/analysis_panel.py — LOC 370

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L209-230 — `_on_address_cell` is private and logs on the failure branch (`_logger.warning("invalid_hex_address", ...)` at L225), but the success branch silently emits `address_navigate`. Consider a debug log on successful navigate emission to maintain end-to-end traceability of GUI workflow milestones (§2.4). Severity LOW because the public `set_analysis` and `clear` events are logged elsewhere.
- [LOW] L137-162 — `_create_table` is non-trivial but it is purely a widget factory invoked only during `_setup_ui`; its current `_setup_ui`-level coverage is acceptable. Noted for completeness.

No HIGH or MEDIUM findings. The `set_analysis`, `get_current_analysis`, and `clear` public methods all log at info/debug with structured kwargs.

---

### src/intellicrack/ui/panels/async_bridge.py — LOC 335

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L266 — `except RuntimeError:` inside `run_bridge_coroutine` is followed only by `_logger.debug("no_running_event_loop", exc_info=True)`. The `exc_info=True` preserves the traceback so this is acceptable, but the message says "no running event loop" which is the *expected* path (no active loop means we must create one). Severity LOW: technically correct, but the wording suggests it might mask a real RuntimeError unrelated to "no running loop". Recommend narrowing the except or noting expected vs unexpected in the log.
- [LOW] L335 — `_log_task_exception` uses `_logger.error(...)` rather than `_logger.exception(...)` for a task that completed with an exception. This is acceptable because the exception is being inspected via `task.exception()` from a done-callback (no active traceback in scope), but worth noting per §3.6 guidance. Recommend documenting this distinction.

All except blocks log. All worker thread error paths log. No HIGH or MEDIUM findings.

---

### src/intellicrack/ui/panels/qt_compat.py — LOC 243

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**: none. Pure thin-shim wrapper module dispatching to Qt method names via `_resolve()`; the only branch that warrants logging (missing-method probe) is logged at warning with class/method context. `connect_cell_changed` also logs when the signal is absent. No except clauses, no external calls beyond Qt API dispatch.

---

### src/intellicrack/ui/panels/graph_view.py — LOC 557

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L311-328 — `CFGGraphScene.load_graph` logs entry/exit at debug. Good. No issues found.
- [LOW] L525-529 — `fit_to_view()` is a public method but is purely a Qt view operation (call `fitInView`). Trivial wrapper, no logging needed.

No except blocks (Qt rendering code), no external calls. No HIGH or MEDIUM findings.

---

### src/intellicrack/ui/panels/stack_viewer.py — LOC 654

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L606-626 — `set_x64dbg_bridge` and `set_frida_bridge` log at info on bridge attach. Good.
- [LOW] L586-604 — `refresh()` is a public method that performs real work (queries bridges, populates table). Logs at debug at L599 after frames are retrieved. Consider an entry-level debug log to record intent for symmetry. Severity LOW.
- [LOW] L628-637 — `add_source(name, source)` mutates state (registers a new data source) but has no log. Per §2.4 (registration of tools/providers), should log at info. Severity LOW because the registry is internal and not user-facing.
- [LOW] L639-643 — `clear()` is a public method that resets state, no log. Severity LOW.

All except blocks in `get_stack_frames` (L176, L254) and `is_connected` (L208, L285) log appropriately. No string formatting in log messages. No HIGH or MEDIUM findings.

---

### src/intellicrack/ui/panels/hex_editor_panel.py — LOC 15

**Logger status**: missing (exempt — shim file)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. The file is a 15-line backward-compatible re-export shim (`from intellicrack.ui.panels.hex_editor import HexEditorPanel`). Exempt per §4.

---

### src/intellicrack/ui/panels/hxd_panel.py — LOC 363

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L67-74 — `except (FileNotFoundError, OSError):` in `_find_hxd_executable` swallows the error silently with `continue`. This is a HIGH violation per §3.2: every except block must log. Fix: `_logger.debug("hxd_registry_probe_failed", reg_path=reg_path, exc_info=True)` before `continue`. (Even a debug log preserves diagnostic capability for missing HxD installations.)
- [MEDIUM] L66-87 — `_find_hxd_executable` performs Windows registry probes (`winreg.OpenKey`, `winreg.QueryValueEx`) and filesystem `Path.exists` checks across multiple locations, with NO entry/exit log. Per §2.3 (Registry / Win32 operations must be logged), this should log at debug with the resolved path on success and at debug "not found" on full miss. Severity MEDIUM.
- [MEDIUM] L201-242 — `load_file()` is a public method that launches HxD as a subprocess via `QProcess.start()` at L226. There is no entry log before the QProcess is started; only a success log at L236 (`hxd_file_loaded`) after `waitForStarted`. Per §2.3 (Subprocess must be logged before AND after), an entry log naming the binary and target file is required. Fix: `_logger.info("hxd_launch_requested", exe=str(self.hxd_exe), file=str(file_path))` before `self.process.start()`.
- [MEDIUM] L244-273 — `start_tool()` launches HxD via QProcess.start (L259) with no entry log; only error-path logging exists (`hxd_start_failed`, `hxd_not_installed`). No success log either. Fix: add entry/success logs. Severity MEDIUM.
- [MEDIUM] L228, L261 — `waitForStarted` returns False path logs only `hxd_start_failed` at L229 but in `start_tool()` (L261-263) the same path returns False without any log. HIGH-adjacent silent failure; rated MEDIUM since it's a soft failure of an external tool.
- [LOW] L315-324 — `stop_tool()` performs sandbox-style lifecycle teardown but has no entry log. Per §2.4 (lifecycle transitions), should log at info. Severity LOW because the teardown happens internally via `_terminate_existing` which is also unlogged.
- [LOW] L326-359 — `_terminate_existing()` performs subprocess termination/kill (`self.process.terminate()`, `self.process.kill()`, `self.process.waitForFinished()`) at L335-338 with NO log of the termination sequence; only the RuntimeError except path logs (L340, L351). Should log info on successful termination. Severity LOW.
- [LOW] L361-363 — `cleanup()` is a public method that calls `_terminate_existing()`, no log. Severity LOW.

Exception logging in `load_file` L237 and `start_tool` L268 uses `_logger.warning("hxd_launch_failed", error=str(e))` rather than `_logger.exception(...)` so the traceback is dropped. Per §3.6 this is a MEDIUM finding:

- [MEDIUM] L237-238, L268-269 — `except (OSError, RuntimeError) as e:` followed by `_logger.warning(...)` drops the traceback. Replace with `_logger.exception("hxd_launch_failed", path=str(file_path))` (no need to pass `error=str(e)` because `exception()` captures the traceback).

---

### src/intellicrack/ui/panels/cutter_panel.py — LOC 1331

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L529-547 — `_on_analyze()` triggers a full Rizin analysis via `self._bridge.analyze()` (significant bridge call); no entry log before the bridge call. Status string is set but no `_logger.info("cutter_analyze_requested", ...)` is emitted. Per §2.3 (bridge invocations must be logged before AND after).
- [MEDIUM] L569-581 — `_on_refresh_functions()` calls `self._bridge.get_functions(filter_text)` without entry log. Same gap.
- [MEDIUM] L779-788 — `_refresh_imports()` calls bridge, no entry log.
- [MEDIUM] L815-824 — `_refresh_exports()` calls bridge, no entry log.
- [MEDIUM] L851-860 — `_refresh_sections()` calls bridge, no entry log.
- [MEDIUM] L910-924 — `search_strings(pattern)` is a **public** method that invokes `self._bridge.search_strings(pattern)`. No entry log naming the pattern; the only log on failure is `cutter_string_search_failed`. Per §2.1 and §2.3 should log entry with structured kwargs.
- [MEDIUM] L1080-1100 — `_on_save_binary()` calls `self._bridge.save_binary(file_path)` (a real bridge invocation writing to disk via the bridge). No entry log; error callback is `lambda e: self._set_status(f"Save failed: {e}")` with no `_logger` call. Per §2.3 this should log before AND after; the error callback should log.
- [MEDIUM] L1134-1153 — `_on_goto_address()` calls `self._bridge.seek(address)`. No entry log; error callback only sets status, no log.
- [MEDIUM] L1176-1190 — `_on_find_function()` calls `self._bridge.get_function_address(name)`. No entry log; error callback only sets status.
- [MEDIUM] L1248-1263 — `_ctx_rename_function()` calls `self._bridge.rename_function(address, new_name)` (mutates analysis state). No entry log; error callback only sets status.
- [MEDIUM] L1275-1290 — `_ctx_add_comment()` calls `self._bridge.add_comment(address, comment)` (state mutation). No entry log; error callback only sets status.
- [MEDIUM] L1303-1318 — `_ctx_read_bytes()` calls `self._bridge.read_bytes(address, count)`. No entry log; error callback only appends to console, no `_logger`.
- [MEDIUM] L484-491 — `_on_initialize_error(exc)` uses `_logger.warning("cutter_init_failed", error=str(exc))`. While this isn't strictly inside an `except` block (the exception was delivered via Qt signal), the loss of traceback for a bridge initialization failure is concerning. Severity MEDIUM. Consider whether `error=str(exc)` is sufficient context or if `exc_info=True` should be set.
- [MEDIUM] L504-513, L559-567, L608-611, L790-797, L826-833, L862-869, L944-951, L1051-1059 — Similar pattern: all these `_on_*_error` slots receive an exception object through Qt signals and log with `_logger.warning(..., error=str(exc))`. Functional, but traceback is dropped. Severity MEDIUM (debatable LOW depending on context-availability).
- [LOW] L583-606 — `_apply_functions()` does substantial work (clears tree, populates entries, toggles sorting) and logs at debug at exit (`cutter_functions_refreshed`). Entry log would be symmetric. Severity LOW.
- [LOW] L425-454 — `analyze_binary()` is a **public** method that triggers bridge load. Logs the success/failure paths but no entry log naming the binary path. Severity LOW because `_logger.info("cutter_binary_loaded", ...)` occurs in `_on_binary_loaded` immediately afterwards.
- [LOW] L1021-1039 — `_on_run_command()` executes raw r2 commands via the bridge. No entry log naming the command. Could be sensitive (commands may include addresses, registers, etc.); a debug-level entry log is acceptable.

L175-176 (`except (RuntimeError, ConnectionError, OSError):` in `_cleanup`) and L737-738 (`except ValueError:` in `_parse_address`) both log correctly.

---

### src/intellicrack/ui/panels/cutter_tabs.py — LOC 892

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L590-595 — `HexdumpTab._on_dump`: `except ValueError:` silently sets `self._output.setPlainText("[error] Invalid address or length")` with NO log call. Per §3.2 this is HIGH. Fix: `_logger.warning("hexdump_input_parse_failed", addr_text=addr_text, length_text=self._len_input.text())` before the return.
- [HIGH] L470-479 — `ROPGadgetsTab._on_search`: calls `self._run_async_fn(self._bridge.search_rop_gadgets(pattern), self._apply_data, None)` — passes `None` as the error callback, meaning bridge failures are silently swallowed. Per §2.3 every bridge invocation must have a logged error path. Fix: pass `_log_tab_error(type(self).__name__, "search_rop_gadgets")` instead of `None`.
- [MEDIUM] L693-706 — `ESILConsoleTab._on_eval`: bridge call `self._bridge.esil_eval(expr)` uses error callback `lambda e: self._output.appendPlainText(f"[error] {e}")` — no `_logger` call. Error path is silent in the structured log.
- [MEDIUM] L708-717 — `ESILConsoleTab._on_step`: same pattern — error lambda appends to UI but doesn't log.
- [MEDIUM] L719-728 — `ESILConsoleTab._on_init_mem`: same pattern.
- [MEDIUM] L583-600 — `HexdumpTab._on_dump`: bridge `hexdump` call's error callback is `lambda e: self._output.setPlainText(f"[error] {e}")` — no `_logger` call.
- [MEDIUM] L561-581 — `HexdumpTab._apply_auto_sections`: triggers bridge `hexdump` with error callback `lambda e: self._output.setPlainText(f"[error] {e}")` — no log.
- [LOW] L120-127, L161-168, L201-208, L239-246, L279-286, L320-327, L362-369, L402-409, L459-468, L756-766, L867-874 — All `refresh(bridge, run_async)` methods on the various tab classes are public methods that perform real work (invoke bridge RPCs and populate UI). They properly route errors via `_log_tab_error(...)` but have no entry log. Per §2.1, these are public methods doing real work and warrant a debug entry log. Severity LOW because the error path is logged via the shared helper.
- [LOW] L657-673 — `ESILConsoleTab.refresh` performs a bridge call (`esil_init_memory`) with success/error callbacks that log only on error (L690 `_logger.warning("esil_auto_init_failed", ...)`). Success path emits no log of the state transition (`self._esil_initialised = True` at L681). Per §2.4 (lifecycle transitions) this should log. Severity LOW.

The `_log_tab_error` helper (L54-74) is a good pattern — properly logs `rpc`, `error`, and `error_type` as structured kwargs.

---

### src/intellicrack/ui/panels/script_manager.py — LOC 1027

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L821-845 — `_on_load_file()` calls `Path(file_path).read_text(encoding="utf-8")` on a user-selected file. Per §2.3 (file I/O involving user-provided targets), an entry log naming the path is required. Currently only the error path logs (`script_file_load_failed` at L838). Fix: add `_logger.info("script_file_load_started", path=file_path)` before the read.
- [MEDIUM] L856-890 — `_on_validate()` invokes `self._validator.validate(script)` (an external dependency that runs validation logic) without entry log. The success and error paths update the status bar but only the exception path logs. Per §2.1, this is a public action with real work and warrants entry/exit logs. Severity MEDIUM.
- [LOW] L504-507 — `_execution_timer` is initialized inside `__init__` and configured (single-shot, interval, signal connection) at L503-506 with no log. The QTimer setup is straightforward; severity LOW.
- [LOW] L671-689 — `_on_script_selected()` triggers a script load and may invoke `_on_save()` based on user dialog. No log of the user-decision flow; only the eventual `script_loaded` debug log fires. Severity LOW.
- [LOW] L796-819 — `_on_delete()` triggers backend `delete_script` (state mutation) plus list mutation; logs `script_deleted` only inside the Yes-branch. Entry log naming the script_id would be helpful. Severity LOW.

L235 contains `print(f"...")` but it is inside a triple-quoted PYTHON template string used to generate user-facing script content — NOT runtime print. Not flagged.

Validation, execution, save, delete events all log appropriately at info. The exception paths at L837-838, L874-875, L919-920 all use `_logger.exception(...)`. Good.

---

### src/intellicrack/ui/panels/sandbox_panel.py — LOC 1855

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L978-1000 — `_on_take_snapshot()`: invokes `self._bridge.snapshot_create(...)`. No entry log naming sandbox_id + label before bridge call. Per §2.3 + §2.4 (state mutation, lifecycle transitions on sandbox snapshots), entry log is required. Success log at L1027 is fine.
- [MEDIUM] L1040-1057 — `_on_restore_snapshot()`: invokes `self._bridge.snapshot_restore(sandbox_id, snapshot_id)`. No entry log of the intent. Success log at L1069 is fine.
- [MEDIUM] L1082-1091 — `_on_screenshot()`: invokes `self._bridge.screenshot(sandbox_id)`. No entry log; success at L1103 is via `self._log` only, no `_logger` info-level event.
- [MEDIUM] L1093-1104 — `_on_screenshot_success()` writes "[+] Screenshot saved: {path}" to the UI console but emits NO `_logger.info("sandbox_screenshot_saved", ...)`. This is a significant state mutation (artifact written to disk by the bridge) — should be logged structurally.
- [MEDIUM] L1115-1133 — `_on_pcap_toggle()`: invokes `pcap_start` or `pcap_stop` (significant lifecycle / network capture). No entry log.
- [MEDIUM] L1135-1148 — `_on_pcap_start_success()`: PCAP capture started, no `_logger.info(...)`; only UI console.
- [MEDIUM] L1159-1172 — `_on_pcap_stop_success()`: PCAP saved to disk path, no `_logger.info(...)`.
- [MEDIUM] L1185-1194 — `_on_memory_dump()`: invokes `self._bridge.memory_dump(...)`. No entry log; memory dump is significant.
- [MEDIUM] L1196-1207 — `_on_memory_dump_success()`: dump written to disk, no `_logger.info(...)`.
- [MEDIUM] L1218-1227 — `_on_extract_files()`: bridge call to extract dropped files, no entry log.
- [MEDIUM] L1229-1240 — `_on_extract_files_success()`: ZIP file written, no `_logger.info(...)`.
- [MEDIUM] L1251-1260 — `_on_yara_scan()`: bridge YARA scan invocation, no entry log.
- [MEDIUM] L1262-1282 — `_on_yara_scan_success()`: structured result (match_count) goes only to UI console, no `_logger.info("sandbox_yara_complete", ...)`.
- [MEDIUM] L1293-1302 — `_on_extract_iocs()`: bridge invocation, no entry log.
- [MEDIUM] L1304-1329 — `_on_extract_iocs_success()`: IOC extraction completed (ioc_count) only via UI log.
- [MEDIUM] L1340-1349 — `_on_timeline()`: bridge invocation, no entry log.
- [MEDIUM] L1351-1375 — `_on_timeline_success()`: timeline events generated (event_count), no structured log.
- [MEDIUM] L1386-1395 — `_on_detect_behaviors()`: bridge invocation, no entry log.
- [MEDIUM] L1397-1423 — `_on_detect_behaviors_success()`: behavior matches found, no structured log.
- [MEDIUM] L1434-1463 — `_on_copy_in()`: bridge `copy_to` invocation (file I/O into sandbox), no entry log naming source/dest. Success/failure callbacks only emit UI text, no `_logger`.
- [MEDIUM] L1483-1512 — `_on_copy_out()`: bridge `copy_from` invocation (file I/O out of sandbox), no entry log. Success/failure callbacks emit UI text only.
- [MEDIUM] L1532-1541 — `_on_continue_vm()`: bridge `cont` invocation (VM lifecycle resume), no entry log. No `_logger` on success path either.
- [MEDIUM] L1561-1578 — `_on_delete_snapshot()`: bridge `snapshot_delete` invocation, no entry log naming sandbox_id + snapshot_id.
- [MEDIUM] L1580-1593 — `_on_delete_snapshot_success()`: state mutation (snapshot removed), no `_logger.info(...)`.
- [MEDIUM] L1604-1620 — `_on_execute_command()`: bridge `execute` invocation (arbitrary command run inside sandbox). No entry log naming the command. This is a significant operation — should log at info.
- [MEDIUM] L1622-1640 — `_on_execute_command_success()`: command result (exit_code, stdout, stderr) goes only to UI; structured log of "sandbox_command_completed" with exit_code is recommended.
- [MEDIUM] L1741-1750 — `_connect_vnc_display()`: invokes `self._bridge.get_vnc_port(...)` (bridge call). Error callback uses `lambda _: _logger.debug("vnc_port_query_failed")` — logs but drops context (which sandbox_id failed). MEDIUM because context (`sandbox_id`) is in scope and should be passed.
- [MEDIUM] L1083, L1107, L1118, etc. — All `_on_*_error(exc)` handlers use `_logger.warning(..., error=str(exc))` losing traceback. Severity MEDIUM (consistent with cutter_panel.py finding).
- [LOW] L472-478 — `_log(message)` is a UI-only helper that appends to the console output. By design it doesn't log structurally. Consider whether selected error UI messages should also fire a structured `_logger.warning(...)`. Severity LOW because most callers do log separately.
- [LOW] L1789-1792 — `_disconnect_vnc_display()` calls VNC widget teardown without log of disconnect intent. Severity LOW.
- [LOW] L1794-1809 — `_clear_report_tabs()` clears 14 trees in one call; no log. Severity LOW because it's a UI reset rather than a state mutation.
- [LOW] L1811-1855 — `load_execution_report(report)` is a public method that displays an execution report. Logs entry (`execution_report_loading` debug at L1817) and exit (`execution_report_loaded` info at L1850). Good.

L334-340, L342-349 (`except (RuntimeError, ConnectionError, OSError):` in `_cleanup`) both log via `_logger.warning(..., exc_info=True)` — good. No bare excepts. No `contextlib.suppress`.

The `set_bridge`, `set_sandbox`, `set_sandbox_manager` methods all log at info with structured kwargs on bridge attach. The `_on_create_success`, `_on_destroy_success`, `_on_restart_success`, `_on_run_binary_success`, `_on_snapshot_taken`, etc. all emit `_logger.info(...)` for the bulk of lifecycle transitions. The findings above are mostly the gap of entry-side logging for the user-action callbacks.

---

## Aggregate notes

### Cross-cutting patterns

1. **Entry log gap for bridge-invocation `_on_*` callbacks**: The dominant pattern in this shard is that user-action callbacks (`_on_*`, `_ctx_*`) invoke a bridge coroutine via `self._run_async(...)` but only log on the success/failure callback, not on the entry. Per §2.3, bridge invocations must be logged before AND after. This affects `cutter_panel.py`, `sandbox_panel.py`, and `cutter_tabs.py` extensively. The simplest remediation is to add `_logger.info("<panel>_<action>_requested", sandbox_id=..., ...)` immediately before the `self._run_async(...)` call.

2. **Error-callback lambdas that don't log**: Many `on_error=lambda e: self._set_status(f"... failed: {e}")` callbacks exist that update the UI but never invoke `_logger`. Per §2.3 + §3, error pathways from bridge calls must be logged. The shared helper `_log_tab_error()` in `cutter_tabs.py` (L54) is a good model and should be reused or extended for the panel modules.

3. **`_logger.warning(..., error=str(exc))` for Qt-signal-delivered exceptions**: All `_on_*_error(exc)` slot handlers in `cutter_panel.py` and `sandbox_panel.py` lose the traceback because they are not in an active `except` clause. This is consistent and arguably correct (no traceback exists at that point), but `error=str(exc)` plus optional `exception_type=type(exc).__name__` would improve diagnostics. Currently noted as MEDIUM per §3.6 with the understanding this may be unavoidable given the Qt signal-slot architecture; downgrade to LOW if the team prefers.

4. **`hxd_panel.py` is the only file with structural logging gaps**: It has a HIGH-severity silent `except` block (registry probe), unlogged QProcess launches (subprocess per §2.3), and unlogged winreg probes (Win32 per §2.3). Recommend a targeted refactor of this file.

5. **`cutter_tabs.py` `ESILConsoleTab` and `HexdumpTab`**: These two interactive tabs use ad-hoc error callbacks (`lambda e: self._output.setPlainText/appendPlainText(...)`) that never invoke `_logger`. Replace with `_log_tab_error(...)` from the same module, or extend it to also write to the UI.

### Cross-file recommendations

- Adopt a standard helper for "bridge call with structured entry/exit logging" in `base_panel.py` (e.g., `_run_async_logged(coro, event_name, **context)`) so panels stop duplicating the entry-log pattern by hand. This would also enable consistent timing measurements.
- Audit `_on_*_error(exc)` slots project-wide: decide whether `_logger.warning(..., error=str(exc), exc_info=False)` or `_logger.exception(...)` is the correct call in the Qt-signal-delivered-exception case, and document the decision in CLAUDE.md.

### Audit difficulty

- `sandbox_panel.py` (1855 LOC) is the largest file in this shard and contains a high density of similar callback pairs (`_on_X`, `_on_X_success`, `_on_X_error`) — most findings are repetitive instances of the same pattern. The findings are precise but visually noisy.
- `cutter_panel.py` (1331 LOC) and `cutter_tabs.py` (892 LOC) interact tightly via the `RunAsyncFn` type alias; cross-file inspection was needed to verify error callbacks are passed correctly.
- All other files (≤654 LOC) were straightforward.
