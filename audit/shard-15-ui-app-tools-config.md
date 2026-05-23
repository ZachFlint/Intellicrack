# Shard 15 — UI app, tools, tool_config, sandbox_config

- **Files audited**: 4
- **Total LOC**: 8147
- **Generated**: 2026-05-22

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 0     |
| MEDIUM   | 28    |
| LOW      | 11    |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0 (only `print(...)` text appears inside string literals embedded in generated bridge-verification scripts in `tool_config.py` at L519/L525/L528 — those are emitted INTO a generated Python file, not runtime output)
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 0

All four files import `from intellicrack.core.logging import get_logger` and define a module-level `_logger` at the documented location. Every `except` clause has a log call. No stdlib `logging` usage and no `contextlib.suppress` anywhere. No `# noqa` / `# type: ignore` / `# pyright: ignore` for logging suppression (the two `# noqa: PLR2004` annotations at `app.py:342` and `tools.py:2372` are for magic-number rules, unrelated to logging).

## Findings by file

### src/intellicrack/ui/app.py — LOC 3077

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L1366-1375 — `_on_load_binary()` (file dialog → load) does not log. Workflow milestone per §2.4 (target loaded). Fix: `_logger.info("load_binary_dialog_opened")` on entry; log selection/cancel branch.
- [MEDIUM] L1377-1404 — `_load_binary(path)` is the central "binary loaded" workflow milestone. It updates `self.current_binary`, enables tool buttons, schedules orchestrator work, and opens the hex editor — but it never logs `_logger.info("binary_loaded", path=..., name=...)`. §2.4 requires logging GUI workflow milestones such as target loaded. Fix: add an info-level log at entry with the binary path.
- [MEDIUM] L1406-1448 — `_on_new_session()` only logs the dialog-result debug at L1426 inside an `if`-branch. The actual `start_session(...)` kickoff (workflow milestone — session lifecycle, §2.4) is not logged. Fix: `_logger.info("session_create_requested", provider=..., model=..., name=...)` before `_run_async(create_session())`.
- [MEDIUM] L1450-1463 — `_on_load_session()` schedules a session load with no log statement. Workflow milestone (§2.4 session lifecycle). Fix: `_logger.info("session_load_dialog_opened")` / log on selection.
- [MEDIUM] L1465-1478 — `_on_session_load_requested(session_id)` invokes orchestrator `load_session` with no log; only `_logger.info("session_deleted_from_manager", ...)` at L1489 in the sibling delete handler. Fix: `_logger.info("session_load_requested", session_id=session_id)`.
- [MEDIUM] L1501-1508 — `_on_save_session()` has no log calls around the `save_session()` orchestrator invocation. Workflow milestone (§2.4 save/load). Fix: `_logger.info("session_save_requested")`.
- [MEDIUM] L1510-1529 — `_on_export_chat()` writes to disk via `Path(path).open("w")` at L1524 with no surrounding log calls. §2.3 file-write requirement. Fix: `_logger.info("chat_export_started", path=path, message_count=len(messages))` before; `_logger.info("chat_export_completed", path=path)` after.
- [MEDIUM] L1531-1579 — `_on_export_session()` launches the export worker without an entry log. Only the failure path at L1570 logs. Fix: `_logger.info("session_export_started", session_id=session.id, path=path)` before `worker.start()`.
- [MEDIUM] L1581-1610 — `_on_import_session()` starts the import worker without entry log; only `_handle_session_import_error` at L1657 logs the failure. Fix: log `_logger.info("session_import_started", path=...)` before `_start_session_import(...)`.
- [MEDIUM] L1709-1741 — `_on_export_analysis()` writes JSON to disk at L1738 (`Path(path).open("w") ... json.dump(...)`). No log calls. §2.3 file-write. Fix: `_logger.info("analysis_export_started"/"_completed", path=path)`.
- [MEDIUM] L1686-1707 — `_on_save_patched_binary()` triggers a save through the embedded hex editor with no log; this is a binary-patch persistence operation (workflow milestone, §2.4). Fix: log entry, decision branch, and completion.
- [MEDIUM] L2017-2072 — `_on_refresh_models()` performs a model-discovery refresh and reads `providers.json` configuration (L2044-L2052) with only a `_logger.debug("config_file_load_failed", ...)` on the exception path. The successful credential-read branch and the model refresh kickoff lack info-level logs (§2.4 credential read, §2.3 read of operationally significant config). Fix: `_logger.info("models_refresh_requested", provider=provider_id, has_credentials=bool(api_key))`.
- [MEDIUM] L2091-2107 — `_on_browse_models()` schedules an AI-provider list-models RPC (`active_provider.list_models()`) with no entry log. §2.3 AI-provider call. Fix: `_logger.info("provider_list_models_requested", provider=...)`.
- [MEDIUM] L2244-2258 — `_on_configure_sandbox()` opens the sandbox dialog and may apply settings — no entry log. Workflow milestone (§2.4 config persistence path). Fix: `_logger.info("sandbox_config_dialog_opened")`.
- [MEDIUM] L2431-2473 — `_on_open_sandbox()` orchestrates an availability probe and sandbox creation (§2.3 bridge invocation) with logging only on the success path inside the nested callback (L2462). Fix: log entry `_logger.info("sandbox_open_requested")` and explicit unavailable branch.
- [MEDIUM] L2475-2491 — `_on_preferences()` opens the preferences dialog without an entry log; the OK path only emits a status-bar update at L2491 and the changed signal handler logs at L2502. Fix: `_logger.info("preferences_dialog_opened")`.
- [MEDIUM] L2533-2538 — `_on_xpu_status()` opens the XPU status dialog with no log. Minor but a workflow event (§2.4 GUI workflow milestone). Fix: `_logger.debug("xpu_status_dialog_opened")`.
- [MEDIUM] L2540-2561 — `_on_about()` queries font/icon manager state and shows the About dialog with no log. Likely LOW, but a debug log of the resolved font info would aid diagnostics. Fix: optional `_logger.debug("about_dialog_opened", code_font=..., ui_font=...)`.
- [MEDIUM] L2784-2786 — `_on_open_binary()` just forwards to `_on_load_binary()`; combined with the unlogged `_load_binary` at L1377 the entire binary-load flow is silent on the success path.
- [MEDIUM] L2788-2806 — `_on_open_sandbox_panel()` creates and wires a sandbox bridge (§2.3 bridge invocation). Only debug-level logs at L2801/L2805 fire after the panel exists. Fix: `_logger.info("sandbox_panel_opened", bridge_attached=bool(bridge))`.
- [MEDIUM] L2833-2840 — `_on_debug_current_binary()` routes the current binary to x64dbg with no log on success. Workflow milestone (§2.4 — analysis queued). Fix: `_logger.info("debug_binary_requested", binary=str(self.current_binary))`.
- [MEDIUM] L2841-2847 — `_on_analyze_current_binary()` same pattern: routes binary to Cutter without success-path log.
- [MEDIUM] L2849-2855 — `_on_hex_edit_current_binary()` same pattern: routes binary to hex editor without log.
- [MEDIUM] L2857-2863 — `_on_open_binary_in_ghidra()` same pattern: routes binary to Ghidra without log.
- [MEDIUM] L3016-3077 — `closeEvent()` is the application shutdown path. It does shut multiple bridges, sandbox, hex editor, etc., but only individual *failure* paths log (L3055/L3063/L3071). The successful shutdown path has no info-level log marking "main_window_closed". §2.4 lifecycle transition. Fix: `_logger.info("main_window_closing")` near start and `_logger.info("main_window_closed")` near end.
- [LOW] L295-313 — `_apply_smart_window_size()` does `QApplication.instance()` / `get_screen_geometry(...)` with two early-return branches that don't log why default sizing was used. Only the exception branch logs at L312. Fix: `_logger.debug("screen_geometry_unavailable_using_default")` in the two early returns.
- [LOW] L1147-1167 — `_on_bridge_analysis_received(analysis)` updates the panel with no log (this is the async-thread entry for bridge analysis results). Workflow event; debug log would be useful.
- [LOW] L1195-1212 — `_on_user_message(text)` schedules `process_user_input(text)` (the central chat-message entry point) with only a debug log of the optional `pid` context (L1207). Fix: `_logger.debug("user_message_received", length=len(text))` to record the workflow event.
- [LOW] L1233-1266 — `_on_tool_result(result)` is the orchestrator-driven completion handler; it only writes to the UI log panel via `append_log_message`. A structured log call (`_logger.debug("tool_result_received", tool_name=..., success=..., duration_ms=...)`) would let the audit trail correlate UI events with file-based logs.
- [LOW] L2980-2986 — `_on_sandbox_toggled(checked)` mutates UI state without a log. Likely fine, but the toggle is a user-visible state change — `_logger.debug("sandbox_button_toggled", checked=checked)` would be consistent with `_on_auto_approve_toggled` (which also lacks a structured log at L2988-3005). Both LOW.

(No HIGH findings: every `except` block logs; no stdlib logging; no `print()`; no `contextlib.suppress`.)

### src/intellicrack/ui/tools.py — LOC 2397

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L894-902 — `set_tab_content(tab_name, content)` is public but only mutates a single tab. Likely LOW — could be skipped per §2.1 ("more than just attribute return or simple delegation"). Marking LOW only if frequently invoked from external code (it is — called by `display_analysis_result`). Logging is therefore not required; leave as is. (Excluded from final tally.)
- [MEDIUM] L1513-1534 — `open_in_ghidra(file_path)` is the public entry for opening a binary in the embedded Ghidra panel (§2.4 GUI workflow milestone; this also indirectly fires a bridge call). No log on entry / no log on success. Fix: `_logger.info("open_in_ghidra_requested", binary_path=str(path))` on entry and `_logger.info("open_in_ghidra_completed", success=success)` on exit.
- [MEDIUM] L1536-1556 — `open_in_hex_editor(file_path)` same pattern: public binary-routing entry point with no log. Fix: log entry+exit.
- [MEDIUM] L1558-1585 — `open_in_x64dbg(file_path, is_64bit)` same pattern: public binary-routing entry to the embedded debugger with no log on entry or success. The downstream `debug_file()` may log inside the panel/bridge, but the orchestration layer here is silent. Fix: log entry+exit with `is_64bit`.
- [MEDIUM] L1587-1610 — `open_in_cutter(file_path)` partially logs at L1606 (`cutter_analyze_binary_starting`) — entry log is fine — but no exit/success log. Fix: log the success result as well.
- [MEDIUM] L2042-2049 — `log_frida_message(message)` and L2051-L2064 `add_frida_hook_entry(hook_info)` are public methods forwarding to the embedded Frida panel. Hook entries are operationally significant (§2.4 — hook registration on a debugger). Fix: `_logger.info("frida_hook_registered", address=..., function=..., hook_id=...)`.
- [MEDIUM] L2240-2252 — `wire_sandbox_bridge(bridge)` mutates state (`_pending_sandbox_bridge` or live panel binding) without a log; same level of structural mutation as `set_tool_registry` at L1117 (which does log). Fix: `_logger.info("sandbox_bridge_wired", deferred=self.sandbox_panel is None)`.
- [MEDIUM] L2300-2318 — `wire_script_backend(backend, validator)` mutates `_pending_script_backend` and/or live panel binding without a log; the lazy-init path at L1159-L1165 in `add_script_panel` also does not log when the pending backend finally lands. Fix: `_logger.info("script_backend_wired", deferred=self.script_panel is None, has_validator=validator is not None)`.
- [MEDIUM] L2375-2386 — `has_unsaved_changes()` is a public predicate that consults the embedded hex editor — likely simple delegation, but the result drives close-event decisions and is worth a debug log. LOW.
- [MEDIUM] L2388-2397 — `save_hex_editor()` is a public save action. §2.3/§2.4 require logging persistence operations. Currently silent. Fix: `_logger.info("hex_editor_save_invoked"/"_result", success=...)`.
- [LOW] L894-923 — `set_tab_content`, `set_tab_info`, `append_tab_content` (and several `set_*`/`activate_tab` helpers below) are public delegations. The criteria explicitly exempt simple delegations, but as a body of "UI surface area used by external orchestration" they could benefit from debug logs. No fix required — listed for completeness.
- [LOW] L1937-1942 — `close_detached_windows()` and L1944-L1950 `get_detached_state()` are public, run during shutdown, and have no logs. Debug-level log would aid diagnostics during exit.
- [LOW] L1966-1990 — `get_bridge_for_tool(tool_id)` is a public bridge resolver. No log. Could benefit from a debug log of the resolution result.
- [LOW] L2042-2049 — already counted above; `log_frida_message` could optionally `_logger.debug("frida_message_logged", length=len(message))` so messages also land in the structured log channel.

(No HIGH findings: every `except` block logs; no stdlib logging; no `print()`; no `contextlib.suppress`. Existing structured logging coverage of the `add_*_tab` methods is excellent — every bridge construction, registry-fetch fallback, and tab-add path logs with rich kwargs.)

### src/intellicrack/ui/tool_config.py — LOC 1630

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L189-251 — `ToolInstallWorker._install_tool()` performs a tracked file download via `httpx.Client.stream(...)` (network, §2.3) at L198-L201 and a ZIP extraction `zf.extractall(self._install_path)` at L235-L236, plus a final installed-binary write through `_post_install_*` methods. The successful path emits no info-level structured log; only failure branches at L222/L227/L238 log. Fix: `_logger.info("tool_download_started", tool_id=self._tool_id, url=url)` before L198 and `_logger.info("tool_install_completed", tool_id=..., name=name)` after L252.
- [MEDIUM] L189 — `self._install_path.mkdir(parents=True, exist_ok=True)` (§2.3 directory create). Logged neither before nor after.
- [MEDIUM] L213-216 — `zip_path.open("wb")` writes the entire downloaded payload to disk with no surrounding log; only a stream-level loop. (Acceptable when paired with a parent `tool_download_started` log; flagging as MEDIUM until that is added.)
- [MEDIUM] L235-236 — `zipfile.ZipFile(...).extractall(self._install_path)` is a file-write operation not logged. Fix: `_logger.info("tool_archive_extracting", tool_id=..., archive=str(zip_path), target=str(self._install_path))` before; success log after.
- [MEDIUM] L246-249 — Post-install dispatch (`_post_install_ghidra` / `_post_install_cutter`) is unlogged at the dispatch site. Each post-install path itself logs individual scripts, but the dispatch event is missing.
- [MEDIUM] L420-425 — `process_manager.run_tracked([sys.executable, '-m', 'pip', 'install', 'ghidra_bridge'], ...)` is a subprocess invocation (§2.3). No log before the call. Only the failure branch at L426-L428 raises and the next call at L437-L440 logs a warning on non-zero exit. Fix: `_logger.info("pip_install_started", package="ghidra_bridge")` before L420.
- [MEDIUM] L430-435 — `process_manager.run_tracked([sys.executable, "-m", "ghidra_bridge.install_server", str(ghidra_root)], ...)` subprocess invocation. Same pattern: no entry log. Failure logged at L437. Fix: `_logger.info("ghidra_bridge_server_install_started", ghidra_root=str(ghidra_root))`.
- [MEDIUM] L442-443, L453-454, L481-482 — `scripts_dir.mkdir(...)`, `extensions_dir.mkdir(...)`, `support_dir.mkdir(...)` are file-write operations (§2.3 directory creation). Not logged. The corresponding `write_text` calls *are* logged (e.g., L450, L457, L461), so the mkdir gaps are minor but missing.
- [MEDIUM] L732-740 — `process_manager.run_tracked(["cutter", "--version"], ...)` subprocess invocation (§2.3). No log before the call. Only failure branches log (L742, L744, L746). Fix: `_logger.debug("cutter_version_probe_started")` before L733.
- [MEDIUM] L1056-1066 — `_load_from_config()` reads the tool-settings JSON via `self._config_path.open(...)` then `json.load(...)`. This is an operationally significant config read (§2.3 read-only when "user-provided / configuration loads"). No log on entry, no log on the success path; only the exception path logs at L1065. Fix: `_logger.debug("tool_settings_load_started", tool_id=..., path=...)` and `_logger.debug("tool_settings_load_completed", tool_id=..., found=True)` on success.
- [MEDIUM] L1068-1075 — `_browse_path()` opens a directory-picker and updates the path input. No log of the user's choice. (Workflow event — minor.) LOW would also be acceptable.
- [MEDIUM] L1077-1094 — `_check_status()` spawns a `ToolStatusCheckWorker` thread for the tool with no entry log. The worker logs internally (L594/L596/L599) but the dialog-side handler does not. Fix: `_logger.debug("tool_status_check_requested", tool_id=self._tool_id)`.
- [MEDIUM] L1114-1156 — `_install_tool()` schedules a `ToolInstallWorker` thread with no entry log. Only the worker logs its lifecycle. Fix: `_logger.info("tool_install_requested", tool_id=..., install_path=str(install_path))` before `self._install_worker.start()`.
- [MEDIUM] L1187-1211 — `save_settings()` persists the tool config to disk (`self._config_path.open("w", ...)`, `json.dump(...)`). §2.3 file-write. Only the *exception* path logs at L1206; the successful save path is silent. Fix: `_logger.info("tool_settings_saved", tool_id=..., path=str(self._config_path))` after the `json.dump`.
- [MEDIUM] L1189 — `self._config_path.parent.mkdir(parents=True, exist_ok=True)` is a file-write operation; unlogged.
- [MEDIUM] L1192-1198 — `if self._config_path.exists(): ... open(...) ... json.load(...)` for read before write — operationally significant config read; no log on entry. Fix: `_logger.debug("tool_settings_pre_save_load", tool_id=...)`.
- [MEDIUM] L1414-1419 — `ToolStatusDialog.__init__` calls `_refresh_status()` which kicks off N status-check workers. No info log marking the dialog open or the batch refresh start. Fix: `_logger.info("tool_status_dialog_opened", prefetched=tool_statuses is not None)`.
- [MEDIUM] L1491-1496 — `_on_configure` opens the configure dialog and re-runs status refresh with no logs. Workflow milestone (§2.4 — opens tool config from status dialog). Fix: `_logger.info("tool_configure_from_status_dialog_invoked")`.
- [MEDIUM] L1498-1513 — `_load_settings()` (Status dialog variant) reads `tools.json` with no entry log; only the exception branch logs at L1512. Same pattern as L1056. Fix: add success-path log.
- [MEDIUM] L1568-1595 — `_refresh_status()` spawns multiple status workers in a loop with no aggregate log. Fix: `_logger.info("tool_status_refresh_started", tool_count=len(tools), prefetched=False)`.
- [LOW] L539-543 — `_post_install_cutter()` only logs the verified-path debug at L543 inside an `if`; the path-not-found branch falls through silently (caller `_find_cutter_executable` does log a warning at L561 — adequate).
- [LOW] L863-866 — `_on_accept()` triggers `_save_all_settings()` and accepts the dialog with no log; same for `_on_apply()` at L868-870. The mutations are individually logged by widget `save_settings`, but the dialog-level "accepted" / "applied" event is not. LOW.
- [LOW] L1158-1172 — `_on_install_finished` only logs via the show_info/show_warning UI; no structured log of the success/failure event. LOW because the worker itself logs the install outcome.
- [LOW] L741-746 — `_logger.warning(...)` is used on `TimeoutExpired` and `FileNotFoundError` paths without traceback. Since the exceptions are expected and not re-raised, `.warning` is the right level (consistent with the project's TRY400 documented guidance). Listed for completeness; no fix needed.

(No HIGH findings: every `except` block logs; no stdlib logging; no `print()` runtime calls — the three `print(...)` occurrences at L519/L525/L528 are inside multi-line `write_text` payloads producing a `verify_intellicrack_bridge.py` script and are not runtime output.)

### src/intellicrack/ui/sandbox_config.py — LOC 1043

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L117-134 — `SandboxTestWorker.run()` writes a `.wsb` configuration file to disk via `tempfile.NamedTemporaryFile(mode="w", ..., delete=False)` (file-write, §2.3) and then launches `Popen(["WindowsSandbox.exe", str(self._wsb_file)], ...)` (subprocess, §2.3). Neither operation has a structured-log entry on the successful path; only failure paths log. The user-facing `output` signal carries human-readable messages, but the structured logger is silent. Fix: `_logger.info("sandbox_wsb_written", path=str(self._wsb_file), size=len(wsb_content))` before L129; `_logger.info("windows_sandbox_launched", pid=self._process.pid)` after the `Popen`.
- [MEDIUM] L137-142 — `process_manager.register(...)` registers a tracked sandbox process — operationally significant (§2.4 — registration). Not logged.
- [MEDIUM] L148-153 — `self._process.wait(timeout=10)` and the subsequent `stderr.read()` decision: the success branch where `returncode != 0` only emits via `finished.emit(...)`. Should also `_logger.warning("sandbox_test_nonzero_exit", returncode=..., stderr=...)`.
- [MEDIUM] L195-205 — Finally-block process termination via `ProcessManager.terminate_tree(pid, ...)` (§2.3 subprocess kill) is unlogged on success. Only failure logs at L201-L204. Fix: `_logger.info("sandbox_test_process_terminated", pid=pid)` after termination.
- [MEDIUM] L209 — `self._wsb_file.unlink()` is preceded by `_logger.info("wsb_file_unlinking", ...)` — good. But the unlink happens on every run; the structured info log is appropriate. (Not flagged.)
- [MEDIUM] L249-265 — `stop()` performs `self._process.terminate()` then `.kill()` and unregisters the process. Subprocess control (§2.3) with no entry log; only failure logs at L263. Fix: `_logger.info("sandbox_test_stop_requested", pid=pid)` on entry.
- [MEDIUM] L431-441 — `_check_availability()` runs `process_manager.run_tracked(["powershell", "-Command", ...], ...)` (subprocess + PowerShell, §2.3) with no entry log. The decision branches at L442/L450 log the outcome (good), but the call itself is undocumented. Fix: `_logger.debug("sandbox_availability_check_started")` before L431.
- [MEDIUM] L534-566 — `_load_settings()` reads `sandbox.json` via `self.CONFIG_FILE.open(...)` + `json.load(...)`. §2.3 config read. There's a `_logger.info("sandbox_config_loaded", ...)` at L552 — good — but no log on entry and no log when the file does not exist (L565-566 silently falls back to default).
- [MEDIUM] L568-575 — `_browse_shared_folder()` updates the shared-folder input from a file dialog with no log. Minor — LOW.
- [MEDIUM] L577-624 — `_test_sandbox()` schedules the test worker with only a `QMessageBox.question(...)` confirmation. No log when the user confirms / when the worker is started. §2.4 workflow milestone. Fix: `_logger.info("sandbox_test_started", network_enabled=..., memory_limit_mb=..., shared_folder=...)`.
- [MEDIUM] L626-632 — `_cancel_test()` calls `self._test_worker.stop()` and resets UI. No log. Fix: `_logger.info("sandbox_test_cancelled")`.
- [MEDIUM] L670-677 — `_on_accept` / `_on_apply` trigger `_save_settings` and accept the dialog. The save is logged at L696-700 (good), but the dialog-level accept/apply distinction is not recorded. LOW.
- [MEDIUM] L679-717 — `_save_settings()`: the `self.CONFIG_FILE.open("w", ...)` at L686 is paired with a success log at L696; however, the directory create at L681 (`self.CONFIG_DIR.mkdir(...)`) and the shared-folder create at L692 (`shared_folder.mkdir(...)`) lack pre-call logs. The shared-folder failure path logs `_logger.debug("shared_folder_create_failed", ...)` at L694 — adequate for failure.
- [MEDIUM] L738-766 — `_apply_config_to_manager(new_config)` dispatches into manager-side methods (`update_default_config` or `load_from_file`) which can mutate sandbox manager state — workflow milestone, §2.4. There is a `_logger.debug("sandbox_manager_not_attached", ...)` at L752 (good) and a successful-invocation log at L804 inside `_invoke_backend_method` (good), but no log on entry to `_apply_config_to_manager` itself.
- [MEDIUM] L977-1016 — `_stop_sandbox()` invokes `asyncio.run(self._manager.destroy_all())` or `taskkill` subprocess. Only failure paths log at L984/L1006. The success branches just push UI text via `append_output(...)`. §2.3 subprocess + §2.4 lifecycle transition. Fix: `_logger.info("sandbox_stop_started", method=...)` before each branch; `_logger.info("sandbox_stop_completed", method=..., pid=...)` after.
- [MEDIUM] L1018-1043 — `_terminate_sandbox_by_name()` runs `process_manager.run_tracked(["taskkill", "/F", "/IM", "WindowsSandbox.exe"], ...)` (§2.3 subprocess kill) with no entry log; only failure logs at L1039. Fix: `_logger.info("sandbox_terminate_by_name_started")`.
- [MEDIUM] L949-967 — `set_running(is_running, binary_name, pid)` is a public state-mutator (sandbox lifecycle UI). Workflow milestone per §2.4. No log. Fix: `_logger.info("sandbox_monitor_running_state", is_running=..., binary=..., pid=...)`.
- [LOW] L155-156 — `_logger.warning("sandbox_test_wait_timeout")` after `TimeoutExpired` from `self._process.wait(timeout=10)`. The exception is intentionally swallowed because the sandbox is still considered "running normally" (output.emit at L156). Using `.warning` is correct here (no re-raise, consistent with project TRY400 guidance). No fix.
- [LOW] L569-575 — `_browse_shared_folder()` user picker without log. Reclassified LOW.

(No HIGH findings: every `except` block logs; no stdlib logging; no `print()`; no `contextlib.suppress`. Logger pattern is exemplary throughout the existing exception paths.)

## Aggregate notes

- **Strengths**: All four files use the canonical `_logger = get_logger(__name__)` pattern with structured kwargs throughout. Every `except` clause logs (no silent failures); exception-path logging is consistently `_logger.exception(...)` or `_logger.warning(...)` (with the warning level intentionally chosen on expected/recoverable paths per the project's TRY400 guidance). No f-strings, `%` formatting, or `.format(...)` calls inside log messages anywhere in the shard. No stdlib `logging`, no `print()` runtime calls, no `contextlib.suppress`, no `# noqa` / `# type: ignore` for logging. Event names are uniformly snake_case stable identifiers.
- **Dominant gap — entry/exit on success paths**: The recurring pattern across all four files is that *failure* paths are logged thoroughly (exception traces, error kwargs) while the *successful* execution of the same operation is silent. This violates §2.1 (entry/exit logging) and §2.3 (external calls logged before AND after). The remediation is uniform: add `_logger.info("<event>_started", ...)` before the operation and `_logger.info("<event>_completed", ...)` after.
- **Workflow milestones (§2.4) are under-logged in `app.py`**: the central `MainWindow` glue lacks structured info logs for several high-value lifecycle events — binary loaded (`_load_binary`), session create/load/save (`_on_new_session`, `_on_session_load_requested`, `_on_save_session`), export operations (`_on_export_chat`, `_on_export_analysis`), main-window close (`closeEvent`), and provider/sandbox toggles. Most of these emit a UI status-bar update only.
- **Subprocess calls in `tool_config.py` and `sandbox_config.py`**: `ProcessManager.run_tracked(...)` and `Popen(...)` invocations are present at L420/L430 (tool_config.py) and L129/L431/L994/L1027 (sandbox_config.py) without pre-call structured logs. Even though the inner `ProcessManager` likely logs internally, the call-site context (which tool, which install path, which sandbox configuration) is operational metadata that belongs at the UI layer too.
- **File-write operations are partially covered**: `tool_config.py` does an excellent job of logging individual `write_text` calls in the post-install pipeline (L450/L457/L461/L484/L509). The gap is that the *enclosing operations* (the `_install_tool` orchestration, the `_save_settings` JSON dump in both files) only log on failure.
- **Audit difficulty**: `app.py` is large (3077 lines) and dense with QtSignal/Slot wiring, so I read it in five chunks. Most public slot methods (`_on_*`) perform real work and should log at least at debug level; many do not. `tools.py` is mostly well-instrumented in its bridge/tab construction paths but the `open_in_*` family at L1513-L1610 is a clear gap. `tool_config.py` and `sandbox_config.py` follow consistent patterns and the gaps are localised.
