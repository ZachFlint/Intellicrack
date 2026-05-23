# Shard 16 — provider config + process panel

- **Files audited**: 11
- **Total LOC**: 7855
- **Generated**: 2026-05-22T00:00:00Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 6     |
| MEDIUM   | 26    |
| LOW      | 13    |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 6 (silent ValueError parses + ToolError swallows)

## Findings by file

### src/intellicrack/ui/provider_config.py — LOC 2912

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L257-269 — `_load_env_file_vars` does `open(env_path, "r")` on three .env candidate locations; only the `OSError` branch logs. No entry log before each `open(...)` attempt and no successful-load log when a .env is parsed. Config load is operationally significant per §2.4 — add `_logger.debug("env_file_scanning", path=str(env_path))` before open and `_logger.info("env_file_loaded", path=str(env_path), keys=len(self._env_file_vars))` on success.
- [MEDIUM] L296-303 — `detect_source()` opens the providers.json config (`self._config_path.open("r")`) for read. Only failure path logs; no entry log noting config probe. Operationally significant config read per §2.3 final paragraph.
- [MEDIUM] L368-389 — `_test_provider_connection` is the dispatcher for all HTTP probes (anthropic/openai/google/ollama/openrouter/huggingface/grok). It performs no entry log identifying which provider's probe is starting. Network calls require entry+exit logs per §2.3; the `_test_*` helpers below it log only failures.
- [MEDIUM] L402-415 — `_test_anthropic` performs `httpx.Client.get` to `api.anthropic.com/v1/models`. Success branch (lines 411-415) has no log; only `ConnectError` / HTTPError branches do. Network call needs surrounding intent + outcome log per §2.3.
- [MEDIUM] L433-443 — `_test_openai` same pattern: no entry log, no success log around `httpx` GET.
- [MEDIUM] L460-470 — `_test_google` same: GET to `generativelanguage.googleapis.com` with no entry/success log.
- [MEDIUM] L488-493 — `_test_ollama` GET to `${base_url}/api/tags` with no entry/success log.
- [MEDIUM] L511-521 — `_test_openrouter` GET to `${base_url}/models` with no entry/success log.
- [MEDIUM] L538-549 — `_test_huggingface` GET to `huggingface.co/api/models` with no entry/success log.
- [MEDIUM] L601-612 — `_test_grok` HTTP fallback GET to `api.x.ai/v1/models` with no entry/success log.
- [MEDIUM] L719-748 — `_fetch_anthropic_models` paginated httpx GETs in a `for _ in range(10)` loop. No log per page, no overall entry log, no success summary log; only the catch-all logs at debug.
- [MEDIUM] L755-795 — `_fetch_openai_models` httpx GET with no entry/success log (only error logged at L794).
- [MEDIUM] L800-823 — `_fetch_google_models` httpx GET with no entry/success log.
- [MEDIUM] L826-845 — `_fetch_ollama_models` httpx GET with no entry/success log.
- [MEDIUM] L848-871 — `_fetch_openrouter_models` httpx GET with no entry/success log.
- [MEDIUM] L886-908 — `_fetch_huggingface_models` httpx GET with no entry/success log.
- [MEDIUM] L962-977 — `_fetch_grok_models` HTTP fallback GET with no entry/success log.
- [LOW] L1043-1047 — `_logger.info("credential_overview", ...)` is fine but emits before the credential store load below; consider also logging the count of credentials retrieved from the store after `_load_store_credentials` completes.
- [LOW] L1062-1063 — `except` block logs at `debug` for an `(RuntimeError, OSError, ValueError)` triple covering both env loader and credential store failures — `_logger.warning` would be more appropriate so the operator sees the credential-overview load skip.
- [MEDIUM] L1407-1427 — `refresh_credentials()` is a public method (button-bound) that triggers env reload + credential overview re-load. The catch-all logs `credential_refresh_failed` at debug only. Use `_logger.warning(... error=str(e))` per §3 wrong-level + missing context kwarg.
- [LOW] L1429-1436 — `create_env_template()`: failure logged at `debug` (`env_template_creation_failed`); should be `warning` since a user clicked the button and may need to see the failure surface.
- [LOW] L1438-1446 — `migrate_credentials()`: failure logged at `debug`; should be `warning` (user-initiated action).
- [MEDIUM] L1500-1512 — `start_oauth_flow` runs `manager.run_authorization_flow(oauth_config)` and `manager.to_provider_credentials(...)`. No entry log identifying the OAuth start. Network/auth flow start is a significant state transition per §2.4.
- [MEDIUM] L2577-2602 — `_persist_api_key_to_env` writes credential to `.env` file via `loader.save_to_env_file(...)`. No entry log and no success log — this is a credential-write state mutation per §2.4 and a file write per §2.3. Only error path logs.
- [MEDIUM] L2537-2575 — `save_settings` writes `providers.json` via `self._config_path.open("w")` (L2558). Entry log is missing; success log exists (L2560 `provider_settings_saved`) — add entry log noting save initiation.
- [MEDIUM] L2461-2476 — `_on_connection_tested` does `QTimer.singleShot(500, self._auto_refresh_models)` on success which triggers further bridge calls; this control transition is not logged.
- [LOW] L1958-1961 — `_setup_xpu_settings` hides the XPU group when unavailable; `xpu_unavailable_ui_hidden` is logged at debug. Consider info-level since this is a meaningful UI state milestone.
- [LOW] L1245-1246, L1266-1267, L1285-1286 — multiple `_logger.debug(..., exc_info=True)` calls for `(RuntimeError, AttributeError, ValueError)` blocks; these are caught silently from user perspective. Debug-only logging makes them invisible in normal operation; bump to `warning` where the lookup feeds visible UI.

### src/intellicrack/ui/dialogs/splash_screen.py — LOC 934

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L494-527 — public `set_progress(value, message)` is called repeatedly during startup (one of the most important workflow surfaces per §2.4 — GUI workflow milestones). Each call moves the splash through `_STAGE_LABELS` (Creds → Providers → … → UI). No log emitted per stage transition. Consider logging at info level when a new stage becomes ACTIVE/COMPLETE inside `_update_stage_states` so the startup pipeline is traceable post-mortem.
- [LOW] L485-492 — `mark_stage_failed(stage_index)` is the panic path during startup; no log. A failed startup stage is exactly the kind of event that needs structured logging — `_logger.error("splash_stage_failed", stage_index=stage_index, stage=_STAGE_LABELS[stage_index])`.
- [LOW] L425-437 — `show_animated()` and L439-453 `finish_animated(window)` are GUI lifecycle milestones (splash open/close). Splash init logs at L207; consider matching info-level logs at show/finish.
- [LOW] L455-460 — `_on_fade_out_finished` calls `self._finish_target.show()` then `self.close()`. Mainwindow surface transition — not logged.
- [LOW] L237-239 — `except FileNotFoundError: _logger.warning("splash_image_not_found")` does not include the path; the variable `splash_path` was constructed on L227 and is in scope. Add `path=str(splash_path)` kwarg.

### src/intellicrack/ui/dialogs/**init**.py — LOC 17

**Logger status**: not applicable (pure re-export)

**Imports `from intellicrack.core.logging import get_logger`**: no (not needed)

**Findings**: none — file is a pure re-export of `SplashScreen`; exempt per §4.

### src/intellicrack/ui/panels/process_panel/**init**.py — LOC 15

**Logger status**: not applicable (pure re-export)

**Imports `from intellicrack.core.logging import get_logger`**: no (not needed)

**Findings**: none — pure re-export of `ProcessPanel`; exempt per §4.

### src/intellicrack/ui/panels/process_panel/_base.py — LOC 375

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L256-260 — `_refresh_arch_label`'s inner `_detect` coroutine has `except ToolError: return None` with no log. This is a silent bridge failure swallow: `bridge.detect_architecture(pid)` can fail and the user simply sees "Arch: Unknown" with no diagnostic in the log. Required: `_logger.warning("arch_detection_failed", pid=pid, error=str(...))`.
- [HIGH] L276-280 — `_refresh_privilege_label`'s `_fetch_privs` has `except ToolError: return None` with no log; same silent bridge failure issue. Required: `_logger.warning("privilege_fetch_failed", pid=pid, ...)`.
- [MEDIUM] L245-266 — `_refresh_arch_label`: bridge call `bridge.detect_architecture(pid)` has no entry log noting the lookup is happening. §2.3 bridge invocation requires logging.
- [MEDIUM] L268-295 — `_refresh_privilege_label`: bridge call `bridge.get_token_privileges(pid)` has no entry log.
- [LOW] L355-364 — `start_tool()` is public and a lifecycle transition (start). Currently emits `tool_started` signal but no log. Per §2.4, lifecycle transitions need logging.
- [LOW] L366-375 — `stop_tool()` is public lifecycle transition; calls `_cleanup` and emits `tool_closed` but no log.
- [LOW] L86-103 — `set_bridge` logs at L103 — fine — but the prior `remove_privileges_changed_callback` call at L93 happens before logging; if it errors silently it's gone. Tiny risk.

### src/intellicrack/ui/panels/process_panel/_memory_tab.py — LOC 703

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L414-449 — `_refresh_regions` invokes `self._bridge.get_memory_map(resolve_names=True)`. No entry log identifying the bridge call. Error path at L446 logs. §2.3 bridge invocation needs intent log.
- [MEDIUM] L451-478 — `_on_read` invokes `self._bridge.read_memory(addr, size)` — no entry log noting addr/size. Error path at L474 logs but uses an f-string-free structured form (good).
- [MEDIUM] L508-547 — `_on_write` invokes `self._bridge.write_memory(addr, data)` — significant state mutation (modifying remote process memory) per §2.4. No entry log noting write intent, no success log noting bytes written. Error logged.
- [MEDIUM] L549-574 — `_on_allocate` invokes `self._bridge.allocate(size, prot)` (process memory allocation). No entry/success log. Only error path logs at L571.
- [MEDIUM] L576-621 — `_on_free` invokes `self._bridge.free(addr)`. Significant mutation per §2.4. No entry/success log; only error and the parse-failure paths log.
- [MEDIUM] L623-664 — `_on_protect` invokes `self._bridge.protect(addr, size, prot)` (memory protection change — significant). No entry/success log; only error path.
- [MEDIUM] L666-703 — `_on_search` invokes `self._bridge.search_pattern(pattern)`. No entry log of search intent + pattern.
- [LOW] L693-696 — `except Exception as exc:` inside `_on_search._on_success` catches broadly, logs and re-raises. Per Ruff TRY400 + project memory the warn pattern is acceptable for re-raise, but the broad `Exception` here could be narrowed.

### src/intellicrack/ui/panels/process_panel/_modules_tab.py — LOC 482

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L405-406 — `_refresh_handles._on_error(exc)`: shows QMessageBox but no log call. Silent bridge failure on `get_handles(...)`. Fix: `_logger.warning("handles_enumerate_failed", error=str(exc))` before the QMessageBox.
- [HIGH] L431-432 — `_refresh_heaps._on_error(exc)`: silent bridge failure on `get_heaps(...)`. Same fix pattern.
- [HIGH] L455-456 — `_refresh_com._on_error(exc)`: silent bridge failure on `enumerate_com_servers(...)`. Same fix pattern.
- [HIGH] L479-480 — `_refresh_dotnet._on_error(exc)`: silent bridge failure on `detect_dotnet(...)`. Same fix pattern.
- [MEDIUM] L329 — `_logger.warning("Module enumeration failed: %s", exc)`: uses `%s` printf formatting + non-event-name message. Should be `_logger.warning("module_enumeration_failed", error=str(exc))` per §1 structured kwargs.
- [MEDIUM] L359-371 — `_on_inject._on_success` logs row to UI but DLL injection success is not logged — this is a significant state mutation per §2.4. Add `_logger.info("dll_injected", path=path, pid=self._attached_pid)`.
- [MEDIUM] L366-371 — `_on_inject._on_error` records to UI table but no log. Add `_logger.warning("dll_inject_failed", path=path, pid=self._attached_pid, error=str(exc))`.
- [MEDIUM] L297-332 — `_refresh_modules` invokes `self._bridge.get_modules(...)` with no entry log.
- [MEDIUM] L334-338 — `_on_browse_dll` opens a file dialog but the selected path (the DLL about to be injected) is not logged. Selection of an injection target is operationally significant.
- [MEDIUM] L340-373 — `_on_inject` invokes `self._bridge.inject_dll(path)` (DLL injection — high-impact action). No entry log noting the inject is being attempted with `path` and `pid`.
- [MEDIUM] L375-408 — `_refresh_handles` invokes `self._bridge.get_handles(...)` with no entry log.
- [MEDIUM] L410-434 — `_refresh_heaps` invokes `self._bridge.get_heaps(...)` with no entry log.
- [MEDIUM] L436-458 — `_refresh_com` invokes `self._bridge.enumerate_com_servers(...)` with no entry log.
- [MEDIUM] L460-482 — `_refresh_dotnet` invokes `self._bridge.detect_dotnet(...)` with no entry log.

### src/intellicrack/ui/panels/process_panel/_process_tab.py — LOC 761

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L324-360 — `_on_refresh` invokes `self._bridge.list_processes_detailed(current_filter)`. Error path logs at L351; no entry log (good debug entry would be nice given the auto-refresh timer fires every 3s).
- [MEDIUM] L459-486 — `_on_attach`: bridge call `self._bridge.open_process(pid)`. Success logs `process_attached` at L473 — good. Missing entry log of the attach attempt before bridge call.
- [MEDIUM] L488-501 — `_on_detach`: bridge call `self._bridge.close()`. No entry log; no success log (just emits signal). Detach is a state mutation per §2.4 and should be logged on both success and failure (error logged at L498 — good).
- [MEDIUM] L503-513 — `_on_suspend`: bridge call `self._bridge.suspend(pid)`. Significant state change (process suspension). No entry/success log; only error logged at L510.
- [MEDIUM] L515-525 — `_on_resume`: bridge call `self._bridge.resume(pid)`. Same pattern — no entry/success log.
- [MEDIUM] L527-557 — `_on_terminate`: bridge call `self._bridge.terminate(pid)`. Success logs at L545 ("process_terminated"). Missing entry log noting the termination attempt before the bridge call.
- [MEDIUM] L559-596 — `_on_inject_dll`: bridge call `self._bridge.inject_dll(path)`. Success logs at L589, error logs at L593 — good. Missing entry log around the bridge call.
- [MEDIUM] L598-642 — `_load_process_info`: two bridge calls `get_process_info(pid)` and `get_environment(pid)`. Both error paths log; neither has an entry log.

### src/intellicrack/ui/panels/process_panel/_system_tab.py — LOC 928

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L905-907 — `_on_raw_query._on_success` has `try: data = bytes.fromhex(result) except ValueError: self._raw_output.setPlainText(result); return`. Silent except: parse failure not logged. The text *is* surfaced to UI, but operational visibility is lost. Add `_logger.debug("raw_query_hex_parse_failed", length=len(result))` or similar.
- [MEDIUM] L512-548 — `_refresh_privileges` invokes `self._bridge.get_token_privileges(pid)`. Error path uses `_show_error` (logs at L138) — good. No entry log of the operation.
- [MEDIUM] L550-566 — `_on_enable_debug` invokes `self._bridge.adjust_token_privilege("SeDebugPrivilege", enable=True, pid=pid)`. This is a privileged operation — significant state mutation per §2.4. Error path logs via `_show_error`. NO success log — enabling SeDebugPrivilege successfully is highly significant and should be logged at info level.
- [MEDIUM] L568-596 — `_refresh_windows` `get_windows(pid)`: no entry/success log.
- [MEDIUM] L598-630 — `_refresh_services` `list_services(pid)`: no entry/success log.
- [MEDIUM] L632-657 — `_on_read_peb` `read_peb(pid)`: no entry/success log.
- [MEDIUM] L659-680 — `_on_read_teb` `read_teb(tid)`: no entry/success log.
- [MEDIUM] L682-703 — `_on_pipe_connect` `pipe_connect(name)`: connection to named pipe is operationally significant per §2.3 (socket-like external resource). Error logged via `_show_error`. NO success log of the connect with the resulting handle.
- [MEDIUM] L705-740 — `_on_pipe_close` `pipe_close(handle)`: closing pipe handle; success path removes from table but no log. Error logged at L737.
- [MEDIUM] L742-774 — `_refresh_mitigations` `get_mitigation_policies(pid)`: no entry/success log.
- [MEDIUM] L776-797 — `_on_reg_read` `reg_read_value(key, name)`: registry read per §2.3 must be logged. No entry/success log; only error via `_show_error`.
- [MEDIUM] L799-818 — `_on_reg_enum_keys` `reg_enum_keys(key)`: registry enumeration. No entry/success log.
- [MEDIUM] L820-839 — `_on_reg_enum_values` `reg_enum_values(key)`: registry enumeration. No entry/success log.
- [MEDIUM] L841-865 — `_on_gui_resources` `get_gui_resources(pid)`: no entry/success log.
- [MEDIUM] L867-891 — `_on_job_info` `get_job_info(pid)`: no entry/success log.
- [MEDIUM] L893-928 — `_on_raw_query` `query_system_info(info_class, buf_size)`: raw NT call to attached process. No entry/success log.
- [LOW] L137-139 — `_show_error` uses `exc=message` kwarg which is acceptable, but consider standardising the kwarg name across the codebase (`error` is the dominant convention used elsewhere in this shard and project memory).

### src/intellicrack/ui/panels/process_panel/_threads_tab.py — LOC 653

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L482-485 — `_on_reg_cell_changed`: `except ValueError: return` is a silent except with no log. User editing a register value with bad input gets no diagnostic. Required: `_logger.debug("register_cell_parse_failed", raw=raw, row=row, col=col)` — debug is acceptable since this is a normal interactive flow but the swallow must be visible.
- [HIGH] L405-409 — `_refresh_threads` calls `run_bridge_coroutine_async(self._bridge.get_threads(self._attached_pid), _on_success, None, self)`. `None` as `on_error` means bridge errors are only logged by `async_bridge.py`'s generic `async_bridge_worker_failed` — caller context (the thread refresh) is lost. Add an `_on_error` that logs `_logger.warning("threads_refresh_failed", pid=..., error=...)`.
- [MEDIUM] L428-432 — `_on_suspend_thread` calls `self._bridge.suspend(self._attached_pid)` with `None, None` callbacks — no success log, no error log with operation context. Suspending an entire process is a significant state mutation per §2.4.
- [MEDIUM] L434-438 — `_on_resume_thread` same as above — `None, None` callbacks. Resuming an entire process — significant state change with no log.
- [MEDIUM] L440-461 — `_refresh_registers` calls `self._bridge.get_thread_context(tid)` with `None` error handler. Add operation-context error logging.
- [MEDIUM] L504-540 — `_on_write_registers` calls `self._bridge.set_thread_context(tid, regs)` with `None, None` callbacks. Writing thread context is a high-impact state mutation per §2.4 — should have entry log, success log, and contextful error log. Currently only the per-row parse failure logs (L532-537).
- [MEDIUM] L542-573 — `_on_stack_walk` calls `self._bridge.stack_walk(tid)` with `None` error handler.
- [MEDIUM] L575-603 — `_on_seh_enumerate` calls `self._bridge.get_seh_chain(tid)` with `None` error handler.
- [MEDIUM] L605-625 — `_on_fiber` calls `self._bridge.get_fiber_data(tid)` with `None` error handler.
- [MEDIUM] L627-653 — `_on_tls` calls `self._bridge.get_tls_values(tid)` with `None` error handler.
- [MEDIUM] L378-409 — `_refresh_threads` itself has no entry log; auto-refresh timer fires every 3s when enabled — debug entry log is appropriate.
- [LOW] L424-426 — `cleanup` is a public lifecycle method; no log.

### src/intellicrack/ui/panels/process_panel/_workers.py — LOC 75

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**: none — `run()` catches `(RuntimeError, ValueError, KeyError)` at L70 and logs via `_logger.warning("tracked_refresh_failed", error=str(exc))`; emits signal. Clean.

## Aggregate notes

- **Pervasive pattern across process_panel tabs**: bridge invocations have rich UI scaffolding for results but most lack any entry-side log of the intent. The strict-mode criterion (§2.3) requires log around external/bridge calls; only the error path is consistently logged via `_show_error` / `_on_error` callbacks. This shard contains roughly 30 such bridge-invocation sites; consider standardising a `_log_bridge_call(event, **kwargs)` helper used uniformly across tabs.
- **`run_bridge_coroutine_async(..., None, None, self)` is a recurring anti-pattern in `_threads_tab.py`**: when both callbacks are None, the only log visibility comes from a generic event name (`async_bridge_worker_failed`) in `async_bridge.py` — caller context (which bridge operation, on which PID/TID) is lost. Either always supply a contextful `_on_error`, or extend `run_bridge_coroutine_async` to take an `operation_name` string for default logging.
- **Modules tab `_refresh_*` error handlers (handles/heaps/com/dotnet)** all use a "QMessageBox without log" pattern that is inconsistent with the rest of the panel (where `_on_error` typically logs first then surfaces QMessageBox). Cat-3 #1 fix in commit `6bab435e` introduced QMessageBox + logger pattern for the memory tab; the same uplift hasn't been applied to modules tab's four enumerators.
- **Provider config `_test_*` and `_fetch_*` HTTP probes**: all log only on failure. Per §2.3, network calls must have log statements before AND after. With 7+ providers each having a test + a fetch, that's 14+ unlogged successful network round-trips. Recommend a `_log_http_probe(provider, method, url)` helper used consistently.
- **`_persist_api_key_to_env` (provider_config.py L2577)** is a credential-write to the filesystem — must log on success per §2.4 (credential read/write). Currently only `OSError` failure logs.
- **OAuth start/revoke flow** in provider_config.py L1480-1531 lacks entry logs; only success and exception logs exist.
- **No `print(...)` runtime output anywhere in the shard.** No stdlib `logging` use. No `contextlib.suppress`. No `# noqa` / `# type: ignore` for logging issues. The canonical `_logger = get_logger(__name__)` pattern is correctly applied in every executable file. This is good baseline hygiene; the shard's gaps are coverage-side (missing logs), not correctness-side (wrong logger / wrong pattern).
- **Splash screen pipeline transitions** are an opportunity: the splash explicitly models 8 startup stages (Creds → Providers → Tools → Session → Engine → Scripts → Models → UI). Logging each stage's ACTIVE/COMPLETE transition at info would give a structured startup trace, which is exactly the orchestration-context Intellicrack benefits from per its scope statement in CLAUDE.md.
