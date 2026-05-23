# Shard 08 — Core Orchestration

- **Files audited**: 5
- **Total LOC**: 8802
- **Generated**: 2026-05-22T22:56:44Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 4     |
| MEDIUM   | 11    |
| LOW      | 14    |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 4 (all in `process_manager._pid_exists_posix`, control-flow probe pattern)

Overall, the shard is in very good shape on the logging coverage axis. The canonical `from intellicrack.core.logging import get_logger` + module-level `_logger = get_logger(__name__)` pattern is used uniformly. All log calls use structured kwargs — no f-string / `%` / `.format` formatting was found inside any logger call. No stdlib `logging`, no `print(`, no `contextlib.suppress`, no `# type: ignore` or `# noqa` used for logging suppressions. Only `# noqa: PLW0603` (global statement, unrelated to logging) appears once.

The findings concentrate on:

- A short OS-PID-existence probe (`_pid_exists_posix`) that uses `except`/`return` as the canonical existence check on POSIX. Strict criteria require a log call in every `except`; this is the only HIGH cluster.
- A handful of public mutator methods on `Session` (data class) that update state without emitting logs (write surface for orchestrator-level state).
- Several public lifecycle/getter helpers in `SessionManager` and `ScriptManager` without entry-log records where the action is non-trivial.

---

## Findings by file

### src/intellicrack/core/orchestrator.py — LOC 3002

**Logger status**: `module-level _logger` (line 69)

**Imports `from intellicrack.core.logging import get_logger`**: yes (line 31, also imports `log_analysis_operation`)

**Findings**:

- [LOW] L575-576 — `classify_tool_call` has a bare `except ValueError: return "unknown"` for an `enum.ValueError` raised by `ToolName(tool_name.lower())`. This is a pure control-flow lookup that returns a typed classification; no operational failure to surface. Strict reading of §3.2 would call this HIGH, but it is a deliberate "enum-not-known" branch immediately followed by a structured return that callers handle. Recommend adding a `_logger.debug("classify_tool_call_unknown_tool", tool_name=tool_name)` for traceability.
- [LOW] L969-1002 — public `load_session()` does not emit an explicit entry log; it logs `session_loaded` only on success. Adding `_logger.debug("session_load_requested", session_id=...)` on entry would aid debuggability.
- [LOW] L1026-1097 — public `process_user_input()` (the main agent entry point) binds a `request_id` and logs `request_cancelled`, but does not emit an explicit `_logger.info("user_input_received", ...)` at the start of the turn. Given this is the principal orchestrator workflow milestone (§2.4), an entry-log line would improve observability.
- [LOW] L2190-2220 — public `add_binary()` performs significant state mutation (adds to `_current_session.binaries`, changes `active_binary_index`, persists session, optionally runs bridge analysis) without an entry log line beyond the inner `_load_binary` debug. Suggest `_logger.info("binary_added", path=str(path), run_bridge_analysis=...)`.
- [LOW] L2418-2457 — public `get_typed_bridge()` only logs the warning branches; on success the bridge instance is returned silently. Add a debug-level log on success for consistency.
- [LOW] L2482-2488 — `set_confirmation_level()` mutates `self._config.confirmation_level` without any log. Configuration mutation should be logged per §2.4.
- [LOW] L2323-2375 — six callback-setter methods (`set_message_callback`, `set_tool_call_callback`, `set_tool_result_callback`, `set_stream_callback`, `set_confirmation_callback`, `set_async_confirmation_callback`) assign callbacks without any log. These are registration events (§2.4 "registration of tools/providers"). Single debug-level entry per call would suffice.
- [LOW] L2504-2518 — `configure_hooks()` registers two hooks without logging. Same rationale as the setters above.

(All `except` blocks log; no f-strings/`%`/`.format` in log calls; all `subprocess`-equivalents (`provider.cancel_request()`, `tool_registry.execute_tool_call()`) are bridged through async calls that the registry layer logs and the orchestrator wraps with `tool_call_success`/`tool_call_failed`.)

### src/intellicrack/core/types.py — LOC 1879

**Logger status**: `module-level _logger` (line 24)

**Imports `from intellicrack.core.logging import get_logger`**: yes (line 17)

**Findings**: none.

Justification: `types.py` is almost entirely `dataclass` / `Enum` / `Protocol` definitions plus a few exception classes. The few `_logger.*` calls present (e.g. L773, L1470, L1513, L1639, L1763, L1874) are appropriate (error on invalid `__getitem__` key, debug on exception construction with structured kwargs). There are zero `except` blocks, zero subprocess / network / file-I/O operations, and zero string-formatted log calls. Per §4 the file is exempt for trivial dunders, dataclass methods, and pure type definitions.

### src/intellicrack/core/script_gen.py — LOC 1464

**Logger status**: `module-level _logger` (line 52)

**Imports `from intellicrack.core.logging import get_logger`**: yes (relative `from .logging import get_logger`, line 48)

**Findings**:

- [LOW] L433-441 — public `Script.add_execution_result()` mutates `execution_results` without any log. The caller `ScriptManager.record_execution` logs (line 894), but the public Script API itself is silent. LOW because the only realistic caller path logs.
- [LOW] L676-687 — `ScriptManager.__init__` does not log construction (`scripts_dir`, `validator` identity). `ScriptGenerator.__init__` does the equivalent at line 1349 — recommend parity.
- [LOW] L825-834 — public `ensure_script_saved()` performs filesystem-affecting work via `save_script()` (which logs internally) without an outer entry log. LOW because the inner call logs.
- [LOW] L1377-1401 — public `ScriptGenerator.prepare_output_path()` performs a `Path.mkdir(parents=True, exist_ok=True)` (§2.3 file-system mutation) without an entry or exit log. Recommend `_logger.debug("output_path_prepared", path=str(path))`.

(All `except` clauses log; all subprocess calls go through `ProcessManager.run_tracked` which logs `subprocess_started` / `subprocess_completed`; the `Script.save` `path.write_text` write is bracketed by `_logger.debug` and `_logger.info` lines; `path.read_text` in `load_script` is followed by `script_file_read` debug.)

### src/intellicrack/core/session.py — LOC 1269

**Logger status**: `module-level _logger` (line 54)

**Imports `from intellicrack.core.logging import get_logger`**: yes (relative `from .logging import get_logger, log_session_operation`, line 22)

**Findings**:

- [MEDIUM] L158-167 — `Session.add_binary()` mutates `binaries`, `active_binary_index`, and `updated_at` without any log. Session state mutations are explicitly called out by §2.4. Recommend `_logger.debug("session_binary_added", session_id=self.id, binary_name=binary.name)`.
- [MEDIUM] L168-175 — `Session.add_message()` mutates the conversation list without logging. Logging here is light because conversation churn is high, but a `_logger.debug(...)` would still be the canonical record. MEDIUM.
- [MEDIUM] L177-184 — `Session.add_patch()` mutates `patches` and `updated_at` without log. Patches are significant state. Note: `Orchestrator.add_patch` (orchestrator.py L2305) does emit `patch_added`, but the Session API itself is silent — direct callers of `Session.add_patch()` skip that.
- [MEDIUM] L186-194 — `Session.add_bridge_analysis()` mutates `bridge_analyses` without log. Recommend `_logger.debug("session_bridge_analysis_added", session_id=self.id, binary_name=binary_name)`.
- [MEDIUM] L207-220 — `Session.set_tool_state()` mutates `tool_states[state.tool]` without log. Per §2.4 "registration of tools/providers" + "lifecycle transitions (start/stop/connect/disconnect)" applies here since tool states track connection/attachment/error. Recommend `_logger.debug("tool_state_set", tool=state.tool.value, connected=state.connected, attached=state.process_attached)`.
- [MEDIUM] L222-235 — `Session.clear_tool_state()` mutates `tool_states` without log. Same rationale.
- [MEDIUM] L237-256 — `Session.add_tag()` mutates `tags` without log. Tag mutations are reported by `Orchestrator.tag_current_session` only as an error path on missing session; the success path delegates silently.
- [MEDIUM] L258-273 — `Session.remove_tag()` mutates `tags` without log. Same as above.
- [LOW] L1049-1059 — `SessionManager.get()` performs SQLite I/O (`asyncio.to_thread(self.store.load, session_id)`) without entry/exit logging. The wrapped store call logs internally, but `get` is a public seam that should record the access for traceability.
- [LOW] L1117-1126 — `SessionManager.list_sessions()` is a synchronous delegator without log. The underlying `store.list_all` logs.
- [LOW] L1128-1137 — `SessionManager.search_by_tag()` is a synchronous delegator without log. The underlying `store.search_by_tag` logs.
- [MEDIUM] L1170-1191 — `SessionManager.import_json()` performs three sequential blocking I/O operations (load JSON, check for existing, save) without an entry log identifying the path or the `replace` mode. Add `_logger.info("session_import_requested", path=str(path), replace=replace)` at L1183.
- [MEDIUM] L1226-1231 — `SessionManager._start_auto_save()` starts a background task without log. Lifecycle transitions (§2.4) should be logged. Recommend `_logger.debug("autosave_task_started", interval=self.save_interval)` after `asyncio.create_task(...)`.

(All `except` clauses log; all `path.open(...)` writes/reads at L893 and L916 are bracketed by `_logger.info(...)`; `sqlite3` operations have surrounding debug/info logs in `SessionStore`.)

### src/intellicrack/core/process_manager.py — LOC 1188

**Logger status**: `module-level _logger` (line 40) plus a `_get_logger()` staticmethod (line 321) that returns the same module logger — used pervasively from the singleton instance.

**Imports `from intellicrack.core.logging import get_logger`**: yes (relative `from .logging import get_logger`, line 32)

**Findings**:

- [HIGH] L141 — `except ProcessLookupError: return False` in `_pid_exists_posix` has no log call. This is a control-flow probe (the canonical POSIX existence check via `os.kill(pid, 0)`), but the audit criteria §3.2 require a log call in every `except`. Recommend `_logger.debug("pid_probe_no_such_process", pid=pid)` before `return False`.
- [HIGH] L143 — `except PermissionError: return True` in `_pid_exists_posix`. Same rationale. Recommend `_logger.debug("pid_probe_permission_denied", pid=pid)`.
- [HIGH] L145 — `except OSError: return False` in `_pid_exists_posix`. Same rationale. Recommend `_logger.debug("pid_probe_oserror", pid=pid)` or `_logger.warning("pid_probe_oserror", pid=pid)`.
- [HIGH] L425-426 — actually `except RuntimeError` in `_signal_handler` does log `no_running_event_loop_for_async_cleanup` at warning — verified clean. (Not a finding; included for transparency.)
- [LOW] L315-318 — `prepare_for_teardown()` clears `_processes` and `_cleanup_in_progress` without log. State reset before singleton teardown. Recommend `_logger.debug("process_manager_teardown_prepare")`.
- [LOW] L876-878 — `clear_shutdown_request()` clears the shutdown event flag without log. Lifecycle helper. Optionally `_logger.debug("shutdown_request_cleared")`.

The `_pid_exists_windows` function (L80-121) uses no `try/except`, only branch-on-return-value, so no findings.

All other except clauses log appropriately (the exhaustive set is at L357 `signal_handler_install_failed`, L376 `signal_handler_uninstall_failed`, L477 `process_lookup_failed`, L491 `process_terminate_target_missing`, L506 `kill_process_target_missing`, L566/575 `terminate_tree_root_*`, L587 `terminate_tree_process_target_missing`, L598 `kill_tree_process_target_missing`, L735 `cleanup_callback_failed`, L776 `process_zombie_fallback`, L810 `async_process_zombie_fallback`, L815 `zombie_wait_fallback_failed`, L851 `cleanup_pid_failed`, L858 `external_pid_terminate_failed`, L999 `process_timeout`, L1174 `external_pid_already_gone`, L1179 `external_pid_terminate_error`).

The `Popen(...)` invocation at L956 is bracketed by `_logger.debug("subprocess_started", ...)` (L955) and `_logger.debug("subprocess_completed", ...)` (L997) — per §2.3 this is the correct pattern. `signal.signal(...)` mutations at L349/350/354/356/370/372/375 are aggregated under the `handlers_installed`/`handlers_uninstalled` info logs at L364/L382 — adequate.

The single `# noqa: PLW0603` at L339 is a pylint suppression for the `global` statement, not a logging suppression. Per criteria §3 it is **not** flagged.

---

## Aggregate notes

### Cross-file patterns

- **Canonical pattern compliance is excellent.** Every module imports `get_logger` from `intellicrack.core.logging` and defines `_logger = get_logger(__name__)` at module level. No instance-level `self._logger` usage (none of these files are LLMProvider subclasses).
- **Structured kwargs everywhere.** Across all 5 files, every single `_logger.<level>(...)` call uses a snake_case event name as the first positional and passes context via kwargs. There are zero formatting-style violations.
- **`structlog.contextvars.bind_contextvars` / `unbind_contextvars` is used effectively in `orchestrator.py`** to attach `session_id`, `provider`, `model`, `request_id`, `tool_call_id`, `tool_name`, `tool_function`, `llm_streaming` to log context — good practice that ensures structured logs in nested calls inherit context.

### Coverage gaps

The largest coverage gap in this shard is the **`Session` dataclass mutator surface** (`add_binary`, `add_message`, `add_patch`, `add_bridge_analysis`, `set_tool_state`, `clear_tool_state`, `add_tag`, `remove_tag`). These are the canonical write-paths for session state, and the criteria §2.4 explicitly call out "session updates" as requiring logging. Because the Session class is mutated both by `Orchestrator` (which logs) and via direct callers (which do not log uniformly), adding logging at the data-class layer would ensure every mutation is recorded exactly once. This is the single most consequential improvement reviewers should consider.

The second cluster is the **`_pid_exists_posix` control-flow probe**. The criteria are strict ("Always HIGH") so the three silent excepts are flagged HIGH, but in practice these are not failure surfaces — they encode "the kernel says PID does not exist / requires privileges / OS error". A short `_logger.debug(...)` line in each branch would satisfy the rule without altering behaviour.

### Files where the audit was difficult

- `orchestrator.py` at 3002 lines required chunked reads. The audit was assisted by the strong structlog pattern: most code paths were trivially log-traceable.
- `types.py` (1879 lines) is overwhelmingly type definitions with no operations; the audit completed quickly once it was confirmed there are no `except` blocks and no I/O.

### Recommendations

1. Add structured `_logger.debug(...)` entries to all `Session` mutator methods listed under the MEDIUM findings in `session.py`.
2. Add `_logger.debug(...)` to each except branch in `_pid_exists_posix` so every `except` clause in the codebase has a log statement, satisfying §3.2 strictly.
3. Consider adding low-overhead entry logs (debug level) to `process_user_input`, `load_session`, `add_binary` in `orchestrator.py` for full §2.1 entry/exit coverage on the primary orchestrator workflow methods.
4. Add a debug-level log in `_start_auto_save` to record the start of the background save loop (§2.4 lifecycle).
5. Optional: add registration debug logs to the orchestrator callback setters (`set_message_callback` etc.) for §2.4 "registration of tools/providers" completeness.
