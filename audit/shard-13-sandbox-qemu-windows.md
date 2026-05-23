# Shard 13 — sandbox infrastructure (qemu, windows, manager, log helpers)

- **Files audited**: 7
- **Total LOC**: 8036
- **Generated**: 2026-05-22T00:00:00Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 6     |
| MEDIUM   | 50    |
| LOW      | 6     |

- Files missing module-level `_logger`: 1 (`_log_helpers.py` — exempt, pure helpers; `_tld_data.py` — exempt, pure data; `__init__.py` — exempt, re-exports only)
- Files using stdlib `logging`: 0 (the stdlib `logging` import at `qemu.py:2154` and `logging.getLogger` at `qemu.py:2180` are inside a Python source string embedded in the module that is written to disk and executed inside the QEMU guest VM — guest agent code, not Intellicrack runtime — see Aggregate notes)
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 4 silent-except sites across `qemu.py` and `windows.py` (see findings)

## Findings by file

### src/intellicrack/sandbox/**init**.py — LOC 86

**Logger status**: `missing` (exempt — pure re-export `__init__.py`)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. File contains only re-exports of `SandboxBase`, `WindowsSandbox`, `QEMUSandbox`, dataclasses, and validators. No executable operations.

---

### src/intellicrack/sandbox/_tld_data.py — LOC 476

**Logger status**: `missing` (exempt — pure data file per §4)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. File defines a single `KNOWN_TLDS: frozenset[str]` constant. No operations.

---

### src/intellicrack/sandbox/_log_helpers.py — LOC 198

**Logger status**: `missing` (defensible — pure string/object normalisation helpers, no operations per §4)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. Functions (`split_addr_port`, `coerce_protocol`, `infer_direction`, `safe_int`, `safe_float`, `format_yara_match`) are all pure transformations over strings or `yara.Match` attributes with `getattr(..., default)` fallbacks. No subprocess, network, file I/O, or registry calls. `format_yara_match` silently drops malformed YARA match string entries shorter than `YARA_MATCH_MIN_FIELDS` (line 171), which is the documented intentional behaviour and does not warrant a log.

---

### src/intellicrack/sandbox/_log_parsers.py — LOC 549

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes (L32)

**Findings**:

- [LOW] L114-116 — `except OSError as err: _logger.warning("log_read_failed", ...)` correctly logs the read failure. The file read at L108-113 is operationally significant (consumed by the sandbox report builders) but has no entry-time log; only the failure path logs. Adding a `_logger.debug("reading_sandbox_log", log=name, shared_folder=str(shared_folder))` before the read would aid traceability when multiple monitor logs are merged. Note: this is the only file-read site in the module — the parser helpers themselves are pure string→dataclass transforms that don't need entry/exit logs.

All other parser functions (`parse_file_log`, `parse_registry_log`, `parse_network_log`, `parse_process_log`, `parse_service_log`, `parse_kernel_object_log`, `parse_dll_log`, `parse_injection_log`, `parse_resource_log`, `parse_clipboard_log`, `parse_api_trace_log`) are pure transforms over the lines returned by `read_log_lines` and require no additional logging — they silently skip malformed lines (insufficient `parts`) which is the documented intent.

---

### src/intellicrack/sandbox/manager.py — LOC 573

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes (L18)

**Findings**:

- [LOW] L467-469 — `except (OSError, RuntimeError, SandboxError): _logger.warning("binary_execution_failed", instance_id=instance.id); raise`. The `.warning()` here (vs `.exception()`) loses the traceback before re-raising. Project memory notes TRY400 conflict with re-raised exception patterns; `.warning` is intentional. However, since the exception is re-raised the upstream catcher will see the traceback, so this is acceptable. Flagged LOW for awareness only — the missing context kwarg is `error=str(e)` (currently dropped).

All other `except` blocks (L328-332, L387-388, L399-400, L537-538) log appropriately. Lifecycle transitions are all logged: `sandbox_manager_initialized`, `sandbox_instance_initialized`, `sandbox_instance_created`, `sandbox_instance_started`, `sandbox_instance_destroyed`, `sandbox_destroy_called`, `sandbox_create_called`, `sandbox_status_queried`, etc. Coverage is strong.

---

### src/intellicrack/sandbox/qemu.py — LOC 3675

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes (L36)

**Findings**:

#### HIGH severity

- [HIGH] L2900-2901 — `except FileNotFoundError: return 0` inside `_stat_size` helper of `_wait_for_logs_stable` is a silent except. Per §2.2, every `except` must have a log. Although this is intentional polling behaviour (the log file may not exist for the first few polls), the rule is strict. Fix: `_logger.debug("logs_stable_stat_missing", path=str(path))`.
- [HIGH] L3168-3170 — `except FileNotFoundError: await asyncio.sleep(...); continue` inside `_wait_for_ppm_stable` is a silent except. Same intentional polling pattern. Fix: `_logger.debug("ppm_stat_missing", ppm_path=str(ppm_path))`.
- [HIGH] L3601-3604 — `except ImportError as exc: raise SandboxError(_ERR_YARA_NOT_AVAILABLE) from exc` in `yara_scan` does not log before re-raising. Fix: `_logger.warning("yara_python_not_installed", error=str(exc))` (or `.exception("yara_import_failed")`) before the raise.

#### MEDIUM severity — `extra={...}` antipattern (structlog kwarg style)

The following call sites use stdlib-logging-style `extra={...}` kwargs instead of canonical structlog flat kwargs. With `structlog.stdlib.BoundLogger` (the configured wrapper, see `core/logging.py:469-481`) the `extra` dict is recorded as a single nested field rather than flattened into the event payload — context filtering / JSON aggregation loses fidelity. All of these are inside Intellicrack-side code (outside the embedded guest-agent Python source string at L2143-2465):

- [MEDIUM] L2476 — `_logger.debug("guest_agent_scripts_created", extra={"path": str(monitor_dir)})`. Fix: `path=str(monitor_dir)`.
- [MEDIUM] L2644 — `_logger.debug("result_read_failed", extra={"error": str(e)})`.
- [MEDIUM] L2656 — `_logger.warning("command_timed_out", extra={"timeout_seconds": time_limit})`.
- [MEDIUM] L2677 — `_logger.debug("sidecar_read_failed", extra={"path": str(path), "error": str(exc)})`.
- [MEDIUM] L2714-2717 — `_logger.debug("result_artifact_cleanup_failed", extra={...})`.
- [MEDIUM] L2746 — `_logger.warning("binary_not_found", extra={"path": str(binary_path)})`.
- [MEDIUM] L2780 — `_logger.warning("sandbox_execution_timeout", extra={"binary": ..., "timeout": ...})`.
- [MEDIUM] L2786 — `_logger.warning("sandbox_execution_error", extra={"binary": ..., "error": ...})`.
- [MEDIUM] L2949 — `_logger.warning("source_file_not_found", extra={"path": str(source)})`.
- [MEDIUM] L2957 — `_logger.debug("file_copied_to_sandbox", extra={"source": ..., "dest": ...})`.
- [MEDIUM] L2978 — `_logger.warning("sandbox_source_file_not_found", extra={"path": source})`.
- [MEDIUM] L2985 — `_logger.debug("file_copied_from_sandbox", extra={...})`.
- [MEDIUM] L3007 — `_logger.warning("snapshot_create_failed", extra={"error": result.error})`.
- [MEDIUM] L3010 — `_logger.info("snapshot_created", extra={"snapshot_name": name})`.
- [MEDIUM] L3027 — `_logger.warning("snapshot_restore_failed", extra={"error": result.error})`.
- [MEDIUM] L3030 — `_logger.info("snapshot_restored", extra={"snapshot_id": snapshot_id})`.
- [MEDIUM] L3068 — `_logger.warning("snapshot_delete_failed", extra={"error": result.error})`.
- [MEDIUM] L3071 — `_logger.info("snapshot_deleted", extra={"snapshot_name": name})`.
- [MEDIUM] L2914-2920 — `_logger.debug("logs_stable_reached", extra={...})`.
- [MEDIUM] L2924-2930 — `_logger.warning("logs_stable_max_wait_elapsed", extra={...})`.

(The same `extra=` antipattern exists L2192-2458, but those calls are inside the Python source string that is written out as the Linux guest-agent `agent.py` and executed inside the QEMU VM — that code is functionally separate from Intellicrack runtime and uses stdlib `logging` deliberately; see Aggregate notes. Those occurrences are NOT counted in the MEDIUM tally above.)

#### MEDIUM severity — missing entry logs for public methods doing real work (§2.1)

- [MEDIUM] L2478 — `run_command()` is a public method that builds a script, writes it into the shared folder, and polls for results. No entry log. Existing logs cover error paths only.
- [MEDIUM] L2719 — `run_binary()` is a public method that copies the binary into the sandbox, resets monitor logs, dispatches `run_command`, and aggregates the report. No entry log.
- [MEDIUM] L2935 — `copy_to_sandbox()` performs file I/O into a shared folder; no entry log, only error/debug.
- [MEDIUM] L2962 — `copy_from_sandbox()` — same pattern as above.
- [MEDIUM] L2990 — `take_snapshot()` issues a QMP `savevm`; no entry log. Lifecycle event but only logs success/failure at end.
- [MEDIUM] L3013 — `restore_snapshot()` — same.
- [MEDIUM] L3054 — `delete_snapshot()` — same.
- [MEDIUM] L3177 — `capture_screenshot()` issues `screendump`, polls PPM stability, converts to PNG; no entry log.
- [MEDIUM] L3236 — `apply_anti_evasion()` runs many guest-agent commands (registry patches, MAC randomisation) — no entry log; only success summary at L3323.
- [MEDIUM] L3326 — `dump_memory()` issues QMP `dump-guest-memory`; no entry log.
- [MEDIUM] L3382 — `extract_dropped_files()` dispatches guest-side `xcopy`/`cp` commands, then builds a zip — no entry log.
- [MEDIUM] L3584 — `yara_scan()` compiles rules and scans guest output — no entry log.

#### MEDIUM severity — unlogged subprocess invocations (§2.3)

- [MEDIUM] L1044-1059 — `_subprocess_run([pwsh, ...])` for `Get-WindowsOptionalFeature` WHPX probe has no pre-call log. Only the exception path logs. Fix: add `_logger.debug("whpx_feature_probe_started", argv=[...])` before the call.
- [MEDIUM] L1073-1079 — `_subprocess_run([bcdedit, ...])` has no pre-call log.

#### LOW severity

- [LOW] L1064 — `except (OSError, _SubprocessTimeoutExpired) as e: _logger.debug("whpx_feature_probe_failed", error=str(e))`. Debug-level for a subprocess failure during availability detection is borderline; warning would be more appropriate so the user can diagnose why WHPX was rejected. Currently the false negative cascades silently to TCG.
- [LOW] L1087 — same pattern for bcdedit probe failure.
- [LOW] L1748-1752 — `except (ValueError, OSError): _logger.debug("pidfile_read_retry", attempt=...)` swallows the underlying error; the `error=str(e)` context is in scope but not captured. Add `error=str(<exc>)` to the log.

---

### src/intellicrack/sandbox/windows.py — LOC 2479

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes (L28)

**Findings**:

#### HIGH severity

- [HIGH] L1501-1502 — `except OSError: break` inside `_wait_for_monitor_quiescence` is a silent except. Fix: `_logger.warning("monitor_quiescence_stat_failed")` (or `.debug` if the surrounding poll is expected to race the file system). The current code aborts the wait loop silently which can mask a deeper IO problem on the shared folder.
- [HIGH] L2193-2196 — `except ImportError as exc: raise SandboxError(_ERR_YARA_NOT_AVAILABLE) from exc` in `yara_scan` does not log before re-raising. Fix: `_logger.warning("yara_python_not_installed", error=str(exc))` before the raise.
- [HIGH] L2478-2479 — `except (OSError, ValueError, AttributeError): return None` inside `_win_handle_from_file` is a silent except. Fix: `_logger.warning("win_handle_from_file_failed")` with `exc_info=True`.

#### MEDIUM severity — missing entry logs for public methods doing real work (§2.1)

- [MEDIUM] L1306 — `run_command()` is a public method that writes a trigger file, polls for the result, and cleans up. No entry log. Only error paths log.
- [MEDIUM] L1374 — `run_binary()` no entry log.
- [MEDIUM] L1526 — `copy_to_sandbox()` no entry log (only logs the debug success).
- [MEDIUM] L1557 — `copy_from_sandbox()` no entry log.
- [MEDIUM] L1674 — `capture_screenshot()` builds & dispatches a PowerShell screenshot script; no entry log.
- [MEDIUM] L1726 — `apply_anti_evasion()` dispatches MOF compilation and multiple guest-side commands; no entry log. Success is logged at L1799.
- [MEDIUM] L1924 — `dump_memory()` builds & dispatches a MiniDumpWriteDump PowerShell payload; no entry log. Error paths and success are logged.
- [MEDIUM] L2089 — `extract_dropped_files()` dispatches multiple `xcopy` commands; no entry log.
- [MEDIUM] L2176 — `yara_scan()` no entry log.

#### MEDIUM severity — significant operations / lifecycle without surrounding logs (§2.3, §2.4)

- [MEDIUM] L481-487 — `await asyncio.to_thread(Popen, [self.SANDBOX_EXE, str(self._wsb_path)], ...)`. The pre-call log at L479 (`windows_sandbox_starting`) is adequate, but no log line confirms the Popen returned (only `windows_sandbox_started` at L518 after worker resolution). Borderline; flagged for awareness.
- [MEDIUM] L1411 — `await self.copy_to_sandbox(binary_path, ...)` inside `run_binary` — no log indicating the binary was staged into the sandbox before exec. Existing debug log in `copy_to_sandbox` covers it but at debug level; consider info-level for the run_binary path so the operational sequence is visible at default log level.
- [MEDIUM] L1605-1607 — `pktmon start` dispatched via `run_command`. No pre-call log naming the operation; only failure path at L1609 logs `pcap_start_failed`. The success is logged at L1613 (`pcap_capture_started`). Add `_logger.info("pcap_capture_start_requested", capture_id=capture_id)` before the dispatch.
- [MEDIUM] L1640 / L1651 — `pktmon stop` and `pktmon etl2pcap` dispatched via `run_command` with no pre-call log naming the conversion step.
- [MEDIUM] L1768-1769 — `Rename-Computer` PowerShell dispatched via `run_command` without a pre-call log identifying the anti-evasion technique being attempted.
- [MEDIUM] L1773-1789 — Multiple anti-evasion guest commands (`decoy_user_profile`, `decoy_documents`) dispatched without pre-call entry logs; only the summary log at L1799 lists which techniques succeeded.
- [MEDIUM] L1846 — `mofcomp.exe -N:root\cimv2 "<mof_guest_path>"` dispatched via `run_command` from `_apply_wmi_hijack`; no pre-call log.
- [MEDIUM] L2009 — `powershell -Command "<MiniDumpWriteDump payload>"` dispatched via `run_command` from `dump_memory`; no pre-call log.
- [MEDIUM] L2122-2123 — `xcopy /S /E /Y /I /Q "<guest_dir>" "<sandbox_staging>"` dispatched from `extract_dropped_files`; no pre-call log per directory (only error logs on certain exit codes).

#### MEDIUM severity — direct subprocess use without surrounding logs

- [MEDIUM] L2009 — also covered above; the MiniDump PowerShell is a complex payload and would benefit from a `_logger.info("guest_minidump_dispatching", target_pid=target_pid, dump_path=sandbox_dump_path)` before the call.

#### LOW severity

- [LOW] L1428-1432 — `except SandboxTimeoutError: _logger.warning("sandbox_execution_timeout", ...)` and L1437-1442 `except SandboxError: _logger.warning("sandbox_execution_error", ...)` use `.warning()` instead of `.exception()`. Since they swallow the exception (assigning to local result fields and not re-raising), the traceback is lost. Consider `.exception(...)` so backtrace lands in the file/JSON log.
- [LOW] L2167 — `_logger.info("dropped_files_extracted", zip_path=str(zip_path))`. `files` count is not included; only added in the qemu equivalent. Inconsistent metadata between the two sandboxes.

All other `except` blocks in `windows.py` log appropriately (L420, L520, L557, L569, L583, L642, L658, L678, L690, L745, L754, L786, L1367, L1475, L1548, L1578, L2029, L2075, L2164, L2253, L2351, L2391, L2426, L2472).

---

## Aggregate notes

### Pattern: embedded guest-side Python agent code in `qemu.py` (L2143-2465)

`qemu.py` writes a complete Python guest-agent program out as a multi-line string in the body of `_create_guest_agent_script` (Linux branch). That embedded code uses stdlib `logging.basicConfig(...)` + `logging.getLogger("sandbox.qemu.agent")` and writes to a file inside the VM. It is exempt from §3.1 (stdlib logging ban) because it is not Intellicrack runtime code — it runs inside the guest with no access to the host's structlog configuration. The lint-style choice of `extra={...}` inside that string is correct for stdlib logging and should be left alone there.

Boundary confirmation: the string opens at L2143 (`agent_content = '''#!/usr/bin/env python3`) and closes at L2465 (a lone `'''`). All log calls between those lines, including the ones containing `extra={...}`, are inside the embedded guest agent and are NOT Intellicrack runtime violations.

### Pattern: `extra={...}` antipattern in Intellicrack-side qemu.py code

Outside the guest-agent string, `qemu.py` still has ~20 log call sites that pass `extra={...}` dicts to structlog's BoundLogger. With the configured stdlib + structlog stack this records the dict as a nested `extra` field instead of flattening into the event payload, hurting log filterability and downstream JSON aggregation. `windows.py` and `manager.py` do not have this pattern — they use flat kwargs correctly. Recommend a single normalising pass over `qemu.py` to flatten every `extra={"k": v, ...}` to direct `k=v, ...` kwargs.

### Pattern: silent excepts in polling helpers

Both `qemu.py` (`_stat_size` L2898-2901, `_wait_for_ppm_stable` L3168-3170) and `windows.py` (`_wait_for_monitor_quiescence` L1501-1502, `_win_handle_from_file` L2478-2479) contain silent `except` clauses. The two qemu polling helpers are intentional polling-doesn't-care-about-FileNotFound patterns; per the strict criteria they still need at least a debug log. The two windows.py cases are not polling — `_wait_for_monitor_quiescence` aborts its loop on OSError silently, and `_win_handle_from_file` swallows three exception classes, both should log at warning level.

### Pattern: yara import failures (both files)

Both `qemu.py:3601-3604` and `windows.py:2193-2196` use the same `except ImportError as exc: raise SandboxError(...) from exc` pattern without logging. Consolidating to a single helper like `core/_optional_imports.py` that logs on ImportError before raising would close both at once.

### Pattern: missing entry logs on public sandbox operations

Both `qemu.py` and `windows.py` consistently skip entry-time logging on their public action methods (`run_command`, `run_binary`, `copy_to_sandbox`, `copy_from_sandbox`, `capture_screenshot`, `apply_anti_evasion`, `dump_memory`, `extract_dropped_files`, `yara_scan`). The state mutations, success summaries, and error paths are all well-logged, but the "operation started" signal is missing. Adding a `_logger.info("<op>_started", ...)` at the top of each public method would make it possible to follow the operational sequence at the default INFO log level without enabling debug.

### Pattern: structured kwargs and lifecycle logging

`manager.py`, the non-embedded portions of `qemu.py`, and `windows.py` all import `get_logger` correctly, define module-level `_logger`, never use stdlib `logging` directly, never use `print(...)` for runtime output, and never use `contextlib.suppress`. Lifecycle transitions (start/stop/snapshot/destroy/registration/cache invalidation) are covered. The shard is in good overall shape; the dominant remaining work is (a) normalising `extra={...}` to flat kwargs in `qemu.py`, (b) logging four silent `except` sites, (c) adding entry logs to public methods, and (d) logging the two yara ImportError sites.

### Cross-shard recommendation

`_log_helpers.py` and `_tld_data.py` correctly omit a logger because they contain no operations. This is the right call and matches the §4 exemption for pure data/utility modules. No action needed.
