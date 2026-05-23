# Shard 06 — bridges (cutter / sandbox_bridge / installer)

- **Files audited**: 3
- **Total LOC**: 8286
- **Generated**: 2026-05-22T16:55:26-06:00

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 5     |
| MEDIUM   | 11    |
| LOW      | 4     |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0 (the `print(frida.__version__)` matches in installer.py are *contents of subprocess command arguments* (lines 333, 1162), not Python `print` calls)
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 5 (all in installer.py)

## Findings by file

### src/intellicrack/bridges/cutter.py — LOC 3527

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes (L30; `_logger = get_logger(__name__)` at L67)

**Findings**: none.

This file is exemplary. Every `except` clause has a structured `_logger.warning/exception(...)` call (verified at L903/911 — `_r2_cmd` timeout/error paths, L981/990/1018/1031/1040/1171 — load_binary and shutdown paths, L1946/1994 — assemble/JSON parse, L2174/2638 — libraries/flag JSON parse). Every public `async` method (`load_binary`, `analyze`, `get_functions`, `decompile`, `disassemble`, `write_bytes`, `assemble_at`, `save_binary`, `add_flag`, `rename_function`, `add_comment`, all `esil_*`, all `search_*`, all `get_*`, all `write_*`, `import_c_header`, `save_project`, etc.) emits a `_logger.debug` or `_logger.info` event with structured kwargs at completion (or on the `_r2 is None` guard with `_logger.warning(...)`). No f-strings, `%`, or `.format` in log calls. No `print(...)`. No stdlib logging. No `contextlib.suppress`. Lifecycle transitions are logged: `cutter_bridge_initialized` (L843, L968), `cutter_bridge_shutdown` (L999), `binary_loaded` (L1155), `analysis_starting`/`analysis_complete` (L1195/1198), `binary_saved` (L2537). State setter `r2.setter` logs `r2_connection_set` (L865).

---

### src/intellicrack/bridges/sandbox_bridge.py — LOC 2450

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes (L24; `_logger = get_logger(__name__)` at L50)

**Findings**:

- [LOW] L1611 — `except Exception as e:` is overly broad for `await qmp.cont()`. The block does log (`_logger.warning("vm_resume_failed", error=str(e))` at L1612) so this is not a missing-log defect. Tightening to a specific QMP/network exception set would be preferable, but with the current logging present this is only a low-severity concern about exception specificity, not logging coverage.
- [LOW] L2140-2143, L2189-2192, L2265-2268, L2309-2312, L2368-2371 — Each of these has a `except (ValueError, KeyError, TypeError)` branch immediately followed by a `except Exception` catch-all branch. Both branches log `_logger.warning(..._unexpected_error, error=str(e))` and re-raise as `ToolError`, so this is not a coverage defect. The duplicate handler pattern is redundant — once tightened, the second handler can collapse into the first. Listed here for completeness of the duplicate-handler observation.
- [LOW] Pattern observation: every `except` block uses `_logger.warning(..., error=str(e))` followed by `raise ToolError(...) from e` instead of `_logger.exception(...)`. Per project memory this is the documented intentional pattern (TRY400 conflicts with re-raise) — not a violation. Listed once here so it is not re-flagged per call site.

No HIGH or MEDIUM findings. Every `except` block (L1082, 1113, 1196, 1259, 1315, 1360, 1433, 1476, 1520, 1567, 1611, 1679, 1718, 1762, 1804, 1894, 1937, 2005, 2051, 2096, 2136, 2140, 2185, 2189, 2248, 2261, 2265, 2305, 2309, 2364, 2368) has a structured log call before the re-raise. The `_StateTracker.__aexit__` (L208-233) logs `state_tracker_failure` with the operation label. All sandbox manager interactions log success (`sandbox_created`, `sandbox_destroyed`, `binary_execution_completed`, `command_executed`, `file_copied_to_sandbox`, `file_copied_from_sandbox`, `snapshot_created`, `snapshot_restored`, `snapshots_listed`, `snapshot_deleted`, `vm_resumed`, `pending_messages_retrieved`, `pcap_capture_started`, `pcap_capture_stopped`, `screenshot_captured`, `anti_evasion_applied`, `memory_dumped`, `dropped_files_extracted`, `yara_scan_completed`, `iocs_extracted`, `timeline_generated`, `behaviors_detected`, `c2_patterns_detected`, `reports_diffed`) and failure paths. Lifecycle: `sandbox_manager_attached` (L332), `sandbox_existing_registered` (L365), `sandbox_bridge_initialized` (L974), `sandbox_bridge_shutdown` (L984). State mutations (`set_vnc_password` L1840) log `vnc_password_registered`. No `print`, no stdlib logging, no `contextlib.suppress`, no f-strings in logs.

---

### src/intellicrack/bridges/installer.py — LOC 2309

**Logger status**: `module-level _logger` (with an unused export alias `logger = _logger` at L2207)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L34; `_logger = get_logger(__name__)` at L43)

**Findings**:

- [HIGH] L422-425 — `_is_user_admin()`: `try: return bool(is_admin_fn()); except OSError: return False` swallows a Win32 admin-check failure with no log call. Fix: add `_logger.debug("is_user_admin_check_failed", error=str(e))` (using `except OSError as e`) before the `return False`. The result is security-relevant (gates plugin deployment into Program Files), so the failure must not be silent.
- [HIGH] L512-513 — `_read_pe_version_info()`: `except (AttributeError, UnicodeError): continue` swallows a per-entry decode failure with no log. Fix: add `_logger.debug("pe_version_decode_failed", exe=str(exe_path), key=key_name, error=str(e))` and capture the exception as `as e`. Without it, a malformed `VS_VERSION_INFO` resource is invisible in logs.
- [HIGH] L1778-1779 — `_detect_vs_generator()`: `except (OSError, TimeoutExpired): return None` swallows the cmake `--help` invocation failure with no log. This is a subprocess error path per §2.3 and §3.2. Fix: `_logger.warning("cmake_help_failed", cmake_path=str(cmake_path), error=str(exc))` (capture `as exc`). The function silently returns `None`, which the caller (`build_x64dbg_plugin`) treats as "no Visual Studio generator detected" and logs only the symptom, not the root cause.
- [HIGH] L2180-2181 — `_path_requires_admin()`: `except OSError: return False` after `target.resolve()` is silent. Fix: `_logger.debug("path_requires_admin_resolve_failed", target=str(target), error=str(exc))` (capture `as exc`) before `return False`. Returning `False` here can let a deploy attempt into a Program Files path proceed without admin elevation.
- [HIGH] L2190-2192 — `_path_requires_admin()`: `except (OSError, ValueError): continue` in the prefix-relative-to loop is silent. Fix: add a `_logger.debug("path_requires_admin_prefix_check_failed", prefix=prefix, error=str(exc))`. Same security significance as the previous finding.
- [MEDIUM] L731 — `_probe_python_package()`: `await process_manager.run_tracked_async([...], name=f"{tool_info.name.value}-version-probe", ...)` has no pre-call log statement. The error paths (TimeoutExpired L737, FileNotFoundError/OSError L745) are logged; the *intent* to spawn the probe subprocess is not. Per §2.3 (subprocess: "log statements before AND after"), add `_logger.debug("python_package_probe_starting", tool=tool_info.display_name, cmd=cmd)` before the call.
- [MEDIUM] L823 — `get_version()`: `await process_manager.run_tracked_async([...], name=f"{tool.value}-version", ...)` has no pre-call log. Add `_logger.debug("tool_version_probe_starting", tool=str(tool), cmd=cmd)` before the call. Successful exit (L830-831) also returns without logging the parsed version — consider adding `_logger.debug("tool_version_probe_succeeded", tool=str(tool), version=raw)`.
- [MEDIUM] L1147-1151 — `_install_frida()` pip-install subprocess: pre-call `_logger.info("frida_pip_installing", tool="frida")` at L1144 exists, but the failure path at L1153-1158 (`if result.returncode != 0: return InstallResult(success=False, ...)`) returns without a log call. Add `_logger.warning("frida_pip_install_failed", returncode=result.returncode, stderr=result.stderr.strip())` before the return.
- [MEDIUM] L1161-1165 — `_install_frida()` version-verify subprocess: no pre-call log, and the TimeoutExpired (L1166-1171), non-zero returncode (L1173-1178), and unparseable-version (L1181-1186) branches all return `InstallResult(success=False, ...)` without logging. Add `_logger.debug("frida_version_verify_starting")` before, and `_logger.warning("frida_version_verify_failed", reason=..., ...)` on each failure return.
- [MEDIUM] L1063 — `install_tool()` calls `await asyncio.to_thread(download_path.unlink, missing_ok=True)` in a `finally` block — no log of the cleanup. Add `_logger.debug("download_temp_unlinked", path=str(download_path))`.
- [MEDIUM] L1315-1332 — `_download_file()` writes the downloaded archive to disk via `temp_path.open("wb")` and streaming `file_handle.write(chunk)`. The download intent is logged (`download_starting` L1305), the completion is logged (`download_completed` L1334), but the file-handle open is not logged. Per §2.3 (file I/O writes must be logged). Lower severity because the intent and outcome bracket the write. Add `_logger.debug("download_file_opened", path=str(temp_path))` after L1315.
- [MEDIUM] L1344 — `_download_file()` failure-cleanup: `await asyncio.to_thread(temp_path.unlink, missing_ok=True)` in the `finally`-only-on-failure branch has no log. Add `_logger.debug("download_partial_removed", path=str(temp_path))`.
- [MEDIUM] L544 — `ToolInstaller.__init__()` calls `self.tools_directory.mkdir(parents=True, exist_ok=True)` (a file-system mutation) without logging. Add `_logger.debug("tools_directory_ready", path=str(self.tools_directory))` after the mkdir.
- [MEDIUM] L1371 — `_extract_archive()` calls `tool_dir.mkdir(parents=True, exist_ok=True)`. The `extraction_starting` log at L1373 is the closest event, but it does not specifically record the mkdir. Acceptable; flag for completeness only — consumers may collapse the two events into one.
- [MEDIUM] L1866 — `build_x64dbg_plugin()` calls `build_dir.mkdir(parents=True, exist_ok=True)` per arch without logging. The surrounding `plugin_build_starting` (L1850) brackets it, but the per-arch mkdir specifically is silent. Lower severity because it is bracketed.
- [MEDIUM] L2092-2093 — `deploy_x64dbg_plugin_detailed()` performs `target_dir.mkdir(parents=True, exist_ok=True)` and `shutil.copy2(source, target)`. Failure is logged (L2095 `plugin_deploy_failed`). Success is logged (L2129 `plugin_deployed`) — but there is no pre-call log of the copy intent. Add `_logger.debug("plugin_copy_starting", source=str(source), target=str(target))` before the copy. (Listed at MEDIUM because the success is bracketed by `plugin_deployed`.)
- [LOW] L2207 — `logger = _logger` is a module-level alias. No internal callers use `logger.` and no external import references `installer.logger` (verified via `Grep`). Inconsistent with the canonical pattern (§3.12) and provides a dual-name path that future contributors could grab. Fix: remove the alias.
- [LOW] L1807-1809 — `_cmake_timeout()`: `except ValueError: _logger.warning("cmake_timeout_env_invalid", ...)` does not capture the exception (`as exc`), so the actual `ValueError` message is not in the structured kwargs. Fix: `except ValueError as exc:` and add `error=str(exc)`.
- [LOW] L1805-1810 — Same function: the success path (parsed value used) emits no log when `max(value, default_s)` clamps a user-supplied lower value up to the default. A `_logger.debug("cmake_timeout_clamped_to_default", env_var=env_var, requested=value, default_s=default_s)` would surface mis-configurations earlier. Not a coverage defect, just a quality-of-life hint.

## Aggregate notes

- **cutter.py** is a model of structured logging: 100% of public methods log an entry guard (`_logger.warning` on `_r2 is None`) and a completion event (`_logger.debug` for queries, `_logger.info` for state-changing commands), all `except` blocks log, and zero f-string / `%` / `.format` log strings are used. Could be cited as the project's reference example.
- **sandbox_bridge.py** is similarly thorough thanks to the `_StateTracker` context manager that consolidates `last_error` lifecycle. The only minor concern is overly broad `except Exception` at L1611 and the repeated `(ValueError, KeyError, TypeError)` + `Exception` paired handlers (L2140/2189/2265/2309/2368) — all log, so no coverage gap.
- **installer.py** has the most gaps in the shard, concentrated in two areas:
  1. Five silent `except` blocks (L424, L512, L1778, L2180, L2190) that swallow OS/format errors with no log call — all marked HIGH. Three of the five gate security-relevant behaviour (admin checks, Program Files deployment).
  2. Subprocess and file-write call sites in `_install_frida`, `_probe_python_package`, `get_version`, and `_download_file` log error paths but not intent (no pre-call `_logger.debug("..._starting", ...)`). Per §2.3 these should bracket the external call.
- The `logger = _logger` alias on L2207 of installer.py is dead but exported via `from intellicrack.bridges.installer import logger` (no callers found in the repo). Recommend removal for §3.12 consistency.
- No `print(...)` runtime output, no `contextlib.suppress`, no `# noqa`/`# type: ignore`/`# pyright: ignore`, no stdlib `logging` references, and no f-string / `%` / `.format` in any `_logger.*()` call across the entire shard. The two `print(...)` substrings in installer.py (L333, L776 docstring, L1162) are inside Python `-c` subprocess command-line strings that drive the frida version probe, not Python `print` calls in this module.
- The pattern of `except SomeError as e: _logger.warning("event", error=str(e)); raise ToolError(...) from e` is used consistently across cutter.py and sandbox_bridge.py. Per project memory this is the intended pattern (TRY400 conflict + explicit `raise from`), so `.warning()` instead of `.exception()` is correct here and was not flagged.
