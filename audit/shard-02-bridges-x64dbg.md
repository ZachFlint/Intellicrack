# Shard 02 — bridges/x64dbg

- **Files audited**: 1
- **Total LOC**: 8685
- **Generated**: 2026-05-22T22:54:18Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 17    |
| MEDIUM   | 9     |
| LOW      | 11    |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 1
- Files with bare `except` (no log): 1 (L3006 `except BaseException`)

## Findings by file

### src/intellicrack/bridges/x64dbg.py — LOC 8685

**Logger status**: `module-level _logger` (declared L126 as `_logger = get_logger("bridges.x64dbg")`)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L101)

Note on logger name: the canonical pattern in the criteria is `get_logger(__name__)`, but here `get_logger("bridges.x64dbg")` is used with a literal logger name. This is consistent with other bridge modules and does not appear to be a violation per §1 (the leading-underscore module-level `_logger` is used). Flagging as informational LOW only.

**Findings**:

#### HIGH — silent exception swallows / re-raises without log

- [HIGH] L416 — `except ValueError: return None` in `_safe_int_or_none()` swallows parse failures with no log. Fix: add `_logger.debug("safe_int_parse_failed", value=str(value))` before `return None`.
- [HIGH] L2208-2209 — `except RuntimeError: continue` in `_cancel_all_step_waiters()` discards `get_loop()` failures with no log. Fix: add `_logger.debug("step_waiter_loop_unavailable_on_cancel", waiter=id(waiter))` before `continue`.
- [HIGH] L2501-2502 — `except ValueError: return 0` in `_coerce_address()` swallows hex/int parse failures silently. Fix: add `_logger.debug("coerce_address_parse_failed", raw=raw)` before `return 0`.
- [HIGH] L2526-2527 — `except RuntimeError: continue` in `_resolve_step_waiters()` discards future-loop failures silently. Fix: add `_logger.debug("step_waiter_loop_unavailable_on_resolve", waiter=id(waiter))` before `continue`.
- [HIGH] L2564 — `contextlib.suppress(ValueError)` in `_cancel_step_waiter()` — forbidden per project memory and criteria §3.3. Fix: replace with explicit `try`/`except ValueError as exc: _logger.debug("step_waiter_already_removed", error=str(exc))`.
- [HIGH] L2999-3005 — `except TimeoutError as exc:` in `_await_step_complete()` cancels the waiter and raises a new `ToolError` with no log call. Fix: add `_logger.warning("x64dbg_step_timeout", command=command, timeout_s=self.STEP_TIMEOUT_SECONDS, error=str(exc))` before `raise ToolError(...) from exc`.
- [HIGH] L3006-3008 — `except BaseException:` (bare-style) in `_await_step_complete()` cancels the waiter and bare-re-raises with no log. Criteria §2.2 explicitly says "any except clause without a log statement is HIGH, even if re-raised." Fix: add `_logger.debug("x64dbg_step_cancelled", command=command, exc_info=True)` before `raise`.
- [HIGH] L3219-3226 — `except ToolError as exc:` in `_verify_breakpoint_applied()` re-raises on the non-`unknown_command` path with no log. Fix: add `_logger.debug("bp_list_verify_failed", address=hex(address), error=str(exc))` before `raise`.
- [HIGH] L3247-3248 — `except ValueError: continue` in `_verify_breakpoint_applied()` skips malformed entries silently. Fix: add `_logger.debug("bp_list_entry_addr_unparseable", raw=raw_addr)` before `continue`.
- [HIGH] L5026-5029 — `except ToolError as exc:` in `_wait_for_instruction_pointer()` re-raises non-`unknown_command` errors with no log. Fix: log before `raise`.
- [HIGH] L5036-5037 — `except ValueError: ip_value = None` in `_wait_for_instruction_pointer()` swallows hex parse failures silently. Fix: `_logger.debug("ip_value_parse_failed", raw=rip_result)`.
- [HIGH] L5070-5073 — `except ToolError as exc:` in `_lookup_annotation_text()` re-raises non-`unknown_command` errors with no log. Fix: log before `raise`.
- [HIGH] L5085-5086 — `except ValueError: continue` in `_lookup_annotation_text()` swallows annotation-address parse failures silently. Fix: log at debug.
- [HIGH] L5140-5143 — `except ToolError as exc:` in `_query_bp_list()` re-raises silently. Fix: log before `raise`.
- [HIGH] L5230-5233 — `except ToolError as exc:` in `_query_thread_details()` re-raises silently. Fix: log before `raise`.
- [HIGH] L5331-5337 — `except ToolError as exc:` in `_wait_for_running_state()` — `unknown_command` path is silent (no log) and non-`unknown_command` path re-raises with no log. Fix: add debug log on the silent path and an error/warning on the raise path.
- [HIGH] L5375-5379 — `except ToolError as exc:` in `_query_script_error()` re-raises non-`unknown_command` errors with no log. Fix: log before `raise`.
- [HIGH] L5406-5408 — `except ToolError as exc:` in `_query_plugin_present()` (first arm, `plugin_list` RPC) re-raises silently. Fix: log before `raise`.
- [HIGH] L5420-5423 — `except ToolError as exc:` in `_query_plugin_present()` (second arm, `plugin.find` evaluator) re-raises silently. Fix: log before `raise`.
- [HIGH] L5555-5556 — `except ValueError: continue` in `get_labels()` swallows label-address parse failures silently. Fix: `_logger.debug("label_address_parse_failed", raw=addr_str)`.
- [HIGH] L5634-5635 — `except ValueError: continue` in `get_comments()` swallows comment-address parse failures silently. Fix: log at debug.
- [HIGH] L8045-8046 — `except ValueError: return None` in `_coerce_hex_int()` swallows hex parse failures silently. Fix: `_logger.debug("hex_int_parse_failed", raw=raw)`.

#### HIGH — every other `except` block in the file *does* log

I traced all ~85 `except` clauses listed by Grep. The remaining clauses (L137, 144, 152 — import fallbacks; L613, L2125, L2140-2155, L2167-2172, L2382, L2427, L2476, L2609, L2617, L2750, L2798, L2925, L3012, L3158-3166, L3290-3293, L3407-3411, L3469-3471, L3607-3613, L3776-3778, L3843-3845, L3943-3947, L3976-3985, L4034-4037, L4092-4094, L4159-4165, L4353-4356, L4386-4391, L4413-4419, L4471-4477, L4601-4604, L4654-4655, L4663-4669, L4682-4688, L4720-4724, L4855-4861, L5541-5542, L5620-5621, L5794-5799, L6022-6030, L6109-6110, L6347-6353, L6457-6466, L6509-6512, L6528-6531, L6547-6550, L6566-6569, L6590-6593, L6836-6839, L6866-6869, L6893-6896, L6917-6920, L6941-6944, L6963-6966, L6982-6985, L7167-7170, L7343-7350, L7461-7467, L7744-7747, L7964-7966, L7979-7980, L7987-7988, L8075-8076, L8085-8086, L8115-8118, L8478-8479, L8545-8546, L8666-8669) all have explicit log calls at appropriate levels. They are NOT findings.

#### MEDIUM — missing entry/exit logging on public methods doing real work

- [MEDIUM] L2222-2234 — `is_available()` performs file-existence checks against two debugger paths but logs neither entry nor result. Public API. Fix: `_logger.debug("x64dbg_availability_checking")` and `_logger.debug("x64dbg_availability_checked", x64_exe=..., x32_exe=..., available=...)`.
- [MEDIUM] L2929-2941 — `detach()` sends a `detach` debugger command (an *external* command to the debugger) and releases handles but has no entry log; only an exit log. Fix: add `_logger.info("x64dbg_process_detaching", pid=self._attached_pid)` at entry.
- [MEDIUM] L3068-3135 — `set_breakpoint()` issues an external debugger RPC (`bp_set`) and verifies via another RPC (`bp_list`) — no entry log; only the exit `breakpoint_set` info. Fix: add `_logger.info("breakpoint_setting", address=hex(address), type=bp_type, condition=condition)` at entry.
- [MEDIUM] L3258-3273 — `remove_breakpoint()` issues `bp_remove` RPC; missing entry log.
- [MEDIUM] L3275-3323 — `get_breakpoints()` issues `bp_list` and merges results — no entry/exit logs at all (state-modifying merge into local mirror).
- [MEDIUM] L3325-3366 — `set_watchpoint()` issues `wp_set` debugger RPC — no entry log; only exit `watchpoint_set`. Add entry log.
- [MEDIUM] L3392-3434 — `get_watchpoints()` issues `wp_list` RPC and merges results — no entry/exit log other than recoverable-error debug.
- [MEDIUM] L3436-3530 — `get_registers()` issues `regs_get` (real RPC, the response of which materially affects every step/IP operation) — no entry log; only an exit debug log on the result (L3524). Add entry log.
- [MEDIUM] L3532-3547 — `set_register()` issues a register-write debugger RPC — has only an exit `_logger.info("register_set", ...)`; no entry log. Acceptable trade-off, marking MEDIUM by strict reading.
- [MEDIUM] L3659-3699 — `write_memory()` does a Win32 `WriteProcessMemory` (security/integrity-significant external call) — no entry log. Only an exit `memory_written` info on success. Fix: add `_logger.info("memory_writing", address=hex(address), size=len(data))` at entry.
- [MEDIUM] L3701-3754 — `allocate_memory()` does a Win32 `VirtualAllocEx` — no entry log; only an exit `memory_allocated` info on success. Fix: add `_logger.info("memory_allocating", size=size, protection=protection)` at entry.
- [MEDIUM] L3756-3787 — `free_memory()` does a Win32 `VirtualFreeEx` — entry debug present (L3765); no exit log on success/failure result. Fix: add `_logger.info("memory_freed", address=hex(address), success=bool(success))` before return.
- [MEDIUM] L7872-7883 — `close_handle()` sends a `handleclose` debugger command (releases an attached-process handle, security-relevant). Has only a `x64dbg_command_queued` debug; no result/outcome log. Fix: log result.
- [MEDIUM] L8483-8547 — `adjust_privilege()` performs `LookupPrivilegeValueW`, `OpenProcessToken`, `AdjustTokenPrivileges` Win32 calls. Has an entry info log (L8493) and an `except` log (L8546). However, the early-return paths at L8527 (`{"success": False, "error": "Privilege {name!r} not found"}`) and L8532 (`{"success": False, "error": "Failed to open process token"}`) silently return without logging. Add `_logger.warning("privilege_lookup_failed", privilege=name)` / `_logger.warning("open_process_token_failed")` before each early return.

#### MEDIUM — unlogged operational paths

- [MEDIUM] L2300-2307 — `Popen(...)` call inside `_start_debugger()` to spawn `x64dbg.exe`. There IS a preceding `_logger.info("x64dbg_starting", path=...)` (L2288), but no post-spawn log (e.g. "spawned pid=") even though the `_process` reference is captured. Add `_logger.info("x64dbg_spawned", pid=self._process.pid)` after the `Popen`.
- [MEDIUM] L8526-8527, L8531-8532 — `LookupPrivilegeValueW` and `OpenProcessToken` Win32 calls inside `adjust_privilege()` fail silently with early `return` (see above). Add warning logs.

#### LOW — minor quality / style

- [LOW] L126 — logger initialised with a literal `"bridges.x64dbg"` rather than `__name__`. Not a violation of §1 (it is module-level `_logger`), but inconsistent with the canonical pattern documented in §1. Acceptable here because the bridge logger name is a stable namespace; flagging informationally.
- [LOW] L3768-3787 — `free_memory()` returns `False` on three early-out paths (L3767, L3772, L3786 fall-through) without distinguishing the cause in logs.
- [LOW] L5042-5043 — `_wait_for_instruction_pointer()` returns `last_ip` on timeout silently. Fix: `_logger.warning("ip_wait_timeout", target=hex(target), last_ip=hex(last_ip) if last_ip else None)` before the timeout-return.
- [LOW] L5197-5214 — `_wait_for_breakpoint_enabled_state()` polls until timeout and returns silently. Add a debug log when the deadline elapses.
- [LOW] L5282-5299 — `_wait_for_thread_state()` polls until timeout and returns silently. Add a debug log when the deadline elapses.
- [LOW] L5325-5353 — `_wait_for_running_state()` polls until timeout and returns silently. Add a debug log when the deadline elapses.
- [LOW] L6906-6924, L6845-6873, L6875-6900 — `read_peb()`, `read_teb()`, `get_pe_directories()` — debug entry log present but the silent-empty-result returns (`return {}` / `return []` when the result is not a list/dict) have no log. Trace gap if the plugin returns unexpected types. Add a debug `_logger.debug("payload_type_unexpected", expected=..., got=type(result).__name__)`.
- [LOW] L8129-8151 — `get_status()` has an entry log but raises `ToolError` on non-dict payload (L8147) without a log. Add `_logger.warning("get_status_protocol_violation", payload_type=type(result).__name__)` before `raise`.
- [LOW] L8166-8202 — `get_tls_callbacks()` reads TLS directory and returns early on missing data (L8181, L8185-86) without distinguishing reason in logs.
- [LOW] L8420-8480 — `get_privileges()` has multiple early-return-`[]` paths (L8428 non-Windows; L8437 OpenProcessToken failure; L8444 GetTokenInformation failure) that go unlogged except for the final OSError. Add warning logs on the Win32 failures.
- [LOW] L8204-8220 — `break_on_tls_callbacks()` (not read in detail) is a public method orchestrating multiple breakpoint sets; ensure it logs entry/exit/aggregation result.

## Aggregate notes

- **Strong baseline.** The module imports `get_logger` correctly, declares `_logger` at module level, uses **structured kwargs everywhere** (zero f-string/`%`/`format` violations in 204 log call sites), uses `_logger.exception(...)` and `_logger.warning(...)` consistently in the major external-call paths (Win32 toolhelp, named-pipe, subprocess spawn), and has a coherent fallback pattern for recoverable plugin RPCs (debug log + fallback to script command).
- **Dominant pattern of HIGH findings**: the repeated `except ToolError as exc: if _x64dbg_error_code(exc) == _X64DBG_ERR_UNKNOWN_COMMAND: ...; raise` pattern logs the `unknown_command` branch (at debug) but **bare-re-raises** on the non-recoverable branch with no log. This occurs at L3219, L5026, L5070, L5140, L5230, L5331, L5375, L5406, L5420 (and is the most common HIGH violation in the file). Recommendation: add a single helper that wraps the pattern and logs both branches uniformly.
- **`except ValueError` silent swallows in inline parsers** (L416, L2501, L3247, L5036, L5085, L5555, L5634, L8045) are individually minor but together represent a systematic missing-log pattern. A small `_safe_int_from_str(value: str, *, context: str) -> int | None` helper that logs at debug on parse failure would eliminate eight HIGH findings at once.
- **`contextlib.suppress` violation (L2564)** is the single forbidden-construct hit per project memory.
- **Public-method entry/exit logging gaps** cluster in the memory/breakpoint/watchpoint surface (`set_breakpoint`, `remove_breakpoint`, `get_breakpoints`, `set_watchpoint`, `get_watchpoints`, `get_registers`, `write_memory`, `allocate_memory`, `free_memory`). These are the highest-traffic debugger primitives; uniform `info`-level entry logs would substantially improve observability of debugger-state changes.
- **`Popen` of `x64dbg.exe` (L2300)** is logged on intent (L2288) but not on result (no logged pid). The bridge already calls `ProcessManager.register` immediately after, which presumably logs internally, so this is a low-priority MEDIUM.
- **The file is large (8685 LOC).** Audit was carried out by Grep-first (all `except`, all `_logger.*`, all `print(`, all `subprocess.`, all `contextlib.suppress`, all `logging.*`) followed by targeted Read of each except-clause neighbourhood. Confidence in the findings is high; the methodology should reliably catch every silent-except and every format-string-in-log violation.
