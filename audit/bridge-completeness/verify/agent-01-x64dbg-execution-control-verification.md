# Verification — Slice 1: x64dbg Execution Control

Adversarial re-check of `audit/bridge-completeness/agent-01-x64dbg-execution-control.md`
against current source: `src/intellicrack/bridges/x64dbg.py`,
`src/intellicrack/ui/panels/x64dbg_panel.py`, `src/intellicrack/core/tools.py`.
No application code was modified. All file:line citations below were
independently re-derived via `rg`/direct reads, not copied from the report.

## Verification table

| # | Finding (feature + claimed verdict) | Verdict | Independent evidence | Note |
|---|---|---|---|---|
| 1 | Run/continue — OK/OK/OK | CONFIRMED | `run()` src/intellicrack/bridges/x64dbg.py:2988-2991 (real `_send_pipe_command("run")`); tool-def `x64dbg.run` x64dbg.py:1057-1063; `_on_run` x64dbg_panel.py:1124-1141 calls `self._bridge.run()` via `run_bridge_coroutine_logged` | Matches exactly |
| 2 | Pause — OK/OK/OK | CONFIRMED | `pause()` x64dbg.py:2993-2996; tool-def x64dbg.py:1063-1069; `_on_pause` x64dbg_panel.py:1156-1163 | Matches |
| 3 | Stop/terminate — OK/OK/OK | CONFIRMED | `stop()` x64dbg.py:2998-3004; tool-def x64dbg.py:1069-1075; `_on_stop` x64dbg_panel.py:1189-1196 | Matches |
| 4 | Restart debuggee — MISSING/MISSING/NO-CONTROL | CONFIRMED | `rg -i "restart"` over both files returns zero hits; full tool-def name list (90 entries, x64dbg.py:1020-2039) contains no `x64dbg.restart`; only `load()` at x64dbg.py:2733-2751 performs `InitDebug`, requiring caller-supplied `path`/`args`; no restart button in `_populate_toolbar` (x64dbg_panel.py:115-190) | Confirmed absent at all three layers |
| 5 | Step into — OK/OK/OK | CONFIRMED | `step_into()` x64dbg.py:3096-3108, delegates to `_await_step_complete` (real paused-event wait, not sleep); tool-def x64dbg.py:1075-1081; `_on_step_into` x64dbg_panel.py:1221-1231 | Matches |
| 6 | Step over — OK/OK/OK | CONFIRMED | `step_over()` x64dbg.py:3110-3121; tool-def x64dbg.py:1081-1087; `_on_step_over` x64dbg_panel.py:1233-1243 | Matches |
| 7 | Step out / til return — OK/OK/OK | CONFIRMED | `step_out()` x64dbg.py:3123-3134; `execute_til_return()` x64dbg.py:5963-5970 (`erun`); tool-defs x64dbg.py:1087-1093 and 1404 area; `_on_step_out` x64dbg_panel.py:1245-1255, `_on_til_ret` x64dbg_panel.py:2081-2091 | Both methods real, both wired |
| 8 | Run to address — OK/OK/OK | CONFIRMED | `run_to()` x64dbg.py:5416+ (queues `runto`, polls `reg_get rip`, raises `ToolError` on timeout, per docstring at 5416-5439); tool-def `x64dbg.run_to`; `_on_run_to` x64dbg_panel.py:2055-2071 (`Go` button + address input) | Matches, verification logic confirmed real |
| 9 | Step N times — OK/OK/NO-CONTROL | CONFIRMED | `step_count()` x64dbg.py:7666-7710 (`tic`/`toc`, polls `status` via `_wait_for_running_state`, raises `ToolError` if never re-paused); tool-def `x64dbg.step_count` x64dbg.py:1842-1855; `rg "step_count" src/intellicrack/ui/panels/x64dbg_panel.py` returns zero hits | No widget anywhere in the single x64dbg panel file invokes it |
| 10 | Animate into/over/stop — OK/OK/NO-CONTROL | CONFIRMED | `animate_start()` x64dbg.py:7714-7743, `animate_stop()` x64dbg.py:7758+ (both poll `status` via `_wait_for_running_state`); tool-defs x64dbg.py:1857-1877; `rg "animate_start\|animate_stop"` in panel returns zero hits | No widget invokes either |
| 11 | Skip instruction — OK/OK/OK | CONFIRMED | `skip_instruction()` x64dbg.py:5973-5999 (disassembles current instruction via `disassemble_at`, computes real byte length from `bytes_str`, advances rip/eip by that length — not a stub); tool-def x64dbg.py:1410 area; `_on_skip` x64dbg_panel.py (Skip button, ~2097+) | Real length computation confirmed, not fixed increment |
| 12 | Software breakpoint — OK/OK/OK | CONFIRMED | `set_breakpoint(bp_type="software")` x64dbg.py:3142-3208, issues `bp_set` then verifies via `_verify_breakpoint_present`/`bp_list` round-trip, raises `ToolError` if not present; tool-def x64dbg.py:1094-1120 (`bp_type` param, enum incl. "software"); `_on_add_breakpoint` x64dbg_panel.py:1313-1338 (combo defaults "software") | Matches |
| 13 | Hardware breakpoint — OK/OK/OK | CONFIRMED | Same `set_breakpoint` method, `type_aliases` dict at x64dbg.py:3230-3234 includes `"hardware": {"hardware"}`; combo item "hardware" at x64dbg_panel.py:423-424 reaches same `_on_add_breakpoint` path | Single method correctly parameterized, same verified path |
| 14 | Memory breakpoint — OK/OK/OK | CONFIRMED | Same method/type_aliases include `"memory": {"memory"}`; combo item "memory" reaches same handler | Matches |
| 15 | Remove/clear breakpoint — OK/OK/OK | CONFIRMED | `remove_breakpoint()` x64dbg.py:~3340 (confirmed real, logs `breakpoint_removed` at x64dbg.py:3356); tool-def `x64dbg.remove_breakpoint` x64dbg.py:1121+; `_on_remove_breakpoint` x64dbg_panel.py:1370-1394 | Matches |
| 16 | Enable breakpoint — OK/OK/OK | CONFIRMED | `enable_breakpoint()` x64dbg.py:6175-6231 (queues `be`, polls `bp_list` for `enabled=True` via `_wait_for_breakpoint_enabled_state`, raises `ToolError` on failure — real verification, not a stub); tool-def x64dbg.py:1460+; `_on_enable_breakpoint` x64dbg_panel.py:1422-1440 | Matches exactly, verification pattern confirmed |
| 17 | Disable breakpoint — OK/OK/OK | CONFIRMED | `disable_breakpoint()` x64dbg.py:6238+ (same pattern for `bd`/`enabled=False`); tool-def x64dbg.py:1468+; `_on_disable_breakpoint` x64dbg_panel.py:1450-1468 | Matches |
| 18 | List/query breakpoints — OK/OK/OK | CONFIRMED | `get_breakpoints()` x64dbg.py:3358-3400+ (merges local `self._breakpoints` dict with live `bp_list` RPC result); tool-def x64dbg.py:1390+; `_refresh_breakpoints` x64dbg_panel.py:1854-1865 called from `_on_bp_added`/`_on_bp_removed`/toggle handlers | Matches, merge logic confirmed real (not local-only) |
| 19 | Conditional breakpoint — bridge OK / tool-def OK / GUI DEAD-CONTROL | CONFIRMED | `set_breakpoint(condition=...)` issues `bpcond` at x64dbg.py:3196 (within cited 3193-3197 range) after verification; `configure_breakpoint()` x64dbg.py:7498-7523 also issues `bpcond` (line 7522); tool-def `x64dbg.set_breakpoint` parameters include `condition` at x64dbg.py:1094-1120 (confirmed present, verified independently); `_build_bp_tab` (x64dbg_panel.py:398-462) has only address input + type combo, **no condition `QLineEdit`** (independently confirmed via `rg -i "condition" x64dbg_panel.py`, only hits are the `_BP_COLUMNS` table-header string, the read-only Condition table column populated from bridge data at line 1882, and the unrelated Trace-tab condition field); `_on_add_breakpoint` (x64dbg_panel.py:1313-1338) calls `set_breakpoint(address, bp_type=bp_type)` with no `condition=` kwarg passed at all | DEAD-CONTROL claim solid: capability exists at bridge+tool-def layers, GUI form structurally cannot express it |
| 20 | Logpoint — OK/OK/NO-CONTROL | CONFIRMED | `set_logging_breakpoint()` x64dbg.py:7481-7496 (`bp` + `SetBreakpointLog` + `SetBreakpointFastResume`, real commands); tool-def x64dbg.py:1773-1786; zero hits in panel via `rg "set_logging_breakpoint" x64dbg_panel.py` | No widget invokes it |
| 21 | Command-on-hit / configure_breakpoint — OK/OK/NO-CONTROL | CONFIRMED | `configure_breakpoint()` x64dbg.py:7498-7523 (bpcond/log/command/fast_resume all real `_send_command` calls); tool-def x64dbg.py:1788-1799; zero hits in panel | No widget invokes it |
| 22 | Breakpoint on API function — OK/OK/OK | CONFIRMED | `set_breakpoint_on_api()` x64dbg.py:6301+; tool-def x64dbg.py:1476+; `_on_set_api_bp` x64dbg_panel.py:2595-2613 (Module/Function inputs + "Set API BP" button) | Matches |
| 23 | Breakpoint on DLL load/unload — OK/OK/NO-CONTROL | CONFIRMED | `set_dll_breakpoint()` x64dbg.py:7531-7546 (`LibrarianSetBreakPoint`, real); tool-def x64dbg.py:1800-1814; zero hits in panel via `rg "set_dll_breakpoint" x64dbg_panel.py` | No widget invokes it |
| 24 | Exception breakpoint config — OK/OK/OK | CONFIRMED | `set_exception_config()` x64dbg.py:6753+; tool-def x64dbg.py:1540+; `_on_set_exception_config` x64dbg_panel.py:2838-2863 (exception code input + handling combo + Set button) | Matches |
| 25 | Start trace recording — OK/OK/OK | CONFIRMED | `trace_start()` x64dbg.py:6719+ (`StartRunTrace` + optional `TraceSetLog`/`TraceSetCondition`); tool-def x64dbg.py:1524+; `_on_trace_start` x64dbg_panel.py:2325-2339 (Trace tab Start button, reads condition/log inputs) | Matches |
| 26 | Stop trace recording — OK/OK/OK | CONFIRMED | `trace_stop()` x64dbg.py:6743+ (`StopRunTrace`); tool-def x64dbg.py:1534+; `_on_trace_stop` x64dbg_panel.py:2342-2352 | Matches |
| 27 | Trace into (conditional) — OK/OK/OK | CONFIRMED | `trace_into()` x64dbg.py:7548+ (`TraceIntoConditional`, verification pattern per docstring); tool-def x64dbg.py:1815-1823; `_on_trace_into` x64dbg_panel.py:2356-2369 | Matches |
| 28 | Trace over (conditional) — OK/OK/OK | CONFIRMED | `trace_over()` x64dbg.py:7596+ (`TraceOverConditional`, same pattern); tool-def x64dbg.py:1824-1832; `_on_trace_over` x64dbg_panel.py:2372-2385 | Matches |
| 29 | Query trace record/hit count — OK/OK/NO-CONTROL | CONFIRMED | `get_trace_record()` x64dbg.py:7641+ (`trace_record` RPC, returns hitCount); tool-def x64dbg.py:1833-1841; `_build_trace_tab` (x64dbg_panel.py:701-745) has only Condition/Log inputs + Start/Stop/Trace-Into/Trace-Over buttons + a scrolling read-only `QPlainTextEdit` log — no address-lookup control; zero hits via `rg "get_trace_record" x64dbg_panel.py` | No per-address query UI exists |

## Cross-cutting checks

- **Dispatch mechanism claim**: `ToolRegistry.execute_tool_call` in
  `src/intellicrack/core/tools.py:551-604` resolves purely via
  `attr_name = function_name.split(".", 1)[-1]` then
  `getattr(bridge, attr_name, None)` (tools.py:585-587), matching the report's
  description exactly (report cited 587-604; actual getattr line is 586-587,
  within the cited range, no material discrepancy).
- **No companion GUI files missed**: `fd -i "x64dbg" src/intellicrack/ui/`
  returns only `src/intellicrack/ui/panels/x64dbg_panel.py` — no `_tabs.py` or
  subdirectory split exists, so the NO-CONTROL grep sweep against the single
  panel file is exhaustive, not partial.
- **No false "restart" elsewhere**: the only other `restart` hits in the UI
  tree are in `sandbox_panel.py` (an unrelated Docker-sandbox restart button)
  and unrelated prose in `app.py` — confirmed irrelevant to x64dbg.
- **Row-count arithmetic**: recount of "fully-OK" rows
  {1,2,3,5,6,7,8,11,12,13,14,15,16,17,18,22,24,25,26,27,28} = 21 elements
  (verified by direct count, matches report's corrected recount at report
  lines 111-112). Total accounting 21 (OK) + 1 (MISSING, row 4) + 6
  (NO-CONTROL: rows 9,10,20,21,23,29) + 1 (DEAD-CONTROL: row 19) = 29,
  matching the 29-feature denominator. Math is internally consistent.
- **Tool-def `condition` parameter for row 19**: independently confirmed
  present at x64dbg.py:1094-1120 (`ToolParameter(name="condition", ...)`),
  validating the report's own footnoted caveat rather than refuting it.

## FALSE POSITIVES / NEEDS REVIEW

None. Every finding in the report was independently reproduced against current
source: all "OK" verdicts have real (non-stub) bridge implementations,
registered tool-defs reachable via `getattr`-based dispatch, and a genuinely
wired GUI control; all "NO-CONTROL" verdicts were confirmed via exhaustive
`rg` sweeps of the single panel file (no companion files exist to hide a
missed widget); the one "MISSING" (restart) was confirmed absent at all three
layers; the one "DEAD-CONTROL" (conditional breakpoints) was confirmed by
reading `_on_add_breakpoint` end-to-end and verifying no `condition=` value is
ever collected or forwarded, despite the bridge and tool-def layers fully
supporting it.

## Tally

- Findings checked: 29 (rows 1-29) + row-accounting/dispatch cross-checks
- Confirmed: 29
- False-positive: 0
- Needs-review: 0
