# Bridge Completeness Audit — Slice 1: x64dbg Execution Control

Scope: soft/hardware/memory/conditional breakpoints, stepping (into/over/out,
run-to), run/pause/restart, trace. Register/memory/module/thread state and
manipulation are explicitly out of scope for this slice.

Files audited:
- Bridge: `src/intellicrack/bridges/x64dbg.py` (9224 lines)
- Tool defs: same file, `X64DbgBridge.tool_definition` property, `src/intellicrack/bridges/x64dbg.py:1009-2049`
- Dispatch: `src/intellicrack/core/tools.py:551-650` (`ToolRegistry.execute_tool_call`)
- GUI: `src/intellicrack/ui/panels/x64dbg_panel.py` (2911 lines)

## Native ground truth (x64dbg execution control)

Source: [x64dbg Commands reference](https://help.x64dbg.com/en/latest/commands/),
[Breakpoint Control](https://help.x64dbg.com/en/latest/commands/breakpoint-control/),
[Conditional Breakpoints](https://help.x64dbg.com/en/latest/introduction/ConditionalBreakpoint.html),
[Stepping and Execution Control (DeepWiki)](https://deepwiki.com/x64dbg/x64dbg/2.3-stepping-and-execution-control),
[SetBreakpointCommand](https://help.x64dbg.com/en/latest/commands/conditional-breakpoint-control/SetBreakpointCommand.html).

Feature list (denominator), grouped:

**Run / pause / stop / restart**
1. Run/Continue (`run`/`go`, F9)
2. Pause (`pause`)
3. Stop/terminate debuggee (`stop`)
4. Restart debuggee from scratch (Ctrl+F2 `InitDebug` re-issue on same target)

**Stepping**
5. Step into (`sti`, F7)
6. Step over (`sto`, F8)
7. Step out / execute till return (`erun`)
8. Run to cursor / run to address (`runto`, F4)
9. Step N times (`tic`/`toc` counted step)
10. Animate (continuous step) into/over (`AnimateInto`/`AnimateOver`/`AnimateStop`)
11. Skip current instruction without executing it

**Breakpoints**
12. Set software breakpoint (`bp`)
13. Set hardware breakpoint (`bph`, exec/read/write, size 1/2/4/8)
14. Set memory breakpoint (`bpm`, guard-page based)
15. Remove/clear breakpoint (`bc`)
16. Enable breakpoint (`be`)
17. Disable breakpoint (`bd`)
18. List/query breakpoints (`bplist`)
19. Conditional breakpoint (`bpcond` — break condition expression)
20. Breakpoint log text / non-stopping "logpoint" (`SetBreakpointLog`, `SetBreakpointFastResume`)
21. Breakpoint command-on-hit (`SetBreakpointCommand`)
22. Breakpoint on API/library function (`bp kernel32.CreateFileW`-style resolution)
23. Breakpoint on DLL load/unload (`LibrarianSetBreakPoint`)
24. Exception breakpoint configuration (`SetExceptionBPX` — break/ignore/log on exception code)

**Trace**
25. Start run trace recording (`StartRunTrace`)
26. Stop run trace recording (`StopRunTrace`)
27. Trace into with condition (`TraceIntoConditional`)
28. Trace over with condition (`TraceOverConditional`)
29. Query trace record / hit count at address (`TraceRecord` query)

Total native features in scope: **29**.

(`set_ip` / instruction-pointer register write is register-state manipulation
and is out of scope per the slice boundary, even though the bridge exposes it
adjacent to `skip_instruction`; it is not counted in the denominator or matrix
below.)

## Coverage matrix

| # | Native feature | Bridge method (file:line) | Tool-def | GUI control |
|---|---|---|---|---|
| 1 | Run/continue | OK `run()` x64dbg.py:2988 | OK `x64dbg.run` x64dbg.py:1058 | OK Run button → `_on_run` x64dbg_panel.py:134,1124-1131 |
| 2 | Pause | OK `pause()` x64dbg.py:2993 | OK `x64dbg.pause` x64dbg.py:1064 | OK Pause button → `_on_pause` x64dbg_panel.py:135,1156-1167 |
| 3 | Stop/terminate | OK `stop()` x64dbg.py:2998 | OK `x64dbg.stop` x64dbg.py:1070 | OK Stop button → `_on_stop` x64dbg_panel.py:136,1189-1205 |
| 4 | Restart debuggee | MISSING — no method issues `InitDebug` against the already-loaded target path/PID; only `load()` (x64dbg.py:2733) performs a fresh `InitDebug`, which requires the caller to resupply a path and re-detect architecture, not a native "restart current session" | MISSING (no `x64dbg.restart` entry, x64dbg.py:1018-2049) | NO-CONTROL — no restart button/action in toolbar (x64dbg_panel.py:126-190) |
| 5 | Step into | OK `step_into()` x64dbg.py:3096 (via `_await_step_complete`, real paused-event synchronization, not a stub sleep) | OK `x64dbg.step_into` x64dbg.py:1076 | OK Step Into button → `_on_step_into` x64dbg_panel.py:140,1221-1235 |
| 6 | Step over | OK `step_over()` x64dbg.py:3112 | OK `x64dbg.step_over` x64dbg.py:1082 | OK Step Over button → `_on_step_over` x64dbg_panel.py:141,1237-1250 |
| 7 | Step out / til return | OK `step_out()` x64dbg.py:3127 (single-frame step-out) AND `execute_til_return()` x64dbg.py:5963 (`erun` full return) — both real | OK `x64dbg.step_out` x64dbg.py:1088; OK `x64dbg.execute_til_return` x64dbg.py:1404 | OK Step Out button → `_on_step_out` x64dbg_panel.py:142,1253-1266; OK "Til Ret" button → `_on_til_ret` x64dbg_panel.py:151,2083-2095 |
| 8 | Run to address | OK `run_to()` x64dbg.py:5416 (queues `runto`, polls `reg_get rip` to verify landing, raises `ToolError` on timeout — real verification, not a fire-and-forget) | OK `x64dbg.run_to` x64dbg.py:1396 | OK "Run To" input+Go button → `_on_run_to` x64dbg_panel.py:148-150,2055-2081 |
| 9 | Step N times | OK `step_count()` x64dbg.py:7666 (`tic`/`toc` with count, verifies debugger returns to paused via `status` polling) | OK `x64dbg.step_count` x64dbg.py:1842 | NO-CONTROL — no widget in panel invokes `step_count` (verified absent via grep of x64dbg_panel.py) |
| 10 | Animate into/over/stop | OK `animate_start()` x64dbg.py:7714, `animate_stop()` x64dbg.py:7758 (both verify running/paused state transition via `status` polling) | OK `x64dbg.animate_start` x64dbg.py:1857; OK `x64dbg.animate_stop` x64dbg.py:1871 | NO-CONTROL — no widget invokes `animate_start`/`animate_stop` (verified absent) |
| 11 | Skip instruction | OK `skip_instruction()` x64dbg.py:5973 (disassembles current instruction, computes real length, advances IP by that length) | OK `x64dbg.skip_instruction` x64dbg.py:1410 | OK "Skip" button → `_on_skip` x64dbg_panel.py:152,2097-2122 |
| 12 | Software breakpoint | OK `set_breakpoint(bp_type="software")` x64dbg.py:3142 (issues `bp_set`, verifies via `bp_list` round-trip, raises if plugin silently rejects) | OK `x64dbg.set_breakpoint` x64dbg.py:1094 | OK Add BP button + type combo ("software" default) → `_on_add_breakpoint` x64dbg_panel.py:413-429,1313-1346 |
| 13 | Hardware breakpoint | OK `set_breakpoint(bp_type="hardware")` — same method, type-aliased verification x64dbg.py:3254-3259 | OK same `x64dbg.set_breakpoint` entry (type is a parameter) | OK reachable via `_bp_type_combo` item "hardware" x64dbg_panel.py:424-425 → same `_on_add_breakpoint` path |
| 14 | Memory breakpoint | OK `set_breakpoint(bp_type="memory")` — same method/verification | OK same `x64dbg.set_breakpoint` entry | OK reachable via `_bp_type_combo` item "memory" x64dbg_panel.py:424-425 → same `_on_add_breakpoint` path |
| 15 | Remove/clear breakpoint | OK `remove_breakpoint()` x64dbg.py:3340 | OK `x64dbg.remove_breakpoint` x64dbg.py:1121 | OK Remove BP button → `_on_remove_breakpoint` x64dbg_panel.py:431-433,1370-1395 |
| 16 | Enable breakpoint | OK `enable_breakpoint()` x64dbg.py:6175 (queues `be`, polls `bp_list` for `enabled=True`, raises on verification failure) | OK `x64dbg.enable_breakpoint` x64dbg.py:1460 | OK Enable BP button → `_on_enable_breakpoint` x64dbg_panel.py:453-455,1422-1444 |
| 17 | Disable breakpoint | OK `disable_breakpoint()` x64dbg.py:6238 (same verification pattern for `bd`/`enabled=False`) | OK `x64dbg.disable_breakpoint` x64dbg.py:1468 | OK Disable BP button → `_on_disable_breakpoint` x64dbg_panel.py:457-459,1450-1472 |
| 18 | List/query breakpoints | OK `get_breakpoints()` x64dbg.py:3358 (merges local registry with live `bp_list`) | OK `x64dbg.get_breakpoints` x64dbg.py:1390 | OK breakpoints table auto-populated via `_refresh_breakpoints` x64dbg_panel.py:1854-1866, called after every add/remove/enable/disable |
| 19 | Conditional breakpoint | OK bridge-side: `set_breakpoint(condition=...)` issues `bpcond` after verification x64dbg.py:3193-3197; also standalone `configure_breakpoint(condition=...)` x64dbg.py:7499-7522 (`bpcond` console command) | OK `x64dbg.set_breakpoint` has a `condition` parameter x64dbg.py:1094-1120 (need to confirm param present — see note below); OK `x64dbg.configure_breakpoint` x64dbg.py:1788 | DEAD-CONTROL — Add-BP form has address input + type combo only, **no condition text field** (x64dbg_panel.py:413-430); `_on_add_breakpoint` (x64dbg_panel.py:1313-1346) calls `set_breakpoint(address, bp_type=bp_type)` and never passes `condition`, so the bridge's conditional-breakpoint capability is unreachable from this control. `configure_breakpoint` (which also sets `bpcond`) has **no control at all** (NO-CONTROL, see row 21) |
| 20 | Logpoint (log text, non-stopping) | OK `set_logging_breakpoint()` x64dbg.py:7481 (`bp` + `SetBreakpointLog` + `SetBreakpointFastResume`) | OK `x64dbg.set_logging_breakpoint` x64dbg.py:1773 | NO-CONTROL — no widget invokes `set_logging_breakpoint` (verified absent via grep) |
| 21 | Command-on-hit / generic breakpoint config | OK `configure_breakpoint()` x64dbg.py:7499 (`bpcond`, `SetBreakpointLog`, `SetBreakpointCommand`, `SetBreakpointFastResume`) | OK `x64dbg.configure_breakpoint` x64dbg.py:1788 | NO-CONTROL — no widget invokes `configure_breakpoint` (verified absent) |
| 22 | Breakpoint on API function | OK `set_breakpoint_on_api()` x64dbg.py:6301 | OK `x64dbg.set_breakpoint_on_api` x64dbg.py:1476 | OK Module/Function inputs + "Set API BP" button → `_on_set_api_bp` x64dbg_panel.py:435-451,2595-2614 |
| 23 | Breakpoint on DLL load/unload | OK `set_dll_breakpoint()` x64dbg.py:7531 (`LibrarianSetBreakPoint`) | OK `x64dbg.set_dll_breakpoint` x64dbg.py:1800 | NO-CONTROL — no widget invokes `set_dll_breakpoint` (verified absent) |
| 24 | Exception breakpoint config | OK `set_exception_config()` x64dbg.py:6753 (`SetExceptionBPX`, maps break/ignore/log) | OK `x64dbg.set_exception_config` x64dbg.py:1540 | OK exception code input + handling combo + Set button → `_on_set_exception_config` x64dbg_panel.py:595-597,2838-2866 |
| 25 | Start trace recording | OK `trace_start()` x64dbg.py:6719 (`StartRunTrace`, optional per-address log/condition via `TraceSetLog`/`TraceSetCondition`) | OK `x64dbg.trace_start` x64dbg.py:1524 | OK Trace tab Start button → `_on_trace_start` x64dbg_panel.py:725-727,2325-2340 |
| 26 | Stop trace recording | OK `trace_stop()` x64dbg.py:6743 (`StopRunTrace`) | OK `x64dbg.trace_stop` x64dbg.py:1534 | OK Trace tab Stop button → `_on_trace_stop` x64dbg_panel.py:729-731,2342-2354 |
| 27 | Trace into (conditional) | OK `trace_into()` x64dbg.py:7548 (`TraceIntoConditional`, verifies running-state transition via `status` polling) | OK `x64dbg.trace_into` x64dbg.py:1815 | OK Trace tab "Trace Into" button → `_on_trace_into` x64dbg_panel.py:733-735,2356-2370 |
| 28 | Trace over (conditional) | OK `trace_over()` x64dbg.py:7596 (`TraceOverConditional`, same verification pattern) | OK `x64dbg.trace_over` x64dbg.py:1824 | OK Trace tab "Trace Over" button → `_on_trace_over` x64dbg_panel.py:737-739,2372-2386 |
| 29 | Query trace record/hit count | OK `get_trace_record()` x64dbg.py:7641 (`trace_record` RPC, returns hit count at address) | OK `x64dbg.get_trace_record` x64dbg.py:1833 | NO-CONTROL — no widget invokes `get_trace_record`; the Trace tab has no per-address hit-count query UI (only a scrolling text log, x64dbg_panel.py:743-747) |

Note on row 19 tool-def: `x64dbg.set_breakpoint`'s `ToolFunction` parameter list
was confirmed to include `condition` at x64dbg.py:1094-1120 (parameters:
`address`, `bp_type`, `condition`), so orchestration/AI callers CAN set
conditional breakpoints through the tool-call path — the gap is GUI-only.

## Coverage summary

- **29 native features** in scope for this slice.
- **20 of 29 fully ported** (all three layers OK): rows 1,2,3,5,6,7,8,11,12,13,14,15,16,17,18,22,24,25,26,27,28 — that's actually 21; recount below.

Recount (explicit list of fully-OK rows): 1, 2, 3, 5, 6, 7, 8, 11, 12, 13, 14,
15, 16, 17, 18, 22, 24, 25, 26, 27, 28 = **21 of 29 fully ported**.

Gap-type counts:
- **MISSING** (bridge layer, no implementation at all): 1 — restart (row 4)
- **NOT-REGISTERED** (implemented, no tool-def): 0
- **NO-CONTROL** (bridge + tool-def OK, no GUI widget at all): 6 — step_count (9), animate_start/stop (10), set_logging_breakpoint (20), configure_breakpoint (21), set_dll_breakpoint (23), get_trace_record (29). That is 6 rows (10 counts as one row covering two methods).
- **DEAD-CONTROL** (widget exists but doesn't exercise the full capability): 1 — conditional breakpoints (row 19): the address/type form exists and is wired, but never plumbs a `condition` value into `set_breakpoint`, and the dedicated `configure_breakpoint` control doesn't exist either.
- **STUB**: 0 — every implemented method performs real IPC calls to the x64dbg plugin, and most (`step_into/over/out`, `run_to`, `enable/disable_breakpoint`, `trace_into/over`, `step_count`, `animate_start/stop`) go further and poll the plugin's actual debugger state (`status`, `bp_list`, `reg_get rip`) to verify the command actually took effect before returning success, per the `audit6.md`/`audit7.md` remediation comments embedded in the docstrings.

Row accounting: 21 OK + 1 MISSING row (also NO-CONTROL/no tool-def by extension) + 6 NO-CONTROL rows + 1 DEAD-CONTROL row = 29 rows. (Row 4's bridge/tool-def cells are marked MISSING and its GUI cell NO-CONTROL; it is counted once in the "not fully ported" set, not double-counted across gap types.)

Orphans checked: no GUI control in the panel invokes an execution-control
method that lacks a matching native feature, and no `_td`/tool-definition
entry references a nonexistent bridge method — `execute_tool_call`
(`src/intellicrack/core/tools.py:587-604`) resolves purely via
`getattr(bridge, attr_name)`, and every `x64dbg.<name>` tool-def name in the
execution-control set has a same-named async method confirmed present above.

## Prioritized gap list

1. **Restart debuggee (row 4)** — highest impact. Native x64dbg exposes a
   one-click "restart" (Ctrl+F2) that re-runs `InitDebug` against the
   currently loaded target without the caller re-supplying a path. Today the
   only path back to a running session is calling `load()` again
   (`src/intellicrack/bridges/x64dbg.py:2733`), which requires the caller
   (GUI or orchestrator) to already be holding the original path/args and
   re-does architecture detection from scratch — there's no bridge-level
   concept of "restart current session." Fix requires new work at all three
   layers: a `restart()` method on `X64DbgBridge` in
   `src/intellicrack/bridges/x64dbg.py` (near `load`/`stop`, reusing
   `self._binary_path` and stored args), a new `x64dbg.restart` `ToolFunction`
   entry in the `tool_definition` property (`x64dbg.py:1009-2049`), and a
   toolbar button wired via `run_bridge_coroutine_logged` in
   `src/intellicrack/ui/panels/x64dbg_panel.py` (alongside `_run_btn`/`_stop_btn`,
   ~line 134-136).

2. **Conditional breakpoints unreachable from the GUI (row 19)** —
   second-highest impact: this is a core, frequently-used x64dbg feature
   (right-click "Edit breakpoint" → condition) and the bridge already fully
   supports it (`set_breakpoint(..., condition=...)` at
   `src/intellicrack/bridges/x64dbg.py:3142`, and the more general
   `configure_breakpoint` at `x64dbg.py:7499`), but
   `src/intellicrack/ui/panels/x64dbg_panel.py:1313-1346` (`_on_add_breakpoint`)
   never collects or forwards a condition string. Fix: add a condition
   `QLineEdit` to the breakpoint toolbar (`x64dbg_panel.py:413-430`) and pass
   its (optional) text through to `set_breakpoint(address, bp_type=bp_type,
   condition=condition or None)`.

3. **No GUI surface for `configure_breakpoint` / logpoints / DLL
   breakpoints / step_count / animate / trace_record query (rows 9, 10, 20,
   21, 23, 29)** — six real, verified bridge methods with registered tool
   definitions that are only reachable via AI/orchestration tool-calls, never
   from the panel itself. Lower priority individually, but collectively a
   large swath of advanced execution-control functionality (logpoints,
   DLL-load breakpoints, animate/counted-step, breakpoint command-on-hit,
   trace-hit-count lookup) is GUI-invisible. Fix would add corresponding
   controls to `src/intellicrack/ui/panels/x64dbg_panel.py`: a "DLL BP"
   input+button near the API-breakpoint controls (~line 449), a
   log-text/command field in the breakpoint tab tied to
   `configure_breakpoint`/`set_logging_breakpoint`, step-count and
   animate-into/over controls near the stepping toolbar (~line 140-142), and
   an address-lookup control in the Trace tab (~line 701-747) for
   `get_trace_record`.
