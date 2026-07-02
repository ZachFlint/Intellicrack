# Verification — x64dbg Remediation (Slices 1 & 2)

Independent, adversarial re-verification of the x64dbg remediation waves
against `src/intellicrack/bridges/x64dbg.py`, `src/intellicrack/core/tools.py`,
`src/intellicrack/bridges/base.py`, `src/intellicrack/ui/panels/x64dbg_panel.py`,
and the new `src/intellicrack/ui/panels/x64dbg_advanced_tab.py`. Read-only for
`src/` — no application code was modified during this review. All file:line
citations below were independently re-derived via `rg`/direct reads.

## PART A — Three-layer verification

Scope: every row marked non-OK in `agent-01-x64dbg-execution-control.md`
(29-row execution-control matrix) and `agent-02-x64dbg-state-manipulation.md`
(60-row state/manipulation matrix), plus the two cross-cutting defects
(`disassemble` tool-def mismatch, missing `restart`).

### Cross-cutting defects (highest priority)

| Item | Status | Evidence |
|---|---|---|
| `x64dbg.disassemble_at` tool-def renamed to match real method | RESOLVED | `ToolFunction(name="x64dbg.disassemble_at", ...)` at `x64dbg.py:1205-1223`; no `x64dbg.disassemble` entry anywhere (`rg '"x64dbg\.disassemble"'` returns zero hits). Real method `async def disassemble_at` at `x64dbg.py:4066`. |
| `X64DbgBridge` declares `supports_static_analysis=True` | RESOLVED | `x64dbg.py:816-825`, `BridgeCapabilities(supports_static_analysis=True, ...)`. `TOOL_CAPABILITY_MAP["disassemble_at"] = "static_analysis"` (`base.py:64`) is now satisfied, so `ToolRegistry.execute_tool_call`'s capability gate (`core/tools.py:678-697`) no longer blocks the call. |
| `x64dbg.restart` L1 method | RESOLVED | `async def restart(self)` at `x64dbg.py:7804-7880`. Real implementation: guards on `self._binary_path is None` (raises `ToolError`), re-issues `InitDebug "<path>"[, "<args>"]` against the bridge's own stored `_binary_path`/`_launch_args` (not a fresh `load()`), captures PID via `reg_get $pid`, and polls `status` via `_wait_for_running_state` to verify the debugger actually returned to paused before reporting success (raises `ToolError` on timeout). Not a stub. |
| `x64dbg.restart` L2 tool-def | RESOLVED | `ToolFunction(name="x64dbg.restart", ...)` at `x64dbg.py:1077-1082`. Dispatch: `getattr(bridge, "restart")` resolves via `core/tools.py:659-660`; `TOOL_CAPABILITY_MAP["restart"] = "debugging"` (`base.py:88`), which `X64DbgBridge` already supports. |
| `x64dbg.restart` L3 GUI | RESOLVED | Toolbar `_restart_btn` at `x64dbg_panel.py:144`, added to toolbar layout at `:188`; handler `_on_restart` (`:1295-1309`) calls `self._bridge.restart()` via `run_bridge_coroutine_logged`; success/error handlers at `:1311-1339` update console output. |

### Slice 1 — Execution control (previously non-OK rows)

| # | Feature | L1 | L2 | L3 | Status |
|---|---|---|---|---|---|
| 4 | Restart debuggee | `restart()` x64dbg.py:7804 | `x64dbg.restart` x64dbg.py:1077 | `_restart_btn`→`_on_restart` x64dbg_panel.py:144,1295 | **RESOLVED — OK/OK/OK** |
| 9 | Step N times (`step_count`) | OK (pre-existing) x64dbg.py:7666 | OK (pre-existing) | `rg "step_count" x64dbg_panel.py x64dbg_advanced_tab.py` = zero hits | **STILL NO-CONTROL** |
| 10 | Animate into/over/stop | OK (pre-existing) x64dbg.py:7714,7767 | OK (pre-existing) | `rg "animate_start\|animate_stop"` in both panel files = zero hits | **STILL NO-CONTROL** |
| 19 | Conditional breakpoint (GUI DEAD-CONTROL) | OK (pre-existing) `set_breakpoint(condition=...)` | OK (pre-existing) | Add-BP form (`_build_bp_tab`, x64dbg_panel.py:420-452) still has no condition `QLineEdit`; `_on_add_breakpoint` (x64dbg_panel.py:1433-1466) still calls `set_breakpoint(address, bp_type=bp_type)` with **no `condition=` kwarg**. Confirmed via direct read, `rg "_bp_cond"` = zero hits. | **STILL DEAD-CONTROL (documented, honestly test-gated — see Part B)** |
| 20 | Logpoint (`set_logging_breakpoint`) | OK (pre-existing) | OK (pre-existing) | `X64DbgAdvancedTab._build_breakpoint_config_tab` → `_on_set_logging_breakpoint` x64dbg_advanced_tab.py:719-740, wired to `_bpcfg_logging_btn` | **RESOLVED — OK/OK/OK** |
| 21 | `configure_breakpoint` (cmd-on-hit) | OK (pre-existing) | OK (pre-existing) | `X64DbgAdvancedTab._on_configure_breakpoint` x64dbg_advanced_tab.py:690-717, wired to `_bpcfg_apply_btn` | **RESOLVED — OK/OK/OK** |
| 23 | DLL load/unload breakpoint | OK (pre-existing) | OK (pre-existing) | `X64DbgAdvancedTab._on_set_dll_breakpoint` x64dbg_advanced_tab.py:742-761, wired to `_bpcfg_dll_btn` | **RESOLVED — OK/OK/OK** |
| 29 | Query trace record/hit count | OK (pre-existing) x64dbg.py:7641 | OK (pre-existing) | `rg "get_trace_record"` in both panel files = zero hits; Trace tab still has only Condition/Log + Start/Stop/Into/Over, no address-lookup control | **STILL NO-CONTROL** |

Slice 1 residual: **4 of 8 previously non-OK rows genuinely closed** (rows 4,
20, 21, 23). **3 rows remain open** (9 step_count, 10 animate, 29
get_trace_record — none wired anywhere, including the new Advanced tab). **1
row remains an honestly-documented DEAD-CONTROL** (19, conditional
breakpoints) — the plan's Wave-3 Agent-G mandate named "Patches window,
Labels/Comments, restart, NO-CONTROL state/manip methods" but did not
explicitly commit to closing row 19; it is not closed, but the residual gap
is now backed by a real, correctly-designed regression test (Part B) instead
of being silently dropped.

### Slice 2 — State & manipulation (previously non-OK rows)

| # | Feature | L1/L2 | L3 | Status |
|---|---|---|---|---|
| 8 | `scan_memory` (indirect-only) | OK (pre-existing) | Still only indirect via `find_pattern`; no direct control in either panel file | **UNCHANGED (low-priority, correctly deprioritized — `find_pattern` covers the user workflow)** |
| 14 | Module imports | OK (pre-existing) | `X64DbgAdvancedTab._on_get_module_imports` x64dbg_advanced_tab.py:151-168, table populated at `:170-187` | **RESOLVED — OK/OK/OK** |
| 15 | Module entry point | OK (pre-existing) | `X64DbgAdvancedTab._on_get_entry_point` x64dbg_advanced_tab.py:189-203, label rendered at `:205-219` | **RESOLVED — OK/OK/OK** |
| 16 | PE data directories | OK (pre-existing) | `X64DbgAdvancedTab._on_get_pe_directories` x64dbg_advanced_tab.py:221-238, table at `:240-256` | **RESOLVED — OK/OK/OK** |
| 21 | Rename thread (`set_thread_name`) | OK (pre-existing) x64dbg.py:7261 | `_on_rename_thread` x64dbg_panel.py:3242-3271, `_rename_thread_btn`/`_thread_name_input` | **RESOLVED — OK/OK/OK** |
| 23 | SEH chain | OK (pre-existing) x64dbg.py:7318 | `X64DbgAdvancedTab._on_get_seh_chain` x64dbg_advanced_tab.py:387-399 | **RESOLVED — OK/OK/OK** |
| 24 | Read PEB | OK (pre-existing) x64dbg.py:7339 | `X64DbgAdvancedTab._on_read_peb` x64dbg_advanced_tab.py:329-341 | **RESOLVED — OK/OK/OK** |
| 25 | Read TEB | OK (pre-existing) x64dbg.py:7367 | `X64DbgAdvancedTab._on_read_teb` x64dbg_advanced_tab.py:353-375 | **RESOLVED — OK/OK/OK** |
| 26 | `assemble_at` (bytes-only preview) | OK (pre-existing) x64dbg.py:4140 | `_on_assemble_preview` x64dbg_panel.py:3093-3120, distinct from `patch_instruction`'s Assemble control | **RESOLVED — OK/OK/OK** |
| 29 | List patches | OK (pre-existing) x64dbg.py:7057 | Patches tab `_build_patches_tab` x64dbg_panel.py:687-, `_on_refresh_patches`/`_apply_patches` x64dbg_panel.py:2853-2884 | **RESOLVED — OK/OK/OK** |
| 30 | Restore patch | OK (pre-existing) x64dbg.py:7078 | `_on_restore_patch` x64dbg_panel.py:2886-2917 | **RESOLVED — OK/OK/OK** |
| 31 | Export patches | OK (pre-existing) x64dbg.py:7100 | `_on_export_patches` x64dbg_panel.py:2919-2944 | **RESOLVED — OK/OK/OK** |
| 33 | Get/list labels | OK (pre-existing) x64dbg.py:6072 | `_lbl_table` now populated: `_on_refresh_labels`/`_apply_labels` x64dbg_panel.py:2562-2593; auto-refresh after `set_label` via `_on_label_set` x64dbg_panel.py:2553-2560; row-click populates edit fields via `_on_label_row_selected` x64dbg_panel.py:2595-2609 | **RESOLVED — OK/OK/OK (populate + edit, per plan mandate)** |
| 35 | Get/list comments | OK (pre-existing) x64dbg.py:6141 | Symmetric fix: `_on_refresh_comments`/`_apply_comments` x64dbg_panel.py:2650-2681, auto-refresh via `_on_comment_set` x64dbg_panel.py:2641-2648, row-click via `_on_comment_row_selected` x64dbg_panel.py:2683-2697 | **RESOLVED — OK/OK/OK** |
| 36-38 | Watch add/remove/list | OK (pre-existing) x64dbg.py:7416,7438,7460 | `X64DbgAdvancedTab` Watches sub-tab, `_on_add_watch`/`_on_remove_watch`/`_on_refresh_watches` x64dbg_advanced_tab.py:482-566 | **RESOLVED — OK/OK/OK** |
| 39 | `configure_breakpoint` | (see slice-1 row 21) | (see slice-1 row 21) | **RESOLVED** |
| 40 | `set_logging_breakpoint` | (see slice-1 row 20) | (see slice-1 row 20) | **RESOLVED** |
| 41 | `set_dll_breakpoint` | (see slice-1 row 23) | (see slice-1 row 23) | **RESOLVED** |
| 44 | Function CFG | OK (pre-existing) x64dbg.py:6971 | `X64DbgAdvancedTab._on_get_function_cfg` x64dbg_advanced_tab.py:900-916, table render at `:918-943` | **RESOLVED — OK/OK/OK** |
| 45 | Find references (xref) | OK (pre-existing) x64dbg.py:6917 | `X64DbgAdvancedTab._on_find_references` x64dbg_advanced_tab.py:881-898 | **RESOLVED — OK/OK/OK** |
| 46 | Find string references | OK (pre-existing) x64dbg.py:6935 | `X64DbgAdvancedTab._on_find_string_references` x64dbg_advanced_tab.py:945-962 | **RESOLVED — OK/OK/OK** |
| 47 | Find intermodular calls | OK (pre-existing) x64dbg.py:6953 | `X64DbgAdvancedTab._on_find_intermodular_calls` x64dbg_advanced_tab.py:964-981 | **RESOLVED — OK/OK/OK** |
| 50 | Clear database | OK (pre-existing) x64dbg.py:7029 (approx) | `_on_clear_db` x64dbg_panel.py:2309-2320 | **RESOLVED — OK/OK/OK** |
| 51-52 | Enumerate/close handles | OK (pre-existing) x64dbg.py:8258,8376 | `X64DbgAdvancedTab` Handles sub-tab, `_on_refresh_handles`/`_on_close_handle` x64dbg_advanced_tab.py:1039-1119 | **RESOLVED — OK/OK/OK** |
| 53-56 | Script load/run/cmd/abort | OK (pre-existing) x64dbg.py:7996,8037,8073,8113 | `X64DbgAdvancedTab` Script sub-tab, `_on_script_load/_run/_cmd/_abort` x64dbg_advanced_tab.py:1200-1266 | **RESOLVED — OK/OK/OK** |
| 57-59 | Load/unload/list plugins | OK (pre-existing) x64dbg.py:8150,8194,8236 | `X64DbgAdvancedTab` Plugins sub-tab, `_on_plugin_load/_unload/_on_refresh_plugins` x64dbg_advanced_tab.py:1357-1418 | **RESOLVED — OK/OK/OK** |

Slice 2 residual: **31 of 32 previously-NO-CONTROL rows and both
previously-DEAD-CONTROL rows are genuinely closed.** Only row 8
(`scan_memory` indirect-only reachability) remains as before — correctly
deprioritized since `find_pattern` already covers the wildcard-search
workflow and `scan_memory`'s exact-byte variant has no distinct native GUI
counterpart in x64dbg itself either.

### Wiring integrity checks

- `X64DbgAdvancedTab` is genuinely instantiated and wired into the panel: `from
  intellicrack.ui.panels.x64dbg_advanced_tab import X64DbgAdvancedTab`
  (x64dbg_panel.py:43), `self._advanced_tab = X64DbgAdvancedTab()` +
  `tabs.addTab(self._advanced_tab, self.tr("Advanced"))`
  (x64dbg_panel.py:416-417), and `self._advanced_tab.set_bridge(bridge)`
  (x64dbg_panel.py:1002) is called wherever the panel's own bridge is set —
  confirmed the advanced tab is not an orphaned, disconnected widget.
- Every `X64DbgAdvancedTab` handler above genuinely routes through
  `run_bridge_coroutine_logged` (`ui/panels/async_bridge.py`), not a
  synchronous/blocking call or a local reimplementation — confirmed by
  reading every `_on_*` handler in `x64dbg_advanced_tab.py`.
- No regressions found in the previously-OK rows: spot-checked rows 1-3, 5-8,
  11-18, 22, 27-28, 32, 34, 42-43, 48-49, 60 remain wired exactly as the
  original audit described; none of the touched files show signs of a
  deleted binding.

## PART B — Test-gate review

Reviewed all three test modules under `tests/test_bridge_completeness/x64dbg/`
plus the shared `conftest.py`.

### `conftest.py` (shared fixtures/doubles)

**VERDICT: SOUND, not a fake-gate mechanism itself.** `FakePipeClient`
substitutes only the single genuine external boundary that cannot execute in
the Docker sandbox — the named-pipe transport to the x64dbg plugin process
(`NamedPipeClient.send_command`). This is the same test-double pattern already
established in `tests/test_bridges/test_x64dbg_wave2b_breakpoints.py` per the
module docstring (verified this is a pre-existing, accepted convention, not a
new mock-the-thing-under-test pattern). Everything upstream — RPC command
selection, parameter framing, response parsing, bookkeeping, GUI wiring, table
rendering — is real, unmodified production code and is what every assertion is
falsified by. `pump_until` correctly drives the real Qt event loop rather than
using a bare `sleep()`-and-hope.

### `test_x64dbg_restart_and_disassemble_dispatch.py`

| Test | Verdict | Reason |
|---|---|---|
| `test_restart_without_prior_load_raises_tool_error` | REAL GATE | Exercises the real `restart()` guard; falsified by removing the `_binary_path is None` check. |
| `test_restart_reissues_init_debug_with_stored_path_and_args` | REAL GATE | Exact-string assertion on the recorded `exec` command (`InitDebug "<path>", "<args>"`), sourced from values the test itself injected into bridge state — a legitimate independent oracle since the test controls the input and asserts the exact command the production code must derive from it, not a re-implementation of `restart()`'s logic. |
| `test_restart_without_launch_args_omits_args_clause` | REAL GATE | Confirms the conditional args-clause omission; would catch a regression that always appends args. |
| `test_restart_raises_tool_error_when_never_paused` | REAL GATE | Verified `VERIFY_TIMEOUT`/`VERIFY_POLL_INTERVAL` are real bridge attributes shortened for test speed, not skipped — `status` responder returns `paused: False` forever, forcing the real timeout path. |
| `test_restart_tool_def_registered` | REAL GATE | Direct membership check on `bridge.tool_definition.functions`; falsified by removing the tool-def entry. |
| `test_restart_dispatchable_via_tool_registry` | REAL GATE | Drives the actual `ToolRegistry.execute_tool_call`, not a bypass — catches the exact `getattr` name-mismatch defect class documented in the audit. |
| `test_restart_button_exists_and_is_wired` | REAL GATE | `receivers(clicked) >= 1` on a real `QPushButton` — genuine signal-connection check, not a repaint/existence-only check. |
| `test_restart_button_click_invokes_bridge_restart_and_updates_console` | REAL GATE | End-to-end: real button click → real coroutine → real fake-pipe `InitDebug` command recorded → real console text. Falsified by rewiring `_on_restart` to any other method. |
| `test_disassemble_tool_def_name_is_disassemble_at` | REAL GATE | Direct regression test for the exact historical defect (asserts both presence of the fixed name and absence of the broken name). |
| `test_bridge_declares_static_analysis_capability` | REAL GATE | Direct attribute check tied to the capability-gate defect. |
| `test_disassemble_at_dispatches_and_decodes_real_process_memory` | REAL GATE, HIGH QUALITY | Genuinely real input (the live test-runner process's own module image via `GetModuleHandleW`) and a genuinely independent oracle (Capstone, a trusted third-party disassembler, decoding real executable memory) — not a hand-built dict, not re-implemented decode logic. Exercises the full registry dispatch path. |

**Verdict: all 11 tests are real, falsifiable gates. Zero non-gates.**

### `test_x64dbg_patches_tab_l3.py`

All 5 tests (widget-existence, signal-connection, refresh-populates-table
with exact address/oldByte/newByte values verified against the RPC responder,
restore-sends-exact-address, export-issues-exact-`savedata`-command) were
independently cross-checked against the real bridge methods
(`get_patches`→`patch_list`, `restore_patch`→`patch_restore` with
`{"address": hex(...)}}`, `export_patches`→`savedata "<path>"`) at
`x64dbg.py:7057-7111`. Every command name and parameter shape the tests assert
matches the real bridge implementation exactly.

**Verdict: all 5 tests are real, falsifiable gates. Zero non-gates.**

### `test_x64dbg_annotations_l3.py`

Independently confirmed `lbl_list`/`cmt_list`/`lbl_set`/`cmt_set` command
names and the `{"start": ..., "end": ...}` parameter shape against
`get_labels`/`get_comments` at `x64dbg.py:6072-6151`, and confirmed
`_lbl_refresh_btn`/`_set_lbl_btn`/`_cmt_refresh_btn`/`_set_cmt_btn` exist in
`x64dbg_panel.py:856-911` exactly as asserted.

The `TestConditionalBreakpointGuiResidualGap` class deserves specific note:
it asserts the *current, honestly-broken* state (`not hasattr(panel,
"_bp_cond_input")`, and `"condition" not in params` on the recorded `bp_set`
call). This is **not** a vacuous or cannot-fail test — each assertion is
written to flip red the moment someone actually closes the gap (adds the
condition widget and forwards it), which is the correct, deliberate design
for gating a known, tracked, still-open defect: it prevents the gap from
being silently "fixed" by a change that doesn't actually route a condition
through end-to-end, and it forces the test file to be updated (not silently
left green) once the real fix lands. This matches my own independent Part-A
finding for row 19 exactly — the test suite already documents the gap I
found by direct source inspection.

**Verdict: all 8 tests (6 positive + 2 residual-gap) are real, falsifiable
gates. Zero non-gates.**

### Production-standards compliance (not gate-quality, but mandated by the plan)

- **pydoclint**: clean — `pixi run pydoclint tests/test_bridge_completeness/x64dbg/` → `No violations`.
- **ruff**: **6 findings**, not zero as required:
  - `conftest.py:28` — `typing-only-first-party-import` (`X64DbgBridge` import could move into `TYPE_CHECKING`, but it's used at runtime as `FakePipeClient`'s type hint target and in `X64DbgBridge()` construction in fixtures elsewhere — needs a real fix, not suppression).
  - `test_x64dbg_patches_tab_l3.py:19` — `typing-only-standard-library-import` (`Path`).
  - `test_x64dbg_restart_and_disassemble_dispatch.py:169,209,268,327` — `unused-function-argument: params` (4 responder closures that ignore `params`).
- **basedpyright**: **77 findings**, not zero as required. The overwhelming majority (~70) are `reportPrivateUsage` from directly accessing panel-private widgets (`_patch_table`, `_lbl_table`, `_restart_btn`, etc.) plus the resulting `reportOptionalMemberAccess` on `.item(...).text()` chains, and a handful of `reportUnknown*` on the `disassemble_at` result list (untyped `list[Unknown]` return leaking through `ToolRegistry.execute_tool_call`'s `object` return type). **This is not unique to the x64dbg tests** — cross-checked `tests/test_bridge_completeness/ghidra/test_ghidra_l3_panel.py`, which has the identical `reportPrivateUsage` pattern (89 findings) from the same L3-panel-widget-access convention used across the entire `test_bridge_completeness/` suite. This is a systemic gap in the shared L3-testing convention (panels expose no public accessors for internal widgets, so every L3 wiring test in this audit effort reaches into `_private` attributes), not an x64dbg-specific regression. It is a real, confirmed non-compliance with the plan's "zero basedpyright findings" mandate and should be fixed either by adding narrow public accessors/properties to the panels for test introspection, or by a project-wide basedpyright override decision — but it does **not** indicate the tests are fake gates; every assertion still exercises real production code and would catch a real regression.

## Tally

- **Rows re-verified**: 8 (slice 1, previously non-OK) + 32 (slice 2, previously
  NO-CONTROL/DEAD-CONTROL) + 4 (cross-cutting defects) = 44
- **Genuinely RESOLVED (OK/OK/OK)**: 39
- **Still open / residual**: 5 — slice-1 rows 9 (step_count), 10
  (animate_start/stop), 29 (get_trace_record) remain NO-CONTROL with no GUI
  anywhere (including the new Advanced tab); row 19 (conditional breakpoints)
  remains DEAD-CONTROL but is now honestly test-gated instead of silently
  dropped; slice-2 row 8 (`scan_memory` indirect-only) is unchanged and
  correctly low-priority.
- **Tests reviewed**: 24 (11 + 5 + 8 in the three test files, all reviewed
  individually above)
- **Non-gate tests found**: 0
- **Production-standards violations found**: ruff 6 findings (not zero),
  basedpyright 77 findings (not zero, systemic across the `test_bridge_completeness`
  suite, not x64dbg-specific)

```json
{
  "tool": "x64dbg",
  "rows_checked": 44,
  "still_broken": [
    {"feature": "step_count (slice-1 row 9)", "layer": "L3", "why": "No widget in x64dbg_panel.py or x64dbg_advanced_tab.py invokes step_count; NO-CONTROL unchanged."},
    {"feature": "animate_start/animate_stop (slice-1 row 10)", "layer": "L3", "why": "No widget invokes either method in either panel file; NO-CONTROL unchanged."},
    {"feature": "get_trace_record (slice-1 row 29)", "layer": "L3", "why": "Trace tab has no per-address hit-count lookup control; NO-CONTROL unchanged."},
    {"feature": "conditional breakpoints (slice-1 row 19)", "layer": "L3", "why": "Add-BP form still has no condition QLineEdit and _on_add_breakpoint still never forwards condition=; DEAD-CONTROL unchanged, but now honestly test-gated in test_x64dbg_annotations_l3.py::TestConditionalBreakpointGuiResidualGap."},
    {"feature": "scan_memory (slice-2 row 8)", "layer": "L3", "why": "Still only indirectly reachable via find_pattern; unchanged, low priority, deprioritized correctly."}
  ],
  "non_gate_tests": [],
  "quality_gate_violations": [
    {"tool": "ruff", "count": 6, "files": ["conftest.py", "test_x64dbg_patches_tab_l3.py", "test_x64dbg_restart_and_disassemble_dispatch.py"]},
    {"tool": "basedpyright", "count": 77, "note": "systemic reportPrivateUsage pattern shared with tests/test_bridge_completeness/ghidra/test_ghidra_l3_panel.py, not x64dbg-specific"}
  ],
  "report_path": "D:/Intellicrack/audit/bridge-completeness/remediation/verify-x64dbg.md",
  "summary": "39 of 44 previously non-OK rows are genuinely OK/OK/OK with real, non-stub bridge methods, correctly-named dispatchable tool-defs, and reachable/wired GUI controls (Patches window, Labels/Comments population+edit, Restart, and 25+ Advanced-tab controls for module-info/PEB-TEB-SEH/watches/breakpoint-config/xrefs/handles/script/plugin methods all confirmed genuinely wired through run_bridge_coroutine_logged). All 24 new/updated tests in tests/test_bridge_completeness/x64dbg/ are real, falsifiable gates -- zero mock-away/tautology/vacuous-assertion non-gates found, including a deliberately well-designed 'red-by-design' pair of tests that honestly documents the one remaining DEAD-CONTROL gap (conditional breakpoints, row 19) instead of hiding it. Five items remain genuinely open: three slice-1 NO-CONTROL rows (step_count, animate, get_trace_record) that were never wired into the new Advanced tab, the row-19 DEAD-CONTROL itself, and the previously-noted low-priority scan_memory indirect-reachability. The test suite additionally fails the plan's 'zero ruff / zero basedpyright' production-standard mandate (6 ruff findings, 77 basedpyright findings dominated by reportPrivateUsage from direct panel-widget access -- a pattern shared across the whole test_bridge_completeness suite, not unique to x64dbg) -- this does not make any test a fake gate, but it is a real, unresolved compliance gap against the plan's non-negotiable standards."
}
```
