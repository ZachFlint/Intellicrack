# Cutter/Rizin Remediation Verification

Scope: `agent-03-cutter-rizin-static-analysis.md` (26 native features) and
`agent-04-cutter-rizin-dynamic-navigation.md` (47 native features). Read-only
verification against `src/intellicrack/bridges/cutter.py`,
`src/intellicrack/ui/panels/cutter_panel.py`, `cutter_tabs.py`, and the four
new sub-modules; test review of
`tests/test_bridge_completeness/cutter/`.

## PART A — Three-layer verification

### A1. `ir`/`iR` correctness bug (the confirmed defect)

**RESOLVED — verified correct on main.**

- `src/intellicrack/bridges/cutter.py:2754` — `get_relocations` issues
  `await self._cmd_json("irj")` (relocations, correct per upstream rizin).
- `src/intellicrack/bridges/cutter.py:2788` — `get_resources` issues
  `await self._cmd_json("iRj")` (resources, correct per upstream rizin).
- The swap identified in the original audit (`get_relocations` sending
  `iRj`, `get_resources` sending `irj`) is fixed. Both methods' parsing
  logic (`RelocationInfo`/`ResourceInfo` field mapping) is unchanged and
  still real.

### A2. Static-analysis slice (agent-03) — previously non-OK rows

| Row | Feature | L1 | L2 | L3 | Verdict |
|---|---|---|---|---|---|
| 1 | Analysis-depth selector | OK (`analyze(level)`) | OK | OK — `cutter_panel.py:142-146` combo box (`_ANALYSIS_LEVELS`), threaded at `cutter_panel.py:578,589` (`self._bridge.analyze(level)`) | **OK/OK/OK** |
| 4 | Linear function disasm (`pdf`) | OK | OK | OK — `FunctionDisasmTab` in `cutter_static_extra_tab.py:710-791`, wired via `StaticAnalysisExtrasTab.show_function` → `cutter_panel.py:719` on function click | **OK/OK/OK** |
| 7 | Basic blocks (`afbj`) | OK | OK | OK — `BasicBlocksTab` in `cutter_static_extra_tab.py:618-707`, same `show_function` wiring | **OK/OK/OK** |
| 8 | Call graph (`agcj`) | OK | OK | OK — `CallGraphTab` in `cutter_static_extra_tab.py:206-259`, refreshed by `StaticAnalysisExtrasTab.refresh` → `cutter_panel.py:1174` | **OK/OK/OK** |
| 18 | Debug info (`iDj`) | OK | OK | **Still NO-CONTROL** — not added to `StaticAnalysisExtrasTab` or anywhere else; zero grep hits for `get_debug_info` in `src/intellicrack/ui` | **RESIDUAL — L3 not remediated** |
| 19 | Classes/RTTI (`icj`) | OK | OK | OK — `ClassesTab` in `cutter_static_extra_tab.py:131-203`, tree view with methods/fields | **OK/OK/OK** |
| 20/21 | Relocations/resources swap | OK (fixed, see A1) | OK | OK (tabs pre-existed) | **OK/OK/OK** |
| 22 | Vtables (`avj`) | OK | OK | OK — `VtablesTab` in `cutter_static_extra_tab.py:262-306` | **OK/OK/OK** |
| 23 | Syscalls (`asj`) | OK | OK | OK — `SyscallsTab` in `cutter_static_extra_tab.py:309-357` | **OK/OK/OK** |
| 24/24b/24c/24d | Zignatures list/generate/add/search | OK | OK | OK — `ZignaturesTab` in `cutter_static_extra_tab.py:360-615`, all four actions wired to their real bridge methods | **OK/OK/OK** |
| 26 | Word-mode hexdump (`pxw`) | OK | OK | OK — mode combo in `HexdumpTab` (`cutter_tabs.py:594-595`), branch at `cutter_tabs.py:683-684` dispatching `hexdump_words` vs `hexdump` | **OK/OK/OK** |

Integration wiring confirmed real (not just constructed-but-orphaned):
`cutter_panel.py:46-49` imports all four new modules;
`cutter_panel.py:384-393` instantiates and adds them as tabs;
`cutter_panel.py:435-444` `set_bridge` propagates to `_debugger_tab`,
`_project_tab`, `_search_tab` (the `_static_extras_tab` gets its bridge
per-call via `refresh(bridge)`, consistent with its own design);
`cutter_panel.py:1155-1174` `_refresh_new_tabs` calls `.refresh(...)` on
every new tab after analysis completes; `cutter_panel.py:700-719`
`_on_function_clicked` calls `self._static_extras_tab.show_function(address)`
which populates the two address-driven sub-tabs (basic blocks, function
disasm). This is genuine, reachable, end-to-end wiring — verified by
direct read, not assumed from the agent's summary.

**Static-analysis slice count: 10 of 11 previously-non-OK rows fully
remediated. Row 18 (`get_debug_info`) remains NO-CONTROL** — a real
residual gap the implementing agent did not close and the test suite does
not claim to cover (correctly; there is no test for it).

### A3. Dynamic & navigation slice (agent-04) — previously NO-CONTROL rows

All 15 debugger rows (1-15), both remaining ESIL rows (18, 20), both flag
rows (22-23), 9 search/compare rows (27-35), 4 zignature rows (39-42,
same methods as 24/24b/24c/24d above), 3 project rows (43-45), and 2
config rows (46-47) were NO-CONTROL at L3 only (L1/L2 were already
complete per the original audit).

| Rows | Feature area | L3 verdict |
|---|---|---|
| 1-15 | Full debugger surface (attach/detach, breakpoints ×3, stepping ×2, continue, registers ×2, memory ×2, regions, threads, modules) | **OK** — `DebuggerTab` (`cutter_debugger_tab.py`), all 15 operations have real controls wired via `run_bridge_coroutine_logged` to the exact named bridge method (verified line-by-line above) |
| 18 | ESIL emulate whole function (`aef`) | **Still NO-CONTROL** — `ESILConsoleTab` (`cutter_tabs.py:705-...`) only has Eval/Step/Init Mem buttons; no "Emulate Function" control added |
| 20 | ESIL set PC (`aepc`) | **Still NO-CONTROL** — same tab, no "Set PC" control added |
| 22 | Flags: add (`f name size @ addr`) | **Still NO-CONTROL** — `FlagsTab` (`cutter_tabs.py:440-481`) remains a read-only table; no add-flag input row |
| 23 | Flags: resolve nearest (`fdj`) | **Still NO-CONTROL** — same tab, no resolve control |
| 27-35 | Advanced search (bytes, wildcard, string, assembly, crypto, magic, value) + compare (bytes, disasm) | **OK** — `SearchTab` (`cutter_search_tab.py`), mode-combo-driven single search panel plus a separate compare panel, all 9 operations dispatch to the exact bridge method per mode (verified line-by-line above) |
| 39-42 | Zignatures list/generate/add/search | **OK** — same `ZignaturesTab` as row 24 above (shared implementation across both slices, correctly cross-referenced) |
| 43-45 | Project save/open/list | **OK** — `ProjectTab` (`cutter_project_tab.py`), all three wired, plus double-click-to-open on the list widget (a real usability addition beyond the minimum) |
| 46 | Config: get value (`e key`) | **Still NO-CONTROL** — no `ConfigTab` or any config control anywhere in the panel/tab files |
| 47 | Config: set value (`e key=value`) | **Still NO-CONTROL** — same, absent |

**Dynamic/navigation slice count: 29 of 35 previously-NO-CONTROL rows
fully remediated (debugger 15/15, search/compare 9/9, project 3/3,
zignatures 4/4 — shared with the static slice). 6 rows remain
NO-CONTROL: `esil_emulate_function`, `esil_set_pc`, `add_flag`,
`resolve_flag`, `get_config`, `set_config`.**

This matches the original slice-4 report's own prioritization — these six
were explicitly called out as "lower priority... acceptable to leave
console-only longer-term" (gap items #4-#6 in the agent-04 report) — so
the remediation wave's scope choice is defensible, but it means the
orchestrator's target of "100% — every audited item rectified" is **not
yet met** for these 6 items. They are genuinely still reachable only via
the raw r2 console (`_on_run_command`), not via a structured widget.

## Layer verdict summary

- **L1 (bridge):** 100% complete for both slices, including the `ir`/`iR`
  regression fix. No stubs, no missing methods.
- **L2 (tool-def/dispatch):** 100% complete for both slices (was already
  100% before remediation per the original audit; unaffected by this wave).
- **L3 (GUI):** Static slice 10/11 closed (91%); dynamic slice 29/35 closed
  (83%). Combined: 39 of 46 previously-non-OK/NO-CONTROL rows now genuinely
  OK/OK/OK. **7 rows remain open**: row 18 (debug info, static slice) plus
  the 6 dynamic-slice rows listed above.

## PART B — Test-gate review

Reviewed: `tests/test_bridge_completeness/cutter/test_cutter_static_analysis.py`
(19 tests), `test_cutter_dynamic_navigation.py` (27 tests), and the shared
`conftest.py`.

### Test-double legitimacy

`CommandRecorder`/`as_r2pipe` in `conftest.py` duck-type only the
`r2pipe.open` interface (`cmd(str) -> str`, `quit() -> None`) — the
genuine external boundary (a live rizin child process over r2pipe) that
cannot run in the Docker sandbox. Everything downstream — real
`CutterBridge` method bodies, real `ToolRegistry.execute_tool_call`
dispatch, real Qt widget construction and event handlers via
`run_bridge_coroutine_logged` — executes for real. This satisfies the
plan's narrow test-double exception; it is not mocking the thing under
test.

### Falsifiability spot-check (representative sample, both files)

- `TestRelocationsResourcesSwapRegression` (static, lines 98-162): seeds
  **distinct** relocation and resource JSON under both `irj`/`iRj` keys,
  asserts the correct command was issued AND the correct dataset was
  parsed (`RelocationInfo.type == "R_X86_64_RELATIVE"` vs
  `ResourceInfo.type == "icon"`). Reverting the swap fix turns both tests
  red. **Real gate.**
- `TestAnalysisDepthSelectorL3.test_quick_level_selection_issues_aa_not_aaa`
  (static, lines 227-258): asserts `"aa" in recorder.commands` **and**
  `"aaa" not in recorder.commands`/`"aaaa" not in recorder.commands` —
  actively rules out the pre-fix behavior (always running the default
  level), not just checking presence. **Real gate.**
- `TestDebuggerTabAttachDetach` (dynamic, lines 94-154): asserts the exact
  command string `"dp 4242"` was issued and the real `bridge.state.process_attached`
  flag flipped, using the real `attach()` production path (not a
  hand-built fixture state). **Real gate.**
- `TestSearchTabByteModes.test_wildcard_mode_translates_question_marks_to_dots`
  (dynamic, lines 625-652): distinguishes `search_bytes` from
  `search_bytes_wildcard` by asserting the exact wildcard-translated
  command `/xj 4889....`; a regression to plain byte search would send a
  different (non-matching) command and fail. **Real gate.**
- `TestZignaturesTabL3.test_generate_button_calls_zg_at_address` /
  `test_add_button_calls_za_with_name_and_data` (static, lines 522-569):
  assert the exact address-scoped/parameterized command strings, not just
  "some command ran." **Real gate.**

No test in either file was found using `assert True`, bare `try/except`
swallowing, `pytest.skip`/`xfail`, mocking of the bridge/tool-def/GUI
layer under test, or a re-implementation-and-compare tautology. Every
test drives a real widget method or a real bridge/registry call and
asserts an exact, independently-meaningful value (command string, parsed
field value, or rendered widget cell text). **No non-gate tests found —
all 46 tests are genuine falsifiable gates on their intended production
lines.**

### Code-quality gate results (mandatory per the remediation plan's own standards)

- **ruff:** `pixi run ruff check` on the 4 new panel files: **0 findings**.
  On the 2 new test files: **2 findings**
  - `tests/test_bridge_completeness/cutter/test_cutter_dynamic_navigation.py:636`
    — `import-outside-top-level`: a stray `import asyncio` inside
    `test_wildcard_mode_translates_question_marks_to_dots`, even though
    `asyncio` is already imported at module top-level (line 32) and used
    by other tests in the same file (e.g. line 88, line 609). This is a
    redundant, misplaced import, not a suppression, but it is a real ruff
    violation that must be removed.
  - `tests/test_bridge_completeness/cutter/test_cutter_dynamic_navigation.py:850`
    — `hardcoded-temp-file`: the literal `"/tmp/other.bin"` path used as a
    compare-target file argument in
    `test_compare_disassembly_issues_disasm_and_json_diff_commands`. The
    value is never touched on disk (it is only used as an opaque string
    argument to the recorder-backed bridge call), so it is not a real
    Windows-compatibility bug, but it is a live ruff finding that violates
    the "ALL code must pass `ruff check`" standard and should be replaced
    with a non-`/tmp` placeholder path (e.g. `"other.bin"` or a
    `tmp_path`-derived string) to both satisfy the linter and better match
    Windows-first path conventions.
- **basedpyright:** the 4 new panel files: **0 findings** (verified).
  The 2 new test files: **324 findings** (197 in
  `test_cutter_static_analysis.py`, 127 in
  `test_cutter_dynamic_navigation.py`), overwhelmingly
  `reportPrivateUsage` from directly reaching into private
  (underscore-prefixed) widget attributes — `tab._bridge`, `tab._table`,
  `tab._tree`, `tab._on_analyze()`, `tab._reg_table`, `tab._bp_table`,
  etc. — across nearly every test in both files, plus a smaller set of
  genuine `reportOptionalMemberAccess` errors from calling `.text()`
  directly on `QTableWidget.item(row, col)` results without a `None`
  check (e.g. `test_cutter_static_analysis.py:432`,
  `test_cutter_dynamic_navigation.py` has the analogous pattern
  throughout). This is a **hard violation** of the project's
  non-negotiable "ALL code must be fully basedpyright compliant... zero
  basedpyright findings are acceptable under any circumstance" standard,
  which explicitly applies to all code, and the remediation plan's own
  self-verification mandate ("basedpyright on the touched files — zero
  findings") was not satisfied before these tests were reported as done.
- **pydoclint:** **0 findings** across all 4 panel files and all 4 test
  files (confirmed directly, "No violations").

## Non-gate tests (falsifiability review)

None. Every test reviewed is a genuine, falsifiable gate on real
production code. The defects found are **code-quality/compliance
failures** (ruff, basedpyright), not weak-gate/fake-gate defects — the
tests themselves correctly exercise real bridge/dispatch/GUI code and
would catch a real regression. They must still be fixed before this
track can be considered fully done, because the project's standards make
zero ruff/basedpyright findings a hard requirement, not a nice-to-have.

### Required fixes (not applied — read-only review)

1. `test_cutter_dynamic_navigation.py:636` — delete the redundant
   `import asyncio` (already imported at module scope).
2. `test_cutter_dynamic_navigation.py:850` — replace the literal
   `"/tmp/other.bin"` with a non-`/tmp` placeholder string.
3. Both test files — eliminate all 324 `reportPrivateUsage` findings.
   Since these are white-box tests intentionally reaching into internal
   widget state to verify exact rendered values (a legitimate testing
   need, not a design flaw), the fix should follow existing repo
   convention for testing private Qt widget internals (check sibling
   bridge-completeness test files for the established pattern — e.g. a
   `# noqa`-free approach such as testing through public accessors where
   they exist, or the codebase's standard mechanism for basedpyright-safe
   private-attribute access in tests) rather than suppressing the
   diagnostic.
4. Both test files — fix every `reportOptionalMemberAccess` on
   `QTableWidget.item(...).text()` chains by binding the item to a local,
   asserting it is not `None`, then reading `.text()` — the same pattern
   already used correctly elsewhere in these same files (e.g.
   `test_cutter_static_analysis.py`'s `top = tab._tree.topLevelItem(0); assert top is not None; top.text(0)`
   at lines 399-402, and `test_cutter_dynamic_navigation.py`'s
   `rax_item = tab._reg_table.item(...)`-style guards used in the
   register tests).

## Summary

```json
{
  "tool": "cutter",
  "rows_checked": 46,
  "still_broken": [
    {"feature": "get_debug_info (row 18, static slice)", "layer": "L3", "why": "No GUI control anywhere; iDj/debug-info presence remains console-only"},
    {"feature": "esil_emulate_function (row 18, dynamic slice)", "layer": "L3", "why": "ESILConsoleTab has no Emulate Function control"},
    {"feature": "esil_set_pc (row 20, dynamic slice)", "layer": "L3", "why": "ESILConsoleTab has no Set PC control"},
    {"feature": "add_flag (row 22)", "layer": "L3", "why": "FlagsTab is read-only, no add-flag input"},
    {"feature": "resolve_flag (row 23)", "layer": "L3", "why": "FlagsTab has no resolve-nearest-flag control"},
    {"feature": "get_config (row 46)", "layer": "L3", "why": "No ConfigTab or any config control exists"},
    {"feature": "set_config (row 47)", "layer": "L3", "why": "No ConfigTab or any config control exists"}
  ],
  "non_gate_tests": [],
  "compliance_defects": [
    {"file": "tests/test_bridge_completeness/cutter/test_cutter_dynamic_navigation.py", "tool": "ruff", "count": 2, "findings": ["import-outside-top-level:636", "hardcoded-temp-file:850"]},
    {"file": "tests/test_bridge_completeness/cutter/test_cutter_static_analysis.py", "tool": "basedpyright", "count": 197, "findings": ["reportPrivateUsage (majority)", "reportOptionalMemberAccess (QTableWidgetItem.text() on possibly-None item)"]},
    {"file": "tests/test_bridge_completeness/cutter/test_cutter_dynamic_navigation.py", "tool": "basedpyright", "count": 127, "findings": ["reportPrivateUsage (majority)", "reportOptionalMemberAccess"]}
  ],
  "report_path": "D:/Intellicrack/audit/bridge-completeness/remediation/verify-cutter.md",
  "summary": "L1/L2 100% complete for both cutter slices including the confirmed ir/iR command-swap regression fix (verified: get_relocations sends irj, get_resources sends iRj). L3 GUI: 39 of 46 previously-non-OK/NO-CONTROL rows now genuinely OK/OK/OK via 4 new sub-modules (cutter_debugger_tab.py, cutter_project_tab.py, cutter_search_tab.py, cutter_static_extra_tab.py) all correctly imported, instantiated, bridge-wired, and refresh-wired into cutter_panel.py. 7 rows remain residual NO-CONTROL (debug-info, ESIL emulate-function/set-pc, flag add/resolve, config get/set) -- all previously flagged as lower-priority in the original audit but still open against the orchestrator's 100% target. All 46 new tests are genuine falsifiable gates with no mocks/stubs/tautologies -- test-writer's falsifiability work is sound. However the two new test files carry real, uncorrected compliance defects: 2 ruff findings and 324 basedpyright findings (mostly reportPrivateUsage from direct private-attribute access, plus reportOptionalMemberAccess on unguarded QTableWidgetItem.text() calls) that violate the project's zero-findings mandate and must be fixed before this track is complete."
}
```
