# Verification — Slice 6: Ghidra Program Model & Scripting

Adversarial re-check of `audit/bridge-completeness/agent-06-ghidra-program-model-scripting.md`
against the live source: `src/intellicrack/bridges/ghidra.py`,
`src/intellicrack/ui/panels/ghidra_panel.py`, `src/intellicrack/core/tools.py`.
Read-only — no application code was modified. All line citations below are my
own independent reads (three parallel sub-agent verifications plus direct
checks in the main verification session), not copied from the report.

## Highest-stakes claim: `add_comment` REPEATABLE downgrade bug

Read `ghidra.py:2984-3038` directly.

- `comment_map` (ghidra.py:3017-3022) contains exactly 4 keys: `EOL`, `PRE`,
  `POST`, `PLATE`. `REPEATABLE` is absent.
- Line 3023: `ghidra_type = comment_map.get(comment_type, "CodeUnit.EOL_COMMENT")`
  — any unrecognized `comment_type` (including the valid Ghidra type
  `REPEATABLE`) silently resolves to `CodeUnit.EOL_COMMENT` with **no
  exception, no warning, no logged deviation**. The resulting Jython snippet
  (lines 3027-3037) then calls `cu.setComment(CodeUnit.EOL_COMMENT, ...)`.
- Read-side confirmed to genuinely support all 5 types: `get_comments`
  (ghidra.py:6203-6209) and `get_all_comments` (ghidra.py:6254-6260) both
  build a `comment_types` list that includes
  `('REPEATABLE', CodeUnit.REPEATABLE_COMMENT)`.
- GUI-side: `_cmt_type_combo.addItems(["EOL", "PRE", "POST", "PLATE"])`
  (ghidra_panel.py:662) — REPEATABLE is not selectable from the GUI at all,
  so the bug is currently only reachable through the tool-def/AI-orchestration
  call path (`add_comment` is tool-def registered at ghidra.py:482 and
  accepts an arbitrary `comment_type: str` with no validation), not through
  the panel.

**Verdict: CONFIRMED.** This is a genuine correctness bug (silent wrong-type
write, not just a coverage gap) and the report's description of the mechanism
is accurate down to the exact line numbers.

## Verification table

| Finding (report ref) | Verdict | Independent evidence (file:line) | Note |
|---|---|---|---|
| Wiring model: generic `getattr` dispatch, `ghidra.` prefix strip | CONFIRMED | `core/tools.py:587-588` (`attr_name = function_name.split(".", maxsplit=1)[-1]...`; `method = getattr(bridge, attr_name, None)`) | Exactly as described; `None` triggers an explicit raise (tools.py:589+), not silent swallow. |
| "All 86 `ghidra.*` entries...no NOT-REGISTERED cases" | NEEDS-REVIEW (count only) | `rg -c 'name="ghidra\.'` on ghidra.py → **81**, not 86 | Off by 5 (~6%). Does not change the NOT-REGISTERED=0 conclusion — 8-method spot check (create_data_type, create_data, add_bookmark, remove_bookmark, get_program_tree, get_properties, add_comment, get_comments) all have matching `async def` in the same class. Minor factual sloppiness in the summary prose, not a misclassification of any row. |
| #1 List/browse structures — OK, struct-only gap noted | CONFIRMED | `get_structures` ghidra.py:3968; GUI list wired ghidra_panel.py:2564 | Report's caveat (no enum/union/typedef listing) is consistent with create_data_type findings below. |
| #2 Create structure — OK | CONFIRMED | `define_structure` ghidra.py:3910; tool-def ghidra.py:681; `_define_struct_btn`→`_on_define_structure` ghidra_panel.py:417,2534 | Not independently re-verified line-by-line beyond method existence check (in-scope grep), but consistent with wider pattern; no contradicting evidence found. |
| #3-6 Create enum/union/typedef/function_def — NO-CONTROL | CONFIRMED | `create_data_type` ghidra.py:5813, full if/elif handling of all 4 kinds at ghidra.py:5852-5877 (EnumDataType/UnionDataType/TypedefDataType/FunctionDefinitionDataType); tool-def ghidra.py:986; `rg create_data_type` in ghidra_panel.py → only hit is the unrelated method name `_create_data_types_tab` (ghidra_panel.py:302,902), whose body (902-968) only wires Get/Set Data Type forms | Real, complete bridge method; genuinely zero GUI path. No dynamic/generic dispatch pattern found in panel that could reach it indirectly. |
| #7 Apply structure at address — OK | CONFIRMED | `apply_structure_at` ghidra.py:4014; tool-def ghidra.py:714; wired ghidra_panel.py:2603 | Method exists, matches signature described. |
| #8-9 Get/Set data type at address — OK | CONFIRMED | `get_data_type` ghidra.py:3175, `set_data_type` ghidra.py:3248; both tool-def registered (ghidra.py:521,534); `_dt_get_btn`/`_dt_set_btn` wired ghidra_panel.py:926-928,960-963 | Confirmed as the two real forms present in the Data Types tab. |
| #9b `create_data` — NO-CONTROL, duplicate of set_data_type | CONFIRMED | `create_data` ghidra.py:5900 (real: `DataTypeParser` + `listing.createData`); tool-def ghidra.py:1025; zero word-boundary matches for `create_data` in ghidra_panel.py | Genuinely orphaned; correctly distinguished from the `create_data_type`/`_create_data_types_tab` string collision. |
| #11 Read program tree — NO-CONTROL | CONFIRMED | `get_program_tree` ghidra.py:6284, real recursive walk (`build_module`/`build_fragment`, depth/cycle guards ~6314-6358); tool-def ghidra.py:1096; tab list `ghidra_panel.py:294-302` has no "Program Tree" entry; zero matches for `get_program_tree` in panel | Independently confirmed the addTab list myself — 12 tabs, no tree tab. |
| #12 Create/edit modules and fragments — MISSING | CONFIRMED | Whole-file grep of ghidra.py for `TreeManager`, `ProgramModule`, `createModule`, `createFragment`, `ProgramFragment` → only hits are inside `get_program_tree` itself (import + isinstance checks, ~6310-6347); no write-side method anywhere | No method under any other name provides tree mutation. |
| #13 List memory blocks — OK | CONFIRMED (spot check) | `get_memory_map` ghidra.py:4069; tool-def ghidra.py:723; "Memory" tab ghidra_panel.py:296 | Method exists at cited line; not exhaustively traced GUI callback but tab presence confirmed via addTab list. |
| #14 Create memory block — OK | CONFIRMED (spot check) | `create_memory_block` ghidra.py:6127, real (`memory.createInitializedBlock` + read/write/execute flags ~6158-6162); tool-def ghidra.py:1058 | Confirmed non-stub. |
| #15 Remove/split/join memory blocks — MISSING | CONFIRMED | Whole-file grep for `removeBlock`, `splitBlock`, `joinBlocks`, `memory.split`, `memory.join` (and generic `split`/`join` substring survey) → zero true hits; only unrelated Python `str.join`/`thread.join` calls (e.g. ghidra.py:1396,2792,2853) | No such capability exists under any name. |
| #16 Create overlay address space — OK | CONFIRMED (spot check) | `create_overlay_space` ghidra.py:6863; tool-def ghidra.py:1176; wired ghidra_panel.py:1618 | Method exists at cited line. |
| #17-20 Set EOL/PRE/POST/PLATE — OK (4 of 5 types) | CONFIRMED | See "highest-stakes claim" section above | `_cmt_type_combo` confirmed to have exactly 4 items. |
| #21 Set REPEATABLE comment — STUB (silent EOL fallback) | CONFIRMED | ghidra.py:3017-3023; ghidra_panel.py:662 | See detailed analysis above; genuine correctness bug, not merely a gap. |
| #22 Read comments in range — OK, includes REPEATABLE | CONFIRMED | `get_comments` ghidra.py:6175, type list at 6203-6209 includes REPEATABLE | Verified directly. |
| #23 Read all comments — OK, includes REPEATABLE | CONFIRMED | `get_all_comments` ghidra.py:6232, type list at 6254-6260 includes REPEATABLE | Verified directly. |
| #24 Create bookmark — OK | CONFIRMED (spot check) | `create_bookmark` ghidra.py:3538 (direct `setBookmark` + readback verification); wired `_on_create_bookmark` ghidra_panel.py:2459 | Matches report. |
| #24b `add_bookmark` — NO-CONTROL, duplicate | CONFIRMED | `add_bookmark` ghidra.py:6894 (transaction-wrapped `setBookmark`, no readback); tool-def ghidra.py:1184; zero references to `add_bookmark` in ghidra_panel.py (only `create_bookmark` is called, ghidra_panel.py:2459) | Functionally equivalent to create_bookmark (same underlying `BookmarkManager.setBookmark` call); "duplicate" characterization is accurate, not overstated. |
| #25 List/filter bookmarks — OK | CONFIRMED (spot check) | `get_bookmarks` ghidra.py:3628; "Refresh Bookmarks" ghidra_panel.py:375 (`_on_refresh_bookmarks`) | Matches. |
| #26 Remove bookmark — NO-CONTROL | CONFIRMED | `remove_bookmark` ghidra.py:6965 (real, transactional); tool-def ghidra.py:1202; exhaustive search of all ~41 "bookmark" occurrences in ghidra_panel.py shows only create/refresh/apply widgets (`_bm_addr_input`, `_bm_category_input`, `_bm_comment_input`, `_bm_type_combo`, `_create_bm_btn`, `_bookmarks_table` built via `_make_table` with no context-menu policy set) | Contrast case found: Functions tab *does* wire a delete context-menu (`customContextMenuRequested`, ghidra_panel.py:1123, "Delete Function" ~1958/2122) proving the codebase has this pattern elsewhere but never applied it to bookmarks — strengthens rather than weakens the finding. |
| #27-30 Namespaces/equates create+list — OK | CONFIRMED (spot check #29) | `create_equate` ghidra.py:5301 (real Jython script, EquateTable + readback); tool-def ghidra.py:909; `_create_eq_btn`→`_on_create_equate` ghidra_panel.py:761,3222, calls via `run_bridge_coroutine_logged` | Matches exactly. |
| #31 Get properties — NO-CONTROL | CONFIRMED | `get_properties` ghidra.py:6383 (real, `getUsrPropertyManager`/`propertyNames`); tool-def ghidra.py:1102; zero matches for `get_properties`/`UsrPropertyManager`/property-viewer widget in ghidra_panel.py | Genuine gap. |
| #32 Get program info — OK | CONFIRMED (spot check) | `get_program_info` ghidra.py:4256; "Refresh Program Info" ghidra_panel.py:566-567 | Matches. |
| #33 Set program name/image base — OK | CONFIRMED | `set_program_metadata` ghidra.py:6612; tool-def ghidra.py:1132; "Update" button (`self._update_meta_btn`) ghidra_panel.py:583-584 → `_on_update_metadata` (2866) → `bridge.set_program_metadata(...)` (2878) via `run_bridge_coroutine_logged` | Matches exactly. |
| #34 Headless launch — OK, with documented flag-coverage caveat | CONFIRMED (spot check) | `start_headless` ghidra.py:1433; tool-def ghidra.py:553; "Start Headless" toolbar button ghidra_panel.py:1405-1424 | Method exists; caveat about missing `-import`/`-process`/etc. flags plausible given RPC-bridge architecture description, not separately falsified but not contradicted either. |
| #35-36 Execute script / with params — OK | CONFIRMED (spot check) | `execute_script` ghidra.py:3294, `execute_script_with_params` ghidra.py:6701; tool-defs ghidra.py:586,1141 | Matches. |
| #37 Import debug info — OK | CONFIRMED (spot check) | `import_debug_info` ghidra.py:4886; tool-def ghidra.py:854 | Matches. |
| #38 Configure analyzer options — OK | CONFIRMED | `configure_analysis` ghidra.py:5947 (real); tool-def ghidra.py:1034; "Configure Analysis" button (`self._configure_analysis_btn`) ghidra_panel.py:882-883 → `_on_configure_analysis` (3438+) → `bridge.configure_analysis(...)` via `run_bridge_coroutine_logged` | Matches exactly. |
| #39 Decompiler options config — OK | CONFIRMED (spot check) | `set_decompiler_options` ghidra.py:6009; tool-def ghidra.py:1044 | Matches. |
| #40 Program diff — OK | CONFIRMED | `diff_programs` ghidra.py:6434 (real `ProgramDiff`/`ProgramDiffFilter` Jython script, not a stub); tool-def ghidra.py:1110; "Diff..." button (`self._diff_btn`) ghidra_panel.py:177 → `_on_diff_programs` (1568) → `bridge.diff_programs(file_path)` (1583) via `run_bridge_coroutine_logged` | Matches exactly. |

## FALSE POSITIVES / NEEDS REVIEW

No false positives were found. One minor factual imprecision:

- **Tool-def entry count (report line 17, summary line ~137).** The report
  states "All 86 `ghidra.*` entries found in the bridge were cross-checked."
  Independent count via `rg -c 'name="ghidra\.' src/intellicrack/bridges/ghidra.py`
  yields **81**, not 86 (verified twice, once by a sub-agent and once directly
  in this verification session). This is a ~6% overstatement in the report's
  narrative text. It does **not** invalidate the report's NOT-REGISTERED=0
  conclusion — an 8-method spot check across the full range of the file
  (early: `create_data_type`, `add_comment`; late: `get_program_tree`,
  `get_properties`, `remove_bookmark`, `add_bookmark`, `create_data`,
  `get_comments`) found matching `async def` methods for every tool-def entry
  checked, with no NOT-REGISTERED or DEAD-CONTROL cases in this slice. This is
  classified as NEEDS-REVIEW only for the specific numeric claim "86" — the
  qualitative conclusion (all present, none dangling) remains CONFIRMED.

No other discrepancies were found. Every NO-CONTROL, MISSING, and STUB
classification in the report was independently reproduced by direct source
reads and/or exhaustive greps of `ghidra_panel.py` and `ghidra.py`, including
active searches for alternate naming, context-menu wiring, and dynamic/generic
dispatch patterns that could have silently satisfied a claimed gap. None were
found. The report's central correctness-bug claim (`add_comment` silently
downgrading REPEATABLE to EOL) is fully substantiated end to end: the write
map, the `.get(..., default)` fallback, the read-side's broader 5-type
support, and the GUI combo's 4-item restriction were all verified directly
against the live file.

## Tally

- **41 findings/rows checked** (40 native-feature rows + the wiring-model /
  tool-def-count claim, counting `create_data_type` as one consolidated claim
  covering rows #3-6 and each spot-checked "OK" row individually)
- **40 CONFIRMED**
- **0 FALSE-POSITIVE**
- **1 NEEDS-REVIEW** (tool-def entry count: report says 86, actual is 81 —
  narrative imprecision only, does not change any row's verdict)
