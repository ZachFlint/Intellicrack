# Bridge Completeness Audit — Slice 6: Ghidra Program Model & Scripting

Scope: data-type manager, program tree, memory map, comments/bookmarks,
headless/scripting API surface. Decompiler/disassembler/P-code/function
manager/symbol table/xrefs are explicitly out of scope for this slice.

Files audited:
- Bridge: `src/intellicrack/bridges/ghidra.py` (7372 lines)
- Dispatch: `src/intellicrack/core/tools.py` (`ToolRegistry.execute_tool_call`, generic `getattr(bridge, attr_name)` dispatch at `src/intellicrack/core/tools.py:587-588`)
- GUI: `src/intellicrack/ui/panels/ghidra_panel.py` (3481 lines)

Wiring model note: this bridge does not use a `_td(...)` helper. Each
`ghidra.<method>` capability is declared as a `ToolFunction` entry inside the
`tool_definition` property (`src/intellicrack/bridges/ghidra.py:326-`), and
`ToolRegistry.execute_tool_call` in `core/tools.py:554-588` dispatches by
stripping the `ghidra.` prefix and calling `getattr(bridge, attr_name)`. All
86 `ghidra.*` entries found in the bridge were cross-checked against actual
`async def` methods; every declared tool function has a matching method (no
NOT-REGISTERED cases were found for any method examined in this slice).

## Native ground truth (research basis)

Sources: Ghidra `FlatProgramAPI` Javadoc
(https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html),
`AnalyzeHeadless.java` usage
(https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/util/headless/AnalyzeHeadless.java),
Ghidra Program Tree help topic, DataTypeManager/StructureDataType Javadoc.

Native feature surface for this slice:
1. Data Type Manager — browse/list defined types (structs, unions, enums, typedefs, function defs)
2. Data Type Manager — create structure
3. Data Type Manager — create enum
4. Data Type Manager — create union
5. Data Type Manager — create typedef
6. Data Type Manager — create function definition type
7. Data Type Manager — apply a structure at an address
8. Data Type Manager — get/inspect the data type applied at an address
9. Data Type Manager — set/apply a named data type at an address (createData)
10. Data Type Manager — remove/undefine a memory block region's data-type binding (not separately auditable; covered by #9 clear+recreate)
11. Program Tree — read module/fragment hierarchy
12. Program Tree — create/edit modules and fragments (write side)
13. Memory Map — list memory blocks with permissions
14. Memory Map — create a new memory block
15. Memory Map — remove/split/join memory blocks
16. Memory Map — create an overlay address space
17. Comments — set EOL comment
18. Comments — set PRE comment
19. Comments — set POST comment
20. Comments — set PLATE comment
21. Comments — set REPEATABLE comment
22. Comments — read comments (single address / range)
23. Comments — read all comments (whole program)
24. Bookmarks — create a bookmark (Note/Analysis/Error/Warning/Info)
25. Bookmarks — list/filter bookmarks
26. Bookmarks — remove a bookmark
27. Namespaces — create namespace
28. Namespaces — list namespaces
29. Equates — create equate
30. Equates — list equates
31. Program properties — get user-defined properties at an address
32. Program metadata — get program info (name, image base, format, etc.)
33. Program metadata — set program name / image base
34. Headless — launch `analyzeHeadless` and establish a scripting/RPC session
35. Scripting — execute arbitrary script code
36. Scripting — execute script with injected parameters
37. Debug info import — PDB/DWARF symbol/type import into the program model
38. Analysis configuration — enable/disable/configure individual analyzers
39. Decompiler options — configure simplification style / instruction limits (program-model-adjacent config surface)
40. Program diff — compare current program against another program file

## Coverage matrix

| # | Native feature | Bridge method (file:line) | Tool-def | GUI control (file:line) | Verdict |
|---|---|---|---|---|---|
| 1 | List/browse structures | `get_structures` ghidra.py:3968 | OK ghidra.py:706 (`ghidra.get_structures`) | `_on_...` via `_refresh_struct_btn`/list ghidra_panel.py:2564 | OK (struct-only; **no listing for enums/unions/typedefs** — see gap list) |
| 2 | Create structure | `define_structure` ghidra.py:3910 | OK ghidra.py:681 | `_define_struct_btn` → `_on_define_structure` ghidra_panel.py:417,2534 | OK |
| 3 | Create enum | `create_data_type(type_kind="enum")` ghidra.py:5813 | OK ghidra.py:986 (`ghidra.create_data_type`) | none found | **NO-CONTROL** |
| 4 | Create union | `create_data_type(type_kind="union")` ghidra.py:5813 | OK ghidra.py:986 | none found | **NO-CONTROL** |
| 5 | Create typedef | `create_data_type(type_kind="typedef")` ghidra.py:5813 | OK ghidra.py:986 | none found | **NO-CONTROL** |
| 6 | Create function-def type | `create_data_type(type_kind="function_def")` ghidra.py:5813 | OK ghidra.py:986 | none found | **NO-CONTROL** |
| 7 | Apply structure at address | `apply_structure_at` ghidra.py:4014 | OK ghidra.py:714 | wired via structures tab, `_on_...` ghidra_panel.py:2603 | OK |
| 8 | Get data type at address | `get_data_type` ghidra.py:3175 | OK ghidra.py:521 | `_dt_get_btn` → `_on_get_data_type` ghidra_panel.py:926-928,970 | OK |
| 9 | Set/apply named data type at address | `set_data_type` ghidra.py:3248 | OK ghidra.py:534 | `_dt_set_btn` → `_on_set_data_type` ghidra_panel.py:960-962,1032 | OK |
| 9b | Create data item at address (redundant alias of #9) | `create_data` ghidra.py:5900 | OK ghidra.py:1025 (`ghidra.create_data`) | none found | **NO-CONTROL** (orphan/duplicate of `set_data_type`; low impact since #9 covers the workflow) |
| 11 | Read program tree (modules/fragments) | `get_program_tree` ghidra.py:6284 | OK ghidra.py:1096 (`ghidra.get_program_tree`) | none — no Program Tree tab/widget exists in `ghidra_panel.py` (tab list at ghidra_panel.py:294-302) | **NO-CONTROL** |
| 12 | Create/edit modules and fragments | — | — | — | **MISSING** (no bridge method for tree mutation; `TreeManager`/`ProgramModule.createModule`/`createFragment` not wrapped) |
| 13 | List memory blocks | `get_memory_map` ghidra.py:4069 | OK ghidra.py:723 | "Memory" tab, refresh action, ghidra_panel.py:296,2624 | OK |
| 14 | Create memory block | `create_memory_block` ghidra.py:6127 | OK ghidra.py:1058 | `_create_block_btn` → `_on_create_memory_block` ghidra_panel.py:518,2747 | OK |
| 15 | Remove/split/join memory blocks | — | — | — | **MISSING** (no `remove_memory_block`/`splitBlock`/`joinBlocks` bridge method exists at all) |
| 16 | Create overlay address space | `create_overlay_space` ghidra.py:6863 | OK ghidra.py:1176 | `_create_overlay_btn` → `_on_create_overlay_space` ghidra_panel.py:533,1618 | OK |
| 17-20 | Set EOL/PRE/POST/PLATE comment | `add_comment` ghidra.py:2984 (comment_map covers EOL/PRE/POST/PLATE only, ghidra.py:3017-3022) | OK ghidra.py:482 | `_add_cmt_btn` + `_cmt_type_combo` (items: EOL/PRE/POST/PLATE) → `_on_add_comment` ghidra_panel.py:661-662,674,3031 | OK (4 of 5 types) |
| 21 | Set REPEATABLE comment | — (not in `add_comment`'s `comment_map`, ghidra.py:3017-3022) | — | `_cmt_type_combo` does not offer "REPEATABLE" ghidra_panel.py:662 | **STUB** (bridge silently falls back to EOL for unrecognized type via `.get(comment_type, "CodeUnit.EOL_COMMENT")`, ghidra.py:3023 — no explicit REPEATABLE support end to end) |
| 22 | Read comments in range | `get_comments` ghidra.py:6175 (covers all 5 types incl. REPEATABLE, ghidra.py:6203-6209) | OK ghidra.py:1075 | `_on_...` ghidra_panel.py:3068,3072 | OK |
| 23 | Read all comments | `get_all_comments` ghidra.py:6232 (all 5 types, ghidra.py:6254-6260) | OK ghidra.py:1090 | wired, ghidra_panel.py:3085,3089,3094 | OK |
| 24 | Create bookmark | `create_bookmark` ghidra.py:3538 (verified round-trip) | OK ghidra.py:617 | `_create_bm_btn` → `_on_create_bookmark` ghidra_panel.py:365,2459 | OK |
| 24b | Create bookmark (transactional alias) | `add_bookmark` ghidra.py:6894 | OK ghidra.py:1184 (`ghidra.add_bookmark`) | none found | **NO-CONTROL** (orphan/duplicate of `create_bookmark`; low impact) |
| 25 | List/filter bookmarks | `get_bookmarks` ghidra.py:3628 | OK ghidra.py:635 | "Refresh Bookmarks" button ghidra_panel.py:374,2493 | OK |
| 26 | Remove bookmark | `remove_bookmark` ghidra.py:6965 | OK ghidra.py:1202 (`ghidra.remove_bookmark`) | none — Labels/Bookmarks tab has only Create + Refresh Bookmarks buttons (ghidra_panel.py:307-374); no delete control | **NO-CONTROL** (real capability gap: no way to remove a bookmark from the GUI at all) |
| 27 | Create namespace | `create_namespace` ghidra.py:5219 | OK ghidra.py:894 | `_create_ns_btn` → `_on_create_namespace` ghidra_panel.py:737,3172 | OK |
| 28 | List namespaces | `get_namespaces` ghidra.py:5261 | OK ghidra.py:903 | wired, ghidra_panel.py:3200,3204 | OK |
| 29 | Create equate | `create_equate` ghidra.py:5301 | OK ghidra.py:909 | `_create_eq_btn` → `_on_create_equate` ghidra_panel.py:761,3222 | OK |
| 30 | List equates | `get_equates` ghidra.py:5396 | OK ghidra.py:919 | wired, ghidra_panel.py:3259,3263 | OK |
| 31 | Get user-defined properties at address | `get_properties` ghidra.py:6383 | OK ghidra.py:1102 (`ghidra.get_properties`) | none found anywhere in `ghidra_panel.py` | **NO-CONTROL** |
| 32 | Get program info | `get_program_info` ghidra.py:4256 | OK ghidra.py:750 | "Refresh Program Info" button, Segments/Program tab ghidra_panel.py:566-567,2824 | OK |
| 33 | Set program name / image base | `set_program_metadata` ghidra.py:6612 (verified round-trip) | OK ghidra.py:1132 | "Update" button ghidra_panel.py:583-584,2878 | OK |
| 34 | Headless launch + scripting session bootstrap | `start_headless` ghidra.py:1433 | OK ghidra.py:553 | "Start Headless" toolbar button ghidra_panel.py:162,1405-1424 | OK (real subprocess launch of `analyzeHeadless`/`.bat` with `-scriptPath`/`-postScript`, process registered with `ProcessManager`, waits for RPC port; does **not** expose `-import`, `-process`, `-recursive`, `-deleteProject`, `-overwrite`, `-analysisTimeoutPerFile` batch-mode flags — architecture is RPC-bridge-only, not general batch headless analysis) |
| 35 | Execute script | `execute_script` ghidra.py:3294 | OK ghidra.py:586 | Scripting tab, `_script_editor` → run button ghidra_panel.py:823,3339-3357 | OK |
| 36 | Execute script with params | `execute_script_with_params` ghidra.py:6701 | OK ghidra.py:1141 | wired in Scripting tab ghidra_panel.py:3368-3389 | OK |
| 37 | Import debug info (PDB/DWARF) | `import_debug_info` ghidra.py:4886 | OK ghidra.py:854 | "Debug Info..." toolbar button ghidra_panel.py:176,1540-1558 | OK |
| 38 | Configure analyzer options | `configure_analysis` ghidra.py:5947 | OK ghidra.py:1034 | "Configure Analysis" button ghidra_panel.py:882-883,3438-3476 | OK |
| 39 | Decompiler options config | `set_decompiler_options` ghidra.py:6009 | OK ghidra.py:1044 | wired ghidra_panel.py:3427-3431 | OK |
| 40 | Program diff | `diff_programs` ghidra.py:6434 | OK ghidra.py:1110 | "Diff..." toolbar button ghidra_panel.py:177,1568-1587 | OK |

Additional bridge method in scope with no native-feature mapping found:
- `create_memory_block`/`create_overlay_space` — legitimate, mapped above (#14, #16).
- `add_bookmark` (ghidra.py:6894) and `create_data` (ghidra.py:5900) are real,
  fully-functional, individually tool-def-registered methods that duplicate
  existing wired methods (`create_bookmark`, `set_data_type`) and have no GUI
  control of their own. Flagged as orphans above (#9b, #24b) rather than
  counted as independent native-feature gaps, since the underlying user
  capability is reachable through the sibling method.

## Coverage summary

- Native features enumerated: **40** (rows above; #10 folded into #9 as a
  non-independent capability, so effectively 39 independently gradable rows)
- Fully ported (Bridge OK + Tool-def OK + GUI OK): **28**
- Gap counts by type:
  - NO-CONTROL (bridge + tool-def real, GUI absent): **8**
    (`create_data_type`×4 kinds counted as 4 rows [enum/union/typedef/function_def],
    `get_program_tree`, `get_properties`, `remove_bookmark`, plus orphans
    `create_data` and `add_bookmark` making 10 total instances — see note below)
  - MISSING (no native-feature-satisfying bridge method at all): **2**
    (program-tree module/fragment write API; memory-block remove/split/join)
  - STUB (bridge exists but incomplete relative to native feature): **1**
    (REPEATABLE comment write support absent from `add_comment`)
  - NOT-REGISTERED: **0** (every method examined in this slice has a matching `ToolFunction` entry)
  - DEAD-CONTROL: **0** (no widget found calling a non-existent/broken method in this slice)

Note on NO-CONTROL count: strictly by native-feature row, NO-CONTROL rows are
#3, #4, #5, #6 (create_data_type kinds), #11 (get_program_tree), #26
(remove_bookmark), #31 (get_properties) = **7** native-feature rows with no
GUI path, plus 2 additional orphan bridge methods (`create_data`,
`add_bookmark`) that are NO-CONTROL but map to already-covered features.

## Prioritized gap list

1. **Data Type Manager: no GUI to create enum/union/typedef/function-def types** (native features #3-#6).
   Bridge (`create_data_type`, ghidra.py:5813) and tool-def (ghidra.py:986)
   are both complete and correct — this is a pure GUI gap. Fix belongs in
   `src/intellicrack/ui/panels/ghidra_panel.py`, most naturally as new
   controls inside `_create_data_types_tab` (ghidra_panel.py:902) alongside
   the existing Get/Set Data Type forms — e.g. a "Create Type" sub-form with
   a kind selector (enum/union/typedef/function_def) and a dynamic field
   editor, calling `bridge.create_data_type(...)` via
   `run_bridge_coroutine_logged`. High impact: without this, the Data Type
   Manager surface is read/apply-only, and a power user cannot define new
   custom types from the GUI at all.

2. **Program Tree entirely absent from GUI** (native feature #11).
   `get_program_tree` (ghidra.py:6284) is a real, well-implemented
   recursive-walk method with a registered tool-def (ghidra.py:1096), but
   `ghidra_panel.py` has no tab, tree widget, or button anywhere that calls
   it (confirmed via `addTab(self._create_...)` enumeration,
   ghidra_panel.py:294-302). Fix: add a "Program Tree" tab rendering the
   `trees`/module/fragment hierarchy in a `QTreeWidget`, wired to
   `bridge.get_program_tree()`.

3. **No way to delete a bookmark from the GUI** (native feature #26).
   `remove_bookmark` (ghidra.py:6965) and its tool-def (ghidra.py:1202) are
   complete, but the Labels/Bookmarks tab (ghidra_panel.py:307-374) only has
   "Create" and "Refresh Bookmarks" — no delete/remove action, not even from
   a context menu on the bookmark list. Fix: add a "Remove" button or
   right-click action in `_create_labels_bookmarks_tab`
   (ghidra_panel.py:311) wired to `bridge.remove_bookmark`.

4. **REPEATABLE comment type unsupported end-to-end for writing** (native
   feature #21). `get_comments`/`get_all_comments` already read REPEATABLE
   comments (ghidra.py:6208, 6259) but `add_comment`'s `comment_map`
   (ghidra.py:3017-3022) only recognizes EOL/PRE/POST/PLATE and silently
   defaults unknown types to EOL (ghidra.py:3023) — meaning a caller passing
   `comment_type="REPEATABLE"` gets an EOL comment written instead, with no
   error. This is a correctness bug, not just a coverage gap. Fix: add
   `"REPEATABLE": "CodeUnit.REPEATABLE_COMMENT"` to the map in
   `src/intellicrack/bridges/ghidra.py:3017-3022`, and add "REPEATABLE" to
   `_cmt_type_combo.addItems(...)` in
   `src/intellicrack/ui/panels/ghidra_panel.py:662`.

5. **User-defined properties viewer missing from GUI** (native feature #31).
   `get_properties` (ghidra.py:6383) and its tool-def (ghidra.py:1102) are
   real and complete, but no panel control anywhere calls it. Lower priority
   than 1-3 since `UsrPropertyManager` properties are a niche/legacy Ghidra
   feature, but still a full NO-CONTROL gap. Fix: could be folded into a
   details panel (e.g. shown alongside comments or data type lookups) in
   `ghidra_panel.py`.

6. **No memory block removal/split/join** (native feature #15). This is a
   bridge-layer MISSING, not just a GUI gap — no method wraps
   `Memory.removeBlock`, `Memory.split`, or `Memory.join`. Fix belongs in
   `src/intellicrack/bridges/ghidra.py` (new method near
   `create_memory_block`, ghidra.py:6127), a new `ToolFunction` entry in the
   `tool_definition` property, and a "Remove Block" action in the Memory tab
   (`_create_memory_tab`, referenced at ghidra_panel.py:296).

7. **No program-tree module/fragment write API** (native feature #12). Also
   a bridge-layer MISSING — `get_program_tree` is read-only; there is no
   `create_module`/`create_fragment`/`move_into_fragment` equivalent wrapping
   `ProgramModule.createModule`/`createFragment`. Lower priority than #6
   since Program Tree organization is a less commonly automated workflow
   than memory layout editing, and the read side (#11 above, once wired to
   the GUI) already delivers most of the analytical value.

8. **Two orphan duplicate bridge methods** (`create_data` ghidra.py:5900 and
   `add_bookmark` ghidra.py:6894): both are real, tool-def-registered, and
   functionally redundant with already-wired methods (`set_data_type`,
   `create_bookmark`). No user-facing impact since the underlying capability
   is reachable via the sibling method, but they represent dead surface area
   for AI/orchestration tool-calling (an agent could call either the wired
   or unwired variant with identical effect) — worth a design decision on
   whether to consolidate or wire both to the same GUI action to avoid
   confusion for tool-calling consumers.
