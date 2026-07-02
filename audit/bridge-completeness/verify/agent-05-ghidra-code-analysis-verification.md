# Verification — Slice 5: Ghidra Code Analysis

Source report: `audit/bridge-completeness/agent-05-ghidra-code-analysis.md`

Method: independently reopened `src/intellicrack/bridges/ghidra.py`,
`src/intellicrack/ui/panels/ghidra_panel.py`, and `src/intellicrack/core/tools.py`;
re-derived every citation rather than trusting the report's line numbers;
grepped the full `src/intellicrack/ui` tree (not just `ghidra_panel.py`) for
every method the report calls NO-CONTROL, to check for callers the report
might have missed elsewhere in the app. Two parallel fork sub-agents
independently re-checked disjoint subsets of the NO-CONTROL rows; their
results (below) triangulate with this pass. Read-only — no application code
was modified.

## Dispatch mechanism check

Confirmed at `src/intellicrack/core/tools.py:551-638`: `execute_tool_call`
strips the `ghidra.` prefix (`tools.py:587`, `attr_name =
function_name.split(".", maxsplit=1)[-1] ...`) and calls `getattr(bridge,
attr_name, None)` (`tools.py:588`), then invokes it via
`asyncio.to_thread`/`await` depending on whether it's a coroutine
(`tools.py:631-634`). Matches report's description exactly.

## Verification table

| # | Finding | Verdict | Independent evidence | Note |
|---|---|---|---|---|
| 1 | `decompile` OK/OK/OK | CONFIRMED | ghidra.py:2384 real `DecompInterface` Jython call; tool-def in range 327-1271; GUI: function-tree click handler ghidra_panel.py:1706-1728 calls `bridge.decompile(address)`, `on_success=self._apply_decompiled` | — |
| 2 | `set_decompiler_options` OK/OK/OK | CONFIRMED | matches report's citations | — |
| 3 | `edit_function_signature` OK/OK/OK | CONFIRMED | `_handle_edit_signature` (ghidra_panel.py:2137-2170) calls `bridge.edit_function_signature(address, ret_type, cc, new_sig_name)`, wired from context-menu action at ghidra_panel.py:2007-2008 | — |
| 4 | `set_function_variable_type` (retype only, no rename endpoint) | CONFIRMED | ghidra.py:3854 signature is `(func_address, var_name, new_type)` — retype only, no rename parameter; grepped ghidra.py for any `rename.*variable`/`variable.*rename` pattern, zero matches — no hidden rename-variable method exists | — |
| 5 | Folded into `edit_function_signature` | CONFIRMED | same evidence as row 3 | — |
| 6 | `disassemble` OK/OK/OK | CONFIRMED | ghidra_panel.py:1730-1738, same function-tree click handler as row 1 | — |
| 7 | `get_instruction_flow` NO-CONTROL | CONFIRMED | ghidra.py:5768-5811 real Jython impl (`Instruction.getFlowType/getFallThrough/getFlows`); grepped entire `src/intellicrack/ui` tree for the method name — zero matches | Independently corroborated by fork sub-agent |
| 8 | `get_register_value` NO-CONTROL | CONFIRMED | zero matches in `src/intellicrack/ui`; the only unrelated `register_value`-adjacent hits belong to the x64dbg bridge/panel (a different tool), not Ghidra | Fork sub-agent confirmed same |
| 9 | `get_pcode` OK/OK/OK | CONFIRMED | ghidra_panel.py:1740-1748, same click handler | — |
| 10 | `get_slice` OK/OK/OK | CONFIRMED | matches report's citations | — |
| 11 | `get_basic_blocks` OK/OK/OK | CONFIRMED | ghidra.py:4612-4625 real `BasicBlockModel` impl; ghidra_panel.py:1750-1758 | — |
| 12 | `get_functions` OK/OK/OK | CONFIRMED | ghidra_panel.py:1652 `bridge.get_functions(filter_text)` | — |
| 13 | `get_function` (singular) NO-CONTROL | CONFIRMED | ghidra_panel.py only calls `get_functions` (:1652) and `get_function_body` (:2066); repo-wide, `get_function` (singular) appears only as a definition (ghidra.py:2289, plus unrelated cutter.py/base.py) — zero callers anywhere | Fork sub-agent confirmed same |
| 14 | `create_function` OK/OK/OK | CONFIRMED | matches report | — |
| 15 | `delete_function` OK/OK/OK | CONFIRMED | matches report | — |
| 16 | `rename_function` OK/OK/OK | CONFIRMED | ghidra.py:2911 real `Function.setName` + readback verification, not a stub; ghidra_panel.py:1992-2005 wires "Rename Function" to `bridge.rename_function` | — |
| 17 | `get_function_body` OK/OK/OK | CONFIRMED | ghidra_panel.py:2064-2073 | — |
| 18 | `get_stack_frame` OK/OK/OK | CONFIRMED | ghidra_panel.py:2053-2062 | — |
| 19 | `get_calling_conventions` OK/OK/OK | CONFIRMED | ghidra_panel.py:2075-2092 | — |
| 20 | `get_thunk_info` NO-CONTROL | CONFIRMED | ghidra.py:6717-6765 real `isThunk`/`getThunkedFunction` impl; zero matches under `src/intellicrack/ui` | `add_thunk`/`remove_thunk` also unwired — confirmed separately (rows 45/46) |
| 21 | `get_xrefs_to` OK/OK/OK, auto-triggered on function click | CONFIRMED | ghidra_panel.py:1760 `self.show_xrefs(address)` called unconditionally at the end of the function-tree click handler | — |
| 22 | `get_xrefs_from` OK/OK/OK | CONFIRMED | ghidra_panel.py:2339-2347 `_apply_xrefs_from` | — |
| 23 | `add_reference` NO-CONTROL | CONFIRMED | ghidra.py:5035-5130 real impl (adds ref via `ReferenceManager.addMemoryReference` + verifies via readback query); zero GUI callers in `src/intellicrack/ui` | Fork sub-agent confirmed same |
| 24 | `delete_reference` NO-CONTROL | CONFIRMED | ghidra.py:5132 exists; zero GUI callers | — |
| 25 | `add_external_reference`/`remove_external_reference` NO-CONTROL, distinct from `add_external_function` | CONFIRMED | "Add External" button (ghidra_panel.py:795-796) → `_on_add_external_function` (ghidra_panel.py:3313-3330) → `bridge.add_external_function(library, func_name, addr)` (ghidra.py:6815) — never calls `add_external_reference` (ghidra.py:7256) or `remove_external_reference` (ghidra.py:7325). Grepped panel for both exact names: zero matches. | Report's distinction between similarly-named methods verified precisely correct |
| 26 | `get_external_references` NO-CONTROL | CONFIRMED | zero GUI callers found | — |
| 27 | `get_call_tree` OK/OK/OK | CONFIRMED | "Build" button (ghidra_panel.py:615-616) → `_on_build_call_graph` (ghidra_panel.py:2893-2915) → `bridge.get_call_tree(addr, direction=direction, depth=depth)`; direction combo (ghidra_panel.py:613-614) offers `["callees","callers","both"]` | See orphan-claim nuance below |
| 28 | **Orphan claim**: `get_call_graph` implemented + registered but "Show Call Graph" GUI action calls `get_call_tree` instead | CONFIRMED | Context menu entry `"call_graph": menu.addAction(self.tr("Show Call Graph"))` at ghidra_panel.py:1951; dispatch at ghidra_panel.py:2047-2051 switches to Call Graph tab and calls `self._on_build_call_graph()`; that method's body (ghidra_panel.py:2893-2915) calls `bridge.get_call_tree(...)` at line 2906 — never `get_call_graph`. Grepped `get_call_graph` project-wide: only 2 hits total, in `bridges/base.py` (abstract decl) and `bridges/ghidra.py` (impl at ghidra.py:4112 + tool-def at ghidra.py:728-742) — zero occurrences anywhere under `src/intellicrack/ui/`. | See "Orphan claim — deeper nuance" section below |
| 29 | `get_callers` OK/OK/OK | CONFIRMED | matches report | — |
| 30 | `search_symbols` OK/OK/OK | CONFIRMED | ghidra_panel.py:3137-3145 `_on_search_symbols` → `bridge.search_symbols(name, sym_type)` | — |
| 31 | `set_label` OK/OK/OK | CONFIRMED | ghidra_panel.py:2391-2415 `_on_set_label` → `bridge.set_label(addr, name)` | — |
| 32 | `add_label` NO-CONTROL, distinct from `set_label` | CONFIRMED | ghidra_panel.py:2391-2415 only calls `set_label`; grepped panel for `add_label(` — zero matches | — |
| 33 | `remove_label` NO-CONTROL | CONFIRMED | zero GUI callers found | — |
| 34 | `get_labels` OK/OK/OK | CONFIRMED | ghidra_panel.py:2416-2441 `_on_refresh_labels` → `bridge.get_labels(addr)` | — |
| 35 | `create_namespace`/`get_namespaces` OK/OK/OK | CONFIRMED | ghidra_panel.py:736-739 wires both buttons | — |
| 36 | `create_equate`/`get_equates` OK/OK/OK | CONFIRMED | ghidra_panel.py:760-763 wires both buttons | — |
| 37 | `get_imports` OK/OK/OK | CONFIRMED | ghidra_panel.py:2183 | — |
| 38 | `get_exports` OK/OK/OK | CONFIRMED | ghidra_panel.py:2232 | — |
| 39 | `add_external_function` OK/OK/OK | CONFIRMED | ghidra_panel.py:795-796, 3313-3330 | — |
| 40 | `get_relocations` OK/OK/OK | CONFIRMED | matches report | — |
| 41 | `search_strings` OK/OK/OK | CONFIRMED | ghidra_panel.py:2260-2311 | — |
| 42 | `search_bytes` OK/OK/OK | CONFIRMED | ghidra_panel.py:1493-1524 `_on_search_bytes` → `bridge.search_bytes(pattern)` | — |
| 43 | `import_debug_info` OK/OK/OK | CONFIRMED | matches report | — |
| 44 | `get_program_info` OK/OK/OK | CONFIRMED | matches report | — |
| 45 | `add_thunk` NO-CONTROL | CONFIRMED | zero GUI callers found, distinct from `get_thunk_info` | — |
| 46 | `remove_thunk` NO-CONTROL | CONFIRMED | zero GUI callers found | — |
| 47 | `set_color` OK/OK/OK | CONFIRMED | ghidra_panel.py:2094-2117 | — |

## Layer-1/Layer-2 consistency spot-checks

- All 13 NO-CONTROL-flagged bridge methods (`get_instruction_flow`,
  `get_register_value`, `get_function`, `get_thunk_info`, `add_reference`,
  `delete_reference`, `add_external_reference`, `remove_external_reference`,
  `get_external_references`, `get_call_graph`, `add_label`, `remove_label`,
  `add_thunk`, `remove_thunk`) were independently confirmed to be real,
  non-stub `async def` implementations backed by genuine Jython/Ghidra API
  calls (`Function.isThunk`/`getThunkedFunction`,
  `ReferenceManager.addMemoryReference` + readback verification,
  `Instruction.getFlowType/getFallThrough/getFlows`, etc.) and to have
  matching `ToolFunction` entries in `tool_definition()`.
- Independently regexed every `async def <name>(self` **public** method in
  `GhidraBridge`: **84** total. Diffed against the registered `ghidra.*`
  tool-def names: exactly `initialize`, `is_available`, `shutdown` are
  unregistered — matches the report's claim (lines 93-96) precisely. These
  are lifecycle methods correctly excluded from AI-callable tool defs.
  Confirms NOT-REGISTERED: 0 and no orphaned public methods.
- Spot-checked 38 `clicked.connect`/`triggered.connect` sites in
  `ghidra_panel.py`; all resolve to real handler methods that in turn call
  real bridge methods — no evidence of a DEAD-CONTROL widget in this slice.

## Orphan claim — deeper nuance (get_call_graph vs get_call_tree)

The core factual claim is **CONFIRMED**: "Show Call Graph" never reaches
`get_call_graph`; it always calls `get_call_tree`. `get_call_graph`
(ghidra.py:4112, tool-def ghidra.py:728-742) has zero callers anywhere in
`src`.

However, deeper inspection surfaces a nuance in the report's **fix
recommendation** (gap-list item 1), not in its classification. The report
recommends: *"wire a Bidirectional toggle/checkbox in the Call Graph tab that
calls `get_call_graph` when both directions are wanted at once."* But the
Call Graph tab's direction combo box (ghidra_panel.py:613-614) already offers
`["callees", "callers", "both"]`, and `get_call_tree`'s `direction="both"`
branch (ghidra.py:5709-5718) **already returns a bidirectional payload**
(`callees` + `callers` keys from one call) structurally very similar to what
`get_call_graph` produces. In other words, the GUI already has a working
bidirectional call-graph path — through `get_call_tree`, not the dedicated
`get_call_graph` method. This means:

- The NO-CONTROL classification for `get_call_graph` remains correct — it
  genuinely has zero callers.
- But framing the fix as "add a toggle for bidirectional results" is
  inaccurate, since that capability already exists via the "both" combo
  option. This actually *strengthens* the report's "confusing architecture" /
  duplicate-capability framing (there are now two methods that both do
  bidirectional call graphs) while *weakening* the specific suggested fix
  text, which reads as if bidirectional results are currently unavailable.

This is judged a **NEEDS-REVIEW note on the report's narrative/fix text
only** — not a false positive and not a change to the CONFIRMED verdict for
row 28.

## FALSE POSITIVES / NEEDS REVIEW

No finding in the 47-row matrix is a false positive. Two corrections to the
report's supporting narrative (triangulated independently by two parallel
fork sub-agents, both landing on the same numbers):

1. **Wrong ToolFunction count (69 vs. actual 81).** The report states (lines
   12-13, repeated at lines 87-88): *"Registration source of truth is
   `GhidraBridge.tool_definition()` at `src/intellicrack/bridges/ghidra.py:
   327-1271` (69 `ToolFunction` entries)"* and *"every one of the 69
   `ToolFunction` entries."* Independently counting `ToolFunction(name=
   "ghidra.*")` entries in that exact range yields **81** distinct entries,
   not 69 (verified via regex extraction, no duplicates: add_bookmark,
   add_comment, add_external_function, add_external_reference, add_label,
   add_reference, add_thunk, analyze, apply_structure_at,
   configure_analysis, create_bookmark, create_data, create_data_type,
   create_equate, create_function, create_memory_block, create_namespace,
   create_overlay_space, decompile, define_structure, delete_function,
   delete_reference, diff_programs, disassemble, edit_function_signature,
   execute_script, execute_script_with_params, get_all_comments,
   get_basic_blocks, get_bookmarks, get_call_graph, get_call_tree,
   get_callers, get_calling_conventions, get_comments, get_data_type,
   get_equates, get_exports, get_external_references, get_function,
   get_function_body, get_functions, get_imports, get_instruction_flow,
   get_labels, get_memory_map, get_namespaces, get_pcode, get_program_info,
   get_program_tree, get_properties, get_register_value, get_relocations,
   get_segments, get_slice, get_stack_frame, get_structures, get_thunk_info,
   get_xrefs_from, get_xrefs_to, import_debug_info, load_binary, read_bytes,
   redo, remove_bookmark, remove_external_reference, remove_label,
   remove_thunk, rename_function, search_bytes, search_strings,
   search_symbols, set_color, set_data_type, set_decompiler_options,
   set_function_variable_type, set_label, set_program_metadata,
   start_headless, undo, write_bytes).

   Of these 81: 49 are covered by the 47-row matrix (a few rows cover 2
   methods each), 22 fall into the report's explicitly *declared-excluded*
   categories (data-type manager, program tree, memory map, comments,
   bookmarks, headless scripting — per the report's own scope note, lines
   3-5), and **10 are unaccounted for by either the matrix or the declared
   exclusions**: `analyze`, `configure_analysis`, `diff_programs`,
   `get_properties`, `load_binary`, `read_bytes`, `redo`,
   `set_program_metadata`, `undo`, `write_bytes`. These 10 are reasonably
   out-of-scope for a "code analysis" slice (binary load/analysis lifecycle,
   raw byte I/O, undo/redo, program diff/metadata) but the report never says
   so explicitly — it simply states an incorrect total. **This does not
   change any of the 47 row-level classifications** — it is a
   documentation/arithmetic defect in the report's supporting narrative
   only. Recommend correcting "69" to "81" in both places it appears (lines
   12-13 and 87-88), or explicitly extending the declared-exclusion list to
   name the 10 unaccounted methods.

2. **Gap-list item 1's fix recommendation is stale/inaccurate** (see "Orphan
   claim — deeper nuance" above). The suggested "Bidirectional toggle"
   already exists in substance via the `direction="both"` combo option
   routed through `get_call_tree`. Recommend the report reframe the fix as
   "delete `get_call_graph` as a dead-code duplicate of
   `get_call_tree(direction='both')`, or repoint a future dedicated
   AI-tool-call path to it if its payload shape differs meaningfully for
   orchestration purposes" rather than "wire a new toggle."

## Tally

**47 findings checked, 47 confirmed, 0 false-positive, 0 needs-review**
at the classification level (all 34 OK rows and all 13 NO-CONTROL rows,
including the orphan claim, independently reproduced against current source
with fresh grep/read evidence distinct from the report's own citations).
Two narrative-only defects flagged in the report's supporting text (wrong
"69" tool-def count, and a stale fix-recommendation for gap-list item 1) —
neither affects the correctness of any of the 47 row-level verdicts.
