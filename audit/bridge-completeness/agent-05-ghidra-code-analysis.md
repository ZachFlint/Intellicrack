# Bridge Completeness Audit — Slice 5: Ghidra Code Analysis

Scope: decompiler, disassembler, P-code, function manager, symbol table, xrefs.
Excluded (different slice): data-type manager, program tree, memory map, comments,
bookmarks, headless scripting.

- Bridge: `src/intellicrack/bridges/ghidra.py` (7372 lines)
- Panel: `src/intellicrack/ui/panels/ghidra_panel.py` (3481 lines)
- Dispatch: `src/intellicrack/core/tools.py:551-620` (`ToolRegistry.execute_tool_call`)
  resolves `function_name` by stripping the `ghidra.` prefix and calling
  `getattr(bridge, attr_name)` (`core/tools.py:587-588`). Registration source of
  truth is `GhidraBridge.tool_definition()` at
  `src/intellicrack/bridges/ghidra.py:327-1271` (69 `ToolFunction` entries).

Legend: OK = fully wired and real | MISSING = no implementation | STUB = fake/no-op
implementation | NOT-REGISTERED = method exists, no tool-def | NO-CONTROL = no GUI
widget reaches it | DEAD-CONTROL = widget exists but not wired.

## Coverage matrix

| # | Native feature (Ghidra ground truth) | Bridge method (file:line) | Tool-def | GUI control |
|---|---|---|---|---|
| 1 | Decompile function to C pseudocode | `decompile` ghidra.py:2384 — real `DecompInterface` call via Jython, distinguishes not-found/failed/ok | OK ghidra.py:370-381 (`ghidra.decompile`) | OK — function-tree click, `ghidra_panel.py:1720-1728` → `_apply_decompiled` |
| 2 | Configure decompiler (simplification style, max instructions, extra options) | `set_decompiler_options` ghidra.py:6009 | OK ghidra.py:1044-1056 (`ghidra.set_decompiler_options`) | OK — "Apply Decompiler Options" button, `ghidra_panel.py:867-868` → `_on_apply_decompiler_options` |
| 3 | Edit function signature (return type, calling convention, name) from decompiler/listing | `edit_function_signature` ghidra.py:3772 | OK ghidra.py:660-669 (`ghidra.edit_function_signature`) | OK — function context menu "Edit Signature", `ghidra_panel.py:2007-2008,2137-2170` |
| 4 | Rename local variable / retype variable (decompiler-driven) | `set_function_variable_type` ghidra.py:3854 (retype only; no dedicated *rename* endpoint — renaming is folded into the same variable dialog via `var_name:new_type` in the GUI, not a distinct Ghidra "rename local var" op) | OK ghidra.py:670-679 (`ghidra.set_function_variable_type`) | OK — function context menu "Set Variable Type", `ghidra_panel.py:2026-2045` |
| 5 | Commit parameters / return type back to database from decompiler analysis | Folded into `edit_function_signature` (ghidra.py:3772); no separate "commit params" endpoint | OK (see row 3) | OK (see row 3) |
| 6 | Disassemble instructions at an address (Listing view) | `disassemble` ghidra.py:2486 | OK ghidra.py:382-401 (`ghidra.disassemble`) | OK — function-tree click, `ghidra_panel.py:1730-1738` → `_apply_disassembly` |
| 7 | Single-instruction control-flow inspection (mnemonic, flow type, fallthrough, flow targets) | `get_instruction_flow` ghidra.py:5768 — real, queries `Instruction.getFlowType/getFallThrough/getFlows` | OK ghidra.py:977-984 (`ghidra.get_instruction_flow`) | **NO-CONTROL** — zero references from `ghidra_panel.py` or any other panel (`rg get_instruction_flow` only hits bridge + tool-def) |
| 8 | Register value tracking at an address (context register analysis) | `get_register_value` ghidra.py:4836 — real, uses `ProgramContext.getRegisterValue` | OK ghidra.py:844-852 (`ghidra.get_register_value`) | **NO-CONTROL** — no GUI caller anywhere in repo |
| 9 | P-code IR listing for a function | `get_pcode` ghidra.py:4530 | OK ghidra.py:790-804 (`ghidra.get_pcode`) | OK — function-tree click, `ghidra_panel.py:1740-1748` → `_apply_pcode`, "PCode" tab `ghidra_panel.py:235-239` |
| 10 | Program slicing (forward/backward data-flow slice on P-code) | `get_slice` ghidra.py:4686 | OK ghidra.py:820-835 (`ghidra.get_slice`) | OK — "Get Slice" button in Call Graph tab, `ghidra_panel.py:631-632,2991-3008` → `_apply_slice` |
| 11 | Basic-block / CFG structure of a function | `get_basic_blocks` ghidra.py:4612 — real, uses `BasicBlockModel` | OK ghidra.py:805-819 (`ghidra.get_basic_blocks`) | OK — function-tree click, `ghidra_panel.py:1750-1758` → `_apply_cfg`, "CFG" tab (`CFGGraphView`) `ghidra_panel.py:241-248` |
| 12 | Function listing / enumeration with name filter | `get_functions` ghidra.py:2220 | OK ghidra.py:356-368 (`ghidra.get_functions`) | OK — Refresh button + filter box, `ghidra_panel.py:1106-1108,1642-1659,1691-1697` |
| 13 | Get single function info at address | `get_function` ghidra.py:2289 | OK ghidra.py:572-584 (`ghidra.get_function`) | **NO-CONTROL** — no GUI caller anywhere in repo (only `get_functions` plural and `get_function_body` are wired) |
| 14 | Create function at address | `create_function` ghidra.py:3675 | OK ghidra.py:642-650 (`ghidra.create_function`) | OK — "Create" button in functions sidebar, `ghidra_panel.py:1131-1132,1905-1925` |
| 15 | Delete function definition | `delete_function` ghidra.py:3714 | OK ghidra.py:651-658 (`ghidra.delete_function`) | OK — function context menu "Delete Function", `ghidra_panel.py:1958,2119-2135` |
| 16 | Rename function | `rename_function` ghidra.py:2911 | OK ghidra.py:462-480 (`ghidra.rename_function`) | OK — function context menu "Rename Function", `ghidra_panel.py:1947,1992-2005` |
| 17 | Function body / address ranges / thunk-size info | `get_function_body` ghidra.py:5589 | OK ghidra.py:946-953 (`ghidra.get_function_body`) | OK — function context menu "Get Function Body", `ghidra_panel.py:1953,2064-2073` → `_show_function_body_info` |
| 18 | Stack frame layout (locals/params) for a function | `get_stack_frame` ghidra.py:5486 | OK ghidra.py:938-945 (`ghidra.get_stack_frame`) | OK — function context menu "Get Stack Frame", `ghidra_panel.py:1952,2053-2062` |
| 19 | List available calling conventions from compiler spec | `get_calling_conventions` ghidra.py:5734 | OK ghidra.py:971-976 (`ghidra.get_calling_conventions`) | OK — function context menu "Show Calling Conventions", `ghidra_panel.py:1954,2075-2092` |
| 20 | Thunk status / resolved thunk target for a function | `get_thunk_info` ghidra.py:6717 — real, uses `Function.isThunk`/`getThunkedFunction` | OK ghidra.py:1149-1156 (`ghidra.get_thunk_info`) | **NO-CONTROL** — no GUI caller; `add_thunk`/`remove_thunk` mutators are also unwired (see gap list) |
| 21 | Xrefs-to an address (incoming references) | `get_xrefs_to` ghidra.py:2555 | OK ghidra.py:402-414 (`ghidra.get_xrefs_to`) | OK — auto on function click via `show_xrefs`, `ghidra_panel.py:1760,2317-2337` → `_apply_xrefs_to`, "XRefs" tab `ghidra_panel.py:289-292` |
| 22 | Xrefs-from an address (outgoing references) | `get_xrefs_from` ghidra.py:2604 | OK ghidra.py:415-427 (`ghidra.get_xrefs_from`) | OK — `ghidra_panel.py:2339-2347` → `_apply_xrefs_from` |
| 23 | Add a manual memory reference between addresses | `add_reference` ghidra.py:5035 | OK ghidra.py:861-877 (`ghidra.add_reference`) | **NO-CONTROL** — no GUI caller found |
| 24 | Delete a memory reference | `delete_reference` ghidra.py:5132 | OK ghidra.py:878-886 (`ghidra.delete_reference`) | **NO-CONTROL** — no GUI caller found |
| 25 | External reference add/remove (imported symbol xrefs) | `add_external_reference` ghidra.py:7256 / `remove_external_reference` ghidra.py:7325 | OK ghidra.py:1253-1269 | **NO-CONTROL** — `_on_add_external_function` (`ghidra_panel.py:795-796`) wires `add_external_function` (symbol-table entry), not `add_external_reference`/`remove_external_reference` (xref-specific) |
| 26 | Query external references from an address | `get_external_references` ghidra.py:6767 | OK ghidra.py:1157-1164 (`ghidra.get_external_references`) | **NO-CONTROL** — no GUI caller found |
| 27 | Call-tree navigation (callees/callers/both, recursive, depth-bounded) | `get_call_tree` ghidra.py:5644 | OK ghidra.py:954-970 (`ghidra.get_call_tree`) | OK — "Build" button, Call Graph tab, `ghidra_panel.py:615-616,2893-2915` |
| 28 | Bidirectional call graph (callees+callers in one call from a root) | `get_call_graph` ghidra.py:4112 — real, distinct algorithm from `get_call_tree` (returns both directions in one payload) | OK ghidra.py:728-742 (`ghidra.get_call_graph`) | **NO-CONTROL** — the "Show Call Graph" context-menu action (`ghidra_panel.py:1951,2047-2051`) actually opens the Call Graph *tab* and calls `_on_build_call_graph`, which invokes `get_call_tree`, not `get_call_graph`. `get_call_graph` itself has zero GUI callers — functionally orphaned duplicate of `get_call_tree` from the GUI's perspective. |
| 29 | List callers of a function (direct callers only) | `get_callers` ghidra.py:4791 | OK ghidra.py:836-843 (`ghidra.get_callers`) | OK — "Show Callers" button, Call Graph tab, `ghidra_panel.py:629-630,2958-2989` |
| 30 | Symbol search by name/type (Symbol Table window equivalent) | `search_symbols` ghidra.py:5436 | OK ghidra.py:924-937 (`ghidra.search_symbols`) | OK — Symbols tab "Search Symbols", `ghidra_panel.py:714-715,3144-3145` |
| 31 | Set/create label at address | `set_label` ghidra.py:3307 | OK ghidra.py:598-606 (`ghidra.set_label`) | OK — Labels/Bookmarks tab "Set Label", `ghidra_panel.py:329-330,2391-2415` |
| 32 | Explicit add-label mutator (separate from set_label) | `add_label` ghidra.py:7036 | OK ghidra.py:1211-1220 (`ghidra.add_label`) | **NO-CONTROL** — GUI's "Set Label" button calls `set_label`, not `add_label`; `add_label` is unreferenced from the panel |
| 33 | Remove label at address | `remove_label` ghidra.py:7097 | OK ghidra.py:1221-1229 (`ghidra.remove_label`) | **NO-CONTROL** — no GUI caller found |
| 34 | List labels near an address (radius search) | `get_labels` ghidra.py:3379 | OK ghidra.py:607-615 (`ghidra.get_labels`) | OK — "Refresh Labels" button, `ghidra_panel.py:339-341,2416-2458` |
| 35 | Namespace create / list (symbol table namespace tree) | `create_namespace` ghidra.py:5219 / `get_namespaces` ghidra.py:5261 | OK ghidra.py:894-907 | OK — Symbols tab "Create Namespace"/"Refresh", `ghidra_panel.py:736-739` |
| 36 | Equate (named constant) create / list | `create_equate` ghidra.py:5301 / `get_equates` ghidra.py:5396 | OK ghidra.py:908-923 | OK — Symbols tab "Create Equate"/"Refresh", `ghidra_panel.py:760-763` |
| 37 | Imported symbol table (Imports window) | `get_imports` ghidra.py:3078 | OK ghidra.py:508-513 (`ghidra.get_imports`) | OK — Imports tab, auto-refreshed after analysis, `ghidra_panel.py:1392,2176-2189` |
| 38 | Exported symbol table (Exports window) | `get_exports` ghidra.py:3127 | OK ghidra.py:514-519 (`ghidra.get_exports`) | OK — Exports tab, auto-refreshed after analysis, `ghidra_panel.py:1393,2225-...` |
| 39 | Add external function to external symbol table | `add_external_function` ghidra.py:6815 | OK ghidra.py:1165-1174 (`ghidra.add_external_function`) | OK — Symbols tab "Add External", `ghidra_panel.py:795-796` |
| 40 | Relocation table listing | `get_relocations` ghidra.py:5176 | OK ghidra.py:887-892 (`ghidra.get_relocations`) | OK — Symbols tab "Refresh Relocations", `ghidra_panel.py:775-776` |
| 41 | String search (Defined Strings window equivalent) | `search_strings` ghidra.py:2681 | OK ghidra.py:428-448 (`ghidra.search_strings`) | OK — Strings tab search box/button, `ghidra_panel.py:271-278,2260-2311` |
| 42 | Byte-pattern search (with wildcard mask) | `search_bytes` ghidra.py:2812 | OK ghidra.py:449-461 (`ghidra.search_bytes`) | OK — toolbar byte search input, `ghidra_panel.py:1493-1524` |
| 43 | Import debug symbols (PDB/DWARF) | `import_debug_info` ghidra.py:4886 | OK ghidra.py:853-860 (`ghidra.import_debug_info`) | OK — "Import Debug Info", `ghidra_panel.py:1540-1567` |
| 44 | Program/language metadata (compiler, endianness, address size, image base) | `get_program_info` ghidra.py:4256 | OK ghidra.py:750-754 (`ghidra.get_program_info`) | OK — Segments/Program tab "Refresh Program Info", `ghidra_panel.py:566-567,2818-...` |
| 45 | Add thunk relationship | `add_thunk` ghidra.py:7146 | OK ghidra.py:1230-1243 (`ghidra.add_thunk`) | **NO-CONTROL** — no GUI caller found |
| 46 | Remove thunk relationship | `remove_thunk` ghidra.py:7204 | OK ghidra.py:1244-1251 (`ghidra.remove_thunk`) | **NO-CONTROL** — no GUI caller found |
| 47 | Set color highlight on code unit (visual analysis marker) | `set_color` ghidra.py:6488 | OK ghidra.py:1122-1130 (`ghidra.set_color`) | OK — function context menu "Set Color", `ghidra_panel.py:1955,2094-2117` |

## Coverage summary

- **47 native code-analysis features** enumerated for this slice.
- **Fully ported (OK/OK/OK, all 3 layers): 34 of 47.**
- **Gap counts by type** (features with at least one non-OK layer; all gaps here
  are GUI-layer since bridge+tool-def were 100% consistent — see below):
  - NO-CONTROL: **13** (`get_instruction_flow`, `get_register_value`,
    `get_function` singular, `get_thunk_info`, `add_reference`,
    `delete_reference`, `add_external_reference`/`remove_external_reference`
    (counted together as row 25), `get_external_references`, `get_call_graph`,
    `add_label`, `remove_label`, `add_thunk`, `remove_thunk`)
  - DEAD-CONTROL: 0
  - MISSING (no bridge implementation): 0
  - STUB (fake/no-op implementation): 0
  - NOT-REGISTERED (implemented, no tool-def): 0

Layer-1/Layer-2 consistency check: every one of the 69 `ToolFunction` entries in
`tool_definition()` resolves via `getattr` to a real `async def` method with a
genuine Jython/`_execute_remote` implementation (spot-verified: `decompile`,
`get_instruction_flow`, `get_basic_blocks`, `get_register_value`,
`get_thunk_info`, `get_call_graph` — all perform real Ghidra API calls, none are
stubs). No orphaned tool-defs (pointing at nonexistent methods) and no
unregistered public methods were found for this slice — the only public methods
without a `ToolFunction` entry are lifecycle methods (`initialize`,
`is_available`, `shutdown`), which are correctly excluded since they aren't
AI-callable analysis actions.

## Prioritized gap list

All gaps are **Layer 3 (GUI) only** — bridge and tool-definition layers are
complete for this slice. Ordered by user-facing impact:

1. **`get_call_graph` orphaned by GUI duplication** (highest impact — confusing
   architecture). The panel's only "call graph" affordance
   (`ghidra_panel.py:2893-2915`, `_on_build_call_graph`) calls `get_call_tree`
   (ghidra.py:5644), a single-direction recursive tree. The distinct
   `get_call_graph` method (ghidra.py:4112) computes a genuinely different
   bidirectional (callers+callees in one payload) result and is fully
   implemented/registered but has no button. Fix: either wire a "Bidirectional"
   toggle/checkbox in the Call Graph tab that calls `get_call_graph` when
   both directions are wanted at once, or remove the duplicate capability.
   Host file: `src/intellicrack/ui/panels/ghidra_panel.py` (`_create_call_graph_tab`,
   `_on_build_call_graph`).

2. **Thunk management entirely unreachable from GUI** (`get_thunk_info`,
   `add_thunk`, `remove_thunk` — 3 of the 13 NO-CONTROL gaps belong to this one
   feature). A power user inspecting call graphs/imports frequently needs to see
   or fix thunk relationships (common in packed/obfuscated binaries and import
   tables). Fix: add a "Thunk Info" action to the function context menu
   (alongside existing "Get Function Body"/"Get Stack Frame" entries at
   `ghidra_panel.py:1946-1958`) plus add/remove-thunk controls, most naturally
   in the functions sidebar or context menu. Host file:
   `src/intellicrack/ui/panels/ghidra_panel.py`.

3. **Reference table editing has no controls** (`add_reference`,
   `delete_reference`, `get_external_references`, `add_external_reference`,
   `remove_external_reference` — 5 of the 13 NO-CONTROL gaps). The XRefs tab
   (`ghidra_panel.py:289-292`) is read-only/display-only; there's no way to
   manually add/remove a reference or inspect external references for the
   selected address, even though the bridge fully supports it. Fix: add
   "Add Reference" / "Delete Reference" buttons to the XRefs tab wired to
   `bridge.add_reference`/`bridge.delete_reference`, and either merge external
   references into the same view or add a small external-refs sub-panel calling
   `get_external_references`. Host file:
   `src/intellicrack/ui/panels/ghidra_panel.py` (new controls near
   `show_xrefs`/`_apply_xrefs_to`/`_apply_xrefs_from`, ~line 2317-2386).

4. **`get_instruction_flow` and `get_register_value` unreachable** (lower
   impact — power-user/debugging features, not core workflow). Both are
   real, useful for understanding branch/jump targets and tracked register
   context at a specific instruction, natural additions to the Disassembly
   tab (e.g., a context menu on the disassembly view, or a "Get Flow"/"Get
   Register" button next to the address). Host file:
   `src/intellicrack/ui/panels/ghidra_panel.py` (`_create_code_tabs`, disassembly
   view section ~line 229-233).

5. **`get_function` (singular) and `add_label` unreachable** (minor — largely
   redundant with existing wired equivalents `get_functions`/`get_function_body`
   and `set_label`). Low priority; could be left AI-orchestration-only, or
   `get_function` could back a "Go to address" lookup box, and `add_label`'s
   `primary` flag could be exposed as a checkbox next to the existing Set Label
   controls. Host file: `src/intellicrack/ui/panels/ghidra_panel.py`
   (`_create_labels_bookmarks_tab`, ~line 310-384).
