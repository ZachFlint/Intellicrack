# Remediation Verification — Ghidra (slices 5 & 6)

Scope: `src/intellicrack/bridges/ghidra.py`, `src/intellicrack/ui/panels/ghidra_panel.py`
and its new sub-modules (`ghidra_panel_data_types.py`, `ghidra_panel_program_tree.py`,
`ghidra_panel_extras.py`), and `tests/test_bridge_completeness/ghidra/`.

Method: read-only re-verification against the live working tree (all edits are
currently uncommitted — `git status` shows the bridge/panel files modified and
the three new panel sub-modules + test directory untracked). Every citation
below is an independent read, not copied from the slice reports or the prior
`verify/agent-05`/`verify/agent-06` reports (which only verified the
*pre-remediation* audit, not this remediation).

## PART A — Three-layer verification

### `add_comment` REPEATABLE fix (slice 6, gap-list item 4 — correctness bug)

CONFIRMED, real fix, no silent downgrade. `ghidra.py:3081-3092`:
`comment_map` now has 5 entries (`EOL`/`PRE`/`POST`/`PLATE`/`REPEATABLE` →
`CodeUnit.REPEATABLE_COMMENT`). The lookup changed from
`.get(comment_type, "CodeUnit.EOL_COMMENT")` (silent fallback) to
`.get(comment_type)` followed by an explicit `if ghidra_type is None: raise
ToolError(...)` (`ghidra.py:3088-3092`) — an unrecognized type now raises
instead of silently writing EOL. The write path (`ghidra.py:3104`) and the
readback verification (`ghidra.py:3115-3142`) both use the resolved
`ghidra_type`, so a REPEATABLE request genuinely writes and verifies a
`CodeUnit.REPEATABLE_COMMENT`. GUI: `_cmt_type_combo.addItems([...,
"REPEATABLE"])` at `ghidra_panel.py:766`.

### New program-model methods (slice 6, gap-list items 4/6/7 — was MISSING)

All four are real, non-stub, transaction-wrapped, verified-outcome
implementations:

- `remove_memory_block` (`ghidra.py:6244-6290`) — emits `memory.removeBlock`,
  guards on `found`/`ok`, raises `ToolError` on either failure.
- `split_memory_block` (`ghidra.py:6292-6349`) — emits `memory.split`, guards
  on `found`/`in_range`/`ok`.
- `join_memory_blocks` (`ghidra.py:6351-6406`) — emits `memory.join`, returns
  the exact joined-block name Ghidra reports (not a hardcoded echo of the
  first input name).
- `edit_program_tree` (`ghidra.py:6616-6725`) — `create_module` /
  `create_fragment` / `move_child` operations against
  `ProgramModule.createModule`/`createFragment`/`moveChild`; validates
  `operation` against an explicit set before any RPC call; guards on
  `tree_found`/`parent_found`/`ok`.

Tool-defs: `ghidra.remove_memory_block` (`ghidra.py:1081-1087`),
`ghidra.split_memory_block` (`ghidra.py:1089-1101`),
`ghidra.join_memory_blocks` (`ghidra.py:1103-1110`),
`ghidra.edit_program_tree` (`ghidra.py:1139-1164`) — every parameter name in
each schema matches the corresponding method signature exactly (`name`;
`name`+`split_address`; `name1`+`name2`; `tree_name`+`operation`+
`parent_module`+`child_name`, with `operation` correctly declared as an
`enum` of the three valid values).

### `ghidra.get_memory_map` / `ghidra.write_bytes` capability gate

CONFIRMED not blocked. `bridges/base.py:156-157` maps both to
`"static_analysis"`; `GhidraBridge` (class starts `ghidra.py:5607`) inherits
`supports_static_analysis=True` from its constructor default at
`bridges/base.py:268`, so `ToolRegistry.execute_tool_call`'s capability check
(`core/tools.py:679-696`) passes for both and dispatch proceeds normally.

### New GUI sub-modules — real integration, not orphaned files

`ghidra_panel.py:50-52` imports `DataTypeManagerWidget`,
`GhidraAnalysisExtrasWidget`, `ProgramTreeWidget`. Each is instantiated inside
its own tab-builder method (`_create_data_types_tab` line 1071,
`_create_program_tree_tab` line 1091, `_create_analysis_extras_tab` line
1111), added via `layout.addWidget(...)`, and all three tabs are registered
with `tabs.addTab(...)` at `ghidra_panel.py:302-304` ("Data Types", "Program
Tree", "Analysis Extras"). The panel's own `set_bridge` (`ghidra_panel.py:
1323-1334`) propagates the bridge to all three sub-widgets on
(re)connection, so a widget built before a bridge exists still gets wired
correctly — this matches the existing pattern the rest of the panel uses.

**`ghidra_panel_data_types.py`** (`DataTypeManagerWidget`, 243 lines): real
"Create Type" sub-form for `create_data_type`, covering all four kinds
(enum/union/typedef/function_def) with kind-appropriate field prompts (enum
member value, union member type, typedef base type) and a real
`run_bridge_coroutine_logged(self._bridge.create_data_type(category, name,
kind, fields or None), ...)` call (`ghidra_panel_data_types.py:196-207`).
Closes slice 6 gap-list item 1 (rows #3-6).

**`ghidra_panel_program_tree.py`** (`ProgramTreeWidget`, 298 lines): real
`QTreeWidget` browser wired to `get_program_tree()`
(`ghidra_panel_program_tree.py:148-155`) with recursive module/fragment
rendering (`_populate_node`, including fragment address-range formatting),
plus a real edit form wired to `edit_program_tree(tree_name, operation,
parent_module, child_name)` (`ghidra_panel_program_tree.py:254-266`) that
refreshes the tree on success. Closes slice 6 gap-list item 2 (row #11) and
item 7 (row #12, the write-side MISSING method) at L3.

**`ghidra_panel_extras.py`** (`GhidraAnalysisExtrasWidget`, 742 lines): five
real sections, each backed by a genuine `run_bridge_coroutine_logged` call
against the real bridge method — instruction flow (`get_instruction_flow`)
and register value (`get_register_value`) at
`ghidra_panel_extras.py:174-182,220-229`; thunk management
(`get_thunk_info`/`add_thunk`/`remove_thunk`) at lines 310-383, with
mutations correctly re-querying `get_thunk_info` afterward
(`_on_thunk_mutated`, line 385); external references
(`get_external_references`/`add_external_reference`/
`remove_external_reference`) at lines 464-539, with add/remove correctly
re-triggering a refresh; properties (`get_properties`) at lines 594-602; and
the bidirectional call graph (`get_call_graph`, explicitly distinct from
`get_call_tree`) at lines 673-681, rendering both `callees` and `callers`
subtrees from one payload. Closes slice 5 gap-list items 2/3/4 and slice 6
gap-list item 5.

### Remaining slice-5 items wired directly in `ghidra_panel.py` (not via sub-modules)

- **XRefs tab add/delete reference** (slice 5 gap-list item 3, rows 23/24):
  real form with `_ref_from_input`/`_ref_to_input`/`_ref_type_combo`, wired
  `_on_add_reference`/`_on_delete_reference` (`ghidra_panel.py:2603-2653`)
  calling `bridge.add_reference(from_addr, to_addr, ref_type)` /
  `bridge.delete_reference(from_addr, to_addr)`, both refreshing xrefs via
  `self.show_xrefs(addr)` on success.
- **Bookmark removal** (slice 6 gap-list item 3, row #26): `_remove_bm_btn`
  (line 434) plus a context-menu action on `_bookmarks_table`
  (`customContextMenuRequested` wired at line 426) both route to
  `_on_remove_bookmark` (`ghidra_panel.py:2830-2844`) →
  `bridge.remove_bookmark(addr, category, bookmark_type)`.
- **Memory block remove/split/join** (slice 6 gap-list item 6, row #15):
  `_remove_block_btn`/`_split_block_btn`/`_join_blocks_btn` (lines 615-638)
  wired to `_on_remove_memory_block`/`_on_split_memory_block`/
  `_on_join_memory_blocks` (`ghidra_panel.py:3130-3190`), each calling the
  corresponding new bridge method with parsed inputs.
- **`add_label` primary flag** (slice 5 gap-list item 5, row #32): the
  existing Set Label form gained a `_label_primary_check` checkbox;
  `_on_set_label` (`ghidra_panel.py:2659-2704`) routes through
  `bridge.add_label(addr, name, primary=True)` when checked, otherwise the
  pre-existing `bridge.set_label(addr, name)` path — genuinely reaches the
  previously-orphaned `add_label` method rather than just renaming a call
  site.
- **`get_function` singular / "Go to address"** (slice 5 gap-list item 5,
  row #13): new `_goto_func_addr`/`_goto_func_btn` in the functions sidebar,
  `_on_goto_function` (`ghidra_panel.py:1860-1878`) calls
  `bridge.get_function(address)` and loads the resolved function's code
  views on a hit, reports "not found" on `None`.

### Genuine residual gap found: `remove_label` (slice 5, row 33) — still NO-CONTROL

`remove_label` has a complete, real L1 implementation
(`ghidra.py:7441-7480+`, transaction-wrapped) and a registered L2 tool-def
(`ghidra.py:1286`, confirmed via `grep -n 'name="ghidra.remove_label"'`), but
**no GUI control reaches it anywhere in the repository** — a repo-wide grep
for `remove_label` outside the bridge file returns zero hits under
`src/intellicrack/ui/`, and the only other reference is an unrelated entry in
`core/orchestrator.py:301` (an AI-tool-name allowlist, not a GUI wiring
site). The Labels table (`_labels_table`, `ghidra_panel.py:389-390`) has no
`customContextMenuRequested` connection and no delete button — contrast with
the Bookmarks table (`ghidra_panel.py:426`) and the Functions tree
(`ghidra_panel.py:1281`), both of which do have a context-menu wired for
their respective delete operations, showing the codebase has this exact
pattern available but never applied it to Labels. This item was explicitly
in scope (slice 5 report row 33, "**NO-CONTROL** — no GUI caller found") and
was not remediated. No test exists for it either (confirmed: zero hits for
`remove_label` under `tests/test_bridge_completeness/ghidra/`).

This is the **only** row across both slices (47 + 40 native-feature rows)
that I found still short of OK/OK/OK. Every other previously-flagged
NO-CONTROL/MISSING/STUB row — `get_instruction_flow`, `get_register_value`,
`get_function` (singular), `get_thunk_info`/`add_thunk`/`remove_thunk`,
`add_reference`/`delete_reference`, `add_external_reference`/
`remove_external_reference`/`get_external_references`, `get_call_graph`,
`add_label`, `create_data_type` (all 4 kinds), `get_program_tree` +
`edit_program_tree` (read+write), `remove_bookmark`, `get_properties`,
`remove_memory_block`/`split_memory_block`/`join_memory_blocks`, and the
`add_comment` REPEATABLE correctness bug — is now genuinely OK/OK/OK, each
independently confirmed against live source with file:line evidence above.

## PART B — Test-gate review

Reviewed `tests/test_bridge_completeness/ghidra/conftest.py`,
`test_ghidra_l1_l2.py` (1234 lines), and `test_ghidra_l3_panel.py` (1360
lines).

### `conftest.py` — legitimate external-boundary double

`FakeGhidraBridge` stands in only for the external `ghidra_bridge` RPC
transport (`remote_exec`/`remote_eval`), which cannot run headless Ghidra in
the sandbox. Every `GhidraBridge` production method body under test —
including the `comment_map` lookup, the transaction wrapping, the
readback/guard logic — executes for real against this fake wire. This
satisfies the mandate's "test doubles allowed only at a genuine external
boundary" carve-out.

### `test_ghidra_l1_l2.py` — real, falsifiable gates

Every test asserts exact values (specific hex addresses, exact returned
dicts, exact Jython-fragment substrings like `"CodeUnit.REPEATABLE_COMMENT"`,
`"removeBlock"`, `"memory.split"`, `"createModule"` vs `"createFragment"`)
rather than existence-only checks. Error paths are covered for every new
method (not-found block, out-of-range split address, missing join operand,
unknown comment type, unknown tree operation, missing parent module,
non-thunk removal, zero-match bookmark removal, zero-match external
reference removal). Each remediated method also gets a
`ToolRegistry.execute_tool_call`-driven L2 dispatch test that verifies the
tool-def name and parameter names actually bind to the real method (would
TypeError or ToolError on any drift). The REPEATABLE-comment regression
suite (`TestAddCommentRepeatableRegression`, lines 101-184) is exactly what
the plan asked for: it proves REPEATABLE emits `REPEATABLE_COMMENT` (not
EOL), that an unknown type raises before any RPC call, that EOL still works
(no regression), and that the fix is reachable through the real
`ToolRegistry`. I did not find a single vacuous assertion, tautology, or
swallowed failure path in this file. **Verdict: genuine falsifiable gates
throughout.**

One non-blocking quality defect: **8 basedpyright errors** in this file
(`reportUnknownMemberType`/`reportAttributeAccessIssue` at lines 996-998 and
1034) because `run_async(...)` returns `object` and the test accesses
`.name`/`.address`/`.calling_convention` on it directly without narrowing.
Fix: `cast("FunctionInfo", run_async(...))`, matching the `cast("dict[str,
Any]", ...)` pattern already used everywhere else in this same file (e.g.
line 208, 242, 280). This does not affect falsifiability — the test still
correctly gates the production behavior — but it violates the plan's "ZERO
basedpyright findings" production standard, which explicitly applies to
tests.

### `test_ghidra_l3_panel.py` — real, falsifiable gates, but a systemic basedpyright violation

Functionally, this file is equally strong: `_RecordingBridge` and per-test
`_StubBridge` classes are genuine `async def` coroutines (never
`MagicMock`), `_install_sync_dispatch` patches only the dispatcher wrapper
(`run_bridge_coroutine_logged`) to run synchronously — the real widget
`clicked` signal, the real handler method, and the real bridge coroutine all
execute unmodified. Assertions check exact call-argument tuples (e.g.
`bridge.add_reference_calls == [(0x401000, 0x402000, "CALL")]`), exact
rendered text/table contents, and short-circuit-on-invalid-input behavior
for essentially every new control. The
`test_build_bidirectional_call_graph_calls_get_call_graph` test
(lines 1294-1330) is a good example of intentional falsifiability: the stub
only implements `get_call_graph`, not `get_call_tree`, so a regression that
rewired the button to the old duplicate method would leave `calls` empty
and fail loudly, not silently pass. I found no mocks-of-the-thing-under-test,
no tautologies, and no cannot-fail patterns.

However: **89 basedpyright errors**, all `reportPrivateUsage` (85 of them)
plus 3 `reportOptionalMemberAccess` and false-clean elsewhere. Every single
widget attribute this file reaches into — `_ref_from_input`, `_add_ref_btn`,
`_label_primary_check`, `_bookmarks_table`, `_block_remove_name_input`,
`_kind_combo`, `_tree`, `_bicg_tree`, dozens more across `GhidraPanel`,
`DataTypeManagerWidget`, `ProgramTreeWidget`, and
`GhidraAnalysisExtrasWidget` — is name-mangled private (leading underscore)
and is accessed from outside the class that declares it. basedpyright
flags every one of these under `reportPrivateUsage`. The 3
`reportOptionalMemberAccess` findings (lines 1008, 1292, 1330) are a
secondary, genuine issue: `QTreeWidgetItem.text(0)`/`QTableWidgetItem.text()`
return `str | None`-compatible optionals in the stubs and the test calls
`.text(0)` without a None guard.

This is a real, non-trivial violation of the plan's explicit mandate:
*"Full type hints; ZERO basedpyright findings. Never use any type/lint
suppression comment... fix the real error."* The plan does not carve out an
exception for reaching into a panel's private widgets from test code, and
the fix is not a suppression — it requires either (a) exposing the specific
widgets these tests need through a minimal public/`__test__`-style accessor
on each widget class (matching whatever convention the codebase already
uses elsewhere for test-observability, if one exists), or (b) restructuring
the assertions to observe outcomes through already-public surfaces
(rendered `QPlainTextEdit`/table contents, which several tests already do)
instead of reading private input-field state directly. Given the volume
(85 occurrences across every single test class in the file), this is a
systemic authoring pattern, not a handful of stray accesses, and needs a
real rewrite pass, not a one-line patch.

**Verdict on test_ghidra_l3_panel.py: functionally a real, falsifiable gate
suite (would fail if the wiring were reverted) — I am not recommending any
test be deleted or weakened — but it does NOT meet the plan's explicit
zero-basedpyright-findings bar and must be revised to either expose a
sanctioned test-access path to these widgets or reroute the assertions
through public state.**

## Summary (JSON-ish)

```
{
  "tool": "ghidra",
  "rows_checked": 87,
  "still_broken": [
    {
      "feature": "remove_label (slice 5, row 33)",
      "layer": "L3",
      "why": "L1 (ghidra.py:7441-7480) and L2 (tool-def ghidra.py:1286) are real and registered, but no GUI control anywhere invokes it -- Labels table has no context menu or delete button, unlike the Bookmarks table and Functions tree which both have this exact pattern wired. No test exists for it either."
    }
  ],
  "non_gate_tests": [],
  "quality_defects": [
    {
      "file": "tests/test_bridge_completeness/ghidra/test_ghidra_l1_l2.py",
      "issue": "8 basedpyright reportUnknownMemberType/reportAttributeAccessIssue errors at lines 996-998, 1034 (accessing .name/.address/.calling_convention on the object-typed return of run_async without a cast)",
      "fix": "cast(\"FunctionInfo\", run_async(...)) matching the cast(\"dict[str, Any]\", ...) pattern already used elsewhere in the same file",
      "gates_valid": true
    },
    {
      "file": "tests/test_bridge_completeness/ghidra/test_ghidra_l3_panel.py",
      "issue": "89 basedpyright errors: 85 reportPrivateUsage (reaching into underscore-prefixed widget attributes across class boundaries throughout every test class) + 3 reportOptionalMemberAccess (unguarded .text(0)/.text() on Optional-typed Qt item results, lines 1008/1292/1330)",
      "fix": "Systemic -- needs either a sanctioned test-access accessor added to each widget class or assertions rerouted through already-public rendered state (several tests already do this for output, none do for input); not a one-line fix given 85 occurrences across the whole file",
      "gates_valid": true
    }
  ],
  "report_path": "D:/Intellicrack/audit/bridge-completeness/remediation/verify-ghidra.md",
  "summary": "L1/L2 fully remediated for slices 5 and 6: the add_comment REPEATABLE correctness bug is genuinely fixed (raises on unknown type, no silent EOL downgrade), all 4 previously-MISSING program-model methods (remove_memory_block/split_memory_block/join_memory_blocks/edit_program_tree) are real and transaction-wrapped, and ghidra.get_memory_map/write_bytes dispatch correctly under the static_analysis capability gate. L3: three new, properly-integrated GUI sub-modules (Data Type Manager create-type form, Program Tree browser+editor, Analysis Extras tab) plus direct ghidra_panel.py wiring close every previously-flagged gap except one -- remove_label remains genuinely NO-CONTROL with zero test coverage. Test suite (2594 lines across two files) is functionally excellent -- every test is a real falsifiable gate with exact-value assertions, comprehensive error-path coverage, and a properly-scoped single external-boundary double -- but fails the plan's explicit zero-basedpyright-findings standard: 97 total errors (8 in the L1/L2 file, 89 in the L3 panel file, the latter being a systemic reportPrivateUsage pattern across nearly every test). Source files (bridge + all panel modules) are 100% clean on ruff, basedpyright, pydoclint, and pydocstyle. Recommend: (1) wire remove_label into the Labels table via a context-menu action following the Bookmarks/Functions precedent, with a matching L3 test; (2) fix the 8 L1/L2 basedpyright errors with a FunctionInfo cast; (3) resolve the 89 L3 basedpyright errors via a real widget-access mechanism, not suppression -- before this tool's track is considered done."
}
```
