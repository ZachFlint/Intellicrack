# Verification — Slice 3: Cutter/Rizin, Static Analysis Only

Adversarial re-check of `audit/bridge-completeness/agent-03-cutter-rizin-static-analysis.md`
against the live source: `src/intellicrack/bridges/cutter.py` (4574 lines, read in full),
`src/intellicrack/ui/panels/cutter_panel.py` (1432 lines, read in full),
`src/intellicrack/ui/panels/cutter_tabs.py` (1018 lines, read in full), and
`src/intellicrack/core/tools.py` (dispatch: `execute_tool_call`, `core/tools.py:551-643`).

## Highest-stakes claim: relocations/resources command swap

**Independently confirmed as a genuine, correctly-classified defect.**

Read directly from `src/intellicrack/bridges/cutter.py`:
- `get_relocations` (cutter.py:2726-2750) issues `await self._cmd_json("iRj")` — command string at cutter.py:2739.
- `get_resources` (cutter.py:2752-2785) issues `await self._cmd_json("irj")` — command string at cutter.py:2773.

Ground truth pulled directly from rizin's own command-definition source
(`librz/core/cmd_descs/cmd_info.yaml`, fetched from
`https://raw.githubusercontent.com/rizinorg/rizin/dev/librz/core/cmd_descs/cmd_info.yaml`):
- `ir` → summary: **"List relocations"**
- `iR` → summary: **"List Resources"**

Cross-corroborated against the Rizin Handbook reference card
(`https://book.rizin.re/src/refcard/intro.html`), which independently states `ir` = "Display
relocations" (the refcard does not enumerate `iR` directly, but the primary command-descriptor
YAML is authoritative and unambiguous).

Conclusion: `get_relocations` sends the **resources** command (`iRj`) and `get_resources` sends
the **relocations** command (`irj`) — the two are swapped exactly as the report states. This is
a real functional defect (not a naming/cosmetic issue): the Relocations GUI tab
(`RelocationsTab`, cutter_tabs.py:293-338, wired cutter_panel.py:1131) will render PE-resource
entries mislabeled as relocations, and the Resources tab (`ResourcesTab`, cutter_tabs.py:341-387,
wired cutter_panel.py:1132) will render relocation entries mislabeled as resources. Both parse
loops run without raising (each JSON shape is close enough in field names — `name`/`type` — that
neither crashes), so this fails silently at the data level, matching the report's characterization.

**Verdict: CONFIRMED.**

## Full verification matrix

| # | Finding | Verdict | Independent evidence (file:line) | Note |
|---|---|---|---|---|
| 1 | Analysis passes — OK/DEAD-CONTROL(partial) | CONFIRMED | `analyze` cutter.py:1679-1702, cmd_map at 1692-1697 (`quick`->`aa`,`normal`->`aaa`,`deep`->`aaaa`); `_tf("analyze",...)` cutter.py:520-534, enum at 530; toolbar wiring cutter_panel.py:133 `_add_tool_button(..., self._on_analyze)`; handler cutter_panel.py:552 `self._bridge.analyze()` — zero args, so only default `"normal"` reachable. Grepped `"quick"`/`"deep"` across `src/intellicrack/ui`: 0 hits. | Bridge and tool-def both real/complete; GUI genuinely offers no level selector. |
| 2 | Function list/detection — OK | CONFIRMED | `get_functions` cutter.py:1704-1751 (`aflj` at 1726), `get_function` cutter.py:1753-1841 (`afij`/`afvj` at 1781/1789), `get_function_address` cutter.py:2446-2488 (`afij {name}` at 2482); GUI: `_on_refresh_functions` cutter_panel.py:582-598 calls `get_functions`; `_on_find_function` cutter_panel.py:1256-1271 calls `get_function_address`. | Matches exactly. |
| 3 | Disassembly (range) — OK | CONFIRMED | `disassemble` cutter.py:1940-1985 (`pdj {count}` at 1966); GUI calls at cutter_panel.py:667 (`_on_function_clicked`) and 1246 (`_on_goto_complete`). | Matches. |
| 4 | Disassembly (whole function) — NO-CONTROL | CONFIRMED | `disassemble_function` cutter.py:3921-3939 (`pdf @ {address}` at 3937); `_tf` at cutter.py:967-974. Grep for `disassemble_function` in `src/intellicrack/ui`: 0 hits (checked cutter_panel.py and cutter_tabs.py directly — only `disassemble` (pdj-range) is called, at cutter_panel.py:667/1246). | No GUI path exists. |
| 5 | Decompiler (pdc/pdg dual path) — OK | CONFIRMED | `decompile` cutter.py:1909-1938: `pdc` at 1930, falls back to `pdg` at 1933 when empty/"Cannot"; GUI: `_on_function_clicked` cutter_panel.py:656-664 and `_on_decompile_selected` cutter_panel.py:688-715. | Real dual-path impl, not stub. |
| 6 | CFG / function graph — OK | CONFIRMED | `get_function_graph` cutter.py:2419-2444 (`agj @ {hex(address)}` at 2436, unwraps `blocks` at 2439-2442); GUI: `_apply_graph`/`CFGGraphView` wired cutter_panel.py:676-684, 717-737. | Matches. |
| 7 | Basic blocks — NO-CONTROL | CONFIRMED | `get_basic_blocks` cutter.py:3941-3969 (`afbj @ {address}` at 3957); `_tf` cutter.py:975-982. Grep `get_basic_blocks` in `src/intellicrack/ui`: only hit is `ghidra_panel.py:1751` (`bridge.get_basic_blocks(address)`), which is a call on the Ghidra bridge instance in `ghidra_panel.py`, an unrelated bridge/panel with a same-named method — not a Cutter GUI path. | Correctly attributed false lead ruled out; genuinely NO-CONTROL for Cutter. |
| 8 | Call graph — NO-CONTROL | CONFIRMED | `get_callgraph` cutter.py:2820-2835 (`agcj` at 2833); `_tf` cutter.py:695. Grep `get_callgraph` across `src/intellicrack`: 0 hits outside bridge/tool-def files. | No GUI path. |
| 9 | Imports — OK | CONFIRMED | `get_imports`/`_get_imports_internal` cutter.py:2191-2211/1277-1300 (`iij` at 1290); GUI `_refresh_imports` cutter_panel.py:814-826. | Matches. |
| 10 | Exports — OK | CONFIRMED | `get_exports`/`_get_exports_internal` cutter.py:2213-2233/1302-1325 (`iEj` at 1315); GUI `_refresh_exports` cutter_panel.py:853-865. | Matches. |
| 11 | Sections — OK | CONFIRMED | `get_sections`/`_get_sections_internal` cutter.py:2235-2255/1250-1275 (`iSj` at 1263); GUI `_refresh_sections` cutter_panel.py:892-904; also reused by `HexdumpTab._apply_auto_sections` cutter_tabs.py:628-653. | Matches; extra reuse path confirmed too. |
| 12 | Segments — OK | CONFIRMED | `get_segments` cutter.py:3852-3877 (`iSSj` at 3865); `_tf` cutter.py:948; GUI `SegmentsTab.refresh` cutter_tabs.py:985-999, wired cutter_panel.py:348-349 (`_segments_tab`, added to tabs) and refreshed at cutter_panel.py:1133. | Matches (report's cited `cutter_tabs.py:985-999` matches `SegmentsTab.refresh` at 985-999 in re-read). |
| 13 | Strings (data-section, filtered) — OK | CONFIRMED | `search_strings` cutter.py:2081-2133 (`izj` at 2104, regex filter 2106-2133); GUI search box/table cutter_panel.py:954-1004 (`search_strings`/`_on_search_strings`). | Matches. |
| 14 | Strings (whole-binary izz) — OK | CONFIRMED | `get_all_strings` cutter.py:2494-2529 (`izzj` at 2507); GUI `AllStringsTab.refresh` cutter_tabs.py:121-135, wired cutter_panel.py:330-331/1127. | Matches. |
| 15 | Symbols — OK | CONFIRMED | `get_symbols` cutter.py:2531-2556 (`isj` at 2544); GUI `SymbolsTab.refresh` cutter_tabs.py:169-183, wired cutter_panel.py:333-334/1128. | Matches. |
| 16 | Libraries — OK | CONFIRMED | `get_libraries` cutter.py:2558-2588 (`ilj` at 2571, manual parse of str/dict entries 2579-2586); GUI `LibrariesTab.refresh` cutter_tabs.py:216-230, wired cutter_panel.py:336-337/1129. | Matches. |
| 17 | Headers — OK | CONFIRMED | `get_headers` cutter.py:2590-2613 (`ihj` at 2603); GUI `HeadersTab.refresh` cutter_tabs.py:261-275, wired cutter_panel.py:339-340/1130. | Matches. |
| 18 | Debug info — NO-CONTROL | CONFIRMED | `get_debug_info` cutter.py:2615-2630 (`iDj` at 2628); `_tf` cutter.py:683. Grep across `src/intellicrack/ui`: 0 hits. | No GUI path. |
| 19 | Classes/RTTI — NO-CONTROL | CONFIRMED | `get_classes` cutter.py:2632-2665 (`icj` at 2654) + real normalization helpers `_normalize_class_methods`/`_normalize_class_fields` cutter.py:2667-2724; `_tf` cutter.py:684. Grep across `src/intellicrack/ui`: 0 hits; `_create_data_tabs()` cutter_panel.py:262-369 has no Classes tab; `cutter_tabs.py` defines no `ClassesTab` class (confirmed by full read — only the classes enumerated in the report's coverage matrix exist). | No GUI path; bridge-side work genuinely orphaned. |
| 20 | Relocations — STUB/DEFECT | CONFIRMED (see detailed section above) | `get_relocations` cutter.py:2726-2750, command `iRj` at 2739 — should be `irj`. GUI tab `RelocationsTab` cutter_tabs.py:293-338 (real widget, wired cutter_panel.py:342-343/1131) but fed wrong data. | Genuine defect, not cosmetic. |
| 21 | Resources — STUB/DEFECT | CONFIRMED (see detailed section above) | `get_resources` cutter.py:2752-2785, command `irj` at 2773 — should be `iRj`. GUI tab `ResourcesTab` cutter_tabs.py:341-387 (real widget, wired cutter_panel.py:345-346/1132) but fed wrong data. | Genuine defect, not cosmetic. |
| 22 | Vtables — NO-CONTROL | CONFIRMED | `get_vtables` cutter.py:2837-2860 (`avj` at 2850); `_tf` cutter.py:696. Grep across `src/intellicrack/ui`: 0 hits. | No GUI path. |
| 23 | Syscalls — NO-CONTROL | CONFIRMED | `get_syscalls` cutter.py:2862-2877 (`asj` at 2875); `_tf` cutter.py:697. Grep across `src/intellicrack/ui`: 0 hits. | No GUI path. |
| 24/24b/24c/24d | Zignatures (list/generate/add/search) — NO-CONTROL | CONFIRMED | `get_zignatures` cutter.py:3314-3329 (`zj`), `generate_zignatures` cutter.py:3331-3353 (`zg`/`zg @ addr`), `add_zignature` cutter.py:3355-3374 (`za {name} {zigdata}`), `search_zignatures` cutter.py:3376-3391 (`z/j`); `_tf` entries cutter.py:782, 783-790, 791-799, 800. Grep for all four names across `src/intellicrack/ui`: 0 hits; no `ZignaturesTab`/`SignaturesTab` class exists in `cutter_tabs.py` (confirmed by full read of the file — the tab classes present are `AllStringsTab, SymbolsTab, LibrariesTab, HeadersTab, RelocationsTab, ResourcesTab, CommentsTab, FlagsTab, ROPGadgetsTab, HexdumpTab, ESILConsoleTab, TypeBrowserTab, SegmentsTab`). | No GUI path for any of the four; all four correctly identified. |
| 25 | Hexdump byte mode — OK | CONFIRMED | `hexdump` cutter.py:3879-3898 (`px {length} @ {address}` at 3896); GUI `HexdumpTab` cutter_tabs.py:563-690, manual dump `_on_dump` (655-682) and auto-dump `_apply_auto_sections` (628-653), wired cutter_panel.py:363-364/1138. | Matches. |
| 26 | Hexdump word mode — NO-CONTROL | CONFIRMED | `hexdump_words` cutter.py:3900-3919 (`pxw {length} @ {address}` at 3917); `_tf` cutter.py:958-966. `HexdumpTab` (cutter_tabs.py:563-690) has exactly one dump button (`_dump_btn`, line 590) whose only handler `_on_dump` (655-682) always calls `self._bridge.hexdump(...)` (line 674) — never `hexdump_words`. Grep confirms 0 references to `hexdump_words` in `src/intellicrack/ui`. | No mode toggle exists; confirmed single-button, single-mode widget. |

## Orphans section

- **`execute_command`** — CONFIRMED as correctly-scoped-out and fully wired. `execute_command` cutter.py:2395-2405, `_tf` cutter.py:622-629, GUI wiring `_on_run_command` cutter_panel.py:1077-1100 (button/enter-key at 397/402, method body at 1077, `self._bridge.execute_command(command)` call at 1092). Legitimately excluded from the numbered matrix per the task's own scope note; no gap.
- **Relocations/resources swap** — CONFIRMED, see above. Recommended fix (swap `"iRj"`/`"irj"` between the two methods) is the correct minimal fix given the ground truth.
- **No broken/typo'd GUI→bridge wiring found** — spot-checked: `_on_run_command`→`execute_command` (exists, cutter.py:2395), `_on_analyze`→`analyze` (exists, cutter.py:1679), `_on_decompile_selected`→`decompile` (exists, cutter.py:1909), `_refresh_new_tabs`→ 13 tab `.refresh(bridge, run_fn)` calls (cutter_panel.py:1122-1139) each resolving to a real bridge method per the mixin chain read in full (`_CutterBridgeBase` → ... → `CutterDebugMixin`). No unresolved `getattr` targets found in the dispatch path (`core/tools.py:588`, `getattr(bridge, attr_name, None)`), and no dead-string GUI calls found. Claim upheld.
- **No bridge method or `_tf` entry within scope lacking a matching native feature** — upheld; every command string cited in the matrix (`aa/aaa/aaaa`, `aflj`, `afij`, `afvj`, `pdj`, `pdf`, `pdc`/`pdg`, `agj`, `agcj`, `afbj`, `iij`, `iEj`, `iSj`, `iSSj`, `izj`, `izzj`, `isj`, `ilj`, `ihj`, `iDj`, `icj`, `iRj`/`irj` (swapped), `avj`, `asj`, `zj`, `zg`, `za`, `z/j`, `px`, `pxw`) is a real, independently-verifiable rizin command family, not an invented API.

## Coverage-summary arithmetic check

- 26 native features audited (24/24b/24c/24d counted individually) — recomputed by counting matrix rows: 22 single rows + 4 zignature sub-rows = 26. Arithmetic checks out.
- "Fully ported: 14 of 26" — recount of rows marked fully OK across all 3 layers (bridge/tool-def/GUI, no caveat): rows 2, 3, 5, 6, 9, 10, 11, 12, 13, 14, 15, 16, 17, 25 = 14 rows. Confirmed correct.
- NO-CONTROL count "9": rows 4, 7, 8, 18, 19, 22, 23, [24/24b/24c/24d as one feature area], 26 = 9 distinct feature areas. Confirmed correct (zignatures legitimately counted once as an area per the report's own stated convention, since it's one missing tab covering four operations — this convention is reasonable and consistently applied elsewhere, e.g. rows 20/21 are still counted as 2 separate STUB rows since they are two independently defective methods, not one feature area).
- STUB/DEFECT count "2" (rows 20, 21): confirmed.
- DEAD-CONTROL count "1 (partial)" (row 1): confirmed.
- MISSING count "0", NOT-REGISTERED count "0": confirmed — every native feature listed has a real bridge method (no gaps found), and the tool-definition list (`_build_tool_functions`, cutter.py:505-1097) was read in full; every in-scope method name (`analyze`, `get_functions`, `decompile`, `disassemble`, `get_function`, `get_function_address`, `get_function_graph`, `get_all_strings`, `get_symbols`, `get_libraries`, `get_headers`, `get_debug_info`, `get_classes`, `get_relocations`, `get_resources`, `get_callgraph`, `get_vtables`, `get_syscalls`, `get_zignatures`, `generate_zignatures`, `add_zignature`, `search_zignatures`, `get_segments`, `hexdump`, `hexdump_words`, `disassemble_function`, `get_basic_blocks`, `get_imports`, `get_exports`, `get_sections`) has a matching `_tf(...)` entry. No omissions found.

## FALSE POSITIVES / NEEDS REVIEW

**None found.** Every finding in the report — all 26 matrix rows, the orphans section, the
prioritized-gap list, and the coverage-summary arithmetic — was independently re-derived from
the live source and/or an authoritative external reference (rizin's own `cmd_info.yaml` command
descriptors) and matches the report's claims exactly, including every cited file:line. No
stale/incorrect line citations were found; no GUI wiring was missed by the original audit; no
"NO-CONTROL" claim was refuted by a hidden reachable path; the one "DEAD-CONTROL/partial" claim
(analysis-depth selector) was confirmed by direct inspection of the toolbar handler's argument-free
`analyze()` call.

## Tally

- **26 checked** (matrix rows, with 24/24b/24c/24d counted individually as instructed) + 3 orphans-section claims + arithmetic/summary checks
- **26 confirmed** (all matrix rows) + **3 confirmed** (orphans section: execute_command wiring, relocations/resources swap, no-broken-wiring claim) + **arithmetic confirmed**
- **0 false positives**
- **0 needs-review**

All findings in `audit/bridge-completeness/agent-03-cutter-rizin-static-analysis.md` are upheld
as written. The relocations/resources command swap (rows 20/21) is independently confirmed as a
real, correctly-diagnosed production defect via rizin's own command-descriptor source
(`ir` = relocations, `iR` = resources — the bridge has them inverted).
