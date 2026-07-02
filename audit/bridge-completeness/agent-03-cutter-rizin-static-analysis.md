# Bridge-Completeness Audit — Slice 3: Cutter/Rizin, Static Analysis Only

Scope: analysis passes, disassembly, decompiler, graphs/CFG, imports/exports,
strings, signatures/FLIRT (zignatures), hexdump. Debugging, ESIL emulation,
flags, xrefs, search, seek, project save/load, config, patch/write
operations, comments, rename, and the C-type system are explicitly
out-of-scope for this slice (audited elsewhere) and are excluded from the
coverage matrix below even though they live in the same `cutter.py` file.

Audit method: read every in-scope async method body in
`src/intellicrack/bridges/cutter.py` to confirm it issues a genuine
rizin/r2 command and parses real output; read the full body of
`_build_tool_functions()` (lines 505-1097) to confirm `_tf(` registration;
read `src/intellicrack/ui/panels/cutter_panel.py` (1432 lines) and
`src/intellicrack/ui/panels/cutter_tabs.py` (1018 lines) in full, plus a
repo-wide grep of `src/intellicrack/ui/` for each in-scope method name, to
find GUI wiring. All line numbers below were confirmed by direct `Read` of
the current file state (no prior/stale numbers were trusted without
re-verification).

## Native ground truth (rizin static-analysis command set)

Rizin (the community fork of radare2 that Cutter's GUI is built on) exposes
its static-analysis surface through the `a` (analysis), `p` (print/disasm),
`i` (info), `ag` (graph), `z` (zignature), and `px` (hexdump) command
families. This list reflects the well-documented, stable rizin/radare2
command reference (rizin book "Analysis"/"Information"/"Print" chapters;
the command set has been stable across r2/rizin for many years and is also
corroborated directly by the exact command strings the bridge itself issues,
verified by reading the bridge source below):

1. **Analysis passes** — `aa` (quick: function boundaries from
   symbols/entrypoints/preludes), `aaa` (normal: aa + autoname, xref
   resolution, type propagation, string-xrefs), `aaaa` (deep/experimental:
   aaa + additional slower passes). Three distinct depth levels.
2. **Function list/detection** — `afl`/`aflj` (list analyzed functions),
   `afi`/`afij` (single function info), `afo`/`afoj` (name→address lookup).
3. **Disassembly, single/range** — `pd N` (disassemble N instructions from
   current seek), `pdj N` (JSON form).
4. **Disassembly, whole function** — `pdf` (linear function disassembly).
5. **Decompiler** — `pdc` (rizin's native built-in pseudo-decompiler,
   no plugin needed) and `pdg` (Ghidra-derived decompiler via the
   `r2ghidra`/`rz-ghidra` plugin, when installed).
6. **CFG / function graph** — `agf` (ASCII-art graph), `agj` (JSON graph
   data used for GUI rendering).
7. **Call graph** — `agc`/`agcj` (global or per-function call graph).
8. **Basic blocks** — `afb`/`afbj` (basic-block list for a function,
   distinct from full CFG rendering — used for coverage/complexity
   tooling).
9. **Imports** — `ii`/`iij` (imported symbol table).
10. **Exports** — `iE`/`iEj` (exported symbol table).
11. **Sections** — `iS`/`iSj` (PE/ELF/Mach-O section table).
12. **Segments** — `iSS`/`iSSj` (segment table — ELF program headers /
    coarser PE view), distinct from sections.
13. **Strings, data-section only** — `iz`/`izj`.
14. **Strings, whole-binary scan** — `izz`/`izzj` (scans beyond declared
    data sections — catches strings the section table misses).
15. **Symbols** — `is`/`isj` (full symbol table: exports, locals, etc).
16. **Libraries** — `il`/`ilj` (linked/imported library names).
17. **Headers** — `ih`/`ihj` (format-specific header field dump, e.g. PE
    optional header fields) and `iH`/`iHj` (a per-field alternate view);
    `ihj` is the canonical JSON form used by tooling.
18. **Debug info presence** — `iD`/`iDj` (DWARF/PDB/debug-format detection
    metadata).
19. **Classes / RTTI (C++ OOP analysis)** — `ic`/`icj` (class, method, and
    field enumeration from RTTI/vtable heuristics).
20. **Relocations** — `ir`/`irj` (relocation table entries).
21. **Resources** — PE resource enumeration; rizin exposes this via the
    binary-info resource JSON (`iRj` in this bridge's usage — PE resource
    directory walk).
22. **Vtables** — `av`/`avj` (virtual-table detection/listing, C++ RTTI
    analysis family alongside `ic`).
23. **Syscalls** — `as`/`asj` (syscall-table / syscall-at-address info).
24. **Zignatures (FLIRT-equivalent)** — `z`/`zj` (list), `zg` (generate
    from analyzed functions, optionally scoped `zg @ addr`), `za <name>
    <bytes>` (add/define one signature manually), `z/`/`z/j` (search
    loaded zignature space against the current binary).
25. **Hexdump, byte mode** — `px N @ addr` (canonical 8-bit hex+ASCII
    dump).
26. **Hexdump, word mode** — `pxw N @ addr` (32-bit word-grouped hex
    dump — distinct visualization used for e.g. spotting pointer/constant
    patterns).

Source corroboration: every command name above matches exactly what
`cutter.py` sends to `self._r2_cmd`/`self._cmd_json` in the method bodies
read for this audit (cited per-row below), which is the strongest possible
confirmation that the bridge targets real native rizin functionality and
not an invented API.

## Coverage matrix

| # | Native feature | Bridge method (file:line) | Tool-def (file:line) | GUI control (file:line) |
|---|---|---|---|---|
| 1 | Analysis passes (aa/aaa/aaaa, 3 depth levels) | OK — `CutterAnalysisMixin.analyze` cutter.py:1679-1702 (cmd_map aa/aaa/aaaa at 1692-1697) | OK — `_tf("analyze", ...)` cutter.py:520-534 (enum `["quick","normal","deep"]`) | **DEAD-CONTROL (partial)** — Analyze toolbar button wired: `_add_tool_button(..., self._on_analyze)` cutter_panel.py:133, handler calls `self._bridge.analyze()` with **no level argument** cutter_panel.py:552, so only the default `"normal"` level is ever reachable; "quick" and "deep" have no UI path anywhere in `cutter_panel.py`/`cutter_tabs.py` (grep confirmed zero references to `"quick"`/`"deep"`/level selection in `src/intellicrack/ui`) |
| 2 | Function list/detection | OK — `get_functions` cutter.py:1704-1751 (`aflj`), `get_function` cutter.py:1753-1841 (`afij`/`afvj`), `get_function_address` cutter.py:2446-2488 (`afij <name>`) | OK — `_tf("get_functions", ...)` cutter.py:535-542, `_tf("get_function", ...)` cutter.py:630-637, `_tf("get_function_address", ...)` cutter.py:663-670 | OK — functions sidebar populated via `_on_refresh_functions` → `self._bridge.get_functions(...)` cutter_panel.py:590-598; `_on_find_function` → `get_function_address` cutter_panel.py:1262-1271 |
| 3 | Disassembly (range from address) | OK — `disassemble` cutter.py:1940-1985 (`pdj {count}`) | OK — `_tf("disassemble", ...)` cutter.py:551-559 | OK — Disassembly tab populated on function click, cutter_panel.py:666-674, and on Goto, cutter_panel.py:1246-1254 |
| 4 | Disassembly (whole function, linear text) | OK — `disassemble_function` cutter.py:3921-3939 (`pdf @ addr`) | OK — `_tf("disassemble_function", ...)` cutter.py:967-974 | **NO-CONTROL** — zero references to `disassemble_function` anywhere in `src/intellicrack/ui` (grep confirmed); the Disassembly tab only ever calls the range-based `disassemble` (`pdj`), never `pdf` |
| 5 | Decompiler (pdc native, pdg plugin fallback) | OK — `decompile` cutter.py:1909-1938: tries `pdc` first, falls back to `pdg` if unavailable/errored (lines 1929-1936) — real dual-path implementation, not a stub | OK — `_tf("decompile", ...)` cutter.py:543-550 | OK — Decompiler tab populated on function click, cutter_panel.py:656-664, and via toolbar "Decompile" button `_on_decompile_selected` cutter_panel.py:688-715 |
| 6 | CFG / function graph (rendering) | OK — `get_function_graph` cutter.py:2419-2444 (`agj @ addr`, unwraps `blocks` array) | OK — `_tf("get_function_graph", ...)` cutter.py:671-678 | OK — CFG tab (`CFGGraphView`) populated on function click cutter_panel.py:676-684, toolbar "Graph" button `_on_graph_selected` cutter_panel.py:717-737 |
| 7 | Basic blocks (list, non-graph) | OK — `get_basic_blocks` cutter.py:3941-3969 (`afbj @ addr`) | OK — `_tf("get_basic_blocks", ...)` cutter.py:975-982 | **NO-CONTROL** — zero references to `get_basic_blocks` anywhere in `src/intellicrack/ui` (grep confirmed; the one hit in the tree is `ghidra_panel.py:1751`, a different bridge's own method of the same name) |
| 8 | Call graph | OK — `get_callgraph` cutter.py:2820-2835 (`agcj`) | OK — `_tf("get_callgraph", ...)` cutter.py:695 | **NO-CONTROL** — zero references to `get_callgraph` anywhere in `src/intellicrack/ui` |
| 9 | Imports | OK — `get_imports`/`_get_imports_internal` cutter.py:2191-2211 / 1277-1300 (`iij`) | OK — `_tf("get_imports", ...)` cutter.py:592 | OK — Imports tab, `_refresh_imports` cutter_panel.py:814-826 |
| 10 | Exports | OK — `get_exports`/`_get_exports_internal` cutter.py:2213-2233 / 1302-1325 (`iEj`) | OK — `_tf("get_exports", ...)` cutter.py:593 | OK — Exports tab, `_refresh_exports` cutter_panel.py:853-865 |
| 11 | Sections | OK — `get_sections`/`_get_sections_internal` cutter.py:2235-2255 / 1250-1275 (`iSj`) | OK — `_tf("get_sections", ...)` cutter.py:594 | OK — Sections tab, `_refresh_sections` cutter_panel.py:892-904; also reused by HexdumpTab auto-dump cutter_tabs.py:618-626 |
| 12 | Segments | OK — `get_segments` cutter.py:3852-3877 (`iSSj`) | OK — `_tf("get_segments", ...)` cutter.py:948 | OK — Segments tab, `SegmentsTab.refresh` cutter_tabs.py:985-999, wired from `_refresh_new_tabs` cutter_panel.py:1133 |
| 13 | Strings (data-section, filtered search) | OK — `search_strings` cutter.py:2081-2133 (`izj` + regex filter) | OK — `_tf("search_strings", ...)` cutter.py:576-583 | OK — Strings tab + search box, `search_strings`/`_on_search_strings` cutter_panel.py:954-1004 |
| 14 | Strings (whole-binary, `izz`) | OK — `get_all_strings` cutter.py:2494-2529 (`izzj`) | OK — `_tf("get_all_strings", ...)` cutter.py:679 | OK — "All Strings" tab, `AllStringsTab.refresh` cutter_tabs.py:121-135, wired from `_refresh_new_tabs` cutter_panel.py:1127 |
| 15 | Symbols | OK — `get_symbols` cutter.py:2531-2556 (`isj`) | OK — `_tf("get_symbols", ...)` cutter.py:680 | OK — Symbols tab, `SymbolsTab.refresh` cutter_tabs.py:169-183, wired cutter_panel.py:1128 |
| 16 | Libraries | OK — `get_libraries` cutter.py:2558-2588 (`ilj`, manual JSON parse of string/dict entries) | OK — `_tf("get_libraries", ...)` cutter.py:681 | OK — Libraries tab, `LibrariesTab.refresh` cutter_tabs.py:216-230, wired cutter_panel.py:1129 |
| 17 | Headers | OK — `get_headers` cutter.py:2590-2613 (`ihj`) | OK — `_tf("get_headers", ...)` cutter.py:682 | OK — Headers tab, `HeadersTab.refresh` cutter_tabs.py:261-275, wired cutter_panel.py:1130 |
| 18 | Debug info presence | OK — `get_debug_info` cutter.py:2615-2630 (`iDj`) | OK — `_tf("get_debug_info", ...)` cutter.py:683 | **NO-CONTROL** — zero references to `get_debug_info` anywhere in `src/intellicrack/ui` |
| 19 | Classes / RTTI | OK — `get_classes` cutter.py:2632-2665 (`icj`, plus real normalization helpers `_normalize_class_methods`/`_normalize_class_fields` cutter.py:2667-2724 handling rizin's inconsistent key spellings) | OK — `_tf("get_classes", ...)` cutter.py:684 | **NO-CONTROL** — zero references to `get_classes` anywhere in `src/intellicrack/ui`; no Classes tab exists in `_create_data_tabs()` (cutter_panel.py:262-369) or `cutter_tabs.py` |
| 20 | Relocations | **STUB/DEFECT (wrong command)** — `get_relocations` cutter.py:2726-2750 issues `"iRj"`, but in upstream rizin `iR` is the **resources** command, not relocations (`ir` is relocations). This method therefore parses the resource stream as relocations. Parsing logic is real but it is pointed at the wrong native command. See Orphans/Defects note below. | OK — `_tf("get_relocations", ...)` cutter.py:685 | OK (widget exists) — Relocations tab, `RelocationsTab.refresh` cutter_tabs.py:308-322, wired cutter_panel.py:1131 — but displays mislabeled data due to the bridge command swap |
| 21 | Resources | **STUB/DEFECT (wrong command)** — `get_resources` cutter.py:2752-2785 issues `"irj"`, but in upstream rizin `ir` is the **relocations** command, not resources (`iR` is resources). This method therefore parses the relocation stream as resources. Parsing logic is real but pointed at the wrong native command. See Orphans/Defects note below. | OK — `_tf("get_resources", ...)` cutter.py:686 | OK (widget exists) — Resources tab, `ResourcesTab.refresh` cutter_tabs.py:356-370, wired cutter_panel.py:1132 — but displays mislabeled data due to the bridge command swap |
| 22 | Vtables | OK — `get_vtables` cutter.py:2837-2860 (`avj`) | OK — `_tf("get_vtables", ...)` cutter.py:696 | **NO-CONTROL** — zero references to `get_vtables` anywhere in `src/intellicrack/ui` |
| 23 | Syscalls | OK — `get_syscalls` cutter.py:2862-2877 (`asj`) | OK — `_tf("get_syscalls", ...)` cutter.py:697 | **NO-CONTROL** — zero references to `get_syscalls` anywhere in `src/intellicrack/ui` |
| 24 | Zignatures — list | OK — `get_zignatures` cutter.py:3314-3329 (`zj`) | OK — `_tf("get_zignatures", ...)` cutter.py:782 | **NO-CONTROL** |
| 24b | Zignatures — generate | OK — `generate_zignatures` cutter.py:3331-3353 (`zg` / `zg @ addr`) | OK — `_tf("generate_zignatures", ...)` cutter.py:783-790 | **NO-CONTROL** |
| 24c | Zignatures — add | OK — `add_zignature` cutter.py:3355-3374 (`za {name} {zigdata}`) | OK — `_tf("add_zignature", ...)` cutter.py:791-799 | **NO-CONTROL** |
| 24d | Zignatures — search | OK — `search_zignatures` cutter.py:3376-3391 (`z/j`) | OK — `_tf("search_zignatures", ...)` cutter.py:800 | **NO-CONTROL** — no Zignatures/Signatures tab exists anywhere in `cutter_panel.py` or `cutter_tabs.py`; zero grep hits for any of the four zignature method names in `src/intellicrack/ui` |
| 25 | Hexdump, byte mode | OK — `hexdump` cutter.py:3879-3898 (`px {length} @ {address}`) | OK — `_tf("hexdump", ...)` cutter.py:949-957 | OK — Hexdump tab, manual dump + auto-dump-on-refresh, `HexdumpTab._on_dump`/`refresh` cutter_tabs.py:605-682, wired cutter_panel.py:1138 |
| 26 | Hexdump, word mode | OK — `hexdump_words` cutter.py:3900-3919 (`pxw {length} @ {address}`) | OK — `_tf("hexdump_words", ...)` cutter.py:958-966 | **NO-CONTROL** — `HexdumpTab` (cutter_tabs.py:563-690) has only one dump button, always calling `bridge.hexdump(...)` (byte mode); zero references to `hexdump_words` anywhere in `src/intellicrack/ui` |

## Orphans

- **`execute_command`** (cutter.py:2395-2405; `_tf` at cutter.py:622-629; GUI-wired via the raw r2 console, `_on_run_command` cutter_panel.py:1077-1100) — general passthrough utility, not tied to one native feature. Fully wired end-to-end but intentionally excluded from the numbered matrix per the task's own scope note. No gap.
- **PRODUCTION DEFECT — relocations/resources commands are swapped** — `get_relocations` (cutter.py:2739) issues `"iRj"`, and `get_resources` (cutter.py:2773) issues `"irj"`. Verified against the upstream rizin command reference (rizin book refcard: `ir` = "Display relocations", `iR` = PE resources): the bridge has these two commands **inverted**. As written, `get_relocations` fetches and parses the *resource* directory stream, and `get_resources` fetches and parses the *relocation* table stream — each method returns the other feature's data. Both parse loops run without error (so it is not a crash), but the data surfaced in the Relocations tab and the Resources tab is swapped/mislabeled. This is a genuine functional defect, not a cosmetic naming note. Fix: swap the two command strings — `get_relocations` should send `"irj"` and `get_resources` should send `"iRj"`. File to fix: `src/intellicrack/bridges/cutter.py` lines 2739 and 2773. (Recommend confirming at runtime with `ir?`/`iR?` in a rizin session on the target platform before committing, since resource support can be format-specific.)
- No GUI control anywhere in `cutter_panel.py`/`cutter_tabs.py` calls a Cutter-bridge method name that does not exist on `CutterBridge` — every `run_bridge_coroutine_logged(bridge.<name>(...))` and `self._bridge.<name>(...)` call site found by grep for the in-scope method names resolves to a real method confirmed present in the class hierarchy (`_CutterBridgeBase` → `CutterAnalysisMixin` → ... → `CutterDebugMixin`). No broken/typo'd wiring found in-scope.
- No bridge method or `_tf` entry within scope lacks a matching native rizin feature — every in-scope method maps to a real, named rizin command family in the ground-truth list above.

## Coverage summary

- **Native features audited: 26** (rows 1-26, with the 4 zignature sub-capabilities counted individually as 24/24b/24c/24d, consistent with the task's per-sub-capability instruction).
- **Fully ported (all 3 layers OK): 14 of 26** — rows 2, 3, 5, 6, 9, 10, 11, 12, 13, 14, 15, 16, 17, 25. (Rows 20 and 21 were reclassified out of "fully ported" after cross-verification against the upstream rizin command reference revealed the relocations/resources command swap — see Defect below.)
- **Gap counts by type:**
  - MISSING (no bridge method at all): **0**
  - STUB / wrong-command DEFECT (bridge method exists and parses, but is pointed at the wrong native command so it returns another feature's data): **2** — rows 20 (relocations) and 21 (resources), which have their `iRj`/`irj` commands swapped relative to upstream rizin.
  - NOT-REGISTERED (method exists, no `_tf` entry): **0**
  - NO-CONTROL (bridge + tool-def OK, zero GUI wiring): **9** — rows 4, 7, 8, 18, 19, 22, 23, 24/24b/24c/24d (zignatures counted as one NO-CONTROL feature area spanning 4 sub-rows), 26
  - DEAD-CONTROL (widget/action exists but doesn't fully invoke the feature): **1 (partial)** — row 1, analysis-depth selector: the Analyze button *does* invoke `analyze()` and works for the default "normal" level, but "quick" and "deep" — both explicitly declared in the tool-definition's `enum` — have no reachable UI path, so two of the three declared depth levels are GUI-dead.

Note on rows 20/21: their GUI tabs and tool-definitions are fully present and correct — the *only* defect is the swapped rizin command in the two bridge methods, which is a one-line-each fix (see prioritized gap #1 below). Once the commands are un-swapped, rows 20 and 21 become fully ported, raising the fully-ported count to 16 of 26.

Layer-2 (tool-definition) is 100% complete — every in-scope method has a
correct `_tf(` entry, no NOT-REGISTERED gaps. Layer-1 (bridge) is complete
in coverage (every native feature has a real, non-stub implementing method)
with a single functional defect: the relocations/resources pair have their
rizin commands swapped (rows 20/21), so those two methods return each
other's data despite being fully "present". The remaining slice-3 gap is
concentrated in layer-3 (GUI): the panel never grew tabs/controls for
classes, call-graph, vtables, syscalls, zignatures, basic-block listing,
function-linear-disassembly text view, word-mode hexdump, or an
analysis-depth selector.

## Prioritized gap list

1. **Relocations/resources command swap (rows 20/21, functional DEFECT)** —
   highest impact and lowest effort: this is a correctness bug that
   silently shows wrong data in two shipping GUI tabs. `get_relocations`
   (cutter.py:2739) sends `"iRj"` (upstream = resources) and
   `get_resources` (cutter.py:2773) sends `"irj"` (upstream = relocations),
   so the two feature outputs are transposed. Fix: swap the two command
   strings so `get_relocations` sends `"irj"` and `get_resources` sends
   `"iRj"`. Two one-character edits. File to fix:
   `src/intellicrack/bridges/cutter.py` (lines 2739 and 2773). Verify at
   runtime with `ir?`/`iR?` in a rizin session before committing.

2. **Analysis-depth selector (row 1, DEAD-CONTROL/partial)** — high
   impact: `analyze()` already supports `quick`/`normal`/`deep` end-to-end
   in the bridge and is declared in the tool definition's `enum`
   (cutter.py:524-531), but the toolbar only offers one undifferentiated
   "Analyze" button (cutter_panel.py:133, 538-559) with no way to pick a
   level. A power user cannot force a fast `aa` pass on a huge binary or
   request the exhaustive `aaaa` pass — the GUI silently always runs `aaa`.
   Fix: add a level combo box next to the Analyze button in
   `_populate_toolbar` (cutter_panel.py:126-151) and thread the selected
   value into `self._bridge.analyze(level=...)` at cutter_panel.py:552.
   File to fix: `src/intellicrack/ui/panels/cutter_panel.py`.

3. **Classes/RTTI tab (row 19, NO-CONTROL)** — C++ class/vtable analysis
   is a headline reverse-engineering feature (comparable in importance to
   Imports/Exports, which already have tabs) and the bridge-side
   normalization work already done (cutter.py:2667-2724) indicates this
   was built to be surfaced, but never wired to a tab. Fix: add a
   `ClassesTab` to `cutter_tabs.py` (following the exact pattern of
   `RelocationsTab`/`ResourcesTab`) and register it in
   `_create_data_tabs()` and `_refresh_new_tabs()` in `cutter_panel.py`.

4. **Zignatures/FLIRT-equivalent (rows 24/24b/24c/24d, NO-CONTROL)** —
   signature-based function identification is a core power-user static-RE
   workflow (this is rizin's FLIRT equivalent) with all four operations
   (list/generate/add/search) fully implemented and registered in the
   bridge, but completely absent from the GUI — there is no way to
   generate or apply signatures without dropping into the raw r2 console.
   Fix: add a `ZignaturesTab` (list + generate + search actions, similar
   shape to `ROPGadgetsTab`'s search-plus-table pattern) to
   `cutter_tabs.py`, register in `cutter_panel.py`.

5. **Call graph / vtables / syscalls / basic-blocks / linear function
   disassembly / word-mode hexdump / debug-info (rows 7, 8, 18, 22, 23, 26,
   NO-CONTROL)** — lower priority: each is a real, working bridge
   capability with no consumer. Call graph and basic-blocks are partially
   redundant with the existing CFG tab (which already renders `agj`
   blocks) so may be lower priority to add as distinct views; vtables and
   syscalls are niche enough that a single combined "Advanced" tab could
   house all four cheaply. Word-mode hexdump is a one-line addition to
   the existing `HexdumpTab` (a mode toggle next to the existing Dump
   button, cutter_tabs.py:590-593). Files to fix:
   `src/intellicrack/ui/panels/cutter_tabs.py` (new/extended tab classes)
   and `src/intellicrack/ui/panels/cutter_panel.py` (registration in
   `_create_data_tabs()`/`_refresh_new_tabs()`).
