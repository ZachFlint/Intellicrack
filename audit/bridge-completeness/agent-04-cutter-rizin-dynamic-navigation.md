# Bridge Completeness Audit — Slice 4: Cutter/Rizin — Dynamic & Navigation

Scope: debugging, ESIL emulation, flags, xrefs, search, seek/navigation, project/session handling.
Excluded (different slice): analysis passes, disassembly, decompiler, graphs, imports/exports/strings-as-static-listing, signatures-as-static-info, hexdump.

- Bridge: `src/intellicrack/bridges/cutter.py` (4573 lines)
- Panels: `src/intellicrack/ui/panels/cutter_panel.py` (1431 lines), `src/intellicrack/ui/panels/cutter_tabs.py` (1017 lines)
- Dispatch: `src/intellicrack/core/tools.py` — `ToolRegistry.execute_tool_call()` resolves `getattr(bridge, attr_name)` (`src/intellicrack/core/tools.py:551-621`); tool metadata comes from `CutterBridge.tool_definition` (`src/intellicrack/bridges/cutter.py:1336-1347`) built by `_build_tool_functions()` (`src/intellicrack/bridges/cutter.py:505-1097`). Note: the audit brief's assumed `_td(...)` helper does not exist in this codebase — the actual pattern is `_tf(name, description, params, returns)` list entries returned from `_build_tool_functions()`; this is the functional equivalent of "Layer 2" and was mapped as such.

## Native ground truth (rizin command families, source: rizin official docs/handbook)

1. **Debugger session** (`d` commands): attach/detach to process (`dp <pid>`, `dp-`), breakpoints (`db`, `db-`, `dbj`, `dbH` hardware, `dbm` memory, `dbC` condition), stepping (`ds` step-into, `dso` step-over), continue (`dc`), registers (`dr`, `drj`, `dr reg=val`), memory read/write (`p8`, `wx ... @ addr`), memory maps (`dm`, `dmj`), threads/process list (`dp`, `dptj`), loaded modules (`dmI`, `dmIj`).
2. **ESIL emulation** (`ae` family): evaluate expression (`ae`), step (`aes`), step N (`aesp`... / loop of `aes`), emulate whole function (`aef`), init emulation memory/stack (`aeim`), set PC (`aepc`).
3. **Flags** (`f` family): list flags (`fj`), add flag (`f name size @ addr`), resolve nearest flag to address (`fd`/`fdj`), flagspaces (`fs`), rename (`fr`), delete (`f-`).
4. **Cross-references** (`ax` family): xrefs to address (`axt`/`axtj`), xrefs from address (`axf`/`axfj`).
5. **Search** (`/` family): byte pattern (`/x`), wildcard byte pattern (`/x` with `..`), string search (`/j`, `/xj` on encoded bytes), assembly pattern search (`/a`), crypto constant search (`/c`), magic search (`/m`), value search (`/v`), regex string search over parsed string table (`izj` + regex).
6. **Seek/navigation** (`s` family): seek to address (`s <addr>`), resolve symbol/function address by name (`afij <name>`).
7. **Byte/disassembly comparison** (`c`/`cD`/`cC` family): compare bytes at address, compare disassembly against another file.
8. **Zignatures** (`z` family): list (`zj`), generate from analysis (`zg`), add (`za`), search matches (`z/`).
9. **Project/session** (`P` family): save project (`Ps`), open project (`Po`), list projects (`Pl`).
10. **Runtime configuration** (`e` family): get config value (`e key`), set config value (`e key=value`).

## Coverage matrix

| # | Native feature | Bridge method | Tool-def | GUI control |
|---|---|---|---|---|
| 1 | Attach to process | `attach` — `cutter.py:4029-4059` (real, issues `dp <pid>`) | OK — `cutter.py:983-990` | **NO-CONTROL** |
| 2 | Detach from process | `detach` — `cutter.py:4061-4079` (real, issues `dp-`, clears bp/thread state) | OK — `cutter.py:991-996` | **NO-CONTROL** |
| 3 | Set breakpoint (sw/hw/mem, conditional) | `set_breakpoint` — `cutter.py:4081-4147` (real, `db`/`dbH`/`dbm`/`dbC`) | OK — `cutter.py:997-1013` | **NO-CONTROL** |
| 4 | Remove breakpoint | `remove_breakpoint` — `cutter.py:4149-4166` (real, `db-`) | OK — `cutter.py:1014-1021` | **NO-CONTROL** |
| 5 | List breakpoints | `get_breakpoints` — `cutter.py:4168-4219` (real, `dbj` merged with local cache) | OK — `cutter.py:1022-1027` | **NO-CONTROL** |
| 6 | Step into | `step_into` — `cutter.py:4221-4238` (real, `ds` + `dr?PC`) | OK — `cutter.py:1028-1033` | **NO-CONTROL** |
| 7 | Step over | `step_over` — `cutter.py:4240-4257` (real, `dso` + `dr?PC`) | OK — `cutter.py:1034-1039` | **NO-CONTROL** |
| 8 | Continue execution | `run` — `cutter.py:4259-4267` (real, `dc`) | OK — `cutter.py:1040-1045` | **NO-CONTROL** |
| 9 | Read registers | `get_registers` — `cutter.py:4269-4338` (real, `drj` parsed into `RegisterState`) | OK — `cutter.py:1046-1051` | **NO-CONTROL** |
| 10 | Set register | `set_register` — `cutter.py:4340-4358` (real, `dr reg=value`, validated) | OK — `cutter.py:1052-1060` | **NO-CONTROL** |
| 11 | Read process memory | `read_memory` — `cutter.py:4360-4397` (real, `p8 size @ addr`) | OK — `cutter.py:1061-1069` | **NO-CONTROL** |
| 12 | Write process memory | `write_memory` — `cutter.py:4399-4420` (real, `wx hex @ addr`) | OK — `cutter.py:1070-1078` | **NO-CONTROL** |
| 13 | Enumerate memory regions | `get_memory_regions` — `cutter.py:4422-4469` (real, `dmj`) | OK — `cutter.py:1079-1084` | **NO-CONTROL** |
| 14 | Enumerate threads | `get_threads` — `cutter.py:4471-4507` (real, `dptj`) | OK — `cutter.py:1085-1090` | **NO-CONTROL** |
| 15 | Enumerate loaded modules | `get_modules` — `cutter.py:4509-4551` (real, `dmIj`) | OK — `cutter.py:1091-1096` | **NO-CONTROL** |
| 16 | ESIL: evaluate expression | `esil_eval` — `cutter.py:3211-3229` (real, `ae <expr>`) | OK — `cutter.py:749-756` | OK — `ESILConsoleTab._on_eval`, `cutter_tabs.py:777-795`, wired to Eval button/Enter (`cutter_tabs.py:733-734`) |
| 17 | ESIL: single step | `esil_step` — `cutter.py:3231-3251` (real, `aes` loop) | OK — `cutter.py:757-764` | OK — `ESILConsoleTab._on_step`, `cutter_tabs.py:797-810`, wired to Step button (`cutter_tabs.py:735`) |
| 18 | ESIL: emulate whole function | `esil_emulate_function` — `cutter.py:3253-3271` (real, `aef @ addr`) | OK — `cutter.py:765-772` | **NO-CONTROL** |
| 19 | ESIL: init emulation memory | `esil_init_memory` — `cutter.py:3273-3288` (real, `aeim`) | OK — `cutter.py:773` | OK — `ESILConsoleTab._on_init_mem`/auto-init on tab refresh, `cutter_tabs.py:738-757,812-825`, wired to Init Mem button (`cutter_tabs.py:736`) |
| 20 | ESIL: set program counter | `esil_set_pc` — `cutter.py:3290-3308` (real, `aepc addr`) | OK — `cutter.py:774-781` | **NO-CONTROL** |
| 21 | Flags: list all | `get_flags` — `cutter.py:2975-2998` (real, `fj`) | OK — `cutter.py:716` | OK — `FlagsTab.refresh`, `cutter_tabs.py:452-466`, auto-populates on analyze via `_refresh_new_tabs` (`cutter_panel.py:1122-1139`); **read-only table, no add/resolve control** |
| 22 | Flags: add named flag | `add_flag` — `cutter.py:3000-3020` (real, `f name size @ addr`) | OK — `cutter.py:717-726` | **NO-CONTROL** |
| 23 | Flags: resolve nearest flag to address | `resolve_flag` — `cutter.py:3022-3065` (real, `fdj`, nearest-by-distance) | OK — `cutter.py:727-734` | **NO-CONTROL** |
| 24 | Xrefs to address | `get_xrefs_to` — `cutter.py:1991-2034` (real, `axtj`) | OK — `cutter.py:560-567` | OK — `CutterPanel._show_xrefs`, `cutter_panel.py:1006-1025`, invoked automatically from function-tree click handler `_on_function_clicked` (`cutter_panel.py:638-686`) populating "XRefs" tab tree |
| 25 | Xrefs from address | `get_xrefs_from` — `cutter.py:2036-2079` (real, `axfj`) | OK — `cutter.py:568-575` | OK — same `_show_xrefs` call site as above, `cutter_panel.py:1027-1035` |
| 26 | Search: string regex over string table | `search_strings` — `cutter.py:2081-2133` (real, `izj` + Python regex) | OK — `cutter.py:576-583` | OK — `CutterPanel._on_search_strings`/`search_strings`, `cutter_panel.py:954-1004`, wired to search input Enter + Search button (`cutter_panel.py:279,284`) |
| 27 | Search: byte pattern | `search_bytes` — `cutter.py:2135-2159` (real, `/xj`) | OK — `cutter.py:584-591` | **NO-CONTROL** |
| 28 | Search: wildcard byte pattern | `search_bytes_wildcard` — `cutter.py:2161-2185` (real, `..`-wildcarded `/xj`) | OK — `cutter.py:638-645` | **NO-CONTROL** |
| 29 | Search: literal string (byte-encoded, injection-safe) | `search_string_live` — `cutter.py:3669-3701` (real, UTF-8-hex `/xj`) | OK — `cutter.py:903-910` | **NO-CONTROL** |
| 30 | Search: assembly instruction pattern | `search_assembly_pattern` — `cutter.py:3703-3733` (real, `/aj`, validated) | OK — `cutter.py:911-918` | **NO-CONTROL** |
| 31 | Search: crypto constants | `search_crypto_constants` — `cutter.py:3735-3750` (real, `/cj`) | OK — `cutter.py:919` | **NO-CONTROL** |
| 32 | Search: magic signatures | `search_magic` — `cutter.py:3752-3767` (real, `/mj`) | OK — `cutter.py:920` | **NO-CONTROL** |
| 33 | Search: numeric value | `search_value` — `cutter.py:3769-3789` (real, `/vj{size}`) | OK — `cutter.py:921-929` | **NO-CONTROL** |
| 34 | Compare bytes at address | `compare_bytes` — `cutter.py:3791-3810` (real, `c hex @ addr`) | OK — `cutter.py:930-938` | **NO-CONTROL** |
| 35 | Compare disassembly against another file | `compare_disassembly` — `cutter.py:3812-3847` (real, `cD` + `cCj`) | OK — `cutter.py:939-947` | **NO-CONTROL** |
| 36 | Seek to address | `seek` — `cutter.py:2407-2417` (real, `s <addr>` via `execute_command`) | OK — `cutter.py:655-662` | OK — `CutterPanel._on_goto_address`, `cutter_panel.py:1206-1230`, wired to "Go" toolbar button/goto-input (`cutter_panel.py:144-145`) |
| 37 | Resolve function address by name | `get_function_address` — `cutter.py:2446-2488` (real, `afij <name>`, exact-match + validated) | OK — `cutter.py:663-670` | OK — `CutterPanel._on_find_function`, `cutter_panel.py:1256-1287`, wired to "Find" toolbar button/find-func-input (`cutter_panel.py:146-147`) |
| 38 | Raw command execution (generic navigation/console escape hatch) | `execute_command` — `cutter.py:2395-2405` (real, direct `r2_cmd`) | OK — `cutter.py:622-629` | OK — `CutterPanel._on_run_command`, `cutter_panel.py:1077-1120`, wired to console input/Run button (`cutter_panel.py:397,402`) |
| 39 | Zignatures: list | `get_zignatures` — `cutter.py:3314-3329` (real, `zj`) | OK — `cutter.py:782` | **NO-CONTROL** |
| 40 | Zignatures: generate | `generate_zignatures` — `cutter.py:3331-3353` (real, `zg`/`zg @ addr`) | OK — `cutter.py:783-790` | **NO-CONTROL** |
| 41 | Zignatures: add | `add_zignature` — `cutter.py:3355-3374` (real, `za name data`) | OK — `cutter.py:791-799` | **NO-CONTROL** |
| 42 | Zignatures: search matches | `search_zignatures` — `cutter.py:3376-3391` (real, `z/j`) | OK — `cutter.py:800` | **NO-CONTROL** |
| 43 | Project: save | `save_project` — `cutter.py:3397-3415` (real, `Ps name`) | OK — `cutter.py:801-808` | **NO-CONTROL** |
| 44 | Project: open | `open_project` — `cutter.py:3417-3435` (real, `Po name`) | OK — `cutter.py:809-816` | **NO-CONTROL** |
| 45 | Project: list | `list_projects` — `cutter.py:3437-3453` (real, `Pl`) | OK — `cutter.py:817` | **NO-CONTROL** |
| 46 | Config: get value | `get_config` — `cutter.py:3455-3473` (real, `e key`) | OK — `cutter.py:818-825` | **NO-CONTROL** |
| 47 | Config: set value | `set_config` — `cutter.py:3475-3494` (real, `e key=value`) | OK — `cutter.py:826-834` | **NO-CONTROL** |

Note: `rename_function`, `add_comment`, `write_bytes`/`write_xor`/`write_add`/`write_sub`/`write_from_file`/`write_to_file`/`write_value`/`write_string`, `save_binary`, `assemble_at` exist in the bridge but are patch/editing features, out of scope for this slice (dynamic & navigation) and were excluded from the matrix rather than counted as gaps.

## Coverage summary

- **Native features in slice: 47**
- **Fully ported (all 3 layers OK): 12** — ESIL eval/step/init-mem (3), xrefs-to/xrefs-from (2), search_strings (1), seek (1), get_function_address (1), execute_command (1), get_flags (1, though the control is read-only-view not an add/resolve control — counted OK because the native "list flags" feature itself is fully reachable end-to-end)
- **NO-CONTROL (bridge + tool-def OK, no reachable GUI widget): 35**
  - All 15 debugger/process-control methods (attach, detach, set/remove/get breakpoints, step_into, step_over, run, get_registers, set_register, read_memory, write_memory, get_memory_regions, get_threads, get_modules)
  - 2 ESIL methods (esil_emulate_function, esil_set_pc)
  - 2 flag-mutation methods (add_flag, resolve_flag)
  - 9 search/compare methods (search_bytes, search_bytes_wildcard, search_string_live, search_assembly_pattern, search_crypto_constants, search_magic, search_value, compare_bytes, compare_disassembly)
  - 4 zignature methods (get/generate/add/search_zignatures)
  - 3 project methods (save/open/list_projects)
  - 2 config methods (get/set_config)
- **STUB: 0**
- **NOT-REGISTERED: 0**
- **DEAD-CONTROL: 0**
- **MISSING (native feature with no bridge method at all): 0** — every native feature enumerated maps to a real, implemented bridge method.

All Layer-1 (bridge) and Layer-2 (tool-definition/dispatch) implementations for this slice are complete and real — every method inspected performs an actual rizin command round-trip with real parsing, error handling (`ToolError` on missing binary/attachment/invalid input), and structured logging; none are stubs or placeholders. The gap is entirely concentrated in Layer 3 (GUI). AI/orchestration-driven usage of these 47 functions is already fully possible via `ToolRegistry.execute_tool_call` and the raw command console; only end-user point-and-click access is missing for 35 of them.

## Prioritized gap list

1. **No debugger UI at all (highest impact).** 15 of 15 native debugging operations (attach/detach, breakpoints, stepping, continue, registers, memory, threads, modules) are fully implemented and tool-def-registered but have zero GUI presence — `cutter_panel.py` and `cutter_tabs.py` contain no `Debugger` tab, no attach dialog, no breakpoint list widget, no register/memory view, and no step/continue buttons. This is the single largest usability gap in the slice: a user cannot drive rizin's debugger at all from the panel; they must fall back to typing raw `d*` commands into the generic console (`cutter_panel.py:1077-1120`), which defeats the point of structured widgets. Fix location: new `DebuggerTab`/`DebuggerPanel` class in `src/intellicrack/ui/panels/cutter_tabs.py` (or a new file alongside it) with breakpoint table, register grid, memory/threads/modules views, and step/continue/attach controls, registered into `cutter_panel.py`'s tab widget (pattern to follow: `FlagsTab`/`ROPGadgetsTab` for read tables, `ESILConsoleTab` for the input+button+output layout for stepping/continue actions).

2. **No project/session management UI.** `save_project`, `open_project`, `list_projects` are fully implemented (`cutter.py:3397-3453`) but unreachable from the GUI, even though "project/session handling" is explicitly named in this slice's mandate and the panel already has a "Save Binary" and "Patch..." toolbar affordance pattern to mirror (`cutter_panel.py:139-140`). Fix location: add toolbar buttons or a Project menu in `cutter_panel.py:_populate_toolbar` (around line 139) wired via `run_bridge_coroutine_logged` to the three project methods, following the `_on_save_binary` pattern (`cutter_panel.py:1141-1166`).

3. **No advanced-search UI beyond string/ROP-gadget search.** 7 distinct native search/compare capabilities (byte pattern, wildcard byte pattern, literal-string byte search, assembly-pattern search, crypto-constant search, magic search, numeric-value search, plus 2 compare operations) have no dedicated widget — only regex string search (`_on_search_strings`) and ROP-gadget search (`ROPGadgetsTab`) are exposed. A power user researching a binary has no point-and-click way to search for byte patterns, crypto constants, or embedded magic signatures. Fix location: a `SearchTab` in `cutter_tabs.py` with a mode selector (bytes/wildcard/assembly/crypto/magic/value) analogous to `ROPGadgetsTab`'s pattern-input + search-button + results-table structure (`cutter_tabs.py:484-561`).

4. **Flags are read-only in the GUI.** `add_flag` and `resolve_flag` are implemented and registered but `FlagsTab` (`cutter_tabs.py:437-481`) only lists existing flags; there is no way to create a flag or resolve an address to its nearest flag from the UI. Fix location: extend `FlagsTab.__init__` in `cutter_tabs.py:440-450` with a name/address/size input row and "Add" button, and optionally a resolve-lookup field, following `ROPGadgetsTab`'s toolbar-row pattern.

5. **ESIL function-level emulation and PC control are console-only.** `esil_emulate_function` and `esil_set_pc` are implemented (`cutter.py:3253-3271,3290-3308`) but `ESILConsoleTab` only exposes eval/step/init-mem (`cutter_tabs.py:718-736`); a user must type `aef @ addr` or `aepc addr` manually via the expression field (which does work through raw `execute_command`-style passthrough is not even wired here — `esil_eval` sends `ae <expr>`, not arbitrary ESIL admin commands) rather than through a dedicated "Emulate Function" or "Set PC" control. Fix location: add two more buttons/inputs to `ESILConsoleTab` in `cutter_tabs.py:693-736` (an address field + "Emulate Fn" button, and a "Set PC" button), each wired via `run_bridge_coroutine_logged` per the existing `_on_step`/`_on_init_mem` pattern.

6. **Zignatures and runtime config have no UI at all** (lower priority — power-user/scripting-oriented features). All 4 zignature methods and both config methods are implemented and registered but entirely absent from the GUI; acceptable to leave console-only longer-term, but if prioritized, a `ZignatureTab` (list + generate + add + search, mirroring `FlagsTab`/`ROPGadgetsTab`) and a simple key/value `ConfigTab` would close the gap. Fix location: new tab classes in `cutter_tabs.py`, registered in `cutter_panel.py`.

Sources consulted for native ground truth: [Rizin Handbook — Basic Debugger Session](https://book.rizin.re/src/first_steps/basic_debugger_session.html), [Rizin Handbook — Debugger intro](https://book.rizin.re/src/debugger/intro.html), [Rizin Handbook — Registers](https://book.rizin.re/src/debugger/registers.html), [Rizin Handbook — Flags](https://book.rizin.re/src/basic_commands/flags.html), [Rizin Handbook — Basic Search](https://book.rizin.re/src/search_bytes/basic_searches.html), [Introducing Projects in Rizin](https://rizin.re/posts/introducing-projects/), [radare2/rizin cheatsheet](https://rehex.ninja/posts/radare2-rizin-cheatsheet/).
