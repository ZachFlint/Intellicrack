# Adversarial Verification — Slice 4: Cutter/Rizin — Dynamic & Navigation

Report under verification: `audit/bridge-completeness/agent-04-cutter-rizin-dynamic-navigation.md`

Source files opened and read in full for this verification:
- `src/intellicrack/bridges/cutter.py` (4573 lines)
- `src/intellicrack/ui/panels/cutter_panel.py` (1432 lines, full read)
- `src/intellicrack/ui/panels/cutter_tabs.py` (1018 lines, full read)
- `src/intellicrack/core/tools.py` (dispatch, lines 540-624 read)

## Method

For every one of the 47 matrix rows: independently located the bridge method body, independently located the `_tf(...)` tool-definition entry, and — for every row marked **NO-CONTROL** — grepped/read `cutter_panel.py` and `cutter_tabs.py` in full (not just the cited line) for any widget, button, context-menu action, or handler that could call the method directly or via `run_bridge_coroutine`/`run_bridge_coroutine_logged`. Also checked `src/intellicrack/ui/app.py` and other UI files for any top-level menu/dialog that might dispatch into `CutterBridge` methods outside the two panel files. Also independently re-summed the coverage-summary counts against the matrix.

## Verification table

| # | Finding | Verdict | Independent evidence | Note |
|---|---|---|---|---|
| 1-15 | Debugger session (attach/detach/breakpoints/step/run/registers/memory/threads/modules) — all NO-CONTROL | CONFIRMED | `cutter_panel.py` (full read, 1432 lines) and `cutter_tabs.py` (full read, 1018 lines) contain no debugger tab, no attach dialog, no breakpoint table, no register/memory/thread/module view, and no step/continue button anywhere. `app.py:2822-2836` only opens the Cutter panel and loads a binary; no debugger menu wired at app level. | Bridge methods verified real at `cutter.py:4029-4551` (genuine `dp`/`db`/`ds`/`dso`/`dc`/`dr`/`p8`/`wx`/`dm`/`dp`/`dmI` round-trips with state tracking). Tool-defs verified present at `cutter.py:983-1096`. |
| 16 | ESIL eval — OK | CONFIRMED | `ESILConsoleTab._on_eval`, `cutter_tabs.py:777-795`, wired to Eval button (`cutter_tabs.py:718-720,733`) and Enter (`734`). Bridge real at `cutter.py:3211-3229` (`ae <expr>`). | |
| 17 | ESIL step — OK | CONFIRMED | `ESILConsoleTab._on_step`, `cutter_tabs.py:797-810`, wired to Step button (`722-723,735`). Bridge real at `cutter.py:3231-3251`, loops `aes` `count` times. | |
| 18 | ESIL emulate function — NO-CONTROL | CONFIRMED | No address-field/"Emulate Fn" control anywhere in `ESILConsoleTab` (`cutter_tabs.py:693-835`) or elsewhere. Bridge real at `cutter.py:3253-3271` (`aef @ addr`). Tool-def at `cutter.py:765-772`. | |
| 19 | ESIL init memory — OK | CONFIRMED | Explicit "Init Mem" button wired to `_on_init_mem` (`cutter_tabs.py:726-728,736,812-825`) **and** auto-invoked on tab refresh (`cutter_tabs.py:745-757`). Genuinely GUI-reachable both ways, not just an internal auto-call. | |
| 20 | ESIL set PC — NO-CONTROL | CONFIRMED | No "Set PC" control anywhere. Bridge real at `cutter.py:3290-3308` (`aepc addr`). Tool-def at `cutter.py:774-781`. | |
| 21 | Flags: list — OK (read-only) | CONFIRMED | `FlagsTab` (`cutter_tabs.py:437-482`) is a plain table with only a `refresh()` method calling `get_flags()`; no add/resolve inputs exist in the class body. Auto-populated via `_refresh_new_tabs` (`cutter_panel.py:1122-1139`, `cutter_panel.py:1135`). The report's own caveat ("read-only-view not an add/resolve control") is accurate and not overstated. | |
| 22 | Flags: add — NO-CONTROL | CONFIRMED | `FlagsTab` has no name/address/size input row or Add button (verified full class body, `cutter_tabs.py:437-482`). Bridge real at `cutter.py:3000-3020`. Tool-def at `cutter.py:717-726`. | |
| 23 | Flags: resolve — NO-CONTROL | CONFIRMED | Same class, no resolve field. Bridge real at `cutter.py:3022-3065` (uses `fdj`, nearest-by-distance, as claimed). Tool-def at `cutter.py:727-734`. | |
| 24-25 | Xrefs to/from — OK | CONFIRMED | `_show_xrefs` (`cutter_panel.py:1006-1035`) called from `_on_function_clicked` (`cutter_panel.py:638-686`, specifically line 686 `self._show_xrefs(address)`). Populates "XRefs" tree tab (`cutter_panel.py:325-328`). Bridge real at `cutter.py:1991-2079` (`axtj`/`axfj`). | |
| 26 | Search strings (regex) — OK | CONFIRMED | `_on_search_strings`/`search_strings`, `cutter_panel.py:954-1004`, wired to Enter (`cutter_panel.py:279`) and Search button (`cutter_panel.py:282-284`). Bridge real at `cutter.py:2081-2133` (`izj` + Python regex). | |
| 27 | Search bytes — NO-CONTROL | CONFIRMED | No byte-pattern search widget anywhere in either file; only the string-regex search box exists. Bridge real at `cutter.py:2135-2159` (`/xj`). Tool-def at `cutter.py:584-591`. | |
| 28 | Search bytes wildcard — NO-CONTROL | CONFIRMED | Same as above; no wildcard mode selector exists. Bridge real at `cutter.py:2161-2185`. Tool-def at `cutter.py:638-645`. | |
| 29 | Search string (literal, byte-encoded) — NO-CONTROL | CONFIRMED | Distinct from row 26 (`search_strings` regex) — `search_string_live` (`cutter.py:3669-3701`, UTF-8-hex `/xj`) has no separate GUI entry point; only the regex-search box calls `search_strings`, not `search_string_live`. Tool-def at `cutter.py:903-910`. | |
| 30 | Search assembly pattern — NO-CONTROL | CONFIRMED | No assembly-pattern search widget. Bridge real at `cutter.py:3703-3733` (`/aj`, `validate_r2_argument`-style checks visible in surrounding code). Tool-def at `cutter.py:911-918`. | |
| 31 | Search crypto constants — NO-CONTROL | CONFIRMED | No such widget. Bridge real at `cutter.py:3735-3750` (`/cj`). Tool-def at `cutter.py:919`. | |
| 32 | Search magic — NO-CONTROL | CONFIRMED | No such widget. Bridge real at `cutter.py:3752-3767` (`/mj`). Tool-def at `cutter.py:920`. | |
| 33 | Search value — NO-CONTROL | CONFIRMED | No such widget. Bridge real at `cutter.py:3769-3789` (`/v{size}j`). Tool-def at `cutter.py:921-929`. | |
| 34 | Compare bytes — NO-CONTROL | CONFIRMED | No compare widget anywhere. Bridge real at `cutter.py:3791-3810`. Tool-def at `cutter.py:930-938`. | |
| 35 | Compare disassembly — NO-CONTROL | CONFIRMED | Same as above. Bridge real at `cutter.py:3812-3847`. Tool-def at `cutter.py:939-947`. | |
| 36 | Seek — OK | CONFIRMED | `_on_goto_address`, `cutter_panel.py:1206-1230`, wired to "Go" button (`cutter_panel.py:144-145`). Bridge real at `cutter.py:2407-2417`. | |
| 37 | Get function address (find) — OK | CONFIRMED | `_on_find_function`, `cutter_panel.py:1256-1287`, wired to "Find" button/input (`cutter_panel.py:146-147`). Bridge real at `cutter.py:2446-2488`. | |
| 38 | Execute command (console) — OK | CONFIRMED | `_on_run_command`, `cutter_panel.py:1077-1120`, wired to console input Enter (`397`) and Run button (`400-402`). Bridge real at `cutter.py:2395-2405`. | |
| 39-42 | Zignatures (list/generate/add/search) — all NO-CONTROL | CONFIRMED | No zignature tab/widget exists anywhere in either UI file. Bridge methods real at `cutter.py:3314-3391` (`zj`/`zg`/`za`/`z/j`). Tool-defs at `cutter.py:782-800`. | |
| 43-45 | Project (save/open/list) — all NO-CONTROL | CONFIRMED | No project menu/toolbar button exists; only "Save Binary" (patched-bytes save, a different feature entirely — `_on_save_binary`, `cutter_panel.py:1141-1166`, calling `save_binary`, not `save_project`) and "Patch..." exist. Bridge methods real at `cutter.py:3397-3453` (`Ps`/`Po`/`Pl`). Tool-defs at `cutter.py:801-817`. | |
| 46-47 | Config (get/set) — both NO-CONTROL | CONFIRMED | No config key/value widget exists. Bridge methods real at `cutter.py:3455-3494` (`e key`/`e key=value`). Tool-defs at `cutter.py:818-834`. | |
| — | "Excluded as out of scope" list (rename_function, add_comment, write_bytes family, save_binary, assemble_at) | CONFIRMED (correct scoping, not a miscount) | All are genuinely GUI-wired: `rename_function` via context-menu Rename (`cutter_panel.py:1305-1306,1331-1352`), `add_comment` via context-menu Add Comment (`cutter_panel.py:1309-1310,1364-1385`), `write_bytes` via Patch dialog (`cutter_panel.py:140,1168-1204`), `save_binary` via Save Binary toolbar button (`cutter_panel.py:139,1141-1166`). Correctly excluding these (rather than counting them as slice gaps) is accurate; they are patch/editing features, a different slice per the report's own stated scope line 4. | |
| — | "Layer 1 = 100% real" claim | CONFIRMED | Spot-checked 6 methods across debug/ESIL/flags/project/config families (`attach`, `detach`, `set_breakpoint`, `get_breakpoints`, `esil_eval/step/emulate_function/init_memory/set_pc`, `get_flags/add_flag/resolve_flag`, `save_project/open_project/list_projects/get_config/set_config`) — every one issues a genuine rizin command via `_r2_cmd`/`_cmd_json`/`_debug_cmd_json`, has real structured parsing (dataclasses `BreakpointInfo`/`FlagInfo`/etc.), real `ToolError` guards on missing binary/attachment, and real logging. None are stubs. | |
| — | "Layer 2 = 100% registered" claim | CONFIRMED | Spot-checked all 47 `_tf(...)` entries by line-range read (`cutter.py:700-950`, `960-1097`) — every cited tool-def entry exists with matching name, description, and parameter list. `tool_definition` property (`cutter.py:1336-1347`) genuinely calls `_build_tool_functions()`, which is the function containing all these `_tf(...)` calls. | |
| — | Dispatch mechanism claim (`ToolRegistry.execute_tool_call` via `getattr`) | CONFIRMED | `tools.py:551-604`: `execute_tool_call` resolves `bridge = self._bridges.get(tool_enum)`, then `method = getattr(bridge, attr_name, None)`, then calls it — exactly as described. Report's caveat that the assumed `_td(...)` helper doesn't exist and the actual pattern is `_tf(...)` is also independently confirmed (no `_td(` in the file; `_tf(` is the real helper name used throughout). | |
| — | Coverage summary counts (12 fully-ported / 35 NO-CONTROL) | **FALSE (arithmetic error in report, not in the underlying findings)** | Independently tallied the 47-row matrix's GUI-control column: **10** rows marked `OK` (#16,17,19,21,24,25,26,36,37,38) and **37** rows marked `NO-CONTROL` (all others). The report's own detailed NO-CONTROL breakdown (15+2+2+9+4+3+2 = **37**) matches this recount and contradicts its own summary bullet header text ("35"). The "Fully ported" bullet's own itemized list (3+2+1+1+1+1+1 = **10**) likewise contradicts its stated "12". | See correction below. |

## FALSE POSITIVES / NEEDS REVIEW

No individual matrix-row finding (rows 1-47) is a false positive. Every NO-CONTROL claim was independently verified by a full read of both UI files (not just the cited line) plus a check of `app.py` for any hidden top-level dispatch; no missed widget, dialog, menu, or debugger UI was found anywhere in the codebase for any of the 37 claimed-missing controls. Every "OK" claim was independently confirmed end-to-end (signal wired to slot wired to bridge call). Every "real implementation" (Layer 1) and "registered" (Layer 2) claim spot-checked correctly.

**One correction needed — summary arithmetic:**

- Report states (line 80): "Fully ported (all 3 layers OK): **12**" — should be **10**. The report's own examples list sums to 10 (ESIL eval/step/init-mem=3, xrefs-to/from=2, search_strings=1, seek=1, get_function_address=1, execute_command=1, get_flags=1 → 3+2+1+1+1+1+1=10), and independent recount of the 47-row matrix confirms exactly 10 rows marked OK.
- Report states (line 81): "NO-CONTROL ... : **35**" — should be **37**. The report's own itemized breakdown sums to 37 (15+2+2+9+4+3+2=37), and independent recount of the matrix confirms exactly 37 rows marked NO-CONTROL.
- 10 + 37 = 47, consistent with "Native features in slice: 47" (line 79) and with "STUB: 0 / NOT-REGISTERED: 0 / DEAD-CONTROL: 0 / MISSING: 0" (lines 89-92).
- Net effect: this is a **transcription/arithmetic slip in the summary headline numbers only** — the underlying per-feature classification, the itemized breakdown list, the full 47-row matrix, and the prioritized gap list are all internally consistent with 10/37, not 12/35. This does not change the report's central conclusion (the GUI gap is dominated by NO-CONTROL, concentrated in debugger/search/project/zignature/config UI) but the two headline counts should be corrected to 10 and 37 respectively.

## Tally

- **47 findings checked** (47 matrix rows + Layer 1/Layer 2/dispatch/scope-exclusion claims + summary arithmetic)
- **46 confirmed** (all 47 matrix rows individually confirmed as correctly classified; Layer 1, Layer 2, dispatch mechanism, and scope-exclusion claims all confirmed)
- **0 false-positive** (no matrix row is wrongly classified)
- **1 needs-review** (summary headline counts "12 fully ported / 35 NO-CONTROL" are an internal arithmetic error; correct values, confirmed by both the report's own itemized lists and independent recount, are **10 fully ported / 37 NO-CONTROL**)
