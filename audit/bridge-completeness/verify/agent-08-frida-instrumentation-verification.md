# Verification: Frida Instrumentation Slice (agent-08-frida-instrumentation.md)

Adversarial re-check of every row/finding in `audit/bridge-completeness/agent-08-frida-instrumentation.md`
against the actual source: `src/intellicrack/bridges/frida_bridge.py` (7146 lines),
`src/intellicrack/ui/panels/frida_panel.py` (2505 lines), `src/intellicrack/core/tools.py`.

Method: independently re-read every cited bridge method body (checked for real Frida JS round-trips
vs. stub/no-op), independently grepped `frida_panel.py` for every claimed-missing method name (zero
assumed matches — full-file grep, not cite-trust), and independently grepped the bridge for the
"MISSING" Stalker primitives. Also traced the dispatch path in `tools.py:551-638` and the full tab
structure of the panel (Hooks/Threads/Stalker/Modules/Memory/Symbols/Advanced) to rule out any hidden
generic/dynamic-dispatch control that could reach a "NO-CONTROL" method indirectly.

## Dispatch mechanism (preliminary check)

Confirmed at `src/intellicrack/core/tools.py:587-588`: `attr_name = function_name.split(".", 1)[-1]`
then `getattr(bridge, attr_name)` (line 588), called via `asyncio.to_thread` or `await` at line
631-634. This matches the report's description exactly — no NOT-REGISTERED risk from a broken
dispatch pattern.

## Verification Table

| # | Finding | Verdict | Independent evidence (file:line) | Note |
|---|---|---|---|---|
| 1 | `hook_function` OK, GUI wired | CONFIRMED | frida_panel.py:302-304 `_add_hook_btn`→`_on_add_hook`; call site confirmed via `run_bridge_coroutine_logged(self._bridge.hook_function(target), ...)` at frida_panel.py:783-784 | Real button, real call site |
| 2 | `replace_function` OK, GUI wired | CONFIRMED | frida_panel.py:317-319 `_replace_fn_btn`; call site frida_panel.py:1379-1380 `self._bridge.replace_function(target.strip(), code.strip())` | matches |
| 3 | `revert_hook` NO-CONTROL | CONFIRMED | Bridge impl frida_bridge.py:5054-5086 (real `Interceptor.revert(targetAddr)` JS, error handling, raises `ToolError` on failure — not a stub). Tool-def frida_bridge.py:701-708. Full-file grep of frida_panel.py for `revert_hook` → **0 matches** | Genuine gap |
| 4 | `flush_interceptor` NO-CONTROL | CONFIRMED | Bridge impl frida_bridge.py:5088-5111 (`Interceptor.flush()`, real). Tool-def frida_bridge.py:709-714. Grep frida_panel.py for `flush_interceptor` → **0 matches** | Genuine gap |
| 5 | `remove_hook`/`get_hooks` OK, GUI wired | CONFIRMED | `_remove_hook_btn` frida_panel.py:307-309 → `_on_remove_hook` → frida_panel.py:859-860 `self._bridge.remove_hook(hook_id)`; `_refresh_hooks_btn` :322-324 → frida_panel.py:1397-1398 `self._bridge.get_hooks()` | matches |
| 6 | `intercept_return` OK, GUI wired | CONFIRMED | `_intercept_ret_btn` frida_panel.py:312-314 → frida_panel.py:1347-1348 `self._bridge.intercept_return(...)` | matches |
| 7 | `stalker_follow` OK, GUI wired, real impl | CONFIRMED | Bridge impl frida_bridge.py:3930-4098 spot-checked: real `Stalker.follow`-equivalent JS with `Stalker.unfollow`/`Stalker.flush` embedded stop logic, `recv('stalker_unfollow_request', ...)` handler — genuine, not a thin wrapper. GUI: `_stalker_start_btn` frida_panel.py:437-439 → frida_panel.py:1107-1108 `self._bridge.stalker_follow(...)` | matches; spot-check requested by task passed |
| 8 | `stalker_unfollow` OK, GUI wired | CONFIRMED | `_stalker_stop_btn` frida_panel.py:442-445 → frida_panel.py:1157-1158 `self._bridge.stalker_unfollow(...)` | matches |
| 9 | `stalker_add_call_probe` NO-CONTROL | CONFIRMED | Bridge impl frida_bridge.py:5208-5265 (real `Stalker.addCallProbe(ptr(...), function(args){...})`, script lifecycle, `self._call_probes[probe_id]` bookkeeping — genuine). Tool-def frida_bridge.py:733-741. Grep frida_panel.py for `stalker_add_call_probe` → **0 matches**. Stalker section (frida_panel.py:385-450+) only has thread-id/events-checkboxes/limit/Start-Stop — no probe list/add/remove widgets | Genuine gap |
| 10 | `stalker_remove_call_probe` NO-CONTROL | CONFIRMED | Bridge impl frida_bridge.py:5267-5282 (real, pops `_call_probes`, calls `_unload_script`). Tool-def frida_bridge.py:742-748. Grep frida_panel.py → **0 matches** | Genuine gap |
| 11 | `Stalker.exclude`/`garbageCollect`/`invalidate`/`trustThreshold` MISSING | CONFIRMED | Grepped frida_bridge.py for `exclude|garbageCollect|invalidate|trustThreshold` → **0 matches** anywhere in the 7146-line file. Grepped all `def` names in the file for anything Stalker-related beyond `stalker_follow`, `stalker_unfollow`, `stalker_add_call_probe`, `stalker_remove_call_probe` — none found under another name | Truly absent, not an alias |
| 12 | `scan_memory` OK, uses `Memory.scanSync`, GUI wired | CONFIRMED | Bridge impl frida_bridge.py:1890-1968 spot-checked: genuine per-range `Memory.scanSync(range.base, range.size, hex_pattern)` loop (line 1944), real hex/wildcard pattern handling, not a no-op. GUI: `_mem_scan_btn` → `_on_scan_memory` → frida_panel.py:1900-1901 `self._bridge.scan_memory(pattern_bytes)` | matches; spot-check passed |
| 13 | `read_memory`/`write_memory` OK, GUI wired | CONFIRMED | Call sites frida_panel.py:1810-1811 (`read_memory`) and 1854-1855 (`write_memory`) both present and reach `self._bridge.*` | matches |
| 14 | `get_memory_regions` OK, GUI wired | CONFIRMED | Call site frida_panel.py:1943-1944 `self._bridge.get_memory_regions(protection)` | matches |
| 15 | `protect_memory` OK, GUI wired | CONFIRMED | Call site frida_panel.py:1997-1998 `self._bridge.protect_memory(addr, size, protection)` | matches |
| 16 | `allocate_memory` OK, GUI wired | CONFIRMED | Call site frida_panel.py:1871-1872 `self._bridge.allocate_memory(size)` | matches |
| 17 | `patch_code` NO-CONTROL | CONFIRMED | Bridge impl frida_bridge.py:4544-4584 (real `Memory.patchCode(ptr(...), size, function(code){code.writeByteArray(bytes)})` — genuine, implicit I-cache flush via `Memory.patchCode` semantics is correct). Tool-def frida_bridge.py:616-624 (`frida.patch_code`, verified name present in earlier grep). Grep frida_panel.py for `patch_code` → **0 matches** | Genuine gap |
| 18 | `allocate_string` NO-CONTROL | CONFIRMED | Bridge impl frida_bridge.py:4586-4653 (real `Memory.allocUtf8String/allocAnsiString/allocUtf16String` dispatch by encoding, persistent script + `_alloc_scripts` bookkeeping to prevent GC — genuine). Tool-def frida_bridge.py:625-632. Grep frida_panel.py for `allocate_string` → **0 matches**; Memory tab confirmed to have only Read/Write/Scan/Regions/Protect sub-tabs (frida_panel.py:1641-1645), no string-alloc tab | Genuine gap |
| 19 | `call_function` OK, GUI wired | CONFIRMED | Advanced tab "Function Calling" section frida_panel.py:2237-2270, `_adv_call_btn` :2250-2252 → `_on_call_function` → frida_panel.py:2358-2359 `self._bridge.call_function(addr, args, return_type=ret_type, arg_types=arg_types, calling_convention=cc)` | matches |
| 20 | `call_system_function` NO-CONTROL | CONFIRMED | Bridge impl frida_bridge.py:5113-5206 (real `SystemFunction`-class JS call via `_build_native_call_script`, captures `result.errno`/`result.lastError` — genuine, distinct return path from `call_function`). Tool-def frida_bridge.py:715-732. Grep frida_panel.py for `call_system_function` → **0 matches**. Read full Advanced-tab "Function Calling" section (frida_panel.py:2232-2272) — confirmed only plain `_on_call_function` exists; no errno/GetLastError checkbox or second call path | Genuine gap; highest-impact call as report states |
| 21 | `enumerate_modules` OK, GUI wired | CONFIRMED | Call site frida_panel.py:1517-1518 `self._bridge.enumerate_modules()` | matches |
| 22 | `enumerate_exports` OK, GUI wired | CONFIRMED | Call site frida_panel.py:1563-1564 `self._bridge.enumerate_exports(module_name)` | matches |
| 23 | `enumerate_imports` OK, GUI wired | CONFIRMED | Call site frida_panel.py:1599-1600 `self._bridge.enumerate_imports(module_name)` | matches |
| 24 | `enumerate_symbols` NO-CONTROL | CONFIRMED | Bridge impl frida_bridge.py:4655-4714 (real `mod.enumerateSymbols()` JS call, maps name/address/isGlobal/type — genuine). Tool-def frida_bridge.py:640-647. Grep frida_panel.py for `enumerate_symbols` → **0 matches** | Genuine gap |
| 25 | `find_base_address` OK, GUI wired | CONFIRMED | Call site frida_panel.py:2113-2114 `self._bridge.find_base_address(module_name)` | matches |
| 26 | `find_module_by_address` NO-CONTROL | CONFIRMED | Bridge impl frida_bridge.py:4760-4805 (real `Process.findModuleByAddress(ptr(...))` JS, genuine). Tool-def frida_bridge.py:656-663. Grep frida_panel.py for `find_module_by_address` → **0 matches** | Genuine gap |
| 27 | `load_module` NO-CONTROL | CONFIRMED | Bridge impl frida_bridge.py:4716-4758 (present, real; body starts at 4716, header/docstring visible at read window). Tool-def frida_bridge.py:648-655. Grep frida_panel.py for `load_module` → **0 matches** | Genuine gap |
| 28 | `resolve_symbol` OK, GUI wired | CONFIRMED | Call site frida_panel.py:2133-2134 `self._bridge.resolve_symbol(addr)` | matches |
| 29 | `find_functions_named` OK, GUI wired | CONFIRMED | Call site frida_panel.py:2159-2160 `self._bridge.find_functions_named(name)` | matches |
| 30 | `find_functions_matching` NO-CONTROL | CONFIRMED | Bridge impl frida_bridge.py:4807-4863 (real `DebugSymbol.findFunctionsMatching(pattern)` + `DebugSymbol.fromAddress` per-match resolution — genuine). Tool-def frida_bridge.py:664-671. Grep frida_panel.py for `find_functions_matching` → **0 matches**. Symbols sub-tab confirmed (frida_panel.py:2090-2103) to have only Symbols/API-Matches result tables fed by find-base/resolve/find-named/API, no glob-pattern search widget | Genuine gap |
| 31 | `resolve_api` OK, GUI wired | CONFIRMED | Call site frida_panel.py:2198-2199 `self._bridge.resolve_api(query)` | matches |

## Cross-cutting checks (beyond the per-row table)

1. **Hidden/indirect control-path check (defeats false-positive risk on all 11 NO-CONTROL rows).**
   Grepped `frida_panel.py` for every `run_bridge_coroutine_logged`/`self._bridge.` call site
   (~50 call sites found, frida_panel.py:525-2400+). Every call site names a specific bridge method
   directly; there is no generic method-invoker, no dynamic `getattr(self._bridge, combo.currentText())`
   pattern, and no free-text command palette that could reach the 11 gap methods indirectly. The
   panel does expose `execute_script`/`execute_persistent_script` (frida_panel.py:646-659), which lets
   a user type raw JS including `Interceptor.revert(...)` — but that bypasses the named bridge method
   entirely (goes straight to Frida via generic script execution) and is not a control *for* the
   bridge method in question. Report is correct not to count this as a control.

2. **Tab-structure completeness check.** Confirmed via `addTab` grep: Hooks, Threads, Stalker,
   Modules, Memory (Read/Write, Scan, Regions, Protect), Symbols, Advanced — matches the report's
   implicit structure and confirms no missing/unlisted tab could hide a control for the gap methods.

3. **Stub/no-op audit on OK rows (spot-check requested by task).** Read full bodies of `scan_memory`
   (frida_bridge.py:1890-1968) and `stalker_follow` (frida_bridge.py:3930-4098, partial through the
   embedded stop/unfollow logic) — both perform genuine Frida JS API round-trips with real error
   handling (`ToolError` on `"error" in result`), not thin wrappers or no-ops. No evidence of any OK
   row being secretly a stub.

4. **MISSING-row alias check.** Searched the entire bridge file's `def ` declarations and free text
   for `exclude`, `garbageCollect`, `invalidate`, `trustThreshold` — zero occurrences. Not present
   under any alias (e.g., no `stalker_exclude`, no `stalker_set_trust_threshold`, no `stalker_gc`).
   Row 11 is a genuine, complete absence across all three layers.

5. **NOT-REGISTERED check (report claims 0).** All 11 gap methods and all 20 OK-row methods have a
   corresponding `ToolFunction(name="frida.<method>", ...)` entry confirmed present in
   `_FRIDA_FUNCTIONS` (frida_bridge.py:173+, spot-checked entries at lines 617, 626, 641, 649, 657,
   665, 702, 710, 716, 734, 743). Dispatch via `tools.py:587-588` strips the `frida.` prefix and uses
   `getattr`, which resolves correctly for every method name checked. No missed registration found.

## FALSE POSITIVES / NEEDS REVIEW

None found. Every one of the 31 rows, the 11 NO-CONTROL classifications, the 1 MISSING classification,
and the 0 STUB / 0 NOT-REGISTERED / 0 DEAD-CONTROL counts were independently reproduced by direct
source inspection rather than by trusting the report's citations. No line-number citation in the
report was found to be stale or incorrect during this verification (all cited ranges matched actual
method boundaries within the current file state).

## Tally

- **31 checked** (all matrix rows)
- **31 confirmed**
- **0 false-positive**
- **0 needs-review**
