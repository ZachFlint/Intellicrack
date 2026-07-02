# Frida Instrumentation Slice — Bridge Completeness Audit

Scope: Interceptor, Stalker, Memory operations, NativeFunction/NativePointer (call/script-gen side),
Module & export/import/symbol enumeration. Excludes spawn/attach/resume/detach, device enumeration,
session management, script loading/compilation (generic), RPC exports, message dispatch (covered by
another slice).

Files audited:
- Bridge: `src/intellicrack/bridges/frida_bridge.py` (7146 lines)
- Dispatch: `src/intellicrack/core/tools.py` (`ToolRegistry.execute_tool_call`, lines 551-620)
- GUI: `src/intellicrack/ui/panels/frida_panel.py` (2505 lines) — single file, no subpackage found via Glob

Dispatch mechanism confirmed: `tools.py:587-588` strips the `frida.` prefix from the function name
(`function_name.split(".", maxsplit=1)[-1]`) and calls `getattr(bridge, attr_name)`. Since every
in-scope bridge method name matches its `_td`/`ToolFunction` suffix exactly, all registered functions
dispatch correctly (no NOT-REGISTERED findings in this slice).

## Coverage Matrix

| # | Native feature (Frida JS API) | Bridge method | Tool-def | GUI control |
|---|---|---|---|---|
| 1 | `Interceptor.attach` (onEnter/onLeave) | OK — `hook_function` frida_bridge.py:2173-2269 | OK — `frida.hook_function` frida_bridge.py:234 | OK — "Add" button `_add_hook_btn` frida_panel.py:302,304 → `_on_add_hook` → frida_panel.py:783-792 |
| 2 | `Interceptor.replace` / `replaceFast` | OK — `replace_function` frida_bridge.py:3371-3460 | OK — `frida.replace_function` frida_bridge.py:440 | OK — "Replace" button `_replace_fn_btn` frida_panel.py:319 → `_on_replace_function` → frida_panel.py:1379-1389 |
| 3 | `Interceptor.revert` | OK — `revert_hook` frida_bridge.py:5054-5086 | OK — `frida.revert_hook` frida_bridge.py:702 | NO-CONTROL — no widget/action anywhere in frida_panel.py references `revert_hook` |
| 4 | `Interceptor.flush` | OK — `flush_interceptor` frida_bridge.py:5088-5111 | OK — `frida.flush_interceptor` frida_bridge.py:710 | NO-CONTROL — no reference in frida_panel.py |
| 5 | Hook removal / registry (bridge-side, no direct native call but pairs with attach) | OK — `remove_hook` frida_bridge.py:2271-2288, `get_hooks` frida_bridge.py:2290-2299 | OK — `frida.remove_hook` :259, `frida.get_hooks` :375 | OK — "Remove" `_remove_hook_btn` :307,309 → `_on_remove_hook` → :859-868; "Refresh" `_refresh_hooks_btn` :322-324 → `_on_refresh_hooks` → :1397-1404 |
| 6 | Return-value interception (`retval.replace`, built on Interceptor) | OK — `intercept_return` frida_bridge.py:2387-2409 | OK — `frida.intercept_return` frida_bridge.py:322 | OK — "Intercept Return" `_intercept_ret_btn` frida_panel.py:314 → `_on_intercept_return` → :1347-1359 |
| 7 | `Stalker.follow` (call/exec/block events, `Stalker.parse`) | OK — `stalker_follow` frida_bridge.py:3930-4098 | OK — `frida.stalker_follow` frida_bridge.py:472 | OK — "Start Trace" `_stalker_start_btn` frida_panel.py:437,439 → `_on_stalker_start` → :1107-1118 |
| 8 | `Stalker.unfollow` / `Stalker.flush` (retrieve trace) | OK — `stalker_unfollow` frida_bridge.py:4100-4139 | OK — `frida.stalker_unfollow` frida_bridge.py:499 | OK — "Stop Trace" `_stalker_stop_btn` frida_panel.py:442,445 → `_on_stalker_stop` → :1157-1164 |
| 9 | `Stalker.addCallProbe` | OK — `stalker_add_call_probe` frida_bridge.py:5208-5265 | OK — `frida.stalker_add_call_probe` frida_bridge.py:734 | NO-CONTROL — no widget/action in frida_panel.py |
| 10 | `Stalker.removeCallProbe` | OK — `stalker_remove_call_probe` frida_bridge.py:5267-5282 | OK — `frida.stalker_remove_call_probe` frida_bridge.py:743 | NO-CONTROL — no widget/action in frida_panel.py |
| 11 | `Stalker.exclude`, `garbageCollect`, `invalidate`, `trustThreshold` | MISSING — no bridge method found for any of these | MISSING | NO-CONTROL |
| 12 | `Memory.scanSync` (used) / `Memory.scan` (async, not used) | OK — `scan_memory` frida_bridge.py:1890-1968 (uses `Memory.scanSync` per-range at :1944) | OK — `frida.scan_memory` frida_bridge.py:290 | OK — "Scan" `_mem_scan_btn` frida_panel.py:1727 → `_on_scan_memory` → :1882+ |
| 13 | `NativePointer.readByteArray` / `writeByteArray` (via generated script) | OK — `read_memory` frida_bridge.py:1748-1791, `write_memory` frida_bridge.py:1793-1825 | OK — `frida.read_memory` :267, `frida.write_memory` :276 | OK — "Read" `_mem_read_btn` :1671 → `_on_read_memory` → :1800+; "Write" `_mem_write_btn` :1691 → `_on_write_memory` → :1833+ |
| 14 | `Process.enumerateRanges` (memory map) | OK — `get_memory_regions` frida_bridge.py:1827-1888 | OK — `frida.get_memory_regions` frida_bridge.py:354 | OK — "List Regions" `_mem_regions_btn` :1754 → `_on_list_regions` → :1944 call site |
| 15 | `Memory.protect` | OK — `protect_memory` frida_bridge.py:3079-3137 | OK — `frida.protect_memory` frida_bridge.py:381 | OK — "Set Protection" `_mem_prot_set_btn` :1791 → `_on_set_protection` → :1998 call site |
| 16 | `Memory.alloc` | OK — `allocate_memory` frida_bridge.py:3009-3077 | OK — `frida.allocate_memory` frida_bridge.py:367 | OK — "Alloc" `_mem_alloc_btn` :1703 → `_on_allocate_memory` → :1872 call site |
| 17 | `Memory.patchCode` | OK — `patch_code` frida_bridge.py:4544-4584 (writes bytes inside `Memory.patchCode` callback, flushes I-cache implicitly) | OK — `frida.patch_code` frida_bridge.py:617 | NO-CONTROL — no widget/action in frida_panel.py |
| 18 | `Memory.allocUtf8String` / `allocAnsiString` / `allocUtf16String` | OK — `allocate_string` frida_bridge.py:4586-4653 (dispatches by `encoding` param to the three JS alloc functions) | OK — `frida.allocate_string` frida_bridge.py:626 | NO-CONTROL — no widget/action in frida_panel.py |
| 19 | `NativeFunction` construction + invocation (typed args/return) | OK — `call_function` frida_bridge.py:2411-2485 | OK — `frida.call_function` frida_bridge.py:336 | OK — "Call" `_adv_call_btn` frida_panel.py:2250,2252 → `_on_call_function` → :2359 call site |
| 20 | `SystemFunction`-style call capturing errno/GetLastError (native-call variant) | OK — `call_system_function` frida_bridge.py:5113-5206 | OK — `frida.call_system_function` frida_bridge.py:716 | NO-CONTROL — no widget/action in frida_panel.py |
| 21 | `Process.enumerateModules` | OK — `enumerate_modules` frida_bridge.py:2051-2105 | OK — `frida.enumerate_modules` frida_bridge.py:206 | OK — "Refresh" `_refresh_modules_btn` frida_panel.py:1465 → `_on_refresh_modules` → :1518 call site |
| 22 | `Module.enumerateExports` / `Process.findModuleByName` | OK — `enumerate_exports` frida_bridge.py:2107-2171 | OK — `frida.enumerate_exports` frida_bridge.py:212 | OK — "Exports" `_exports_btn` frida_panel.py:1485 → `_on_show_exports` → :1564 call site |
| 23 | `Module.enumerateImports` | OK — `enumerate_imports` frida_bridge.py:2877-2944 | OK — `frida.enumerate_imports` frida_bridge.py:220 | OK — "Imports" `_imports_btn` frida_panel.py:1489 → `_on_show_imports` → :1600 call site |
| 24 | `Module.enumerateSymbols` | OK — `enumerate_symbols` frida_bridge.py:4655-4714 | OK — `frida.enumerate_symbols` frida_bridge.py:641 | NO-CONTROL — no widget/action in frida_panel.py |
| 25 | `Process.findModuleByName` → `mod.base` (base-address lookup) | OK — `find_base_address` frida_bridge.py:3139-3177 | OK — `frida.find_base_address` frida_bridge.py:396 | OK — "Find Base" `_sym_find_base_btn` frida_panel.py:2049,2051 → `_on_find_base` → :2114 call site |
| 26 | `Process.findModuleByAddress` | OK — `find_module_by_address` frida_bridge.py:4760-4805 | OK — `frida.find_module_by_address` frida_bridge.py:657 | NO-CONTROL — no widget/action in frida_panel.py |
| 27 | `Module.load` | OK — `load_module` frida_bridge.py:4716-4758 | OK — `frida.load_module` frida_bridge.py:649 | NO-CONTROL — no widget/action in frida_panel.py |
| 28 | `DebugSymbol.fromAddress` (symbol resolution) | OK — `resolve_symbol` frida_bridge.py:3179-3243 | OK — `frida.resolve_symbol` frida_bridge.py:404 | OK — "Resolve" `_sym_resolve_btn` frida_panel.py:2064 → `_on_resolve_symbol` → :2134 call site |
| 29 | `DebugSymbol.findFunctionsNamed` | OK — `find_functions_named` frida_bridge.py:3245-3306 | OK — `frida.find_functions_named` frida_bridge.py:412 | OK — "Find" `_sym_find_btn` frida_panel.py:2075 → `_on_find_functions` → :2160 call site |
| 30 | `DebugSymbol.findFunctionsMatching` | OK — `find_functions_matching` frida_bridge.py:4807-4863 | OK — `frida.find_functions_matching` frida_bridge.py:665 | NO-CONTROL — no widget/action in frida_panel.py |
| 31 | `ApiResolver` (`Module.findExportByName` equivalent via `exports:*!Name`, also objc/swift) | OK — `resolve_api` frida_bridge.py:3308-3369 | OK — `frida.resolve_api` frida_bridge.py:420 | OK — "API" `_sym_api_btn` frida_panel.py:2086 → `_on_resolve_api` → :2199 call site |

## Coverage Summary

- **19 of 31 native features fully ported (all 3 layers OK)** — Interceptor.attach/replace, hook lifecycle, intercept-return, Stalker.follow/unfollow, Memory read/write/scan/regions/protect/alloc, NativeFunction call, module/export/import enumeration, base-address/symbol/function-name/API resolution.
- Gap counts by type (within this slice's 31-row denominator; 19 OK + 11 NO-CONTROL + 1 MISSING = 31):
  - **MISSING** (no bridge method at all): 1 — row 11 (`Stalker.exclude`/`garbageCollect`/`invalidate`/`trustThreshold`, treated as a single grouped row)
  - **STUB**: 0 — every implemented method performs real Frida JS-bridge round trips with error handling, no stub/placeholder/no-op bodies found
  - **NOT-REGISTERED**: 0 — every implemented bridge method in scope has a matching `ToolFunction` entry in `_FRIDA_FUNCTIONS` and dispatches via `tools.py` getattr routing
  - **NO-CONTROL**: 11 — row 3 (`revert_hook`), row 4 (`flush_interceptor`), row 9 (`stalker_add_call_probe`), row 10 (`stalker_remove_call_probe`), row 17 (`patch_code`), row 18 (`allocate_string`), row 20 (`call_system_function`), row 24 (`enumerate_symbols`), row 26 (`find_module_by_address`), row 27 (`load_module`), row 30 (`find_functions_matching`) — bridge + tool-def both OK, but no widget/action in frida_panel.py reaches these methods
  - **DEAD-CONTROL**: 0 — every widget found in frida_panel.py that references a Frida bridge call does reach the bridge via `run_bridge_coroutine_logged`; no broken/orphaned wiring found

## Orphan / Broken-Wiring Check

- No bridge method within scope lacks a corresponding native Frida API feature — all 31 matrix rows map to real `frida.re/docs/javascript-api/` surface.
- No GUI control in frida_panel.py calls a bridge method name that doesn't exist — every `self._bridge.<method>(` call site (hook_function, remove_hook, stalker_follow, stalker_unfollow, intercept_return, replace_function, get_hooks, enumerate_modules, enumerate_exports, enumerate_imports, read_memory, write_memory, allocate_memory, scan_memory, get_memory_regions, protect_memory, find_base_address, resolve_symbol, find_functions_named, resolve_api, call_function) resolves to a real, implemented bridge method. Zero DEAD-CONTROL findings.

## Prioritized Gap List

1. **`call_system_function` (row 20) — GUI layer only.** Bridge and tool-def are complete (frida_bridge.py:5113-5206, `frida.call_system_function` at :716) but the "Advanced" tab only exposes plain `call_function` (frida_panel.py:2250-2256). This is the highest-impact gap: errno/GetLastError capture is valuable for Windows API instrumentation workflows and the panel already has a call-function UI section that could add a "capture errno" checkbox routing to this method. Fix location: `src/intellicrack/ui/panels/frida_panel.py` (extend the Advanced/native-call section around line 2240-2272).
2. **`patch_code` / `revert_hook` / `flush_interceptor` (rows 3, 4, 17) — GUI layer only.** These are core Interceptor/code-patching primitives with zero GUI surface, meaning users can only revert or patch via raw `execute_script`. Fix location: `src/intellicrack/ui/panels/frida_panel.py`, likely a new "Interceptor" sub-section near the existing hooks table (around line 300-330) with Revert/Flush buttons, and a Memory sub-section addition near the existing patch/write controls (around line 1671-1800) for `patch_code`.
3. **`stalker_add_call_probe` / `stalker_remove_call_probe` (rows 9, 10) — GUI layer only.** The Stalker tab (frida_panel.py:430-450) only has Start/Stop trace controls; call-probe management (a distinct Stalker feature from full tracing) has no UI. Fix location: `src/intellicrack/ui/panels/frida_panel.py`, extend the Stalker tab with a probe list + add/remove controls.
4. **`enumerate_symbols` / `find_module_by_address` / `find_functions_matching` (rows 24, 26, 30) — GUI layer only.** The Symbols sub-tab (frida_panel.py:2040-2090) covers find-base/resolve/find-named/API but omits full-module symbol dump, reverse address→module lookup, and glob-pattern function search. Fix location: same Symbols sub-tab, add three more result actions.
5. **`allocate_string` (row 18) — GUI layer only.** Memory tab has read/write/alloc/scan/regions/protect but no string-allocation helper, despite the bridge supporting utf8/ansi/utf16 encodings. Fix location: `src/intellicrack/ui/panels/frida_panel.py` Memory tab (near line 1703, alongside the numeric `_mem_alloc_btn`).
6. **`Stalker.exclude` / `garbageCollect` / `invalidate` / `trustThreshold` (row 11) — all 3 layers missing.** No bridge method implements these; lowest priority since `stalker_follow`'s auto-managed event batching/GC already covers the common tracing workflow, but `trustThreshold` (tuning) and `exclude` (scoping out noisy modules) would improve large-target trace usability. Fix location: new bridge methods in `src/intellicrack/bridges/frida_bridge.py` (near the existing Stalker methods at line 3930-4139), new `ToolFunction` entries near line 472-511, and new GUI controls in the Stalker tab.
