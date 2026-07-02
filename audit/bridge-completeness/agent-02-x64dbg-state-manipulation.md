# x64dbg Bridge Completeness Audit — Slice 2: State & Manipulation

Scope: register read/write, memory read/write/search/map, modules, threads, call
stack, patches, comments/labels, script & command execution, plugin commands.
Explicitly excludes breakpoints/stepping/run/trace (a different slice), though
breakpoint-adjacent *state* configuration methods that live in this file
(`configure_breakpoint`, `set_dll_breakpoint`, `set_logging_breakpoint`) are
included because they are pure state-manipulation calls with no
stepping/running semantics of their own.

Files audited:
- Bridge: `src/intellicrack/bridges/x64dbg.py` (9224 lines)
- Dispatch: `src/intellicrack/core/tools.py` (`execute_tool_call`, lines 551-654)
- Capability gating: `src/intellicrack/bridges/base.py` (`TOOL_CAPABILITY_MAP`, lines 61-151)
- GUI panel: `src/intellicrack/ui/panels/x64dbg_panel.py` (2911 lines)

Dispatch mechanism confirmed: `ToolRegistry.execute_tool_call()` strips the
`x64dbg.` prefix from `function_name` and calls `getattr(bridge, attr_name)`
(core/tools.py:587-588). A `ToolFunction(name="x64dbg.X", ...)` entry only
makes `X` reachable via AI/orchestration if a bridge method literally named
`X` exists — the registry does no other name mapping. This bridge also
declares `BridgeCapabilities(supports_debugging=True, supports_dynamic_analysis=True,
supports_patching=True, supports_scripting=True, supports_memory_access=True, ...)`
at x64dbg.py:815-823, with **no** `supports_static_analysis`.

## Native ground truth (x64dbg feature surface, state & manipulation only)

Derived from x64dbg's command reference / plugin SDK (`_plugins.h`, GUI menus:
CPU tab register/memory panes, Symbols/Memory Map, Log, Patches window,
Comments/Labels/Bookmarks, Handles window, Script engine, Plugin manager) and
this bridge's own RPC surface (`_send_pipe_command` verbs):

1. Read general-purpose/flags/segment registers
2. Write/modify a register value
3. Read process memory
4. Write process memory
5. Allocate memory in target process
6. Free/release allocated memory
7. Enumerate memory regions / memory map
8. Byte-pattern memory scan (no wildcards)
9. Wildcard pattern search (`find_pattern`, x64dbg's "Find Pattern")
10. Dump a memory region to file
11. Enumerate loaded modules
12. Get module sections (PE section table)
13. Get module exports
14. Get module imports (IAT)
15. Get module entry point (AddressOfEntryPoint)
16. Get PE data directories for a module
17. Enumerate threads
18. Suspend a thread
19. Resume a thread
20. Switch active/focused thread
21. Rename a thread (SetThreadName)
22. Get call stack / stack trace
23. Get SEH exception handler chain
24. Read PEB (Process Environment Block)
25. Read TEB (Thread Environment Block)
26. Assemble an instruction to bytes (keystone-style, no write)
27. Patch/write an assembled instruction into memory (x64dbg's Assemble)
28. NOP a byte range
29. List applied patches (Patches window)
30. Restore/revert a single patch
31. Export patches to file
32. Set a label (name) at an address
33. Get/list labels
34. Set a comment at an address
35. Get/list comments
36. Add a watch expression (Watch window)
37. Remove a watch expression
38. List watch expressions/values
39. Configure breakpoint properties (condition/log/command/fast-resume)
40. Set a logging breakpoint (non-stopping "trace log")
41. Set a DLL load/unload breakpoint (Librarian)
42. Execute an arbitrary x64dbg command (command bar / `run_command`)
43. Evaluate an expression (x64dbg expression evaluator)
44. Get control-flow graph of a function
45. Find references to an address (xref)
46. Find string references in a module
47. Find intermodular calls in a module
48. Save the persistent analysis database
49. Load the persistent analysis database
50. Clear the persistent analysis database
51. Enumerate process handles
52. Close a process handle
53. Load an x64dbg script file
54. Run the loaded script
55. Execute a single script command
56. Abort the running script
57. Load a plugin
58. Unload a plugin
59. List loaded plugins
60. Get process info summary (PID/name/path/cmdline/PPID)

## Coverage matrix

| # | Native feature | Bridge method (file:line) | Tool-def | GUI control |
|---|---|---|---|---|
| 1 | Read registers | OK `get_registers` x64dbg.py:3526 | OK `x64dbg.get_registers` x64dbg.py:1134 | OK Registers tab, `_bridge.get_registers()` x64dbg_panel.py:1775 |
| 2 | Write register | OK `set_register` x64dbg.py:3622 | OK `x64dbg.set_register` x64dbg.py:1140 | OK Registers table edit → `_bridge.set_register(...)` x64dbg_panel.py:1627 |
| 3 | Read memory | OK `read_memory` x64dbg.py:3705 | OK `x64dbg.read_memory` x64dbg.py:1159 | OK Memory tab → `_bridge.read_memory(...)` x64dbg_panel.py:1686 |
| 4 | Write memory | OK `write_memory` x64dbg.py:3748 | OK `x64dbg.write_memory` x64dbg.py:1178 | OK Memory tab → `_bridge.write_memory(...)` x64dbg_panel.py:2672 |
| 5 | Allocate memory | OK `allocate_memory` x64dbg.py:3791 | OK `x64dbg.allocate_memory` x64dbg.py:1301 | OK Memory Map tab → `_bridge.allocate_memory(...)` x64dbg_panel.py:2528 |
| 6 | Free memory | OK `free_memory` x64dbg.py:3847 | OK `x64dbg.free_memory` x64dbg.py:1321 | OK Memory Map tab → `_bridge.free_memory(...)` x64dbg_panel.py:2557 |
| 7 | Memory regions/map | OK `get_memory_regions` x64dbg.py:3880 | OK `x64dbg.get_memory_regions` x64dbg.py:1372 | OK Memory Map tab → `_bridge.get_memory_regions()` x64dbg_panel.py:2453, 2905 |
| 8 | Byte-pattern scan | OK `scan_memory` x64dbg.py:4269 | OK `x64dbg.scan_memory` x64dbg.py:1353 | OK indirect — invoked internally by `find_pattern` (x64dbg.py:5289) which the Search tab calls; `scan_memory` itself has no direct GUI hook |
| 9 | Wildcard pattern search | OK `find_pattern` x64dbg.py:5256 | OK `x64dbg.find_pattern` x64dbg.py:1223 | OK Search tab → `_bridge.find_pattern(...)` x64dbg_panel.py:2296 |
| 10 | Dump memory to file | OK `dump_memory_to_file` x64dbg.py:6368 | OK `x64dbg.dump_memory_to_file` x64dbg.py:1485 | OK Memory tab + Memory Map row → `_bridge.dump_memory_to_file(...)` x64dbg_panel.py:2502, 2638 |
| 11 | Enumerate modules | OK `get_modules` x64dbg.py:5095 | OK `x64dbg.get_modules` x64dbg.py:1384 | OK Modules tab → `_bridge.get_modules()` x64dbg_panel.py:1929 |
| 12 | Module sections | OK `get_module_sections` x64dbg.py:6461 | OK `x64dbg.get_module_sections` x64dbg.py:1495 | OK Modules tab detail button → `_bridge.get_module_sections(...)` x64dbg_panel.py:1519 |
| 13 | Module exports | OK `get_module_exports` x64dbg.py:6623 | OK `x64dbg.get_module_exports` x64dbg.py:1503 | OK Modules tab detail button → `_bridge.get_module_exports(...)` x64dbg_panel.py:1563 |
| 14 | Module imports | OK `get_module_imports` x64dbg.py:6902 | OK `x64dbg.get_module_imports` x64dbg.py:1582 | **NO-CONTROL** — no imports button/table in Modules tab (only Sections/Exports buttons exist, x64dbg_panel.py:1502-1590) |
| 15 | Module entry point | OK `get_entry_point` x64dbg.py:6653 | OK `x64dbg.get_entry_point` x64dbg.py:1511 | **NO-CONTROL** — not referenced anywhere in panel |
| 16 | PE data directories | OK `get_pe_directories` x64dbg.py:7392 | OK `x64dbg.get_pe_directories` x64dbg.py:1743 | **NO-CONTROL** — not referenced anywhere in panel |
| 17 | Enumerate threads | OK `get_threads` x64dbg.py:5215 | OK `x64dbg.get_threads` x64dbg.py:1378 | OK Threads tab → `_bridge.get_threads()` x64dbg_panel.py:1960 |
| 18 | Suspend thread | OK `suspend_thread` x64dbg.py:7104 | OK `x64dbg.suspend_thread` x64dbg.py:1681 | OK Threads tab "Suspend" button → `_bridge.suspend_thread(...)` x64dbg_panel.py:2759 |
| 19 | Resume thread | OK `resume_thread` x64dbg.py:7162 | OK `x64dbg.resume_thread` x64dbg.py:1689 | OK Threads tab "Resume" button → `_bridge.resume_thread(...)` x64dbg_panel.py:2785 |
| 20 | Switch thread | OK `switch_thread` x64dbg.py:7218 | OK `x64dbg.switch_thread` x64dbg.py:1697 | OK Threads tab "Switch" button (`_switch_thread_btn`, x64dbg_panel.py:350) → `_bridge.switch_thread(...)` x64dbg_panel.py:2811 |
| 21 | Rename thread | OK `set_thread_name` x64dbg.py:7261 | OK `x64dbg.set_thread_name` x64dbg.py:1705 | **NO-CONTROL** — no rename control in Threads tab |
| 22 | Call stack / stack trace | OK `get_stack_trace` x64dbg.py:4172 | OK `x64dbg.get_stack_trace` x64dbg.py:1217 | OK Stack tab → `_bridge.get_stack_trace()` x64dbg_panel.py:1892 |
| 23 | SEH chain | OK `get_seh_chain` x64dbg.py:7318 | OK `x64dbg.get_seh_chain` x64dbg.py:1714 | **NO-CONTROL** — not referenced anywhere in panel |
| 24 | Read PEB | OK `read_peb` x64dbg.py:7339 | OK `x64dbg.read_peb` x64dbg.py:1720 | **NO-CONTROL** — not referenced anywhere in panel (only used internally by `detect_anti_debug`, x64dbg.py:8396) |
| 25 | Read TEB | OK `read_teb` x64dbg.py:7367 | OK `x64dbg.read_teb` x64dbg.py:1730 | **NO-CONTROL** — not referenced anywhere in panel |
| 26 | Assemble instruction (bytes only) | OK `assemble_at` x64dbg.py:4140 | OK `x64dbg.assemble_at` x64dbg.py:1334 | **NO-CONTROL** — Memory tab "Assemble" button calls `patch_instruction`, not `assemble_at` (x64dbg_panel.py:2702); `assemble_at` itself unreferenced |
| 27 | Patch instruction (assemble+write) | OK `patch_instruction` x64dbg.py:6770 | OK `x64dbg.patch_instruction` x64dbg.py:1564 | OK Memory tab "Assemble" → `_bridge.patch_instruction(...)` x64dbg_panel.py:2702 |
| 28 | NOP range | OK `nop_range` x64dbg.py:6817 | OK `x64dbg.nop_range` x64dbg.py:1573 | OK Memory tab "NOP" → `_bridge.nop_range(...)` x64dbg_panel.py:2732 |
| 29 | List patches | OK `get_patches` x64dbg.py:7048 | OK `x64dbg.get_patches` x64dbg.py:1659 | **NO-CONTROL** — no Patches tab/table exists in panel |
| 30 | Restore patch | OK `restore_patch` x64dbg.py:7069 | OK `x64dbg.restore_patch` x64dbg.py:1665 | **NO-CONTROL** — no Patches tab exists |
| 31 | Export patches | OK `export_patches` x64dbg.py:7091 | OK `x64dbg.export_patches` x64dbg.py:1673 | **NO-CONTROL** — no Patches tab exists |
| 32 | Set label | OK `set_label` x64dbg.py:6019 | OK `x64dbg.set_label` x64dbg.py:1424 | OK Annotations→Labels sub-tab "Set Label" → `_bridge.set_label(...)` x64dbg_panel.py:2407 |
| 33 | Get/list labels | OK `get_labels` x64dbg.py:6063 | OK `x64dbg.get_labels` x64dbg.py:1433 | **DEAD-CONTROL** — `_lbl_table` widget exists (x64dbg_panel.py:801-807) but is never populated; no code path calls `get_labels()` or inserts rows into it |
| 34 | Set comment | OK `set_comment` x64dbg.py:6097 | OK `x64dbg.set_comment` x64dbg.py:1442 | OK Annotations→Comments sub-tab "Set Comment" → `_bridge.set_comment(...)` x64dbg_panel.py:2437 |
| 35 | Get/list comments | OK `get_comments` x64dbg.py:6141 | OK `x64dbg.get_comments` x64dbg.py:1451 | **DEAD-CONTROL** — `_cmt_table` widget exists (x64dbg_panel.py:843-849) but is never populated; no code path calls `get_comments()` |
| 36 | Add watch expression | OK `add_watch` x64dbg.py:7416 | OK `x64dbg.add_watch` x64dbg.py:1751 | **NO-CONTROL** — no Watch-expression tab/widget exists (only Watchpoints, a different debugging feature, is present) |
| 37 | Remove watch expression | OK `remove_watch` x64dbg.py:7438 | OK `x64dbg.remove_watch` x64dbg.py:1759 | **NO-CONTROL** — same as above |
| 38 | List watch expressions | OK `get_watches` x64dbg.py:7460 | OK `x64dbg.get_watches` x64dbg.py:1767 | **NO-CONTROL** — same as above |
| 39 | Configure breakpoint props | OK `configure_breakpoint` x64dbg.py:7499 | OK `x64dbg.configure_breakpoint` x64dbg.py:1788 | **NO-CONTROL** — Breakpoints tab only exposes set/remove/enable/disable (x64dbg_panel.py:1337-1500); no condition/log/command/fast-resume controls |
| 40 | Logging breakpoint | OK `set_logging_breakpoint` x64dbg.py:7481 | OK `x64dbg.set_logging_breakpoint` x64dbg.py:1773 | **NO-CONTROL** — not referenced anywhere in panel |
| 41 | DLL load/unload breakpoint | OK `set_dll_breakpoint` x64dbg.py:7531 | OK `x64dbg.set_dll_breakpoint` x64dbg.py:1800 | **NO-CONTROL** — not referenced anywhere in panel |
| 42 | Execute raw command | OK `run_command` x64dbg.py:4387 | OK `x64dbg.run_command` x64dbg.py:1243 | OK Console tab → `_bridge.run_command(...)` x64dbg_panel.py:1731 |
| 43 | Evaluate expression | OK `evaluate_expression` x64dbg.py:4865 | OK `x64dbg.evaluate_expression` x64dbg.py:1614 | OK Eval row → `_bridge.evaluate_expression(...)` x64dbg_panel.py:2827 |
| 44 | Function CFG | OK `get_function_cfg` x64dbg.py:6971 | OK `x64dbg.get_function_cfg` x64dbg.py:1627 | **NO-CONTROL** — not referenced anywhere in panel |
| 45 | Find references (xref) | OK `find_references` x64dbg.py:6917 | OK `x64dbg.find_references` x64dbg.py:1590 | **NO-CONTROL** — not referenced anywhere in panel |
| 46 | Find string references | OK `find_string_references` x64dbg.py:6935 | OK `x64dbg.find_string_references` x64dbg.py:1598 | **NO-CONTROL** — not referenced anywhere in panel |
| 47 | Find intermodular calls | OK `find_intermodular_calls` x64dbg.py:6953 | OK `x64dbg.find_intermodular_calls` x64dbg.py:1606 | **NO-CONTROL** — not referenced anywhere in panel |
| 48 | Save database | OK `save_database` x64dbg.py:6987 | OK `x64dbg.save_database` x64dbg.py:1641 | OK toolbar/menu → `_bridge.save_database()` x64dbg_panel.py:2166 |
| 49 | Load database | OK `load_database` x64dbg.py:7010 | OK `x64dbg.load_database` x64dbg.py:1647 | OK toolbar/menu → `_bridge.load_database()` x64dbg_panel.py:2180 |
| 50 | Clear database | OK `clear_database` x64dbg.py:7029 | OK `x64dbg.clear_database` x64dbg.py:1653 | **NO-CONTROL** — not referenced anywhere in panel |
| 51 | Enumerate handles | OK `get_handles` x64dbg.py:8258 | OK `x64dbg.get_handles` x64dbg.py:1953 | **NO-CONTROL** — no Handles tab/widget exists |
| 52 | Close handle | OK `close_handle` x64dbg.py:8376 | OK `x64dbg.close_handle` x64dbg.py:1959 | **NO-CONTROL** — same as above |
| 53 | Load script | OK `script_load` x64dbg.py:7996 | OK `x64dbg.script_load` x64dbg.py:1903 | **NO-CONTROL** — no Script tab exists |
| 54 | Run script | OK `script_run` x64dbg.py:8037 | OK `x64dbg.script_run` x64dbg.py:1911 | **NO-CONTROL** — same |
| 55 | Script single command | OK `script_cmd` x64dbg.py:8073 | OK `x64dbg.script_cmd` x64dbg.py:1917 | **NO-CONTROL** — same |
| 56 | Abort script | OK `script_abort` x64dbg.py:8113 | OK `x64dbg.script_abort` x64dbg.py:1925 | **NO-CONTROL** — same |
| 57 | Load plugin | OK `plugin_load` x64dbg.py:8150 | OK `x64dbg.plugin_load` x64dbg.py:1931 | **NO-CONTROL** — no Plugin tab exists |
| 58 | Unload plugin | OK `plugin_unload` x64dbg.py:8194 | OK `x64dbg.plugin_unload` x64dbg.py:1939 | **NO-CONTROL** — same |
| 59 | List plugins | OK `plugin_list` x64dbg.py:8236 | OK `x64dbg.plugin_list` x64dbg.py:1947 | **NO-CONTROL** — same |
| 60 | Process info summary | OK `get_process_info` x64dbg.py:5223 | OK `x64dbg.get_process_info` x64dbg.py:1366 | OK Process Info tab → `_bridge.get_process_info()` x64dbg_panel.py:2572 |

## Orphan / defect note (outside the coverage denominator, flagged for correctness)

- **Broken tool-def dispatch**: `ToolFunction(name="x64dbg.disassemble", ...)`
  is registered at x64dbg.py:1197-1215, but no bridge method named
  `disassemble` exists — the real implementation is `disassemble_at`
  (x64dbg.py:4057). Because `execute_tool_call` does a bare
  `getattr(bridge, "disassemble")` (core/tools.py:587-588), any AI/orchestration
  call to `x64dbg.disassemble` raises `ToolError("unknown function")`. It is
  additionally blocked by capability gating: `TOOL_CAPABILITY_MAP["disassemble"]
  = "static_analysis"` (bridges/base.py:63) but `X64DbgBridge` never sets
  `supports_static_analysis=True` (x64dbg.py:815-823). The GUI is unaffected
  because it calls `disassemble_at` directly, bypassing the tool registry
  (x64dbg_panel.py:1823). This is technically part of "disassembly" rather
  than the state/manipulation slice, so it is not counted in the 60-feature
  matrix above, but it is a live, provable defect worth flagging since it
  lives in this bridge file and blocks a registered `_td`.

## Coverage summary

- **26 of 60** native state/manipulation features are fully ported (all three
  layers OK): #1-13, 17-20, 22, 27-28, 32, 34, 42-43, 48-49, 60.
- **Bridge layer**: 60/60 implemented, all confirmed real (not stubs) —
  every method reads/writes live process memory via `ReadProcessMemory`/
  `WriteProcessMemory`, calls `NtQuerySystemInformation`, sends pipe RPCs to
  the x64dbg plugin, or queues x64dbg script commands with genuine
  verification/readback logic (several methods, e.g. `script_load`,
  `plugin_load`, `set_thread_name`, explicitly document a prior "claims
  success without verifying" defect from `audit7.md F-0001` that has since
  been fixed with readback verification).
- **Tool-def layer**: 60/60 registered as `ToolFunction` entries and
  dispatchable via `getattr` (name matches method name in all 60 cases).
- **GUI layer breakdown**:
  - OK (wired): 26
  - NO-CONTROL (no widget/action at all): 32 — #14, 15, 16, 21, 23, 24, 25,
    26, 29, 30, 31, 36, 37, 38, 39, 40, 41, 44, 45, 46, 47, 50, 51, 52, 53,
    54, 55, 56, 57, 58, 59, plus `scan_memory` (#8) is only indirectly
    exercised through `find_pattern`
  - DEAD-CONTROL (widget exists, not wired): 2 — #33 (`get_labels` /
    `_lbl_table`), #35 (`get_comments` / `_cmt_table`)

Gap-type counts:
- MISSING (bridge): 0
- STUB (bridge): 0
- NOT-REGISTERED (tool-def): 0
- NO-CONTROL (GUI): 32 (33 counting `scan_memory`'s indirect-only reachability)
- DEAD-CONTROL (GUI): 2

## Prioritized gap list

1. **Patches window (list/restore/export) — highest impact.** `get_patches`,
   `restore_patch`, `export_patches` (x64dbg.py:7048, 7069, 7091) are fully
   implemented and registered but there is no Patches tab in
   `x64dbg_panel.py` — despite `patch_instruction`/`nop_range` being wired
   for *creating* patches, a user has no GUI way to see what's patched or
   revert a single patch (only "reload database" style workflows exist).
   Fix: add a "Patches" tab similar to the existing Breakpoints/Watchpoints
   tabs, host in `x64dbg_panel.py`, calling `get_patches()` on refresh,
   `restore_patch(address)` on a "Restore" button, `export_patches(path)` on
   an "Export" button (mirrors `_build_wp_tab` pattern at x64dbg_panel.py:600s).

2. **Labels/Comments tables are dead controls.** `_lbl_table` and
   `_cmt_table` (x64dbg_panel.py:801, 843) are built and added to the
   Annotations tab but never populated — `get_labels`/`get_comments`
   (x64dbg.py:6063, 6141) are implemented and registered yet completely
   unreachable from the GUI, so users can set labels/comments but never see
   the list they've created (short of scrolling the disassembly view
   outside this slice). Fix: call `get_labels(start, end)` /
   `get_comments(start, end)` on tab-show / after each successful
   `set_label`/`set_comment`, and populate `_lbl_table`/`_cmt_table` in
   `x64dbg_panel.py` (near `_on_set_label`/`_on_set_comment_btn`,
   x64dbg_panel.py:2388-2446).

3. **Broken `x64dbg.disassemble` tool-def dispatch.** Registered at
   x64dbg.py:1197 with no matching method (`disassemble_at` is the real
   name) — any AI/orchestration caller invoking the advertised
   `x64dbg.disassemble` function gets `ToolError("unknown function")` (and
   would additionally fail the `static_analysis` capability check since
   `X64DbgBridge` doesn't declare it). Fix: either rename the `ToolFunction`
   entry to `x64dbg.disassemble_at` and add `x64dbg.disassemble_at` to
   `TOOL_CAPABILITY_MAP`, or add a `disassemble` alias method on the bridge
   that forwards to `disassemble_at`. (Out of the 60-feature denominator for
   this slice, but lives in the audited file and is a genuine defect.)

4. **PEB/TEB/SEH inspection has no GUI surface.** `read_peb`, `read_teb`,
   `get_seh_chain` (x64dbg.py:7339, 7367, 7318) are real, useful
   anti-debug/exception-analysis primitives with zero GUI reachability —
   currently `read_peb` is only invoked internally by `detect_anti_debug`
   (x64dbg.py:8396), which itself also has no GUI control. Fix: add a
   "Process Structures" or extend the existing "Process Info" tab
   (x64dbg_panel.py:376) with PEB/TEB/SEH sub-views.

5. **Watch expressions, Handles, Script engine, Plugin manager — entire
   feature families with no GUI.** `add_watch`/`remove_watch`/`get_watches`,
   `get_handles`/`close_handle`, and all four `script_*`/three `plugin_*`
   methods are fully implemented, registered, and dispatchable, but none
   have any panel presence. These are lower priority than #1-2 individually
   but collectively represent 15 of the 32 NO-CONTROL gaps. Fix: lowest
   effort is to expose them via the existing Console tab's `run_command`
   pathway is insufficient for `script_*`/`plugin_*` since those methods add
   verification (`_query_script_error`, `_query_plugin_present`) that raw
   `run_command` does not perform — dedicated controls are needed to surface
   that verification to the user.

6. **Module Imports / Entry Point / PE Directories not exposed alongside
   Sections/Exports.** The Modules tab already has "Show Sections" and
   "Show Exports" buttons (x64dbg_panel.py:1502-1590) reusing
   `_mod_detail_table`; `get_module_imports` (x64dbg.py:6902),
   `get_entry_point` (x64dbg.py:6653), and `get_pe_directories`
   (x64dbg.py:7392) would fit the same pattern with one more button each.

7. **Thread rename and breakpoint-property configuration (`configure_breakpoint`,
   `set_logging_breakpoint`, `set_dll_breakpoint`) have no GUI.** Lower
   priority since the Console tab's `run_command` can reach the same
   underlying x64dbg commands manually, but the bridge methods add
   structured params and (for `set_thread_name`) verification that raw
   commands don't provide.
