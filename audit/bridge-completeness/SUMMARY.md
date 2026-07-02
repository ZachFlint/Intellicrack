# Bridge Completeness Audit — Cross-Tool Synthesis

Audit of Intellicrack's native tool-bridge port across three integration layers:
**L1 Bridge** (async method that does real work) · **L2 Tool-def/Dispatch**
(`_td(...)` registered + reachable via `core/tools.py` `getattr(bridge, fn)`) ·
**L3 GUI** (a reachable panel control invokes the method). A feature is *fully
ported* only when all three are present and correctly wired.

10 slices, one subagent each (model: sonnet). Per-slice detail in
`agent-01`…`agent-10` reports in this directory.

> **Verification note (2026-07-01):** every finding in this audit was
> independently adversarially re-checked by a second wave of 10 verifier agents.
> **Zero false positives were found** — no feature was wrongly flagged. Two
> per-slice tallies were corrected (slice 2: 26→27; slice 4: 12→10; slice 10:
> −1, P1 `list_processes` was counted fully-ported but has no GUI control) and
> are reflected below; the `frida.attach` bug was found to be *worse* than first
> reported. See `verify/VERIFICATION-SUMMARY.md` and the per-slice
> `verify/agent-NN-*-verification.md` reports.

## Headline

**307 of 492 native features fully ported across all three layers — 62.4%.**

The port is **deep but not wide**: Layer 1 (bridge) is essentially production-
complete everywhere (near-zero stubs), and Layer 2 (tool-def registration) is
complete for every tool except Frida and Sandbox/Process. **The overwhelming
majority of the 185-feature gap is Layer 3 — real, dispatchable bridge methods
with no GUI control to invoke them (~164 NO-CONTROL + 7 DEAD-CONTROL).** Many
of these are reachable by AI/orchestration tool-calls but invisible to a human
panel user.

## Cross-tool coverage

| Tool | Slices | Fully ported | % | Where the gap lives |
|---|---|---|---|---|
| **Hex editor** | 9 | 77 / 96 | **80.2%** | L3 (19 NO-CONTROL + 13 orphan-by-local-reimpl) |
| **Ghidra** | 5, 6 | 62 / 87 | **71.3%** | L3 (20) + 1 STUB, 2 MISSING, 1 correctness bug |
| **Process** | 10 (proc) | 46 / 66 | **69.7%** | L2 (unregistered) + L3 |
| **Sandbox** | 10 (sbx) | 21 / 30 | **70.0%** | L2 (unregistered) + L3 |
| **Frida** | 7, 8 | 29 / 51* | **56.9%** | L2 (4 unregistered) + L3 + 2 dispatch bugs |
| **x64dbg** | 1, 2 | 48 / 89 | **53.9%** | L3 (heavy) + 1 dispatch bug |
| **Cutter/Rizin** | 3, 4 | 24 / 73 | **32.9%** | L3 (heavy) + 1 correctness DEFECT |
| **TOTAL** | 1–10 | **307 / 492** | **62.4%** | — |

\* Frida slice 7 counts 10/20 native features. Combined Frida uses the
20-feature denominator. The externally-addressable view is 8/17 for slice 7 (the
verifier corrected 8/18 → 8/17: "kill process" is an internal-only primitive
that should be excluded like features 12/13), giving 27/48 = 56.3% combined.

### Per-slice breakdown

| # | Slice | Ported | Gap types |
|---|---|---|---|
| 1 | x64dbg — execution control | 21/29 | 6 NO-CTRL, 1 DEAD-CTRL, 1 MISSING (restart) |
| 2 | x64dbg — state & manipulation | 27/60 | 32 NO-CTRL, 2 DEAD-CTRL, **1 dispatch bug** |
| 3 | Cutter — static analysis | 14/26 | **2 DEFECT (swapped cmds)**, 9 NO-CTRL, 1 DEAD-CTRL |
| 4 | Cutter — dynamic & navigation | 10/47 | 37 NO-CTRL (L1/L2 100%) |
| 5 | Ghidra — code analysis | 34/47 | 13 NO-CTRL (incl. 1 orphan) |
| 6 | Ghidra — program model & scripting | 28/40 | 10 NO-CTRL, 2 MISSING, 1 STUB, **1 correctness bug** |
| 7 | Frida — lifecycle & scripting | 10/20 | 4 NOT-REG, 5 NO-CTRL, 1 MISSING, **1 param-dispatch bug** |
| 8 | Frida — instrumentation | 19/31 | 11 NO-CTRL, 1 MISSING |
| 9 | Hex editor | 77/96 | 19 NO-CTRL + 13 orphan-by-local-reimpl; **1 wrong-bridge wiring** |
| 10 | Sandbox + Process | 67/96 | 13 NOT-REG, 22 NO-CTRL, 3 DEAD-CTRL |

## Top gaps overall, ranked by impact

### Tier 1 — Correctness defects (real bugs, not coverage; fix first)

1. **Cutter relocations/resources display swapped data** — `get_relocations`
   sends rizin `iRj` and `get_resources` sends `irj`, but upstream is
   `ir`=relocations / `iR`=resources. The two shipping GUI tabs each render the
   other feature's data. Two one-character edits at `bridges/cutter.py:2739` and
   `:2773`. *(agent-03)*
2. **`x64dbg.disassemble` tool-def is undispatchable** — registered name
   (`x64dbg.py:1197`) doesn't match the real method `disassemble_at`
   (`x64dbg.py:4057`), so AI/orchestration calls fail with unknown-function.
   *(agent-02)*
3. **`frida.attach` param-dispatch mismatch** — tool-def advertises a
   name-or-PID `target` but dispatches to `attach(pid: int)` only; a call with a
   process name raises TypeError (`frida_bridge.py:184-192` vs `:1356`).
   *(agent-07)*
4. **Ghidra `add_comment` silently downgrades REPEATABLE comments** — the
   `comment_map` covers only EOL/PRE/POST/PLATE, so `comment_type="REPEATABLE"`
   silently writes an EOL comment (`ghidra.py:3017-3023`); the read side supports
   all five types. *(agent-06)*
5. **Hex-editor sandbox save/test wired to the wrong bridge** — the panel's
   "Save to Sandbox"/"Test in Sandbox" buttons (`ui/panels/hex_editor/sandbox.py`)
   call a generic `SandboxBridge` directly instead of `hex_editor.py`'s own
   `save_to_sandbox`/`test_in_sandbox`, which are strictly safer (auto-provision +
   auto-cleanup sandbox instances, handle unsaved documents). The GUI uses the
   weaker path — a latent regression risk, not a hard failure. *(agent-09)*

### Tier 2 — Whole-capability GUI blackouts (working bridge + tool-def, zero GUI)

5. **Cutter has no debugger UI** — all 15 native debug ops (attach/detach,
   breakpoints, stepping, registers, memory, threads, modules) are implemented
   and registered but unreachable except via the raw command console.
   *(agent-04)*
6. **x64dbg has no Patches window** — `get_patches`/`restore_patch`/
   `export_patches` (`x64dbg.py:7048-7091`) are complete; users can create
   patches but can never list, revert, or export them. Labels/Comments tables
   are DEAD-CONTROL (built, never populated). *(agent-02)*
7. **Hex editor has no Search-and-Replace** — `replace_bytes`
   (`hex_editor.py:5329`) is fully implemented; the Search tab offers
   Hex/Text/Regex/Numeric search with no replace affordance — a core
   professional-hex-editor feature. *(agent-09)*
8. **Sandbox VM/environment config unreachable** — timeout/network/memory
   config has full bridge + tool-def support but `sandbox_panel.py` exposes only
   a type combo box. *(agent-10)*
9. **Cutter project/session management + advanced search have no GUI** —
   save/open/list project and 7 search/compare variants (byte/wildcard/asm/
   crypto/magic/value, compare bytes/disasm) are implemented, unreachable.
   *(agent-04)*
10. **Ghidra editing surfaces missing** — Data Type Manager (create enum/union/
    typedef), Program Tree (no GUI at all), Bookmarks delete, and reference-table
    editing are all bridge-complete but GUI-absent. *(agent-05, agent-06)*

### Tier 3 — Missing bridge capability (L1 absent)

11. **x64dbg "restart debuggee"** — native Ctrl+F2 restart-current-target has no
    equivalent at any layer; only full `load()` re-init exists. *(agent-01)*
12. **Frida/Ghidra scattered MISSING** — a handful of L1 gaps (Frida lifecycle 1,
    Frida instrumentation 1, Ghidra program-model 2, plus 1 Ghidra STUB).
    *(agent-06, 07, 08)*

## Cross-cutting patterns

1. **Layer 3 is the systemic bottleneck.** ~164 of 185 gaps are NO-CONTROL:
   real, registered bridge methods with no panel widget. Bridges were ported far
   ahead of the GUI. The AI-orchestration surface is much more complete than the
   human-GUI surface — for x64dbg, Cutter, and Sandbox/Process, large capability
   blocks are only reachable by tool-call.
2. **Layer 1 is production-grade.** Across all 10 slices, near-zero stubs were
   found (1 STUB total, in Ghidra). Several bridges actively verify that commands
   took effect against live debugger/plugin state (x64dbg slices note prior
   "claims success without verifying" defects already remediated).
3. **Layer 2 is complete except Frida and Sandbox/Process.** Only those two
   tools have NOT-REGISTERED methods (Frida 4: `attach_by_name`, `unload_script`,
   `unload_all_scripts`, `execute_persistent_script`; Sandbox/Process 13,
   including `sandbox.stop`, `stop_pcap`, and ~10 process primitives like
   `decommit_memory`, `duplicate_token`, `remove_privilege`) — real methods
   invisible to AI orchestration.
4. **Dispatch/parameter mismatches cluster at the L2 boundary.** Two tool-defs
   point at the wrong thing (`x64dbg.disassemble` name mismatch, `frida.attach`
   param-type mismatch) — silent until called.
5. **Orphan methods exist but are benign.** A few real methods duplicate a
   registered sibling (Ghidra `get_call_graph` vs the wired `get_call_tree`;
   several Sandbox/Process orphans) — code-hygiene, not completeness gaps.
6. **GUI-reimplements-the-bridge drift (hex editor).** 13 hex-editor bridge
   methods (`base_convert`, `generate_structure_bookmarks`, `auto_detect_pattern`,
   `toggle_bit`, `list_process_regions`, signature scans, …) are bypassed by a
   parallel *local* GUI reimplementation instead of being invoked through the
   bridge. The feature works today, but bridge and GUI can silently diverge —
   the same class of risk as the sandbox wrong-bridge wiring above. This is
   distinct from NO-CONTROL and is why the hex editor's fully-wired count is
   lower than a pure widget-inventory would suggest.

## Suggested remediation order

1. Fix the 4 Tier-1 correctness/dispatch bugs (tiny diffs, user-visible /
   orchestration-breaking).
2. Register the 17 NOT-REGISTERED Frida + Sandbox/Process methods (L2 — makes
   them AI-reachable immediately).
3. Build the highest-value missing GUI: Cutter debugger, x64dbg Patches window,
   Hex-editor search-and-replace, Sandbox config (L3).
4. Add the missing L1 capabilities (x64dbg restart, remaining MISSING/STUB).
