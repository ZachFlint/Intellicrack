# Bridge Completeness Audit — Verification Synthesis

A second wave of 10 adversarial verifier agents (model: sonnet) independently
re-checked every finding in the 10 original audit reports against the actual
source code. Each verifier was instructed to actively *refute* every finding —
to hunt for a missed GUI control behind a NO-CONTROL call, a real implementation
behind a STUB/MISSING call, an existing registration behind a NOT-REGISTERED
call, and to reproduce every correctness-defect claim end-to-end (including
fetching rizin's authoritative command reference). Per-slice detail in
`agent-01`…`agent-10`-verification reports in this directory.

## Headline

**Zero false positives across all 10 slices.** Every *gap/bug finding* that was
deep-checked held up. No feature was wrongly flagged as a gap; no claimed bug
was refuted. Several findings were *understated* — real but worse than the
original report said. The only correction in the opposite direction is an
over-count: one row (slice 10, P1 `list_processes`) was counted as fully-ported
but is actually a NO-CONTROL at the GUI layer per the report's own matrix cell —
found during the orchestrator's review of V-10's residual rows.

| Verifier | Slice | Checked | Confirmed | False-pos | Needs-review |
|---|---|---|---|---|---|
| V-01 | x64dbg exec control | 29 | 29 | 0 | 0 |
| V-02 | x64dbg state & manip | 63 | 62 | 0 | 1 |
| V-03 | Cutter static | 26 | 26 | 0 | 0 |
| V-04 | Cutter dynamic & nav | 47 | 46 | 0 | 1 |
| V-05 | Ghidra code analysis | 47 | 47 | 0 | 0 |
| V-06 | Ghidra program model | 41 | 40 | 0 | 1 |
| V-07 | Frida lifecycle | 26 | 24 | 0 | 2 |
| V-08 | Frida instrumentation | 31 | 31 | 0 | 0 |
| V-09 | Hex editor | 22 | 22 | 0 | 1 |
| V-10 | Sandbox + Process | 77* | 77 | 0 | 19 |
| **Total** | — | **409** | **404** | **0** | **25** |

\* V-10 deep-checked 77 of 96; the remaining 19 are "OK" rows following an
already-verified wiring pattern, marked needs-review only as unchecked, not
suspected wrong.

## The five correctness/dispatch bugs — all CONFIRMED

1. **Cutter relocations/resources swap** — CONFIRMED with external ground truth.
   V-03 fetched rizin's own `librz/core/cmd_descs/cmd_info.yaml` from GitHub:
   `ir`="List relocations", `iR`="List Resources". The bridge sends `iRj` for
   `get_relocations` (`cutter.py:2739`) and `irj` for `get_resources`
   (`cutter.py:2773`) — genuinely inverted; both GUI tabs show the other's data.
2. **`x64dbg.disassemble` undispatchable** — CONFIRMED. Tool-def `x64dbg.py:1197`
   has no matching method; only `disassemble_at` exists (`:4057`). `getattr(
   bridge, "disassemble", None)` returns None → `ToolError` on call.
3. **`frida.attach` param mismatch — CONFIRMED and WORSE than reported.** The
   real signature is `attach(self, pid: int, *, cancellable_id=None)` — there is
   **no `target` parameter at all**. Since dispatch calls `method(**arguments)`
   and the tool-def's only param is `target`, *every* schema-built call raises
   `TypeError: attach() got an unexpected keyword argument 'target'` —
   unconditionally, even for a numeric PID, not merely for name input as the
   original report implied.
4. **Ghidra `add_comment` REPEATABLE downgrade** — CONFIRMED line-by-line.
   `comment_map` (`ghidra.py:3017-3022`) covers only EOL/PRE/POST/PLATE;
   `.get(comment_type, "CodeUnit.EOL_COMMENT")` (`:3023`) silently downgrades a
   valid `REPEATABLE` to an EOL write. Read side supports all 5 types; the GUI
   combo only offers 4, so the bug is reachable only via the AI/tool-def path.
5. **Hex-editor wrong-bridge sandbox wiring** — CONFIRMED. `sandbox.py:135-249`
   calls `SandboxBridge.copy_to`/`.execute` directly, bypassing the hex-editor's
   own `save_to_sandbox`/`test_in_sandbox`, which alone have auto-provisioning,
   orphan-instance cleanup in a `finally` block, and unsaved-document handling.

The `get_call_graph` orphan (Ghidra) was also confirmed precisely: the "Show
Call Graph" action binds `get_call_tree` at `ghidra_panel.py:2906`, and
`get_call_graph` has zero GUI callers project-wide.

## Corrections applied (flagged for review, now reconciled)

All are arithmetic/narrative slips in the original reports' *summary prose* —
none reclassified any individual finding. The aggregate `SUMMARY.md` has been
updated where the number affected the totals.

| Slice | Item | Was | Corrected | Effect |
|---|---|---|---|---|
| 2 | Fully-ported count (prose) | 26 | **27** | +1 to totals |
| 4 | Fully-ported / NO-CONTROL (headline) | 12 / 35 | **10 / 37** | −2 to totals |
| 5 | Tool-def entry count (prose) | 69 | **81** | none (no finding) |
| 5 | `get_call_graph` fix text | "wire toggle" | **remove redundant dup** | remediation text only |
| 6 | Tool-def entry count (prose) | 86 | **81** | none (no finding) |
| 7 | Externally-addressable denom. | 8/18 | **8/17** | ratio only |
| 7 | `frida.attach` severity | name-input only | **all calls fail** | severity ↑ |
| 10 | P1 `list_processes` OK/OK/OK | counted fully-ported | **L3 NO-CONTROL** | −1 to totals |

**Net effect on the headline: 309/492 → 307/492 (62.4%).** x64dbg 48/89
(53.9%), Cutter/Rizin 24/73 (32.9%), Process 46/66 (69.7%).

## Needs-review items — now reviewed

- **V-10's residual Sandbox/Process "OK" rows — REVIEWED (orchestrator pass).**
  The named residual rows (P5, P14, P15, P16, P18, P23, P44) were each verified
  end-to-end against source: every one is a genuine OK/OK/OK — real WinAPI-backed
  bridge method (`TerminateProcess`, `VirtualQueryEx` loop, chunked wildcard
  scan, `CreateToolhelp32Snapshot` for modules, Toolhelp+`NtQueryInformationThread`
  for threads, `AdjustTokenPrivileges`, `CloseHandle`), registered tool-def
  (`process.py:572/663/677/647/655/733/867`), and a GUI control invoking it via
  `run_bridge_coroutine_logged` (`process_tab.py:591`, `memory_tab.py:450/768`,
  `modules_tab.py:333`, `threads_tab.py:414`, `system_tab.py:572/802`). P2/P4/P41
  were also spot-confirmed wired. **One over-count found:** **P1 (`list_processes`,
  basic variant)** was included in the report's 47 fully-ported PROCESS rows, but
  its own GUI cell reads *"Not directly used (superseded by P2)"* — no GUI control
  calls `list_processes` (the panel uses `list_processes_detailed`). By the
  three-layer rubric P1 is **NO-CONTROL at L3**, not OK/OK/OK. Corrected below.
- **V-09 / V-05 / V-06 / V-02:** clarity/presentation notes only (e.g. `add_
  bookmark` vs `generate_structure_bookmarks` both ultimately call
  `document.add_bookmark`; tool-def counts) — reviewed, no factual correction.

## Bottom line

The audit's findings are trustworthy. The gap picture stands: **Layer 1 (bridge)
is production-grade, Layer 2 (tool-def) is complete except Frida + Sandbox/
Process, and Layer 3 (GUI) is the systemic bottleneck.** The five actionable
bugs are real — and the `frida.attach` one is more severe than first reported,
so it should move to the top of the fix list alongside the Cutter command swap.
