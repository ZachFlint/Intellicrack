# Remediation Verification — Final Scoreboard

**Date:** 2026-06-27
**Method:** 10 parallel adversarial `test-reviewer` agents (sonnet), each
re-enumerated the non-REAL inventory rows in its assigned audit sections and
verified each against the current `tests/` tree using the strict real-gate
rubric (independent oracle + nameable mutation; no mock-SUT, no type-only, no
bare `pytest.raises`, no suppressions). Read-only verification.

## Result

| Group | Sections | Resolved | Red-by-design | **Still open** | Total |
|---|---|---:|---:|---:|---:|
| 01 | §1 Bridge + §5 Hex + §6 HexPat | 34 | 0 | 17 | 51 |
| 02 | §2 Disassembler + §15 UI Panels | 45 | 5 | 50 | 100 |
| 03 | §3 X64Dbg | 34 | 0 | 29 | 63 |
| 04 | §3 Frida | 34 | 2 | 35 | 71 |
| 05 | §4 PE/Process + §13 Rust | 25 | 2 | 20 | 47 |
| 06 | §7 Orch + §8 Infra + §12 Sandbox | 22 | 0 | 26 | 48 |
| 07 | §9 Cloud Providers | 56 | 0 | 34 | 90 |
| 08 | §10 Local-AI + §14 UI Shell | 13 | 2 | 45 | 60 |
| 09 | §11 Credentials #1–64 | 19 | 0 | 31 | 50 |
| 10 | §11 Credentials #65–127 | 3 | 0 | 22 | 25 |
| **TOTAL** | **all 15 sections** | **285** | **11** | **309** | **605** |

**Done (real gate or correct red-by-design): 296 / 605 ≈ 49%.**
**Still open (no real falsifiable gate yet): 309 / 605 ≈ 51%.**

The 605 enumerated findings vs the audit's headline "~617" differ only by
row-granularity between agents; the two figures describe the same body of work.

## Where the open work clusters (largest first)

1. §2 Disassembler — 50 (Ghidra analysis/xref/section/vtable + Cutter search/compare/segment ops)
2. §10 Local-AI + §14 UI Shell — 45 (worst ratio, 13/60)
3. §3 Frida — 35 (advanced instrumentation band: cloak/stalker-probe/cmodule/inject/monitor/backtrace)
4. §9 Cloud Providers — 34 (offline-coverable request-shaping branches)
5. §11 Credentials — 53 total (store.py + env_loader.py error branches, keyring-unavailable, alias lookup)
6. §3 X64Dbg — 29
7. §7/§8/§12 — 26
8. §4/§13 — 20
9. §1/§5/§6 — 17

Per-finding detail (operation, source:line, the exact missing assertion, and the
mutation it must catch) is in `group-01..10-report.md`. The flat index of all 309
open items is `CONSOLIDATED-OPEN.md`.

## Red-by-design (correct gates intentionally red — not counted as open)

PD-002 (set_thread_context dr0–dr3), PD-003 (10 Ghidra trailing-expr methods),
PD-004 (objc/java hook reserved kwarg), PD-005 (get_fiber_data union),
PD-006 (highlighter ordering). 11 gate-rows across the suite. See
`audit/PRODUCTION-DEFECTS.md`.
