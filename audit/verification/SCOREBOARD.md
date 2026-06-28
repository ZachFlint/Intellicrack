# Remediation Verification — Final Scoreboard

## Wave 5 closure (2026-06-28) — all 309 STILL-OPEN findings remediated

The 309 STILL-OPEN findings below were closed by Wave 5: ≤5 sonnet
`test-writer` agents in phases wrote NEW `tests/**/test_*_wave5.py` files (one
per cluster), the orchestrator sandbox-verified every file (custom/offline),
sonnet `linter` agents drove every new/modified file to full ruff + basedpyright
+ pydoclint + pydocstyle compliance, and reds were triaged as test-bug (fixed)
vs real-defect (left red-by-design + documented).

**Final wave-5 suite result (31 files, single sandbox run):**
`701 passed, 12 failed, 2 skipped`. All 2 skips are legitimate capability skips
(loopback TCP / hardware). All 12 reds are documented RED-BY-DESIGN production
defects (the gate asserts correct behaviour the buggy src cannot yet deliver):

| Defect | Reds | What the gate correctly demands |
|---|---:|---|
| PD-003 | 3 | `create_data_type` must return the union/typedef result dict (trailing if/else captures nothing) |
| PD-007 | 1 | `_scan_window` must unpack modern yara `StringMatch` results |
| PD-008 | 1 | no-pid token-privilege op must not overflow the GetCurrentProcess pseudo-handle |
| PD-009 | 2 | orchestrator agent loop must honour `timeout_seconds` and max-iterations |
| PD-010/011 | 5 | `generate_timeline` must handle the `resource` category; RustTransformNode real transform name |

Per-cluster outcomes: §2 Disassembler (cutter + ghidra sections/introspection/
datatypes/core — 3 PD-003 red); §9 Cloud (anthropic/openai/google/grok/
openrouter/ollama — offline fake-transport gates, all green); §10 Local-AI
(huggingface/local_transformers + model_loader/gpu_pci/xpu_utils — torch/ctypes
boundary mocks, all green); §11 Credentials (oauth/store/env_loader — all green);
§14 UI Shell + §15 UI Panels (show_info/preferences/FlowLayout/XPUStatusDialog/
main/__main__ + stack_viewer/async_bridge, all green). Finding #48 (SandboxMixin
`copy_to` routing) is already gated by
`tests/test_audit4/c12_hex_sandbox_route/test_sandbox_route.py:289` (exact
`(instance_id, source, dest)` triple + no-subprocess assertion), so it is not
duplicated. Five "ghidra" rows (get_data_references/get_instruction_at/
emulate_function/get_local_variables/get_stack_trace) reference methods that do
not exist in `bridges/ghidra.py` → audit artifacts, non-gateable. Likewise S7-14
(`TransformPipeline.to_dict`/`from_dict` round-trip) references methods absent
from the production class → audit artifact, non-gateable.

## Independent authenticity re-audit (2026-06-28)

5 parallel `haiku` `test-reviewer` agents adversarially re-graded every wave-5
test against the real-gate rubric (independent-oracle + nameable mutation; the
forbidden-pattern list; capability-skip and red-by-design carve-outs). Result
across ~740 tests: **~731 REAL + 10 RED-BY-DESIGN + 3 WEAK** (the bins double-
count a couple of red rows by class). The only 3 WEAK gates were remediated:
the two `TestTransformPipelineSerializationUntestable` absence-assertions were
removed (S7-14 is a non-gateable audit artifact, above) and the isinstance-only
`test_remove_privilege_returns_bool` was removed (its companion
`test_remove_privilege_privilege_no_longer_enabled_in_token` reads the live
Win32 token state and is the real gate). Full per-test verdicts:
`audit/verification/haiku-audit/bin-1..5.md`.

Ledger now PD-002..PD-011. See `audit/PRODUCTION-DEFECTS.md`.

---

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
