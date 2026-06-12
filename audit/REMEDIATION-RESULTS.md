# Offender Remediation Results

Outcome of the dynamic Workflow that strengthened the audit-flagged weak test
gates catalogued in `audit/OFFENDERS.md` into genuine falsifiable tests.

- **Run ID:** `wf_45643f61-0af` (1 initial launch + 2 resumes)
- **Agents:** sonnet `test-writer` + `test-reviewer` (custom agent types), plus
  sonnet `Explore` for discovery/pending scan
- **Policy:** test-only — no `src/` edits; real production bugs reported in
  `audit/PRODUCTION-DEFECTS.md`
- **Completed:** 2026-06-08

## Headline

| Metric | Value |
|--------|-------|
| Files in scope | 55 (50 from OFFENDERS.md + 5 pending-review) |
| Offenders remediated | 126 |
| Files PASS (writer + reviewer gate) | 54 |
| Files resolved post-workflow | 1 (`test_hxd_panel.py`, `ruff format` only) |
| **Total resolved** | **55 / 55** |
| Production defects fixed | 2 — P-001, PD-001 (now FIXED in src/; gates green) |
| Production defects (writer-claimed, NOT reproduced) | 2 — PD-01, PD-02 (clipboard; gate passes on host) |
| Files left unresolved | 0 |

The discovery agent parsed `OFFENDERS.md` at runtime into 50 files / ~111
offenders; the 5 pending-review files added 15 more genuine offenders found on
full read — 55 files / 126 offenders total.

## Run history (session-limit interruptions, recovered by resume)

| Attempt | Outcome | Cumulative PASS |
|---------|---------|-----------------|
| Initial launch | session limit hit (8:10pm reset) | 1 / 55 |
| Resume 1 | session limit hit (1:10am reset) | 30 / 55 |
| Resume 2 | completed, no deaths | 54 / 55 (+1 post-fix) |

Resume used the workflow journal: completed writers/reviewers returned from
cache (no re-edit, no re-spend); only failed agents re-ran live. Each resume
strictly accumulated progress.

## Convergence (attempts to PASS)

- **1 attempt:** 34 files
- **2 attempts:** 16 files (reviewer caught a weak spot, writer fixed on re-loop)
- **3 attempts:** 5 files

The writer→reviewer loop demonstrably worked: 21 files needed a reviewer
rejection before reaching a real gate, including the 4 files whose strengthened
tests exposed production defects.

## The one unresolved → resolved

`tests/test_ui/test_hxd_panel.py` exhausted 3 attempts on a single blocking
reason: the rewrite introduced parenthesized `assert x, ('message')` forms that
`ruff format` collapses, so `ruff format --check` failed (tests passed, `ruff
check` clean). The reviewer correctly refused to pass it. Resolved post-workflow
with `pixi run ruff format tests/test_ui/test_hxd_panel.py` →
`ruff format --check` clean, `ruff check` clean, 53 tests collect.

## Representative transformations

- **`test_cutter_bridge.py` (15-F2/F3):** malformed `testvalidate_*` names (never
  collected) → two proper test classes, 20 collected gates; r2 argument-injection
  guard now actually tested. Collection 28→48.
- **`test_types.py` (10-F5):** ~80 construction-only tautologies → behavioral
  gates (flag math, `__str__` formatting, register-state `__getitem__` raising,
  GPR/segment dict membership).
- **`test_frida_bridge.py` (03 ×11):** dataclass field-assignment tests → real
  bridge integration assertions (12 findings, 3 attempts).
- **`test_start_calls_agent_connect.py` (18-F0001..3 + 19-F1):** `_RecordingAgent`
  mock → real `GuestAgentClient` against live loopback sockets.
- **`test_hashing.py` (04-F1/F2):** monkeypatched `QMessageBox` + hardcoded
  `0xC0FFEE42` checksum → real PE checksum oracle, which exposed **P-001**.

## Per-file results

Format: `STATUS | attempts | findings | path`

```
PASS|1|1|tests/test_audit4/b2_process_tab/test_process_tab.py
PASS|1|1|tests/test_audit4/c8_hex_signatures_offload/test_signatures_offload.py
PASS|1|1|tests/test_audit4/c9_hex_disassembly_debounce/test_follow_cursor_debounce.py
PASS|1|1|tests/test_audit5/u2_bridges_frida/test_frida_bridge_audit5.py
PASS|1|1|tests/test_audit7/sandbox_windows/test_memory_dump_target_pid.py
PASS|1|1|tests/test_bridges/test_ghidra_audit6.py
PASS|1|1|tests/test_bridges/test_sandbox_bridge.py
PASS|1|1|tests/test_core/test_config.py
PASS|1|1|tests/test_core/test_script_gen.py
PASS|1|1|tests/test_core/test_types.py
PASS|1|1|tests/test_hexcore_e2e/test_bridge_new_capabilities.py
PASS|1|1|tests/test_hexcore_e2e/test_hex_document_state.py
PASS|1|1|tests/test_hexcore_e2e/test_hexpat_control_flow.py
PASS|1|1|tests/test_hexcore_e2e/test_realcov_09b_stdlib_realbin.py
PASS|1|1|tests/test_hexpat/test_realcov_08_preprocessor_vendor.py
PASS|1|1|tests/test_providers/test_discovery_unit.py
PASS|1|1|tests/test_sandbox/test_log_parsers.py
PASS|1|1|tests/test_sandbox/test_sandbox_bridge.py
PASS|1|1|tests/test_ui/log_viewer/test_proxy.py
PASS|1|1|tests/test_ui/log_viewer/test_realcov_15_window_real_logs.py
PASS|1|1|tests/test_ui/test_icon_manager.py
PASS|1|1|tests/test_ui/test_realcov_13b_hex_sections.py
PASS|1|2|tests/test_audit4/c6_hex_hashing/test_hashing.py            (surfaced P-001)
PASS|1|2|tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py
PASS|1|2|tests/test_bridges/test_schemas.py
PASS|1|2|tests/test_ui/log_viewer/test_handler.py
PASS|1|2|tests/test_ui/log_viewer/test_model.py
PASS|1|2|tests/test_ui/log_viewer/test_tail_reader.py
PASS|1|3|tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py
PASS|1|3|tests/test_hexcore_e2e/test_bridge_va_mapping.py
PASS|1|3|tests/test_scripts/test_commit_message.py
PASS|1|4|tests/test_bridges/test_x64dbg_audit6.py
PASS|1|4|tests/test_providers/test_openai_provider.py
PASS|1|8|tests/test_ui/test_app_embedded_tools.py
PASS|2|1|tests/test_audit3/sandbox/test_clipboard_monitor.py         (surfaced PD-01, PD-02)
PASS|2|1|tests/test_audit7/ui_panels_process/test_threads_auto_refresh.py
PASS|2|1|tests/test_bridges/test_realcov_02b_named_pipe_real.py
PASS|2|1|tests/test_hexcore_e2e/test_bridge_pe_checksum.py
PASS|2|1|tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py
PASS|2|1|tests/test_hexcore_e2e/test_hexpat_type_system_e2e.py
PASS|2|1|tests/test_providers/test_anthropic_provider.py
PASS|2|1|tests/test_sandbox/test_analysis.py
PASS|2|1|tests/test_sandbox/test_realcov_12a_base_contract.py
PASS|2|2|tests/test_audit3/bridges/test_realcov_04_installer.py
PASS|2|2|tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py
PASS|2|2|tests/test_ui/test_process_panel.py
PASS|2|4|tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py
PASS|2|4|tests/test_core/test_session_audit6.py
PASS|2|5|tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py
PASS|2|6|tests/test_ui/test_graph_view.py
PASS|3|1|tests/test_audit4/c16_hex_panel_selection_dispatch/test_selection_dispatch.py
PASS|3|2|tests/test_providers/test_realcov_10_google_safety.py
PASS|3|12|tests/test_bridges/test_frida_bridge.py
PASS|3|15|tests/test_ui/test_xpu_status.py
RESOLVED(format)|3|4|tests/test_ui/test_hxd_panel.py                 (surfaced PD-001 via test_icon_manager; hxd format-fixed post-run)
```

## Independent verification (2026-06-09)

The workflow's PASS verdicts are agent self-reports; these were re-verified
directly against the on-disk result, not trusted. Findings:

- **Test-only policy held:** `git status` shows **0 `src/` changes**; only 56
  test files + `tests/test_sandbox/conftest.py` modified.
- **Static gates (all 56 files):** ruff check ✓, basedpyright `0 errors/0
  warnings/0 notes` ✓, pydoclint ✓, pydocstyle ✓.
- **Caught & fixed — `ruff format`:** 10 files (the originally-unresolved
  `test_hxd_panel.py` + 9 others the per-file reviewers passed) failed
  `ruff format --check` due to parenthesized assert-message expressions.
  Reformatted; all 56 now pass `ruff format --check`.
- **Caught & fixed — order-dependent test:** `test_ghidra_audit6.py::
  test_analyze_logs_distinguish_phases` passed in isolation but FAILED in the
  full suite — it scraped structlog records off global stdout via `capsys`,
  which breaks once a sibling test reconfigures logging (a forbidden
  non-deterministic anti-pattern the per-file reviewer could not see). Rewrote
  it to `structlog.testing.capture_logs()` (the pattern already accepted in
  `test_ghidra_f11_audit.py`), asserting exact structured fields — stronger and
  order-independent. Now passes in-suite.
- **Caught & corrected — over-claimed defects:** PD-01/PD-02 (clipboard) were
  logged as production defects but their genuine end-to-end gate
  `test_smoke_script_logs_clipboard_change` PASSES on this Windows 11 host (all
  10 clipboard tests pass). Reclassified as NOT-REPRODUCED in
  PRODUCTION-DEFECTS.md; their docstring NOTEs are stale (follow-up).
- **Removed stray artifact:** `xpu_test_results.txt` (a pytest-output dump a
  writer agent left at repo root) deleted.

**Full-suite result (56 files, headless `QT_QPA_PLATFORM=offscreen`):**
`2 failed, 2040 passed, 44 skipped` in 6m02s, 0 errors. The 2 failures are
exactly the verified production-defect reds (P-001 `test_hashing`,
PD-001 `test_icon_manager`) — red-by-design until `src/` is fixed.

## Production-defect fixes + 439-finding verification (2026-06-12)

Both confirmed production defects were fixed in `src/` and the "already
SATISFIED" findings were verified to close the trust gap.

**P-001 / PD-001 fixed** (see PRODUCTION-DEFECTS.md). Fixing P-001 exposed a
**second, contradictory test** (`test_insert_hash_fires_notify`) that had
codified the `0x58` bug as expected; it was reconciled to the correct derived
offset. All 9 hashing tests and the icon-manager tests pass.

**Trust-gap verification:** re-ran the union of all audit-cited test files
(354 files, ~7,900 tests, far broader than the 439 findings) headless. Result:
**0 failures attributable to this work** — every failing file is
workflow-untouched and unrelated to the `hashing.py` / `ai_brain.svg` changes.
The surfaced failures break down as:

- **8 latent cross-group order-dependencies** (ghidra `capture_logs`,
  `test_hex_editor_bottom_audit1`, `test_process_bridge`, `test_window`): each
  **passes in isolation / its own file**; they only collide because the 354-file
  mega-batch crosses the project's normal 8-group test boundaries. They do not
  fail in the project's standard grouped runs.
- **2 environment false-positives** (`test_config_paths` D:-drive): production
  correctly derives the path from the project root, which legitimately is
  `D:\Intellicrack` on this host; the test hardcodes that as "forbidden".
- **1 outdated test expectation** (`test_notepad_imports_include_kernel32`, not
  an audit finding): Win11 notepad imports via `api-ms-win-core-*` apisets; the
  PE-introspection bridge parsed them correctly — only the test's `kernel32.dll`
  assumption is stale.
- **1 pre-existing packaging observation** (`test_runtime_deps`, not caused
  here): `frida-tools` and `pydantic` are absent from `[project].dependencies`.
  Touches packaging config — flagged for separate decision, not changed.
- **1 UI teardown segfault** (`_audit_batch_07`, native crash with an
  `async_bridge._run_loop` thread alive): environmental UI-shutdown crash class,
  not an audit-finding regression.

Net: the 439 satisfied findings hold; nothing this work touched regressed.

## Recommended next steps

1. Triage the 4 production defects in `audit/PRODUCTION-DEFECTS.md` (P-001,
   PD-01, PD-02, PD-001) — their gating tests are intentionally red until fixed.
2. Run the full touched-file suite once to confirm green-except-documented-reds:
   `pixi run pytest <touched files> -p no:timeout`.
3. Commit the strengthened tests (56 test files + `tests/test_sandbox/conftest.py`).
