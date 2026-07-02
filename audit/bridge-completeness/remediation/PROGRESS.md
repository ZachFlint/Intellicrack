# Bridge-Completeness Remediation — Progress Tracker

Mode: **full autonomous run**. Test authoring: **dedicated test-writer per tool**, then test-reviewer audit.
Target: 5 correctness bugs + 185 coverage gaps → OK/OK/OK across L1 bridge / L2 tool-def / L3 GUI.

## Wave plan

| Wave | Agents (disjoint files) | Status |
|---|---|---|
| 1 — L1/L2 batch A | A x64dbg bridge · B Cutter bridge · C Ghidra bridge | **VERIFIED (all gates green on main)** |
| 2 — L1/L2 batch B | D Frida bridge · E Hex-editor bridge+sandbox · F Sandbox/Process tool-defs | DISPATCHED |
| 3 — L3 GUI batch A | G x64dbg panel · H Cutter panel · I Ghidra panel | pending |
| 4 — L3 GUI batch B | J Frida panel · K Hex-editor panel · L Sandbox/Process panel | pending |
| Tests | test-writer per tool → test-reviewer audit | pending |
| Verify | per-tool verifier agents (read-only src) | **DONE (verify-<tool>.md × 6)** |
| Gate | Docker sandbox full quality gate | **DONE — 374/374 PASS (per-dir)** |
| Deliverable | remediation/REMEDIATION-RESULTS.md | **DONE** |

## FINAL STATUS (2026-07-01) — COMPLETE
All 5 Tier-1 bugs + 185 coverage gaps + 2 systemic defects fixed on `main` (no branches).
Docker sandbox gate run **per-directory** (contains Frida's native `on_detach` access-violation
exit-255 crash that zeroes a whole-tree run) with root autouse modal-dialog guard
(`tests/test_bridge_completeness/conftest.py`) so headless Qt never blocks on QMessageBox/
QInputDialog/QFileDialog. Final green counts:
- cutter 53/53 · ghidra 100/100 · x64dbg 30/30 · sandbox_process 70/70 · hex_editor 63/63 · frida 58/58
- **TOTAL 374/374 PASS, 0 failed, 0 errors.** All tests real falsifiable gates, 0 suppressions.
- src+tests clean: ruff 0 / basedpyright 0 / pydoclint 0 / pydocstyle 0.
- HxD untouched (user removed it in parallel; native hex_editor package only).
Fixes landed this session beyond the workflow: hex ctypes OpenProcess argtypes (real ArgumentError),
hex search-status label ordering, structure-bookmarks PE-signature validation + local refresh,
pattern_editor mixin-shadow removal, sandbox error-status race, core/tools error-cause preservation,
frida rpc snake_case (`_to_frida_export_attr`), Frida-17 `ptr.writeU8` in post_message tests,
revert_hook active-hook validation, on_detached application-requested teardown-race guard.

## Rules in force
- No two concurrent agents write the same file. Max 3 agents/wave.
- Impl agents write production code only (no tests, no pytest). Self-verify ruff/basedpyright/pydoclint/pydocstyle/import.
- Advance a tool to its L3 wave only after its L1/L2 is verified by me (spot-Read).

## Import-verify gotcha (applies to ALL waves)
Cold-importing a bridge submodule directly (`python -c "import intellicrack.bridges.<tool>"`)
raises a FALSE circular-import error (`bridges.base` <-> `core.tools`). Correct self-verify import:
`python -c "import intellicrack; import intellicrack.core.tools; import intellicrack.bridges.<tool>; print('OK')"`.
Do NOT treat the cold-submodule failure as a regression.

## Wave 1 results
- A x64dbg: **VERIFIED** — disassemble tool-def renamed to `disassemble_at` @1205 (old name gone,
  dispatchable, static_analysis capability @817); real `restart` L1 @7804 + tool-def @1078
  (`_launch_args` @803 persisted in load() @2757); runtime dispatch asserts pass; all gates green.
- B Cutter: **VERIFIED** — swap fix irj@2739 / iRj@2773; tool-defs `_tf` @685/686;
  ruff clean (orchestrator fixed 2 pre-existing property-docstring findings @1329/1338);
  basedpyright/pydoclint clean; import OK via package init.
- C Ghidra: **VERIFIED** — REPEATABLE→CodeUnit.REPEATABLE_COMMENT @3080 + explicit unknown-type
  ToolError (no silent downgrade); 3 real memory-block methods @6238/6286/6345; edit_program_tree
  @6610; 4 tool-defs @1075/1083/1097/1133 discoverable+dispatchable; all gates green.
- base.py: added `"restart":"debugging"` to TOOL_CAPABILITY_MAP for gate parity; cleaned 5
  pre-existing lint findings (1 blank-line + 4 property-docstring). All gates green.

## Wave 2 results
- D Frida: **VERIFIED** — frida.attach fix: method now attach(pid: int|str, *, cancellable_id) @1429
  (name-string routes to attach_by_name @1453; numeric attaches via _perform_attach); tool-def param
  renamed target->`pid` @189 (matches signature). 4 methods registered: attach_by_name @1576,
  execute_persistent_script @2462, unload_script @2504, unload_all_scripts @2850. 102 tool-defs;
  deep schema check found 1 NEW mismatch: **frida.write_memory hex_data(str) vs data(bytes)** ->
  handed to workflow Phase 1. gates clean, import OK.

## PIVOT to Workflow orchestration (user asked "why aren't you using ultracode")
Waves 1-2 (all L1/L2) + capability-gate systemic fix are DONE & verified on main. Remaining work
(residual L2 schema sweep + Waves 3-4 GUI + tests + review + verify) is now driven by the Workflow
harness. **Run ID: wf_da15437d-570** (resume via scriptPath+resumeFromRunId if session limits hit).
Workflow phases: L1L2-residual (frida.write_memory + all-bridge schema sweep) -> per-tool pipeline
[GUI clusters sequential/tool, parallel across 6 tools] -> test-writer -> test-reviewer(+1 rewrite)
-> completeness verifier(verify-<tool>.md). On completion I: verify synthesis, fix any still_broken
rows, run the Docker sandbox gate on new tests (sandbox-only per policy), write REMEDIATION-RESULTS.md.

## Workflow wf_da15437d-570 OUTCOME (partial success; crashed on final synthesis + transient server rate-limit)
39 agents, ~4.79M tokens, ~105min. Did NOT fail the implementation — crashed only in my JS synthesis
(r.gui.map) and lost the test/review/verify stages for 5 tools to server-side rate-limiting.
LANDED & VERIFIED BY ORCHESTRATOR (direct gating on main):
- Phase 1 coercion: core/tools.py now has `_coerce_hex_string_arguments` + `_is_bytes_annotation`
  (+ _ERR_INVALID_HEX_ARGUMENT) — decodes hex-string args to bytes for bytes-typed params before
  dispatch. Fixes frida.write_memory + the whole write_memory class. (Confirmed: there was NO prior coercion.)
- GUI landed for ALL 6 tools, well-factored into NEW sub-modules: cutter_{debugger,project,search,static_extra}_tab.py;
  ghidra_panel_{data_types,program_tree,extras}.py; frida_instrumentation_tab.py; x64dbg_advanced_tab.py;
  hex_editor/{export_report,va_mapping}.py + search.py(search-replace) + drift reroutes; sandbox_panel config;
  process_panel {memory,system,threads}_tab + hint_overlay.
- GATES CLEAN across all 37 changed+new src files: ruff + basedpyright + pydoclint = 0 findings;
  all 18 new/changed panel modules import cleanly. (orchestrator fixed sections.py Path -> TYPE_CHECKING.)
  NOTE: providers/local_transformers.py has 3 pre-existing property-docstring findings — OUT OF SCOPE
  (unrelated provider, pre-modified before this remediation), intentionally left alone.
- TESTS present under tests/test_bridge_completeness/ for x64dbg, cutter, ghidra, frida, sandbox-process.
  HEX-EDITOR tests MISSING (rate-limited) -> agent `hextests` re-writing now.
- verify-sandbox-process.md produced by workflow; verify-<x64dbg/cutter/ghidra> running now
  (agents vr-x64dbg/vr-cutter/vr-ghidra: combined 3-layer verify + test-gate review, read-only src).

## REMAINING (recovery, small controlled batches to avoid rate-limit):
1. hextests -> write hex-editor gate tests. [running]
2. verify+review x64dbg/cutter/ghidra [running]; then frida + hex-editor (batch 2).
3. Docker sandbox gate over ALL of tests/test_bridge_completeness/ (custom mode, -p no:timeout,
   --timeout 1800) — run ONCE after hex tests land. Fix any real failures.
4. Fix any still_broken rows the verifiers find.
5. Write REMEDIATION-RESULTS.md.

## CRITICAL FINDING (vr-cutter): test files miss the zero-findings norm
- Enforced `just basedpyright` gate is **src/ only** (justfile:183) -> my src is clean. BUT existing
  sibling test dirs (test_audit4/c1_hex_search_wiring, test_audit5/u1_bridges_cutter) are 0 basedpyright/
  0 ruff -> established NORM = tests must also be clean (plan requires it too). New tests violate it:
  cutter ~324 basedpyright (mostly reportPrivateUsage tab._bridge/_table/_on_analyze + some
  reportOptionalMemberAccess .item().text() no None-check) + 2 ruff (dup import asyncio, /tmp hardcode);
  frida ruff (escape-seq docstring, missing-yields); x64dbg reportUnknownMemberType; etc.
- FIX PATTERN (no assertion weakening): cast(<type>, getattr(obj,"_priv",default)) per sibling
  test_audit4/c1_hex_search_wiring; None-guard before .item().text(); fix docstrings/imports/temp-paths.
  Ruff DOES check tests (only S101/S102/S404 ignored) -> ruff findings are hard-enforced.
- vr-cutter: cutter L1/L2 100%; L3 39/46 OK; ALL 46 tests are REAL GATES. 7 residual NO-CONTROL rows:
  get_debug_info, esil_emulate_function, esil_set_pc, add_flag, resolve_flag, get_config, set_config.

## Recovery agents dispatched (batch)
- hextests (hex tests), vr-x64dbg, vr-ghidra [running]
- clean-cutter-tests (tests->0 findings), cutter-residual-gui (7 NO-CONTROL rows) [running]
## Verifier results (verify-<tool>.md written)
- verify-sandbox-process.md (workflow) — done.
- verify-cutter.md — L1/L2 100%; L3 39/46 OK; ALL 46 tests REAL GATES. 7 residual NO-CONTROL.
- verify-x64dbg.md — 39/44 OK; ALL 24 tests REAL GATES (incl red-by-design row-19 pair).
  5 open: step_count, animate_start, animate_stop, get_trace_record (NO-CTRL); row-19 cond-BP DEAD-CTRL.
  6 ruff + 77 basedpyright in tests (reportPrivateUsage). scan_memory indirect = OK/low-pri.
- verify-ghidra.md — ~86/87 OK; ALL tests REAL GATES. 1 residual: remove_label NO-CONTROL (+ needs test).
  97 basedpyright in tests (8 cast-fixable + 89 reportPrivateUsage).

## Residual-src agents dispatched (src panels only; tests deferred to a sequenced follow-up)
- cutter-residual-gui: 7 rows (get_debug_info, esil_emulate_function/set_pc, add_flag, resolve_flag,
  get/set_config). [running]
- x64dbg-residual-src: 4 NO-CTRL (step_count, animate_start/stop, get_trace_record) + row-19 cond-BP
  field/forwarding. NOTE: red-by-design row-19 test must be flipped to assert FIXED state by test agent. [running]
- ghidra-residual-src: remove_label delete affordance on Labels table (copy Bookmarks delete pattern). [running]

## Wave B (after residual-src): per-tool TEST-FINISH (add new-row tests + flip x64dbg row-19 test + clean
ALL tool tests to 0 ruff/basedpyright/pydoclint via cast+getattr private-access & None-guards) for
cutter/x64dbg/ghidra/frida/sandbox-process/hex; + frida & hex verify/review; then sandbox gate; then RESULTS.md.

## SRC 100% COMPLETE for: cutter, ghidra, x64dbg (all residual rows closed, gates 0), + frida, sandbox-process, hex (workflow).
## Per-tool status snapshot:
- sandbox-process: FULLY DONE — src + tests CLEAN (0/0/0) + verify-sandbox-process.md. [DONE]
- cutter: src 100% (7 rows closed); cutter-test-finish RUNNING (add 7 tests + clean 197 basedpyright).
- ghidra: src 100% (remove_label closed); ghidra-test-finish RUNNING (add test + clean 97).
- x64dbg: src 100% (5 rows closed, cond-BP fixed); x64dbg-test-finish RUNNING (flip row-19 gate + add 4 + clean 77).
- frida: verify-frida.md DONE. attach fix validated (89-def schema audit, 0 mismatch); 4 methods + 10
  instrumentation rows wired. 6 residual L3 NO-CONTROL rows -> frida-residual-gui RUNNING (Stalker
  exclude/gc/invalidate/trustThreshold, rpc_call, post_message, eternalize_script, create_cancellable/cancel,
  load_module). frida-test-finish PENDING must: (a) DELETE broken autouse fixture
  `_shutdown_self_attached_bridge_after_test` @588 (forces real Frida attach on EVERY test - actively
  harmful), (b) add tests for the 6 new rows, (c) add a frida.write_memory hex->bytes dispatch gate
  (Phase-1 _coerce_hex_string_arguments has NO falsifiable test anywhere), (d) clean 17 basedpyright
  (12 need cast on object-typed execute_tool_call results) + 1 ruff + 2 pydoclint to 0.
- hex: hextests RUNNING (writing tests); hex verify + test-finish PENDING.
## HARD CONSTRAINT (user, 2026-07-01): HxD is slated for removal — NO work may touch it.
- `src/intellicrack/ui/panels/hxd_panel.py` / `HxDPanel` = dead/abandoned external-HxD-exe embed.
  Audit agent-09 line 174 ALREADY excluded it from the coverage matrix. Verified: git status shows
  ZERO hxd modifications; ALL hex work is in the native `ui/panels/hex_editor/` package (mixins:
  Search/Sandbox/Calculator/DataInspector/ProcessMemory/ExportReport/... composed into HexEditorPanel
  via the hex_editor_panel.py shim the app loads) + bridges/hex_editor.py. My hex GUI IS reachable there.
- ALL remaining hex agents (hextests [guarded via SendMessage], hex verify, hex test-finish) MUST NOT
  read/import/test/edit hxd_panel.py or HxDPanel — native hex_editor package ONLY.

## INCIDENT: test-dir edit collisions from FAILED-workflow zombie children (diagnosed + contained)
The failed workflow wf_da15437d-570 crashed on synthesis but its child test-writer agents were NOT
cleanly killed; they kept running in the background and collided with my manually-dispatched test-finish
agents on the SAME test dirs (cutter, x64dbg). Cutter reconciled OK (both agents' work merged -> 0/0/0).
x64dbg-test-finish paused to avoid corruption; workflow now confirmed DEAD (TaskStop: no task found),
so x64dbg-test-finish told it is SOLE OWNER -> finishing to 0. LESSON: one agent per test dir; verify a
failed workflow is fully dead before dispatching agents onto files its children may still hold.

## TEST-DIR STATUS (live):
- cutter: DONE 0/0/0, 53 test fns incl all 7 new-row gates (get_debug_info@767, esil_emulate@806, esil_set_pc@837, add_flag/resolve_flag/get_config/set_config). [DONE]
- sandbox-process: DONE 0/0/0. [DONE]
- ghidra: 1 basedpyright left; ghidra-test-finish finishing.
- x64dbg: ~10 ruff + 57 basedpyright; x64dbg-test-finish finishing as SOLE owner (loop-verify to 0).
- frida: src 100% (6 rows wired: StalkerConfigControls/ScriptMessagingControls/CancellableControls/load_module, gates 0). frida-test-finish RUNNING (delete broken fixture, add 6 new-row tests + write_memory hex gate, clean 17bp/2ruff to 0).
- hex: hextests writing (hxd-guarded).
## ALL 6 TOOLS 100% AT SRC LEVEL: cutter, ghidra, x64dbg, frida, sandbox-process, hex. Remaining = tests + gate + RESULTS.

## TESTS DONE (0/0/0, real gates, no suppressions): cutter, ghidra, x64dbg, frida, sandbox_process.
- x64dbg: orchestrator fixed final 2 (moved local `from pathlib import Path` to top; removed spurious
  Raises section from conftest priv() docstring -> DOC502). Row-19 positive gate + 4 stepping tests present.
- frida: broken autouse fixture deleted; write_memory hex->bytes coercion gate added; 0/0/0.
- IMPORTANT FIX: test dir `sandbox-process` (hyphen = invalid Python package, no __init__) RENAMED ->
  `sandbox_process` + __init__.py added, matching the other package dirs. Prevents collection failure.
  (hex test-writer correctly used `hex_editor` underscore already.)
## IN FLIGHT: hex-test-clean (hex_editor tests: 119 basedpyright -> 0; hxd-guarded, real tests already written:
  test_search_replace/test_sandbox_reroute/test_process_memory_reroute/test_pattern_autodetect/test_export_report/test_va_mapping).
## THEN: hex verify (read-only, after clean); Docker sandbox gate over tests/test_bridge_completeness/; RESULTS.md.
## PRE-GATE CHECK: before sandbox gate, confirm ui/panels/__init__.py + app.py import-consistent (user removing HxD in parallel).
   -> DONE: user removed HxD cleanly (hxd_panel.py gone, no refs in __init__.py/app.py, `import
   intellicrack.ui.panels` OK). Import graph consistent. Targeted gate unaffected by any other-dir HxD refs.

## ALL 6 TOOL TEST DIRS CLEAN (0 ruff / 0 basedpyright / 0 pydoclint, no suppressions, hxd-free):
   cutter 53, ghidra 91, x64dbg 30, frida 52, sandbox_process 59, hex_editor 50 = 335 gate test fns.
## vr-hex RUNNING (last verify-<tool>.md, hxd-guarded, read-only).
## DOCKER SANDBOX GATE RUNNING: bg task b0a6vctml -> docker_sandbox custom --extra-args
   "tests/test_bridge_completeness -p no:timeout -q -ra" --timeout 1800. Windows container, ~335 tests.
   On completion: record pass/fail in RESULTS.md; fix any real failures (re-dispatch file-owner); re-gate.
## FINAL: REMEDIATION-RESULTS.md (per-bug + per-tool three-layer file:line + guarding test + gate results).

## vr-hex RESULT: hex-editor NOT done — 10/15 rows fixed, but 5 drift-reroutes were NEVER touched
(calculator.py/templates.py/signatures.py/data_inspector.py = zero-diff). Rows: base_convert(#45),
generate_structure_bookmarks(#52), list_templates_detailed(#51), scan_die/clamav/custom_signatures
(#87-89, audit's HIGHEST drift-risk), toggle_bit(#18b). All 32 hex tests confirmed REAL GATES though.
-> hex-residual-gui DONE: all 5 closed via bridge-first/local-fallback (base_convert, generate_structure_bookmarks@513,
list_templates_detailed@309, scan_die/clamav/custom@633-635, toggle_bit@265; gates 0/0/0). Fallback preserves the
existing test_audit4 mixin-harness tests (they drive mixins with no _bridge). HEX SRC NOW 100% (15/15 rows).
-> hex-newtests RUNNING (gate tests for the 5 reroutes asserting the bridge path + keep hex tests at 0).
-> hex-newtests: added 5 reroute gate tests; self-corrected a noqa the stop-hook caught (now priv_set, 0 suppressions);
   still finishing basedpyright cleanup (14 left) on its new test_scan_signatures_reroute.py etc.

## SANDBOX-GATE HANG (real defect, must fix before green):
- Validation (bblgop56f, module mode) HUNG 900s -> exit 124 (timeout), total=0. Module mode DOES avoid the
  custom-container collision (both containers coexisted) -> collision theory retired; this is a REAL runtime hang.
- Collect-only over the FULL tree (b4tmvzj2n) PASSED exit 0 (104s) -> collection is clean tree-wide; hang is at RUNTIME.
- Likely cause (matches [ui_qthread_retention] exit-124 modal-dialog note): panel L3 test triggers an UNPATCHED
  blocking modal (QMessageBox.warning/.information/.question or QFileDialog.getOpenFileName — many sites in
  process_tab/system_tab/threads_tab/modules_tab). Tests patch QMessageBox.warning but not the other dialog types.
- DIAGNOSTIC RUNNING: b6ksz7ua6 (sandbox_process -v -s, 240s) -> identifies the exact hanging test from streamed output.
- FIX PLAN: surgical (patch the specific unpatched dialog in the offending test) OR add a sandbox_process conftest.py
  autouse dialog-guard (patch QMessageBox static methods + QFileDialog/QInputDialog to non-blocking defaults) — a
  legitimate headless-UI-boundary guard, not weakening any gate. Then re-run to confirm no hang. May need same guard
  for other tools' L3 dirs (verify in the full gate).

## SANDBOX GATE — 2 runs (b0a6vctml, ba4oi7q1v) both total=0 / exit 0xC0000001 = CONTAINER-NAME COLLISION
with the user's concurrent `custom`-mode HxD-verification runs (shared name intellicrack-sandbox-custom;
log shows sandbox_stale_container_removed + interleaved 21-45/21-55/21-58 runs; the access-violation in the
log is from test_bridges/test_get_windows_no_crash, a DIFFERENT concurrent run, NOT ours). FIX: run the
final gate in `module` mode (-m tests/test_bridge_completeness) -> container `intellicrack-sandbox-module`,
which does NOT collide with the user's custom-mode runs. Do this AFTER hex is complete.

## THEN: Docker sandbox gate over tests/test_bridge_completeness/ (custom, -p no:timeout, --timeout 1800); fix real failures; REMEDIATION-RESULTS.md.
- E Hex-editor: **VERIFIED** — sandbox reroute in ui/panels/hex_editor/sandbox.py: both handlers
  `_on_save_to_sandbox`@126 / `_on_test_in_sandbox`@172 now call bridge.save_to_sandbox@160 /
  test_in_sandbox@202 via run_bridge_coroutine_logged (signatures match; zero raw SandboxBridge/
  copy_to/execute left); replace_bytes@5329 + 13 drift methods confirmed complete at L1 (no change);
  2 property-docstrings fixed. All gates green.
- F Sandbox/Process: **VERIFIED** — 13 NOT-REGISTERED methods now registered (sandbox 29 tool-defs
  incl. stop/stop_pcap; process 66 incl. decommit_memory/duplicate_token/remove_privilege). Deep gate:
  EVERY tool-def dispatches AND 0 schema/signature mismatches across all 95 defs (frida-class bug
  absent). ruff/basedpyright/pydoclint clean.

## Systemic capability-gate fix (discovered during Wave 2, user-approved: fix all 9)
Bug: `core/tools.py` capability gate keyed on bare method name globally; 9 registered tool-defs
inherited a capability their bridge doesn't advertise -> silently ToolError-blocked at dispatch
(NOT caught by the audit, which only checked registration + getattr). Fix (Approach A):
- `core/tools.py:607`: `required = TOOL_CAPABILITY_MAP.get(function_name) or TOOL_CAPABILITY_MAP.get(attr_name)` (prefer full-name).
- `base.py` TOOL_CAPABILITY_MAP += 9 tool-qualified overrides -> each maps to a capability the
  owning bridge advertises: sandbox.stop/frida.attach/frida.detach/frida.disassemble_instruction
  -> dynamic_analysis; ghidra.get_memory_map/ghidra.write_bytes/hex_editor.run_python_script
  -> static_analysis; process.get_modules/process.get_threads -> memory_access.
- Falsifiable gate PASSES: re-scan of all 7 bridges -> 0 capability-gate-blocked tool-defs (was 9).
- Backward-compatible (short-name entries still resolve). All gates clean. NEEDS a permanent test.
