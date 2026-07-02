# Bridge Completeness Remediation — Results

Remediation of the bridge-completeness audit (185 coverage gaps + 5 Tier-1
correctness/dispatch bugs) across the three integration layers — **L1 Bridge**,
**L2 Tool-def/Dispatch**, **L3 GUI** — to genuine OK/OK/OK, each guarded by a
real, falsifiable test. All edits on `main`, no branches.

> **Gate COMPLETE (2026-07-01).** The full `tests/test_bridge_completeness/`
> suite passes in the Docker sandbox — **374/374 tests green across all six
> tool dirs** (run per-directory to contain Frida's native detach crash). All
> `src/` and test files are clean on ruff + basedpyright + pydoclint with zero
> suppressions.

## Headline

**All 5 Tier-1 bugs fixed and all 185 coverage gaps closed across L1/L2/L3**,
plus **two systemic defects discovered during remediation** (a global
capability-gate collision and a missing hex→bytes dispatch coercion) that the
original audit did not catch. Every remediated row has a real gate test; the
whole `tests/test_bridge_completeness/` suite (348 test functions expanding to
**374 collected items via parametrization**) and every touched `src/` file are
clean on ruff + basedpyright + pydoclint with **zero suppressions**.

## Tier-1 correctness / dispatch bugs — all RESOLVED

| # | Bug | Fix (L1/L2) file:line | Guarding test (falsified_by) |
|---|---|---|---|
| 1 | Cutter relocations/resources swapped commands | `bridges/cutter.py:2739` `get_relocations`→`irj`; `:2773` `get_resources`→`iRj` | cutter `ir`/`iR` regression: asserts each method sends the correct rizin command and returns the right dataset |
| 2 | `x64dbg.disassemble` tool-def undispatchable | tool-def renamed to `disassemble_at` `bridges/x64dbg.py:1205`; `supports_static_analysis=True` `:817` | x64dbg dispatch test: `x64dbg.disassemble_at` resolves + dispatches, old name absent |
| 3 | `frida.attach` param mismatch (every call TypeErrors) | `attach(pid: int\|str,...)` `bridges/frida_bridge.py:1429`; tool-def param `target`→`pid` `:189` | frida attach test: succeeds for BOTH a numeric PID and a process name |
| 4 | Ghidra `add_comment` silently downgrades REPEATABLE | `comment_map` +`REPEATABLE→CodeUnit.REPEATABLE_COMMENT` `bridges/ghidra.py:3080`; unknown type raises `ToolError` | ghidra REPEATABLE regression: writes a repeatable comment; unknown type raises |
| 5 | Hex-editor sandbox save/test wired to wrong bridge | panel reroutes to `hex_editor.save_to_sandbox`/`test_in_sandbox` `ui/panels/hex_editor/sandbox.py:160,202` | hex sandbox-reroute test: handler targets `bridge.save_to_sandbox`/`test_in_sandbox`, NOT raw `SandboxBridge` |

## Systemic defects found + fixed during remediation (beyond the audit)

- **Capability-gate collision (9 registered tool-defs silently blocked).** The
  gate in `core/tools.py` keyed on the bare method name globally, so
  `sandbox.stop`, `frida.attach`/`detach`/`disassemble_instruction`,
  `ghidra.get_memory_map`/`write_bytes`, `hex_editor.run_python_script`,
  `process.get_modules`/`get_threads` inherited a capability their bridge does
  not advertise and TypeError-blocked at dispatch. Fix: tool-qualified lookup
  `core/tools.py:607` (`MAP.get(function_name) or MAP.get(attr_name)`) + 9
  full-name overrides in `bridges/base.py` TOOL_CAPABILITY_MAP. Falsifiable
  gate: re-scan of all 7 bridges → 0 capability-gate-blocked tool-defs (was 9).
- **Missing hex→bytes dispatch coercion.** `write_memory`-class tool-defs pass
  hex strings to `bytes`-typed params, but no coercion existed — every such
  tool-call would fail. Fix: `_coerce_hex_string_arguments` + `_is_bytes_annotation`
  in `core/tools.py` decode hex→bytes for bytes-annotated params before
  `method(**arguments)`. Guarding test: `frida.write_memory` dispatched with a
  hex-string `data` arg reaches the method as decoded `bytes`.

## Per-tool completion

| Tool | Rows closed | Residual | Tests (collected) | Gate | Verify report |
|---|---|---|---|---|---|
| x64dbg | 44/44 (incl. Patches window, Labels/Comments, Advanced tab, restart, step_count, animate_start/stop, get_trace_record, conditional-BP) | none | 30 | 30/30 | verify-x64dbg.md |
| Cutter | 46/46 (debugger UI, project/session, advanced search, static NO-CONTROLs, ESIL/flags/config) | none | 53 | 53/53 | verify-cutter.md |
| Ghidra | 87/87 (Data Type Manager, Program Tree, bookmarks/refs, remove_label) | none | 100 | 100/100 | verify-ghidra.md |
| Frida | all (attach fix, 4 registrations, 10 instrumentation rows, 6 residual: Stalker cfg/rpc_call/post_message/eternalize/cancellable/load_module) | none | 58 | 58/58 | verify-frida.md |
| Sandbox/Process | 13 registrations + GUI (sandbox config, process primitives, DEAD-CONTROLs) | none | 70 | 70/70 | verify-sandbox-process.md |
| Hex editor | Search-and-Replace, sandbox reroute, 13 drift-reroutes, annotated export | none | 63 | 63/63 | verify-hex-editor.md |
| **Total** | — | — | **374** | **374/374** | — |

## Test integrity

- Every remediated row has a REAL, falsifiable gate: reverting/breaking the
  production line makes the test fail. Verifiers (per-tool) independently
  confirmed **zero non-gate tests survived** after review.
- One actively-harmful test defect was found and removed: a broken `autouse`
  fixture in the frida suite that forced a real Frida self-attach on every test.
- Test doubles appear ONLY at genuine external boundaries that cannot run in the
  sandbox (r2pipe subprocess, live Frida device, Ghidra RPC, x64dbg plugin
  pipe); the bridge/dispatch/GUI-wiring logic under test executes for real.

## Gate results

Scope note: the tree also carries unrelated uncommitted work in
`providers/local_transformers.py` (HuggingFace token/model-config, NOT part of
this remediation) which has 3 pre-existing property-docstring ruff findings on
lines this remediation never touched. The counts below are for the
bridge-completeness remediation files only.

- **ruff**: 0 findings across all remediation `src/` + all test files.
- **basedpyright**: 0 across all remediation `src/`; 0 across all 6 test dirs.
  (Re-verified 2026-07-01; caught + fixed a self-introduced regression —
  removing the shadowing `_populate_template_combo` from `PatternEditorMixin`
  left two call sites the type checker could no longer resolve; fixed by
  declaring the host-provided method as a `Callable[[], None]` attribute
  annotation, no suppression.)
- **pydoclint / pydocstyle**: 0 across all remediation `src/` + tests.
- **Docker sandbox pytest** (`tests/test_bridge_completeness/`, Windows container,
  `-p no:timeout -p no:randomly -p no:sugar`, run **per-directory** to contain
  Frida's native `on_detach` access-violation crash): **374/374 PASS** —
  cutter 53/53, ghidra 100/100, x64dbg 30/30, sandbox_process 70/70,
  hex_editor 63/63, frida 58/58. Zero failures, zero errors.

## Notes

- HxD (`hxd_panel.py`) was out of audit scope and is being removed by the user
  in parallel; NO remediation work touched it — all hex work is in the native
  `ui/panels/hex_editor/` package + `bridges/hex_editor.py`.
- A test dir naming defect was corrected: `sandbox-process` (invalid Python
  package name) → `sandbox_process` with `__init__.py`, matching the other dirs.
