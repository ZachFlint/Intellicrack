# Remediation Verification Protocol (10-agent fan-out)

You are an **adversarial test-reviewer**. A prior remediation effort claims it
converted every WEAK / FAKE / NO-COVERAGE finding in the test-coverage audit
into a **REAL falsifiable gate**. Your job is to **independently verify that
claim** for your assigned slice of findings — and to **catch any that are still
not done**. Be skeptical. "A test exists" is not proof. Default to NOT_RESOLVED
unless you can prove otherwise.

This is **read-only**. Do **NOT** edit any source, test, or audit file. Your
only writes are (1) your own report file and (2) nothing else.

---

## Step 1 — Enumerate your findings (authoritative)

Read your assigned section file(s) / row-range (given in your task prompt). In
the Operation Inventory table(s), **every row whose Verdict/Status is NOT a real
gate is one finding you must verify.** Non-real verdicts include any of:
`WEAK GATE`, `FAKE GATE`, `NO COVERAGE`, `PARTIAL`, `WEAK`, `UNKNOWN`,
`Not tested`, `No tests`, `Zero tests`, `No dedicated test`, empty/`—` test
columns, or any verdict qualified with a gap. Rows already marked plain
`REAL GATE` / `REAL` (no qualifier) are **out of scope** — skip them.

Enumerate them yourself from the source table. Do not trust any pre-built list;
build your own so nothing is missed. Count them.

## Step 2 — Verify each finding against the CURRENT test tree

For each finding, search `tests/` for the test(s) that now gate that exact
operation. Use rg/Glob/Read. The remediation added many files; likely homes:

- New wave files: `tests/**/test_*_wave2a/2b/2c/2d/wave4*.py`,
  `tests/test_credentials/test_oauth_section11_gates.py`,
  `tests/test_bridges/test_ghidra_wave2a_*.py`, `test_cutter_wave2a_*.py`,
  `test_x64dbg_wave2b_*.py`, `test_frida_wave2c_*.py`,
  `tests/test_providers/test_*_offline_wave2d.py`, `test_local_model_classify_wave2d.py`,
  `tests/test_ui/test_realcov_p3_ui_zero_coverage.py`,
  `tests/test_core/test_types_exceptions_wave4.py`, `test_p3_orch_script.py`,
  `tests/test_hexpat/test_hexpat_tails_wave4.py`,
  `tests/test_bridges/test_hex_editor_bridge_methods_wave4.py`,
  `test_named_pipe_client_errors_wave2d.py`.
- Strengthened existing files (Wave 1/3): `test_elevation.py`, `test_hexpat_core.py`,
  `test_sandbox_bridge.py`, `test_providers_cloud_audit1.py`, `test_process_audit7.py`,
  `test_selection_dispatch.py`, `test_sandbox_route.py`, plus Rust
  `src/intellicrack-hexcore/src/**` `#[cfg(test)]` modules (for §13).

## Step 3 — Classify each finding (the rubric)

A gate counts as a **REAL GATE** only if ALL hold:
- It asserts **exact values** against an **INDEPENDENT oracle** — pefile,
  capstone, hashlib, `binascii.crc32`, `struct.unpack`, a NIST/known-answer
  vector, a known constant, or the language/format spec — **never** a value
  recomputed by the same production code (no tautology).
- A **nameable one-line production mutation** would turn it **red**.
- It does **NOT** use any forbidden pattern (below).

**Forbidden / does-NOT-count patterns** (if the only "gate" is one of these, the
finding is NOT resolved):
- `MagicMock` / `AsyncMock` / `unittest.mock.patch` applied to the **code under
  test** (mocking the SUT or its decision dependency).
- Asserting only: no-exception, `isinstance`, `len(x) > 0`, `is not None`,
  key-existence, or a docstring/substring check.
- `pytest.raises(...)` **without** `match=`.
- `pytest.skip` that hides a real failure (capability skips for genuinely
  unavailable kernel/hardware features are acceptable).
- Any inline suppression: `# noqa`, `# type: ignore`, `# pyright: ignore`.

**Verdicts you assign:**
- `RESOLVED` — a real gate now exists. You MUST cite `test_file:line`, name the
  **independent oracle**, and name the **one-line mutation** it catches.
- `RED_BY_DESIGN` — a correct gate exists but is intentionally **red** because it
  exposes a real production defect (PD-002..PD-006, see below). This counts as
  done (the gate is correct; src is left unfixed per directive). Cite the test
  and the PD id.
- `NOT_RESOLVED` — no real gate exists yet, OR the only coverage is a forbidden
  pattern. This is the critical output. Cite what you found (or "nothing") and
  state the one-line missing assertion that would make it real.

## Red-by-design production defects (gates correctly RED — count as done)

- **PD-002** `set_thread_context` drops dr0–dr3 debug registers.
- **PD-003** ten GhidraBridge methods whose remote Jython snippet ends in an
  if/else block never capture their result (`prepare_remote_script` needs a
  trailing expression).
- **PD-004** `objc_hook_method` / `java_hook_method` log with the reserved
  structlog kwarg `method_name=` → TypeError on first line.
- **PD-005** `get_fiber_data` computes `has_fiber = fiber_data != 0` but TEB+0x20
  is the FiberData/Version union → misclassifies ordinary threads as fibers.
- **PD-006** highlighter operator/comment rule ordering + def/class full-match
  formatting.

Full detail: `audit/PRODUCTION-DEFECTS.md`.

## Step 4 — Write your report + return a summary

Write `audit/verification/group-<NN>-report.md` (NN = your group number) with a
table: `| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation) |`
one row per finding, `Now` ∈ {RESOLVED, RED_BY_DESIGN, NOT_RESOLVED}. List every
NOT_RESOLVED finding again in a dedicated "STILL OPEN" section with specifics.

Then **return as your final message** exactly this block (machine-readable):

```
GROUP <NN> SUMMARY
sections: <e.g. 11 ops #1-64>
total_findings: <N>
resolved: <R>
red_by_design: <D>
not_resolved: <U>
STILL_OPEN:
- <operation> (<source:line>) :: <why not real> :: <missing assertion>
- ...
```

If `not_resolved` is 0, write `STILL_OPEN: none`. Accuracy over optimism — a
false RESOLVED is worse than flagging a borderline one as NOT_RESOLVED.
