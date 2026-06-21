# Test-Gate Audit Rubric (shared)

## Mission

A test is only valuable if it is a **production-release functionality gate**:
it MUST turn red when Intellicrack can no longer perform the real operation it
claims to verify. A test that stays green regardless of whether the underlying
functionality works **is not a test** and must be flagged.

The governing question for every test:

> "If the real Intellicrack functionality under test were broken, deleted, or
> made to return garbage, would this test FAIL?"

If the answer is "no" or "not necessarily", the test is a **non-gate** and must
be flagged.

## What you must do per file

1. Read the **entire** file with the Read tool — never excerpts, never skim.
2. For tests whose gating strength is unclear, read the relevant **source
   module** under `src/intellicrack/` (or rust/hexcore, scripts/) so you can
   judge whether a real defect would actually trip the assertion. "In context"
   means: understand what the production code does and whether the test
   constrains it.
3. Classify every test function/method as **GENUINE GATE** or **NON-GATE
   (flagged)**.

## Non-gate categories (flag any that apply)

- **N1 No-assert** — test executes code but makes no assertion (or only prints
  / logs). Always green.
- **N2 Swallowed failure** — `try/except` around the operation that passes (or
  `return`/`pass`/logs) on exception, so a real failure is absorbed. Includes
  bare `except`, `except Exception`, `contextlib.suppress` around the asserted
  call.
- **N3 Skip/xfail on real failure** — `pytest.skip`/`importorskip`/`xfail`
  (non-strict) triggered by the *thing under test* being missing/unavailable,
  masking a capability that a production gate should hard-require. (Legitimate
  environment-capability skips — e.g. no admin, no loopback TCP, missing OS
  service — are NOT flagged; call those out as acceptable.)
- **N4 Tautological/vacuous** — `assert True`, `assert 1 == 1`, `assert x == x`,
  `assert isinstance(r, object)`, `assert r is not None` where `r` provably
  cannot be None, asserting a literal you just defined.
- **N5 Mock-validates-mock** — the unit under test is itself mocked/patched, so
  the assertion only proves the mock returned its configured value or that the
  test called its own mock (`mock.assert_called*` with no real-side effect).
- **N6 Vacuously-satisfiable conditional** — assertion guarded by `if r:` /
  `if r is not None:` / iterating a possibly-empty collection, so an empty or
  falsy real result silently skips the check.
- **N7 Accepts-both-outcomes** — assertion passes on success AND on
  failure/error sentinel, e.g. `assert r in (expected, None)`,
  `assert r is None or r.ok`, `assert status in ("ok", "error")`.
- **N8 Existence-only for a behavior test** — only checks `hasattr` / `callable`
  / return type / dict has key, when the test name/intent claims to verify
  actual behavior or a correct value.
- **N9 Log/string-presence proxy** — asserts a log line, message text, or
  printed string instead of the actual operation result/side effect.
- **N10 Self-fulfilling data** — asserts on data the test itself injected
  through a mock/fixture without the production code transforming it.

## Severity

- **CRITICAL** — test can essentially never fail regardless of source state
  (N1, N2, N4, N5, N10, unconditional skip).
- **HIGH** — fails to gate the core behavior it names (N3 masking real
  capability, N6, N7).
- **MEDIUM** — weak/partial gate (N8, N9) — gates something trivial but not the
  claimed behavior.
- **LOW** — real gate but narrower/weaker than it should be; worth hardening.

## Output file format

Write to `audit/test-gate-audit/<AREA>.md` with EXACTLY this structure:

```
# Test-Gate Audit — <AREA>

## Summary
- Files audited: N
- Test functions examined: N
- Genuine gates: N
- Flagged non-gates: N  (CRITICAL: a, HIGH: b, MEDIUM: c, LOW: d)

## Coverage checklist
<one row per file proving it was read>
- [x] relative/path/test_x.py — gates: G, flagged: F

## Flagged tests

### relative/path/test_file.py
#### `test_name` — SEVERITY — category(Nx)
- **Location:** relative/path/test_file.py:LINE
- **Current behavior:** what the test actually does
- **Why it is not a gate:** the specific reason a real defect would not fail it
- **Recommended fix:** the concrete assertion / change that makes it gate real functionality

## Acceptable skips (not flagged)
- relative/path:LINE `test_name` — environment-capability skip, why legitimate
```

Rules for the report:
- Use real line numbers from the files.
- Detailed entries ONLY for flagged tests; genuine gates are just counted per
  file in the coverage checklist (no per-gate prose).
- Be precise and conservative: only flag a test if you can name the concrete
  reason a real defect would not fail it. Do not pad findings.
- Parametrized tests / fixtures count once per test function.
