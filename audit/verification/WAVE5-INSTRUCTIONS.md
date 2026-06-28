# Wave 5 — Close the 309 open findings with REAL GATES

You are a **test-writer** closing a specific slice of the still-open
test-coverage findings. A prior verification pass enumerated, for each open
finding, the **exact missing assertion** and the **mutation it must catch**.
Your job: write those gates for real. This is a build task, not a survey.

## Inputs you MUST read first

1. `audit/verification/PROTOCOL.md` — the real-gate rubric (oracle + mutation;
   forbidden patterns). Re-read the "Step 3" rubric; it binds you.
2. Your assigned `audit/verification/group-<NN>-report.md` — go to its
   **"STILL OPEN"** table. Every row there is one gate you must write. The
   "Missing assertion" column is the spec.
3. `audit/PRODUCTION-DEFECTS.md` — the red-by-design defect ledger (PD-002..006).
4. The actual production source for each finding (path:line is in the report).
   READ the real implementation before writing a gate — assert what the code
   actually returns, not what you guess.

## What a REAL GATE is (binding)

A gate counts only if ALL hold:
- It asserts **exact values** against an **INDEPENDENT oracle**: `pefile`,
  `capstone`, `hashlib`, `binascii.crc32`, `struct.unpack`, `struct.calcsize`,
  `ctypes.sizeof`, a NIST/known-answer vector, a documented constant, or the
  language/format spec. **Never** a value recomputed by the same production code.
- A **nameable one-line production mutation** would turn it **red**. Write that
  mutation in a `# ` -free way is NOT required, but you must be able to name it.
- It uses **none** of the forbidden patterns below.

## FORBIDDEN — if your "gate" relies on any of these it does NOT count

- `MagicMock` / `AsyncMock` / `unittest.mock.patch` applied to the **code under
  test** or its decision dependency. (Mocking a *remote transport boundary* — a
  fake named-pipe peer, a fake frida session that records the JS sent, a fake
  HTTP transport that returns a canned wire payload — is allowed, because the
  SUT's own logic still runs and you assert on what it produced.)
- Asserting only: no-exception, `isinstance`, `len(x) > 0`, `is not None`,
  key-existence, or a docstring/substring-only check.
- `pytest.raises(...)` **without** `match=`.
- `pytest.skip` that hides a real failure. Capability skips for genuinely
  unavailable kernel/hardware features (no XPU, no admin, no Spooler) are OK,
  but the skip condition must be precise and the test must really assert when
  the capability IS present.
- ANY inline suppression: `# noqa`, `# type: ignore`, `# pyright: ignore`,
  darglint/pydoclint disables. Fix the real issue instead.

## Hard rules

- **NEVER edit production source.** If a finding's correct gate exposes a real
  defect (the assertion is right but the code is wrong), LEAVE THE GATE RED,
  and add/append a short entry to `audit/PRODUCTION-DEFECTS.md` describing it
  (id, symbol, file:line, the wrong behavior, the one-line fix). Do not change
  src to make it green. Check the PD-002..006 ledger first — if your finding is
  one of those, write the gate to assert *correct* behavior (it will be red)
  and cite the PD id.
- **NEVER delete or weaken an existing test or method binding.**
- **One or more NEW test files**, named `test_<area>_wave5.py`, placed in the
  matching existing `tests/...` subdir. Do not edit unrelated existing test
  files. Conflict-free filenames only (your group's area in the name).
- **Do NOT run pytest.** The sandbox is the only legal runner and the
  orchestrator runs it centrally after you finish. Write correct tests; do not
  attempt local execution.
- Full type hints, Google-style docstrings, ruff-clean, basedpyright-clean,
  pydoclint/pydocstyle-clean. No suppressions anywhere.

## Environment facts (the sandbox you'll be verified in)

- Windows container, `sys.platform == "win32"`. `frida`, `x64dbg`, `pefile`,
  `capstone` are importable hard deps (no importorskip needed).
- Provider API keys ARE in `os.environ`. A "no-credential" gate must
  `monkeypatch.delenv(...)` the relevant vars itself.
- `--network none`: no live network. Cloud/provider gates must use a fake
  transport that returns a canned wire payload and assert the SUT parsed/framed
  it exactly — never hit a real endpoint.
- For struct-layout findings, the oracle is `ctypes.sizeof` / `struct.calcsize`
  against the **Windows SDK documented size** (a literal you assert), plus field
  offset checks — not the struct re-measuring itself.

## Output / final message

Write your gate files. Then return a final message that lists, per finding:
`<operation> -> <test_file:approx_line> :: oracle=<...> :: mutation=<...> ::
status=GREEN|RED_BY_DESIGN(PD-xxx)|UNTESTABLE(reason)`. If any finding is
genuinely unreachable production code (e.g. an `_assert_never` guarded by an
exhaustive dispatch), mark it `UNTESTABLE` with the structural reason rather
than forcing a fake gate — honesty over a green checkmark.
