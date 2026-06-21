export const meta = {
  name: 'test-gate-remediation',
  description: 'Harden 99 flagged test files into real falsifiable production gates: per-file fixer + adversarial reviewer',
  phases: [
    { title: 'Fix', detail: 'one fixer per flagged test file: harden / delete / red-prod-defect gate + self-lint (ruff/pydoclint/pydocstyle)' },
    { title: 'Review', detail: 'adversarial static re-check that each rewritten test is a real falsifiable gate' },
  ],
}

function coerceFiles(a) {
  let v = a
  if (typeof v === 'string') {
    try { v = JSON.parse(v) } catch (_e) { v = [] }
  }
  if (v && !Array.isArray(v) && Array.isArray(v.files)) v = v.files
  return Array.isArray(v) ? v : []
}
const FILES = coerceFiles(args)
log(`args typeof=${typeof args}; resolved FILES=${FILES.length}`)

const FALSIFIABILITY_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    src_file: { type: 'string', description: 'Production file (relative path) whose behavior the test gates' },
    mutation_search: { type: 'string', description: 'Exact UNIQUE substring currently present in src_file' },
    mutation_replace: { type: 'string', description: 'Replacement that makes the behavior wrong/garbage while keeping the file importable and syntactically valid' },
    covering_test: { type: 'string', description: 'pytest nodeid that MUST turn RED under the mutation, e.g. tests/x/test_y.py::TestZ::test_w' },
    expected_baseline: { type: 'string', enum: ['green', 'expected-red'], description: 'green = test passes on current correct src; expected-red = real production defect, stays red' },
    note: { type: 'string' },
  },
  required: ['src_file', 'mutation_search', 'mutation_replace', 'covering_test', 'expected_baseline'],
}

const FIX_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    file: { type: 'string' },
    summary: { type: 'string', description: 'What was changed and why, in 2-4 sentences' },
    findings_addressed: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          test: { type: 'string' },
          severity: { type: 'string' },
          category: { type: 'string' },
          action: { type: 'string', enum: ['hardened', 'deleted', 'red-prod-defect'] },
          oracle: { type: 'string', description: 'The independent oracle used to compute expected value (hashlib/zlib/struct/pefile/capstone/difflib/hand-decoded field/known math). For deletions: "n/a".' },
          deletion_sibling: { type: 'string', description: 'For action=deleted: the stronger sibling test (nodeid) that already gates this behavior' },
          falsifiability: FALSIFIABILITY_SCHEMA,
        },
        required: ['test', 'action', 'oracle'],
      },
    },
    production_defects: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          src_file: { type: 'string' },
          line: { type: 'integer' },
          symbol: { type: 'string' },
          expected: { type: 'string' },
          actual: { type: 'string' },
          red_test: { type: 'string' },
        },
        required: ['src_file', 'expected', 'actual', 'red_test'],
      },
    },
    ruff_clean: { type: 'boolean' },
    pydoclint_clean: { type: 'boolean' },
    pydocstyle_clean: { type: 'boolean' },
    lint_evidence: { type: 'string', description: 'Exact final tool output lines proving zero findings' },
    notes: { type: 'string' },
  },
  required: ['file', 'summary', 'findings_addressed', 'ruff_clean', 'pydoclint_clean', 'pydocstyle_clean'],
}

const REVIEW_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    file: { type: 'string' },
    overall: { type: 'string', enum: ['pass', 'fail'] },
    per_finding: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          test: { type: 'string' },
          verdict: { type: 'string', enum: ['real-gate', 'not-a-gate', 'deletion-justified', 'red-prod-defect-valid'] },
          mutation_would_flip: { type: 'boolean', description: 'Traced: does the fixer mutation actually make this test fail?' },
          oracle_independent: { type: 'boolean', description: 'Is the expected value computed independently (not injected by the test)?' },
          reason: { type: 'string' },
        },
        required: ['test', 'verdict', 'reason'],
      },
    },
    ruff_clean: { type: 'boolean' },
    pydoclint_clean: { type: 'boolean' },
    pydocstyle_clean: { type: 'boolean' },
    problems: { type: 'array', items: { type: 'string' } },
    notes: { type: 'string' },
  },
  required: ['file', 'overall', 'per_finding', 'ruff_clean', 'pydoclint_clean', 'pydocstyle_clean'],
}

const REAL_GATE_DEF = `A REAL GATE (definition of done per test):
- Asserts the actual operation's result/side-effect against an INDEPENDENT ORACLE: recompute the expected value a DIFFERENT way (hashlib/zlib/struct/pefile/capstone/difflib/known math, a hand-decoded real binary field, the RFB/PE/ELF spec, etc.). NEVER assert data the test itself injected.
- Drives REAL Intellicrack code end-to-end against REAL inputs (real PE/ELF/Mach-O fixtures, real bridges, real engines). Doubles are allowed ONLY at the external transport boundary (network/pipe/clipboard/UAC/external-tool stdout); NEVER mock the unit under test.
- Is FALSIFIABLE: if the production behavior were broken/deleted/made to return garbage, the test FAILS.
- Eliminates the flagged anti-pattern entirely. Forbidden: N1 no-assert/"did not raise"; N2 swallowed-exception pass; N3 skip/xfail masking a real capability; N4 tautology (assert True, assert r is not None where r cannot be None); N5 mock-validates-mock; N6 if-result-guarded / empty-collection vacuous assertions; N7 accepts-both-outcomes disjunctions; N8 existence/type-only checks for behavior tests; N9 source-text/inspect.getsource substring proxies; N10 self-fulfilling injected data.`

const DECISION_RULES = `PER-FINDING DECISION RULES:
1. PRODUCTION DEFECT: if writing the correct gate reveals the production code is actually broken (e.g. a setter hardcoded to "return True"), write the correct falsifiable gate ANYWAY (it will stay RED) and DO NOT modify any src/ file. Record it in production_defects (src_file, line, expected vs actual, the now-red test) and set action="red-prod-defect", falsifiability.expected_baseline="expected-red".
2. REDUNDANT DUPLICATE: if a flagged test is an exact weaker duplicate of a stronger sibling that already gates the same behavior, DELETE it (action="deleted") and name the sibling in deletion_sibling. Delete for NO other reason.
3. OTHERWISE: harden into a real gate (action="hardened").
Legitimate environment-capability skips already marked acceptable by the audit (missing admin/QEMU/external tools/GPU/loopback/OS services, live-cloud-no-billing) STAY as skips - do not convert them to hard failures.`

const HARD_CONSTRAINTS = `HARD CONSTRAINTS (non-negotiable):
- You may edit ONLY this one test file. NEVER edit any src/ file, conftest, or other test file.
- The file must pass ruff, pydoclint, AND pydocstyle with ZERO findings. NO suppressions of any kind (no noqa, type-ignore, pyright-ignore, disable comments). Fix the real issue.
- Full type hints/annotations on every function and fixture. Google-style docstrings that EXACTLY match signatures (params, returns, raises, yields). Windows-compatible with proper platform checks (sys.platform). NO comments, NO emojis, NO TODO markers.
- You CANNOT run pytest (the harness blocks all local pytest; tests run only in a separate Docker sandbox). Do NOT attempt to run pytest/coverage. Prove falsifiability by REASONING and by providing a concrete, correct mutation plan instead.
- Write code fully basedpyright-compliant (it is batch-checked centrally afterward); precise, correct type annotations everywhere. Concretely, to avoid reportUndefinedVariable / reportUnknown* findings: IMPORT every type name you reference (e.g. \`from typing import Any\`, the real event/enum/dataclass types from their defining module); fully annotate every callback/observer parameter, lambda where possible, and non-trivial local; never leave a value at an inferred Unknown/partially-unknown type. When you register an observer or callback whose signature comes from production code, import and use that exact production type for its parameters.`

function fixerPrompt(item) {
  return `You are hardening ONE Intellicrack test file into real, falsifiable production-release gates.

YOUR FILE (you own it exclusively; fix ALL flagged tests in it): ${item.file}
Audit report with the findings: audit/test-gate-audit/${item.report}
Expected number of flagged report-entries for this file: ${item.n} (note: one entry may cover several test functions, e.g. "family (N tests)" - fix every individual test it names).

STEP 1 - READ (use the Read tool, full files, no skimming):
  a) audit/test-gate-audit/_RUBRIC.md - the standard.
  b) audit/test-gate-audit/${item.report} - locate the "### ${item.file}" heading and read EVERY "#### " finding beneath it (Location / Current behavior / Why it is not a gate / Recommended fix). These are your exact work items.
  c) ${item.file} - the entire test file.
  d) The production source the tests exercise (search src/intellicrack/, rust/hexcore/, scripts/ as needed) so you understand the real behavior and can pick an independent oracle and a correct mutation.

${REAL_GATE_DEF}

${DECISION_RULES}

${HARD_CONSTRAINTS}

STEP 2 - REWRITE every flagged test in ${item.file} per the decision rules. Edit the file IN PLACE with the Edit/Write tools. Keep all genuine (non-flagged) tests untouched. Preserve imports/fixtures other tests need.

STEP 3 - SELF-VERIFY LINT (run these; fix until each prints zero findings):
  pixi run ruff check ${item.file}
  pixi run pydoclint ${item.file}
  pixi run pydocstyle ${item.file}
Capture the final clean output into lint_evidence.

STEP 4 - FALSIFIABILITY PLAN (mandatory for every hardened and every red-prod-defect test):
  For each such test provide falsifiability = { src_file, mutation_search, mutation_replace, covering_test, expected_baseline }.
  - mutation_search MUST be an exact, unique substring that currently exists in src_file (verify by reading it).
  - mutation_replace MUST change the behavior so your hardened assertion FAILS, while keeping src_file importable and syntactically valid (flip a comparison/operator, change a returned constant/offset, drop a transform - never introduce a syntax error or break an import).
  - covering_test MUST be the precise pytest nodeid that turns RED under that mutation.
  - expected_baseline = "green" for a normal hardened test; "expected-red" only for a real production defect (rule 1).
  This plan will be executed for real in the Docker sandbox later; make it concrete and correct.

Return the structured FIX result. Be exhaustive and precise - every flagged test must appear in findings_addressed with a real oracle and (unless deleted) a falsifiability plan.`
}

function reviewerPrompt(item, fix) {
  return `You are an ADVERSARIAL test-gate reviewer. A fixer just rewrote ONE Intellicrack test file. Your job is to try to PROVE the rewrite is still NOT a real gate, and to confirm the falsifiability plan actually works. You may NOT edit any file and may NOT run pytest. Static reading + lint only.

FILE: ${item.file}
Report: audit/test-gate-audit/${item.report}
Fixer's structured claim:
${JSON.stringify(fix, null, 1)}

READ: audit/test-gate-audit/_RUBRIC.md; the "### ${item.file}" section of the report; the CURRENT (rewritten) ${item.file} in full; and the production source it exercises.

${REAL_GATE_DEF}

FOR EACH finding the fixer addressed, decide a verdict:
  - "real-gate": anti-pattern (N1-N10) is gone; the assertion checks the real operation against an INDEPENDENT oracle (NOT self-injected data, NOT a mock of the unit under test, NOT a source-text/log substring proxy); AND the fixer's mutation (apply mutation_search -> mutation_replace in src_file) would genuinely make covering_test FAIL - trace the data flow from the mutated code to the assertion and set mutation_would_flip accordingly.
  - "deletion-justified": action was delete and the named sibling truly covers the same behavior.
  - "red-prod-defect-valid": the test correctly gates real behavior and is red because src is genuinely defective (no src edit was made).
  - "not-a-gate": anything else (still tautological/guarded/both-outcomes/mock-validates-mock/source-text proxy; oracle not independent; mutation would NOT flip the assertion; or it asserts injected data).

Set oracle_independent per finding. Re-run and report: pixi run ruff check ${item.file}; pixi run pydoclint ${item.file}; pixi run pydocstyle ${item.file}.

overall = "fail" if ANY finding is "not-a-gate", any mutation_would_flip is false for a hardened/red-prod-defect test, any oracle is not independent, or any lint tool is not clean. List every concrete problem in problems[] so the fixer can repair it. Be skeptical and specific.`
}

phase('Fix')
const results = await pipeline(
  FILES,
  (item) => agent(fixerPrompt(item), { label: `fix:${item.file}`, phase: 'Fix', schema: FIX_SCHEMA, agentType: 'developer', model: 'sonnet' }),
  (fix, item) => {
    if (!fix) return null
    return agent(reviewerPrompt(item, fix), { label: `review:${item.file}`, phase: 'Review', schema: REVIEW_SCHEMA, agentType: 'test-reviewer', model: 'sonnet' })
      .then((review) => ({ file: item.file, report: item.report, n: item.n, fix, review }))
      .catch(() => ({ file: item.file, report: item.report, n: item.n, fix, review: null }))
  },
)

const done = results.filter(Boolean)
const failed = done.filter((r) => !r.review || r.review.overall === 'fail')
const prodDefects = done.flatMap((r) => (r.fix.production_defects || []).map((d) => ({ ...d, test_file: r.file })))
log(`Fix+Review complete: ${done.length}/${FILES.length} files processed; ${failed.length} flagged by reviewer; ${prodDefects.length} production defects surfaced`)

return {
  total_files: FILES.length,
  processed: done.length,
  reviewer_failed: failed.map((r) => r.file),
  production_defects: prodDefects,
  results: done,
}
