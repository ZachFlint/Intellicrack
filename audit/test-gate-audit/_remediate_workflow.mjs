export const meta = {
  name: 'test-gate-remediation',
  description: 'Harden weak test-gate findings into real falsifiable gates, one wave (test group) per run',
  phases: [
    { title: 'Fix', detail: 'one sonnet fixer per file rewrites all its findings into real gates / deletions / red-prod-defect gates' },
    { title: 'Quality', detail: 'independent ruff/basedpyright/pydoclint/pydocstyle gate per file' },
    { title: 'Repair', detail: 'sonnet repair for any file the quality gate flagged dirty' },
    { title: 'Green', detail: 'one batched serial sandbox run over the wave\'s changed files' },
    { title: 'Adversarial', detail: 'independent falsifiability re-check on a sample of done files' },
  ],
}

const RUBRIC = `A REAL GATE (definition of done for every test you touch):
- Asserts the actual operation's result/side-effect against an INDEPENDENT ORACLE: recompute the
  expected value a DIFFERENT way (hashlib / zlib.crc32 / struct.unpack / pefile / capstone / difflib /
  known math / a hand-decoded real binary field). NEVER assert a value the test itself injected.
- Drives REAL Intellicrack code end-to-end against REAL inputs. Use the committed real-binary helpers:
  from tests._helpers.real_binaries import resolve_real_pe_exe, resolve_real_pe_dll, resolve_real_pe_dlls,
  load_real_elf, load_real_macho. resolve_real_pe_* return real Windows System32 PEs (Windows-only -
  guard with the same platform/skip the helper already raises); load_real_elf/load_real_macho return
  committed cross-platform ELF/Mach-O fixtures.
- Doubles are allowed ONLY at the external transport boundary (network socket / OS pipe / clipboard /
  UAC elevation / external-tool stdout). NEVER mock, monkeypatch, or replace the unit under test itself.
- Must be FALSIFIABLE: there must exist a concrete one-line mutation to the PRODUCTION code the test
  covers that makes the assertion FAIL. You DOCUMENT that mutation (static proof) - you do NOT run it.
- Eliminate the flagged anti-pattern entirely: no no-assertion/"did not raise" (N1); no swallowed-
  exception pass (N2); no skip/xfail masking a real capability (N3); no tautology asserting injected
  data (N4); no mock-validates-mock (N5); no if-result-guarded or empty-collection vacuous assertion
  (N6); no accepts-both-outcomes disjunction (N7); no existence/type-only check for a behavior test
  (N8); no source-text/inspect.getsource substring proxy (N9); no self-fulfilling injected data (N10).

FORBIDDEN WEAK PATTERNS (an adversarial reviewer WILL reject the test and bounce it back if you use any):
- NO substring/"X in big_string" OR-chains as a correctness proxy. If the output is JSON, json.loads it
  and assert the STRUCTURE (exact keys/values at the right nesting), not that a word appears somewhere.
  Common English words ("bytes", "Red", "pe") appear incidentally and pass under partial breakage.
- NO oracle inputs that collapse to identity. XOR keys that cancel (k1^k2^k3 == 0), add+sub that net to
  zero, or any payload where expected == input means a NO-OP implementation passes. Choose inputs whose
  expected result is DISTINCT from the input and from a trivial constant.
- NO capability-guarded assertions where the fixture never triggers the meaningful branch
  (e.g. 'if oracle_has_imports: assert len>0 else: assert ==[]' on a fixture that has no imports). Pick a
  REAL input that exercises the capability (e.g. resolve_real_pe_dll() for a PE WITH imports/exports) so
  the strong assertion actually runs; skip only on a genuine platform/capability gap.
- NO range/membership checks that admit the initial/default state. 'assert cursor in range(50)' passes a
  no-op that leaves cursor at its default 0. Use inputs that exclude the default and assert the value is
  one actually produced by the operation.
- NO narrow exception filters in "does not raise" tests. If you must catch, catch BaseException and record
  it so the assertion is meaningful; far better, assert a concrete post-condition instead of non-raising.
- NO str()-of-collection substring fallbacks. Navigate the real structure and assert exact field values.`

const DECISION = `PER-FINDING DECISION RULES:
1. PRODUCTION DEFECT - if writing the correct gate reveals the PRODUCTION code is actually broken
   (e.g. a method hardcoded to return True), write the correct falsifiable gate ANYWAY (it stays RED)
   and DO NOT modify any src/ file. Record it in your status JSON prod_defects[] (src_file, line,
   expected vs actual, the now-red test name). A red test here is the CORRECT, expected outcome.
2. REDUNDANT DUPLICATE - if a flagged test is an exact WEAKER duplicate of a stronger sibling that
   already gates the same behaviour, DELETE it and name the covering sibling test. Delete for NO other
   reason. (Many findings' recommendation already say "Remove this test - covered by <sibling>".)
3. OTHERWISE - harden into a real gate per the rubric.`

const CONSTRAINTS = `HARD CONSTRAINTS:
- Edit ONLY this one test file (main tree, in place). Do NOT touch any other test file or any src/ file.
- NEVER run pytest/python -m pytest/coverage locally - blocked by hook and unnecessary (static proof).
- Run quality tools scoped to THIS file on the host and fix every finding until all four are clean:
    pixi run ruff check <file>
    pixi run basedpyright <file>
    pixi run pydoclint <file>
    pixi run pydocstyle <file>
  ALWAYS pass the explicit path to YOUR ONE test file. NEVER run a command that touches src/ or the whole
  repo: do NOT run 'just lint', 'just lint-fix', 'just typecheck', 'ruff format', 'ruff check --fix' with
  no path, 'pyupgrade', or any unscoped formatter. Those reformat src/ and are a forbidden src edit. If you
  need to auto-fix lint, use 'pixi run ruff check --fix <your-test-file>' with the explicit path ONLY.
  ZERO findings required. NO suppressions of any kind (no noqa, type-ignore, pyright-ignore, disable
  comments). Fix the real issue. NEVER weaken/edit locked configs (pyproject basedpyright/pydoclint/
  pydocstyle sections).
- Full type hints/annotations everywhere. Google-style docstrings that EXACTLY match signatures
  (params, returns, raises, yields). Windows-compatible with proper platform guards. No comments,
  no emojis, no TODO markers.
- Legitimate environment-capability skips the audit already accepts (missing admin/QEMU/external
  tools/GPU/loopback/OS services, live-cloud-without-billing) STAY as skips - do not convert those to
  hard failures.
- Do NOT weaken an assertion just to make a real production defect pass (rule 1 governs that).`

const FIX_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['file', 'findings_addressed', 'prod_defects', 'deletions', 'self_quality', 'status_written', 'notes'],
  properties: {
    file: { type: 'string' },
    findings_addressed: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['id', 'test', 'action', 'oracle', 'documented_mutation'],
        properties: {
          id: { type: 'string' },
          test: { type: 'string' },
          action: { type: 'string', enum: ['hardened', 'deleted', 'red-prod-defect'] },
          oracle: { type: 'string', description: 'the independent oracle used, or deletion sibling' },
          documented_mutation: { type: 'string', description: 'the one-line src mutation that turns this test red' },
        },
      },
    },
    prod_defects: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['src_file', 'line', 'expected', 'actual', 'red_test'],
        properties: {
          src_file: { type: 'string' }, line: { type: 'integer' },
          expected: { type: 'string' }, actual: { type: 'string' }, red_test: { type: 'string' },
        },
      },
    },
    deletions: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['test', 'covered_by'],
        properties: { test: { type: 'string' }, covered_by: { type: 'string' } },
      },
    },
    self_quality: {
      type: 'object', additionalProperties: false,
      required: ['ruff', 'basedpyright', 'pydoclint', 'pydocstyle'],
      properties: {
        ruff: { type: 'string', enum: ['pass', 'fail'] },
        basedpyright: { type: 'string', enum: ['pass', 'fail'] },
        pydoclint: { type: 'string', enum: ['pass', 'fail'] },
        pydocstyle: { type: 'string', enum: ['pass', 'fail'] },
      },
    },
    status_written: { type: 'boolean' },
    notes: { type: 'string' },
  },
}

const QUALITY_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['file', 'ruff', 'basedpyright', 'pydoclint', 'pydocstyle', 'clean', 'diagnostics'],
  properties: {
    file: { type: 'string' },
    ruff: { type: 'string', enum: ['pass', 'fail'] },
    basedpyright: { type: 'string', enum: ['pass', 'fail'] },
    pydoclint: { type: 'string', enum: ['pass', 'fail'] },
    pydocstyle: { type: 'string', enum: ['pass', 'fail'] },
    clean: { type: 'boolean' },
    diagnostics: { type: 'string' },
  },
}

const GREEN_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['command', 'exit_code', 'passed', 'failed', 'errors', 'skipped', 'failing_tests', 'summary'],
  properties: {
    command: { type: 'string' },
    exit_code: { type: 'integer' },
    passed: { type: 'integer' }, failed: { type: 'integer' },
    errors: { type: 'integer' }, skipped: { type: 'integer' },
    failing_tests: { type: 'array', items: { type: 'string' } },
    summary: { type: 'string' },
  },
}

const ADV_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['file', 'falsifiable', 'reasoning', 'weak_tests'],
  properties: {
    file: { type: 'string' },
    falsifiable: { type: 'boolean' },
    reasoning: { type: 'string' },
    weak_tests: { type: 'array', items: { type: 'string' } },
  },
}

function statusKey(file) {
  return file.replace(/^tests[\/\\]/, '').replace(/\.py$/, '').replace(/[\/\\]/g, '__')
}

function fixerPrompt(file, findings, statusPath, contextNote) {
  const findingsText = findings.map((f, i) =>
    `[${i + 1}] id=${f.id}  test=${f.test}  line=${f.line}  category=${f.category}  severity=${f.severity}` +
    (f.why_not_gate ? `\n    why it is NOT a gate: ${f.why_not_gate}` : '') +
    (f.recommendation ? `\n    audit recommendation: ${f.recommendation}` : '')).join('\n\n')
  return `You are hardening ONE test file in the Intellicrack repo (cwd = D:/Intellicrack) into real,
falsifiable production-release gates. You own exactly this file and nothing else.

FILE: ${file}

FINDINGS TO FIX IN THIS FILE (${findings.length}):
${findingsText}

The COMPLETE audit detail for every finding in this file - full "why it is not a gate" rationale and the
audit's recommended fix - is in audit/test-gate-audit/_worklist.json under the JSON key "${file}". Read
that entry first if any finding above is truncated; it is the authoritative description.
${contextNote ? `\nWAVE CONTEXT (applies to this file):\n${contextNote}\n` : ''}

${RUBRIC}

${DECISION}

${CONSTRAINTS}

PROCEDURE:
1. Read ${file} in full. Read the production source each flagged test covers (follow the test's
   imports into src/intellicrack/...). Understand the REAL behaviour being gated.
2. For EACH finding above, apply the decision rules. When hardening, replace the weak assertion with
   one that drives the real code against a real input and checks the result against an INDEPENDENT
   oracle. Prefer the audit recommendation when it is sound; improve on it when you can make a stronger
   gate. Keep all OTHER (non-flagged) tests in the file intact unless a flagged one is a duplicate of one.
3. After editing, run the four quality tools scoped to this file and fix until ALL are clean (zero
   findings, no suppressions).
4. Write a status record to ${statusPath} as JSON with keys: file, findings_addressed (list of
   {id, test, action, oracle, documented_mutation}), prod_defects, deletions, self_quality, notes.
   documented_mutation must name the concrete one-line change to the covered PRODUCTION code that would
   make the new assertion FAIL (this is your static falsifiability proof).
5. Return the FIX_SCHEMA object describing exactly what you did. status_written must be true.

Your returned text is consumed as structured data, not shown to a human. Be precise and truthful: if a
finding is a real production defect, say so (action=red-prod-defect) and do NOT edit src.`
}

function qualityPrompt(file) {
  return `Independently re-run the quality gate on ONE already-edited test file and FIX every finding.
cwd = D:/Intellicrack. Edit ONLY this file.

FILE: ${file}

Run each, scoped to this file, and fix every finding until all four are clean (zero findings, no
suppressions of any kind - fix the real issue):
  pixi run ruff check ${file}
  pixi run basedpyright ${file}
  pixi run pydoclint ${file}
  pixi run pydocstyle ${file}

Do NOT weaken or change any test assertion or test behaviour - fix only lint/type/doc issues (unused
imports, missing annotations, docstring mismatches, etc.). Re-run until every tool is clean. Report
pass/fail per tool, clean = all four pass, and put any finding you could not resolve in diagnostics.
NEVER run 'just lint', 'just lint-fix', 'just typecheck', 'ruff format', or any unscoped command that
touches src/ or the whole repo - those reformat src/ and are a forbidden src edit. Pass the explicit path
to THIS one test file on every command. Return the QUALITY_SCHEMA object reflecting the FINAL state.`
}

function refixPrompt(file, weakTests, reasoning) {
  return `An adversarial reviewer found that these tests in ONE file are NOT genuinely falsifiable and must
be re-hardened. cwd = D:/Intellicrack. Edit ONLY this file. NEVER edit any src/ file.

FILE: ${file}
NOT-FALSIFIABLE TESTS: ${weakTests.join(', ')}

REVIEWER REASONING (the exact weakness to eliminate):
${reasoning}

${RUBRIC}

Re-harden ONLY the listed tests into real gates that FAIL under the realistic breakage the reviewer
described. Keep every other test untouched. If a listed test is red because it reveals a real PRODUCTION
defect, write the correct strong gate anyway (it stays red) and record the defect in the status JSON; do
NOT edit src. After editing, run all four quality tools scoped to this file and fix until clean (no
suppressions). Update audit/test-gate-audit/remediation/ status JSON for this file. Return the
QUALITY_SCHEMA object (clean must be true).`
}

function advPrompt(file, findings) {
  const names = findings.map((f) => f.test).join(', ')
  return `Adversarially re-check that the rewritten gates in ONE test file are genuinely FALSIFIABLE.
cwd = D:/Intellicrack. Do NOT edit anything. Do NOT run pytest.

FILE: ${file}
Formerly-weak tests now claimed hardened/deleted: ${names}

For each formerly-weak test that still exists in the file: read it and the production code it covers, then
construct a CONCRETE realistic breakage of that production code (wrong return value, deleted branch,
off-by-one, garbage output) and reason whether the test's assertions would actually FAIL under it. A test
that would still pass under a realistic breakage is NOT falsifiable. Also reject any test that asserts only
existence/type/truthiness, asserts data it injected itself, accepts both outcomes, or guards its assertions
behind if-result. falsifiable = true ONLY if every remaining formerly-weak test would go red under a real
breakage. List any test that fails this bar in weak_tests. Return the ADV_SCHEMA object.`
}

// ---- driver ----
const input = typeof args === 'string' ? JSON.parse(args) : args
const group = input.group
const files = input.files
const waveContext = input.context || ''
const greenFlags = input.greenFlags ? `${input.greenFlags} ` : ''
const fileEntries = Object.entries(files)
log(`Wave ${group}: ${fileEntries.length} files, ${fileEntries.reduce((n, [, fs]) => n + fs.length, 0)} findings`)

phase('Fix')
const fixResults = await pipeline(
  fileEntries,
  ([file, findings]) =>
    agent(fixerPrompt(file, findings, `audit/test-gate-audit/remediation/${statusKey(file)}.status.json`, waveContext),
      { label: `fix:${statusKey(file)}`, phase: 'Fix', model: 'sonnet', schema: FIX_SCHEMA })
      .then((fix) => ({ file, findings, fix })),
  (prev) =>
    prev
      ? agent(qualityPrompt(prev.file), { label: `qa:${statusKey(prev.file)}`, phase: 'Quality', model: 'sonnet', schema: QUALITY_SCHEMA })
        .then((quality) => ({ ...prev, quality }))
      : null,
  async (prev) => {
    if (!prev) return null
    const k = statusKey(prev.file)
    let adv = await agent(advPrompt(prev.file, prev.findings), { label: `adv:${k}`, phase: 'Verify', model: 'sonnet', schema: ADV_SCHEMA })
    let refixed = false
    if (adv && !adv.falsifiable && adv.weak_tests && adv.weak_tests.length) {
      refixed = true
      await agent(refixPrompt(prev.file, adv.weak_tests, adv.reasoning), { label: `refix:${k}`, phase: 'Verify', model: 'sonnet', schema: QUALITY_SCHEMA })
      adv = await agent(advPrompt(prev.file, prev.findings), { label: `readv:${k}`, phase: 'Verify', model: 'sonnet', schema: ADV_SCHEMA })
    }
    return { ...prev, adv, refixed }
  },
)

const done = fixResults.filter(Boolean)

phase('Green')
const changedFiles = done
  .filter((r) => !(r.fix && r.fix.findings_addressed && r.fix.findings_addressed.length && r.fix.findings_addressed.every((f) => f.action === 'deleted') && r.findings.length === r.fix.findings_addressed.length))
  .map((r) => r.file)
const allFiles = done.map((r) => r.file)
const greenTargets = (changedFiles.length ? changedFiles : allFiles)
const expectedRed = done.flatMap((r) => (r.fix && r.fix.prod_defects ? r.fix.prod_defects.map((d) => d.red_test) : []))
const green = await agent(
  `Run the Intellicrack test suite for this wave's changed files INSIDE THE DOCKER SANDBOX ONLY. cwd = D:/Intellicrack.

You are STRICTLY RUN-ONLY. Do NOT edit, create, or delete any file - not a test file, not a source
file, not anything. If a test fails or errors, report it; NEVER modify code to make a test pass.

Run EXACTLY this command (call docker_sandbox directly, NOT 'just test' - the just recipe's variadic
drops the --extra-args quotes and splits the multi-file list, which fails. This direct call routes
through the container and the hook allows it):
  pixi run python -m scripts.sandbox.docker_sandbox custom ${greenFlags}--extra-args "${greenTargets.join(' ')} -p no:timeout -rA"

Then parse the result. These tests are EXPECTED to be RED because they gate real, unfixed production
defects (do NOT count them as failures of the remediation): ${expectedRed.length ? expectedRed.join(', ') : '(none)'}.
Report exit_code, passed/failed/errors/skipped counts, the full list of failing_tests (node ids), and a
summary that explicitly separates expected-red prod-defect tests from any UNEXPECTED failures/errors.
Return the GREEN_SCHEMA object.`,
  { label: `green:${group}`, phase: 'Green', model: 'haiku', schema: GREEN_SCHEMA },
)

const advResults = done.map((r) => r.adv).filter(Boolean)
const bounced = done.filter((r) => r.adv && !r.adv.falsifiable)
const refixedCount = done.filter((r) => r.refixed).length

return {
  group,
  files_total: fileEntries.length,
  files_done: done.length,
  findings_total: fileEntries.reduce((n, [, fs]) => n + fs.length, 0),
  actions: {
    hardened: done.reduce((n, r) => n + (r.fix ? r.fix.findings_addressed.filter((f) => f.action === 'hardened').length : 0), 0),
    deleted: done.reduce((n, r) => n + (r.fix ? r.fix.findings_addressed.filter((f) => f.action === 'deleted').length : 0), 0),
    red_prod_defect: done.reduce((n, r) => n + (r.fix ? r.fix.findings_addressed.filter((f) => f.action === 'red-prod-defect').length : 0), 0),
  },
  prod_defects: done.flatMap((r) => (r.fix && r.fix.prod_defects ? r.fix.prod_defects.map((d) => ({ ...d, test_file: r.file })) : [])),
  quality_dirty_after: done.filter((r) => r.quality && !r.quality.clean).map((r) => r.file),
  green: { exit_code: green ? green.exit_code : null, passed: green ? green.passed : null, failed: green ? green.failed : null, errors: green ? green.errors : null, failing_tests: green ? green.failing_tests : [], summary: green ? green.summary : 'no-green' },
  adversarial: { reviewed: advResults.length, refixed: refixedCount, still_bounced: bounced.map((r) => ({ file: r.file, weak_tests: r.adv.weak_tests, reasoning: r.adv.reasoning })) },
}
