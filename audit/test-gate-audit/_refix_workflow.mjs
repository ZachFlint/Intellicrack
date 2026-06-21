export const meta = {
  name: 'test-gate-refix',
  description: 'Re-harden reviewer-failed test files into genuinely falsifiable gates using reviewer feedback',
  phases: [
    { title: 'Refix', detail: 'one agent per reviewer-failed file: fix the specific falsifiability gaps' },
    { title: 'Reverify', detail: 'adversarial reviewer re-checks the rewritten gate' },
  ],
}

function coerce(a) {
  let v = a
  if (typeof v === 'string') { try { v = JSON.parse(v) } catch (_e) { v = [] } }
  return Array.isArray(v) ? v : []
}
const ITEMS = coerce(args)
log(`refix items=${ITEMS.length}`)

const FAL = {
  type: 'object', additionalProperties: false,
  properties: {
    src_file: { type: 'string' }, mutation_search: { type: 'string' }, mutation_replace: { type: 'string' },
    covering_test: { type: 'string' }, expected_baseline: { type: 'string', enum: ['green', 'expected-red'] }, note: { type: 'string' },
  },
  required: ['src_file', 'mutation_search', 'mutation_replace', 'covering_test', 'expected_baseline'],
}
const FIX_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    file: { type: 'string' }, summary: { type: 'string' },
    findings_addressed: {
      type: 'array', items: {
        type: 'object', additionalProperties: false,
        properties: {
          test: { type: 'string' }, action: { type: 'string', enum: ['hardened', 'deleted', 'red-prod-defect'] },
          oracle: { type: 'string' }, deletion_sibling: { type: 'string' }, falsifiability: FAL,
        }, required: ['test', 'action', 'oracle'],
      },
    },
    production_defects: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { src_file: { type: 'string' }, line: { type: 'integer' }, symbol: { type: 'string' }, expected: { type: 'string' }, actual: { type: 'string' }, red_test: { type: 'string' } }, required: ['src_file', 'expected', 'actual', 'red_test'] } },
    ruff_clean: { type: 'boolean' }, basedpyright_clean: { type: 'boolean' }, pydoclint_clean: { type: 'boolean' }, pydocstyle_clean: { type: 'boolean' },
    notes: { type: 'string' },
  },
  required: ['file', 'summary', 'findings_addressed', 'ruff_clean', 'basedpyright_clean', 'pydoclint_clean', 'pydocstyle_clean'],
}
const REVIEW_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    file: { type: 'string' }, overall: { type: 'string', enum: ['pass', 'fail'] },
    per_finding: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { test: { type: 'string' }, verdict: { type: 'string', enum: ['real-gate', 'not-a-gate', 'deletion-justified', 'red-prod-defect-valid'] }, mutation_would_flip: { type: 'boolean' }, oracle_independent: { type: 'boolean' }, reason: { type: 'string' } }, required: ['test', 'verdict', 'reason'] } },
    ruff_clean: { type: 'boolean' }, basedpyright_clean: { type: 'boolean' }, pydoclint_clean: { type: 'boolean' }, pydocstyle_clean: { type: 'boolean' },
    problems: { type: 'array', items: { type: 'string' } }, notes: { type: 'string' },
  },
  required: ['file', 'overall', 'per_finding', 'ruff_clean', 'basedpyright_clean', 'pydoclint_clean', 'pydocstyle_clean'],
}

function fixerPrompt(item) {
  return `A previous pass hardened this Intellicrack test file, but an adversarial reviewer PROVED its gate is still inadequate. Re-harden it into a GENUINELY falsifiable gate that fixes every problem below.

FILE (edit only this file): ${item.file}
Audit report: audit/test-gate-audit/${item.report}

REVIEWER PROBLEMS you MUST fix (each is a real falsifiability gap):
${(item.problems || []).map((p) => '  - ' + p).join('\n')}
${(item.notagate || []).map((p) => `  - NOT-A-GATE ${p.test}: ${p.reason}`).join('\n')}

REQUIREMENTS for a real gate:
- Assert the real operation's result/side-effect against an INDEPENDENT oracle (recompute expected a different way; never assert injected data).
- The falsifiability mutation you propose MUST actually flip the assertion. If a single mutation site is insufficient because the behavior has multiple code paths (e.g. both a TCP and a UDP log line, or two $rtype occurrences), assert ALL of them so that breaking ANY one path turns the test red, and pick a mutation that demonstrably flips at least one asserted path. Avoid mutations the reviewer showed do NOT flip (e.g. an isinstance check that survives an id change).
- Eliminate non-determinism / order-dependence (e.g. shared global caches): isolate state so the assertion is deterministic.
- Make empty/zero results FAIL (assert count > 0 where the capability must produce items), not silently pass.
- Target the mutation at the ACTUAL production code path the test exercises (verify by reading the source), not a fallback path that the test never hits.

CONSTRAINTS: no suppressions (no noqa/type-ignore/etc.); edit only this file; never edit src/; full type hints; Google docstrings matching signatures; Windows-compatible; no comments/emojis/TODO. You CANNOT run pytest (sandbox-only); reason about falsifiability and give a concrete correct mutation plan.

STEPS: read _RUBRIC.md, the report section for this file, the current file, and the production source. Rewrite the inadequate tests. Run and make clean: pixi run ruff check ${item.file}; (NODE_OPTIONS=--max-old-space-size=4096) pixi run basedpyright ${item.file}; pixi run pydoclint ${item.file}; pixi run pydocstyle ${item.file}. Return the structured FIX result with corrected falsifiability plans.`
}

function reviewerPrompt(item, fix) {
  return `Adversarial re-review of a RE-HARDENED Intellicrack test file. The prior version failed review for these reasons:
${(item.problems || []).map((p) => '  - ' + p).join('\n')}

FILE: ${item.file}
Re-fixer's claim:
${JSON.stringify(fix, null, 1)}

Read _RUBRIC.md, the current ${item.file}, and the production source. For each finding, decide verdict (real-gate / not-a-gate / deletion-justified / red-prod-defect-valid). Crucially: trace whether the new mutation_search->mutation_replace actually makes covering_test FAIL (set mutation_would_flip), and whether each prior problem is genuinely resolved. Re-run ruff/basedpyright/pydoclint/pydocstyle. overall='fail' if any finding is not-a-gate, any mutation would not flip, oracle not independent, or any lint/type tool not clean. List remaining problems precisely.`
}

phase('Refix')
const results = await pipeline(
  ITEMS,
  (item) => agent(fixerPrompt(item), { label: `refix:${item.file}`, phase: 'Refix', schema: FIX_SCHEMA, agentType: 'developer', model: 'sonnet' }),
  (fix, item) => {
    if (!fix) return null
    return agent(reviewerPrompt(item, fix), { label: `rereview:${item.file}`, phase: 'Reverify', schema: REVIEW_SCHEMA, agentType: 'test-reviewer', model: 'sonnet' })
      .then((review) => ({ file: item.file, report: item.report, fix, review }))
      .catch(() => ({ file: item.file, report: item.report, fix, review: null }))
  },
)
const done = results.filter(Boolean)
const stillFail = done.filter((r) => !r.review || r.review.overall === 'fail')
log(`refix done: ${done.length}; still failing: ${stillFail.length}`)
return { processed: done.length, still_fail: stillFail.map((r) => r.file), results: done }
