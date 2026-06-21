export const meta = {
  name: 'test-gate-greenfix',
  description: 'Resolve sandbox green-baseline failures: fix test bugs, add capability skip-guards, or document real production defects',
  phases: [{ title: 'GreenFix', detail: 'one agent per file: triage each failing test to fix / skip-guard / document-defect' }],
}

function coerce(a) {
  let v = a
  if (typeof v === 'string') { try { v = JSON.parse(v) } catch (_e) { v = [] } }
  return Array.isArray(v) ? v : []
}
const ITEMS = coerce(args)
log(`greenfix items=${ITEMS.length}`)

const SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    file: { type: 'string' },
    summary: { type: 'string' },
    per_test: {
      type: 'array', items: {
        type: 'object', additionalProperties: false,
        properties: {
          test: { type: 'string' },
          category: { type: 'string', enum: ['test-bug-fixed', 'capability-skip-guard', 'production-defect', 'already-correct'] },
          detail: { type: 'string' },
        }, required: ['test', 'category', 'detail'],
      },
    },
    production_defects: { type: 'array', items: { type: 'object', additionalProperties: false, properties: { src_file: { type: 'string' }, line: { type: 'integer' }, symbol: { type: 'string' }, expected: { type: 'string' }, actual: { type: 'string' }, red_test: { type: 'string' } }, required: ['src_file', 'expected', 'actual', 'red_test'] } },
    ruff_clean: { type: 'boolean' }, basedpyright_clean: { type: 'boolean' }, pydoclint_clean: { type: 'boolean' }, pydocstyle_clean: { type: 'boolean' },
    notes: { type: 'string' },
  },
  required: ['file', 'summary', 'per_test', 'ruff_clean', 'basedpyright_clean', 'pydoclint_clean', 'pydocstyle_clean'],
}

function prompt(item) {
  return `A hardened Intellicrack test in this file FAILED in the Docker sandbox green-baseline (the sandbox runs Windows, headless, network='none', with .env API keys mounted, and a prebuilt native intellicrack_hexcore). Triage each failure correctly. Do NOT blindly make tests pass.

FILE (edit only this file): ${item.file}
Sandbox failures:
${item.failures.map((f) => `  - ${f.test} [${f.status}]: ${f.detail}`).join('\n')}

Category guidance for this file: ${item.guidance}

For EACH failing test choose exactly one action:
- "production-defect": the test correctly gates real behavior and is RED because the PRODUCTION code is genuinely wrong. Leave the gate red (do NOT weaken it) and record it in production_defects (src_file, line, expected vs actual, red_test). NEVER edit src/.
- "capability-skip-guard": the failure is a genuine ENVIRONMENT capability absence (no network for a live-cloud call, no display/window-manager for a GUI HWND test, a Win32 API unsupported in the container, a data corpus not shipped to the container). Add a precise skip guard that SKIPS when the capability is absent but still RUNS and asserts the real behavior when present. Reuse the project's existing skip mechanism if one exists (e.g. for live-cloud tests, find how sibling provider tests / conftest skip without billing/network and apply the same marker/fixture). Do NOT turn it into a no-op; the assertion must remain a real gate when the capability is present.
- "test-bug-fixed": the production code is correct but the test's oracle/logic/isolation is wrong (e.g. an expected-set that ignores overlapping matches, or a test that reads real os.environ instead of an isolated env). Fix the test so its oracle matches real semantics. Keep it a real falsifiable gate.
- "already-correct": only if you can prove the failure cannot reproduce (rare).

CONSTRAINTS: no suppressions (no noqa/type-ignore/etc.); edit only this file; never edit src/; full type hints; Google docstrings matching signatures; Windows-compatible platform checks; no comments/emojis/TODO. You CANNOT run pytest (sandbox-only) — reason from the source.

STEPS: read the file, the relevant production source, and (for skip decisions) the project conftest.py / sibling tests to find existing skip conventions. Apply the right action. Make clean: pixi run ruff check ${item.file}; (NODE_OPTIONS=--max-old-space-size=4096) pixi run basedpyright ${item.file}; pixi run pydoclint ${item.file}; pixi run pydocstyle ${item.file}. Return the structured result.`
}

phase('GreenFix')
const results = await parallel(
  ITEMS.map((item) => () =>
    agent(prompt(item), { label: `greenfix:${item.file}`, phase: 'GreenFix', schema: SCHEMA, agentType: 'developer', model: 'sonnet' })
      .then((r) => r || { file: item.file, basedpyright_clean: false, notes: 'null' })
      .catch((e) => ({ file: item.file, basedpyright_clean: false, notes: String(e).slice(0, 200) })),
  ),
)
const defects = results.flatMap((r) => (r.production_defects || []).map((d) => ({ ...d, test_file: r.file })))
log(`greenfix done: ${results.length} files; production defects: ${defects.length}`)
return { processed: results.length, production_defects: defects, results }
