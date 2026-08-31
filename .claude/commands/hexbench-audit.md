---
description: Run the Hexbench (multi-language web GUI) audit-and-fix pass via the hexbench-auditor subagent. Invoke with /hexbench-audit.
argument-hint: [scope or focus — e.g. "A1 security", "jobs.py", or blank for the full sweep]
allowed-tools: Task, Read, Edit, Grep, Glob, Bash
---

You are running the **Hexbench audit** for Intellicrack — a complete production-standards audit-and-fix pass over the `hexbench` package (`src/hexbench/`), the standalone, stdlib-only web GUI that drives the compiled `intellicrack_hexcore` extension. It is a local HTTP server that decodes untrusted JSON into native calls and renders results into an embedded WebView2 window, so its security surface and its dispatch/concurrency correctness both matter. It spans **Python, JavaScript, CSS, HTML and PowerShell**.

## Execution

1. Launch the `hexbench-auditor` subagent (via the Task tool) to perform the audit. Its authoritative methodology is [`prompts/Hexbench-Audit.md`](../../prompts/Hexbench-Audit.md) — instruct it to read that file **in full** and follow it exactly (Ground rules → Part A cross-cutting invariants → Part B per-surface sweep incl. frontend/design/packaging → How to run → Deliverable).
2. **Scope**: pass `$ARGUMENTS` through as the audit focus. If empty, the auditor runs the complete sweep. If a surface, module, or area is given (e.g. `A1`, `jobs.py`, `codec`), scope the pass to that.
3. When the subagent reports, do **not** accept its claims at face value — move to Accountability.

## Accountability (you own the result)

- **Read the actual diffs** the subagent produced — never approve on its say-so.
- **Re-run the gates yourself** and confirm green: `pwsh -File src/hexbench/gate.ps1` (ruff format + ruff check + basedpyright + pydoclint + pydocstyle + the `*.test.mjs` node suite + unittest + design-card dirty-check), plus `pwsh -File scripts/lint-psscriptanalyzer.ps1` if any `.ps1` changed.
- **Verify every new test is a real falsifiable gate in the language of the fix** (unittest for Python, `.test.mjs` for JS/CSS/HTML, PSScriptAnalyzer-clean for PowerShell): revert the fix, confirm RED, restore. Reject any test that stays green.
- **Reject** any suppression (`type: ignore`, `# noqa`, `// NOLINT`, PSSA disable), any weakened gate config, any new third-party import (the package is stdlib-only), any HTTP/JS-contract break, and any placeholder.
- Summarize the confirmed findings and their fixes, **severity-ordered (security and concurrency first)**, each with `file:line`.
