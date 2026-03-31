---
description: Run ruff linter via justfile and fix all findings in Intellicrack Python code. Invoke manually with /lint.
argument-hint: [path... --flag...]
allowed-tools: Read, Edit, Glob, Grep, Bash
---

You are fixing ruff lint findings for Intellicrack, a binary analysis platform that bridges external tools and AI providers. Every import and variable in this codebase exists for a reason or can serve a real purpose. Your default stance is to **implement functional code that uses flagged symbols**, not delete them. Removal is the last resort, only after you have confirmed there is genuinely no productive use in that module's context.

## Execution

1. Review all findings in the **Findings** section below. Group them by file, then by severity.
2. Work **one file at a time**. Read the file, understand its purpose and surrounding context before making changes.
3. Fix **every single finding** in the current file before moving to the next.
4. After completing each file, re-run `pixi run ruff check <that-file>` to confirm zero findings remain in it and no new findings were introduced.
5. After completing all files, run `pixi run ruff check src/ tests/` for a full sweep.
6. If the full sweep reveals new findings (from cross-file effects of your changes), fix those too.
7. Repeat until `pixi run ruff check src/ tests/` returns **zero findings**.

## Rules — Non-Negotiable

- **NO inline suppression comments of any kind.** Do not add any ruff, pylint, mypy, or pyright suppression directives to any line, under any circumstance. This includes all forms of per-line rule disabling.
- **NO per-file-ignores.** Do not add, modify, or expand `per-file-ignores` in `pyproject.toml` or any ruff configuration.
- **NO rule disabling.** Do not add rules to the `ignore` list in `[tool.ruff.lint]` or any other ruff configuration section. Do not modify the ruff configuration in `pyproject.toml` in any way.
- **NO suppression of any kind.** The only acceptable resolution for a finding is fixing the actual code.
- **NO skipping findings.** Every finding in the list must be addressed. Do not silently skip a finding because it looks difficult or ambiguous.
- **NO moving on without verification.** After fixing a file, you must re-run the linter on that file before proceeding to the next. Do not assume your fix worked — confirm it.
- **NO introducing regressions.** Your ruff fixes must not break basedpyright type checking or pydoclint docstring compliance. If you change a function signature, update its type annotations and docstring to match. If you restructure imports, ensure type stubs and TYPE_CHECKING blocks remain correct.
- **IMPLEMENT over remove.** When ruff flags an unused import or variable, your first priority is to write functional code that uses it to genuinely improve Intellicrack. Only remove after confirming there is no productive use. A finding resolved by adding useful functionality is always superior to one resolved by deleting code.

## Agent and Subagent Oversight

If you delegate any fixes to agents or subagents:
- **You must read the actual edits** they made. Do not accept their claim that findings are fixed without reviewing the code changes yourself.
- **You must re-run the linter** on every file they touched and verify zero findings.
- **You must verify cross-tool compliance** — run `pixi run basedpyright` on files with significant changes to confirm no type regressions. Spot-check docstrings if signatures changed.
- **You are accountable for their work.** If an agent introduces a suppression comment, a broad `Any` type, or deletes functional code to silence a finding, you must catch it and fix it.

## How to Fix — Priority Order

### Unused Imports and Variables — IMPLEMENT, Don't Remove

- **Unused imports**: Determine what the import provides. If the import brings in a capability the module logically should use (binary analysis, protection detection, error handling, utility), **write the code that uses it**. Only remove if genuinely no implementable use exists.
- **Unused variables**: Determine if the variable captures a value that should be acted on — a return value that should be checked, a result that should be logged, a computation that should feed into downstream logic. **Write the code that uses the variable**. Only remove or prefix with `_` if truly no actionable purpose exists.

### All Other Findings

- **Import ordering**: Reorder imports correctly.
- **Complexity**: Refactor the function to reduce complexity while preserving identical behavior.
- **Type/style issues**: Fix the actual code to conform to the rule.
- **Any other finding**: Apply the most correct fix that addresses the root cause.

## Cross-Tool Compliance

Every fix you make must maintain compliance with the full toolchain:
- **basedpyright**: Do not introduce type errors. If you change a return value, parameter, or variable type, update annotations. If you add new code, it must be fully typed.
- **pydoclint**: Do not break docstring compliance. If you change a function signature (add/remove/rename parameters, change return type), update the docstring to match.
- **ruff format**: Your code must remain properly formatted. If in doubt, run `pixi run ruff format <file>` after edits.

## False Positives

If you encounter a finding that you have thoroughly verified is a genuine false positive — meaning the code is correct and the rule is being triggered erroneously — **do not suppress it**. Instead, **stop and use the `AskUserQuestion` tool** to describe the finding, explain why you believe it is a false positive, and ask the user how they want to handle it. Do not proceed past a confirmed false positive without user direction.

## Constraints

- **Do not break existing functionality.** Every fix must preserve the original behavior of the code. If a fix requires a non-trivial refactor, ensure the logic remains identical.
- **Do not delete method bindings or functional code** to resolve a finding. Create or restructure code instead.
- **Maintain all type hints.** Fixes must remain fully type-annotated and basedpyright compliant.
- **Do not batch too many files at once.** Work one file at a time and verify before moving on. Context switching across many files simultaneously leads to missed regressions.

## Completion Criteria

The task is complete when:
1. `pixi run ruff check src/ tests/` returns **zero findings**
2. **Zero suppression comments or configuration changes** exist anywhere in the codebase
3. No basedpyright or pydoclint regressions were introduced (spot-check if you made significant changes)

---

## Findings

The following findings were produced by `just ruff $ARGUMENTS`:

!`just ruff $ARGUMENTS >/dev/null 2>&1 || true; cat reports/txt/ruff_findings.txt 2>/dev/null || echo "ERROR: No findings report at reports/txt/ruff_findings.txt. Run 'just ruff' manually to diagnose."`
