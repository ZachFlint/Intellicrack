Lint the entire Intellicrack project with `ruff check` and fix every single finding.

## Execution

1. Run `pixi run ruff check src/ tests/` to get the full list of findings.
2. Fix **every single finding** with the most correct, production-appropriate fix. This means actually correcting the underlying code issue — refactoring, rewriting, adding proper imports, restructuring logic, etc.
3. After fixing a batch of findings, re-run `pixi run ruff check src/ tests/` to confirm they are resolved and to catch any new findings introduced by your fixes.
4. Repeat until `ruff check` returns **zero findings**.

## Rules — Non-Negotiable

- **NO inline suppression comments of any kind.** Do not add any ruff, pylint, mypy, or pyright suppression directives to any line, under any circumstance. This includes all forms of per-line rule disabling.
- **NO per-file-ignores.** Do not add, modify, or expand `per-file-ignores` in `pyproject.toml` or any ruff configuration.
- **NO rule disabling.** Do not add rules to the `ignore` list in `[tool.ruff.lint]` or any other ruff configuration section. Do not modify the ruff configuration in `pyproject.toml` in any way.
- **NO suppression of any kind.** The only acceptable resolution for a finding is fixing the actual code.

## How to Fix — Priority Order

### Unused Imports and Variables — IMPLEMENT, Don't Remove

**This is critical.** When ruff flags an unused import or unused variable, your **first priority** is to find a way to use it that genuinely improves Intellicrack's functionality, usability, or robustness. This is a binary analysis and licensing protection cracking platform — almost every import and variable exists for a reason or can serve a real purpose.

- **Unused imports**: Before removing, determine what the import provides and whether it should be used in the module. If the import brings in a capability that the module logically should use (e.g., a binary analysis function, a protection detection routine, a utility that would improve error handling or functionality), **write the code that uses it**. Only remove an import if there is genuinely no implementable use for it in that module's context.
- **Unused variables**: Before removing, determine if the variable captures a value that should be acted on — a return value that should be checked, a result that should be logged, a computation that should feed into downstream logic. **Write the code that uses the variable** to improve functionality. Only remove or prefix with `_` if the variable truly has no actionable purpose.

### All Other Findings

- **Import ordering**: Reorder imports correctly.
- **Complexity**: Refactor the function to reduce complexity while preserving identical behavior.
- **Type/style issues**: Fix the actual code to conform to the rule.
- **Any other finding**: Apply the most correct fix that addresses the root cause.

## False Positives

If you encounter a finding that you have thoroughly verified is a genuine false positive — meaning the code is correct and the rule is being triggered erroneously — **do not suppress it**. Instead, **stop and use the `AskUserQuestion` tool** to describe the finding, explain why you believe it is a false positive, and ask the user how they want to handle it. Do not proceed past a confirmed false positive without user direction.

## Constraints

- **Do not break existing functionality.** Every fix must preserve the original behavior of the code. If a fix requires a non-trivial refactor, ensure the logic remains identical.
- **Do not delete method bindings or functional code** to resolve a finding. Create or restructure code instead.
- **Maintain all type hints.** Fixes must remain fully type-annotated and basedpyright compliant.
- **Re-run ruff after every batch of fixes** to verify convergence toward zero findings.
- **Implement functional code over removal.** Improving Intellicrack's capabilities and usability is always the priority. A finding resolved by adding useful functionality is superior to one resolved by deleting code.

## Completion Criteria

The task is complete when `pixi run ruff check src/ tests/` returns **zero findings** with **zero suppression comments or configuration changes** anywhere in the codebase.
