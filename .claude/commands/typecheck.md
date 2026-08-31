---
description: Run basedpyright type checker via justfile and fix all findings in Intellicrack Python code. Invoke manually with /typecheck.
argument-hint: [path... --flag...]
allowed-tools: Read, Edit, Glob, Grep, Bash
---

You are fixing basedpyright type checking findings for Intellicrack, a binary analysis platform that bridges external tools and AI providers. Every type annotation must be precise and meaningful — it must accurately describe the actual data flowing through the code. Vague types that exist only to silence the checker are forbidden. Your default stance is to **investigate code paths until you can determine the exact type**, not to reach for `Any` or `object`.

## Execution

1. Review all findings in the **Findings** section below. Group them by file, then by severity (errors before warnings).
2. Work **one file at a time**. Read the file, understand its purpose, its imports, and how its types flow before making changes.
3. Fix **every single finding** in the current file before moving to the next.
4. After completing each file, re-run `pixi run basedpyright --outputjson 2>&1 | grep <filename>` or re-run `pixi run basedpyright` to confirm zero findings remain in it and no new findings were introduced.
5. After completing all files, run `pixi run basedpyright` for a full sweep.
6. If the full sweep reveals new findings (from cross-file type propagation effects), fix those too.
7. Repeat until `pixi run basedpyright` returns **zero findings**.

## Rules — Non-Negotiable

- **NO type suppression comments of any kind.** Do not add any type-ignore directives, pyright-ignore directives, or any inline mechanism to suppress type checking findings on any line, under any circumstance.
- **NO basedpyright configuration changes.** Do not modify the `[tool.basedpyright]` section in `pyproject.toml` in any way. Do not weaken strictness, add exclusions, change diagnostic severity levels, or alter any setting. The basedpyright configuration is locked and immutable.
- **NO suppression of any kind.** The only acceptable resolution for a finding is fixing the actual code.
- **NO broad, basic, or generic types.** Using `Any`, `object`, bare `dict`, bare `list`, `Union[...]` with excessive members, or any other vague type just to make a finding go away is **absolutely forbidden**. If you cannot determine the precise type, investigate the code paths until you can.
- **NO skipping findings.** Every finding in the list must be addressed. Do not silently skip a finding because it looks difficult or involves complex generics.
- **NO moving on without verification.** After fixing a file, you must re-run basedpyright to confirm the findings are resolved before proceeding to the next file. Do not assume your fix worked.
- **NO introducing regressions.** Your type fixes must not break ruff lint compliance or pydoclint docstring compliance. If you change a function signature's types, update the docstring to match. If you add imports for type annotations, ensure they pass ruff import ordering.
- **IMPLEMENT over remove.** When basedpyright flags an unused import or variable, your first priority is to find a genuine use that improves Intellicrack's functionality. Only remove if there is truly no implementable use in that module's context.

## Agent and Subagent Oversight

If you delegate any fixes to agents or subagents:
- **You must read the actual edits** they made. Do not accept their claim that findings are fixed without reviewing the code changes yourself.
- **You must re-run basedpyright** on every file they touched and verify zero findings.
- **You must verify cross-tool compliance** — run `pixi run ruff check <file>` on files they changed to confirm no lint regressions. Spot-check docstrings if signatures changed.
- **You are accountable for their work.** If an agent introduces `Any` types, suppression comments, or overly broad unions to silence findings, you must catch it and replace them with precise types.
- **Watch for lazy type fixes.** Common agent shortcuts to reject: `cast(Any, ...)`, `object` as a catch-all, `dict[str, Any]` when the value type is knowable, `list[Any]` when element types are deterministic.

## Current basedpyright Configuration (Read-Only Reference)

The project uses `typeCheckingMode = "strict"` targeting Python 3.13 on Windows. Key settings:
- `useLibraryCodeForTypes = false`
- `strictListInference`, `strictDictionaryInference`, `strictSetInference` all enabled
- `reportMissingImports = "warning"`, `reportUndefinedVariable = "error"`, `reportGeneralTypeIssues = "error"`
- Scope: `src/intellicrack` directory

## How to Fix — By Category

### Missing or Incorrect Type Annotations

- Add explicit return types to all functions and methods.
- Add parameter type annotations to all function signatures.
- Use precise types that reflect the actual data — `Any` is a last resort only for genuine interoperability with untyped third-party code, and even then must be scoped as narrowly as possible.
- For containers, use precise generic types (`list[str]`, `dict[str, int]`, etc.) rather than bare `list` or `dict`. The generic parameters must reflect the actual contents.

### Type Narrowing and Compatibility

- Use `isinstance()`, `is None` checks, `assert`, or other narrowing constructs to satisfy the type checker when a value could be multiple types.
- For optional values, explicitly check for `None` before using the value rather than assuming it exists.
- When dealing with union types, narrow to the specific type needed before performing operations.

### Missing Imports and Type Stubs

- For `reportMissingImports` warnings: verify the import path is correct. If the module exists but basedpyright cannot resolve it, check that `extraPaths` covers the source root. If it is a third-party library without stubs, create a minimal typed wrapper or use `TYPE_CHECKING` imports with protocol classes.
- For missing type stubs: do not change `reportMissingTypeStubs`. Instead, create local type stubs or use protocol-based abstractions where appropriate.

### Attribute and Member Access

- For `reportAttributeAccessIssue` or similar: ensure the type annotation on the object is precise enough to include the accessed attribute. If the object comes from a dynamic source, add proper type narrowing or cast with `cast()` only when the type is genuinely known at runtime.
- For dynamically dispatched attributes (e.g., `getattr` patterns), ensure the return type is properly annotated.

### Callable and Return Type Issues

- Ensure all callables have explicit parameter and return type annotations.
- For callbacks and higher-order functions, use `Callable[[ParamTypes], ReturnType]` or `Protocol` with `__call__` for complex signatures.
- Ensure all code paths return the declared type. Add explicit returns for branches that the type checker identifies as missing.

### Platform Compatibility

- The project targets Windows (`pythonPlatform = "Windows"`). Ensure all platform-specific code uses proper `sys.platform` checks and conditional imports.
- Use `TYPE_CHECKING` blocks for imports only needed by the type checker, with runtime fallbacks where necessary.

## Cross-Tool Compliance

Every fix you make must maintain compliance with the full toolchain:
- **ruff**: Do not introduce lint violations. If you add imports, ensure correct ordering. If you restructure code, ensure it passes style checks. Run `pixi run ruff check <file>` after significant changes.
- **pydoclint**: Do not break docstring compliance. If you change a function signature (add/remove/rename parameters, change return type), update the docstring to match. Run `pixi run pydoclint --quiet <file>` if you changed signatures.
- **ruff format**: Your code must remain properly formatted.

## False Positives

If you encounter a finding that you have thoroughly verified is a genuine false positive — meaning the code is correct and basedpyright is wrong — **do not suppress it**. Instead, **stop and use the `AskUserQuestion` tool** to describe the finding, explain why you believe it is a false positive, and ask the user how they want to handle it. Do not proceed past a confirmed false positive without user direction.

## Constraints

- **Do not break existing functionality.** Every fix must preserve the original behavior of the code.
- **Do not delete method bindings or functional code** to resolve a finding. Create or restructure code instead.
- **Do not batch too many files at once.** Work one file at a time and verify before moving on. Type changes propagate across files — fixing one file can create or resolve findings in another.
- **All fixes must also pass ruff.** Do not introduce ruff violations while fixing type issues.

## Completion Criteria

The task is complete when:
1. `pixi run basedpyright` returns **zero findings** (errors and warnings)
2. **Zero suppression comments or configuration changes** exist anywhere in the codebase
3. No ruff or pydoclint regressions were introduced (spot-check if you made significant changes)

---

## Findings

The following findings were produced by `just basedpyright $ARGUMENTS`:

!`just basedpyright $ARGUMENTS >/dev/null 2>&1 || true; cat reports/txt/basedpyright_findings.txt 2>/dev/null || echo "ERROR: No findings report at reports/txt/basedpyright_findings.txt. Run 'just basedpyright' manually to diagnose."`
