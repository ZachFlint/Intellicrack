Run basedpyright across the entire Intellicrack project and fix every single finding.

## Execution

1. Run `pixi run basedpyright` to get the full list of type checking findings.
2. Fix **every single finding** with the most correct, production-appropriate fix. This means actually correcting the underlying type issue — adding precise annotations, restructuring code, using proper generics, narrowing types, adding overloads, etc.
3. After fixing a batch of findings, re-run `pixi run basedpyright` to confirm they are resolved and to catch any new findings introduced by your fixes.
4. Repeat until basedpyright returns **zero findings**.

## Rules — Non-Negotiable

- **NO type suppression comments of any kind.** Do not add any type-ignore directives, pyright-ignore directives, or any inline mechanism to suppress type checking findings on any line, under any circumstance.
- **NO basedpyright configuration changes.** Do not modify the `[tool.basedpyright]` section in `pyproject.toml` in any way. Do not weaken strictness, add exclusions, change diagnostic severity levels, or alter any setting. The basedpyright configuration is locked and immutable.
- **NO suppression of any kind.** The only acceptable resolution for a finding is fixing the actual code.
- **NO broad, basic, or generic types that exist only to satisfy the type checker.** Every type annotation must be precise and meaningful. Using `Any`, `object`, bare `dict`, bare `list`, `Union[...]` with excessive members, or any other vague type just to make a finding go away is **absolutely forbidden**. Type annotations must accurately describe the actual data flowing through the code. If you cannot determine the precise type, investigate the code paths until you can. A type annotation that does not convey real, specific information about the value is worse than useless — it hides bugs and defeats the purpose of strict type checking.

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

## Unused Imports and Variables — IMPLEMENT, Don't Remove

When basedpyright flags an unused import or variable, apply the same principle as ruff linting: **first priority is to find a genuine use** that improves Intellicrack's functionality. Only remove if there is truly no implementable use in that module's context.

## False Positives

If you encounter a finding that you have thoroughly verified is a genuine false positive — meaning the code is correct and basedpyright is wrong — **do not suppress it**. Instead, **stop and use the `AskUserQuestion` tool** to describe the finding, explain why you believe it is a false positive, and ask the user how they want to handle it. Do not proceed past a confirmed false positive without user direction.

## Constraints

- **Do not break existing functionality.** Every fix must preserve the original behavior of the code.
- **Do not delete method bindings or functional code** to resolve a finding. Create or restructure code instead.
- **All fixes must also pass ruff.** Do not introduce ruff violations while fixing type issues.
- **Re-run basedpyright after every batch of fixes** to verify convergence toward zero findings.
- **Implement functional code over removal.** Improving Intellicrack's capabilities and usability is always the priority.

## Completion Criteria

The task is complete when `pixi run basedpyright` returns **zero findings** (errors and warnings) with **zero suppression comments or configuration changes** anywhere in the codebase.
