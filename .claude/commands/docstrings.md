---
description: Run pydoclint via justfile and fix all docstring findings in Intellicrack Python code. Invoke manually with /docstrings.
argument-hint: [path... --flag...]
allowed-tools: Read, Edit, Glob, Grep, Bash
---

You are fixing pydoclint docstring findings for Intellicrack, a binary analysis platform that bridges external tools and AI providers. Every docstring must be precise, complete, and exactly synchronized with its function signature. Docstrings in this codebase are not cosmetic — they drive API documentation generation and are validated by CI. Shortcuts like reducing full docstrings to one-liners to avoid checks are forbidden.

## Execution

1. Review all findings in the **Findings** section below. Group them by file, then by violation code.
2. Work **one file at a time**. Read the file to understand function purposes and signatures before editing docstrings.
3. Fix **every single finding** in the current file before moving to the next.
4. After completing each file, re-run `pixi run pydoclint --quiet <that-file>` to confirm zero findings remain in it and no new findings were introduced.
5. After completing all files, run `pixi run pydoclint --quiet src/ tests/` for a full sweep.
6. If the full sweep reveals new findings, fix those too.
7. Repeat until `pixi run pydoclint --quiet src/ tests/` returns **zero findings**.

## Rules — Non-Negotiable

- **NO inline suppression comments of any kind.** Do not add any `noqa` directives, pydoclint disable comments, or any other mechanism to suppress docstring findings on any line, under any circumstance.
- **NO configuration changes.** Do not modify `[tool.pydoclint]` in `pyproject.toml` in any way. Do not weaken checking, add exclusions, skip sections, or alter any setting. The pydoclint configuration is locked and immutable.
- **NO suppression of any kind.** The only acceptable resolution for a finding is fixing the actual docstring or adding a correct one.
- **NO short-docstring shortcuts.** Do not reduce a full docstring to a one-liner summary just to avoid Args/Returns/Raises checks. If a function has parameters, returns, or raises, the docstring must document them fully.
- **NO skipping findings.** Every finding in the list must be addressed. Do not silently skip a finding because the docstring is complex or the function has many parameters.
- **NO moving on without verification.** After fixing a file, you must re-run pydoclint on that file to confirm the findings are resolved before proceeding. Do not assume your fix worked.
- **NO introducing regressions.** Your docstring fixes must not break ruff lint compliance or basedpyright type checking. If you discover a function signature is wrong while fixing its docstring, fix both together — but verify both tools pass afterward.
- **NO lazy descriptions.** Docstring parameter descriptions must be substantive. Do not restate the parameter name as its description (e.g., `path: The path.` is unacceptable). Describe what the parameter controls, its valid values, or its effect on behavior.

## Agent and Subagent Oversight

If you delegate any fixes to agents or subagents:
- **You must read the actual docstring edits** they made. Do not accept their claim that findings are fixed without reviewing the docstrings yourself.
- **You must re-run pydoclint** on every file they touched and verify zero findings.
- **You must verify cross-tool compliance** — run `pixi run ruff check <file>` and spot-check type annotations on files they changed.
- **You are accountable for their work.** If an agent writes lazy descriptions, adds types to docstrings (violating `arg-type-hints-in-docstring = false`), or deletes docstrings to silence findings, you must catch it and fix it.
- **Watch for common agent shortcuts to reject:** one-word parameter descriptions, copy-pasted descriptions across unrelated parameters, `Returns:` sections that just say "The result", docstrings that don't match the actual function behavior.

## Current pydoclint Configuration (Read-Only Reference)

The project uses Google style with these settings:
- `style = "google"`
- `arg-type-hints-in-docstring = false` — types belong in signatures, NOT in docstrings
- `check-return-types = true`
- `check-yield-types = true`
- `skip-checking-short-docstrings = true` (default) — but do NOT exploit this to avoid writing complete docstrings

## Docstring Standard — Google Style

### Summary Line
- First line must be a concise imperative-mood description.
- Must fit on a single line.
- Followed by a blank line if the docstring has additional sections.

### Args Section
- Every parameter (except `self` and `cls`) must be documented in an `Args:` section.
- Parameter names must exactly match the signature, in the same order.
- Star arguments (`*args`, `**kwargs`) must be documented.
- **Do not include type annotations in docstrings.** Types belong exclusively in the function signature.
- Descriptions must be substantive — not just restating the parameter name.

### Returns Section
- Required if the function returns a value (anything other than bare `return` or implicit `None`).
- Must not be present if the function cannot return (e.g., `__init__`, functions returning `None`).
- Return type in the docstring must be consistent with the return annotation.

### Yields Section
- Required if the function contains `yield` statements.
- Must not be present if the function does not yield.
- Yield type must be consistent with the return annotation (Generator/Iterator/Iterable).

### Raises Section
- Required if the function contains `raise` statements.
- Must not be present if the function does not raise.
- Exception types in the docstring must match those actually raised in the function body.

### Class Docstrings
- Document class-level attributes in an `Attributes:` section.
- Attribute names must match actual class attributes, in the same order.
- Do not put an Args or Raises section in the class docstring — those belong in `__init__()`.

### __init__ Docstrings
- `__init__()` must not have its own docstring. Combine it with the class docstring OR document parameters in `__init__()` and the class summary in the class docstring. Follow whichever pattern is already established in the codebase.

## How to Fix — By Violation Code

### Argument Mismatches (DOC101–DOC111)
- **DOC101**: Add missing parameters to the `Args:` section.
- **DOC102**: Remove extra arguments not in the signature.
- **DOC103**: Correct docstring names to match the signature exactly.
- **DOC104**: Reorder the `Args:` section to match the signature.
- **DOC105–DOC111**: Remove type hints from docstring (our config is `arg-type-hints-in-docstring = false`).

### Return Mismatches (DOC201–DOC203)
- **DOC201**: Add a `Returns:` section.
- **DOC202**: Remove the `Returns:` section (function doesn't return).
- **DOC203**: Fix return type in docstring to match the annotation.

### Class and __init__ Issues (DOC301–DOC307)
- **DOC301**: Move `__init__()` docstring content to the class docstring.
- **DOC302/DOC303**: Remove Returns section from class/init docstring.
- **DOC304/DOC305**: Move Args/Raises from class docstring to `__init__()`.

### Yield Mismatches (DOC401–DOC405)
- **DOC401/DOC402**: Add `Yields:` section to generator function.
- **DOC403**: Remove `Yields:` section (function doesn't yield).
- **DOC404**: Fix yield type to match annotation.

### Raise Mismatches (DOC501–DOC504)
- **DOC501**: Add `Raises:` section documenting each exception.
- **DOC502**: Remove `Raises:` section (function doesn't raise).
- **DOC503**: Fix exception types to match actual raises.

### Class Attribute Mismatches (DOC601–DOC605)
- **DOC601**: Add missing attributes to `Attributes:` section.
- **DOC602**: Remove extra attributes.
- **DOC603**: Correct attribute names to match actual attributes.
- **DOC604**: Reorder to match class definition.

## Cross-Tool Compliance

Every fix you make must maintain compliance with the full toolchain:
- **ruff**: Do not introduce lint violations. Docstring changes can trigger ruff rules (D-series). Run `pixi run ruff check <file>` after significant changes.
- **basedpyright**: If you discover a signature mismatch while fixing a docstring and choose to fix the signature too, ensure the type annotations remain correct. Run `pixi run basedpyright` if you changed any signatures or type annotations.
- **ruff format**: Your code must remain properly formatted.

## False Positives

If you encounter a finding that you have thoroughly verified is a genuine false positive — meaning the docstring is correct and pydoclint is wrong — **do not suppress it**. Instead, **stop and use the `AskUserQuestion` tool** to describe the finding, explain why you believe it is a false positive, and ask the user how they want to handle it.

## Constraints

- **Do not break existing functionality.** Docstring fixes must not alter code behavior.
- **Do not delete functions, methods, or classes** to eliminate docstring findings.
- **Do not batch too many files at once.** Work one file at a time and verify before moving on.
- **Docstrings must be kept in sync with code.** If fixing a docstring reveals that the function signature is also wrong, fix both together and verify both tools pass.

## Completion Criteria

The task is complete when:
1. `pixi run pydoclint --quiet src/ tests/` returns **zero findings**
2. **Zero suppression comments or configuration changes** exist anywhere in the codebase
3. No ruff or basedpyright regressions were introduced (spot-check if you made significant changes)

---

## Findings

The following findings were produced by `just pydoclint $ARGUMENTS`:

!`just pydoclint $ARGUMENTS >/dev/null 2>&1 || true; cat reports/txt/pydoclint_findings.txt 2>/dev/null || echo "ERROR: No findings report at reports/txt/pydoclint_findings.txt. Run 'just pydoclint' manually to diagnose."`
