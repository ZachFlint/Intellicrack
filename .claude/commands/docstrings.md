Fix all pydoclint findings across the entire Intellicrack project.

## Execution

1. Run `pixi run pydoclint --quiet src/ tests/` to get the full list of findings.
2. Fix **every single finding** with the most correct, production-appropriate fix. This means writing precise, complete, Google-style docstrings that exactly match function signatures — parameters, return values, raised exceptions, yields, and class attributes.
3. After fixing a batch of findings, re-run `pixi run pydoclint --quiet src/ tests/` to confirm they are resolved and to catch any new findings introduced by your fixes.
4. Repeat until pydoclint returns **zero findings**.

## Rules — Non-Negotiable

- **NO inline suppression comments of any kind.** Do not add any `noqa` directives, pydoclint disable comments, or any other mechanism to suppress docstring findings on any line, under any circumstance.
- **NO configuration changes.** Do not modify `[tool.pydoclint]` in `pyproject.toml` in any way. Do not weaken checking, add exclusions, skip sections, or alter any setting. The pydoclint configuration is locked and immutable.
- **NO suppression of any kind.** The only acceptable resolution for a finding is fixing the actual docstring or adding a correct one.
- **NO short-docstring shortcuts.** Do not reduce a full docstring to a one-liner summary just to avoid Args/Returns/Raises checks. If a function has parameters, returns, or raises, the docstring must document them.

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
- **Do not include type annotations in docstrings.** Types belong exclusively in the function signature. The `arg-type-hints-in-docstring = false` setting enforces this.
- Descriptions must be substantive — not just restating the parameter name.

### Returns Section
- Required if the function returns a value (anything other than bare `return` or implicit `None`).
- Must not be present if the function cannot return (e.g., `__init__`, functions returning `None`).
- Return type in the docstring must be consistent with the return annotation.

### Yields Section
- Required if the function contains `yield` statements.
- Must not be present if the function does not yield.
- Yield type must be consistent with the return annotation (Generator/Iterator/Iterable).
- If a function has both `return` and `yield`, use `Generator[YieldType, SendType, ReturnType]` as the annotation.

### Raises Section
- Required if the function contains `raise` statements.
- Must not be present if the function does not raise.
- Exception types in the docstring must match those actually raised in the function body.

### Class Docstrings
- Document class-level attributes in an `Attributes:` section.
- Attribute names must match actual class attributes, in the same order.
- Do not put an Args or Raises section in the class docstring — those belong in `__init__()`.
- Do not put a Returns or Yields section in the class docstring.

### __init__ Docstrings
- `__init__()` must not have its own docstring. Combine it with the class docstring OR document parameters in `__init__()` and the class summary in the class docstring. Follow whichever pattern is already established in the codebase.
- `__init__()` docstrings must not have Returns or Yields sections.

## How to Fix — By Violation Code

### Formatting and Parsing (DOC001–DOC003)
- **DOC001**: Fix formatting errors in the docstring structure (indentation, section headers, blank lines).
- **DOC002**: Fix syntax errors that prevent parsing.
- **DOC003**: Docstring uses wrong style (numpy/sphinx instead of google). Rewrite in Google style.

### Argument Mismatches (DOC101–DOC111)
- **DOC101**: Docstring is missing arguments. Add the missing parameters to the `Args:` section.
- **DOC102**: Docstring has extra arguments not in the signature. Remove them.
- **DOC103**: Argument names differ between docstring and signature. Correct the docstring names to match the signature exactly.
- **DOC104**: Arguments are correct but in wrong order. Reorder the `Args:` section to match the signature.
- **DOC105**: Argument type hints in docstring don't match signature. Since `arg-type-hints-in-docstring = false`, this should not occur — if it does, remove type hints from the docstring.
- **DOC106–DOC108**: Type hint presence mismatches with configuration. Ensure types are in the signature only, not in the docstring.
- **DOC109–DOC111**: Docstring type hint presence mismatches. Remove type hints from docstring arg descriptions (our config is `false`).

### Return Mismatches (DOC201–DOC203)
- **DOC201**: Function returns a value but docstring has no `Returns:` section. Add one.
- **DOC202**: Docstring has a `Returns:` section but function doesn't return anything. Remove it.
- **DOC203**: Return type in docstring doesn't match annotation. Fix the docstring to match the annotation.

### Class and __init__ Issues (DOC301–DOC307)
- **DOC301**: `__init__()` has a docstring but shouldn't (per config). Move content to the class docstring.
- **DOC302/DOC303**: Class or `__init__` docstring has a Returns section. Remove it.
- **DOC304**: Class docstring has an Args section. Move it to `__init__()`.
- **DOC305**: Class docstring has a Raises section. Move it to `__init__()`.
- **DOC306/DOC307**: Class or `__init__` docstring has a Yields section. Remove it.

### Yield Mismatches (DOC401–DOC405)
- **DOC401/DOC402**: Generator function missing `Yields:` section. Add one.
- **DOC403**: Docstring has `Yields:` but function doesn't yield. Remove it.
- **DOC404**: Yield type in docstring doesn't match annotation. Fix the docstring.
- **DOC405**: Function has both return and yield. Use `Generator[YieldType, SendType, ReturnType]` annotation and document accordingly.

### Raise Mismatches (DOC501–DOC504)
- **DOC501**: Function raises exceptions but docstring has no `Raises:` section. Add one documenting each exception.
- **DOC502**: Docstring has `Raises:` but function doesn't raise. Remove it.
- **DOC503**: Exceptions in `Raises:` section don't match the function body. Fix the docstring to match actual raises.
- **DOC504**: Function has assert statements but no `Raises:` section for `AssertionError`. Add it if configured to check.

### Class Attribute Mismatches (DOC601–DOC605)
- **DOC601**: Class docstring is missing attributes. Add them to the `Attributes:` section.
- **DOC602**: Class docstring has extra attributes. Remove them.
- **DOC603**: Attribute names differ. Correct the docstring to match actual attributes.
- **DOC604**: Attributes are in wrong order. Reorder to match class definition.
- **DOC605**: Attribute type hints don't match. Fix the docstring types.

## False Positives

If you encounter a finding that you have thoroughly verified is a genuine false positive — meaning the docstring is correct and pydoclint is wrong — **do not suppress it**. Instead, **stop and use the `AskUserQuestion` tool** to describe the finding, explain why you believe it is a false positive, and ask the user how they want to handle it. Do not proceed past a confirmed false positive without user direction.

## Constraints

- **Do not break existing functionality.** Docstring fixes must not alter code behavior.
- **Do not delete functions, methods, or classes** to eliminate docstring findings.
- **All fixes must also pass ruff and basedpyright.** Do not introduce lint or type checking violations while fixing docstrings.
- **Re-run pydoclint after every batch of fixes** to verify convergence toward zero findings.
- **Docstrings must be kept in sync with code.** If fixing a docstring reveals that the function signature is also wrong (e.g., missing return annotation that pydoclint needs to validate against), fix both the docstring and the annotation together.

## Completion Criteria

The task is complete when `pixi run pydoclint --quiet src/ tests/` returns **zero findings** with **zero suppression comments or configuration changes** anywhere in the codebase.
