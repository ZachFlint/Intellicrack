---
description: Run Clippy linter via justfile and fix all findings in Intellicrack Rust hexcore crate. Invoke manually with /lint-rust.
argument-hint: [--flag...]
allowed-tools: Read, Edit, Glob, Grep, Bash
---

You are fixing Clippy lint findings for the Intellicrack hexcore crate (`src/intellicrack-hexcore/`), a high-performance Rust library providing binary analysis primitives (entropy, hashing, search, diff, transforms, data inspection, memory-mapped I/O, piece table, undo, patch export). Every function in this crate exists for a reason. Your default stance is to **fix the code to satisfy the lint**, not suppress it. Suppression is the last resort, only after you have confirmed the lint is a genuine false positive and received user approval.

## Crate Layout

- **Crate root**: `src/intellicrack-hexcore/`
- **Source files**: `src/intellicrack-hexcore/src/*.rs`
- **Templates**: `src/intellicrack-hexcore/src/templates/`
- **Tests**: inline `#[cfg(test)]` modules within source files
- **Cargo.toml**: `src/intellicrack-hexcore/Cargo.toml`

## Execution

1. Review all findings in the **Findings** section below. Group them by file, then by severity.
2. Work **one file at a time**. Read the file, understand its purpose and surrounding context before making changes.
3. Fix **every single finding** in the current file before moving to the next.
4. After completing each file, re-run Clippy on the crate to confirm zero findings remain from that file and no new findings were introduced:
   ```
   cd src/intellicrack-hexcore && pixi run cargo clippy --all-targets -- -W clippy::all -W clippy::pedantic 2>&1
   ```
5. After completing all files, run a full Clippy check:
   ```
   cd src/intellicrack-hexcore && pixi run cargo clippy --all-targets -- -W clippy::all -W clippy::pedantic 2>&1
   ```
6. If the full check reveals new findings (from cross-file effects of your changes), fix those too.
7. Repeat until Clippy returns **zero warnings**.

## Rules -- Non-Negotiable

- **NO `#[allow(...)]` attributes** unless you have confirmed a genuine false positive with the user. Do not add `#[allow(clippy::...)]`, `#[allow(unused_...)]`, or any other allow attribute to silence a finding. Fix the actual code.
- **NO `#[expect(...)]` attributes** to suppress findings. Same rule as `#[allow()]`.
- **NO changes to `Cargo.toml` lint configuration.** Do not modify `[lints.clippy]`, `[lints.rust]`, or any other lint configuration section. The lint config is locked.
- **NO skipping findings.** Every finding in the list must be addressed. Do not silently skip a finding because it looks difficult or ambiguous.
- **NO moving on without verification.** After fixing a file, you must re-run Clippy before proceeding to the next. Do not assume your fix worked -- confirm it.
- **NO introducing regressions.** Your Clippy fixes must not break compilation, tests, or the public API. If you change a function signature, update all call sites. If you change a type, ensure downstream code compiles.

## Agent and Subagent Oversight

If you delegate any fixes to agents or subagents:
- **You must read the actual edits** they made. Do not accept their claim that findings are fixed without reviewing the code changes yourself.
- **You must re-run Clippy** on the crate after their changes and verify zero findings.
- **You must verify compilation and tests** -- run `cd src/intellicrack-hexcore && pixi run cargo test 2>&1` on files with significant changes.
- **You are accountable for their work.** If an agent introduces an `#[allow(...)]` attribute, changes public API without updating call sites, or introduces unsafe code unnecessarily, you must catch it and fix it.

## How to Fix -- Priority Order

### Clippy Pedantic Lints

These are the most common categories. Fix them as follows:

- **`clippy::must_use_candidate`**: Add `#[must_use]` to the function with a meaningful message if appropriate, or add it without a message for simple getters/constructors.
- **`clippy::missing_errors_doc`**: Add an `# Errors` section to the function's doc comment describing when and why it returns an error.
- **`clippy::missing_panics_doc`**: Add a `# Panics` section to the function's doc comment describing when and why it panics.
- **`clippy::module_name_repetitions`**: Rename the type/function to remove the redundant module name prefix, updating all references.
- **`clippy::cast_possible_truncation`**, **`clippy::cast_sign_loss`**, **`clippy::cast_precision_loss`**: Replace raw `as` casts with safe conversion methods (`try_from`, `try_into`, `.into()`) or add explicit bounds checks before the cast. Use `u*::try_from()` with proper error handling.
- **`clippy::unnecessary_wraps`**: If a function always returns `Ok(...)` or `Some(...)`, remove the wrapper and return the inner value directly. Update all call sites.
- **`clippy::needless_pass_by_value`**: Change the parameter to a borrow (`&T` or `&str` instead of `String`). Update the function body and all call sites.
- **`clippy::redundant_closure_for_method_calls`**: Replace `.map(|x| x.method())` with `.map(Type::method)` or `.map(method)`.
- **`clippy::uninlined_format_args`**: Move variables directly into the format string: `format!("{x}")` instead of `format!("{}", x)`.
- **`clippy::items_after_statements`**: Move function/struct definitions before the first statement in the block.
- **`clippy::similar_names`**: Rename variables to be more distinct and descriptive.
- **`clippy::too_many_lines`**: Extract logical subsections into helper functions.

### Clippy Correctness and Style Lints

- **`clippy::needless_return`**: Remove explicit `return` at the end of a function; use expression position.
- **`clippy::redundant_field_names`**: Use shorthand field initialization (`Foo { bar }` instead of `Foo { bar: bar }`).
- **`clippy::single_match`**: Replace `match` with a single arm with an `if let`.
- **`clippy::manual_map`**, **`clippy::manual_filter`**: Replace manual match/if-let patterns with `.map()` or `.filter()`.
- **`clippy::len_without_is_empty`**: If a type has a `len()` method, also add an `is_empty()` method.
- **`clippy::unused_self`**: If `self` is not used, consider making the method a free function or an associated function.

### Unsafe Code

- **`clippy::undocumented_unsafe_blocks`**: Add a `// SAFETY: ...` comment directly above every `unsafe` block explaining why the operation is sound.
- **Never introduce new `unsafe` blocks** unless the existing code already uses unsafe and the fix requires it. If you must, include a thorough SAFETY comment.

### Dead Code and Unused Items

- **`dead_code`**, **`unused_imports`**, **`unused_variables`**: Determine if the item serves a purpose in the crate's functionality. If the item provides a capability the crate logically should expose (binary analysis, data processing, error handling), **write the code that uses it**. Only remove if genuinely no implementable use exists.
- **`unused_mut`**: Remove the `mut` qualifier if the variable is never mutated.

## Cross-Tool Compliance

Every fix you make must maintain compliance with the full Rust toolchain:
- **rustfmt**: Your code must remain properly formatted. Run `cd src/intellicrack-hexcore && pixi run cargo fmt` after significant edits.
- **cargo test**: Your fixes must not break any tests. Run `cd src/intellicrack-hexcore && pixi run cargo test` after fixing each file with significant changes.
- **cargo-deny**: Do not add new dependencies without checking license compliance.

## False Positives

If you encounter a finding that you have thoroughly verified is a genuine false positive -- meaning the code is correct and the lint is being triggered erroneously -- **do not suppress it**. Instead, **stop and use the `AskUserQuestion` tool** to describe the finding, explain why you believe it is a false positive, and ask the user how they want to handle it. Do not proceed past a confirmed false positive without user direction.

## Constraints

- **Do not break existing functionality.** Every fix must preserve the original behavior of the code. If a fix requires a non-trivial refactor, ensure the logic remains identical.
- **Do not change the public API** without updating all call sites, including Python bindings (PyO3 `#[pyfunction]`/`#[pymethods]` exports).
- **Maintain all documentation.** Fixes must preserve or improve doc comments. If you change a function signature, update its doc comment to match.
- **Do not batch too many files at once.** Work one file at a time and verify before moving on. Context switching across many files simultaneously leads to missed regressions.

## Completion Criteria

The task is complete when:
1. `cd src/intellicrack-hexcore && pixi run cargo clippy --all-targets -- -W clippy::all -W clippy::pedantic` returns **zero warnings**
2. **Zero `#[allow(...)]` or `#[expect(...)]` attributes** were added to silence findings
3. `cd src/intellicrack-hexcore && pixi run cargo test` passes with no regressions
4. `cd src/intellicrack-hexcore && pixi run cargo fmt -- --check` shows no formatting issues

---

## Findings

The following findings were produced by `just clippy $ARGUMENTS`:

!`just clippy $ARGUMENTS >/dev/null 2>&1 || true; cat reports/txt/clippy_findings.txt 2>/dev/null || echo "ERROR: No findings report at reports/txt/clippy_findings.txt. Run 'just clippy' manually to diagnose."`
