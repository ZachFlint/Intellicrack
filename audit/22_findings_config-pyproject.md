> # Workgroup Directive — Execution Order 22/23: `config-pyproject`
>
> Spawn a multi-agent workgroup to drive **every F-#### finding below** to
> production release-ready. The workgroup must run this pipeline for every
> finding in this file:
>
> 1. **`developer`** agents (in parallel where findings touch disjoint
>    files) — implement the full fix per the finding's `Suggested
>    remediation summary`. No placeholders, mocks, stubs, hardcoded
>    returns, or fake-success paths. Re-verify each finding against the
>    cited source/lines before fixing; if already resolved, annotate
>    `[obsolete]` with the resolving commit hash and move on.
> 2. **`code-reviewer`** — verify each fix actually addresses the failure
>    mode described in `Why this is non-functional` and audit every caller
>    listed under `Callers / blast radius` for regressions.
> 3. **`test-writer`** — author production-grade tests that fail without
>    the fix and pass with it. Tests must execute against real binaries,
>    real bridges, and real protocols. No mocks of the unit under test.
> 4. **`test-reviewer`** — confirm tests genuinely validate the fix and
>    meet Intellicrack's no-mock standard.
> 5. **`linter`** — run `ruff check`, `basedpyright`, `pydoclint`, and
>    `pydocstyle`; resolve every finding without suppression directives.
>
> Hard constraints (non-negotiable):
>
> - Production-ready and immediately deployable; zero placeholders, mocks,
>   stubs, simulated implementations, or fake-success returns.
> - `ruff check` clean, fully `basedpyright` compliant, `pydoclint` and
>   `pydocstyle` clean — no inline suppression directives of any kind.
> - Windows-first compatibility, preserve existing functionality, never
>   delete a method binding — implement the missing function instead.
> - When this file is fully processed, every F-#### below must be either
>   fixed-and-tested or annotated `[obsolete]` with the resolving commit.
> - **All work for this file ships as one single PR (one PR per prompt /
>   per file).** Every F-#### in this file must be batched into the same
>   PR — do not split findings across multiple PRs, and do not merge any
>   subset until the whole file is fixed-and-tested or annotated
>   `[obsolete]`.
>
> ---
>
# Findings: config-pyproject

## Files audited (1)

- `pyproject.toml`

## Findings

### Category 23 - Build Metadata Lies

#### F-0001 - `pyproject.toml` redundantly declares 95+ dev/test/docs/profile packages as runtime `dependencies`

- **File:** `pyproject.toml:43-154`
- **Pattern:** Cat 23, Cat 12
- **Why non-factual:** `pip install intellicrack` pulls pytest, mypy, bandit, basedpyright, ruff, sphinx, mkdocs-material, pre-commit, tox, nox, twine, monkeytype, pyannotate, safety, commitizen, bumpversion as runtime requirements. These are development-time tooling packages that have no business in the published distribution's `[project].dependencies` list — they belong in `[dependency-groups]` / `[project.optional-dependencies]` extras (`dev`, `test`, `docs`, `profile`) instead.
- **Suggested remediation summary:** Move every dev/test/docs/profile-only package from `[project].dependencies` into the appropriate `[dependency-groups]` table (`dev`, `test`, `docs`, `profile`) so that `pip install intellicrack` only pulls genuine runtime requirements. Verify against the existing pixi feature/environment layout in `pyproject.toml` to keep tool resolution consistent.
