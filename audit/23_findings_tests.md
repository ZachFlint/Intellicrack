> # Workgroup Directive — Execution Order 23/23: `tests`
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
# Findings: tests

## Files audited (158)

All `.py` files under `D:/Intellicrack/tests/` recursively (158 Python files; no `.toml`/`.cfg`/`.ini` files exist in the tests tree). Notable directories: `tests/`, `tests/_helpers/`, `tests/core/`, `tests/test_bridges/`, `tests/test_core/`, `tests/test_credentials/`, `tests/test_hexcore_e2e/`, `tests/test_hexpat/`, `tests/test_integration/`, `tests/test_providers/`, `tests/test_sandbox/`, `tests/test_scripts/`, `tests/test_ui/`.

## Findings

### Category 22 - Test / Debug Code Leaked Into Production

**(no Category 22 findings)**

## Audit notes (informational; not findings)

- **No test/dev/debug files exist under `src/`.** A `find D:/Intellicrack/src -type f \( -name "test_*.py" -o -name "*_test.py" -o -name "_dev_*.py" -o -name "debug_*.py" -o -name "*_debug.py" -o -name "*_dev.py" -o -name "conftest.py" \)` returned zero results. Production source is free of test scaffolding.
- **No production module under `src/` imports from `tests.*`.** `rg "from tests\.|import tests\." D:/Intellicrack/src` returned 0 matches. The reverse-direction test scaffolding under `D:/Intellicrack/tests/_helpers/process_cleanup.py` is a legitimate test helper that lives in the test tree (not under `src/`) and is only imported by `tests/conftest.py`.
- **`sys.modules` is mutated in only two test files, both safely scoped:**
  - `D:/Intellicrack/tests/test_scripts/test_commit_message.py:35` registers a script-loaded `generate_commit_message` module key; this key is never consumed by any production module under `src/` (verified via `rg generate_commit_message src/` -> 0 matches), so it cannot leak into a production import path. Confined to the test process.
  - `D:/Intellicrack/tests/test_bridges/test_ghidra.py:423-433` saves and restores `sys.modules["ghidra_bridge"]` inside a `try/finally` and calls `importlib.invalidate_caches()` after restore.
- **No `sys.path.insert/append` mutation anywhere in `tests/`.**
- **Credential-looking strings** (e.g., `sk-ant-invalid-key-12345` in `tests/test_providers/test_anthropic_provider.py:207`, `sk-or-invalid-key-12345` in `tests/test_providers/test_openrouter_provider.py:246`) are literal "invalid" placeholders used to drive the providers' 401 paths. They do not appear anywhere under `src/` (`rg "sk-ant-invalid|sk-or-invalid" src/` -> 0 matches) and are not real secrets.
- **All 41 `monkeypatch.setattr/setenv/delenv` usages** across 6 test files use the pytest `monkeypatch` fixture, which auto-restores state at test teardown; no leakage risk.
- **`D:/Intellicrack/tests/test_ui/launch_splash_demo.py`** is a developer-only visual demo (the only `if __name__ == "__main__"` file in `tests/`) that ships under `tests/`, not `src/`. It does not get imported by any production module and is not packaged with the application.
- **Production source contains zero references to test machinery:** `rg "pytest\.fixture|pytest\.mark|pytest\.raises|MagicMock|MonkeyPatch|@pytest|@fixture|unittest\.mock"` against `D:/Intellicrack/src` returns 0 matches. No production code branches on `PYTEST_CURRENT_TEST` or any test-only env var.
