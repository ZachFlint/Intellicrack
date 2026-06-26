# Intellicrack Test-Gate Audit

Every `test_*.py` under `tests/` (excluding vendored suites) was read in full and evaluated against a single criterion: **if the production capability the test covers were broken, removed, or made to return wrong data, would this test FAIL?** A test that stays green under a realistic breakage is not a production gate and is flagged below.

**Independent verification:** 372 of 372 findings have been re-checked by hand against the actual test and production source. Each confirmed finding is tagged _[verified accurate]_, _[CORRECTED]_, or _[RECLASSIFIED]_; findings proven wrong were moved to the refuted section or removed.

## Totals

- Test files audited: **353**
- Findings (after verification): **372** (0 removed as invalid)
- Flags refuted on verification (genuine gates): **60**
- **Confirmed non-gate tests: 312**
  - high: **55**, medium: **108**, low: **149**

## Confirmed defects by category

| Category | Count | Meaning |
| --- | ---: | --- |
| `weak-existence` | 181 | Asserts only not-None / isinstance / hasattr / truthiness - a thin impl passes |
| `tautological` | 50 | Assertion always true / circular (asserts a value the test itself set) |
| `no-assertion` | 29 | No behavioral assertion - only 'does not raise' smoke |
| `conditional-never-runs` | 12 | Assertions guarded so the body never executes in CI |
| `skip-masks-failure` | 12 | Skips/xfails when capability missing so a broken build goes green |
| `other` | 9 | Other reason the test cannot fail on real breakage |
| `swallows-failure` | 6 | try/except or 'or' that lets the failure path pass the test |
| `mock-shadows-target` | 6 | Replaces the unit under test; assertion checks the canned value |
| `asserts-on-stub-output` | 4 | Expected value matches a hardcoded/thin prod return (circular) |
| `mock-call-only` | 3 | Asserts only that a collaborator was called, never the real produced effect |

## Confirmed defects by test group

| Group | Confirmed | high | med | low | Refuted | Report |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `tests/test_audit3` | 15 | 4 | 3 | 8 | 0 | [test_audit3.md](test_audit3.md) |
| `tests/test_audit4` | 19 | 1 | 4 | 14 | 3 | [test_audit4.md](test_audit4.md) |
| `tests/test_audit5` | 4 | 1 | 1 | 2 | 5 | [test_audit5.md](test_audit5.md) |
| `tests/test_audit7` | 11 | 2 | 3 | 6 | 1 | [test_audit7.md](test_audit7.md) |
| `tests/test_bridges` | 38 | 10 | 20 | 8 | 7 | [test_bridges.md](test_bridges.md) |
| `tests/test_core` | 19 | 6 | 7 | 6 | 1 | [test_core.md](test_core.md) |
| `tests/test_credentials` | 2 | 0 | 1 | 1 | 0 | [test_credentials.md](test_credentials.md) |
| `tests/test_hexcore_e2e` | 104 | 16 | 24 | 64 | 14 | [test_hexcore_e2e.md](test_hexcore_e2e.md) |
| `tests/test_hexpat` | 3 | 0 | 1 | 2 | 2 | [test_hexpat.md](test_hexpat.md) |
| `tests/test_providers` | 40 | 6 | 21 | 13 | 5 | [test_providers.md](test_providers.md) |
| `tests/test_sandbox` | 22 | 5 | 7 | 10 | 3 | [test_sandbox.md](test_sandbox.md) |
| `tests/test_ui` | 35 | 4 | 16 | 15 | 19 | [test_ui.md](test_ui.md) |

## Methodology

- **Finder pass:** 71 Sonnet 4.6 agents read each chunk of ~5 test files plus the production source under test and flagged every test that would stay green under a realistic breakage.
- **Adversarial verify pass:** one verifier per chunk tried to refute each flag by constructing a real breakage the test would catch (67 findings on Sonnet 4.6, 305 on Haiku 4.5).
- **Independent hand-verification:** each finding re-checked directly against the cited test and production code; inaccurate findings corrected, reclassified, or removed.
