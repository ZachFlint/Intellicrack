# Group 10 Verification Report
## Section 11 — Credentials & OAuth, ops #65–#127

**Auditor:** group-10 (adversarial test-reviewer)
**Assigned range:** ops #65–#127 (store.py and env_loader.py portions of section-11 inventory)
**Worst Offenders in range:** 2a (op #79), 2b (op #108), 2d (op #116)
**Date:** 2026-06-27

---

## Methodology

Enumerated every non-REAL row in the ops #65–127 range from the audit table,
then searched `tests/test_credentials/`, `tests/test_providers/`,
and the full `tests/` tree for any test now gating each operation.
The remediation added `tests/test_credentials/test_oauth_section11_gates.py`.
No other new files under `tests/test_credentials/` exist beyond the six files
present at the time of the original audit.

Checked per-operation:
- `test_oauth_section11_gates.py` — new remediation file
- `test_realcov_15_store_api.py` — pre-existing/strengthened
- `test_credential_store_live.py` — pre-existing
- `test_env_loader_roundtrip_live.py` — pre-existing
- `tests/test_providers/test_credential_loading.py` — pre-existing/strengthened

---

## Findings Table

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation) |
|---|------------------------|-----------------|-----|------------------------------------------|
| 67 | `CredentialStore._deserialize_credentials` — malformed JSON (store.py:238) | NO COVERAGE | RESOLVED | `test_oauth_section11_gates.py:941` · oracle=`CredentialStoreError` type + match pattern · mutation: catch-and-return-None instead of raising turns test red |
| 70 | `CredentialStore._deserialize_metadata` — corrupted fallback (store.py:282) | NO COVERAGE | NOT_RESOLVED | No test found. Nothing in any test file calls `_deserialize_metadata` with corrupt input or asserts the fallback `StoredCredential`. |
| 72 | `CredentialStore.get_or_raise` — found (store.py:442) | NO COVERAGE | RESOLVED | `test_oauth_section11_gates.py:922` · oracle=literal "gate_test_key_section11" injected by test · mutation: returning None raises AttributeError and turns test red |
| 73 | `CredentialStore.get_or_raise` — not found (store.py:455) | NO COVERAGE | RESOLVED | `test_oauth_section11_gates.py:898` · oracle=`CredentialNotFoundError` type + `match="ollama"` · mutation: raising generic `Exception` instead turns test red |
| 74 | `CredentialStore.set` — keyring unavailable (store.py:485) | NO COVERAGE | NOT_RESOLVED | No test constructs a `CredentialStore` with `keyring_available=False` and calls `set`. `test_realcov_15_store_api.py` skips when keyring is unavailable. |
| 76 | `CredentialStore.delete` — keyring unavailable (store.py:508) | NO COVERAGE | NOT_RESOLVED | No test exercises `delete` when keyring is unavailable. Same skip pattern applies in the live tests. |
| 78 | `CredentialStore.delete` — credential not found (store.py:518) | NO COVERAGE | NOT_RESOLVED | No test calls `delete` for a provider that was never stored and asserts `False` return. `test_credential_roundtrip_live` only deletes a credential that was just written. |
| 79 | `CredentialStore.list_providers` — WEAK (store.py:536) | WEAK | NOT_RESOLVED | `test_credential_store_live.py:185` still asserts only `assert isinstance(result, list)`. No test asserts entry fields (`provider`, `key_name`, `source`, timestamps). Deleting the metadata-assembly loop and returning `[]` always leaves the test green. |
| 80 | `CredentialStore.migrate_from_env` — keyring unavailable (store.py:591) | NO COVERAGE | NOT_RESOLVED | All `migrate_from_env` tests in `test_realcov_15_store_api.py` skip when `_keyring_usable()` returns False. The `KeyringUnavailableError` path (store.py:591) is never exercised. |
| 83 | `CredentialStore.migrate_from_env` — env missing key (store.py:601) | NO COVERAGE | NOT_RESOLVED | All `migrate_from_env` tests inject the key being migrated into the env file. No test passes a provider whose env var is absent and asserts `result[provider] is False`. |
| 85 | `CredentialStore.validate` — no credentials (store.py:637) | NO COVERAGE | NOT_RESOLVED | All `validate` tests in `test_realcov_15_store_api.py` write a credential before calling `validate`. The early-return path where no credential exists and `validate` returns `(False, message)` is never exercised. |
| 88 | `CredentialStore.get_source` — no credential returns None (store.py:689) | NO COVERAGE | NOT_RESOLVED | `test_realcov_15_store_api.py:394` and `:420` cover KEYRING and ENV_FILE paths. Neither test exercises `get_source` when no credential exists and asserts `None` is returned. |
| 92 | `_decode_double_quoted` — unknown escape pass-through (env_loader.py:69) | NO COVERAGE | NOT_RESOLVED | The parametrized round-trip tests in `test_env_loader_roundtrip_live.py` test quoter→parser pairs but never drive `_decode_double_quoted` with a raw `\q`-style unknown escape and assert the documented pass-through (backslash dropped, char kept). |
| 106 | `CredentialLoader._load_env_file` — file missing (env_loader.py:348) | NO COVERAGE | NOT_RESOLVED | `_make_keyring_free_store` in `test_oauth_section11_gates.py:145` constructs a loader pointing at a nonexistent path but uses it only as a keyring fallback; no assertion on the silent-return behaviour of `_load_env_file` when the file is absent. |
| 107 | `CredentialLoader._load_env_file` — read error (env_loader.py:357) | NO COVERAGE | NOT_RESOLVED | No test injects a file that raises `OSError` on read (e.g. via `monkeypatch` of `open`) and asserts the loader handles it silently. |
| 110 | `CredentialLoader.get_credentials` — alias lookup (env_loader.py:406) | NO COVERAGE | NOT_RESOLVED | No test writes only `GEMINI_API_KEY` (without `GOOGLE_API_KEY`) and asserts `get_credentials(ProviderName.GOOGLE)` returns the alias value. Code in `test_credential_loading.py:114` clears aliases but does not exercise the alias-resolution path itself. |
| 112 | `CredentialLoader.get_credentials` — unknown provider (env_loader.py:396) | NO COVERAGE | NOT_RESOLVED | `_assert_get_credentials_value` tests a key-absent provider (op #111 path), not a provider absent from `PROVIDER_MAPPINGS` (op #112 early-return path at env_loader.py:396). |
| 123 | `CredentialLoader.save_to_env_file` — read error (env_loader.py:602) | NO COVERAGE | NOT_RESOLVED | No test patches `open` to raise `OSError` on read of an existing `.env` file and asserts the error is re-raised. |
| 124 | `CredentialLoader.save_to_env_file` — write error (env_loader.py:642) | NO COVERAGE | NOT_RESOLVED | No test patches `open` to raise `OSError` on the write call and asserts it propagates. |
| 125 | `get_api_key_env_var_mapping` (env_loader.py:655) | NO COVERAGE | NOT_RESOLVED | Zero tests found in the entire test tree that call or assert on `get_api_key_env_var_mapping`. |
| 126 | `create_env_template` (env_loader.py:667) | NO COVERAGE | NOT_RESOLVED | Zero tests found for `create_env_template`. |
| 127 | `get_credential_loader` — singleton/lru_cache (env_loader.py:710) | NO COVERAGE | NOT_RESOLVED | No test calls `get_credential_loader()` twice and asserts object identity, or exercises the `lru_cache` guarantee. |

### Worst Offenders in range (ops #65–#127)

| Offender | Operation | Original verdict | Now | Evidence |
|----------|-----------|-----------------|-----|----------|
| 2a | `CredentialStore.list_providers` (op #79) | WEAK GATE | NOT_RESOLVED | Same as row #79 above — `test_credential_store_live.py:185` only asserts `isinstance(result, list)`. |
| 2b | `CredentialLoader.reload` (op #108; table says REAL) | ENVIRONMENT-DEPENDENT/WEAK | NOT_RESOLVED | `test_credential_loading.py:476–488` asserts `before == after` using the ambient `.env`. When the file is empty or absent, both sets are empty and the test passes vacuously without verifying that `reload` re-reads the file at all. No controlled test writes a key, calls `reload`, and asserts the loader picks it up. |
| 2d | `CredentialLoader.list_configured_providers` (op #116; table says REAL) | TYPE-ONLY CHECK | NOT_RESOLVED | `test_credential_loading.py:293–304` checks `isinstance(configured, list)` and `isinstance(provider, ProviderName)`. A new test `test_configured_and_missing_cover_all_providers` at :321 asserts `configured ∪ missing == all_providers`, but this partition property is satisfied even if `list_configured_providers` always returns `[]` (as long as `list_missing_providers` returns all providers). Neither test would turn red if `list_configured_providers` were replaced with a function that always returns `[]`. |

---

## STILL OPEN

All 21 NOT_RESOLVED findings listed below. Every one of them has no real
falsifiable gate — deleting or corrupting the production code path would not
turn any existing test red.

1. **op #70** — `CredentialStore._deserialize_metadata` corrupted fallback (store.py:282) :: No test at all :: Need: `store._deserialize_metadata("corrupt-json")` and assert returned `StoredCredential` has default field values (provider source, created_at fallback).
2. **op #74** — `CredentialStore.set` keyring unavailable (store.py:485) :: Only tests skip when unavailable :: Need: construct `CredentialStore` with `_keyring_available=False`, call `set(...)`, assert `KeyringUnavailableError` is raised.
3. **op #76** — `CredentialStore.delete` keyring unavailable (store.py:508) :: Only tests skip when unavailable :: Need: same setup as #74, call `delete(...)`, assert `KeyringUnavailableError`.
4. **op #78** — `CredentialStore.delete` credential not found (store.py:518) :: No test :: Need: keyring-free store with no entries, call `delete(provider)`, assert returns `False`.
5. **op #79** — `CredentialStore.list_providers` content (store.py:536) :: Only `isinstance(result, list)` assertion :: Need: seed a credential, call `list_providers()`, assert the returned entry has `entry.provider == ProviderName.OLLAMA` and `entry.source == CredentialSource.KEYRING`.
6. **op #80** — `CredentialStore.migrate_from_env` keyring unavailable (store.py:591) :: All tests skip when unavailable :: Need: keyring-free store, call `migrate_from_env(...)`, assert `KeyringUnavailableError` is raised.
7. **op #83** — `CredentialStore.migrate_from_env` env missing key (store.py:601) :: No test :: Need: env file without the specified provider's var, call `migrate_from_env([provider])`, assert `result[provider] is False`.
8. **op #85** — `CredentialStore.validate` no credentials (store.py:637) :: All validate tests pre-seed credentials :: Need: keyring-free store with no entries, call `validate(provider)`, assert `(False, non-empty-str)`.
9. **op #88** — `CredentialStore.get_source` no credential returns None (store.py:689) :: Tests only cover KEYRING and ENV_FILE paths :: Need: keyring-free store, no env entry, call `get_source(provider)`, assert returns `None`.
10. **op #92** — `_decode_double_quoted` unknown escape pass-through (env_loader.py:69) :: No test :: Need: call `_decode_double_quoted('"val\\qend"')` and assert result == `"valqend"` (backslash dropped, char kept) per the documented behaviour.
11. **op #106** — `CredentialLoader._load_env_file` file missing (env_loader.py:348) :: No assertion on silent-return :: Need: `CredentialLoader(env_path=Path("/does/not/exist/.env"))`, assert `get_credentials(provider) is None` and no exception raised.
12. **op #107** — `CredentialLoader._load_env_file` read error (env_loader.py:357) :: No test :: Need: monkeypatch `open` to raise `OSError`, construct loader pointing at an existing file, assert loader initialises without raising and returns no credentials.
13. **op #110** — `CredentialLoader.get_credentials` alias lookup (env_loader.py:406) :: No test :: Need: env file containing only `GEMINI_API_KEY=AIzaXXXX`, assert `get_credentials(ProviderName.GOOGLE).api_key == "AIzaXXXX"`.
14. **op #112** — `CredentialLoader.get_credentials` unknown provider (env_loader.py:396) :: No test :: Need: call `get_credentials` with a provider not present in `PROVIDER_MAPPINGS` (if extensible) or confirm the early-return branch is dead code; either way, the branch has no gate.
15. **op #123** — `CredentialLoader.save_to_env_file` read error (env_loader.py:602) :: No test :: Need: monkeypatch `open` to raise `OSError` on read, call `save_to_env_file(...)`, assert `OSError` propagates.
16. **op #124** — `CredentialLoader.save_to_env_file` write error (env_loader.py:642) :: No test :: Need: monkeypatch `open` to raise `OSError` on write, call `save_to_env_file(...)`, assert `OSError` propagates.
17. **op #125** — `get_api_key_env_var_mapping` (env_loader.py:655) :: No test :: Need: call `get_api_key_env_var_mapping()`, assert it returns a dict mapping every `ProviderName` to a non-empty env-var string.
18. **op #126** — `create_env_template` (env_loader.py:667) :: No test :: Need: call `create_env_template()`, assert it returns a string containing at least one `ANTHROPIC_API_KEY=` placeholder.
19. **op #127** — `get_credential_loader` singleton (env_loader.py:710) :: No test :: Need: call `get_credential_loader()` twice, assert `result1 is result2` (lru_cache identity guarantee).
20. **Worst Offender 2b** — `CredentialLoader.reload` (op #108) :: Vacuously passes when `.env` is empty :: Need: write a key to a temp `.env` file, construct loader, call `reload()` after the key is present, assert `list_configured_providers()` now includes that provider (proving reload re-read the file).
21. **Worst Offender 2d** — `CredentialLoader.list_configured_providers` (op #116) :: Only type assertions and partition test that can be satisfied by `always-return-[]` :: Need: write exactly one provider's key to a controlled env file, call `list_configured_providers()`, assert the exact provider is in the result.
