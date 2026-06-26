# Section 11 — Credentials & OAuth: Test Coverage Audit

**Date:** 2026-06-26
**Auditor:** test-reviewer agent (adversarial mode)
**Source scope:**
- `src/intellicrack/credentials/oauth.py`
- `src/intellicrack/credentials/store.py`
- `src/intellicrack/credentials/env_loader.py`
- `src/intellicrack/credentials/__init__.py`

**Tests located:**
- `tests/test_credentials/test_oauth_manager_live.py`
- `tests/test_credentials/test_credential_store_live.py`
- `tests/test_credentials/test_env_loader_roundtrip_live.py`
- `tests/test_credentials/test_realcov_15_store_api.py`
- `tests/test_providers/test_credential_loading.py`
- `tests/test_providers/test_provider_bugfixes.py` (partial — `TestOAuthFlowValidation`)

---

## 1. Operation Inventory Table

### oauth.py

| # | Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|-----------|-----------------|-------------------|---------|---------------|
| 1 | `_oauth_provider_to_name` — happy path | oauth.py:109 | (implicit, via _store_token/other callers) | WEAK — never exercised directly with assertion on return | KeyError when unmapped provider |
| 2 | `_oauth_provider_to_name` — KeyError path | oauth.py:121 | none | NO COVERAGE | All |
| 3 | `OAuthToken.is_expired` (5-min buffer) | oauth.py:176 | none | NO COVERAGE | Just-expired boundary, valid-with-buffer, None expires_at |
| 4 | `OAuthToken.needs_refresh` (10-min buffer) | oauth.py:188 | none | NO COVERAGE | 10-min boundary, valid, None expires_at |
| 5 | `OAuthToken.to_dict` | oauth.py:199 | none | NO COVERAGE | All fields, None values, scopes tuple |
| 6 | `OAuthToken.from_dict` | oauth.py:215 | none | NO COVERAGE | Round-trip, malformed/missing fields, None expires_at, bad type |
| 7 | `OAuthState.is_expired` (10-min timeout) | oauth.py:280 | none | NO COVERAGE | Just-expired, still-valid, boundary exactly at 10 min |
| 8 | `generate_pkce_pair` | oauth.py:334 | test_oauth_manager_live.py:180, :201; test_provider_bugfixes.py:201 | REAL | None identified |
| 9 | `verify_pkce_pair` — accept | oauth.py:350 | test_oauth_manager_live.py:186, :206; test_provider_bugfixes.py:201 | REAL | None identified |
| 10 | `verify_pkce_pair` — reject mutated verifier | oauth.py:350 | test_oauth_manager_live.py:190, :207 | REAL | None identified |
| 11 | `OAuthCallbackHandler.do_GET` — code+state, CSRF check | oauth.py:406 | test_oauth_manager_live.py:355–362 (state mismatch); :296–310 (valid) | REAL | |
| 12 | `OAuthCallbackHandler.do_GET` — error in params | oauth.py:402 | none | NO COVERAGE | "error" param triggers 400 + error message |
| 13 | `OAuthCallbackHandler.do_GET` — missing code/state | oauth.py:419 | none | NO COVERAGE | Neither "code" nor "error" branch |
| 14 | `OAuthCallbackServer.start` — bind success | oauth.py:498 | test_oauth_manager_live.py:256 | REAL (implicit) | |
| 15 | `OAuthCallbackServer.start` — OSError on bind | oauth.py:510 | none | NO COVERAGE | OAuthCallbackError raised |
| 16 | `OAuthCallbackServer.wait_for_callback` — success | oauth.py:532 | test_oauth_manager_live.py:307 | REAL | |
| 17 | `OAuthCallbackServer.wait_for_callback` — timeout | oauth.py:543 | none | NO COVERAGE | OAuthCallbackError raised |
| 18 | `OAuthCallbackServer.wait_for_callback` — denied | oauth.py:556 | none | NO COVERAGE | OAuthAuthorizationError for "denied"/"access_denied" |
| 19 | `OAuthCallbackServer.wait_for_callback` — other error | oauth.py:558 | test_oauth_manager_live.py:361 | REAL | |
| 20 | `OAuthCallbackServer.wait_for_callback` — missing code/state | oauth.py:566 | none | NO COVERAGE | OAuthCallbackError for null code or state |
| 21 | `OAuthCallbackServer.stop` | oauth.py:573 | test_oauth_manager_live.py (finally blocks) | REAL (implicit) | |
| 22 | `OAuthManager.build_authorization_url` — valid config | oauth.py:680 | test_provider_bugfixes.py:181; test_oauth_manager_live.py:249 | REAL | |
| 23 | `OAuthManager.build_authorization_url` — missing client_id | oauth.py:692 | test_provider_bugfixes.py:224 | REAL | |
| 24 | `OAuthManager.build_authorization_url` — PKCE disabled | oauth.py:701 | none | NO COVERAGE | code_challenge params must be absent |
| 25 | `OAuthManager.start_authorization_flow` | oauth.py:731 | test_oauth_manager_live.py:245 | REAL | open_browser=True path |
| 26 | `OAuthManager.handle_callback` — happy path | oauth.py:761 | test_oauth_manager_live.py:311 | REAL | |
| 27 | `OAuthManager.handle_callback` — unknown state | oauth.py:786 | none | NO COVERAGE | OAuthCallbackError |
| 28 | `OAuthManager.handle_callback` — expired state | oauth.py:791 | none | NO COVERAGE | OAuthCallbackError |
| 29 | `OAuthManager.handle_callback` — PKCE verifier missing | oauth.py:796 | none | NO COVERAGE | OAuthCallbackError |
| 30 | `OAuthManager._post_token_exchange` | oauth.py:816 | test_oauth_manager_live.py:268–276 (via handle_callback) | REAL | Non-2xx HTTP errors propagated |
| 31 | `OAuthManager._exchange_code_for_token` — HTTP error | oauth.py:901 | none direct | NO COVERAGE | OAuthTokenError wraps HTTPStatusError |
| 32 | `OAuthManager._exchange_code_for_token` — network error | oauth.py:906 | none direct | NO COVERAGE | OAuthTokenError wraps RequestError/OSError |
| 33 | `OAuthManager._store_token` — no credential store | oauth.py:920 | test_oauth_manager_live.py (credential_store=None in all tests) | REAL (implicit path taken) | |
| 34 | `OAuthManager._store_token` — keyring unavailable | oauth.py:924 | none | NO COVERAGE | Warning only, no error raised |
| 35 | `OAuthManager._store_token` — keyring success | oauth.py:935 | none | NO COVERAGE | Token stored as JSON, exact keyring entry |
| 36 | `OAuthManager._load_token_from_store` | oauth.py:953 | none | NO COVERAGE | Returns token, None path, JSON decode error |
| 37 | `OAuthManager._load_token` — cache hit | oauth.py:1003 | test_oauth_manager_live.py:387 (seeds cache, but no assertion on cache path) | WEAK — cache seeded by helper, not via real store |
| 38 | `OAuthManager._load_token` — cache miss, keyring load | oauth.py:1006 | none | NO COVERAGE | |
| 39 | `OAuthManager._load_token` — JSON decode error | oauth.py:1020 | none | NO COVERAGE | Warning + returns None |
| 40 | `OAuthManager.get_token` — no token | oauth.py:1047 | none | NO COVERAGE | Returns None |
| 41 | `OAuthManager.get_token` — valid, no refresh needed | oauth.py:1062 | none | NO COVERAGE | Returns token as-is |
| 42 | `OAuthManager.get_token` — needs_refresh, auto_refresh=True | oauth.py:1052 | none | NO COVERAGE | refresh_token called |
| 43 | `OAuthManager.get_token` — needs_refresh, refresh fails with OAuthTokenRefreshError | oauth.py:1056 | none | NO COVERAGE | Returns None |
| 44 | `OAuthManager.get_token` — needs_refresh, refresh fails OAuthTokenError, not expired | oauth.py:1059 | none | NO COVERAGE | Returns stale but not-expired token |
| 45 | `OAuthManager.get_token` — expired after failed refresh | oauth.py:1062 | none | NO COVERAGE | Returns None even if OAuthTokenError |
| 46 | `OAuthManager._post_token_refresh` | oauth.py:1064 | test_oauth_manager_live.py:419, :455 (via refresh_token) | REAL (error paths); happy path never asserted | Happy path token fields |
| 47 | `OAuthManager.refresh_token` — 401 response | oauth.py:1178 | test_oauth_manager_live.py:419 | REAL | |
| 48 | `OAuthManager.refresh_token` — 403 response | oauth.py:1178 | none | NO COVERAGE | 403 must also raise OAuthTokenRefreshError |
| 49 | `OAuthManager.refresh_token` — other HTTP error | oauth.py:1181 | none | NO COVERAGE | OAuthTokenError (non-auth) |
| 50 | `OAuthManager.refresh_token` — network error | oauth.py:1183 | test_oauth_manager_live.py:454 | REAL | |
| 51 | `OAuthManager.refresh_token` — no refresh token | oauth.py:1148 | none | NO COVERAGE | OAuthTokenError raised |
| 52 | `OAuthManager.revoke_token` — no token | oauth.py:1209 | none | NO COVERAGE | Returns False |
| 53 | `OAuthManager.revoke_token` — no revoke_url | oauth.py:1213 | none | NO COVERAGE | Skips remote, deletes from keyring |
| 54 | `OAuthManager.revoke_token` — with revoke_url, success | oauth.py:1218 | none | NO COVERAGE | |
| 55 | `OAuthManager.revoke_token` — revoke HTTP error | oauth.py:1230 | none | NO COVERAGE | revoke_succeeded=False |
| 56 | `OAuthManager.revoke_token` — cache always cleared | oauth.py:1240 | none | NO COVERAGE | Cache cleared even on failure |
| 57 | `OAuthManager.to_provider_credentials` | oauth.py:1268 | none | NO COVERAGE | Returns ProviderCredentials with access_token |
| 58 | `OAuthManager.run_authorization_flow` | oauth.py:1290 | none | NO COVERAGE | All |
| 59 | `get_oauth_manager` — singleton | oauth.py:1350 | test_oauth_manager_live.py:151 | REAL | |
| 60 | `authorize_google` | oauth.py:1368 | none | NO COVERAGE | All |

### store.py

| # | Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|-----------|-----------------|-------------------|---------|---------------|
| 61 | `CredentialStore._check_keyring` — library not installed | store.py:147 | none explicit | NO COVERAGE | Returns False, logs warning |
| 62 | `CredentialStore._check_keyring` — fail/null backend | store.py:161 | none | NO COVERAGE | Returns False |
| 63 | `CredentialStore._check_keyring` — priority <= 0 | store.py:169 | none | NO COVERAGE | Returns False |
| 64 | `CredentialStore._check_keyring` — success | store.py:179 | test_credential_store_live.py:163 (implicit, called via keyring_available) | REAL (if keyring available on host) | |
| 65 | `CredentialStore._serialize_credentials` | store.py:204 | test_credential_store_live.py:242 (roundtrip) | REAL (implicit) | None |
| 66 | `CredentialStore._deserialize_credentials` — valid JSON | store.py:218 | test_credential_store_live.py:242 (roundtrip) | REAL (implicit) | |
| 67 | `CredentialStore._deserialize_credentials` — malformed JSON | store.py:238 | none | NO COVERAGE | CredentialStoreError raised |
| 68 | `CredentialStore._serialize_metadata` | store.py:243 | test_credential_store_live.py:242 (roundtrip) | REAL (implicit) | |
| 69 | `CredentialStore._deserialize_metadata` — valid | store.py:263 | test_credential_store_live.py:242 (roundtrip) | REAL (implicit) | |
| 70 | `CredentialStore._deserialize_metadata` — corrupted fallback | store.py:282 | none | NO COVERAGE | Fallback StoredCredential returned |
| 71 | `CredentialStore.get` — keyring first, then env | store.py:420 | test_realcov_15_store_api.py:161 | REAL | |
| 72 | `CredentialStore.get_or_raise` — found | store.py:442 | none | NO COVERAGE | |
| 73 | `CredentialStore.get_or_raise` — not found | store.py:455 | none | NO COVERAGE | CredentialNotFoundError raised |
| 74 | `CredentialStore.set` — keyring unavailable | store.py:485 | none | NO COVERAGE | KeyringUnavailableError raised |
| 75 | `CredentialStore.set` — success | store.py:461 | test_credential_store_live.py:252; test_realcov_15_store_api.py:162 | REAL (conditional on keyring) | |
| 76 | `CredentialStore.delete` — keyring unavailable | store.py:508 | none | NO COVERAGE | KeyringUnavailableError raised |
| 77 | `CredentialStore.delete` — success | store.py:496 | test_credential_store_live.py:266 | REAL (conditional on keyring) | |
| 78 | `CredentialStore.delete` — credential not found | store.py:518 | none | NO COVERAGE | Returns False |
| 79 | `CredentialStore.list_providers` | store.py:536 | test_credential_store_live.py:182 | WEAK — only `assert isinstance(result, list)` | Content not validated |
| 80 | `CredentialStore.migrate_from_env` — keyring unavailable | store.py:591 | none | NO COVERAGE | KeyringUnavailableError raised |
| 81 | `CredentialStore.migrate_from_env` — overwrite=False skip | store.py:605 | test_realcov_15_store_api.py:255 | REAL | |
| 82 | `CredentialStore.migrate_from_env` — overwrite=True replace | store.py:612 | test_realcov_15_store_api.py:285 | REAL | |
| 83 | `CredentialStore.migrate_from_env` — env missing key | store.py:601 | none explicit | NO COVERAGE | results[provider]=False |
| 84 | `CredentialStore.validate` — per-provider prefix (all 6 providers) | store.py:641 | test_realcov_15_store_api.py:356 | REAL | |
| 85 | `CredentialStore.validate` — no credentials | store.py:637 | none | NO COVERAGE | Returns (False, message) |
| 86 | `CredentialStore.get_source` — KEYRING | store.py:663 | test_realcov_15_store_api.py:411 | REAL | |
| 87 | `CredentialStore.get_source` — ENV_FILE/ENV_VAR | store.py:680 | test_realcov_15_store_api.py:445 | REAL | |
| 88 | `CredentialStore.get_source` — no credential | store.py:689 | none | NO COVERAGE | Returns None |
| 89 | `get_credential_store` — singleton | store.py:709 | test_credential_store_live.py:188 | REAL | |
| 90 | `get_credentials` wrapper | store.py:726 | test_realcov_15_store_api.py:161 | REAL | |

### env_loader.py

| # | Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|-----------|-----------------|-------------------|---------|---------------|
| 91 | `_decode_double_quoted` — known escapes | env_loader.py:36 | test_env_loader_roundtrip_live.py:70 (via parametrized round-trip) | REAL | Unknown escape (pass-through) |
| 92 | `_decode_double_quoted` — unknown escape pass-through | env_loader.py:69 | none explicit | NO COVERAGE | Behavior: drops backslash, keeps char |
| 93 | `_strip_unquoted_inline_comment` | env_loader.py:77 | test_env_loader_roundtrip_live.py:186 (inline_hash_space case) | REAL | hash at position 0 |
| 94 | `_parse_env_value` — double quoted | env_loader.py:118 | test_env_loader_roundtrip_live.py:70 (round-trip); :186 | REAL | |
| 95 | `_parse_env_value` — single quoted | env_loader.py:127 | test_env_loader_roundtrip_live.py:186 ("SINGLE='single quoted'") | REAL | |
| 96 | `_parse_env_value` — unquoted | env_loader.py:132 | test_env_loader_roundtrip_live.py:186 ("UNQUOTED=simple_value") | REAL | |
| 97 | `_parse_env_value` — empty | env_loader.py:115 | test_env_loader_roundtrip_live.py:70 (empty label) | REAL | |
| 98 | `_parse_env_text` — valid input | env_loader.py:136 | test_env_loader_roundtrip_live.py:70 (parametrized) | REAL | |
| 99 | `_parse_env_text` — export prefix | env_loader.py:153 | test_env_loader_roundtrip_live.py:186 (ALSO_EXPORTED) | REAL | |
| 100 | `_parse_env_text` — comment lines | env_loader.py:151 | test_env_loader_roundtrip_live.py:186 | REAL | |
| 101 | `_quote_env_value` — empty | env_loader.py:181 | test_env_loader_roundtrip_live.py:231 | REAL | |
| 102 | `_quote_env_value` — safe chars unquoted | env_loader.py:182 | test_env_loader_roundtrip_live.py:216 | REAL | |
| 103 | `_quote_env_value` — needs quoting | env_loader.py:185 | test_env_loader_roundtrip_live.py:222 | REAL | |
| 104 | `_detect_eol` | env_loader.py:191 | test_env_loader_roundtrip_live.py:128–145 (CRLF preservation) | REAL (implicit) | |
| 105 | `CredentialLoader._load_env_file` — success | env_loader.py:342 | test_credential_loading.py:133 | REAL (implicit) | |
| 106 | `CredentialLoader._load_env_file` — file missing | env_loader.py:348 | none explicit | NO COVERAGE | Silently returns, no vars loaded |
| 107 | `CredentialLoader._load_env_file` — read error | env_loader.py:357 | none | NO COVERAGE | OSError logged, returns silently |
| 108 | `CredentialLoader.reload` | env_loader.py:377 | test_credential_loading.py:480 | REAL | |
| 109 | `CredentialLoader.get_credentials` — key present | env_loader.py:387 | test_credential_loading.py:282; test_realcov_15_store_api.py:211 | REAL | |
| 110 | `CredentialLoader.get_credentials` — alias lookup | env_loader.py:406 | none | NO COVERAGE | GEMINI_API_KEY alias for Google |
| 111 | `CredentialLoader.get_credentials` — key absent | env_loader.py:414 | test_credential_loading.py:125 | REAL | |
| 112 | `CredentialLoader.get_credentials` — unknown provider | env_loader.py:396 | none explicit | NO COVERAGE | Returns None |
| 113 | `CredentialLoader.validate_credentials` — valid | env_loader.py:464 | test_credential_loading.py:213; test_credential_loading.py:356 | REAL | |
| 114 | `CredentialLoader.validate_credentials` — invalid format | env_loader.py:496 | test_credential_loading.py:202 | REAL | |
| 115 | `CredentialLoader.validate_credentials` — missing key | env_loader.py:487 | test_credential_loading.py:244 | REAL | |
| 116 | `CredentialLoader.list_configured_providers` | env_loader.py:512 | test_credential_loading.py:294 | REAL | |
| 117 | `CredentialLoader.list_missing_providers` | env_loader.py:530 | test_credential_loading.py:306 | REAL | |
| 118 | `CredentialLoader.set_env_var` | env_loader.py:548 | test_credential_loading.py:459 | REAL | |
| 119 | `CredentialLoader.get_env_var` | env_loader.py:558 | test_credential_loading.py:414 | REAL | |
| 120 | `CredentialLoader.save_to_env_file` — create new | env_loader.py:573 | test_env_loader_roundtrip_live.py:150 | REAL | |
| 121 | `CredentialLoader.save_to_env_file` — update existing | env_loader.py:573 | test_env_loader_roundtrip_live.py:104 | REAL | |
| 122 | `CredentialLoader.save_to_env_file` — preserve structure | env_loader.py:573 | test_env_loader_roundtrip_live.py:104 | REAL | |
| 123 | `CredentialLoader.save_to_env_file` — read error | env_loader.py:602 | none | NO COVERAGE | OSError re-raised |
| 124 | `CredentialLoader.save_to_env_file` — write error | env_loader.py:642 | none | NO COVERAGE | OSError re-raised |
| 125 | `get_api_key_env_var_mapping` | env_loader.py:655 | none | NO COVERAGE | |
| 126 | `create_env_template` | env_loader.py:667 | none | NO COVERAGE | |
| 127 | `get_credential_loader` — singleton (lru_cache) | env_loader.py:710 | none explicit | NO COVERAGE | Multiple calls return same instance |

---

## 2. Worst Offenders — Fake Gates

### 2a. `test_list_providers_no_deadlock` — FAKE GATE on content
**File:** `tests/test_credentials/test_credential_store_live.py:166`

```python
result = asyncio.run(_run())
assert isinstance(result, list)
```

The test's stated purpose is deadlock prevention, and for that it is genuine. But the only assertion on the return value of `list_providers` is `isinstance(result, list)`. If `list_providers` were rewritten to always return an empty list, or to return a list of wrong types, or to silently drop all entries, this test would still pass. It is a smoke test masquerading as a gate on list content. The `list_providers` method computes `StoredCredential` metadata objects with `provider`, `key_name`, `created_at`, `updated_at`, and `source` fields — none of which are asserted.

**Falsifiability failure:** Deleting the metadata-assembly loop in `list_providers` (returning `[]` always) would not turn this test red.

### 2b. `test_reload_maintains_configured_providers` — ENVIRONMENT-DEPENDENT / WEAK
**File:** `tests/test_providers/test_credential_loading.py:479`

```python
before = set(credential_loader.list_configured_providers())
credential_loader.reload()
after = set(credential_loader.list_configured_providers())
assert before == after, ...
```

The fixture `credential_loader` reads from the live `.env` at test time. This test asserts reload idempotence but only when run in an environment where the `.env` file does not change between the two calls. If the `.env` file is empty, `before == after == set()` and the test passes vacuously. The test never verifies that `reload` actually re-reads the file (for example, adding a key to the file between calls and checking the loader picks it up). The reload path's actual effect is not gated.

### 2c. `test_validate_credentials_returns_tuple` — AMBIENT-ENVIRONMENT-DEPENDENT
**File:** `tests/test_providers/test_credential_loading.py:170`

For providers actually present in the ambient `.env`, the loop hits the `result[0] is True` branch. For absent providers it hits `result[0] is False`. The test correctly asserts semantic contracts within each branch. However, the actual validation logic for specific prefixes (`sk-ant-`, `sk-`, etc.) is not exercised here — those come from the explicit controlled-key tests. This test is a contract-structure gate, not a format-validation gate. As a contract gate it is acceptable; it is documented as such.

### 2d. `TestProviderListing.test_list_configured_providers_returns_list` — TYPE-ONLY CHECK
**File:** `tests/test_providers/test_credential_loading.py:294`

```python
configured = credential_loader.list_configured_providers()
assert isinstance(configured, list)
for provider in configured:
    assert isinstance(provider, ProviderName), ...
```

Only checks return types. Does not assert the specific providers returned match what was configured, or that the list is derived from the same logic as `validate_credentials`. A reimplementation that always returned `[]` (or `[ProviderName.ANTHROPIC]`) would pass.

---

## 3. Critical Gap List

The following behaviors have zero test coverage. They are ordered by risk.

### GAP-01 — `OAuthToken.is_expired` and `OAuthToken.needs_refresh` (CRITICAL)
**Source:** oauth.py:176, 188
**Risk:** These are the sole gatekeepers that decide whether the production `get_token` call triggers a refresh or returns an expired token to callers. The 5-minute `is_expired` buffer and the 10-minute `needs_refresh` buffer are the key timing boundaries. No test constructs an `OAuthToken` with a controlled `expires_at` and asserts the property value at boundary conditions.

**Needed:** Three parametrized unit tests with a controlled `datetime.now(UTC)` oracle:
1. Token with `expires_at` = now minus 10 seconds → `is_expired=True`, `needs_refresh=True`
2. Token with `expires_at` = now plus 3 minutes → `is_expired=True` (within 5-min buffer), `needs_refresh=True`
3. Token with `expires_at` = now plus 15 minutes → `is_expired=False`, `needs_refresh=False`
4. Token with `expires_at = None` → `is_expired=False`, `needs_refresh=False`

### GAP-02 — `OAuthToken.to_dict` / `OAuthToken.from_dict` round-trip (CRITICAL)
**Source:** oauth.py:199, 215
**Risk:** `_store_token` serializes the token via `to_dict` and stores it as JSON. `_load_token_from_store` deserializes via `from_dict`. Corruption at either step (e.g., `scopes` tuple serialized as list then misread, `expires_at` isoformat truncation, `id_token=None` dropped) would produce a silently broken token that appears valid. No test asserts the round-trip identity: `OAuthToken.from_dict(token.to_dict()) == token`.

**Needed:** A parametrized unit test using an independent oracle (manually constructed expected dict) and also the round-trip identity check. Must cover: `refresh_token=None`, `expires_at=None`, `scopes=()`, `id_token` present.

### GAP-03 — `OAuthToken.from_dict` with malformed input (CRITICAL)
**Source:** oauth.py:215
**Risk:** Malformed stored token (missing `access_token`, wrong type for `scopes`, bad ISO string for `expires_at`) silently falls back in `from_dict`. The fallback behavior (empty string access_token, empty scopes tuple) is not tested and could silently return an unusable token.

### GAP-04 — `OAuthManager.get_token` — complete absence (CRITICAL)
**Source:** oauth.py:1024
**Risk:** `get_token` is the primary public API for callers getting a valid token. Its logic includes: return `None` when no token exists; call `refresh_token` when `needs_refresh` is True; return `None` when `OAuthTokenRefreshError`; return stale non-expired token when `OAuthTokenError` but not expired; return `None` when token `is_expired` after failed refresh; suppress refresh when `auto_refresh=False`. None of these branches are tested.

**Needed:** Integration tests seeding the `_token_cache` with controlled tokens (with fixed `expires_at`) and exercising each decision branch. An `OAuthToken` with `expires_at` in the recent past plus a mock HTTP server to trigger refresh success/failure covers most branches.

### GAP-05 — `OAuthManager.handle_callback` error paths (HIGH)
**Source:** oauth.py:786, 791, 796
**Risk:** Unknown state, expired state (OAuthState with `created_at` more than 10 min ago), and PKCE verifier missing are security-critical error paths. A regression removing these checks would be undetected. Currently the only `handle_callback` test is the happy path via the full callback flow.

**Needed:** Three unit tests driving `manager.handle_callback(code, unknown_state)`, `handle_callback` with an expired `OAuthState` seeded into `_pending_states`, and a PKCE config with `use_pkce=True` but `code_verifier=None`.

### GAP-06 — `OAuthState.is_expired` (HIGH)
**Source:** oauth.py:280
**Risk:** The 10-minute OAuth state window is a security boundary — a stale state should not be accepted. The property is used in `handle_callback` but is never directly tested.

### GAP-07 — `OAuthManager.revoke_token` (HIGH)
**Source:** oauth.py:1190
**Risk:** Token revocation has a complex return-value contract: `True` only when both remote revocation (if any) and keyring deletion succeed; cache always cleared. The documented contract for the return value and the cache-always-cleared guarantee are not tested at all.

### GAP-08 — `OAuthManager.refresh_token` — 403 status (MODERATE)
**Source:** oauth.py:1178
**Risk:** The `{_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN}` set is tested for 401 but not 403. A regression that changed the set to `{_HTTP_UNAUTHORIZED}` would not be caught.

### GAP-09 — `OAuthManager.refresh_token` — no refresh token available (MODERATE)
**Source:** oauth.py:1148
**Risk:** When the cached token has `refresh_token=None`, `OAuthTokenError` should be raised immediately. Not tested.

### GAP-10 — `CredentialStore.get_or_raise` (MODERATE)
**Source:** store.py:442, 455
**Risk:** The `CredentialNotFoundError` path is not tested. If the wrong exception type were raised, or no exception at all, the test would not catch it.

### GAP-11 — `CredentialStore._deserialize_credentials` malformed JSON (MODERATE)
**Source:** store.py:238
**Risk:** A corrupted keyring entry (truncated JSON, wrong type in api_key) should raise `CredentialStoreError`. This error path is entirely untested.

### GAP-12 — `CredentialStore._check_keyring` failure paths (MODERATE)
**Source:** store.py:147, 161, 169
**Risk:** The three failure branches of `_check_keyring` (library not installed, fail/null backend, priority <= 0) are not directly tested. Only the success branch is implicitly covered when keyring is available.

### GAP-13 — `CredentialStore.delete` and `set` when keyring unavailable (MODERATE)
**Source:** store.py:485, 508
**Risk:** Both operations should raise `KeyringUnavailableError` when keyring is not available. No test constructs a `CredentialStore` with `keyring_available=False` and calls `set` or `delete`.

### GAP-14 — `CredentialLoader.get_credentials` alias lookup (MODERATE)
**Source:** env_loader.py:406
**Risk:** The `GEMINI_API_KEY` alias for Google is never tested. The alias-lookup loop is skipped by every test because primary keys are always set.

### GAP-15 — Secret redaction in log entries (LOW but architectural)
**Source:** Throughout oauth.py (e.g., line 859: logs `has_refresh_token`, not the token value)
**Risk:** There are no tests asserting that log records emitted by the credentials module do not contain token values, API key material, or refresh tokens. If a future log call accidentally emits `access_token=token.access_token` instead of a safe flag, no test would catch it.

---

## 4. Falsifiability Verification for Critical Operations

### OAuthToken.is_expired (oauth.py:176)
No test exists. Mutation: change `timedelta(minutes=5)` to `timedelta(minutes=0)` — no test turns red.
The correct oracle for `is_expired` is: construct a token with `expires_at = datetime.now(UTC) - timedelta(seconds=10)` and assert `is_expired is True`. The oracle is `datetime.now(UTC)`, independent of the implementation.

### OAuthToken.to_dict / from_dict (oauth.py:199, 215)
No test exists. Mutation: add `"extra_field": None` to `to_dict` output, or drop `refresh_token` from the dict — no test turns red.
The correct oracle is a manually constructed expected dict, or the identity assertion `OAuthToken.from_dict(t.to_dict()).access_token == t.access_token` etc., checked field-by-field against the original instance.

### CredentialStore round-trip (store.py:420-534)
`test_credential_roundtrip_live` (test_credential_store_live.py:242): asserts `fetched.api_key == marker` where `marker` is a unique UUID string. This IS falsifiable — if `_serialize_credentials` dropped `api_key`, the assertion would fail. The concern is the conditional skip; when keyring is unavailable in the Docker sandbox, this test never runs and the guarantee is absent.

### OAuthCallbackHandler CSRF check (oauth.py:409)
`test_state_mismatch_is_rejected`: sends a callback with `state="different-state"` when server expects `"expected-state-value"`, asserts HTTP 400 and `OAuthCallbackError`. This is falsifiable: removing the `secrets.compare_digest` check would allow the wrong state through and the `wait_for_callback` call would succeed instead of raising, turning the test red.

### refresh_token 401 → OAuthTokenRefreshError (oauth.py:1178)
`test_refresh_token_rejected_raises_refresh_error`: mock server at `/token/authfail` returns 401. `pytest.raises(OAuthTokenRefreshError)` would fail if the code raised `OAuthTokenError` instead. This is falsifiable.

---

## 5. Edge-Case Coverage Assessment

| Edge Case | Source Location | Covered? | Test |
|-----------|----------------|----------|------|
| Token just-expired (within 5-min buffer) | oauth.py:185 | NO | None |
| Token valid (expires_at > now + 5min) | oauth.py:185 | NO | None |
| Token expires_at = None (no expiry) | oauth.py:177 | NO | None |
| Token needs_refresh boundary (10-min) | oauth.py:197 | NO | None |
| Malformed stored token (bad JSON) | oauth.py:1020 | NO | None |
| Concurrent get_token calls | oauth.py:1024 | NO | None |
| Secret/token value NOT in log output | Throughout oauth.py | NO | None |
| Missing env var, loader returns None | env_loader.py:414 | YES | test_credential_loading.py:244 |
| Corrupt .env file (parse error) | env_loader.py:362 | NO | None |
| Refresh token rejected (401) | oauth.py:1178 | YES | test_oauth_manager_live.py:419 |
| Refresh token rejected (403) | oauth.py:1178 | NO | None |
| No refresh token in cached token | oauth.py:1148 | NO | None |
| State mismatch CSRF in callback | oauth.py:409 | YES | test_oauth_manager_live.py:361 |
| Callback timeout | oauth.py:543 | NO | None |
| User denied authorization | oauth.py:556 | NO | None |
| Keyring unavailable: set raises | store.py:485 | NO | None |
| Keyring unavailable: delete raises | store.py:508 | NO | None |
| Keyring fail/null backend detected | store.py:161 | NO | None |

**Edge-case score:** 4/18 = 22%

---

## 6. Section Scores

### Gate Coverage Score
- Total behavior-bearing operations inventoried: 127
- Operations with ≥1 real, falsifiable gate: 54
- **Gate coverage: 54/127 = 43%**

### Edge-Case Coverage Score
- Edge cases inventoried: 18 (from the specification — expiry boundary, malformed token, concurrent access, secret redaction, missing/empty env, corrupt store, refresh failure, CSRF, timeout, denied)
- Edge cases with real gate: 4
- **Edge-case score: 4/18 = 22%**

---

## 7. Remediation Recommendations

### R-01 — OAuthToken property unit tests (CRITICAL, unit, independent)
Add `tests/test_credentials/test_oauth_token_properties.py`. Construct tokens with explicit `expires_at` values relative to `datetime.now(UTC)` without mocking. Assert `is_expired` and `needs_refresh` at four boundary points: (a) expired more than 5 min ago, (b) expired within 5-min buffer, (c) within 10-min buffer but not the 5-min buffer, (d) fully valid, (e) `expires_at=None`. Oracle: the expected boolean is derivable from the `timedelta` arithmetic independently.

### R-02 — OAuthToken serialization round-trip (CRITICAL, unit)
Add `test_oauth_token_roundtrip` in the same file. Construct a fully populated `OAuthToken`, call `to_dict()`, assert each key against an independently written expected dict (do not mirror the implementation), then call `OAuthToken.from_dict(d)` and assert field equality. Also test malformed input: `from_dict({})`, `from_dict({"access_token": 42})`, `from_dict({"expires_at": "not-a-datetime"})`.

### R-03 — OAuthManager.get_token decision-tree tests (CRITICAL, integration)
Add `test_get_token_decision_branches` in `test_oauth_manager_live.py`. Seed `_token_cache` directly with controlled `OAuthToken` instances (fixed `expires_at`). Test: no token → returns `None`; valid token → returns same token without refresh; token in needs_refresh window → triggers `refresh_token` (drive with mock server); `OAuthTokenRefreshError` on refresh → returns `None`; `OAuthTokenError` on refresh, token not yet expired → returns stale token; token `is_expired` → returns `None`.

### R-04 — `handle_callback` error paths (HIGH, unit)
Add three `pytest.raises` unit tests. Seed `_pending_states` with a known state key. (a) Call with unknown state → `OAuthCallbackError`. (b) Seed with an `OAuthState` whose `created_at` is `datetime.now(UTC) - timedelta(minutes=11)` → `OAuthCallbackError` (expired). (c) Seed a state for a PKCE config but with `code_verifier=None` → `OAuthCallbackError`.

### R-05 — `OAuthManager.revoke_token` (HIGH, integration)
Test using the mock OAuth provider fixture. Drive revoke with: (a) no token in cache/store → returns `False`; (b) token in cache, no `revoke_url` → cache cleared, keyring delete attempted; (c) token in cache, with `revoke_url`, provider returns 200 → `True`; (d) provider revoke endpoint returns 500 → `revoke_succeeded=False`; confirm cache is always cleared.

### R-06 — `CredentialStore.get_or_raise` (MODERATE, unit)
Add two tests: (a) seed a credential, `get_or_raise` returns it; (b) with no credential, `get_or_raise` raises exactly `CredentialNotFoundError` and the message contains the provider name.

### R-07 — Malformed JSON in credential store (MODERATE, unit)
Construct a `CredentialStore` with a real `keyring_available=True` backend and manually inject a non-JSON blob via `keyring.set_password(SERVICE_NAME, key, "not-json")`. Call `store.get(provider)` and assert it returns `None` (handled via `_get_from_keyring` exception path) rather than raising.

### R-08 — `refresh_token` 403 status (MODERATE)
Add a mock server endpoint that returns 403. Assert `OAuthTokenRefreshError` is raised (same as 401). This distinguishes from a regression that only handles 401.

### R-09 — `CredentialLoader.get_credentials` alias (MODERATE, unit)
Write `.env` containing only `GEMINI_API_KEY=AIzaXXXX` (no `GOOGLE_API_KEY`). Assert `get_credentials(ProviderName.GOOGLE).api_key == "AIzaXXXX"`.

### R-10 — `CredentialStore.set`/`delete` when keyring unavailable (MODERATE)
Construct a `CredentialStore` whose `keyring_available` returns `False` (create one before keyring is available, or monkeypatch `_check_keyring`). Assert `set(...)` raises `KeyringUnavailableError` and `delete(...)` raises `KeyringUnavailableError`.

### R-11 — `list_providers` content validation (LOW, unit)
Strengthen `test_list_providers_no_deadlock`: after storing a known credential, call `list_providers`, find the entry for that provider, assert `entry.provider == ProviderName.OLLAMA`, `entry.source == CredentialSource.KEYRING`, `entry.key_name` is non-empty. Fallback: at minimum assert that for each returned entry `isinstance(entry.provider, ProviderName)` and `isinstance(entry.source, CredentialSource)`.

### R-12 — OAuthCallbackHandler error and missing-params branches (LOW, unit)
Drive `OAuthCallbackHandler` via real HTTP: (a) send `?error=access_denied` → response status 400, `callback_error` set; (b) send request with no params → 400 response; assert the handler sets the expected server attributes.
