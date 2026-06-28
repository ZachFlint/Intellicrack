# Group 09 Verification Report

**Assigned scope:** `audit/test-coverage-audit/section-11-credentials-oauth.md`, ops #1–#64
**Reviewer:** GROUP 09 (test-reviewer agent)
**Date:** 2026-06-27
**Remediation file examined:** `tests/test_credentials/test_oauth_section11_gates.py`
**Supporting files examined:** `tests/test_providers/test_credential_loading.py`, `tests/test_credentials/test_oauth_manager_live.py`, `tests/test_credentials/test_credential_store_live.py`

---

## Finding Enumeration

Non-REAL rows enumerated from the audit table (ops #1–#64), including all rows with any qualifier on their verdict:

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation) |
|---|------------------------|-----------------|-----|------------------------------------------|
| 1 | `_oauth_provider_to_name` happy path (oauth.py:109) | WEAK | NOT_RESOLVED | No direct test with assertion on return value. All callers (revoke_token, _store_token) exercise it but never assert the specific ProviderName returned. |
| 2 | `_oauth_provider_to_name` KeyError path (oauth.py:121) | NO COVERAGE | NOT_RESOLVED | No test. Note: all three OAuthProvider enum values are mapped in _OAUTH_TO_PROVIDER_NAME, making this currently dead code. Still no direct gate. |
| 3 | `OAuthToken.is_expired_at` 5-min buffer (oauth.py:176) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:179–244 · oracle: controlled `datetime(2030,1,1,12,0,0,UTC)` independent of impl · mutation: change `>= (expires_at - 5min)` to `> (expires_at - 5min)` would fail exact-boundary test at line 213 |
| 4 | `OAuthToken.needs_refresh_at` 10-min buffer (oauth.py:188) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:268–349 · oracle: controlled frozen datetime · mutation: change 10-minute buffer to 6 minutes fails test at line 284 |
| 5 | `OAuthToken.to_dict` (oauth.py:199) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:357–443 · oracle: independently written expected dict with exact field names and values · mutation: renaming `access_token` key fails line 374 |
| 6 | `OAuthToken.from_dict` (oauth.py:215) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:451–513 · oracle: original OAuthToken field values vs round-tripped values; ValueError from fromisoformat for bad date · mutation: dropping `id_token` from to_dict fails round-trip at line 473 |
| 7 | `OAuthState.is_expired_at` 10-min timeout (oauth.py:280) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:521–601 · oracle: controlled frozen datetime with arithmetic independently verified · mutation: changing 10-minute timeout to 12 minutes fails test at line 521 |
| 12 | `OAuthCallbackHandler.do_GET` error in params (oauth.py:402) | NO COVERAGE | NOT_RESOLVED | No test in gate file or live file. Error-param path (HTTP 400 + callback_error) entirely untested. |
| 13 | `OAuthCallbackHandler.do_GET` missing code/state (oauth.py:419) | NO COVERAGE | NOT_RESOLVED | No test. Neither-code-nor-error branch untested. |
| 14 | `OAuthCallbackServer.start` bind success (oauth.py:498) | REAL (implicit) | RESOLVED | test_oauth_manager_live.py:256 exercises full callback flow requiring start() to bind; mutation of start() to raise OSError would propagate through and fail the flow test's assertions on HTTP interactions. Integration test asserting meaningful flow values is sufficient. |
| 15 | `OAuthCallbackServer.start` OSError on bind (oauth.py:510) | NO COVERAGE | NOT_RESOLVED | No test for OAuthCallbackError when bind fails (e.g., port already in use). |
| 17 | `OAuthCallbackServer.wait_for_callback` timeout (oauth.py:543) | NO COVERAGE | NOT_RESOLVED | No test asserting OAuthCallbackError raised on timeout. |
| 18 | `OAuthCallbackServer.wait_for_callback` denied (oauth.py:556) | NO COVERAGE | NOT_RESOLVED | No test asserting OAuthAuthorizationError for "denied"/"access_denied" callback result. |
| 20 | `OAuthCallbackServer.wait_for_callback` missing code/state (oauth.py:566) | NO COVERAGE | NOT_RESOLVED | No test asserting OAuthCallbackError for null code or null state in callback result. |
| 21 | `OAuthCallbackServer.stop` (oauth.py:573) | REAL (implicit) | RESOLVED | test_oauth_manager_live.py finally blocks call stop(); mutation of stop() to raise would propagate and fail the live flow tests. Implicit integration coverage is genuine. |
| 24 | `OAuthManager.build_authorization_url` PKCE disabled (oauth.py:701) | NO COVERAGE | NOT_RESOLVED | No test asserting code_challenge and code_challenge_method params are absent when use_pkce=False. |
| 27 | `OAuthManager.handle_callback` unknown state (oauth.py:786) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:609–618 · pytest.raises(OAuthCallbackError, match="Unknown state") · oracle: literal message `f"Unknown state parameter: {state}"` in production code · mutation: removing the `oauth_state is None` guard would not raise and test would fail |
| 28 | `OAuthManager.handle_callback` expired state (oauth.py:791) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:621–650 · pytest.raises(OAuthCallbackError, match=r"[Ee]xpired") · oracle: production message "Authorization flow expired" · mutation: removing the `oauth_state.is_expired` guard passes the wrong state through and test fails |
| 29 | `OAuthManager.handle_callback` PKCE verifier missing (oauth.py:796) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:653–682 · pytest.raises(OAuthCallbackError, match=r"[Pp]KCE\|pkce\|verifier") · oracle: production message "PKCE flow missing code_verifier" · mutation: removing the `not oauth_state.code_verifier` guard skips the raise |
| 31 | `OAuthManager._exchange_code_for_token` HTTP error (oauth.py:901) | NO COVERAGE | NOT_RESOLVED | No test asserting OAuthTokenError wraps HTTPStatusError from code exchange. |
| 32 | `OAuthManager._exchange_code_for_token` network error (oauth.py:906) | NO COVERAGE | NOT_RESOLVED | No test asserting OAuthTokenError wraps RequestError/OSError from code exchange. |
| 33 | `OAuthManager._store_token` no credential store (oauth.py:920) | REAL (implicit path taken) | RESOLVED | All tests in test_oauth_section11_gates.py use credential_store=None; mutation of the None-guard to call methods on None would raise AttributeError, turning all tests using this path red. |
| 34 | `OAuthManager._store_token` keyring unavailable (oauth.py:924) | NO COVERAGE | NOT_RESOLVED | No test asserting only a warning is logged (no error raised) when keyring is unavailable in _store_token. |
| 35 | `OAuthManager._store_token` keyring success (oauth.py:935) | NO COVERAGE | NOT_RESOLVED | No test asserting token serialized as JSON and stored at correct keyring key. |
| 36 | `OAuthManager._load_token_from_store` (oauth.py:953) | NO COVERAGE | NOT_RESOLVED | No test for any path: token loaded, None when absent, or JSON decode error. |
| 37 | `OAuthManager._load_token` cache hit (oauth.py:1003) | WEAK | RESOLVED | test_oauth_section11_gates.py:702–722 · asserts `result.access_token == "valid_acc"` (exact value against known constant) · mutation: making _load_token return None for a cached token fails the assertion |
| 38 | `OAuthManager._load_token` cache miss, keyring load (oauth.py:1006) | NO COVERAGE | NOT_RESOLVED | No test for the path where cache misses and token is loaded from the credential store. |
| 39 | `OAuthManager._load_token` JSON decode error (oauth.py:1020) | NO COVERAGE | NOT_RESOLVED | No test asserting warning is logged and None returned when stored token has malformed JSON. |
| 40 | `OAuthManager.get_token` no token (oauth.py:1047) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:690–699 · asserts `result is None` · oracle: empty cache + credential_store=None means _load_token returns None · mutation: returning placeholder token instead of None fails assertion |
| 41 | `OAuthManager.get_token` valid, no refresh needed (oauth.py:1062) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:702–722 · asserts `result.access_token == "valid_acc"` (exact value) · oracle: known-constant access_token seeded into cache · mutation: always triggering a refresh or returning None would fail |
| 42 | `OAuthManager.get_token` needs_refresh, auto_refresh=True (oauth.py:1052) | NO COVERAGE | NOT_RESOLVED | No test exercises the auto_refresh=True branch that calls refresh_token. All new tests use auto_refresh=False. |
| 43 | `OAuthManager.get_token` OAuthTokenRefreshError path (oauth.py:1056) | NO COVERAGE | NOT_RESOLVED | No test for the except OAuthTokenRefreshError block → return None path inside get_token. |
| 44 | `OAuthManager.get_token` OAuthTokenError, not expired (oauth.py:1059) | NO COVERAGE | NOT_RESOLVED | No test for the except OAuthTokenError block when token.is_expired is False → return stale token. |
| 45 | `OAuthManager.get_token` expired after failed refresh (oauth.py:1062, line 1090) | NO COVERAGE | NOT_RESOLVED | `test_get_token_returns_none_when_token_is_expired_and_no_auto_refresh` tests line 1092 via auto_refresh=False. Line 1090 (inside except OAuthTokenError) is never reached; deleting it would not turn any test red. |
| 46 | `OAuthManager._post_token_refresh` happy path (oauth.py:816) | REAL (error paths); happy path never asserted | NOT_RESOLVED | No test in gate file or live file asserts the fields of the refreshed token (access_token, token_type, expires_at derived from expires_in) returned by a successful POST. The error paths are gated; the success-path token-field assertions are absent. |
| 48 | `OAuthManager.refresh_token` 403 response (oauth.py:1178) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:824–852 · mock_403_server fixture returns HTTP 403 · pytest.raises(OAuthTokenRefreshError, match="403") · oracle: production message f"Refresh token rejected by provider (403)" · mutation: removing 403 from the forbidden-status set raises OAuthTokenError instead, fails |
| 49 | `OAuthManager.refresh_token` other HTTP error (oauth.py:1181) | NO COVERAGE | NOT_RESOLVED | No test for non-auth HTTP error (e.g., 500) asserting OAuthTokenError (not OAuthTokenRefreshError) is raised. |
| 51 | `OAuthManager.refresh_token` no refresh token (oauth.py:1148) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:860–890 · token with refresh_token=None seeded · pytest.raises(OAuthTokenError, match=r"[Nn]o refresh token") · oracle: production message "No refresh token available" · mutation: silently returning without raising would not raise, test fails |
| 52 | `OAuthManager.revoke_token` no token (oauth.py:1209) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:777–787 · empty cache + credential_store=None · asserts `result is False` · oracle: production `if token is None: return False` · mutation: returning True would fail |
| 53 | `OAuthManager.revoke_token` no revoke_url (oauth.py:1213) | NO COVERAGE | NOT_RESOLVED | `test_revoke_token_always_clears_cache` covers cache clearing with ANTHROPIC (no revoke_url) but uses credential_store=None, so the keyring-delete portion of the "no revoke_url" path is never exercised or asserted. |
| 54 | `OAuthManager.revoke_token` with revoke_url, success (oauth.py:1218) | NO COVERAGE | NOT_RESOLVED | No test for the path where revoke_url is configured and the remote call succeeds → returns True. |
| 55 | `OAuthManager.revoke_token` revoke HTTP error (oauth.py:1230) | NO COVERAGE | NOT_RESOLVED | No test asserting revoke_succeeded=False and combined_success=False when HTTP call fails. |
| 56 | `OAuthManager.revoke_token` cache always cleared (oauth.py:1240) | NO COVERAGE | RESOLVED | test_oauth_section11_gates.py:790–816 · asserts `OAuthProvider.ANTHROPIC not in cache_after` (exact membership check) · oracle: cache inspected directly via cast · mutation: removing `self._token_cache.pop(provider, None)` leaves token in cache, assertion fails |
| 57 | `OAuthManager.to_provider_credentials` (oauth.py:1268) | NO COVERAGE | NOT_RESOLVED | No test asserting ProviderCredentials returned with access_token set from a cached OAuthToken. |
| 58 | `OAuthManager.run_authorization_flow` (oauth.py:1290) | NO COVERAGE | NOT_RESOLVED | No test for this method in gate file or live file. |
| 60 | `authorize_google` (oauth.py:1368) | NO COVERAGE | NOT_RESOLVED | No test. |
| 61 | `CredentialStore._check_keyring` library not installed (store.py:147) | NO COVERAGE | NOT_RESOLVED | No test asserting `_check_keyring` returns False and logs warning when `_keyring_module is None`. |
| 62 | `CredentialStore._check_keyring` fail/null backend (store.py:161) | NO COVERAGE | NOT_RESOLVED | No test asserting returns False for FailKeyring/NullKeyring/fail.Keyring backend. |
| 63 | `CredentialStore._check_keyring` priority <= 0 (store.py:169) | NO COVERAGE | NOT_RESOLVED | No test asserting returns False for a backend whose priority attribute is zero or negative. |
| 64 | `CredentialStore._check_keyring` success (store.py:179) | REAL (if keyring available on host) | RESOLVED | test_credential_store_live.py:163 provides real coverage when keyring is present; the conditional skip is an accepted environmental-capability skip (keyring availability is a platform/hardware feature). |

---

## STILL OPEN

The following 31 findings have no real gate:

### #1 — `_oauth_provider_to_name` happy path (oauth.py:109)
**Why not real:** Only exercised as a side-effect of callers; no test directly calls the function and asserts the returned `ProviderName` value.
**Missing assertion:** `assert _oauth_provider_to_name(OAuthProvider.GOOGLE) == ProviderName.GOOGLE` (and similarly for ANTHROPIC and HUGGINGFACE).

### #2 — `_oauth_provider_to_name` KeyError path (oauth.py:121)
**Why not real:** All three OAuthProvider enum values are currently mapped, making the KeyError branch dead code. No test documents this invariant.
**Missing assertion:** Either a test that verifies all enum members are mapped (so a new unmapped member fails the build), or a test using a mock un-mapped value asserting `pytest.raises(KeyError, match="No provider name mapping")`.

### #12 — `OAuthCallbackHandler.do_GET` error in params (oauth.py:402)
**Why not real:** No test sends a request with `?error=access_denied` and asserts HTTP 400 response plus `callback_error` attribute set.
**Missing assertion:** `assert response.status == 400` and `assert server.callback_error == "access_denied"` after real HTTP GET with `?error=access_denied`.

### #13 — `OAuthCallbackHandler.do_GET` missing code/state (oauth.py:419)
**Why not real:** No test sends a request with no query parameters and asserts HTTP 400 response.
**Missing assertion:** `assert response.status == 400` after GET with no params.

### #15 — `OAuthCallbackServer.start` OSError on bind (oauth.py:510)
**Why not real:** No test binds to an already-occupied port and asserts `OAuthCallbackError` is raised.
**Missing assertion:** `pytest.raises(OAuthCallbackError, match="bind|port")` when start() is called on a port that is already bound.

### #17 — `OAuthCallbackServer.wait_for_callback` timeout (oauth.py:543)
**Why not real:** No test exercises the timeout path asserting `OAuthCallbackError`.
**Missing assertion:** `pytest.raises(OAuthCallbackError, match="[Tt]imeout")` with a short timeout and no callback arriving.

### #18 — `OAuthCallbackServer.wait_for_callback` denied (oauth.py:556)
**Why not real:** No test drives the "denied" / "access_denied" result and asserts `OAuthAuthorizationError`.
**Missing assertion:** `pytest.raises(OAuthAuthorizationError)` when callback_result is "denied".

### #20 — `OAuthCallbackServer.wait_for_callback` missing code/state (oauth.py:566)
**Why not real:** No test for the path where callback_result provides no code or state and `OAuthCallbackError` is raised.
**Missing assertion:** `pytest.raises(OAuthCallbackError, match="[Cc]ode|[Ss]tate")`.

### #24 — `OAuthManager.build_authorization_url` PKCE disabled (oauth.py:701)
**Why not real:** No test calls `build_authorization_url` with `use_pkce=False` and asserts `code_challenge` and `code_challenge_method` are absent from the returned URL.
**Missing assertion:** `assert "code_challenge" not in url` when `use_pkce=False`.

### #31 — `OAuthManager._exchange_code_for_token` HTTP error (oauth.py:901)
**Why not real:** No test for the non-2xx HTTP response path asserting `OAuthTokenError` wraps `HTTPStatusError`.
**Missing assertion:** `pytest.raises(OAuthTokenError, match="HTTP")` when token endpoint returns non-2xx.

### #32 — `OAuthManager._exchange_code_for_token` network error (oauth.py:906)
**Why not real:** No test for transport failure asserting `OAuthTokenError` wraps `RequestError` or `OSError`.
**Missing assertion:** `pytest.raises(OAuthTokenError)` when the token endpoint is unreachable.

### #34 — `OAuthManager._store_token` keyring unavailable (oauth.py:924)
**Why not real:** No test constructs an `OAuthManager` with a credential_store whose keyring is unavailable and asserts only a warning is emitted (no exception).
**Missing assertion:** After seeding, `_store_token` returns normally (no exception); log warning is emitted.

### #35 — `OAuthManager._store_token` keyring success (oauth.py:935)
**Why not real:** No test asserts the exact JSON serialized into the keyring entry after `_store_token` succeeds.
**Missing assertion:** Read back keyring entry and assert `json.loads(stored)["access_token"] == original.access_token`.

### #36 — `OAuthManager._load_token_from_store` (oauth.py:953)
**Why not real:** No test exercises any path of `_load_token_from_store`: not the success path, not the None path, not the JSONDecodeError path.
**Missing assertion:** After storing a token via keyring, `await _load_token_from_store(provider)` returns a token whose `access_token` matches the stored value.

### #38 — `OAuthManager._load_token` cache miss, keyring load (oauth.py:1006)
**Why not real:** All tests pre-seed the in-memory cache. No test starts with an empty cache and a credential_store that has a stored token, asserting the store is consulted.
**Missing assertion:** `result.access_token == stored_token.access_token` after `_load_token` with empty cache but populated credential_store.

### #39 — `OAuthManager._load_token` JSON decode error (oauth.py:1020)
**Why not real:** No test injects malformed JSON into the credential_store for an OAuthToken and asserts `_load_token` returns None and logs a warning.
**Missing assertion:** `result is None` when credential_store contains non-JSON token data.

### #42 — `OAuthManager.get_token` needs_refresh, auto_refresh=True (oauth.py:1052)
**Why not real:** No test seeds a token in the needs_refresh window (expires in 7 minutes) with `auto_refresh=True` and asserts `refresh_token` is called, returning the refreshed token.
**Missing assertion:** Result token's `access_token` differs from the stale token's value (equals the refreshed token's value from mock server).

### #43 — `OAuthManager.get_token` OAuthTokenRefreshError path (oauth.py:1056)
**Why not real:** No test exercises the `except OAuthTokenRefreshError: return None` branch inside `get_token` (distinct from the `refresh_token` method's own test).
**Missing assertion:** `result is None` when `auto_refresh=True`, `needs_refresh=True`, and the token endpoint returns 401/403.

### #44 — `OAuthManager.get_token` OAuthTokenError, not expired (oauth.py:1059)
**Why not real:** No test drives the `except OAuthTokenError: return None if token.is_expired else token` branch where `is_expired` is False.
**Missing assertion:** `result.access_token == stale_token.access_token` when `auto_refresh=True`, `needs_refresh=True`, refresh raises `OAuthTokenError`, but token is not yet is_expired (e.g., expires in 7 minutes).

### #45 — `OAuthManager.get_token` expired after failed refresh (oauth.py:1062, line 1090)
**Why not real:** `test_get_token_returns_none_when_token_is_expired_and_no_auto_refresh` covers line 1092 via `auto_refresh=False`. Line 1090 (inside `except OAuthTokenError:` when `token.is_expired` is True) is never reached; deleting it would not turn any test red.
**Missing assertion:** `result is None` when `auto_refresh=True`, `needs_refresh=True`, refresh raises `OAuthTokenError`, and `token.is_expired` is True.

### #46 — `OAuthManager._post_token_refresh` happy path (oauth.py:816)
**Why not real:** No test asserts the fields of the `OAuthToken` returned by a successful POST to the token refresh endpoint — specifically that `access_token`, `token_type`, and `expires_at` (derived from `expires_in`) are correctly set.
**Missing assertion:** After a successful refresh POST returning `{"access_token":"new_acc","token_type":"Bearer","expires_in":3600}`, assert `result.access_token == "new_acc"` and `result.token_type == "Bearer"` and `result.expires_at` is approximately `datetime.now(UTC) + timedelta(seconds=3600)`.

### #49 — `OAuthManager.refresh_token` other HTTP error (oauth.py:1181)
**Why not real:** No test for a non-auth HTTP error (e.g., 500 Internal Server Error) asserting `OAuthTokenError` (not `OAuthTokenRefreshError`) is raised. The 403 test proves only that 403 is in the forbidden set; a regression removing 500 from the OAuthTokenError branch would go undetected.
**Missing assertion:** `pytest.raises(OAuthTokenError, match="500")` when token endpoint returns 500.

### #53 — `OAuthManager.revoke_token` no revoke_url (oauth.py:1213)
**Why not real:** `test_revoke_token_always_clears_cache` uses `credential_store=None`, which causes the keyring-delete block to be skipped entirely (`if self._credential_store:` is False). The "no revoke_url, deletes from keyring" aspect of this path is not exercised.
**Missing assertion:** With a real credential_store, after revoke with no revoke_url, `credential_store.delete(provider_name)` is called (or its effect verified by a subsequent failed `get_or_raise`).

### #54 — `OAuthManager.revoke_token` with revoke_url, success (oauth.py:1218)
**Why not real:** No test configures a provider with a real revoke_url, drives revocation via a mock server returning 200, and asserts `result is True`.
**Missing assertion:** `result is True` and cache cleared when mock server returns 200 to DELETE/POST on revoke_url.

### #55 — `OAuthManager.revoke_token` revoke HTTP error (oauth.py:1230)
**Why not real:** No test drives revoke where the remote endpoint returns non-2xx and asserts `revoke_succeeded=False` and `result is False` (combined_success False).
**Missing assertion:** `result is False` when mock revoke endpoint returns 500.

### #57 — `OAuthManager.to_provider_credentials` (oauth.py:1268)
**Why not real:** No test calls `to_provider_credentials` with a cached token and asserts the returned `ProviderCredentials.api_key` equals the token's `access_token`.
**Missing assertion:** `creds.api_key == token.access_token` where `creds = await manager.to_provider_credentials(provider)`.

### #58 — `OAuthManager.run_authorization_flow` (oauth.py:1290)
**Why not real:** No test. This is the primary high-level API for completing a full OAuth authorization flow.
**Missing assertion:** Run against a mock authorization + token server, assert returned token's `access_token` is what the server issued.

### #60 — `authorize_google` (oauth.py:1368)
**Why not real:** No test.
**Missing assertion:** Assert `authorize_google` calls `run_authorization_flow` with the Google config and returns the token.

### #61 — `CredentialStore._check_keyring` library not installed (store.py:147)
**Why not real:** No test constructs a CredentialStore when the keyring module is not importable (or patches `_keyring_module` to None) and asserts `_check_keyring()` returns False.
**Missing assertion:** `assert store._check_keyring() is False` when `_keyring_module is None`.

### #62 — `CredentialStore._check_keyring` fail/null backend (store.py:161)
**Why not real:** No test exercises the branch that returns False for FailKeyring/NullKeyring backends.
**Missing assertion:** `assert store._check_keyring() is False` when `keyring.get_keyring()` returns a backend named "fail.Keyring" or "null.Keyring".

### #63 — `CredentialStore._check_keyring` priority <= 0 (store.py:169)
**Why not real:** No test for the branch that returns False when the backend's priority attribute is <= 0.
**Missing assertion:** `assert store._check_keyring() is False` when a mock backend has `priority=0`.

---

## Gate Quality Notes on the New Test File

`tests/test_credentials/test_oauth_section11_gates.py` is a genuine improvement. The tests that were added pass the falsifiability test:

- **OAuthToken expiry/refresh-boundary tests** use a frozen `datetime(2030,…,UTC)` reference and assert exact boolean values at known arithmetic boundaries. The oracle is the independent arithmetic (`now >= (expires_at - 5min)`), not the production code's output.
- **`to_dict` / `from_dict` tests** assert exact key names and values against an independently written expected dict; the round-trip identity test would catch any field being dropped or renamed.
- **`handle_callback` error tests** all use `pytest.raises` with a `match=` argument that would catch the wrong exception type or message prefix. The error messages in the production code (`"Unknown state parameter"`, `"Authorization flow expired"`, `"PKCE flow missing code_verifier"`) are independently verified above.
- **`get_token` no-token and valid-token tests** assert exact values (`result is None`, `result.access_token == "valid_acc"`), not merely non-None.
- **`refresh_token` 403 test** uses a real in-process HTTP server (not a mock) that returns 403, proving the production httpx client and error-handling path are exercised.
- **`revoke_token` cache-clear test** directly inspects the internal cache dict before and after, asserting exact membership.
- **`get_or_raise` tests** assert exact exception type with match and exact api_key value.
- **`_deserialize_credentials` malformed JSON test** asserts the specific `CredentialStoreError` exception type with match.

No forbidden patterns (MagicMock, bare `is not None`, no-match `pytest.raises`, bare `isinstance`) appear in the new file.

One concern: `test_handle_callback_expired_state_raises` and `test_handle_callback_pkce_verifier_missing_raises` use `datetime.now(UTC)` (live clock) for `created_at`. This is acceptable because the 11-minute offset for the expired test always exceeds the 10-minute boundary regardless of execution timing, and the fresh (0-second) state for the PKCE test always underflows the boundary. Deterministic in practice.

The `_make_keyring_free_store` helper correctly bypasses the `cached_property keyring_available` by setting `_keyring_checked=True` and `_keyring_available=False` before `keyring_available` is first accessed (since `__init__` does not call it). This makes `get_or_raise` and `set`/`delete` behave deterministically without a real keyring backend.
