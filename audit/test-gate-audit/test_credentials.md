# Test-Gate Audit - `tests/test_credentials`

**2 confirmed non-gate defects** (high: 0, medium: 1, low: 1) | 0 flags refuted (genuine gates).

## Confirmed non-gate tests

### `tests/test_credentials/test_realcov_15_store_api.py`

- **test_get_credentials_wrapper_delegates_to_singleton** (line 191) - `tautological` / **medium** - _[verified accurate]_
  - Why it is not a gate: With ollama_clean fixture purging the keyring, both get_credentials() and get_credential_store().get() return None. The assertion None == None passes regardless of whether the wrapper actually delegates to the singleton or creates a fresh CredentialStore(). A fresh instance would also return None on a purged keyring, so the test cannot distinguish between singleton delegation and independent instantiation.
  - Fix: Seed a known credential into the singleton store before running the test, then assert that get_credentials() returns the exact same seeded value. This proves delegation to the singleton rather than independent store creation.
  - Independent check: Hand-checked: on a purged keyring both calls return None, so wrapper_result == store_result is None==None and cannot distinguish singleton delegation from a fresh CredentialStore(). Accurate tautological flag.

### `tests/test_credentials/test_credential_store_live.py`

- **test_list_providers_no_deadlock** (line 166) - `weak-existence` / **low** - _[verified accurate]_
  - Why it is not a gate: The asyncio.wait_for timeout at line 182 DOES gate against actual deadlock - if list_providers() deadlocks, TimeoutError is raised and the test fails. This is a real, effective gate for the deadlock scenario. However, the sole postcondition assertion `assert isinstance(result, list)` does not verify content. When no credentials are pre-seeded (as in this test), an empty list is indistinguishable from correct behavior. Breaking list_providers to always return [] (e.g., skipping the iteration loop entirely) would pass both the timeout gate and the isinstance check.
  - Fix: Pre-seed at least one credential with `store.set(...)` before calling list_providers(), then assert the returned list is non-empty and contains a StoredCredential matching the seeded provider, with cleanup in finally block. This simultaneously gates both deadlock prevention AND the actual list-building behavior.
  - Independent check: Hand-checked: wait_for(timeout=5.0) genuinely gates the named deadlock regression; weak-existence correctly targets that isinstance(result, list) does not gate list-building content (a shaped empty result passes). Low is right.
