# Test-Gate Audit — credentials + root + ui/core + scripts + helpers

## Summary
- Files audited: 21
- Test functions examined: 56
- Genuine gates: 49
- Flagged non-gates: 7  (CRITICAL: 5, HIGH: 0, MEDIUM: 1, LOW: 1)

## Coverage checklist
- [x] tests/test_credentials/__init__.py — no test functions (package docstring only)
- [x] tests/test_credentials/test_realcov_15_store_api.py — gates: 11, flagged: 0
- [x] tests/test_credentials/test_oauth_manager_live.py — gates: 6, flagged: 0
- [x] tests/test_credentials/test_credential_store_live.py — gates: 4, flagged: 0
- [x] tests/test_credentials/test_env_loader_roundtrip_live.py — gates: 9 (2 parametrized funcs counted once each + 7), flagged: 0
- [x] tests/core/test_process_cleanup.py — gates: 11, flagged: 6
- [x] tests/core/test_process_manager_leaks.py — gates: 2, flagged: 0
- [x] tests/ui/__init__.py — no test functions (package docstring only)
- [x] tests/ui/conftest.py — no test functions (qapp fixture only)
- [x] tests/ui/test_system_tab_warnings.py — gates: 9, flagged: 1
- [x] tests/test_scripts/__init__.py — no test functions (package docstring only)
- [x] tests/test_scripts/test_commit_message.py — gates: 24, flagged: 0
- [x] tests/test_integration/__init__.py — no test functions (package docstring only)
- [x] tests/conftest.py — no test functions (shared fixtures + collection hooks only)
- [x] tests/__init__.py — no test functions (package docstring only)
- [x] tests/_helpers/__init__.py — no test functions (pure helper package)
- [x] tests/_helpers/guest_allowlist.py — no test functions (pure helper module)
- [x] tests/_helpers/process_cleanup.py — no test functions (pure helper module)
- [x] tests/_helpers/realcov_pipe_server.py — no test functions (pure helper / child-process entry point)
- [x] tests/_helpers/realcov_process_panel.py — no test functions (pure helper module)
- [x] tests/_helpers/real_binaries.py — no test functions (pure fixture-locator module)
- [x] scripts/sandbox/test_types.py — no test functions (PRODUCTION source module; `test_` prefix is misleading — defines TestType enum and build_pytest_args)
- [x] scripts/test_commit_pipeline.py — no test functions (manual CLI driver script with main()/prints, no assertions)

## Flagged tests

### tests/core/test_process_cleanup.py

#### `test_sandbox_temp_wsb_file_cleaned_up` — CRITICAL — N4/N10 (tautological / self-fulfilling)
- **Location:** tests/core/test_process_cleanup.py:147
- **Current behavior:** The test writes a `.wsb` file itself (`wsb_file.write_text(...)`), asserts it exists, then the test itself calls `wsb_file.unlink()` and asserts it no longer exists. No production code is invoked at any point.
- **Why it is not a gate:** It exercises `pathlib.Path.write_text`/`unlink`, not `SandboxTestWorker.run()`'s finally-block cleanup. Deleting the entire production cleanup path would leave this test green because the test never calls it. The docstring claims it validates the finally block, but the finally block is never executed.
- **Recommended fix:** Drive the real `SandboxTestWorker.run()` (or the real method that creates and is responsible for unlinking the `.wsb` file), then assert the file the production code created is gone after the worker completes/fails.

#### `test_qemu_pidfile_retry_constants_are_reasonable` — MEDIUM — N8 (existence-only / asserts config constants)
- **Location:** tests/core/test_process_cleanup.py:309
- **Current behavior:** Asserts `qemu_module.PIDFILE_MAX_RETRIES >= 2`, `PIDFILE_RETRY_DELAY >= 1.0`, and their product `>= 4.0`.
- **Why it is not a gate:** It checks the numeric value of two configuration constants, not the retry behaviour that consumes them. The real retry loop (`QemuSandbox._read_pidfile_loop` around qemu.py:1907 using `_read_pidfile_once`) could be deleted or broken and this test stays green. It gates a config sanity bound, not a capability.
- **Recommended fix:** Invoke the real production retry method against a real (or tmp_path-backed) pidfile and assert it reads the PID / raises `SandboxError` on exhaustion; let the constants be exercised through the real code path rather than asserted directly.

#### `test_qemu_pidfile_retry_reads_immediate_file` — CRITICAL — N4 (tautological: re-implements logic under test)
- **Location:** tests/core/test_process_cleanup.py:320
- **Current behavior:** The test body copies the production retry loop inline (its own `for _attempt in range(...)`, `pidfile.exists()`, `read_text`, `int(...)`, `break`) and asserts the PID it just read. Production `_read_pidfile_once` / the real retry loop in qemu.py are never called.
- **Why it is not a gate:** It validates the test's own re-implementation of the loop, not the shipping code. Corrupting or deleting `QemuSandbox`'s real pidfile reader would not fail this test. The docstring even says it "replicates the exact retry loop" — that is the defect.
- **Recommended fix:** Call the real `QemuSandbox` pidfile-read method (`_read_pidfile_once` and the retry wrapper) against the tmp_path pidfile and assert its return value.

#### `test_qemu_pidfile_retry_reads_delayed_file` — CRITICAL — N4 (tautological: re-implements logic under test)
- **Location:** tests/core/test_process_cleanup.py:346
- **Current behavior:** Same pattern — the retry loop is re-implemented in the test; a background task writes the pidfile after a delay; the inline loop reads it.
- **Why it is not a gate:** Tests the inline copy, not production. A regression in the real retry loop (e.g. single read with no retry) would not be caught.
- **Recommended fix:** Drive the real retry method and assert it recovers the delayed PID.

#### `test_qemu_pidfile_retry_exhausted_returns_none` — CRITICAL — N4 (tautological: re-implements logic under test)
- **Location:** tests/core/test_process_cleanup.py:380
- **Current behavior:** Re-implements the loop over a nonexistent pidfile and asserts `qemu_pid is None`. The docstring states the real code now raises `SandboxError` on exhaustion, but the test asserts `None` from its own loop and never calls the production raise path.
- **Why it is not a gate:** The asserted behaviour (`None`) contradicts the documented production behaviour (`SandboxError`); the real exhaustion path is never invoked, so removing the `SandboxError` raise would not fail this test.
- **Recommended fix:** Call the real retry method with a never-appearing pidfile and assert it raises `SandboxError` (matching the documented contract).

#### `test_qemu_pidfile_retry_handles_corrupt_content` — CRITICAL — N4 (tautological: re-implements logic under test)
- **Location:** tests/core/test_process_cleanup.py:409
- **Current behavior:** Re-implements the loop (which swallows `ValueError`/`OSError` and retries) inline; a background task rewrites the corrupt pidfile with a valid PID; the inline loop eventually reads it.
- **Why it is not a gate:** Validates the test's own retry/parse copy, not the production `_read_pidfile_once` corrupt-content handling. A regression that stopped tolerating corrupt content would not be caught.
- **Recommended fix:** Exercise the real production reader/retry method against the corrupt-then-fixed pidfile and assert the recovered PID.

### tests/ui/test_system_tab_warnings.py

#### `test_unattached_handlers_do_not_raise` — LOW — N1 (no meaningful assertion)
- **Location:** tests/ui/test_system_tab_warnings.py:320
- **Current behavior:** Calls the three handlers with no attached PID and makes no assertion beyond not raising (the `warning_calls` fixture result is discarded via `_ = warning_calls`).
- **Why it is not a gate (weakly):** It is a pure "does not raise" smoke check. The user-visible behaviour (warning shown, dispatch skipped, raw-output text) is asserted by the three sibling tests at lines 237/276/298, so this adds reach but no falsifiable assertion of its own — a handler that silently no-opped (showed no warning) would still pass.
- **Recommended fix:** Either drop it as redundant or have it assert the same observable outcomes (one warning per handler, no dispatch) so it can fail when a handler stops surfacing the guard.

## Acceptable skips (not flagged)

- tests/test_credentials/test_realcov_15_store_api.py — module-level `skipif(sys.platform != "win32")` and per-test `pytest.skip("Keyring backend is not available")` (lines 53-56, 156, 183, 207, 238, 273, 299, 325, 369, 400, 437): legitimate environment-capability skips. The tests target Windows Credential Manager; on the Windows host/Docker container the backend is always present (store._check_keyring passively inspects the live backend), so the skip masks no capability that the gate should hard-require — it only triggers on a genuinely broken keyring environment.
- tests/test_credentials/test_credential_store_live.py — same `skipif(win32)` + `_keyring_backend_usable` skips (lines 46-49, 177, 249, 291): legitimate environment-capability skips for the same reason. (`test_keyring_error_handled` monkeypatches `keyring.set_password` to raise, but that patches the external keyring dependency, not the store mapping logic under test — the real `CredentialStore.set` error-translation path is exercised and asserted via `pytest.raises(CredentialStoreError)`, so it is a genuine gate.)
- tests/test_credentials/test_realcov_15_store_api.py:357 `test_validate_per_provider_prefix_branches` — the inner `try/finally` only guarantees `store.delete` teardown; it does not swallow the assertions, which run after the `asyncio.run`. Genuine gate.
- tests/_helpers/realcov_process_panel.py:35 `require_windows` and tests/_helpers/real_binaries.py / tests/conftest.py real_* fixtures — `pytest.skip` / `FixtureUnavailableError` are raised only when the OS backend (Win32 ProcessBridge) or a real binary fixture is genuinely unavailable; these are environment-capability skips, not capability-masking, and they validate the fixture's own existence/magic-byte contract before returning a path.

## Notes
- `scripts/sandbox/test_types.py` is a PRODUCTION module under `scripts/`, not a test file, despite its `test_` filename prefix. It defines the `TestType` enum, `TestRunSpec`, and `build_pytest_args`. It contains zero pytest test functions and is therefore not gateable here; its own behaviour (the arg-vector mapping) should be covered by a dedicated test elsewhere if it is not already.
- `scripts/test_commit_pipeline.py` is a manual end-to-end driver (a `main()` that prints to stderr and calls the real Gemini API). It has no assertions and is not a pytest module; it is an operator convenience tool, correctly excluded from gate counting.
- The OAuth tests (test_oauth_manager_live.py) use a real in-process `http.server` standing in for the OAuth provider (the trusted external party), and drive the real `OAuthManager`/`OAuthCallbackServer`/PKCE code under test — the provider is the external dependency, not the unit under test, so this is faithful integration testing, not mock-validates-mock. All six are genuine gates (PKCE roundtrip, state/CSRF rejection, 401->RefreshError vs transient->TokenError distinction, full callback token exchange).
- The commit-message tests (test_commit_message.py) are strong gates: the token estimator is checked against an independent tiktoken oracle with falsifiable ratio bounds, the fallback dispatch raises genuine google.genai exception instances and asserts exact estimate values, and the throttle uses a virtual clock to assert the exact `interval - elapsed` sleep duration.
