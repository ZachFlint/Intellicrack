# U00-fixtures - remediation of shared-fixture audit findings

Unit U00 owns three shared `conftest.py` fixture modules:

- `tests/test_audit4/b6_system_tab/conftest.py`
- `tests/test_bridges/conftest.py`
- `tests/test_sandbox/conftest.py`

All three modules had already been rewritten in a prior commit to remove the
mocks/stubs the audit flagged (the `silence_qmessagebox` monkeypatch is gone,
the `bridge()` fixture now `yield`s a real connected `HexEditorBridge` with
setup assertions, and a real `LocalProcessSandbox` backend exists alongside the
clearly-scoped `InMemorySandbox`). This remediation verified each rewritten
fixture is a genuine gate and closed the remaining gap: the
`warning_recorder` GUI harness was autouse infrastructure that no test ever
asserted against, so its real-warning capture was never exercised as a gate. A
new real-gate test class now drives genuine `QMessageBox.warning` production
paths and asserts on the captured dialog content.

## Per-finding outcomes

| File:line - test | Severity | Status | Real input / oracle / exact assertion now backing it |
| --- | --- | --- | --- |
| `tests/test_audit4/b6_system_tab/conftest.py:18` - `silence_qmessagebox (fixture)` (agent-06) | High | FIXED | The monkeypatch mock no longer exists; the conftest exposes a real GUI harness (`WarningRecorder` + repeating `QTimer`) that captures the genuine modal `QMessageBox` Qt creates and records its real `windowTitle()`/`text()`. New gate tests in `test_system_tab.py::TestUserVisibleWarningDialogIsShown` drive real production warning paths with **no bridge double**: `_refresh_privileges()` with no attached pid asserts `warning_recorder.titles == ["Query Privileges"]` and `warning_recorder.messages == ["Not attached to any process"]`; `_on_read_teb()` with no thread asserts `["Read TEB"]` / `["No thread selected"]`; two distinct unattached actions assert ordered `["Query Privileges", "Enumerate Services"]`. Oracle = the production string constants, independently read from source. Falsifiability confirmed by mutating the production dialog title to "WRONG TITLE" -> two tests went red; reverted. |
| `tests/test_bridges/conftest.py` (file-level) - `fixture bridge()` (agent-18) | Critical | FIXED | The fixture now `yield b`s a real `HexEditorBridge` after `loop.run_until_complete(b.initialize())`, and gates setup with exact-value assertions: `b.state.connected is True`, `b.state.tool_running is True`, `b.document is None`. It drives the real `intellicrack_hexcore` native backend (`importorskip` only when unbuilt). Verified consumed and passing: `test_hex_editor_top_audit1.py` + `test_hex_state_audit1.py` = 64 tests pass against the yielded connected bridge. A broken `initialize()` fails fast at fixture setup instead of returning `None`. |
| `tests/test_sandbox/conftest.py` (file-level) - `InMemorySandbox fixture` (agent-11) | Critical | FIXED | `InMemorySandbox` is retained only for pure log/report-helper unit tests (its fabricated data is never asserted as observed behaviour). A real `LocalProcessSandbox` (`SandboxBase` subclass) executes binaries as genuine OS subprocesses, captures real exit code/stdout/stderr, and reports file changes by diffing the work dir before/after. The real integration suite `test_local_process_sandbox_real.py` drives the running Python interpreter as a real binary and asserts independently-known oracles: exact dropped-file bytes + SHA-256, exact stdout (`"run-ok"`), exact exit codes (0 and 7), real timeout -> `SandboxError`, missing-file export -> `SandboxError`, snapshot/restore exact-byte recovery. 8 real integration tests pass when the process-spawn capability is granted. |

## Notes on legitimate skips

The 8 `LocalProcessSandbox` integration tests carry `spawns_process` and are
skipped on the bare host (the harness refuses to spawn external processes
outside the Docker sandbox). This is an environment-capability gate, not a
skip used to hide breakage: with
`INTELLICRACK_ALLOW_HOST_PROCESS_TESTS=1` set, all 8 genuinely pass
(`8 passed`). Inside the Docker test harness they run unconditionally.

## Verification (all green)

Commands run in the project pixi environment on the touched files
(`tests/test_audit4/b6_system_tab/conftest.py tests/test_bridges/conftest.py
tests/test_sandbox/conftest.py tests/test_audit4/b6_system_tab/test_system_tab.py`):

```
pixi run ruff check <files>            -> All checks passed!
pixi run ruff format <files>           -> 4 files already formatted
pixi run ruff format --check <files>   -> 4 files already formatted (no changes)
pixi run basedpyright <files>          -> 0 errors, 0 warnings, 0 notes
pixi run pydoclint <files>             -> No violations
pixi run pydocstyle <files>            -> (no output) no violations
pixi run pytest <consuming suites> -p no:timeout
    - tests/test_audit4/b6_system_tab/test_system_tab.py           -> 15 passed
    - tests/test_sandbox/test_local_process_sandbox_real.py        -> 8 passed (host-process capability enabled); 8 skipped on bare host
    - tests/test_bridges/{test_hex_editor_top_audit1,test_hex_state_audit1}.py -> 64 passed
    - tests/test_sandbox (full)                                    -> 390 passed, 14 skipped (capability gates)
```

Falsifiability check: mutating the production warning title in
`system_tab.py` turned two `TestUserVisibleWarningDialogIsShown` gates red; the
mutation was reverted and the suite returned to 15 passed.
