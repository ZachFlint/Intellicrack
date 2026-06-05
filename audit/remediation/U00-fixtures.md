# U00-fixtures Remediation

Worktree: `D:/ic-wt2/U00-fixtures` (branch `wf2/U00-fixtures`)

These three files are pytest `conftest.py` fixture providers. The flagged fixtures
were already reworked in the HEAD "harden test suite" commit (the findings describe
the original broken state). To turn them into genuine, falsifiable gates that the
VERIFY pytest command actually exercises, real `test_` functions were added **inside
each conftest** (pytest collects test functions defined in a `conftest.py`). Each new
test drives the real, finding-relevant code path and asserts exact, independently-known
values. Falsifiability was confirmed by mutating the covered logic and observing RED,
then reverting byte-identical.

## Per-finding results

| Finding (report) | Severity | Status | Real input + independent oracle + exact assertion |
| --- | --- | --- | --- |
| `tests/test_audit4/b6_system_tab/conftest.py:18` - `silence_qmessagebox` fixture (agent-06) | High | FIXED | The mocking `silence_qmessagebox` fixture no longer exists; the autouse `WarningRecorder` is driven by a real `QTimer` that captures the genuine modal Qt creates. New gates: production calls real `QMessageBox.warning`; oracle = the exact title/text passed in; assert `warning_recorder.captured == [("Real Title", "Real warning body")]` and ordered `[("First","alpha"),("Second","beta")]`. Mutating the capture to a wrong title goes RED. |
| `tests/test_bridges/conftest.py` - `bridge()` fixture (agent-18) | Critical | FIXED | New gate consumes the `bridge` fixture and a real PE from `_build_pe_binary`; oracle = DOS magic `0x4D 0x5A` and `pe_binary.stat().st_size`. Asserts the yielded object is a connected `HexEditorBridge`, `read_bytes(0,2)=="4D 5A"`, write `90 90` then read `=="90 90"`, restore then read `=="4D 5A"`. Error path: `read_bytes` with no document raises `RuntimeError("no document open")`. Proves the fixture yields a usable connected bridge, not `None`. |
| `tests/test_sandbox/conftest.py` - `InMemorySandbox` fixture (agent-11) | Critical | FIXED | `InMemorySandbox` retained only for pure-helper unit tests; the real `LocalProcessSandbox` is now gated. New gate launches `sys.executable` as a genuine subprocess that writes one file and emits fixed markers; oracle = the program's known behaviour. Asserts `exit_code==0`, exact `stdout`/`stderr`, and a real before/after tree diff yielding a `created` `FileChange` for `artifact.bin` with `size==len(payload)` and matching bytes. Error paths: `run_binary` timeout raises `SandboxError("timed out")`; `copy_from_sandbox` of a missing file raises `SandboxError`. Mutating the diff to drop `created` changes goes RED. |

## Six-command verification (from `D:/ic-wt2/U00-fixtures`)

All commands run via `pixi run --manifest-path D:/Intellicrack/pyproject.toml ...` over the three files.

| # | Command | Result |
| --- | --- | --- |
| 1 | `ruff check` | All checks passed |
| 2 | `ruff format` + `ruff format --check` | 3 files already formatted (no changes) |
| 3 | `basedpyright` | 0 errors, 0 warnings, 0 notes (confirmed actively analyzing: a deliberate `int = "str"` error was caught, then reverted) |
| 4 | `pydoclint` | No violations |
| 5 | `pydocstyle` | exit 0 (no findings) |
| 6 | `pytest -p no:timeout -p no:cacheprovider` | 7 passed in 2.73s |

The `basedpyright` `venvPath ... is not a valid directory` line is an informational
note (the worktree has no local pixi env); type resolution still works via `extraPaths`
to `src`, verified by the deliberate-error probe above. The `ruff format` `COM812`
warning is the pre-existing repo-wide formatter advisory, not a finding on these files.
