# Test-Gate Audit — test_core (part 1)

## Summary
- Files audited: 17
- Test functions examined: 184
- Genuine gates: 152
- Flagged non-gates: 32  (CRITICAL: 0, HIGH: 0, MEDIUM: 4, LOW: 28)

The bulk of this batch is high quality: real-binary fixtures (lief-parsed
System32 PEs and a committed ELF corpus), real on-disk SQLite round-trips, real
OS subprocesses, hand-assembled ELF/Mach-O fixtures driven through the
production extractors, and full-string oracle assertions on the console
renderer. The flagged items are concentrated in `test_logging.py`, where a long
run of convenience-function and `configure` tests call the production function
and assert nothing (N1) — they only fail if the call raises, never if the
logged structure regresses. The remaining flags are existence-only or
weak-assertion checks on otherwise well-covered modules.

## Coverage checklist
- [x] tests/test_core/__init__.py — gates: 0, flagged: 0 (package docstring only)
- [x] tests/test_core/test_analysis_aggregator.py — gates: 4, flagged: 0
- [x] tests/test_core/test_config.py — gates: 27, flagged: 0
- [x] tests/test_core/test_config_audit6.py — gates: 7, flagged: 0
- [x] tests/test_core/test_elevation.py — gates: 12, flagged: 1
- [x] tests/test_core/test_logging.py — gates: 30, flagged: 28
- [x] tests/test_core/test_logging_audit6.py — gates: 4, flagged: 0
- [x] tests/test_core/test_main.py — gates: 17, flagged: 0
- [x] tests/test_core/test_orchestrator.py — gates: 11, flagged: 1
- [x] tests/test_core/test_orchestrator_audit6.py — gates: 31, flagged: 0
- [x] tests/test_core/test_process_manager.py — gates: 33, flagged: 0
- [x] tests/test_core/test_process_manager_audit6.py — gates: 9, flagged: 0
- [x] tests/test_core/test_realcov_05a_orchestration.py — gates: 5, flagged: 0
- [x] tests/test_core/test_realcov_05b_analysis_aggregator.py — gates: 7, flagged: 0
- [x] tests/test_core/test_realcov_05b_process_manager.py — gates: 6, flagged: 0
- [x] tests/test_core/test_realcov_05b_tools.py — gates: 8, flagged: 1
- [x] tests/test_core/test_realcov_06_config_integration.py — gates: 5, flagged: 0

## Flagged tests

### tests/test_core/test_elevation.py
#### `TestPlatformHelpers::test_is_elevated_returns_bool` — LOW — existence-only (N8)
- **Location:** tests/test_core/test_elevation.py:55
- **Current behavior:** Calls `elevation.is_elevated()` and asserts only
  `isinstance(..., bool)`.
- **Why it is not a gate:** The function's return type is `bool` by signature; a
  defect in the actual privilege detection (e.g. always returning `False`, or
  inverting the token check) would still return a `bool` and pass. The test
  never constrains the value against the real process token.
- **Recommended fix:** Assert agreement with an independent oracle, e.g. on
  Windows compare against `ctypes.windll.shell32.IsUserAnAdmin()`, or on
  non-Windows assert `is_elevated() is (os.geteuid() == 0)`. The companion
  `test_is_windows_matches_platform` already does this correctly for the
  platform helper.

### tests/test_core/test_orchestrator.py
#### `test_stats_to_dict` — MEDIUM — existence-only for a behavior test (N8)
- **Location:** tests/test_core/test_orchestrator.py:103
- **Current behavior:** Builds `OrchestratorStats`, records one response time,
  calls `to_dict()`, then asserts `len(d) == 10` and that six keys are present.
- **Why it is not a gate:** It records a `100.0` ms response time but never
  asserts `d["average_response_time_ms"] == 100.0`, nor any other value. A
  regression that serialised the wrong field, swapped two values, or emitted a
  stale/zeroed average would still produce the right key set and length and pass.
  Key-presence + count is structure, not behavior.
- **Recommended fix:** Assert the serialised values, e.g.
  `d["average_response_time_ms"] == _RESPONSE_TIME_A`, `d["total_requests"] == 0`,
  and the token fields equal their recorded counts, so a wrong-value or
  field-swap regression fails.

### tests/test_core/test_realcov_05b_tools.py
#### `TestExecuteToolCallRealDispatch::test_tool_name_is_case_insensitive` — MEDIUM — weak-assertion-on-rich-output (N8)
- **Location:** tests/test_core/test_realcov_05b_tools.py:170
- **Current behavior:** Dispatches `execute_tool_call("X64DBG", "get_breakpoints", {})`
  and asserts only `isinstance(result, list)`.
- **Why it is not a gate:** The test name claims to verify case-insensitive tool
  resolution, but if the registry failed to resolve `"X64DBG"` it would raise a
  `ToolError` (which would fail the test) — so the resolution path is gated only
  incidentally. The asserted value (`isinstance list`) gates nothing about the
  bridge output: an empty list, a wrong list, or a stale list all pass. Compare
  with the sibling dispatch tests that assert real PE size / MZ magic.
- **Recommended fix:** Either assert the resolution explicitly (dispatch both
  `"X64DBG"` and `"x64dbg"` and assert the same bridge instance handled them, or
  assert the returned breakpoint list equals the bridge's own
  `get_breakpoints()` result), so a broken case-fold or a wrong-bridge route is
  caught beyond the not-raising behavior.

### tests/test_core/test_logging.py

The following tests invoke a production logging helper (or `configure`) and make
no assertion on the result or any captured side effect. They pass as long as the
call does not raise, so a regression in *what* is logged — wrong event name,
dropped/renamed structured field, mis-sanitised argument, wrong success flag —
would not fail any of them. They are smoke tests, not gates. Grouped because the
defect and fix are identical for each.

**Recommended fix (applies to all below):** capture emitted records with
structlog's `capture_logs` (or a test-bound `ProcessorFormatter`/`caplog`
integration) and assert the event name plus the exact structured fields each
helper is documented to emit (e.g. `log_tool_call` must emit
`tool`, `function`, sanitised `arguments`, and `success` when provided;
`log_provider_response` must emit `tokens_used` when supplied). For the
`configure`/`get_logger` tests, assert the resulting logger actually routes at
the configured level and writes to the configured file (the audit6 logging file
already demonstrates the file-creation assertion pattern).

#### `test_intellicrack_logger_get_logger_root` — LOW — existence-only (N8)
- **Location:** tests/test_core/test_logging.py:496
- **Current behavior:** Asserts only `hasattr(result, "bind")` /
  `hasattr(result, "unbind")` on the returned logger.

#### `test_intellicrack_logger_get_logger_child` — LOW — existence-only (N8)
- **Location:** tests/test_core/test_logging.py:504

#### `test_intellicrack_logger_configure` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:511
- **Current behavior:** Calls `IntellicrackLogger.configure(...)` with no
  assertion; only fails if it raises.

#### `test_intellicrack_logger_configure_no_file` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:529

#### `test_intellicrack_logger_configure_plain_text` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:539

#### `test_get_logger_returns_bound_logger` — LOW — existence-only (N8)
- **Location:** tests/test_core/test_logging.py:557

#### `test_get_logger_no_name` — LOW — existence-only (N8)
- **Location:** tests/test_core/test_logging.py:564

#### `test_get_logger_with_name` — LOW — existence-only (N8)
- **Location:** tests/test_core/test_logging.py:570

#### `test_log_tool_call_minimal` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:579

#### `test_log_tool_call_with_duration_and_success` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:584

#### `test_log_tool_call_with_failure` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:595

#### `test_log_provider_request` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:600

#### `test_log_provider_response_minimal` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:605

#### `test_log_provider_response_with_tokens` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:610
- **Note:** Specifically claims to cover the `tokens_used` path but never asserts
  the token field is emitted.

#### `test_log_binary_operation` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:621

#### `test_log_binary_operation_path_object` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:626
- **Note:** Claims to cover `Path` handling but never asserts the path was
  stringified/recorded correctly.

#### `test_log_sandbox_operation` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:631

#### `test_log_session_operation_minimal` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:636

#### `test_log_session_operation_with_id` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:641

#### `test_log_session_operation_with_kwargs` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:646

#### `test_log_analysis_operation` — LOW — no-assert (N1)
- **Location:** tests/test_core/test_logging.py:651

#### `test_operation_timer_success` — LOW — weak (asserts only the echoed input)
- **Location:** tests/test_core/test_logging.py:659
- **Current behavior:** Enters `OperationTimer("test_op")` and asserts
  `timer.operation == "test_op"` — the literal it just passed in. It does not
  assert the success log was emitted on normal exit (the documented behavior).

#### `test_operation_timer_with_context` — LOW — weak (asserts only the echoed input)
- **Location:** tests/test_core/test_logging.py:665
- **Current behavior:** Asserts `timer.context["target"] == "app.exe"`, i.e. the
  value it injected; does not assert the context reaches the emitted log.

#### `test_operation_timer_on_exception` — LOW — log/side-effect not asserted (N9-adjacent)
- **Location:** tests/test_core/test_logging.py:671
- **Current behavior:** Asserts the `ValueError` propagates (good, real gate on
  re-raise) but the docstring claims it "logs failure on exception" and that
  failure-log side effect is never asserted. Counted as a gate for the re-raise;
  flagged only for the unverified logging claim — hardening, not a false green.

The renderer tests (lines 125-299), the `_sanitize_arguments` tests
(401-478), the `cleanup_old_logs` tests (305-395), `OperationTimer` timing
(682), and the `LEVEL_COLORS`/`RESET` class-attribute tests (692-701) are
genuine gates: they assert full-string oracle output, exact sanitised
representations, real file deletion/retention with mtime manipulation, and exact
ANSI constants.

## Acceptable skips (not flagged)
- tests/test_core/test_config.py:790 `test_config_save_and_reload` —
  `importorskip("tomli_w")`: the TOML *writer* is an optional serialisation
  dependency, not the operation under test (config round-trip); legitimate.
- tests/test_core/test_realcov_05b_tools.py:102,130,158,270
  `test_hex_editor_*` — `skip` when the Rust hexcore (`intellicrack_hexcore`) is
  not built/available; legitimate missing-native-dependency capability skip.
- tests/test_core/test_realcov_05b_process_manager.py:177
  `test_run_tracked_cmd_exe_captures_real_output` — `skip` when not on Windows
  or `cmd.exe` absent; legitimate OS-binary capability skip (the test targets a
  real system PE).
- tests/test_core/test_realcov_06_config_integration.py:63,93,116
  `importorskip("tomli_w")` and `importorskip("intellicrack.core.tools")` —
  optional writer / module-presence guards around real round-trip behavior;
  legitimate.
- tests/test_core/test_realcov_06_config_integration.py:159
  `test_committed_project_config_loads_if_present` — `skip` when no committed
  `.intellicrack/config.toml` exists in the checkout; legitimate
  data-presence skip (the file is genuinely optional in the repo).
- tests/test_core/test_process_manager.py:663,691 and the `_unix`/`_windows`
  terminate variants — `skipif` on `sys.platform`; legitimate per-OS split where
  the other-platform variant covers the same capability.

## Note on monkeypatch usage (reviewed, not flagged)
Several elevation, process-manager, and orchestrator tests use `monkeypatch`
to replace a true external boundary (`_relaunch_elevated`/`ShellExecuteW`,
`_sync_cleanup`/`cleanup_all_async` scheduling, the confirmation callback
transport) while asserting the production decision/marshalling logic that sits
above that boundary. These are not N5 mock-validates-mock cases: the unit under
test (the `maybe_elevate` decision tree, signal-handler non-blocking dispatch,
atexit dedup, confirmation-future cancellation) runs unmodified and a real
defect in it would fail the assertion. The scripted/fake LLM providers in the
realcov and audit6 suites are likewise the documented network-transport double
only — the agent loop, tool dispatch, real lief parsing, and SQLite persistence
all run for real.
