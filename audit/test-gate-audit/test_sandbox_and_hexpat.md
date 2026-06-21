# Test-Gate Audit — test_sandbox + test_hexpat

## Summary
- Files audited: 23
- Test functions examined: 318
- Genuine gates: 308
- Flagged non-gates: 10  (CRITICAL: 1, HIGH: 4, MEDIUM: 4, LOW: 1)

## Coverage checklist
- [x] tests/test_sandbox/__init__.py — gates: 0, flagged: 0 (package docstring only)
- [x] tests/test_sandbox/conftest.py — gates: 3, flagged: 0 (3 module-level integration tests; rest is fixtures/helpers)
- [x] tests/test_sandbox/test_log_helpers.py — gates: 32, flagged: 0
- [x] tests/test_sandbox/test_base_types.py — gates: 49, flagged: 1
- [x] tests/test_sandbox/test_manager.py — gates: 26, flagged: 1
- [x] tests/test_sandbox/test_log_parsers.py — gates: 73, flagged: 0
- [x] tests/test_sandbox/test_realcov_12b_analysis_real.py — gates: 3, flagged: 2
- [x] tests/test_sandbox/test_local_process_sandbox_real.py — gates: 8, flagged: 0
- [x] tests/test_sandbox/test_realcov_04_sandbox_bridge.py — gates: 7, flagged: 1
- [x] tests/test_sandbox/test_realcov_12a_base_contract.py — gates: 49, flagged: 0
- [x] tests/test_sandbox/test_sandbox_bridge.py — gates: 56, flagged: 3
- [x] tests/test_sandbox/test_analysis.py — gates: 99, flagged: 0
- [x] tests/test_hexpat/__init__.py — gates: 0, flagged: 0 (package docstring only)
- [x] tests/test_hexpat/conftest.py — gates: 0, flagged: 0 (fixtures only)
- [x] tests/test_hexpat/test_parse_helpers.py — gates: 14, flagged: 0
- [x] tests/test_hexpat/test_interpreter.py — gates: 41, flagged: 0
- [x] tests/test_hexpat/test_lexer.py — gates: 18, flagged: 0
- [x] tests/test_hexpat/test_compiler.py — gates: 24, flagged: 0
- [x] tests/test_hexpat/test_realcov_08_lexer_escapes.py — gates: 9, flagged: 0
- [x] tests/test_hexpat/test_realcov_08_parser_unit.py — gates: 14, flagged: 0
- [x] tests/test_hexpat/test_realcov_08_vendor_patterns.py — gates: 6, flagged: 0
- [x] tests/test_hexpat/test_realcov_08_preprocessor_vendor.py — gates: 8, flagged: 1
- [x] tests/test_hexpat/test_realcov_07b_compiler_pragmas.py — gates: 30, flagged: 1

## Flagged tests

### tests/test_sandbox/test_realcov_12b_analysis_real.py
#### `test_detect_c2_patterns_on_real_c2_port_capture` — HIGH — N3 (skip on the thing under test)
- **Location:** tests/test_sandbox/test_realcov_12b_analysis_real.py:310 (skip at :324-328)
- **Current behavior:** Captures live process/network state, then if the loopback `:4444` connection it deliberately generated is NOT observed in `report.network_activity`, it calls `pytest.skip(...)` and never reaches the `detect_c2_patterns` assertions.
- **Why it is not a gate:** The whole point of the test is to drive `detect_c2_patterns` against real port-4444 traffic the test itself generated. If the live monitor fails to capture the very connections the test created (a real defect in the Windows network-monitor source builder it exercises, or a capture-window regression), the test silently skips instead of failing. The detection assertions only run on the lucky path, so a regression that drops the C2 connection from capture turns this green-by-skip, not red.
- **Recommended fix:** This is the in-process listener the test controls on loopback; treat its absence as a failure, not a skip. Widen/poll the capture window deterministically (retry the monitor until the known connection appears, with a bounded timeout) and assert the connection was captured (`assert _C2_PORT in c2_ports`) before asserting on `detect_c2_patterns`. Reserve skip strictly for `pwsh`/Windows absence.

#### `test_match_behaviors_on_real_capture_is_consistent` — HIGH — N3 (skip on the thing under test)
- **Location:** tests/test_sandbox/test_realcov_12b_analysis_real.py:401 (skip at :414-415)
- **Current behavior:** Same pattern: if the deliberately-generated loopback `:4444` connection is not in the captured `network_activity`, the test skips before validating that the custom `network_ports:[4444]` rule matches real captured data.
- **Why it is not a gate:** The custom-rule match against genuine captured state is the capability under test; a capture regression that loses the connection makes the test skip rather than fail. The match assertions are only reached when capture happens to succeed.
- **Recommended fix:** Same as above — make capture of the self-generated loopback connection a hard precondition (deterministic retry + assert), not a skip, so `match_behaviors` is always exercised against the real `:4444` activity.

### tests/test_sandbox/test_realcov_04_sandbox_bridge.py
#### `test_create_windows_sandbox_or_typed_error` — HIGH — N7 (accepts both outcomes)
- **Location:** tests/test_sandbox/test_realcov_04_sandbox_bridge.py:237 (logic at :261-301)
- **Current behavior:** Drives the real `SandboxManager.create("windows")` and accepts EITHER a successful instance id OR a `ToolError` ("Failed to create sandbox") as passing. `_assert_create_outcome` asserts a meaningful message on the error path and a non-empty id on the success path.
- **Why it is not a gate:** Because both success and the typed-failure branch pass, a real regression where the bridge can no longer create a sandbox on a capable host (but still raises a correctly-shaped `ToolError`) is indistinguishable from the legitimate "host lacks Windows Sandbox" case. On essentially every CI host the feature is absent, so this test reliably travels the error branch and never actually gates the create-success path it names. It cannot fail for a create-capability regression.
- **Recommended fix:** Split into two tests. Gate the success path behind an explicit, hard capability check (skip only when Windows Sandbox/Hyper-V is genuinely unavailable) and then require `created_id`. Keep the error-translation contract in a separate, deterministic test (the monkeypatched-`create` test at :195 already does this well), so the create-success capability has a dedicated gate that fails when it breaks.

### tests/test_sandbox/test_sandbox_bridge.py
#### `test_all_resolve_to_methods` — MEDIUM — N8 (existence-only for a behavior claim)
- **Location:** tests/test_sandbox/test_sandbox_bridge.py:122
- **Current behavior:** Iterates every tool-definition function name and asserts `hasattr(bridge, method)` and `callable(...)`.
- **Why it is not a gate:** It only proves the attribute exists and is callable, not that dispatching the tool actually performs the documented operation. A method that exists but returns wrong/garbage data passes. (The realcov_04 dispatch tests partly cover this for a subset, so severity is MEDIUM, not HIGH.)
- **Recommended fix:** Acceptable as a thin completeness check, but harden by invoking each read-only/instance-scoped tool against the fixture instance and asserting a documented return key (as `test_instance_scoped_methods_dispatch` already does for the QEMU subset). Extend that pattern to cover all dispatchable names.

#### `test_create_failure_raises` — MEDIUM — N7 (accepts unrelated failure causes)
- **Location:** tests/test_sandbox/test_sandbox_bridge.py:276
- **Current behavior:** On a bridge backed by the real manager, asserts `bridge.create("windows")` raises `ToolError`. Comment claims it raises "on bridge with no available types".
- **Why it is not a gate:** `pytest.raises(ToolError)` with no `match` passes for ANY `ToolError`, including one raised for a reason unrelated to the intended "no available sandbox type" path (e.g. an internal bridge bug, an import-time failure surfaced as ToolError). It does not pin the failure cause, so a regression that changes why/where the failure occurs still passes.
- **Recommended fix:** Add a `match=` on the expected message ("Failed to create sandbox" / the manager's reason) and assert `bridge.state.last_error` is set to the capability-absence reason, mirroring the stronger `test_create_translates_sandbox_error` in realcov_04.

#### `test_definition_exists` — LOW — N4-adjacent (existence-only)
- **Location:** tests/test_sandbox/test_sandbox_bridge.py:105
- **Current behavior:** `assert bridge.tool_definition is not None`.
- **Why it is not a gate:** `tool_definition` is a property that constructs and returns a definition object; it provably cannot be `None`, so the assertion can never fail. It is pure smoke. (Low severity because the adjacent `test_function_count`, `test_all_params_have_types`, and `test_parameter_names_match_signatures` provide real gates on the same object.)
- **Recommended fix:** Drop it or fold its intent into the count/structure tests that already assert the definition's contents.

### tests/test_sandbox/test_base_types.py
#### `test_new_fields_present` — MEDIUM — N8 (hasattr-only on a dataclass)
- **Location:** tests/test_sandbox/test_base_types.py:291
- **Current behavior:** Constructs an `ExecutionReport` and asserts `hasattr(report, "service_changes")`, `"kernel_objects"`, etc. for six fields.
- **Why it is not a gate:** It only checks attribute existence, not the default value or type. The sibling `test_default_lists_are_empty` (:255) already asserts these same fields default to `[]`, which is the real gate. This test would pass even if a field were mistyped or defaulted wrongly, as long as the name exists.
- **Recommended fix:** Redundant with `test_default_lists_are_empty`; either delete it or change the assertions to check the field default values/types (e.g. `report.kernel_objects == []`) so it gates the dataclass contract rather than mere name presence.

### tests/test_sandbox/test_manager.py
#### `test_timestamps_are_set` — MEDIUM — N4 (asserts values that provably cannot be None)
- **Location:** tests/test_sandbox/test_manager.py:258
- **Current behavior:** Creates a `_TestInstance` and asserts `inst.created_at is not None` and `inst.last_used is not None`.
- **Why it is not a gate:** `created_at`/`last_used` are assigned `datetime.now(UTC)` unconditionally in `_TestInstance.__init__` (lines 228-229), which can never be `None`. More fundamentally, `_TestInstance` is a test-local class, not production `SandboxInstance`, so even a meaningful assertion here would gate test code, not Intellicrack. The assertion can never fail.
- **Recommended fix:** Either assert a falsifiable property (e.g. `created_at <= datetime.now(UTC)` and the two timestamps are close) on the REAL `SandboxInstance` from `intellicrack.sandbox.manager`, or remove the test. The whole `_TestableManager`/`_TestInstance` reimplementation in this file mirrors production logic rather than exercising it (see note below).

### tests/test_hexpat/test_realcov_08_preprocessor_vendor.py
#### `test_missing_include_does_not_raise` — MEDIUM — N8/N2-adjacent (asserts only that no exception propagates plus residual text)
- **Location:** tests/test_hexpat/test_realcov_08_preprocessor_vendor.py:171
- **Current behavior:** Feeds an unresolvable `#include <std/nonexistent...>` and asserts the trailing `u8 x @ 42;` survives and no raw `#include` remains.
- **Why it is not a gate:** The named contract is "missing include is silently skipped, logged as a warning, and does not raise." The test asserts the no-raise behaviour only implicitly (by not wrapping in `pytest.raises`) and never asserts the warning was emitted or that ONLY the missing line was dropped (vs. accidentally dropping more). A regression that swallows the include AND mangles surrounding content differently, or that stops logging the warning, would still pass. The positive checks (`"u8 x @ 42;" in processed`, `"#include" not in processed`) are real but narrow.
- **Recommended fix:** Assert the warning is emitted (via `structlog.testing.capture_logs`, as `test_parse_helpers.py` does) and that the flattened body equals exactly `["u8 x @ 42;"]` (the contrast-style exact-equality already used in `test_std_io_include_absent_without_include_path`), so dropping/mangling surrounding source is caught.

### tests/test_hexpat/test_realcov_07b_compiler_pragmas.py
#### `test_at_least_one_vendor_pattern_compiles_to_static_json` — HIGH — N2 (swallowed failure) / N6 (vacuously satisfiable)
- **Location:** tests/test_hexpat/test_realcov_07b_compiler_pragmas.py:313
- **Current behavior:** Walks every vendor `.hexpat`, compiles each in a `try/except` that `continue`s on `HexPatError`, `ValueError`, `RecursionError`, `KeyError`; only asserts structure for patterns that happen to compile, and finally asserts `compiled >= 1`.
- **Why it is not a gate:** The broad `except (ValueError, RecursionError, KeyError): continue` swallows real compiler crashes — a regression that makes the codegen raise `KeyError`/`ValueError` on patterns it previously handled is absorbed silently. The pass condition only needs ONE pattern in the entire corpus to compile, so the static codegen could regress on the vast majority of real patterns and the test still goes green as long as a single trivial one survives. It does not gate the compiler's real coverage of the vendor corpus.
- **Recommended fix:** Pin a specific, known-static vendor pattern (or a small explicit all-list) and assert it compiles to the exact expected `name`/`fields` shape — no broad `except` continue. If a corpus-wide sweep is wanted, drop `ValueError`/`RecursionError`/`KeyError` from the swallow list (those are crashes, not the documented "contains runtime constructs" rejection, which is `HexPatError`) and assert a meaningful minimum count, not `>= 1`.

## Acceptable skips (not flagged)
- tests/test_sandbox/test_realcov_12b_analysis_real.py:91-97 `pytestmark` skipif `sys.platform != "win32"` — legitimate OS-capability skip; the inline monitors require the live Windows kernel (`Win32_Process`, `Get-NetTCPConnection`).
- tests/test_sandbox/test_realcov_12b_analysis_real.py:100-109 `_resolve_pwsh` skip when `pwsh` absent — legitimate tool-availability skip for a required external binary.
- tests/test_sandbox/test_sandbox_bridge.py:1226-1235 `TestBridgeRealSandboxLifecycle` skipif `INTEGRATION_SANDBOX` — legitimate environment-capability skip (real subprocess execution requires the Docker harness or an explicit opt-in env var); the in-memory unit suite still gates the same bridge logic.
- tests/test_hexpat/test_realcov_08_vendor_patterns.py:96-106, :109-122 `_require_vendor_corpus`/`_read_pattern` skips — legitimate corpus-availability skips (sparse checkout may omit the `vendor/ImHex-Patterns` submodule); not masking a code capability.
- tests/test_hexpat/test_realcov_08_preprocessor_vendor.py:32-39 `_require_vendor_includes` and per-file `pytest.skip` — legitimate corpus-availability skips for the same reason.
- tests/test_hexpat/test_realcov_07b_compiler_pragmas.py:327 `pytest.skip("no vendor .hexpat patterns are available")` — legitimate corpus-availability skip (distinct from the N2 swallow flagged above).

## Notes (not separate findings)
- `tests/test_sandbox/test_local_process_sandbox_real.py` and the `TestBridgeRealSandboxLifecycle`/`_RealLocalManager` paths in `test_sandbox_bridge.py` exercise the test-owned `LocalProcessSandbox`/`_RealLocalManager` helpers (defined in conftest/test files), not the production `WindowsSandbox`/`QEMUSandbox` backends. They DO genuinely gate the production `SandboxBridge` orchestration code (real exit code, stdout, observed artefacts, error translation) and are real, falsifiable gates against the bridge — so they are counted as genuine. The residual gap (no gate over the real OS-backend `run_binary`/artefact capture) is a coverage limitation, not a non-gate; the conftest documents it explicitly.
- `tests/test_sandbox/test_manager.py` validates a test-local `_TestableManager`/`_TestInstance` reimplementation rather than `intellicrack.sandbox.manager.SandboxManager`. Most assertions are falsifiable against that reimplementation (max-instance limits, cleanup-stale math, run_binary report storage) so they are counted as gates, but they gate test code, not production. Worth retargeting at the real `SandboxManager` where feasible; only `test_timestamps_are_set` is weak enough to flag outright.
