# Group 06 Verification Report

**Reviewer:** group-06 agent (adversarial test-reviewer)
**Date:** 2026-06-27
**Sections:** §7 (Orchestration/Session/Context), §8 (Core Infra/Codegen), §12 (Sandbox/Monitors)
**Protocol:** `audit/verification/PROTOCOL.md`

---

## Enumeration Method

Every row with Verdict/Status ∉ {plain REAL GATE, REAL} was extracted from the three source tables and independently verified against the live test tree using rg/Grep/Read. Findings were not taken from any pre-built list.

---

## Section 7 — Orchestration, Session & Context (19 findings)

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation) |
|---|------------------------|-----------------|-----|------------------------------------------|
| S7-01 | `Orchestrator.shutdown()` — orchestrator.py ~1400 | NO COVERAGE | RESOLVED | `tests/test_core/test_p3_orch_script.py:316` — asserts `orch.current_session is None`, `orch.shutdown_called is True`, `orch.shutdown_complete is True` after real `shutdown()` call; oracle: attribute identity; mutation: removing `self._current_session = None` from finally block turns test red |
| S7-02 | `Orchestrator.list_sessions()` — orchestrator.py ~1350 | NO COVERAGE | RESOLVED | `tests/test_core/test_p3_orch_script.py:340` — creates 2 sessions, calls `session_manager.list_sessions()`, asserts exact `id` set and `name` set + `len(sessions)==2`; oracle: known session IDs from create() return values; mutation: SQL SELECT returning 0 rows turns test red |
| S7-03 | `Orchestrator.delete_session(session_id)` — orchestrator.py ~1360 | NO COVERAGE | RESOLVED | `tests/test_core/test_p3_orch_script.py:375` — asserts `deleted is True`, `s1.id not in ids_after`, `s2.id in ids_after`, `len==1`, `store.load(s1.id) is None`, `store.load(s2.id).name=="ToKeep"`; oracle: store.load() round-trip; mutation: wrong-row delete turns multiple assertions red |
| S7-04 | Orchestrator agent loop max_iterations guard — orchestrator.py ~1050 | NO COVERAGE | NOT_RESOLVED | No test found that runs a scripted provider returning tool calls repeatedly until max_iterations is exhausted; config field tested in test_orchestrator.py:65 but loop termination path untested |
| S7-05 | Orchestrator agent loop timeout guard — orchestrator.py ~1060 | NO COVERAGE | NOT_RESOLVED | No test found that triggers timeout_seconds in a running agent loop; missing assertion: asyncio.TimeoutError propagates after elapsed > config.timeout_seconds |
| S7-06 | Confirmation gate — ConfirmationLevel.ALL vs DESTRUCTIVE in live agent loop — orchestrator.py ~1200 | NO COVERAGE | NOT_RESOLVED | cancel() unit test exists (test_orchestrator.py:190, test_orchestrator_audit6.py:785) but no agent loop test drives a destructive tool call through a live confirmation callback (approve/deny paths); missing: real destructive call → callback returns False → bridge call count == 0 |
| S7-07 | `SessionStore.export_to_json` — session.py ~700 | NO COVERAGE | RESOLVED | `tests/test_core/test_p3_orch_script.py:443` — exports session, reads raw JSON, asserts `raw["export_version"]=="1.0"`, then imports and asserts `id`, `name`, `provider`, `model`, `notes`, `messages[0].content`; oracle: original session fields; mutation: corrupt field in export turns assertion red |
| S7-08 | `SessionManager.import_json(path, replace=True)` — session.py ~970 | NO COVERAGE | RESOLVED | Same test, line 482; `replace=True` path exercised, imported session fields match original; oracle: known constants from create() call |
| S7-09 | `ProcessManager.run_tracked` ProcessStateError (returncode is None) — process_manager.py ~240 | NO COVERAGE | NOT_RESOLVED | No test corrupts a subprocess to produce returncode=None after communicate(); the specific ProcessStateError path remains dead to tests |
| S7-10 | `ProcessManager._pid_exists_windows` kernel32→psutil fallback — process_manager.py ~420 | WEAK | NOT_RESOLVED | Only indirect coverage via register_external_pid behavioral tests; no test constructs a scenario where kernel32.OpenProcess fails but psutil.pid_exists returns True; two-stage fallback unverified independently |
| S7-11 | `AnalysisAggregator.aggregate` with Cutter bridge — analysis_aggregator.py ~90 | NO COVERAGE | NOT_RESOLVED | No `_RealDataCutterBridge` or equivalent found in test tree; all aggregate tests use only GhidraBridge or no bridges; parallel Cutter path never executed |
| S7-12 | `AnalysisAggregator.aggregate` with both Ghidra + Cutter bridges — analysis_aggregator.py ~90 | NO COVERAGE | NOT_RESOLVED | No test registers both bridges simultaneously; merged-bridge scenario untested |
| S7-13 | `TransformPipeline` mid-pipeline step error propagation — transform_pipeline.py ~560 | NO COVERAGE | NOT_RESOLVED | test_p3_orch_script.py:418 tests orchestrator provider-error propagation (different pipeline); no test builds a TransformPipeline where step 2 raises TransformParamError and verifies it propagates rather than being swallowed |
| S7-14 | `TransformPipeline.to_dict` / `from_dict` serialization — transform_pipeline.py | NO COVERAGE (if exists) | NOT_RESOLVED | No to_dict/from_dict references found in test_realcov_07a_transform_pipeline.py or any test file; if these methods exist, they have zero test coverage |
| S7-15 | `execute_tool_call` with native coroutine bridge method — tools.py ~200 | WEAK | RESOLVED | `tests/test_core/test_realcov_05b_tools.py:306` — drives `set_alignment_grid`/`get_alignment_grid` through `execute_tool_call` with `await`; docstring at line 313 explicitly names "coroutine dispatch" as the path under test; oracle: `bridge.get_alignment_grid()` direct call == dispatch result; mutation: skipping coroutine detection in execute_tool_call produces wrong result |
| S7-16 | `initialize_tool(GHIDRA)` / `initialize_tool(X64DBG)` installer path — tools.py ~140 | NO COVERAGE | NOT_RESOLVED | test_tools_audit6.py:381 covers local-init path for CUTTER only; GHIDRA/X64DBG installer branches (installer path) untested |
| S7-17 | `ToolRegistry` typed getters ToolError on absence — tools.py ~300 | WEAK | NOT_RESOLVED | test_tools.py:117,127,132,137,148,157 use `pytest.raises(ToolError)` **without** `match=` — forbidden pattern per protocol; these do not verify the specific error message produced; mutation: raising wrong exception type or wrong message goes undetected |
| S7-18 | `RustTransformNode` param coercion with invalid params — transform_pipeline.py ~650 | WEAK | NOT_RESOLVED | No test found with invalid hex string or out-of-range integer params to `RustTransformNode.process()`; only valid coercions tested |
| S7-19 | `RegexReplaceNode` with `str` type replacement — transform_pipeline.py ~400 | WEAK | NOT_RESOLVED | No test passes a Python `str` as the replacement value to `RegexReplaceNode.process()`; only `bytes` and empty replacement tested |

---

## Section 8 — Core Infrastructure & Codegen (21 findings)

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation) |
|---|------------------------|-----------------|-----|------------------------------------------|
| S8-01 | `get_stdlib_root_logger` — logging.py ~280 | WEAK | RESOLVED | `tests/test_ui/log_viewer/test_app_integration.py:63` — calls `get_stdlib_root_logger()`, asserts `handler in root.handlers`, emits a real log record, asserts the probe message appears in `handler.bridge.record_received`; oracle: actual stdlib logging.root.handlers list; mutation: returning wrong logger turns `handler in root.handlers` false |
| S8-02 | `ProviderError` — types.py ~630 | NO COVERAGE | RESOLVED | `tests/test_core/test_types_exceptions_wave4.py:275` — asserts `err.message==msg`, `err.provider_name=="anthropic"`, `err.status_code==502`, `err.response_body==body`, `err.error_code==4001`, `str(err)==msg`, `err.details=={"retry":True}`; oracle: known constants; mutation: removing any self.* assignment raises AttributeError |
| S8-03 | `AuthenticationError` — types.py ~640 | NO COVERAGE | RESOLVED | `tests/test_core/test_types_exceptions_wave4.py:339` — asserts `status_code==403`, `provider_name=="google"`, `response_body==body`, `error_code==4011`, `str(err)==msg`; oracle: known constants; mutation: dropping status_code assignment raises AttributeError |
| S8-04 | `RateLimitError` — types.py ~650 | NO COVERAGE | RESOLVED | `tests/test_core/test_types_exceptions_wave4.py:381` — asserts `math.isclose(err.retry_after, 30.5)`, `err.limit_type=="requests_per_minute"`, `err.provider_name=="anthropic"`, `err.status_code==429`, `str(err)==msg`; oracle: known constants + math.isclose; mutation: dropping retry_after raises AttributeError |
| S8-05 | `ModelNotFoundError` — types.py ~660 | NO COVERAGE | RESOLVED | `tests/test_core/test_types_exceptions_wave4.py:424` — asserts `err.model_name=="gpt-5-turbo"`, `err.available_models==["gpt-4o","gpt-4o-mini","o1"]`, None-coercion to [], `status_code==404`, `str(err)==msg`; oracle: known constants; mutation: dropping model_name assignment raises AttributeError |
| S8-06 | `ToolError` — types.py ~670 | NO COVERAGE | RESOLVED | `tests/test_core/test_types_exceptions_wave4.py:474` — asserts `err.tool_name=="ghidra"`, `err.exit_code==139`, `err.stderr=="Segmentation fault (core dumped)"`, `err.error_code==5001`, `str(err)==msg`; oracle: known constants; mutation: dropping tool_name raises AttributeError |
| S8-07 | `ToolNotFoundError` — types.py ~680 | NO COVERAGE | RESOLVED | `tests/test_core/test_types_exceptions_wave4.py:535` — asserts `err.search_paths==[r"C:\Program Files\Ghidra", r"C:\Tools\ghidra"]`, None-coercion to [], `err.install_hint==hint`, `err.exit_code is None`, `err.stderr is None`; oracle: known constants; mutation: dropping search_paths assignment raises AttributeError |
| S8-08 | `InitializationError` — types.py ~690 | NO COVERAGE | RESOLVED | `tests/test_core/test_types_exceptions_wave4.py:586` — asserts `err.config_path==cfg`, `err.missing_dependency==dep`, `err.exit_code==1`, `err.stderr=="ImportError: no module named frida"`, `err.tool_name=="x64dbg"`, `err.error_code==5010`; oracle: known constants; mutation: dropping config_path raises AttributeError |
| S8-09 | `AttachError` — types.py ~700 | NO COVERAGE | RESOLVED | `tests/test_core/test_types_exceptions_wave4.py:645` — asserts `err.pid==4321`, `err.process_name=="svchost.exe"`, `err.reason=="insufficient privileges"`, `str(err)==msg`; oracle: known constants; mutation: dropping pid assignment raises AttributeError |
| S8-10 | `HexDocumentLike` protocol — types.py ~720 | NO COVERAGE | RESOLVED | `tests/test_core/test_session_audit6.py:537` — AST inspection verifies all method bodies are declarative (`...`/docstring only); `test_session_audit6.py:546` — `isinstance(MinimalHexDoc(), HexDocumentLike)` passes; `test_session_audit6.py:583` — `isinstance(NoMethods(), HexDocumentLike)` fails; oracle: Python structural typing + AST; mutation: adding a concrete statement to a Protocol method body fails AST count check |
| S8-11 | `HexDocumentFull` protocol — types.py ~750 | NO COVERAGE | RESOLVED | `tests/test_core/test_session_audit6.py:541,598` — same pattern as S8-10; `FullHexDoc` implementing all 9 methods satisfies both `HexDocumentFull` and `HexDocumentLike`; concrete implementer missing any method fails isinstance |
| S8-12 | `ConfirmationLevel` enum — types.py ~800 | NO COVERAGE | NOT_RESOLVED | `ConfirmationLevel.ALL/DESTRUCTIVE/NONE` used as values in config/orchestrator tests but no test asserts `.value` strings (e.g., `ConfirmationLevel.DESTRUCTIVE.value == "destructive"`) or verifies the complete member set; renaming the string value (not the member name) goes undetected |
| S8-13 | `ToolChoiceMode` enum — types.py ~820 | NO COVERAGE | NOT_RESOLVED | Only `ToolChoiceMode.AUTO` has indirect wire-format assertion (`_convert_tool_choice(...) == "auto"` at test_providers_cloud_audit1.py:187); `ToolChoiceMode.REQUIRED/SPECIFIC/NONE` member string values never directly asserted; complete member set not verified |
| S8-14 | `ToolName` enum — types.py ~840 | WEAK | RESOLVED | `tests/test_core/test_types.py:825` — asserts exact `.value` for GHIDRA=="ghidra", X64DBG=="x64dbg", FRIDA=="frida", CUTTER=="cutter", SANDBOX=="sandbox", HEX_EDITOR=="hex_editor"; round-trip `ToolName("ghidra") is ToolName.GHIDRA` at line 844; oracle: documented bridge-protocol string constants; mutation: changing any value string fails equality assertion |
| S8-15 | `_relaunch_elevated` — elevation.py ~130 | NO COVERAGE (acceptable) | NOT_RESOLVED | Requires real UAC dialog; no test can drive the actual `ShellExecuteW` call without triggering a system modal. This is a genuine structural constraint. No acceptable workaround exists without invoking the UAC dialog or mocking the thing under test. |
| S8-16 | `maybe_elevate` (F-1 MagicMock anti-pattern) — elevation.py ~145 | WEAK | RESOLVED | `tests/test_core/test_elevation.py` rewritten: no `MagicMock`, `patch`, or `unittest.mock` imports; uses `monkeypatch.setattr(elevation, "is_windows", lambda: False)` and real injectable `_capture_relaunch` callables; tests disabled/attempted/already-elevated paths without triggering UAC; oracle: `relauncher_calls` list populated by real Python function; mutation: removing a decision branch in `maybe_elevate` fails the corresponding assertion |
| S8-17 | `Script.get_extension` — script_gen.py ~290 | NO COVERAGE | RESOLVED | `tests/test_core/test_script_gen.py:418` — parametrized over all `ScriptLanguage` members; asserts exact extension per member (PYTHON→".py", JAVASCRIPT→".js", JAVA→".java", R2_COMMANDS→".r2", X64DBG_SCRIPT→".txt"); completeness guard at line 433 verifies parametrize set == `ScriptLanguage` members; oracle: known file-extension conventions; mutation: returning wrong extension fails equality |
| S8-18 | `ScriptManager.delete_script` — script_gen.py ~390 | NO COVERAGE | RESOLVED | `tests/test_core/test_script_gen.py:744` and `tests/test_core/test_p3_orch_script.py:527` — add script, delete it, assert `delete_script("name")` returns True, `get_script("name")` returns None, `list_scripts()` no longer contains name, re-delete returns False; oracle: get_script identity check; mutation: not removing from cache fails None assertion |
| S8-19 | `ScriptManager.list_scripts` — script_gen.py ~410 | NO COVERAGE | RESOLVED | `tests/test_core/test_script_gen.py:766` and `tests/test_core/test_p3_orch_script.py:494` — add 2-3 scripts, assert `sorted(list_scripts())==["p3_alpha","p3_beta"]`; oracle: known script names; mutation: returning empty list or wrong names fails equality |
| S8-20 | `build_execute_command` for r2/Cutter script type — script_gen.py ~600 | NO COVERAGE | NOT_RESOLVED | Tests in test_audit3/core/test_script_gen.py cover JavaScript, Java, x64dbg, Python; no test for `ScriptLanguage.R2_COMMANDS` through `build_execute_command`; missing assertion: `cmd[0]` contains the rizin/cutter binary path |
| S8-21 | `TemplateBootstrapError` — template_manager.py ~30 | NO COVERAGE | NOT_RESOLVED | No test found that triggers `TemplateBootstrapError` via a real filesystem condition (e.g., read-only patterns_dir); the exception is never raised in the test suite |

---

## Section 12 — Sandbox Orchestration & Monitors (8 findings)

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation) |
|---|------------------------|-----------------|-----|------------------------------------------|
| S12-01 | SHA1 hash extraction in `extract_iocs` — analysis.py | WEAK | NOT_RESOLVED | SHA256 and MD5 extraction tested with exact known values; no test embeds a 40-character hex string in a file path and asserts `ioc_type=="sha1"`; the SHA1 regex pattern is unvalidated; mutation: removing SHA1 pattern from extract_iocs goes undetected |
| S12-02 | `generate_timeline` resource category — analysis.py | NOT FOUND | NOT_RESOLVED | Nine of ten event categories have dedicated tests; no test adds a `ResourceSample` to a report, calls `generate_timeline`, and asserts `events[i]["category"]=="resource"`; mutation: removing resource category from timeline generator goes undetected |
| S12-03 | `_StateTracker` clears `last_error` on success — sandbox_bridge.py | WEAK | NOT_RESOLVED | The "fail then succeed" lifecycle test (`TestF0010LastErrorLifecycleSymmetric`) exists only in `tests/test_bridges/test_sandbox_bridge.py` which uses `AsyncMock`/`patch.object` throughout (verified at lines 1284, 1286, 1291, 1361, 1374, 1408, 1418); real-backend files (`tests/test_sandbox/test_realcov_04_sandbox_bridge.py`) only assert `last_error is None` on a fresh success path, not after a prior failure; mutation: removing `state.last_error = None` from the success branch of `_StateTracker` leaves the real-backend tests green |
| S12-04 | `tests/test_bridges/test_sandbox_bridge.py` — FAKE GATE | FAKE GATE | NOT_RESOLVED | File confirmed to import and use `from unittest.mock import AsyncMock, MagicMock, patch` (line 19); `TestF0001ContBroadException` uses `MagicMock()` for sandbox instance, `AsyncMock()` for qmp.cont/manager (lines 77-87); `TestF0010BridgeStateUpdates.test_create_updates_state_on_success` uses `MagicMock()/AsyncMock()/patch.object(bridge,"ensure_manager")` (lines 1277-1291); `TestF0010LastErrorLifecycleSymmetric._run_failure_then_success` uses `patch.object/AsyncMock` throughout (lines 1408-1426); deleting the production QMP/subprocess code would not turn these tests red |
| S12-05 | `_ppm_p6_to_png` / `_parse_ppm_p6` in `qemu.py` — qemu.py | NO COVERAGE | NOT_RESOLVED | No test found (Grep for `ppm_p6_to_png|parse_ppm_p6|ppm.*png` in tests/ returns zero matches); PNG IHDR/IDAT construction, zlib compression, CRC calculation entirely untested; mutation: corrupting PPM→PNG byte output goes undetected |
| S12-06 | QEMU PCAP capture (real `tshark` subprocess) — qemu.py | NO COVERAGE | NOT_RESOLVED | No test found that calls `start_pcap_capture` against a real `tshark` binary; `InMemorySandbox` stubs return a UUID without invoking tshark; real capture lifecycle untested |
| S12-07 | QEMU memory dump — process memory path — qemu.py | NO COVERAGE | NOT_RESOLVED | `test_audit7/sandbox_windows/test_memory_dump_target_pid.py` validates the `target_pid > 0` precondition only; the actual guest-agent dump invocation code path has no confirmed test; mutation: breaking the dump invocation leaves the precondition test green |
| S12-08 | `_collect_logs` / log collection path — qemu.py | PARTIAL | NOT_RESOLVED | Log collection implicitly covered through `run_binary` integration tests; missing-file and partial-read failure paths of `_collect_logs` itself have no dedicated test; mutation: silently dropping a log file in `_collect_logs` goes undetected |

---

## STILL OPEN

### Section 7

- **max_iterations guard** (orchestrator.py ~1050) :: no test runs a scripted provider loop to exhaustion :: missing: `OrchestratorConfig(max_iterations=3)` + provider always returning ToolCall; assert either `OrchestratorError` raised or `stats.total_tool_calls == 3`
- **timeout guard** (orchestrator.py ~1060) :: no test triggers elapsed > timeout_seconds in running loop :: missing: provider that sleeps + `timeout_seconds=0.1` + assert `asyncio.TimeoutError` propagates
- **Confirmation gate in live agent loop** (orchestrator.py ~1200) :: cancel() unit test only; no live destructive-call approval/denial gate :: missing: `ConfirmationLevel.DESTRUCTIVE` + scripted destructive tool call + callback returns False → assert bridge call count == 0
- **ProcessManager ProcessStateError** (process_manager.py ~240) :: no test triggers returncode=None after communicate() :: missing: subprocess with mocked returncode or forced None state + assert `ProcessStateError` raised
- **_pid_exists_windows kernel32 fallback** (process_manager.py ~420) :: kernel32.OpenProcess fails → psutil fallback path never exercised independently :: missing: direct `_pid_exists_windows(os.getpid())` assert True, `_pid_exists_windows(guaranteed_dead_pid)` assert False
- **AnalysisAggregator with Cutter bridge** (analysis_aggregator.py ~90) :: Cutter path never executed :: missing: `_RealDataCutterBridge` returning imports/exports from real PE; assert `"cutter" in summary.source_bridges` and `summary.complete is True`
- **AnalysisAggregator with both bridges** (analysis_aggregator.py ~90) :: merged-bridge scenario untested :: missing: both bridges registered; assert both in `source_bridges`
- **TransformPipeline mid-step error** (transform_pipeline.py ~560) :: no test drives a step that raises mid-chain :: missing: two-step pipeline where step 2 raises `TransformParamError`; assert exception propagates, step 1 output not silently returned
- **TransformPipeline.to_dict/from_dict** (transform_pipeline.py) :: not found in any test file :: missing: serialize pipeline to dict, reconstruct, assert same step names and params
- **initialize_tool GHIDRA/X64DBG installer path** (tools.py ~140) :: installer branch never hit :: missing: `registry.initialize_tool(ToolName.GHIDRA)` with mocked installer; assert installer invoked, bridge registered
- **ToolRegistry typed getters without match=** (tools.py ~300) :: `pytest.raises(ToolError)` without `match=` in test_tools.py:117,127,132,137,148,157 is forbidden pattern :: missing: add `match=r"_ERR_BRIDGE_NA|not registered"` to each raises call
- **RustTransformNode invalid params** (transform_pipeline.py ~650) :: invalid hex string and out-of-range integer not tested :: missing: `RustTransformNode.process(data, {"key": "not_hex"})` + assert `TransformParamError`
- **RegexReplaceNode str type** (transform_pipeline.py ~400) :: str replacement path not tested :: missing: `RegexReplaceNode.process(data, {"pattern": b"MZ", "replacement": "XX"})` + assert correct behavior or TypeError

### Section 8

- **ConfirmationLevel enum** (types.py ~800) :: no test asserts `.value` strings :: missing: `assert ConfirmationLevel.DESTRUCTIVE.value == "destructive"`, `ConfirmationLevel.ALL.value == "all"`, `ConfirmationLevel.NONE.value == "none"`; assert `set(ConfirmationLevel) == {DESTRUCTIVE, ALL, NONE}`
- **ToolChoiceMode enum** (types.py ~820) :: only AUTO wire-format tested indirectly; REQUIRED/SPECIFIC/NONE values never asserted :: missing: direct `.value` assertions for all members
- **_relaunch_elevated** (elevation.py ~130) :: UAC dialog required; structural constraint :: acceptable gap — cannot test without triggering OS modal
- **build_execute_command r2/Cutter** (script_gen.py ~600) :: R2_COMMANDS script type not exercised through `build_execute_command` :: missing: `mgr.build_execute_command(r2_script, None)` + assert `cmd[0]` is rizin/cutter binary
- **TemplateBootstrapError** (template_manager.py ~30) :: exception never raised in any test :: missing: `patterns_dir.chmod(stat.S_IREAD)` before `bootstrap_builtins()` + assert `pytest.raises(TemplateBootstrapError)`

### Section 12

- **SHA1 IOC extraction** (analysis.py) :: no 40-char hex file-path test :: missing: file path with 40-char hex stem + assert `ioc_type=="sha1"` in result
- **generate_timeline resource category** (analysis.py) :: resource category absent :: missing: `ResourceSample` in report + `generate_timeline()` + assert `events[i]["category"]=="resource"`
- **_StateTracker clears last_error on success** (sandbox_bridge.py) :: only mock-backed "clear" test exists :: missing: `InMemorySandbox` subclass raises on first call, succeeds on second; assert `bridge.state.last_error is None` after second call
- **test_bridges/test_sandbox_bridge.py FAKE GATE** (entire file) :: AsyncMock/MagicMock/patch on the very operations tested :: required action: rewrite using `InMemorySandbox` (state machine tests) or real subprocess (operation tests); delete or replace all AsyncMock/patch.object usages
- **_ppm_p6_to_png / _parse_ppm_p6** (qemu.py) :: zero coverage :: missing: construct minimal PPM P6 bytes in-process; call `_ppm_p6_to_png`; assert output starts with `\x89PNG\r\n\x1a\n` and IHDR encodes correct W/H; add malformed-header test asserting `SandboxError`
- **QEMU PCAP tshark** (qemu.py) :: no real tshark invocation :: missing: `start_pcap_capture()` + brief wait + `stop_pcap_capture()` + assert returned path exists and is non-empty (skip if tshark absent)
- **QEMU memory dump process path** (qemu.py) :: precondition-only test :: missing: guest-agent dump invocation; assert dump file created at expected path with expected content
- **_collect_logs missing-file / partial-read** (qemu.py) :: happy-path only :: missing: `_collect_logs` with one missing log file + one valid log; assert partial read returns what's available without raising

---

## GROUP 06 SUMMARY

```
GROUP 06 SUMMARY
sections: §7 ops #1-19, §8 ops #1-21, §12 ops #1-8
total_findings: 48
resolved: 22
red_by_design: 0
not_resolved: 26
STILL_OPEN:
- max_iterations agent loop guard (orchestrator.py:~1050) :: no test runs scripted provider to max_iterations exhaustion :: missing: OrchestratorConfig(max_iterations=3) + always-ToolCall provider; assert OrchestratorError or stats.total_tool_calls==3
- timeout_seconds agent loop guard (orchestrator.py:~1060) :: no test triggers elapsed > timeout_seconds :: missing: slow provider + timeout_seconds=0.1; assert asyncio.TimeoutError propagates
- Confirmation gate in live agent loop (orchestrator.py:~1200) :: cancel() unit test only; no live destructive-call approved/denied path :: missing: ConfirmationLevel.DESTRUCTIVE + scripted destructive call + callback returns False; assert bridge call count==0
- ProcessManager ProcessStateError (process_manager.py:~240) :: no test triggers returncode=None after communicate() :: missing: forced None returncode scenario + assert ProcessStateError raised
- _pid_exists_windows kernel32→psutil fallback (process_manager.py:~420) :: fallback path unverified :: missing: direct _pid_exists_windows assert with live + dead PIDs
- AnalysisAggregator with Cutter bridge (analysis_aggregator.py:~90) :: Cutter path never executed :: missing: _RealDataCutterBridge returning real PE data; assert "cutter" in source_bridges
- AnalysisAggregator with both Ghidra + Cutter bridges (analysis_aggregator.py:~90) :: merged-bridge scenario untested :: missing: both bridges registered; both in source_bridges
- TransformPipeline mid-step error propagation (transform_pipeline.py:~560) :: no test drives step raising mid-chain :: missing: step 2 raises TransformParamError; assert it propagates, not swallowed
- TransformPipeline.to_dict/from_dict (transform_pipeline.py) :: not found in any test :: missing: serialize + reconstruct pipeline; assert same step names and params
- initialize_tool GHIDRA/X64DBG installer path (tools.py:~140) :: installer branch untested :: missing: initialize_tool(ToolName.GHIDRA) with installer; assert installer invoked + bridge registered
- ToolRegistry typed getters ToolError without match= (tools.py:~300) :: pytest.raises(ToolError) without match= is forbidden pattern in test_tools.py:117,127,132,137,148,157 :: missing: add match=r"_ERR_BRIDGE_NA|not registered"
- RustTransformNode invalid params (transform_pipeline.py:~650) :: invalid hex string and out-of-range not tested :: missing: process(data, {"key":"not_hex"}) assert TransformParamError
- RegexReplaceNode str type replacement (transform_pipeline.py:~400) :: str replacement path untested :: missing: process(data, {"pattern": b"MZ", "replacement": "XX"}) assert correct behavior
- ConfirmationLevel enum values (types.py:~800) :: no .value assertion :: missing: ConfirmationLevel.DESTRUCTIVE.value=="destructive" etc.
- ToolChoiceMode enum values (types.py:~820) :: only AUTO wire-format indirect; REQUIRED/SPECIFIC/NONE values unasserted :: missing: direct .value assertions for all members
- _relaunch_elevated (elevation.py:~130) :: requires UAC dialog; structural constraint; acceptable gap
- build_execute_command r2/Cutter (script_gen.py:~600) :: R2_COMMANDS path untested :: missing: build_execute_command(r2_script, None); assert cmd[0] is rizin/cutter
- TemplateBootstrapError (template_manager.py:~30) :: exception never raised in test suite :: missing: read-only patterns_dir + bootstrap_builtins(); assert TemplateBootstrapError
- SHA1 IOC extraction (analysis.py) :: 40-char hex path not tested :: missing: file path with SHA1-format stem; assert ioc_type=="sha1"
- generate_timeline resource category (analysis.py) :: resource category absent :: missing: ResourceSample in report + generate_timeline(); assert category=="resource"
- _StateTracker clears last_error on success (sandbox_bridge.py) :: only mock-backed clear test :: missing: InMemorySandbox subclass raises first call; assert last_error is None after second success
- tests/test_bridges/test_sandbox_bridge.py FAKE GATE (entire file) :: AsyncMock/MagicMock/patch.object on the operations being tested; delete/rewrite required
- _ppm_p6_to_png/_parse_ppm_p6 (qemu.py) :: zero test coverage :: missing: minimal PPM P6 bytes; assert output starts with \x89PNG\r\n\x1a\n; malformed header asserts SandboxError
- QEMU PCAP tshark (qemu.py) :: no real tshark invocation :: missing: start + wait + stop; assert pcap file exists and non-empty
- QEMU memory dump process path (qemu.py) :: precondition-only test :: missing: guest-agent dump invocation; assert dump file at expected path
- _collect_logs missing-file/partial-read (qemu.py) :: happy-path only :: missing: one missing + one valid log; assert partial read succeeds without raising
```
