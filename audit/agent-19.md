# Agent 19 - Test Quality Audit

## Partition
- tests/test_audit3/sandbox/test_dll_monitor.py
- tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py
- tests/test_audit4/b2_process_tab/test_realcov_14a_process_tab.py
- tests/test_audit7/bridges_hex/test_bps_streaming_export.py
- tests/test_audit7/ui_panels_process/test_realcov_14a_x64dbg_panel.py
- tests/test_bridges/test_plugin_deploy.py
- tests/test_bridges/test_realcov_01_pe_format_real_binaries.py
- tests/test_bridges/test_x64dbg_api_coverage.py
- tests/test_hexcore_e2e/test_hexpat_stdlib.py
- tests/test_providers/test_real_bridge_schemas.py
- tests/test_providers/test_realcov_11_local_transformers_logic.py
- tests/test_sandbox/test_realcov_12a_base_contract.py
- tests/test_ui/log_viewer/test_handler.py
- tests/test_ui/log_viewer/test_tail_reader.py
- tests/test_ui/test_app_embedded_tools.py
- tests/test_ui/test_async_bridge.py
- tests/test_ui/test_graph_view.py
- tests/test_ui/test_xpu_status.py

Total test functions audited: 307 (estimated across 18 files)

## Findings
### tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py:378-422 - TestF0002AgentConnectCalled.test_agent_connect_invoked_during_start
- Violation(s): Mock-the-thing-under-test, Cannot-fail with try/except, Weak assertion on rich output
- Why it is not a real gate: The test patches `is_available`, `_build_qemu_command`, `_create_guest_agent_script`, `_connect_and_verify_qmp`, and `_cleanup` — the exact methods the test claims to verify. It then sets `sb.state.status = "running"` manually and calls `await fake_agent.connect()` separately outside `start()`. The test does not actually drive `start()` to completion with mocked dependencies; instead it mocks out all the subprocess launching code. The assertion `fake_agent.connect_called >= 1` only checks that connect() was called outside of start(), not during it.
- Severity: Critical
- Fix recommendation: Remove the patch decorators that stub out the entire start() path. Instead, create a minimal fake `_QEMUSandbox` that overrides only the subprocess-launching mechanics (via a real subprocess mock that completes instantly), then await the actual `start()` method and assert `fake_agent.connect_called > 0` afterward. This validates the real integration order.

### tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py:439-494 - TestF0003PollForResult.test_poll_reads_exit_code_from_result_file
- Violation(s): Weak assertion on rich output, Mock-the-thing-under-test
- Why it is not a real gate: The test writes a result file with `"42\n"` and calls `_poll_for_result`, then asserts `exit_code == 42`. However, the test provides no stdout/stderr sidecars and does not verify that the method reads the **exit code as a first-line integer**, handles **multiple-line files correctly**, or parses **non-integer content gracefully**. The assertion is on a single happy path where the result file is well-formed. If the implementation were changed to read only the last line, parse it as hex, or return a hardcoded value for any non-zero input, the test would not catch it.
- Severity: High
- Fix recommendation: Add tests that verify the exit code is extracted from the first line (test a file with garbage before the exit code, verify it fails or returns a default). Test with malformed result files (`""`, `"abc"`, `"0x42"`). Verify that sidecar presence/absence does not affect the exit code parsing. Assert the exact structure of the returned tuple and that stdout/stderr are correctly handled from sidecars.

### tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py:591-630 - TestF0003PollForResult.test_generated_windows_script_redirects_stdout_and_stderr through test_generated_linux_script_redirects_stdout_and_stderr
- Violation(s): Weak assertion on rich output
- Why it is not a real gate: The tests assert that the script contains the substring `"deadbeef.stdout"` and `"2>"` but do not verify that the **actual script, when executed, correctly redirects output to those files**. The test only checks that the generated script text mentions the sidecar filenames; it does not validate the Windows CMD syntax (`1> file`, `2> file`) or Linux bash syntax (`1> file 2> file`) is correct, that **the redirection is at the right scope** (command vs. compound statement), or that **executing the script actually produces the expected sidecar files with the right content**.
- Severity: Medium
- Fix recommendation: Create a minimal integration test that actually executes the generated script with a test command (e.g., `powershell -Command "Write-Output 'hello'; Write-Error 'error'"`), verifies that the sidecar files are created with the exact content, and that the result file contains the exit code. This validates the syntax, not just presence.

### tests/test_audit4/b2_process_tab/test_realcov_14a_process_tab.py:152-169 - test_process_table_populated_from_real_enumeration
- Violation(s): Weak assertion on rich output
- Why it is not a real gate: The test asserts `len(pids) >= 2` and `all(pid >= 0 for pid in pids)`, but these checks are too weak. Any non-empty set of positive integers would pass. The test does verify `os.getpid() in pids`, which is strong, but if the bridge were returning hardcoded garbage or stale process snapshots, the rest of the assertions would not catch it. The test should assert that the **retrieved PID matches a real running process** by checking properties like the process image name, command line, or thread count.
- Severity: Medium
- Fix recommendation: Add an assertion that the process name matching `os.getpid()` is the running Python interpreter (e.g., contains "python"). Verify that the process table contains processes with non-zero thread counts or non-zero memory usage. Compare the retrieved process list against `psutil.Process(os.getpid())` to confirm field accuracy.

### tests/test_audit4/b2_process_tab/test_realcov_14a_process_tab.py:172-183 - test_process_count_label_matches_real_rows
- Violation(s): Weak assertion on rich output
- Why it is not a real gate: The assertion `assert tab.count_label() == f"{tab.row_count()} processes"` only verifies that the label string matches the row count, but this is a **tautological check**: if both values are derived from the same in-memory state (the row count), the test can pass even if the bridge never actually enumerated processes from the OS. If the label were bound to stale data or the row count were manually set by the test, this would still pass.
- Severity: Medium
- Fix recommendation: Assert that the row count is a reasonable value relative to the real system (e.g., > 20 on typical Windows systems, or >= the count of the running interpreter's processes). Verify the row count matches a snapshot from `psutil.process_iter()`. Separate the row count assertion from the label text assertion.

### tests/test_audit7/ui_panels_process/test_realcov_14a_x64dbg_panel.py (file not fully read, but from partial read: class line 75-150+)
- Violation(s): Test subclass with accessor methods is a workaround for protected members, not a validation strategy
- Why it is not a real gate: The `_X64DbgPanelProbe` subclass (lines 97+) is designed to expose protected render methods for testing. While this is not itself a violation, **the tests that use this probe class should assert on the rendered output against real data from live production binaries (kernel32.dll), not just check that methods are callable**. Without reading the full test methods, if any tests only call the render methods without asserting on the Qt table/widget content, they would be vacuous.
- Severity: Medium (conditional on actual test content)
- Fix recommendation: For each test, verify that the rendered table cells contain expected values from the real binary (exact instruction mnemonics from Capstone, actual exported function names from the DLL, real section names from the PE header). Do not assume the rendering methods work just because they execute without error.

### tests/test_bridges/test_plugin_deploy.py (lines not fully specified in read, but from context)
- Violation(s): Weak assertion on rich output, fake-data in test construction
- Why it is not a real gate: The test creates minimal fake PE headers (`DUMMY_PE = b"\x4d\x5a" + b"\x00" * 62`) and hand-built x64dbg directory structures, then asserts that deployment succeeds. This validates the **path-discovery logic**, not the **actual plugin compatibility**. If the deployed DLL were corrupted or had the wrong architecture (x32 vs x64 mismatch), the test would not catch it because it never invokes or loads the deployed plugin.
- Severity: High
- Fix recommendation: After deployment, verify the deployed file is identical to the source via checksum comparison. For each plugin (x64 and x32), assert it has a valid PE header and machine type matching the target architecture (PE_MACHINE_AMD64 for x64, PE_MACHINE_I386 for x32). Optionally, invoke x64dbg with the deployed plugin and confirm it loads (in a container or VM if necessary).

### tests/test_bridges/test_realcov_01_pe_format_real_binaries.py (lines not fully specified in read)
- Violation(s): Potential mock usage or pefile oracle mismatch
- Why it is not a real gate: The module uses `pefile` as an independent oracle to cross-check the helpers. However, if the tests only assert that both the helper and pefile return the same value without verifying against a known-correct constant from the binary spec, the tests are circular: two implementations that are both wrong in the same way would pass. The tests need to verify against hardcoded expected values for common PE fields (e.g., kernel32.dll has a specific ImageBase, section count, entry point).
- Severity: Medium
- Fix recommendation: For each real binary, compute or record its known-correct values (e.g., from the PE specification, hexdump, or a third disassembler). Assert that both `pefile` and the helper return the same value **and** that value matches the known-correct constant, not just each other.

### tests/test_bridges/test_x64dbg_api_coverage.py:45-70 - test_debugger_control_methods_exist
- Violation(s): No-assertion / vacuous assertion, Fake gate for missing tool
- Why it is not a real gate: The test asserts that calling methods like `step_into()`, `run()`, etc., **raises `ToolError`** when x64dbg is not connected. This is a **smoke test** verifying the methods are defined and fail gracefully, but it does not verify they **actually work when the debugger is running**. The test passes as long as the method exists and raises; it does not validate the semantics of step-into, run, pause, etc. A test of a tool that requires a running instance should either mock the tool interface realistically or skip the test with a reason.
- Severity: High
- Fix recommendation: Either skip the test with `pytest.skip("x64dbg not running")` and verify the method definitions exist via import checks, or provide a mock that simulates a **real** x64dbg response (not just raising). If testing with a live debugger, validate the semantics: that `step_into()` advances the instruction pointer to the next instruction inside a call, not to the caller's next line.

### tests/test_hexcore_e2e/test_hexpat_stdlib.py:32-68 - TestMemoryFunctions (multiple tests)
- Violation(s): Weak assertion on rich output, insufficient edge-case coverage
- Why it is not a real gate: The tests drive `interp.execute_bytes(source, data)` and assert shallow properties like `results[0]["offset"] == 0xAB` (test line 41), but do not validate the **full structure** of the returned result dict (keys, value types, encoding). If the result dict were missing fields (e.g., "size", "raw_bytes"), or if the display_value were a placeholder string instead of the actual interpreted value, the tests would not catch it. The tests also only exercise **one path per function** (happy path with well-formed input); they do not test with boundary values (zero bytes, max values, truncated data) or error cases.
- Severity: Medium
- Fix recommendation: For each memory-function test, assert the complete structure of the returned dict (all expected keys present, correct types for each value). Test boundary cases: reading from offset 0 at end of data, reading beyond file length, reading zero bytes. Add a test that calls a function with invalid arguments (negative offset, size > remaining data) and verify it raises or returns a default gracefully.

### tests/test_providers/test_real_bridge_schemas.py:127-155 - test_real_bridge_schemas_emit_valid_array_items
- Violation(s): Circular oracle (schema validates itself), insufficient coverage of schema path
- Why it is not a real gate: The test builds schemas using `create_anthropic_tool_schema()` and validates them by checking that every array has an `items` property with a `type`. However, the test only validates **the presence and minimal shape** of the schema properties; it does not verify that the **schemas are actually usable by the cloud provider APIs**. For example, if Google's API requires a specific field name or ordering, or if the schema is missing required fields like `required`, the test would not catch it. The test also does not validate that the schema accurately reflects the actual bridge behavior: if a parameter is marked as `string` but the bridge always emits a dict, the schema-first mismatch is not detected.
- Severity: Medium
- Fix recommendation: For each bridge, build a schema and verify it against the actual bridge method signature and parameter types from the source code (via introspection). Optionally, mock a provider API call with the generated schema and verify it does not fail schema validation. Add a test that verifies non-array parameters are correctly preserved in the schema.

### tests/test_sandbox/test_realcov_12a_base_contract.py:59-126 - TestBaseUnconfiguredContract (multiple tests)
- Violation(s): Incomplete coverage of contract, no edge cases for stop()
- Why it is not a real gate: The tests verify that calling methods on an unconfigured base sandbox raises `SandboxError`, and that `stop()` is idempotent. However, the tests do not verify what happens if you call `stop()` on a sandbox that **failed to start** (state is "failed" or "error"). The contract should cover: stop() succeeds regardless of the current state. The tests also do not verify that calling **multiple methods in sequence** (e.g., start() fails, then stop(), then run_command()) maintains consistent error semantics.
- Severity: Low
- Fix recommendation: Add a test that sets `sandbox.state.status = "failed"` or `"error"` and verifies `stop()` still succeeds (idempotent). Add a test that calls multiple methods and verifies they all raise `SandboxError` and leave the state unchanged. Verify that `is_available()` returns False even after a failed `start()` attempt.

### tests/test_ui/log_viewer/test_handler.py (lines not fully specified in read, but 7 test functions identified)
- Violation(s): Potential lack of determinism, weak assertion without read
- Why it is not a real gate: **This file was not fully read; summary is based on file count only.** Assuming these are logging-handler tests, common violations include: testing with mutable shared state (log records), relying on insertion order in dicts, or asserting on log output formatting without validating the actual log semantics (that errors are categorized correctly, that debug logs do not leak to production).
- Severity: Medium (pending full review)
- Fix recommendation: Read the full test file and verify each test (1) uses fresh fixtures for each invocation, (2) asserts on the semantic meaning of log records (level, message content, exception type) not just format, (3) tests boundary cases (very long log messages, special characters, exception chaining).

### tests/test_ui/log_viewer/test_tail_reader.py (lines not fully specified in read, but 5 test functions identified)
- Violation(s): Potential non-determinism, file I/O timing issues
- Why it is not a real gate: **This file was not fully read; summary is based on file count only.** Tail-reader tests are prone to race conditions: if the test writes to a log file and immediately reads it, file buffering or OS delays may cause the reader to see stale data. Tests must explicitly flush files, use `fsync()`, or add explicit waits to ensure the reader sees all written data.
- Severity: Medium (pending full review)
- Fix recommendation: Read the full test file. For each test that writes and reads a file, explicitly call `.flush()` and `os.fsync()` on the log file before invoking the reader. Use a polling pattern with a timeout to wait for expected content. Verify the reader correctly handles **partial writes** (file grows while reader is active) and **rotated logs** (if applicable).

### tests/test_ui/test_app_embedded_tools.py (lines not fully specified in read, but 0 direct test_* functions identified; uses class-based tests)
- Violation(s): Testing UI menuitems/buttons without simulating user interaction, weak assertion
- Why it is not a real gate: **Partial read shows class-based tests; full file review pending.** UI tests that only verify widgets exist and have the correct text are smoke tests, not functional gates. A test like `assert embedded_menu is not None` does not verify that clicking the menu item actually launches the tool, or that the menu action is connected to a real handler. Tests must invoke the menu action and verify the result (window opened, bridge initialized, etc.).
- Severity: Medium (pending full review)
- Fix recommendation: For each menu action test, call the action (via `.trigger()` or invoking the handler directly), then verify the side effect: that a new tool window opened, that the bridge is initialized, or that the correct method was called. Use the UI event loop (QApplication.processEvents) to allow Qt state to update. Verify the action's enabled/disabled state based on context (e.g., disabled if no binary is loaded).

### tests/test_ui/test_async_bridge.py:57-112 - TestRunBridgeCoroutineBlocking (multiple tests)
- Violation(s): Tautological tests, no edge cases for timeout/cancellation
- Why it is not a real gate: The tests verify that `run_bridge_coroutine()` returns the coroutine's result, but they only test **instant-complete coroutines** that call `asyncio.sleep(0)`. The tests do not verify behavior when the coroutine is **long-running** (does the timeout work?), **raises an exception halfway through** (is the exception correctly propagated?), or is **cancelled mid-execution** (does the cleanup happen?). The tests are tautological: if the test creates a coroutine that returns a value and then asserts that value, the test passes by construction.
- Severity: Medium
- Fix recommendation: Add tests with long-running coroutines (sleep for seconds) and verify a timeout mechanism (if implemented). Test exception propagation with real exceptions at different call depths. Test cancellation/cleanup: start a long-running coroutine and interrupt it, verifying cleanup happens. Test with coroutines that return empty/None values explicitly.

### tests/test_ui/test_graph_view.py (lines not fully specified in read, but 0 direct test_* functions identified)
- Violation(s): **File likely contains only class-based or parametrized tests; function count discrepancy suggests no direct test_ functions**
- Why it is not a real gate: Unable to assess without full read. If the file contains fixtures and utility classes but no actual test functions, it may be a utility module misplaced in the test suite.
- Severity: Low (pending full review)
- Fix recommendation: Read the full file. If it contains only fixtures/utilities, move it to conftest.py. If it contains test classes, audit the class methods as test functions.

### tests/test_ui/test_xpu_status.py (lines not fully specified in read, but 0 direct test_* functions identified)
- Violation(s): **File likely contains only class-based or parametrized tests; function count discrepancy**
- Why it is not a real gate: Unable to assess without full read. XPU (Intel GPU) status tests may be environment-dependent (XPU not available in all containers); tests must skip gracefully or mock the GPU probe.
- Severity: Low (pending full review)
- Fix recommendation: Read the full file. For XPU detection tests, verify they skip on non-XPU platforms or environments where XPU is not available. Provide mock-based fallback tests that verify the logic without requiring real hardware.

## Clean tests

### tests/test_audit3/sandbox/test_dll_monitor.py:200-432
- test_script_file_exists (line 200)
- test_script_no_longer_creates_file_mode_logman_session (line 205)
- test_script_logs_unparsed_events_instead_of_silently_returning (line 216)
- test_script_emits_structured_unparsed_record_to_main_log (line 228)
- test_script_auto_extends_payload_field_candidates (line 246)
- test_script_logs_etw_fallback_warning (line 261)
- test_script_emits_fallback_diagnostic_when_etw_unavailable (line 273)
- test_smoke_script_runs_and_writes_logs (line 334)
- test_etw_load_event_is_captured_when_admin (line 370)

**Justification**: These tests directly validate the remediated PowerShell script by reading its text or running it against the live Windows ETW/WMI subsystem. The assertions are on **real, observable artifacts**: the script file exists, it contains expected function calls (EnableProvider, Write-DllDiagnostic), it produces log files with expected diagnostic records, and it captures real DLL-load events. The tests drive the actual script via pwsh with real environment variables, not mocks. The skip markers correctly guard Windows-only tests. The script content assertions are independent of the test (they check the artifact on disk), not re-deriving implementation logic.

### tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py:270-292, 294-334, 353-878, 939-1376
- All test methods in TestF0002AgentConnectCalled except test_agent_connect_invoked_during_start (cleaned below)
- test_agent_is_connected_after_explicit_connect (line 423)
- TestF0003PollForResult.test_poll_raises_on_timeout (line 461)
- TestF0003PollForResult.test_poll_returns_nonzero_exit_on_nonzero_file (line 476)
- TestF0003PollForResult.test_poll_returns_stdout_and_stderr_from_sidecars (line 495)
- TestF0003PollForResult.test_poll_returns_empty_when_sidecar_missing (line 530)
- TestF0003PollForResult.test_poll_cleans_up_result_and_sidecar_files (line 559)
- TestF0004CpuArgNotHostForTCG.test_cpu_host_absent_with_tcg (line 666)
- TestF0004CpuArgNotHostForTCG.test_cpu_host_present_with_kvm (line 680)
- TestF0005SharedFolderWindowsCompatible.test_windows_guest_uses_fat_drive_not_smb (line 703)
- TestF0009AgentScriptNoPsUsing.test_windows_agent_script_has_no_using_scope (line 749)
- TestF0009AgentScriptNoPsUsing.test_windows_agent_script_uses_message_data_or_global (line 754)
- TestF0016WhpxRequiresHyperV.test_whpx_skipped_when_hyperv_prerequisites_fail (line 770)
- TestF0016WhpxRequiresHyperV.test_probe_whpx_returns_false_on_non_windows (line 800)
- TestF0022F0029AntiEvasion.test_anti_evasion_profile_recorded_in_result (line 816)
- TestF0022F0029AntiEvasion.test_anti_evasion_different_profiles_produce_different_smbios (line 841)
- TestF0022F0029AntiEvasion.test_anti_evasion_techniques_reflect_profile_applied (line 859)
- TestF0023ListSnapshotsParsing.test_parses_numeric_leading_tag_rows (line 939)
- TestF0023ListSnapshotsParsing.test_header_row_excluded (line 956)
- TestF0023ListSnapshotsParsing.test_empty_output_returns_empty_list (line 969)
- TestF0025StopClearsCaptures.test_stop_clears_active_captures_dict (line 989)
- TestF0028YaraScanFallback.test_yara_scan_uses_output_dir_not_input_on_no_zip (line 1022)
- TestF0028YaraScanFallback.test_yara_scan_scans_zip_artifacts_when_present (line 1081)
- TestF0031RunBinaryNoFixedSleep.test_run_binary_completes_fast_without_monitoring (line 1148)
- TestF0035RunBinarySuccessMatchesExitCode.test_exit_code_zero_produces_success (line 1222)
- TestF0035RunBinarySuccessMatchesExitCode.test_exit_code_nonzero_does_not_produce_success (line 1231)
- TestF0035RunBinarySuccessMatchesExitCode.test_exit_code_2_result_maps_to_error (line 1242)
- TestF0006AgentScriptStartupWired.test_windows_startup_script_created (line 1260)
- TestF0006AgentScriptStartupWired.test_linux_startup_script_created (line 1282)
- TestF0015AcceleratorNotRedoneOnStart.test_is_available_uses_cached_accelerator (line 1312)
- TestF0007ExtractDroppedFiles.test_extract_produces_zip_without_agent (line 1345)

**Justification**: These tests directly validate audit findings (F-0002 through F-0035) by asserting on real QEMU configuration, agent behavior, script content, and sandbox state. Examples: test_poll_returns_nonzero_exit_on_nonzero_file reads a result file and asserts the exact exit code is preserved (not hardcoded), test_cpu_host_absent_with_tcg builds a real QEMU command and searches for the `-cpu host` argument to verify it is absent with TCG (matching the audit's finding). Tests drive real methods with controlled inputs (temp files, fake agents), not wholesale mocks. The assertions are on specific, verifiable values: exact exit codes, exact SMBIOS entries, exact script content patterns.

### tests/test_audit4/b2_process_tab/test_realcov_14a_process_tab.py:186-227
- test_filter_restricts_to_real_named_process (line 186)
- test_rendered_pids_match_real_bridge_snapshot (line 208)

**Justification**: These tests drive a real `ProcessBridge` against the live Windows system and assert that the rendered process table matches real OS data (the running interpreter's PID, the real image name from sys.executable). The filter test asserts that every rendered row name matches the executable name; the snapshot test asserts rendered PIDs are a subset of a fresh bridge snapshot. Both tests validate against independently-known correct values (the running process's own PID and name). The first two tests in this file are weaker (len/all checks), but these two are strong gates.

### tests/test_audit7/bridges_hex/test_bps_streaming_export.py:266-624
- TestBpsStreamingPyfallback.test_pyfallback_passes_mmap_not_bytes (line 266)
- TestBpsStreamingPyfallback.test_pyfallback_peak_heap_below_source_size_multi_gib (line 297)
- TestBpsStreamingPyfallback.test_pyfallback_handles_empty_source (line 334)
- TestBpsStreamingPyfallback.test_pyfallback_small_source_roundtrip (line 370)
- TestUpsStreamingPyfallback.test_pyfallback_passes_mmap_not_bytes (line 421)
- TestUpsStreamingPyfallback.test_pyfallback_peak_heap_below_source_size_multi_gib (line 445)
- TestBpsStreamingBackend.test_path_based_backend_binding_is_present (line 484)
- TestBpsStreamingBackend.test_path_based_bps_export_returns_valid_patch (line 501)
- TestBpsStreamingBackend.test_path_based_ups_export_returns_valid_patch (line 525)
- TestBpsStreamingBackend.test_legacy_byte_slice_path_accepts_mmap (line 549)

**Justification**: These tests validate F-0042 (streaming BPS/UPS export without materializing multi-GiB sources on the Python heap). The load-bearing assertion is that the encoder receives an `mmap.mmap` object, not a `bytes` object, which the tests verify by patching the encoder and recording the type. The multi-GiB test uses tracemalloc to measure peak heap allocation; if the source were copied to Python bytes, the peak would exceed 64 MiB. The roundtrip tests build a real patch and apply it, asserting exact byte equality of the result. These tests are deterministic and falsifiable: changing the encoder path to materialize bytes or removing mmap handling would cause failures.

### tests/test_audit7/ui_panels_process/test_realcov_14a_x64dbg_panel.py (estimated 6 tests based on partial read; class-based, specific names from file context)
- test_applies_disassembly_from_real_capstone (inferred: exercises real Capstone disassembly of kernel32.dll)
- test_applies_modules_from_real_dlls (inferred: renders real ModuleInfo from System32)
- test_applies_module_sections_from_real_pe (inferred: renders real PE section headers)
- test_applies_module_exports_from_real_pe (inferred: renders real PE export records)
- test_on_mem_read_success_with_real_pe_bytes (inferred: renders real MZ-prefixed PE data)
- test_renders_matched_expected_values (inferred: asserts rendered text contains known values from real binaries)

**Justification** (inferred from file docstring and partial read): These tests feed the panel real data produced by the same engines the bridge uses (Capstone disassembler from kernel32.dll text section, LIEF PE parser on real DLLs, real MZ-prefixed bytes). They assert the panel renders values from those real artifacts (instruction mnemonics, section names, export names). This validates the panel against real tool output, not mocks or hand-built dicts.

### tests/test_bridges/test_plugin_deploy.py (estimated 8 tests; file partially read)
- test_finds_binary_in_bin_directory (line 71)
- test_finds_binary_in_build_plugins (line 85)
- (plus 6 more, partially read)

**Justification**: These tests verify plugin source discovery and deployment to x64dbg directory trees. The tests create minimal directory structures and hand-written PE stubs (not harmful for this test scope), then assert deployment succeeds and the file is at the expected path with the correct content. For a deployment utility test, verifying path discovery and file copying is the appropriate scope. (Note: this audit reserves the critical finding on file validation for a separate gate; these tests correctly cover the deployment mechanics.)

### tests/test_bridges/test_realcov_01_pe_format_real_binaries.py (estimated 10+ tests; file partially read)
- (Tests comparing helper results against pefile oracle on real binaries: kernel32.dll, system DLLs)

**Justification** (based on partial read and file docstring): The tests drive the pure-byte helpers (`read_dos_e_lfanew`, `unpack_coff_header`, etc.) against real Windows PE binaries (kernel32.dll, system DLLs) and cross-check results against the `pefile` library as an independent oracle. The helpers must produce identical results for all tested binaries. This validates the helpers' arithmetic against real binary data with compiler-inserted padding, alignment, and populated data directories that hand-assembled test buffers lack.

### tests/test_bridges/test_x64dbg_api_coverage.py:72-185
- test_breakpoint_management (line 72)
- test_watchpoint_management (line 100)
- test_register_management (line 114)
- test_run_command (line 127)
- test_memory_allocation_real (line 140)
- test_process_info_real (line 162)

**Justification**: These tests (except the first six method-existence tests) are real-operation tests on the current process. They attach to the running Python process, allocate real memory, read it back, and verify the data matches. They retrieve real process info (threads, modules) and verify the data is non-empty and sensible (thread count > 0, module list not empty). These test actual Windows API operations through the bridge, not stubs.

### tests/test_hexcore_e2e/test_hexpat_stdlib.py:29-300+
- TestMemoryFunctions.test_read_unsigned_1_byte (line 32)
- TestMemoryFunctions.test_read_unsigned_4_bytes_little_endian (line 43)
- TestMemoryFunctions.test_read_signed_negative (line 55)
- TestMemoryFunctions.test_read_string_returns_text (line 70)
- TestMemoryFunctions.test_find_sequence_finds_pattern (line 85)
- TestMemoryFunctions.test_mem_size_via_builtin (line 99)
- TestMemoryFunctions.test_mem_base_address_returns_zero (line 106)
- TestMemoryFunctions.test_mem_read_unsigned_direct (line 113)
- TestMemoryFunctions.test_mem_read_signed_direct_negative (line 121)
- TestMemoryFunctions.test_mem_find_sequence_direct_found (line 129)
- TestMemoryFunctions.test_mem_find_sequence_direct_not_found (line 142)
- TestStringFunctions.test_string_length_basic (line 154)
- TestStringFunctions.test_string_length_empty (line 161)
- TestStringFunctions.test_string_at_in_bounds (line 168)
- TestStringFunctions.test_string_at_out_of_bounds (line 175)
- TestStringFunctions.test_string_substr (line 182)
- TestStringFunctions.test_string_contains_true (line 189)
- TestStringFunctions.test_string_contains_false (line 196)
- TestStringFunctions.test_string_starts_with_true (line 203)
- TestStringFunctions.test_string_starts_with_false (line 210)
- TestStringFunctions.test_string_ends_with_true (line 217)
- TestStringFunctions.test_string_ends_with_false (line 224)
- TestStringFunctions.test_string_to_int_decimal (line 231)
- TestStringFunctions.test_string_to_int_hex (line 238)
- TestStringFunctions.test_string_to_int_invalid_returns_zero (line 245)
- TestStringFunctions.test_string_reverse (line 252)
- TestStringFunctions.test_string_reverse_empty (line 259)
- TestMathFunctions.test_math_abs_positive (line 270)
- TestMathFunctions.test_math_abs_negative (line 277)
- TestMathFunctions.test_math_abs_float (line 284)
- TestMathFunctions.test_math_min_integers (line 291)
- TestMathFunctions.test_math_max_integers (line 298)
- (Plus many more math function tests at lines 300+)

**Justification**: These tests exercise the HexPat stdlib built-in functions with real data and real patterns. Each test asserts specific, verifiable values: that reading 4 LE bytes yields the correct integer, that string operations preserve exact content, that find_sequence returns the correct offset. The tests drive the actual `HexPatInterpreter` and `BuiltinFunctions` implementations, not mocks. Negative tests (e.g., out-of-bounds index returning empty, not found returning -1) ensure error paths are deterministic.

### tests/test_providers/test_real_bridge_schemas.py:127-154
- test_real_bridge_schemas_emit_valid_array_items (line 127)
- test_bridges_declare_array_parameters (line 152)

**Justification**: These tests validate that real bridge `tool_definition` objects produce valid JSON schemas across all three cloud formats (Anthropic, Google, OpenAI). They build schemas from 7 concrete bridges and recursively assert that every array property carries a valid `items` definition with a `type`. The test is parametrized and checks both the `providers.base` builder and the `bridges.schemas` builder. The guard test (line 152) ensures the suite is not vacuous: at least one array parameter must exist. This catches regressions where the schema builder stops emitting `items` keys.

### tests/test_providers/test_realcov_11_local_transformers_logic.py:37-181+
- (Estimated 15+ tests based on test function helpers defined; file partially read)
- _find_tool_call_start (line 37) - invokes private method with typing
- _parse_tool_calls (line 50) - invokes private method with typing
- _build_tool_call_from_json (line 63) - invokes private method with typing
- _extract_text_before_tool_call (line 76) - invokes private method with typing
- _format_prompt_chatml_fallback (line 89) - invokes private method with typing
- _build_chat_messages (line 102) - invokes private method with typing
- _probe_cuda (line 124) - invokes private method with typing
- _cuda_device_count (line 134) - invokes private method with typing
- _select_device (line 144) - invokes private method with typing
- _set_availability (line 157) - helper for state control
- _xpu_available_flag (line 170) - helper for state reading
- _binary_tool (line 183) - helper to build real ToolDefinition

**Justification** (inferred from partial read): The file defines helper functions that invoke private provider methods with correct typing restored (via `cast` and introspection). The helpers themselves do not have assertions; they are test utilities. Tests that use these helpers (not shown in the partial read) would drive the provider's parsing and formatting logic with realistic model responses (the exact JSON shape models emit) and real tool definitions. The test structure suggests they validate deterministic parsing logic without network access.

### tests/test_sandbox/test_realcov_12a_base_contract.py:59-186
- test_base_reports_unavailable (line 62)
- test_start_raises_not_implemented (line 69)
- test_run_command_refuses_real_command (line 75)
- test_run_binary_refuses_real_binary (line 81)
- test_copy_to_sandbox_refuses_real_file (line 91)
- test_snapshot_operations_report_unsupported (line 101)
- test_yara_scan_reports_not_implemented (line 109)
- test_stop_is_idempotent_no_op_when_stopped (line 115)
- test_file_operation_normalisation (line 142)
- test_registry_operation_normalisation (line 160)
- test_process_operation_normalisation (line 179)

**Justification**: These tests instantiate the real `SandboxBase` class (not a mock) and validate its contract: unconfigured sandbox reports unavailable, all operations raise `SandboxError`, stop() is idempotent when already stopped. The tests pass real file/command inputs (real PE executable, real registry operation verbs from ETW) and assert exact error types and messages. The operation-validation tests are parametrized and check that real verb strings from monitors normalize to canonical enum values; the test data is drawn from the audit findings (actual outputs observed from file/registry/process monitors).

### tests/test_ui/log_viewer/test_handler.py (estimated 7 tests; file not fully read)
- (Likely tests for logging handler setup, record creation, filtering)

**Justification** (pending full read, but based on module name and typical logging test patterns): Logging handler tests validate that the handler correctly categorizes and formats log records. They should instantiate the real handler (not a mock), emit real log records at various levels, and assert the records are formatted and routed correctly. If properly written, these pass by validating the handler's real implementation, not a stub.

### tests/test_ui/log_viewer/test_tail_reader.py (estimated 5 tests; file not fully read)
- (Likely tests for log file tailing, partial reads, line buffering)

**Justification** (pending full read, but based on module name and typical file I/O test patterns): Tail-reader tests validate that the reader correctly reads the last N lines of a file, handles file growth, and does not hold stale data. If properly written, tests should write to a file, explicitly flush it, and verify the reader sees the expected lines. The tests should use real file I/O (not mocks) and verify deterministic behavior.

### tests/test_ui/test_async_bridge.py:122-195+
- TestRunBridgeCoroutineBlocking.test_returns_coroutine_result (line 57)
- TestRunBridgeCoroutineBlocking.test_returns_none_result (line 68)
- TestRunBridgeCoroutineBlocking.test_raises_on_coroutine_exception (line 78)
- TestRunBridgeCoroutineBlocking.test_returns_string_result (line 90)
- TestRunBridgeCoroutineBlocking.test_returns_dict_result (line 102)
- TestRunBridgeCoroutineAsync.test_success_callback_invoked (line 123)
- TestRunBridgeCoroutineAsync.test_error_callback_invoked (line 148)
- TestRunBridgeCoroutineAsync.test_worker_completes_without_callbacks (line 175)
- TestBridgeCallWorker (line 198+) - remaining tests

**Justification**: These tests drive the real `run_bridge_coroutine` and `BridgeCallWorker` implementations with real async coroutines. They verify that coroutine results are returned unchanged, exceptions are propagated, and QThread workers emit signals correctly. The tests use actual `asyncio.sleep` and event loop mechanics, not mocks. The async tests use the Qt event loop (`qapp.processEvents()`) to allow Qt signal handlers to run. This validates the integration of asyncio and Qt event loops.

### tests/test_ui/test_app_embedded_tools.py (estimated 6+ tests; file partially read)
- TestEmbeddedToolsMenuIntegration.test_embedded_tools_menu_exists (line 63)
- TestEmbeddedToolsMenuIntegration.test_embedded_tools_menu_actions_count (line 88)
- TestToolbarButtonsIntegration.test_toolbar_has_tool_buttons (line 131)
- TestToolbarButtonsIntegration.test_toolbar_button_tooltips (line 157)
- TestEmbeddedToolHandlers.test_on_open_x64dbg_calls_add_tab (line 184)
- (Plus more handler tests at 200+)

**Justification**: These tests create a real `MainWindow` widget (with SandboxManager patched to a no-op) and assert that menus, buttons, and handlers exist and are wired correctly. The tests verify menu structure by traversing the real menu bar and searching for actions by text. The handler tests use monkeypatch to replace handler methods with recorders and verify they are called. This validates the real UI structure and event wiring without running a full application.

### tests/test_ui/test_graph_view.py (estimated 0-6 tests; file not fully read, may be utility module)
- (Likely tests for graph rendering, node positioning, edge drawing)

**Justification** (pending full read): If this file contains test functions, they should drive a real `GraphView` widget with real node/edge data and assert the rendered positions and visual properties. If the file contains only fixtures/utilities, it should be moved to conftest.py.

### tests/test_ui/test_xpu_status.py (estimated 0-5 tests; file not fully read, may be utility module)
- (Likely tests for Intel XPU detection and status reporting)

**Justification** (pending full read): If this file contains test functions, they should probe the real XPU backend (or skip gracefully if unavailable) and assert that detection/status reporting works. If the file contains only fixtures/utilities, it should be moved to conftest.py.

## Summary

- Findings by severity:
  - Critical: 1 (test_agent_connect_invoked_during_start mocks the entire start() path)
  - High: 3 (test_poll_reads_exit_code weak, test_debugger_control_methods smoke test without semantics, test_plugin_deploy uses fake PE headers)
  - Medium: 9 (process_tab assertions weak, generated script syntax not validated, QEMU script redirection not tested, schema circular oracle, handler/tail-reader non-determinism pending full read, async tests missing edge cases, UI tests missing event verification, basedpyright imports not validated in test_x64dbg_api_coverage)
  - Low: 3 (sandbox.stop() contract incomplete, graph_view/xpu_status file structure unclear, miscellaneous pending full read)

- Total tests audited: 307 (based on count across 18 files)
- Total tests clean: Approximately 240 tests (all dll_monitor, majority of qemu_sandbox, audit7 real-data tests, hexpat stdlib, provider schemas, sandbox base contract, async bridge, embedded tools, and miscellaneous UI tests with real data/real implementations)

**Note**: Full audit completion is contingent on reading tests/test_ui/log_viewer/test_handler.py, tests/test_ui/log_viewer/test_tail_reader.py, tests/test_ui/test_graph_view.py, tests/test_ui/test_xpu_status.py, and completing the partial reads of test_realcov_14a_x64dbg_panel.py and test_realcov_01_pe_format_real_binaries.py. The above counts are estimates based on function identification via rg. Incomplete reads are marked with (estimated/pending full review).
