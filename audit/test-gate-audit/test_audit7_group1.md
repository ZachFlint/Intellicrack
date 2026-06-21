# Test-Gate Audit — test_audit7 (group 1: sandbox qemu/windows/monitors/manager)

## Summary
- Files audited: 13 (8 with tests; 5 `__init__.py`/conftest enumerated)
- Test functions examined: 78 (parametrized counted once per function)
- Genuine gates: 73
- Flagged non-gates: 5  (CRITICAL: 0, HIGH: 0, MEDIUM: 5, LOW: 0)

## Coverage checklist
- [x] tests/test_audit7/__init__.py — gates: 0, flagged: 0 (empty package marker)
- [x] tests/test_audit7/sandbox_qemu/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit7/sandbox_qemu/test_anti_evasion_profile.py — gates: 2, flagged: 0
- [x] tests/test_audit7/sandbox_qemu/test_logs_stable.py — gates: 4, flagged: 0
- [x] tests/test_audit7/sandbox_qemu/test_extract_dropped_files.py — gates: 6, flagged: 0
- [x] tests/test_audit7/sandbox_qemu/test_guest_agent_bootstrap.py — gates: 6, flagged: 0
- [x] tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py — gates: 9, flagged: 0
- [x] tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py — gates: 17, flagged: 3
- [x] tests/test_audit7/sandbox_windows/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit7/sandbox_windows/test_anti_evasion_wmi_hijack.py — gates: 10, flagged: 1
- [x] tests/test_audit7/sandbox_windows/test_launch_failure_detection.py — gates: 10, flagged: 0
- [x] tests/test_audit7/sandbox_windows/test_realcov_12b_inline_monitors.py — gates: 4, flagged: 0
- [x] tests/test_audit7/sandbox_windows/test_memory_dump_target_pid.py — gates: 22, flagged: 0
- [x] tests/test_audit7/sandbox_monitors/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit7/sandbox_monitors/conftest.py — gates: 0, flagged: 0 (fixtures/hooks only)
- [x] tests/test_audit7/sandbox_monitors/test_dll_log_parser.py — gates: 5, flagged: 0
- [x] tests/test_audit7/sandbox_monitors/test_stop_event.py — gates: 7, flagged: 1
- [x] tests/test_audit7/sandbox_manager/__init__.py — gates: 0, flagged: 0
- [x] tests/test_audit7/sandbox_manager/test_eviction_deadlock.py — gates: 2, flagged: 0
- [x] tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py — gates: 9, flagged: 0

## Flagged tests

### tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py
#### `test_qemu_source_awaits_agent_connect` — MEDIUM — Log/string-presence proxy (N9)
- **Location:** tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:560
- **Current behavior:** Reads `qemu.py` as text and asserts the substrings `agent.connect(time_limit=` and `_ensure_agent_connected(` are present in the source file.
- **Why it is not a gate:** This asserts the presence of a literal string in the production source, not the runtime behavior. A refactor that renames the helper, splits the call across lines, or routes the connect through a differently-named wrapper would break the real behavior yet could still keep (or lose) the substring without correlation to correctness. Conversely the substring could exist inside a comment or dead branch and still pass. The behavioral gate already exists in the same file (`test_agent_connect_invoked_during_start`, which drives the real connect end-to-end), making this a redundant text proxy.
- **Recommended fix:** Delete this test in favour of the real integration gate, or replace the string scan with an `ast`-based assertion that the call is reachable from `start()`. The end-to-end behavior is already covered by `TestAgentConnectInvokedDuringStart`, so the strongest fix is removal.

#### `test_attach_qemu_agents_forwards_agent_connect_timeout_not_hardcoded` — MEDIUM — Log/string-presence proxy (N9)
- **Location:** tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:580
- **Current behavior:** Reads `qemu.py` as text and asserts the substring `self._qemu_config.agent_connect_timeout` appears anywhere in the file.
- **Why it is not a gate:** Substring presence does not prove the value is forwarded to `_ensure_agent_connected`. The same property is already exercised behaviorally and far more strongly by `test_attach_qemu_agents_uses_configured_timeout_not_hardcoded` (line 477), which sets `agent_connect_timeout=0.0` against a live server and proves the configured timeout is actually used (a hardcoded positive timeout would make connect succeed and flip the test red). A reference to the attribute that does not actually reach the connect call would still satisfy this string check.
- **Recommended fix:** Remove this test; the behavioral discriminator at line 477 fully covers the forwarding requirement.

#### `test_attach_qemu_agents_creates_guest_agent_client` — MEDIUM — Log/string-presence proxy (N9)
- **Location:** tests/test_audit7/sandbox_qemu/test_start_calls_agent_connect.py:595
- **Current behavior:** Reads `qemu.py` as text and asserts `GuestAgentClient(port=` is present in the source.
- **Why it is not a gate:** The same file already proves at runtime that `_attach_qemu_agents` constructs a `GuestAgentClient` bound to the configured port and connects it (`test_agent_host_and_port_match_config`, line 652, and `test_agent_property_is_guest_agent_client_after_attach`, line 627). A keyword-argument style change (`GuestAgentClient(host=..., port=...)` reordered, or built via a factory) could break this brittle string match without any behavioral regression, and a string in a comment would satisfy it. It gates source spelling, not the bridge construction it names.
- **Recommended fix:** Remove this test; instance construction and port binding are already gated behaviorally by the integration tests in the same module.

### tests/test_audit7/sandbox_windows/test_anti_evasion_wmi_hijack.py
#### `test_mof_text_is_well_formed_for_each_profile` — MEDIUM — Existence-only / weak structural check (N8)
- **Location:** tests/test_audit7/sandbox_windows/test_anti_evasion_wmi_hijack.py:432
- **Current behavior:** For each profile, builds the MOF and asserts it starts with `#pragma autorecover`, contains `#pragma namespace`, has exactly three `instance of` and three `#pragma deleteclass` occurrences, then writes the text to a temp file and asserts the round-trip read equals what was written.
- **Why it is not a gate:** The docstring labels it a "smoke check". It validates pragma/section *counts* and shape but never asserts any spoofed identity value reaches the MOF (manufacturer, model, BIOS), which is the actual F-0013 behavior. The temp-file round-trip asserts that Python file I/O preserves bytes — it tests the filesystem, not the production code. A regression that emitted the right structural pragmas with empty or wrong identity strings would still pass. The strong identity gates exist in the sibling tests (`test_workstation_profile_mof_contains_dell`, etc.), so this one only weakly gates structure.
- **Recommended fix:** Drop the filesystem round-trip assertion (it gates nothing in production), and add per-profile assertions that the generated MOF carries the exact expected `Manufacturer`/`Model`/BIOS values (reuse `_extract_mof_identity` and compare against an independent expected mapping), turning the structural smoke check into a real value gate.

### tests/test_audit7/sandbox_monitors/test_stop_event.py
#### `test_start_monitors_skips_underscore_prefixed_scripts` — MEDIUM — Log/string-presence proxy (N9)
- **Location:** tests/test_audit7/sandbox_monitors/test_stop_event.py:140
- **Current behavior:** Reads `start_monitors.cmd` as text and asserts the substrings `%SCRIPT_NAME:~0,1%"=="_"` and `goto :eof` are present.
- **Why it is not a gate:** This asserts a specific cmd-script spelling exists in the source, not that the launcher actually skips underscore-prefixed helper scripts at runtime. A functionally equivalent filter written differently (e.g. a different variable-substring expression, an `if exist` guard, a different skip target) would correctly preserve the behavior yet fail this string match; conversely the literal could appear in a comment and pass while the real control flow is broken. The other source-guard tests in this file (e.g. `test_monitor_opens_named_stop_event`) at least assert a named function the four monitors all share, but this one pins one implementation detail of a single .cmd file. (Note: this is not flagged N3 — it runs on all platforms and is not skip-masked.)
- **Recommended fix:** Replace with a behavioral check that runs `start_monitors.cmd` against a scratch scripts dir containing an `_helper.ps1` and a real monitor, then asserts the helper was not launched (no PID/lifecycle for it) while the monitor was. If a full cmd run is impractical here, keep the test but assert the observable outcome rather than the literal source expression.

## Acceptable skips (not flagged)
- tests/test_audit7/sandbox_windows/test_realcov_12b_inline_monitors.py:85 module-level `skipif sys.platform != "win32"` — the inline monitors call `Win32_Process`/`Get-NetTCPConnection`; non-Windows cannot exercise the live kernel. Legitimate environment-capability skip.
- tests/test_audit7/sandbox_windows/test_realcov_12b_inline_monitors.py:101 `_resolve_pwsh` skip when `pwsh` absent — tool-availability environment skip, not a skip of the thing under test (the parser/monitor logic). Legitimate.
- tests/test_audit7/sandbox_windows/test_realcov_12b_inline_monitors.py:116 `_resolve_watched_marker` skip when `C:\Windows\Temp` missing — environment precondition. Legitimate.
- tests/test_audit7/sandbox_windows/test_realcov_12b_inline_monitors.py:339 `test_network_monitor_source_captures_live_endpoints` TCP-absent skip — guarded skip only after protocol/port range/direction assertions on every real record have already run; mirrors the documented network-isolated-host limitation of `Get-NetTCPConnection` (loopback not surfaced). The core normalisation behavior is still asserted; only the host-dependent TCP-presence sub-assertion is conditionally skipped. Acceptable.
- tests/test_audit7/sandbox_windows/test_realcov_12b_inline_monitors.py:384 `test_file_monitor_source_captures_real_filesystem_event` no-events skip — `FileSystemWatcher` latency is genuinely non-deterministic; the skip only triggers when zero events were captured, and all real-path/operation assertions run when events exist. Acceptable environment-timing skip.
- tests/test_audit7/sandbox_monitors/test_stop_event.py:75/87 `_resolve_pwsh`/`_resolve_cmd` skips — tool-availability for the Windows-only integration tests. Legitimate.
- tests/test_audit7/sandbox_monitors/test_stop_event.py:214 `_WINDOWS_ONLY` marker on the three integration tests — named Win32 events + pwsh required; non-Windows cannot run them. The source-level guards covering the same scripts run on every platform. Legitimate.
- tests/test_audit7/sandbox_manager/test_realcov_12a_manager_real.py:213/238/329 `spawns_process` marked real-probe tests — these probe the genuine host for QEMU and compare against an independent direct probe (no masking skip); they do not skip on the capability under test. Acceptable.

## Notes on mock/monkeypatch usage that is NOT flagged
- `test_launch_failure_detection.py` uses `MagicMock`/`AsyncMock`/`monkeypatch`, but the unit under test always runs real: `_check_startup_health` and the dialog-text classifier `_is_sandbox_failure_text` execute unmodified; only the OS screen-scrape (`_detect_client_failure_dialog`) and unrelated `start()` internals (`_start_impl`, `_abort_client`, `_cleanup`) are substituted. These are not N5 (the substituted pieces are not the behavior being asserted) and the error-propagation/classification behavior would fail if regressed.
- The `_RecordingAgent`/`_RecordingSandbox`/`_FakeSandbox`/`_FakeQMPClient` subclasses across the QEMU and Windows files replace only the external-tool transport (QEMU process, Windows Sandbox dispatcher, TCP), not the production method under test (`apply_anti_evasion`, `dump_memory`, `extract_dropped_files`, `SandboxManager.create`). Assertions are on production-generated artifacts (reg.exe argv, SMBIOS launch args, MOF identity, minidump ProcessId bytes, eviction state), so they are genuine gates.
- `test_memory_dump_target_pid.py::test_minidump_pid_field_distinguishes_target_from_host` explicitly constructs a buggy-vs-fixed discriminator proving the test can fail — exemplary falsifiability, genuine gate.
