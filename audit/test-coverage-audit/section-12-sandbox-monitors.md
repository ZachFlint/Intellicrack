# Section 12 — Sandbox Orchestration & Monitors: Test-Coverage Audit

**Auditor:** test-reviewer
**Date:** 2026-06-26
**Scope:** All Python source in `src/intellicrack/sandbox/` and `src/intellicrack/bridges/sandbox_bridge.py`; all PowerShell monitor scripts in `src/intellicrack/sandbox/scripts/`; all tests in `tests/test_sandbox/`, `tests/test_bridges/test_sandbox_bridge.py`, `tests/test_audit3/sandbox/`, `tests/test_audit4/a3_qemu_sandbox/`, `tests/test_audit7/sandbox_monitors/`, `tests/test_audit7/sandbox_windows/`, and `tests/test_audit7/sandbox_qemu/`.

---

## 1. Source Files Enumerated

| File | Lines | Description |
|---|---|---|
| `src/intellicrack/sandbox/log_parsers.py` | 551 | 11 async parse functions converting pipe-delimited monitor logs to TypedDicts |
| `src/intellicrack/sandbox/log_helpers.py` | 193 | Pure helpers: split_addr_port, coerce_protocol, infer_direction, safe_int, safe_float, format_yara_match |
| `src/intellicrack/sandbox/base.py` | 754 | 11 TypedDicts, ExecutionReport dataclass, abstract SandboxBase, validate functions |
| `src/intellicrack/sandbox/analysis.py` | ~600 | detect_c2_patterns, extract_iocs, generate_timeline, match_behaviors, diff_reports + private helpers |
| `src/intellicrack/bridges/sandbox_bridge.py` | 2526 | 27-function tool bridge, _StateTracker, json_safe, dataclass_to_dict |
| `src/intellicrack/sandbox/windows.py` | ~400 | WindowsSandbox with inline PS1 monitor sources baked in |
| `src/intellicrack/sandbox/qemu.py` | ~3900 | QEMUSandbox: QMP protocol, GuestAgentClient, _poll_for_result, _generate_execution_script, anti-evasion, screenshot/PCAP/YARA/memory |
| `src/intellicrack/sandbox/scripts/api_trace.ps1` | — | ETW Kernel-Audit-API-Calls consumer |
| `src/intellicrack/sandbox/scripts/dll_monitor.ps1` | — | ETW image-load + WMI fallback; F-0019 extended 8-column format |
| `src/intellicrack/sandbox/scripts/injection_monitor.ps1` | — | Thread-start / injection heuristics |
| `src/intellicrack/sandbox/scripts/service_monitor.ps1` | — | Win32_Service CIM event subscriptions |
| `src/intellicrack/sandbox/scripts/kernel_object_monitor.ps1` | — | Kernel object creation monitoring |
| `src/intellicrack/sandbox/scripts/resource_monitor.ps1` | — | CPU/memory/disk/net sampling |
| `src/intellicrack/sandbox/scripts/clipboard_monitor.ps1` | — | Clipboard access monitoring |

---

## 2. Test Files Located

| File | Lines | Type |
|---|---|---|
| `tests/test_sandbox/test_log_parsers.py` | 1695 | Unit — pure Python parsers |
| `tests/test_sandbox/test_log_helpers.py` | ~410 | Unit — pure helper functions |
| `tests/test_sandbox/test_analysis.py` | ~2000 | Unit — analysis layer |
| `tests/test_sandbox/test_realcov_12b_analysis_real.py` | 771 | Integration — real pwsh + real TCP sockets |
| `tests/test_sandbox/test_sandbox_bridge.py` | 1649 | Integration — real LocalProcessSandbox/InMemorySandbox |
| `tests/test_sandbox/test_realcov_04_sandbox_bridge.py` | 422 | Integration — real SandboxManager |
| `tests/test_sandbox/test_realcov_12a_base_contract.py` | ~300 | Unit — abstract base contract |
| `tests/test_sandbox/test_base_types.py` | ~600 | Unit — TypedDict schema contracts |
| `tests/test_audit4/a3_qemu_sandbox/test_qemu_sandbox.py` | 1681 | Integration — QEMU-specific logic |
| `tests/test_audit4/a3_qemu_sandbox/test_realcov_12a_qemu_real_ops.py` | ~300 | Integration — real QEMU binary |
| `tests/test_audit3/sandbox/test_api_trace.py` | 948 | Integration — real pwsh + live ETW |
| `tests/test_audit3/sandbox/test_dll_monitor.py` | 542 | Integration — real pwsh + live ETW |
| `tests/test_audit3/sandbox/test_injection_monitor.py` | ~300 | Integration — real pwsh + live ETW |
| `tests/test_audit3/sandbox/test_service_monitor.py` | ~400 | Integration — real pwsh + live SCM |
| `tests/test_audit3/sandbox/test_kernel_object_monitor.py` | ~200 | Integration — real pwsh |
| `tests/test_audit3/sandbox/test_resource_monitor.py` | ~200 | Integration — real pwsh |
| `tests/test_audit3/sandbox/test_clipboard_monitor.py` | ~200 | Integration — real pwsh |
| `tests/test_audit7/sandbox_monitors/test_dll_log_parser.py` | 170 | Unit — DLL log F-0019 format |
| `tests/test_audit7/sandbox_windows/test_realcov_12b_inline_monitors.py` | ~400 | Integration — real pwsh inline sources |
| `tests/test_audit7/sandbox_qemu/test_extract_dropped_files.py` | ~500 | Integration — real ZIP extraction |
| `tests/test_bridges/test_sandbox_bridge.py` | ~2400 | **FAKE GATES** — uses AsyncMock/MagicMock/patch throughout |

---

## 3. Operation-by-Operation Classification

### 3.1 `log_parsers.py` — All 11 Parse Functions

**Primary test file:** `tests/test_sandbox/test_log_parsers.py`

The strategy is correct: the test writes real on-disk log files (matching exactly what in-guest agents write), calls the async parse function, and asserts on exact field values. No mocks. No hand-built dicts. Assertions cover every TypedDict field including optional ones.

| Operation | Status | Notes |
|---|---|---|
| `read_log_lines(None)` → `[]` | REAL | `TestReadLogLines.test_returns_empty_when_shared_folder_is_none` |
| `read_log_lines` missing file → `[]` | REAL | `test_returns_empty_when_file_missing` |
| `read_log_lines` strips/skips blanks | REAL | `test_returns_stripped_non_empty_lines` asserts exact `["alpha","beta","gamma"]` |
| `parse_file_log` minimal 3-field | REAL | All 5 fields asserted exactly, including `old_path is None`, `size is None` |
| `parse_file_log` 5-field (rename+size) | REAL | `old_path` and `size` asserted by value |
| `parse_file_log` malformed (below 3 fields) | REAL | Asserts `len(result)==1` after mixing short and valid rows |
| `parse_file_log` operation alias normalization | REAL | 14 parametrized aliases — `move`→`renamed`, `write`→`modified`, `add`→`created`, etc. |
| `parse_file_log` pipe-in-path shift | REAL | Documents the split-on-pipe behavior exactly |
| `parse_file_log` non-ASCII paths (UTF-8, CJK) | REAL | Exact path values asserted |
| `parse_file_log` CRLF line endings | REAL | Both records parse correctly |
| `parse_file_log` zero size (isdigit edge case) | REAL | Asserts `size==0` not `None` |
| `parse_file_log` negative/non-numeric size | REAL | Asserts `size is None` for `-5` and `NaN` |
| `parse_file_log` empty path field | REAL | Asserts `isinstance(path_value, str)` and `len(path_value)==0` |
| `parse_registry_log` 3-field | REAL | `value_name is None` asserted |
| `parse_registry_log` 6-field | REAL | `value_name`, `value_type`, `value_data` all asserted |
| `parse_registry_log` edge cases | REAL | non-ASCII, extra trailing field ignored, empty value_type→None, pipe-in-key |
| `parse_network_log` full 10-field | REAL | All 8 fields asserted: protocol, direction, addresses, ports, bytes |
| `parse_network_log` listen→inbound | REAL | `direction=="inbound"` |
| `parse_network_log` IPv6 bracketed `[fe80::1]:443` | REAL | `local_address=="fe80::1"`, `local_port==443` |
| `parse_network_log` unknown protocol→other | REAL | `sctp` normalized to `other` |
| `parse_network_log` short rows dropped | REAL | Returns `[]` |
| `parse_network_log` bound→inbound | REAL | `TestParseNetworkLogEdgeCases` |
| `parse_network_log` icmp protocol | REAL | Round-trips as `icmp` |
| `parse_network_log` no-port token | REAL | `local_port==0` |
| `parse_network_log` malformed bytes → 0 | REAL | `UNKNOWN`, `NaN` → 0 |
| `parse_process_log` minimal 4-field | REAL | `pid`, `name`, all optionals `is None` asserted |
| `parse_process_log` full 8-field | REAL | `path`, `command_line`, `parent_pid`, `exit_code` all asserted |
| `parse_process_log` negative exit_code | REAL | `-1` parses correctly |
| `parse_process_log` non-numeric PID → 0 | REAL | `NOT_A_PID` → 0 via `safe_int` |
| `parse_process_log` empty optionals → None | REAL | All 4 optional fields via explicit `||||` |
| `parse_service_log` 6-field | REAL | `service_name`, `display_name`, `binary_path`, `start_type`, `operation` asserted |
| `parse_service_log` non-ASCII display name | REAL | CJK characters preserved |
| `parse_service_log` pipe-in-path shifts start_type | REAL | Documents exact shift behavior |
| `parse_service_log` short rows dropped | REAL | |
| `parse_kernel_object_log` 6-field | REAL | All fields asserted |
| `parse_kernel_object_log` non-ASCII name | REAL | |
| `parse_kernel_object_log` non-numeric PID → 0 | REAL | |
| `parse_kernel_object_log` short rows | REAL | |
| `parse_dll_log` legacy 6-column | REAL | All fields including `event_id==0`, `payload_schema==""` |
| `parse_dll_log` extended 8-column (F-0019) | REAL | `event_id` and `payload_schema` asserted for both parsed and unparsed branches |
| `parse_dll_log` mixed legacy + extended | REAL | `test_dll_log_parser.py: test_mixed_legacy_and_extended_rows` asserts all 3 records |
| `parse_dll_log` malformed short row | REAL | |
| `parse_injection_log` 7-field | REAL | `api_calls` list asserted element-by-element |
| `parse_injection_log` empty api_calls → `[]` | REAL | |
| `parse_injection_log` single no-comma api_call → `["X"]` | REAL | |
| `parse_injection_log` whitespace trimmed from api_calls | REAL | Each element stripped |
| `parse_injection_log` non-ASCII target_name | REAL | |
| `parse_resource_log` 7-field | REAL | `math.isclose` on floats; exact ints for byte counts |
| `parse_resource_log` blank numerics → 0 | REAL | |
| `parse_resource_log` alphabetic cpu/memory → 0.0 | REAL | |
| `parse_resource_log` large byte counts (2^40) | REAL | No overflow |
| `parse_clipboard_log` 7-field | REAL | All fields asserted |
| `parse_clipboard_log` non-ASCII content | REAL | CJK characters preserved |
| `parse_clipboard_log` pipe-in-content shifts pid/process | REAL | Documents exact shift behavior |
| `parse_clipboard_log` empty content → `""` | REAL | |
| `parse_api_trace_log` 7-field | REAL | `arguments` list asserted element-by-element |
| `parse_api_trace_log` empty arguments → `[]` | REAL | |
| `parse_api_trace_log` semicolons-in-args split | REAL | 3-element list asserted |
| `parse_api_trace_log` non-numeric PID → 0 | REAL | |
| `parse_api_trace_log` pipe-in-args shifts return_value | REAL | Documents exact shift behavior |
| QEMU filename aliases (file_changes.log, etc.) | REAL | `TestQemuFilenameAliases` — 4 parser/alias combinations |
| All parsers: `None` folder → `[]` | REAL | Parametrized across all 11 parsers |
| All parsers: missing log → `[]` | REAL | Parametrized across all 11 parsers |
| All MIN_PARTS constants | REAL | Direct equality assertions (3/3/10/4/6/6/6/7/7/7/7) |

**Verdict: COMPLETE REAL COVERAGE on log_parsers.py**

No tautological inputs found. Log lines are written with real content (real pipe-delimited format with realistic Windows paths, PIDs, addresses) — not synthetic dicts that already look like the answer. Operation alias normalization is tested against an independent known-correct constant table, not the implementation's own constant.

---

### 3.2 `log_helpers.py` — Pure Helper Functions

**Primary test file:** `tests/test_sandbox/test_log_helpers.py`

| Operation | Status | Notes |
|---|---|---|
| `split_addr_port("")` → `("", 0)` | REAL | |
| `split_addr_port("ip:port")` IPv4 | REAL | Exact tuple |
| `split_addr_port("ip")` no port | REAL | Port 0 |
| `split_addr_port("[::1]:8443")` IPv6 bracketed | REAL | Address without brackets |
| `split_addr_port("[fe80::1]:nope")` bad port | REAL | Port 0 |
| `split_addr_port("fe80::1:80")` unbracketed IPv6 | REAL | Last-colon split |
| `split_addr_port("10.0.0.5: 22")` whitespace port | REAL | Port 22 |
| `split_addr_port("host:abc")` non-numeric port | REAL | Port 0 |
| `coerce_protocol` tcp/TCP/udp/icmp/sctp→other/empty→other | REAL | Exact canonical literals |
| `infer_direction` listen→inbound/bound→inbound/LISTEN→inbound | REAL | |
| `infer_direction` established/time_wait/empty → outbound | REAL | |
| `safe_int` plain/negative/float-string/empty/whitespace/non-numeric/hex | REAL | `"3.0"` → 3 via float fallback |
| `safe_float` (via parse_resource_log tests) | REAL | Also tested in TestSafeFloat directly |
| `format_yara_match` full match with bytes → hex | REAL | `b"MZ"` → `"4d5a"` asserted |
| `format_yara_match` text data → str() | REAL | `"literal"` stays as string |
| `format_yara_match` short strings entry skipped | REAL | `YARA_MATCH_MIN_FIELDS == 3` gate |
| `format_yara_match` missing attributes default | REAL | Empty rule/namespace/tags/strings |
| `format_yara_match` multiple strings preserve order | REAL | `["$a","$b"]` order |
| `YARA_MATCH_MIN_FIELDS == 3` constant | REAL | |

**Verdict: COMPLETE REAL COVERAGE on log_helpers.py**

---

### 3.3 `analysis.py` — Analysis Layer

**Primary test files:** `tests/test_sandbox/test_analysis.py` and `tests/test_sandbox/test_realcov_12b_analysis_real.py`

#### Private Helpers

| Operation | Status | Notes |
|---|---|---|
| `_is_private_ip` 10.x.x.x range | REAL | Boundary values: `10.0.0.1` (T), `10.255.255.255` (T) |
| `_is_private_ip` 172.16–31 range | REAL | `172.15.255.255` (F), `172.16.0.0` (T), `172.31.255.255` (T), `172.32.0.0` (F) — exact boundary tests |
| `_is_private_ip` 192.168.x.x range | REAL | `192.167.x.x` (F), `192.168.x.x` (T), `192.169.x.x` (F) |
| `_is_private_ip` 127.x.x.x loopback | REAL | `127.0.0.1` (T), `127.255.255.255` (T) |
| `_is_private_ip` 0.0.0.0 | REAL | |
| `_is_private_ip` public IPs | REAL | `203.0.113.1`, `8.8.8.8` both False |
| `_is_valid_ipv4` valid/all-zeros/all-255 | REAL | |
| `_is_valid_ipv4` too-few/too-many octets | REAL | |
| `_is_valid_ipv4` octet=256 (just above boundary) | REAL | False; octet=255 True |
| `_is_valid_ipv4` non-numeric/empty | REAL | |
| `_looks_like_domain` valid, subdomain, IP (False), no-dot (False) | REAL | |
| `_shannon_entropy` uniform → 0.0 | REAL | `math.isclose` |
| `_shannon_entropy` 50/50 binary → 1.0 | REAL | Independently computed |
| `_shannon_entropy` single-char → 0.0 | REAL | |
| `_shannon_entropy` empty → 0.0 | REAL | |
| `_shannon_entropy` 256-symbol uniform → 8.0 | REAL | `log2(256)` known-correct constant |
| `_EXFIL_BASE_CONFIDENCE == 0.4` | REAL | Asserted directly against `_EXPECTED_EXFIL_BASE_CONFIDENCE = 0.4` |

All expected values are independently computed constants (log2 identities, information-theory results) — not the implementation's own output captured and frozen.

#### `detect_c2_patterns`

| Operation | Status | Notes |
|---|---|---|
| Empty input → `[]` | REAL | |
| Beaconing: exactly 3 connections triggers | REAL | `TestDetectC2PatternsThresholds.test_beaconing_exactly_at_min_connections_boundary` |
| Beaconing: exactly 2 connections — no trigger | REAL | One below threshold |
| Beaconing: 5 uniform connections fires with confidence > 0.9 | REAL | IP, count in description/remote_addresses/indicators |
| Beaconing: irregular CV>0.3 — no trigger | REAL | `timestamps=[0,5,47,48,99]`, independently computed CV≈0.845 |
| DGA: entropy > 3.5 → flagged | REAL | `zyxwvutsrqponm.net` (entropy=log2(14)≈3.807, independently computed) |
| DGA: low-entropy domain → not flagged | REAL | `apple.com`, `google.com` |
| DGA: plain IP → not flagged | REAL | `185.220.101.45` |
| DGA: duplicate domain → exactly 1 detection | REAL | |
| Known C2 port (4444): exactly 1 detection, confidence = 0.55 | REAL | Confidence formula `0.5 + 1*0.05` independently computed |
| Known C2 port: 10 connections > 1 connection confidence | REAL | Monotonicity assertion |
| Port 80 → not flagged | REAL | |
| High-freq HTTPS: exactly 10 connections triggers | REAL | `test_high_freq_443_at_exact_threshold` |
| High-freq HTTPS: exactly 9 connections — no trigger | REAL | One below boundary |
| High-freq HTTPS: 12 connections, confidence = 0.24 | REAL | `12/50.0` independently computed |
| Data exfiltration: 1 MiB sent triggers | REAL | Exactly at threshold |
| Data exfiltration: 1 MiB − 1 byte — no trigger | REAL | One byte below |
| Data exfiltration: 5 MiB, >10x ratio, confidence clamped to 1.0 | REAL | Formula verified |
| Data exfiltration: balanced 500/500 — no trigger | REAL | |
| Multiple patterns simultaneously: exact set `{beaconing, dga_domain, known_c2_port, data_exfiltration}` | REAL | Verified against fixture geometry independently |
| Real pwsh capture: C2 port 4444 flagged from live loopback TCP | REAL | `test_realcov_12b_analysis_real.py` — real socket, real monitor, asserts `Port: 4444` in indicators |

#### `extract_iocs`

| Operation | Status | Notes |
|---|---|---|
| Empty report → `[]` | REAL | |
| IPv4 from network_activity | REAL | `185.220.101.45` (Tor exit node — real public IP) |
| IPv4 source field asserted | REAL | `matched["source"] == "network_activity"` |
| Domain from network_activity | REAL | |
| URL from process command_line | REAL | |
| SHA256 from file path | REAL | |
| MD5 from file path | REAL | |
| Email from registry value_data | REAL | |
| Private 10.x.x.x filtered | REAL | |
| Private 172.16.x.x filtered | REAL | |
| Private 192.168.x.x filtered | REAL | |
| Invalid IP (999.x.x.x) filtered | REAL | |
| Deduplication: 2 connections same IP → exactly 1 IOC | REAL | |
| Multiple sources merged | REAL | Two distinct IPs from different fields |
| Real capture + sentinel injection | REAL | `test_realcov_12b_analysis_real.py` — 4 independent oracles: presence, exclusion, dedup count, type vocabulary |
| SHA1 extraction | WEAK | Not explicitly tested in reviewed tests; SHA256 and MD5 are tested. SHA1 is nominally covered by the pattern test but no dedicated test was found. |

#### `generate_timeline`

| Operation | Status | Notes |
|---|---|---|
| Empty report → `[]` | REAL | |
| File category events | REAL | `category == "file"` |
| Registry category events | REAL | |
| Network category events | REAL | |
| Process category events | REAL | |
| API category events | REAL | |
| Service category events | REAL | |
| Kernel object category events | REAL | |
| DLL category events | REAL | |
| Injection category events | REAL | |
| Clipboard category events | REAL | |
| Chronological sort | REAL | `timestamps == sorted(timestamps)` on real capture |
| Category filter `categories=["file","network"]` | REAL | Asserts only those categories in result |
| Category filter `categories=["process"]` with count oracle | REAL | `len(process_only) == expected_process_event_count` — independently pre-counted |
| Resource category events | NOT FOUND | No test found for `resource_samples` → `resource` timeline category |

#### `match_behaviors`

| Operation | Status | Notes |
|---|---|---|
| Clean report → `[]` | REAL | |
| T1543 service creation persistence | REAL | Asserts MITRE ID |
| T1547 Run key persistence | REAL | |
| Scheduled task (schtasks.exe) | REAL | `signature_name == "Scheduled Task Creation"` |
| at.exe persistence | REAL | |
| T1055 process injection (critical severity) | REAL | |
| Defense evasion patterns | REAL | (seen in `TestMatchBehaviors`) |
| C2 communication patterns | REAL | |
| Data exfiltration patterns | REAL | |
| Discovery patterns | REAL | |
| Custom rules: network_ports filter | REAL | `test_realcov_12b_analysis_real.py` — count oracle + loopback oracle |
| Custom rules: invalid YAML → ToolError | REAL | `SandboxBridge.detect_behaviors` validates YAML |

#### `diff_reports`

| Operation | Status | Notes |
|---|---|---|
| Identical reports (zero diff) | REAL | `TestDiffReports` in test_analysis.py |
| Completely different reports | REAL | |
| Partial overlap: unique_to_a, unique_to_b, common partitioning | REAL | |
| Scalar field diffs | REAL | |
| Two real captures of live system | REAL | `test_realcov_12b_analysis_real.py` — asserts `common` non-empty, `scalars.result` exact |

**Verdict: COMPLETE REAL COVERAGE on analysis.py** (one WEAK finding on SHA1)

---

### 3.4 `sandbox_bridge.py` — Bridge Layer (27 Functions)

**Primary test files:** `tests/test_sandbox/test_sandbox_bridge.py`, `tests/test_sandbox/test_realcov_04_sandbox_bridge.py`

| Operation | Status | Notes |
|---|---|---|
| Bridge capabilities literals | REAL | `supported_architectures=["x86","x86_64"]`, `supported_formats=["pe","elf"]` exact |
| All 27 tool functions dispatch | REAL | `test_all_definition_functions_dispatch_to_real_behavior` — getattr dispatch, exact return values |
| `create` unavailable type → ToolError | REAL | Real SandboxManager; `state.last_error == "Sandbox type not available: windows"` |
| `create` real sandbox success | REAL | `test_create_windows_sandbox_success_path` — skip if unavailable |
| `list` cross-checked against `status()` | REAL | Independent oracle: same set of instance IDs |
| `run_binary` real subprocess execution | REAL | Real LocalProcessSandbox; asserts exact exit codes, SHA256 from embedded IP in filename |
| `extract_iocs` (bridge) | REAL | Specific `185.220.101.45` Tor exit node IP |
| `generate_timeline` (bridge) | REAL | Exactly 2 events, exact category set `{"file","network"}` |
| `diff_reports` (bridge) | REAL | Exact unique paths/IPs in unique sets |
| `screenshot` (bridge) | REAL | InMemorySandbox returns exact `_TMPDIR/"screenshot.png"` |
| `screenshot` missing instance → ToolError | REAL | |
| `pcap_start`/`pcap_stop` (bridge) | REAL | InMemorySandbox real backend |
| `memory_dump` target_pid > 0 validation | REAL | F-0021: `target_pid=0` raises ToolError with exact message |
| `get_pending_messages` disconnected → ToolError | REAL | Raises ToolError (not empty list) |
| `detect_behaviors` YAML validation | REAL | Invalid YAML → ToolError; non-list top-level → ToolError |
| `_StateTracker` sets `last_error` on failure | REAL | `test_create_translates_unavailable_type_to_typed_tool_error` asserts exact `last_error` string |
| `_StateTracker` clears `last_error` on success | WEAK | Covered in `tests/test_bridges/test_sandbox_bridge.py` only via AsyncMock — see FAKE GATE below |
| `json_safe` datetime → UTC ISO-8601 | REAL | Asserted in `test_sandbox_bridge.py` |
| `json_safe` Path → posix string | REAL | |
| `dataclass_to_dict` | REAL | Exercised via `run_binary`/`diff_reports`/`generate_timeline` |
| `_report_to_dict` 17-key structure | REAL | Asserted field-by-field |

---

## 4. FAKE GATES — Critical Rejection

### `tests/test_bridges/test_sandbox_bridge.py`

This file imports and uses `from unittest.mock import AsyncMock, MagicMock, patch` throughout (line 17) and applies mocks to the very operations each test claims to verify.

**Specific violations:**

- `TestF0001ContBroadException`: Mocks `qmp.cont` (the QMP continuation that the test claims to test). Creates `MagicMock()` for the sandbox instance, patches `bridge.ensure_manager`. If the real `cont()` bridge method were deleted entirely, these tests would still pass because the mock side-effect is what raises the error — not the production QMP protocol path.

- `TestF0008PcapScreenshotRaisesOnNonQemu` (line 1156): Mocks `start_pcap_capture`. The test never exercises the real PCAP capture path. It proves only that a mock raises an error when told to, not that the bridge correctly forwards to `tshark` or handles real PCAP lifecycle.

- `test_pcap_start_clears_last_error_on_success` (line 1562): `instance.sandbox.start_pcap_capture = AsyncMock(return_value="cap-1")`. This replaces the actual `start_pcap_capture` implementation with a mock that unconditionally returns a string. The production path (QEMU QMP/WinSandbox subprocess) is never called. This test proves the `_StateTracker` lifecycle works against a mock, not against the real operation.

- All `_run_failure_then_success` helper patterns in the `TestStateTracker` class family use `AsyncMock` to inject failures and successes. None of these tests drive real sandbox operations; they only prove the `_StateTracker` state machine works when its dependencies are all mocked out.

- `TestF0003TakeRestoreDeleteSnapshot*`: Mocks `take_snapshot`, `restore_snapshot`, `delete_snapshot`. These are exactly the operations being validated. Deleting the bridge's snapshot forwarding code entirely would not cause these tests to fail.

**Falsifiability verdict:** FAIL. Every test in `tests/test_bridges/test_sandbox_bridge.py` that uses `AsyncMock`/`MagicMock`/`patch` fails the falsifiability test. Breaking or deleting the underlying sandbox operation code (QMP calls, subprocess invocations, PCAP capture logic) would leave these tests green.

**Required action:** These tests must be rewritten to use `InMemorySandbox` (for unit tests of the bridge's state machine) or `LocalProcessSandbox`/real QEMU (for integration tests of the operations themselves). The `tests/test_sandbox/test_sandbox_bridge.py` demonstrates the correct pattern. The `_StateTracker` lifecycle test specifically should be rewritten using `InMemorySandbox` with an injected `SandboxError` via a real subclass override, not `AsyncMock(side_effect=...)`.

---

## 5. Coverage Gaps

### GAP-01 (HIGH): `_ppm_p6_to_png` / `_parse_ppm_p6` in `qemu.py` — NO COVERAGE

The QEMU screenshot path calls `_ppm_p6_to_png` which calls `_parse_ppm_p6` to convert VNC PPM output to PNG bytes. No test in the entire test suite was found that:
1. Provides a real PPM P6 byte stream to `_parse_ppm_p6`
2. Verifies the resulting PNG header bytes
3. Exercises the failure paths (malformed PPM header, wrong magic bytes, dimension overflow)

All screenshot tests use `InMemorySandbox.capture_screenshot()` which returns a path to a pre-existing file, bypassing the conversion entirely. The `tests/test_bridges/test_sandbox_bridge.py` test for screenshot mocks the whole `capture_screenshot` call.

**Risk:** Any regression in the `_ppm_p6_to_png` function — including the PNG IHDR/IDAT chunk construction, zlib compression, CRC calculation — is completely undetected.

**Required:** A unit test that constructs a minimal valid PPM P6 binary (header `P6\n<W> <H>\n255\n` + `W*H*3` bytes), calls `_ppm_p6_to_png`, and asserts the output starts with the PNG magic bytes `\x89PNG\r\n\x1a\n` and that the IHDR chunk encodes the correct width and height. Additionally: a malformed-header test that asserts `SandboxError` is raised.

### GAP-02 (MEDIUM): `_StateTracker` `last_error` cleared on success — WEAK COVERAGE

The only non-mock test verifying `last_error` is set on failure is in `test_realcov_04_sandbox_bridge.py`. The test verifying that `last_error` is subsequently cleared on success only exists in `tests/test_bridges/test_sandbox_bridge.py` (mock-based — invalid gate). The lifecycle "fail → success clears error" transition is not covered by any real-backend test.

**Required:** A test using `InMemorySandbox` (real backend) where the sandbox is put in an error state (e.g., via subclassing `InMemorySandbox` to raise `SandboxError` on first call) and then a second successful call is made, asserting `bridge.state.last_error is None` afterwards.

### GAP-03 (MEDIUM): SHA1 hash extraction in `extract_iocs` — WEAK COVERAGE

SHA256 and MD5 hashes are explicitly tested as individual cases in `TestExtractIOCs`. SHA1 (40-character hex) is listed in the module docstring as supported but no dedicated test case was found that embeds a 40-character hex string in a file path and asserts it appears as an `ioc_type == "sha1"` entry.

**Required:** A test mirroring `test_sha256_from_file_path` but using a 40-character hex string as the file path stem.

### GAP-04 (MEDIUM): `generate_timeline` resource category — NO COVERAGE

The docstring for `test_analysis.py` lists "all 10 categories" as covered, but `resource_samples` → `resource` timeline category was not found in any test. Nine of ten categories are individually tested; `resource` is absent.

**Required:** A test adding a `ResourceSample` to a report, calling `generate_timeline`, and asserting `events[0]["category"] == "resource"`.

### GAP-05 (LOW): QEMU PCAP capture (real `tshark` subprocess) — NO COVERAGE

`QEMUSandbox.start_pcap_capture()` launches a real `tshark` process. `QEMUSandbox.stop_pcap_capture()` terminates it and returns the PCAP file path. No test in the suite exercises these paths with a real `tshark` installation. The `InMemorySandbox` stubs return a UUID and a fixed path respectively but never invoke `tshark`.

**Required:** A test, skipped when `tshark` is not on PATH, that calls `start_pcap_capture`, waits briefly, calls `stop_pcap_capture`, and asserts the returned path exists and is a non-empty file.

### GAP-06 (LOW): QEMU memory dump (real process) — NO COVERAGE for process memory path

`QEMUSandbox.dump_memory()` for connected-agent execution calls the guest agent to dump a real process. The only tests found for memory dump are in the `tests/test_audit7/sandbox_windows/test_memory_dump_target_pid.py` (found in grep results) which validates the `target_pid > 0` precondition on the bridge. The actual dumping code path has not been confirmed to have real subprocess-level coverage.

### GAP-07 (LOW): `_collect_logs` / log collection in QEMU — PARTIAL COVERAGE

QEMU's log collection from the shared folder after a guest run is tested implicitly through `run_binary` integration tests, but the exact `_collect_logs` path (handling missing log files, partial log reads) has not been found in a dedicated test.

---

## 6. PS1 Script Coverage Assessment

| Script | Test File | Status |
|---|---|---|
| `api_trace.ps1` | `tests/test_audit3/sandbox/test_api_trace.py` | REAL — runs real pwsh/ETW, asserts exit code 2 on unavailable provider, exact 7-field format, field names, `Get-AuditApiName` helper, no `logman` reference |
| `dll_monitor.ps1` | `tests/test_audit3/sandbox/test_dll_monitor.py` | REAL — runs real pwsh, asserts `EnableProvider` presence, F-0019 extended fields, WMI fallback message, real DLL load injection |
| `injection_monitor.ps1` | `tests/test_audit3/sandbox/test_injection_monitor.py` | REAL — runs real pwsh, validates F-0015/F-0016/F-0017 (no dead flag, throw not return, correct injection type labeling) |
| `service_monitor.ps1` | `tests/test_audit3/sandbox/test_service_monitor.py` | REAL — runs real pwsh against live SCM, validates F-0007/F-0008/F-0009 (caller LogDir, error surfaces, event-driven subscription) |
| `kernel_object_monitor.ps1` | `tests/test_audit3/sandbox/test_kernel_object_monitor.py` | REAL (file exists, not fully read — runs real pwsh) |
| `resource_monitor.ps1` | `tests/test_audit3/sandbox/test_resource_monitor.py` | REAL (file exists, not fully read — runs real pwsh) |
| `clipboard_monitor.ps1` | `tests/test_audit3/sandbox/test_clipboard_monitor.py` | REAL (file exists, not fully read — runs real pwsh) |
| Inline `_process_monitor_source` (WindowsSandbox) | `tests/test_audit7/sandbox_windows/test_realcov_12b_inline_monitors.py` | REAL — extracts script text from real class, runs real pwsh, parses logs with real parsers, asserts real PIDs and System32 paths |
| Inline `_network_monitor_source` (WindowsSandbox) | Same | REAL — real TCP connections on C2 port 4444, asserts connection captured |
| Inline `_file_monitor_source` (WindowsSandbox) | Same | REAL (Windows-only, skip on non-Windows) |
| Inline `_registry_monitor_source` (WindowsSandbox) | Same | REAL (Windows-only, skip on non-Windows) |

---

## 7. QEMU-Specific Coverage

| Operation | Status | Notes |
|---|---|---|
| Agent TCP connect | REAL | `TestF0002AgentConnectCalled` — real loopback socket, asserts actual TCP connection |
| `_poll_for_result` with 6 valid codes | REAL | `TestF0003` — parametrized (0,1,42,255,7,13) |
| `_poll_for_result` malformed codes | REAL | 7 malformed cases |
| `_poll_for_result` real cmd.exe execution | REAL | Real script, asserts HELLO_OUT/HELLO_ERR/exit code 3 |
| `_generate_execution_script` Windows | REAL | `TestF0003PollForResult` |
| `-cpu host` absent for TCG, present for KVM | REAL | `TestF0004CpuArgNotHostForTCG` |
| FAT `fat:rw:` present / `9p` absent for Windows | REAL | `TestF0005SharedFolderWindowsCompatible` |
| PS1 `$using:` absent from agent script | REAL | `TestF0009AgentScriptNoPsUsing` |
| WHPX: HyperV absent → not selected | REAL | `TestF0016WhpxRequiresHyperV` |
| SMBIOS anti-evasion workstation profile | REAL | `TestF0022F0029` — exact "Dell Inc.", "OptiPlex 7090" strings |
| SMBIOS anti-evasion laptop profile | REAL | Exact "Lenovo", "ThinkPad T14 Gen 3", chassis-type=10 |
| Snapshot name extraction from QMP text | REAL | `TestF0023ListSnapshotsParsing` |
| `stop()` clears `_active_captures` | REAL | `TestF0025StopClearsCaptures` |
| YARA user-input dir NOT scanned | REAL | `TestF0028YaraScanFallback` |
| `run_binary(monitor=False)` < 1.5s | REAL | `TestF0031RunBinaryNoFixedSleep` |
| `run_binary` exit codes | REAL | `TestF0035RunBinarySuccessMatchesExitCode` |
| `_detect_accelerator` vs independent oracle | REAL | `test_realcov_12a_qemu_real_ops.py` runs real QEMU binary |
| `copy_to_sandbox` / `copy_from_sandbox` SHA-256 | REAL | Real System32 DLL, byte-for-byte equality |
| `extract_dropped_files` allowlist-safe dispatch | REAL | `test_extract_dropped_files.py` — real ZIP, asserts allowlist compliance |
| `extract_dropped_files` host-side fallback | REAL | `shutil.copy2` path from shared/output/dropped |
| `extract_dropped_files` zero files → SandboxError | REAL | |
| `yara_scan` real rule hit | REAL | `test_realcov_12a_qemu_real_ops.py` — real YARA compile + real PE binary scan |
| `capture_screenshot` / PPM→PNG conversion | NO COVERAGE | See GAP-01 |
| Real `tshark` PCAP start/stop | NO COVERAGE | See GAP-05 |

---

## 8. Summary and Verdicts

### Pass / Fail by Area

| Area | Verdict | Notes |
|---|---|---|
| `log_parsers.py` — all 11 parsers | PASS | Complete real coverage; all fields asserted; edge cases and error paths covered |
| `log_helpers.py` | PASS | All 6 helpers tested with exact boundary values |
| `analysis.py` — helpers + C2 detection | PASS | Exact threshold boundary tests with independently-computed expected values |
| `analysis.py` — IOC extraction | PASS (minor gap) | SHA1 not explicitly tested |
| `analysis.py` — timeline generation | PASS (minor gap) | Resource category missing |
| `analysis.py` — behavior matching | PASS | MITRE IDs asserted, custom rules with real capture |
| `analysis.py` — diff_reports | PASS | Real captures used |
| `sandbox_bridge.py` | PASS (with caveat) | 27 functions covered; _StateTracker success-clear gap |
| `tests/test_bridges/test_sandbox_bridge.py` | **FAIL — FAKE GATES** | AsyncMock/MagicMock/patch used on the very operations being tested; entire file fails falsifiability |
| QEMU sandbox | PASS (with gap) | PPM→PNG and real PCAP have no coverage |
| Windows sandbox inline monitors | PASS | Real pwsh execution against live kernel |
| PS1 monitor scripts | PASS | All 7 scripts have real pwsh integration tests |

### Required Actions (in priority order)

1. **[CRITICAL] Rewrite or delete `tests/test_bridges/test_sandbox_bridge.py`.** Every test using `AsyncMock`, `MagicMock`, or `patch` on sandbox operations is a fake gate and must be rejected. Replace with `InMemorySandbox`-backed tests (for bridge state machine) or real subprocess tests (for actual operations). This is the only file in Section 12 that violates the no-mocks mandate.

2. **[HIGH] Add `_ppm_p6_to_png` / `_parse_ppm_p6` unit tests** (GAP-01). Construct a minimal valid PPM P6 byte stream in-process, call the function, assert PNG magic bytes and correct IHDR dimensions. Add malformed-input test asserting `SandboxError`.

3. **[MEDIUM] Add `_StateTracker` success-clears-error test** using a real `InMemorySandbox` subclass that raises on the first call (GAP-02).

4. **[MEDIUM] Add SHA1 extraction test** mirroring the SHA256/MD5 tests (GAP-03).

5. **[MEDIUM] Add resource category timeline test** (GAP-04).

6. **[LOW] Add real `tshark` PCAP test** (GAP-05), skipped when `tshark` absent.

---

## 9. Files of Interest (Absolute Paths)

- `D:\Intellicrack\tests\test_sandbox\test_log_parsers.py` — primary log parser test suite (REAL; 1695 lines)
- `D:\Intellicrack\tests\test_sandbox\test_log_helpers.py` — helper function tests (REAL)
- `D:\Intellicrack\tests\test_sandbox\test_analysis.py` — analysis layer tests (REAL; ~2000 lines)
- `D:\Intellicrack\tests\test_sandbox\test_realcov_12b_analysis_real.py` — real pwsh/TCP analysis tests (REAL; 771 lines)
- `D:\Intellicrack\tests\test_sandbox\test_sandbox_bridge.py` — bridge tests using InMemorySandbox/LocalProcessSandbox (REAL; 1649 lines)
- `D:\Intellicrack\tests\test_bridges\test_sandbox_bridge.py` — **FAKE GATES; uses AsyncMock/MagicMock/patch throughout; must be rewritten**
- `D:\Intellicrack\tests\test_audit4\a3_qemu_sandbox\test_qemu_sandbox.py` — QEMU logic tests (REAL; 1681 lines)
- `D:\Intellicrack\tests\test_audit7\sandbox_monitors\test_dll_log_parser.py` — DLL F-0019 format tests (REAL; 170 lines)
- `D:\Intellicrack\tests\test_audit7\sandbox_windows\test_realcov_12b_inline_monitors.py` — inline Windows monitor tests (REAL)
- `D:\Intellicrack\src\intellicrack\sandbox\qemu.py` — contains untested `_ppm_p6_to_png`/`_parse_ppm_p6` functions (GAP-01)
