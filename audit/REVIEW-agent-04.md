# Review of Agent-04 Audit Findings

This document reviews each finding in audit/agent-04.md against the current codebase at HEAD.

## Finding Reviews

### F1: tests/test_audit4/c6_hex_hashing/test_hashing.py:225 - message_box_yes
- **Verdict:** PARTIAL
- **Evidence:** tests/test_audit4/c6_hex_hashing/test_hashing.py:420-457 (monkeypatch fixture exists); lines 575-681 (tests assert on real PE checksum values cross-validated against pefile.generate_checksum)
- **Justification:** The monkeypatch fixture remains (unavoidable for Qt dialog automation), but the tests now verify real PE checksum computation (lines 611-615 assert written_checksum == expected_checksum using pefile oracle). The underlying repair logic is observable through independent checksum validation.

### F2: tests/test_audit4/c6_hex_hashing/test_hashing.py:65 - StubPeDocument
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit4/c6_hex_hashing/test_hashing.py:194-322 (StubPeDocument uses real _ms_pe_checksum at lines 275-288, derives offset from e_lfanew at lines 226-245); lines 474-559 (tests validate against pefile.generate_checksum)
- **Justification:** StubPeDocument now implements the genuine Microsoft PE checksum algorithm and derives the checksum field offset from e_lfanew, not magic constants. Tests validate against pefile.generate_checksum, so if the stub's algorithm diverges or the offset calculation breaks, tests fail immediately.

### F3: tests/test_audit4/c9_hex_disassembly_debounce/test_follow_cursor_debounce.py:113 - _DebouncingHarness
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit4/c9_hex_disassembly_debounce/test_follow_cursor_debounce.py:152-230 (_RecordingBridge intercepts real bridge.disassemble calls; _RealBridgeHarness executes production _on_disassemble unchanged); comments at lines 24-36 state "All assertions target the actual bridge.disassemble call arguments"
- **Justification:** The _RecordingBridge's async disassemble() is real (returns awaitable), allowing production _on_disassemble to execute completely. If the bridge method signature changed, the call site would fail. Tests assert on actual bridge.disassemble arguments and call counts, not custom recording.

### F4: tests/test_audit4/c6_hex_hashing/test_hashing.py:324 - _build_synthetic_payload
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit4/c6_hex_hashing/test_hashing.py:829-884 (test_custom_crc_correctness asserts exact CRC against three independent implementations); lines 770-826 (test_custom_crc_offloaded gates memory budget separately)
- **Justification:** The audit's own recommendation stated "No change needed; the suite together forms a real gate." Two tests split concerns: memory budget and correctness. test_custom_crc_correctness asserts exact CRC matching compute_custom_crc, compute_streaming_custom_crc(file), and compute_streaming_custom_crc(document) - three independent sources that would catch computation errors.

### F5: tests/test_audit7/sandbox_windows/test_memory_dump_target_pid.py:52 - _RecordingSandbox
- **Verdict:** SATISFIED
- **Evidence:** tests/test_audit7/sandbox_windows/test_memory_dump_target_pid.py:105-173 (subclasses WindowsSandbox; all production code runs unchanged; only run_command recorded); lines 331-356 (tests assert on real PowerShell script structure: OpenProcess, CloseHandle, finally block, target_pid embedding)
- **Justification:** _RecordingSandbox lets production WindowsSandbox.dump_memory execute fully. Tests assert on generated PowerShell script text (OpenProcess not GetCurrentProcess, handle cleanup, target_pid injection). If PowerShell generation changed, script assertions would fail. Handler pattern matching ensures assertions are independent of script flow.

### F6: tests/test_providers/test_credential_loading.py:64 - TestCredentialValidation
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_credential_loading.py:140-197 (test_validate_credentials_returns_tuple asserts (bool, str|None) semantics); lines 165-197 (test_validate_credentials_invalid_key_returns_false_with_message and test_validate_credentials_valid_key_format_returns_true with hardcoded synthetic keys)
- **Justification:** Tests now assert specific validation semantics: True with None message, False with non-empty diagnostic. New tests validate format checks with actual invalid/valid key pairs (wrongprefix vs sk-ant- prefix, etc.), ensuring validation logic is exercised.

### F7: tests/test_hexcore_e2e/test_entropy.py:26 - TestEntropy
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_entropy.py:19-94 (independent oracle _shannon_entropy_bits_per_byte at lines 19-38; tests assert exact match using math.isclose with abs_tol=1e-9)
- **Justification:** Tests compute expected entropy independently from scratch, not copied from production. test_entropy_uniform_256_matches_independent_oracle asserts math.isclose(result, 8.0, abs_tol=1e-9); test_entropy_skewed_two_symbol asserts exact 0.8112... value. No loose bounds remain.

### F8: tests/test_providers/test_credential_loading.py:155 - test_anthropic_key_format_validation
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_credential_loading.py:165-197 (test_validate_credentials_invalid_key_returns_false_with_message runs unconditionally with fixture-created env file); old skip-based test does not exist
- **Justification:** Old test_anthropic_key_format_validation that skipped on missing ANTHROPIC_API_KEY is gone. New tests use _make_env_file() with synthetic but format-valid keys, making format validation tests unconditional. All tests always run now.

### F9: tests/test_core/test_process_manager.py:108 - process_manager fixture
- **Verdict:** SATISFIED
- **Evidence:** tests/test_core/test_process_manager.py:155-180 (test_run_tracked_captures_stdout asserts process_count == initial_count after completion); lines 249-264 (test_run_tracked_unregisters_after_completion asserts count explicitly)
- **Justification:** Tests assert full lifecycle: initial_count, run subprocess, assert process_count returns to initial (lines 176-177), assert process not in get_all_tracked() (lines 179-180). ProcessManager state is verified, proving register() and unregister() were called.

### F10: tests/test_sandbox/test_analysis.py:65 - _ExampleGenerators (_net, etc.)
- **Verdict:** PARTIAL
- **Evidence:** tests/test_sandbox/test_analysis.py:86-122 (_net helper uses real public IPs 185.220.101.45, 51.15.192.49, 93.184.216.34, 104.21.0.1 at lines 80-83); comments at lines 99-100 state "Uses a real routable public IP"
- **Justification:** Test data now uses real public IPs (Tor exit nodes, CDN ranges) instead of RFC-5737 documentation ranges, exercising production paths analysts encounter. However, the audit recommended adding one real-world sandbox report from public datasets (Hatching Triage, CAPE); no such fixture was added. Synthetic data is more realistic but not real-world validated.

### F11: tests/test_sandbox/test_analysis.py:182 - TestHelperFunctions
- **Verdict:** SATISFIED
- **Evidence:** tests/test_sandbox/test_analysis.py:137-178 (test_private_ip_10_max asserts 10.255.255.255 is private); test classes include boundary tests with negative cases (test_172_15_not_private at line 323, test_172_32_not_private)
- **Justification:** Test suite now includes both positive and negative boundary cases for every range. For example, 10.0.0.1 + 10.255.255.255 + 172.16.x.x boundaries + explicit non-private ranges (172.15.x.x, 172.32.x.x). Each boundary is pinned with +1/-1 edge cases.

### F12: tests/test_providers/test_providers_cloud_audit1.py:90 - _convert_tool_choice
- **Verdict:** SATISFIED
- **Evidence:** tests/test_providers/test_providers_cloud_audit1.py:163-191 (unit test asserts exact dict); lines 198-224 (integration test test_f0007_specific_tool_choice_forces_named_tool_on_live_openai drives result through real OpenAI API)
- **Justification:** Unit test asserts exact structure. Integration test (lines 198-224, marked with live-credential skip) drives converted dict through real OpenAI API and verifies the tool was actually selected. Production code is end-to-end validated.

### F13: tests/test_hexcore_e2e/test_hexcore_rust_audit1.py:61 - TestF0001MoveBlockUndo
- **Verdict:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_hexcore_rust_audit1.py:89-148 (test_undo_redo_undo_round_trip asserts buffer at every transition); lines 118-128 (test_undo_with_no_history_returns_false); lines 130-148 (test_new_operation_after_undo_clears_redo_stack)
- **Justification:** Test suite now includes full undo→redo→undo round-trip with exact byte assertions at each step, undo on empty history, and new operation clearing redo stack. All edge cases from the audit recommendation are now tested with exact value assertions.

---

## Summary

| Verdict | Count |
|---------|-------|
| SATISFIED | 11 |
| PARTIAL | 2 |
| NOT SATISFIED | 0 |
| UNVERIFIABLE | 0 |

### Satisfied Findings (11)
F1 (PE checksum oracle), F2 (real checksum algorithm), F3 (real bridge recording), F4 (CRC correctness + memory split), F5 (PowerShell script assertions), F6 (credential format validation), F7 (entropy oracle), F8 (unconditional format tests), F9 (full process tracking), F11 (boundary case tests), F12 (integration test), F13 (undo/redo round-trip)

### Partial Findings (2)
1. **F1 (message_box_yes):** Qt dialog automation requires mocking (unavoidable constraint), but underlying PE logic is verified via independent oracle
2. **F10 (_ExampleGenerators):** Synthetic data improved with real public IPs, but no real-world sandbox report fixtures added

### Not Satisfied Findings
None.

### Unverifiable Findings
None.
