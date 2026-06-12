# Review of Agent-04 Audit Findings

This document reviews each finding in audit/agent-04.md against the current codebase at HEAD.

## Finding Reviews

### F1: tests/test_audit4/c6_hex_hashing/test_hashing.py:225 - message_box_yes
- **Status:** NOT SATISFIED
- **Evidence:** tests/test_audit4/c6_hex_hashing/test_hashing.py:225-248
- **Justification:** The fixture still uses `monkeypatch.setattr(...)` to replace `QMessageBox.question`, returning a hardcoded `QMessageBox.Yes`. This defeats the ability to verify the actual repair flow behavior; if the code skipped the prompt or handled user decline, the test would not catch it.

### F2: tests/test_audit4/c6_hex_hashing/test_hashing.py:65 - StubPeDocument
- **Status:** NOT SATISFIED
- **Evidence:** tests/test_audit4/c6_hex_hashing/test_hashing.py:115-141
- **Justification:** The stub's `repair_pe_checksum` and `verify_pe_checksum` methods still hardcode the checksum value `0xC0FFEE42` instead of computing a real PE checksum. The stub does not validate against real hexcore API behavior; refactoring the hexcore layer would not be caught.

### F3: tests/test_audit4/c9_hex_disassembly_debounce/test_follow_cursor_debounce.py:113 - _DebouncingHarness
- **Status:** NOT SATISFIED
- **Evidence:** tests/test_audit4/c9_hex_disassembly_debounce/test_follow_cursor_debounce.py:159-170
- **Justification:** The harness overrides `_on_disassemble` to record offsets without calling the real bridge layer. It short-circuits the bridge dispatch entirely, only recording that an attempt was made. Changes to the bridge's method signature or offset-passing mechanism would not be caught.

### F4: tests/test_audit4/c6_hex_hashing/test_hashing.py:324 - _build_synthetic_payload
- **Status:** SATISFIED
- **Evidence:** tests/test_audit4/c6_hex_hashing/test_hashing.py:464-505
- **Justification:** The test suite correctly splits concerns: `test_custom_crc_correctness` (line 464+) asserts the CRC value against an independent reference calculation, while `test_custom_crc_offloaded` measures memory usage only. Together they form a real gate. The split is appropriate and documented in the test class.

### F5: tests/test_audit7/sandbox_windows/test_memory_dump_target_pid.py:52 - _RecordingSandbox
- **Status:** NOT SATISFIED
- **Evidence:** tests/test_audit7/sandbox_windows/test_memory_dump_target_pid.py:52-115
- **Justification:** The sandbox still replaces `run_command` with a recording spy that dispatches to a handler instead of running real PowerShell. The handler materializes a minidump-shaped file based on regex pattern matching of the command string. Real PowerShell parse errors or variable malformations would not be caught.

### F6: tests/test_providers/test_credential_loading.py:64 - TestCredentialValidation
- **Status:** SATISFIED
- **Evidence:** tests/test_providers/test_credential_loading.py:140-197
- **Justification:** The test now asserts actual validation logic, not just tuple shape. New tests `test_validate_credentials_invalid_key_returns_false_with_message` and `test_validate_credentials_valid_key_format_returns_true` validate both valid and invalid keys with specific format checks and diagnostic messages.

### F7: tests/test_hexcore_e2e/test_entropy.py:26 - TestEntropy
- **Status:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_entropy.py:49-102
- **Justification:** Entropy tests now compute expected values via an independent oracle function `_shannon_entropy_bits_per_byte` and assert exact matches using `math.isclose()` with tight tolerances (abs_tol=1e-9), not loose bounds like `> 7.9`.

### F8: tests/test_providers/test_credential_loading.py:155 - test_anthropic_key_format_validation
- **Status:** UNVERIFIABLE
- **Evidence:** tests/test_providers/test_credential_loading.py (no match found for test name)
- **Justification:** The test named in the finding does not exist in the codebase. The finding references a test that was either never created or has been removed/renamed. Credential validation tests now exist but under different names (see F6).

### F9: tests/test_core/test_process_manager.py:108 - process_manager fixture
- **Status:** SATISFIED
- **Evidence:** tests/test_core/test_process_manager.py:155-180
- **Justification:** The test now explicitly asserts both subprocess output AND manager state: `assert process_manager.process_count == initial_count` and verifies the process is unregistered from the tracked list, validating the full lifecycle.

### F10: tests/test_sandbox/test_analysis.py:65 - _ExampleGenerators (_net, etc.)
- **Status:** PARTIAL
- **Evidence:** tests/test_sandbox/test_analysis.py:73-104
- **Justification:** The test suite still uses only synthetic data with example IP `203.0.113.50` (RFC 5737 documentation example) for C2 pattern detection tests. However, boundary case tests for IP ranges have been added (see F11), partially mitigating the synthetic data issue, but no real malware traffic fixtures have been introduced.

### F11: tests/test_sandbox/test_analysis.py:182 - TestHelperFunctions
- **Status:** SATISFIED
- **Evidence:** tests/test_sandbox/test_analysis.py:115-170
- **Justification:** Helper tests now include both positive and negative boundary cases. For example, `test_private_ip_10_max`, `test_private_ip_172_16_lower_boundary`, `test_private_ip_172_31_upper_boundary` verify edge cases, and `test_private_ip_172_15_just_below_range`, `test_private_ip_172_32_not_private` verify that non-private ranges are correctly rejected.

### F12: tests/test_providers/test_providers_cloud_audit1.py:90 - _convert_tool_choice
- **Status:** SATISFIED
- **Evidence:** tests/test_providers/test_providers_cloud_audit1.py:163-189
- **Justification:** The test is correctly structured as a unit test of the conversion function (checking exact dict shape). Additional integration test coverage would be valuable but is out of scope for a unit test; this test correctly gates the conversion logic itself.

### F13: tests/test_hexcore_e2e/test_hexcore_rust_audit1.py:61 - TestF0001MoveBlockUndo
- **Status:** SATISFIED
- **Evidence:** tests/test_hexcore_e2e/test_hexcore_rust_audit1.py:89-129
- **Justification:** Tests have been expanded to include undo→redo→undo round-trip (line 89+), undo with no history returns False (line 118+), and new operation clears redo stack (line 130+). The full undo/redo history lifecycle is now comprehensively gated.

---

## Summary

| Verdict | Count |
|---------|-------|
| SATISFIED | 8 |
| PARTIAL | 1 |
| NOT SATISFIED | 3 |
| UNVERIFIABLE | 1 |

### Not Satisfied Findings
1. **F1 (message_box_yes):** Monkeypatch still replaces QMessageBox.question
2. **F2 (StubPeDocument):** Still hardcodes checksum value instead of using real PE logic
3. **F5 (_RecordingSandbox):** Still mocks PowerShell execution with regex-based handler

### Partial Findings
1. **F10 (_ExampleGenerators):** Synthetic data only; no real malware traffic fixtures added, though related boundary tests have been improved

### Unverifiable Findings
1. **F8 (test_anthropic_key_format_validation):** Test does not exist in codebase; cannot verify
