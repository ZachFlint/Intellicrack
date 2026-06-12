# Review of Agent 13 Audit Findings

## Methodology

This review examines each finding in `audit/agent-13.md` against the actual code at HEAD (commit c78780c1). For each finding, I:
1. Read the production source code and test code at the cited lines
2. Evaluated whether the test is a genuine, falsifiable gate or a mock-based test that doesn't verify real behavior
3. Checked if the violation has been remediated in committed code

---

## Finding Reviews

### Finding 1: test_availability_caching.py:183-196 - test_cached_success_stored_in_dict

**Verdict: NOT-SATISFIED**

**Evidence:** 
- Test file line 183-196 still uses `patch.object(manager, "_probe_type", new_callable=AsyncMock)`
- Line 188: `with patch.object(manager, "_probe_type", new_callable=AsyncMock) as mock_probe:`
- Production code manager.py still has real _probe_type at line 168 that instantiates WindowsSandbox/QEMUSandbox

**Justification:** 
The test mocks away the entire _probe_type method and verifies only that the cache dict was populated with the mocked result, not that real sandbox probes would be cached correctly.

---

### Finding 2: test_availability_caching.py:80-106 - test_probe_called_once_per_type_across_five_calls

**Verdict: NOT-SATISFIED**

**Evidence:**
- Test file line 80-106 uses `patch.object(manager, "_probe_type", side_effect=fake_probe)` at line 95
- Line 90-92: defines fake_probe returning True instead of testing real sandbox availability
- Production manager.py _probe_type at line 168-195 is the real implementation to be tested

**Justification:**
The test patches _probe_type with a fake function that always returns True and doesn't test caching against real sandbox implementations or platform-detection logic.

---

### Finding 3: test_availability_caching.py:108-122 - test_successful_result_returned_consistently

**Verdict: NOT-SATISFIED**

**Evidence:**
- Test file line 108-122 uses `patch.object(manager, "_probe_type", side_effect=fake_probe)` at line 116
- Line 112-113: defines fake_probe returning True
- Production manager.py _get_type_available at line 197-221 requires real probe behavior for full validation

**Justification:**
The test patches the actual probe method and replaces it with a fake that always returns True, which does not test caching behavior against real sandbox availability checks.

---

### Finding 4: test_script_gen.py:349+ - test_script_get_extension and simple assertion tests

**Verdict: PARTIAL**

**Evidence:**
- test_script_get_extension at line 343-355 asserts only enum.value == expected string
- However, test_script_manager_save_uses_language_extension_on_disk at line 358-387 was added, which writes to disk and verifies the actual file extension

**Justification:**
The original test_script_get_extension (line 343-355) is still a weak assertion test that only verifies enum values. However, a new integration test (line 358-387) was added that exercises the real save path and verifies the file extension on disk, creating a genuine gate for the functionality.

---

### Finding 5: test_ghidra_f11_audit.py:64-99 - test_f11_define_structure_logging & test_f11_create_function_logging

**Verdict: SATISFIED**

**Evidence:**
- Test file line 96-121 (test_f11_define_structure_translates_and_logs_remote_failure): Uses `structlog.testing.capture_logs()` at line 106 to capture real logs
- Line 106: `with structlog.testing.capture_logs() as captured, pytest.raises(ToolError) as exc_info:`
- Line 117-120: Asserts actual structured log output including log_level, struct_name, and error message
- No mock_logger patch; uses real logging infrastructure

**Justification:**
The test removed the mock_logger patch and now uses structlog.testing.capture_logs() to verify actual logging behavior, creating a genuine gate for error handling and logging.

---

### Finding 6: test_bridge_bit_ops.py:53-93 - test_get_bit_returns_correct_values & similar bit operation tests

**Verdict: SATISFIED**

**Evidence:**
- test_every_bit_of_known_byte_matches_lsb0_oracle at line 93-107 tests against real binary (b"\xa5") at line 101
- test_all_bytes_all_bits_match_oracle_across_offsets at line 109-124 tests comprehensive pattern matching
- test_get_bit_is_deterministic_across_repeated_calls at line 126-139 verifies determinism across repeated calls
- test_bit_index_out_of_range_raises at line 142+ tests boundary cases
- Production code exercises real bridge operations on real binary data

**Justification:**
The tests exercise real binary data, verify determinism with repeated calls, test boundary cases, and check against independently-known oracle values (LSB-0 bit layout), creating a comprehensive falsifiable gate.

---

### Finding 7: test_log_parsers.py:127-177 - parse_file_log and parse_registry_log tests

**Verdict: PARTIAL**

**Evidence:**
- test_parses_minimal_three_field_lines at line 127-144 writes minimal log data and asserts field extraction
- test_extracts_old_path_and_size at line 147-161 tests additional fields
- test_skips_lines_below_min_parts at line 164-177 tests error handling
- However, only tests simple, well-formed inputs; no tests for real-world malformed inputs as recommended

**Justification:**
The tests verify correct parsing of simple inputs and basic error handling, but do not test edge cases like escaped pipe characters, special characters in paths, missing fields at boundaries, or non-ASCII characters as the finding recommends.

---

### Finding 8: test_hashing.py:101-127 - test_sha3_256_matches_hashlib_if_supported & test_sha3_512_matches_hashlib_if_supported

**Verdict: SATISFIED**

**Evidence:**
- test_sha3_256_matches_hashlib at line 101-113: No pytest.skip; unconditionally tests SHA3-256 against hashlib
- test_sha3_512_matches_hashlib at line 115-127: No pytest.skip; unconditionally tests SHA3-512 against hashlib
- test_sha3_256_empty_matches_nist_known_answer at line 129-140: Tests against NIST KAT value
- No conditional skips that hide failures

**Justification:**
The tests have been rewritten to unconditionally test SHA3-256 and SHA3-512 (treating them as guaranteed-available algorithms), removing the pytest.skip that could hide failures. They now verify against both hashlib and NIST known-answer test values.

---

## Summary Tally

| Verdict | Count |
|---------|-------|
| SATISFIED | 3 |
| PARTIAL | 2 |
| NOT-SATISFIED | 3 |
| UNVERIFIABLE | 0 |

**Total Findings Reviewed: 8**

### Breakdown

**SATISFIED (3):**
- test_ghidra_f11_audit.py: Real logging capture replaced mock (Finding 5)
- test_bridge_bit_ops.py: Comprehensive real binary testing with determinism checks (Finding 6)
- test_hashing.py: SHA3 tests now unconditional with KAT verification (Finding 8)

**PARTIAL (2):**
- test_script_gen.py: Original weak assertion test still present, but new disk-write integration test added (Finding 4)
- test_log_parsers.py: Basic parsing tests present, but edge cases with malformed/special inputs missing (Finding 7)

**NOT-SATISFIED (3):**
- test_availability_caching.py:80-106: test_probe_called_once_per_type_across_five_calls still mocks _probe_type (Finding 2)
- test_availability_caching.py:108-122: test_successful_result_returned_consistently still mocks _probe_type (Finding 3)
- test_availability_caching.py:183-196: test_cached_success_stored_in_dict still uses AsyncMock for _probe_type (Finding 1)
