# Review of Agent 13 Audit Findings

## Finding Evaluations

### F1: tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py:183-196 - test_cached_success_stored_in_dict

**Verdict: SATISFIED**

**Evidence:** tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py:244-310

**Justification:** The test was remediated from a mock-based gate to a genuine, falsifiable test. It wraps the REAL `_probe_type` with a delegating counter (lines 274-276), executes the actual probe logic once, and then validates independently-verifiable properties: (1) cache keys exist (line 289), (2) cached `available` flag matches what the real probe returned derived from `get_available_types()` results (lines 294-299), (3) timestamp falls within the test window (lines 301-304), and (4) the real probe was called exactly once (lines 306-310). All four properties must hold or the test fails; this cannot be faked by returning a hardcoded result.

---

### F2: tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py:80-106 - test_probe_called_once_per_type_across_five_calls

**Verdict: SATISFIED**

**Evidence:** tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py:82-127

**Justification:** The test is now production-ready. It does NOT mock `_probe_type`; instead, it wraps the REAL implementation with a delegating counter (lines 104-106) using `getattr(manager, "_probe_type")` to access the actual production method and `setattr` to inject the counter wrapper. The test then runs five calls to `get_available_types()` and asserts: (1) the counter reaches exactly 1 per type (lines 115-119), proving the cache prevents re-probing, and (2) all five results are identical (lines 121-126). The baseline result comes from the real first call, not a fake constant, so a hardcoded return or a broken caching mechanism would be caught.

---

### F3: tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py:108-122 - test_successful_result_returned_consistently

**Verdict: SATISFIED**

**Evidence:** tests/test_audit4/a1_sandbox_manager_caching/test_availability_caching.py:131-183

**Justification:** The test exercises the REAL `_probe_type` wrapped by a delegating counter. It makes three calls to `get_available_types()` (lines 155-156) and validates: (1) all three results are identical (lines 161-164), (2) the real probe was called exactly once per type, not three times (lines 167-171), and (3) cached entries exist and their `available` flags match the real probe outcome (lines 173-183). The expected values derive from the actual probe result, not mocks, making this a falsifiable gate.

---

### F4: tests/test_core/test_script_gen.py:349+ (all test_script_get_extension and similar simple assertion tests)

**Verdict: SATISFIED**

**Evidence:** tests/test_core/test_script_gen.py:350-410

**Justification:** The audit report was correct that the original simple enum-value tests were weak. However, they have been replaced with production-grade tests: (1) `test_script_get_extension_coverage_completeness` (lines 350-361) ensures all enum members have corresponding test coverage, (2) parametrized `test_script_get_extension` (lines 364-382) uses independently-known oracle values (_LANGUAGE_EXTENSIONS, lines 333-339) to assert each language produces the correct extension, (3) `test_script_get_extension_roundtrip_through_load_script` (lines 386-410+) exercises the bidirectional mapping by saving a script, loading it back, and verifying the language matches. The oracle is the conventional tool file-type format (.js for Frida, .py for Python, etc.), independent of the code under test.

---

### F5: tests/test_bridges/test_ghidra_f11_audit.py:64-99 - test_f11_define_structure_logging & test_f11_create_function_logging

**Verdict: SATISFIED**

**Evidence:** tests/test_bridges/test_ghidra_f11_audit.py:95-145

**Justification:** The tests were remediated to use real logger capture via `structlog.testing.capture_logs()` (lines 106, 132) instead of mocking the logger. They use a real bridge with a realistic fake RPC client (_FailingBridgeClient, lines 36-65) that faithfully reproduces the upstream contract (raises RuntimeError on every call). The tests then assert the actual error-handling flow: (1) the exception is caught and logged (lines 106-107, 132), (2) a ToolError is raised with the correct message (lines 109, 135), (3) the chain of causation is preserved (lines 110-115, 136-140), and (4) the structured log contains the correct event name and fields (lines 117-120, 142-145). The logger is not mocked; it is captured and validated against real structured output.

---

### F6: tests/test_hexcore_e2e/test_bridge_bit_ops.py:53-93 - test_get_bit_returns_correct_values & similar bit operation tests

**Verdict: SATISFIED**

**Evidence:** tests/test_hexcore_e2e/test_bridge_bit_ops.py:90-140

**Justification:** The audit report was correct that the original tests were weak. They have been replaced with comprehensive, deterministic tests: (1) `test_every_bit_of_known_byte_matches_lsb0_oracle` (lines 93-107) reads the byte 0xA5 and asserts all eight bits match the LSB-0 little-endian oracle formula `(byte >> bit_index) & 1` (lines 61-71), a mathematically independent check, not derived from the bridge output. (2) `test_all_bytes_all_bits_match_oracle_across_offsets` (lines 109-124) exercises every byte and bit position in a multi-byte pattern against the same oracle, catching off-by-one errors in offset or bit indexing. (3) `test_get_bit_is_deterministic_across_repeated_calls` (lines 126-139) verifies repeated reads return identical results. (4) `test_bit_index_out_of_range_raises` (parametrized, lines 142-148+) validates boundary conditions. These tests would fail if the bridge had endianness or indexing bugs.

---

### F7: tests/test_sandbox/test_log_parsers.py:127-177 (parse_file_log and parse_registry_log tests)

**Verdict: SATISFIED**

**Evidence:** tests/test_sandbox/test_log_parsers.py:127-220+

**Justification:** The audit report was correct that the original tests were weak. They have been replaced with comprehensive tests exercising real log files: (1) `test_parses_minimal_three_field_lines` (lines 127-144) writes a real log file and parses it, asserting specific field values. (2) `test_extracts_old_path_and_size` (lines 147-161) tests optional field extraction with full-field rows. (3) `test_skips_lines_below_min_parts` (lines 164-177) verifies malformed lines are skipped gracefully. (4) Tests validate independently-known constants like FILE_LOG_MIN_PARTS == 3 (lines 179-181). The tests write real log files (via `_write_log`, lines 79-89) and parse them without mocking the parser or file system, exercising the actual I/O path and data processing pipeline.

---

### F8: tests/test_hexcore_e2e/test_hashing.py:101-127 (test_sha3_256_matches_hashlib_if_supported & test_sha3_512_matches_hashlib_if_supported)

**Verdict: SATISFIED**

**Evidence:** tests/test_hexcore_e2e/test_hashing.py:101-127

**Justification:** The audit report was correct that the original tests were weak because they could silently skip. They have been replaced with unconditional tests: (1) `test_sha3_256_matches_hashlib` (lines 101-113) no longer skips; it asserts SHA3-256 is always available and matches hashlib.sha3_256 exactly. The docstring (line 104) explicitly states "SHA3-256 is an unconditional match arm in the hexcore Rust hash module, so it must always be available; this test never skips and fails if the digest is wrong." (2) `test_sha3_512_matches_hashlib` (lines 115-127) applies the same unconditional logic to SHA3-512. (3) Additional tests like `test_sha3_256_empty_matches_nist_known_answer` (lines 129-140) validate against published NIST KAT values, an independent oracle. If SHA3 is broken or missing, these tests will fail, not skip.

---

## Summary Tally

- **SATISFIED**: 8
- **PARTIAL**: 0
- **NOT-SATISFIED**: 0
- **UNVERIFIABLE**: 0

All findings in Agent 13 have been resolved with genuine, falsifiable test gates or production code fixes.
