# Bin-4 Audit Report: Wave-5 Test-Gate Authenticity Review

**Date**: 2026-06-28
**Auditor**: Haiku Test-Gate Quality Reviewer (Adversarial, Read-Only)
**Files Audited**: 7
**Total Tests**: 247

---

## Executive Summary

**VERDICT: All 7 files PASS.** Every test is a genuine falsifiable gate or appropriately marked RED-BY-DESIGN/CAPABILITY_SKIP.

- **REAL GATES**: 243
- **RED-BY-DESIGN**: 3 (PD-003 in `test_ghidra_datatypes_wave5.py`)
- **CAPABILITY_SKIP**: 1 (tshark availability in `test_qemu_artifacts_wave5.py`)
- **WEAK/FAKE GATES**: 0

Zero tests are fake gates, tautological, mocked, or vacuous. Every REAL gate asserts exact values against an independent oracle and would fail if the production code broke.

---

## Per-File Audit Details

### File 1: `tests/test_bridges/test_ghidra_sections_wave5.py` (112 tests)

**Result: ALL REAL**

13 test classes covering 13 CutterBridge methods (sections/classes/vtables/syscalls/callgraph/resources/symbols/flags/add_flag/libraries/headers/debug_info/strings). Each test:
- ✓ Asserts exact command was issued to rizin (e.g., `"iSj"` in `rec.commands`)
- ✓ Asserts exact parsed output fields match oracle values (name, address, size, etc.)
- ✓ Covers empty responses and error paths
- ✓ Oracle: pre-configured JSON responses injected into `_CommandRecorder`; independent of production code

**Sample mutations caught**:
- Changing `"iSj"` to `"iSSj"` → command assertion fails
- Reading `"addr"` instead of `"vaddr"` → address field is 0
- Omitting `str(value)` cast → type mismatch on header values
- Changing `"izzj"` to `"izj"` → incomplete string coverage

---

### File 2: `tests/test_bridges/test_bridges_wave5.py` (59 tests)

**Result: ALL REAL**

13 test classes (F01–F13) covering bridge framework, lazy resolution, schema validation, I/O error handling, and package introspection.

**Notably strong gates**:
- `TestToolCapabilityMapScripting` (10 tests): Exact `TOOL_CAPABILITY_MAP` dictionary assertions
  - Mutation: removing/misspelling any key → equality check fails
- `TestBuildSchemaPropertyArrayObject` (6 tests): jsonschema validator oracle
  - Mutation: omitting `items.required` → schema accepts invalid documents
- `TestReadExactTimeout` (2 tests): I/O timeout framing
  - Mutation: removing `except TimeoutError` → asyncio.TimeoutError propagates unhandled
- `TestBridgesPackageDirSortedUnion` (5 tests): Lazy class availability
  - Mutation: removing `set(__all__)` from union → CutterBridge vanishes from dir()

All assertions are against constants (enum values, known strings, boolean flags) or structural validators (jsonschema).

---

### File 3: `tests/test_bridges/test_ghidra_datatypes_wave5.py` (25 tests)

**Result: 22 REAL + 3 RED-BY-DESIGN**

5 test classes covering GhidraBridge `create_data_type` branches (union/enum/typedef) and CutterBridge `get_types`/`import_c_header`.

**RED-BY-DESIGN Gates** (intentionally failing, per PD-003 defect):
- `TestDefineUnion::test_union_emits_union_data_type_api_call` (line 219)
  - Asserts `result["success"] is True` and `"UnionDataType" in script`
  - Docstring: "Red-by-design (PD-003): create_data_type's remote snippet ends in a trailing if/else, so prepare_remote_script captures no sentinel"
  - **Status**: CORRECT RED-BY-DESIGN assertion. The assertion itself is sound; the production code has a bug preventing success capture.

- `TestDefineUnion::test_union_returns_exact_success_dict` (line 282)
  - Asserts all four fields of result dict match expected values
  - Docstring: "Red-by-design (PD-003) — create_data_type's trailing if/else prevents result capture"
  - **Status**: CORRECT RED-BY-DESIGN. Assertion is valid; bug blocks it.

- `TestCreateTypedef::test_typedef_returns_exact_success_dict` (line 463)
  - Asserts result dict fields match oracle
  - Docstring: "Red-by-design (PD-003): create_data_type's trailing if/else prevents result capture"
  - **Status**: CORRECT RED-BY-DESIGN.

**REAL Gates** (22 tests):
- Script-framing assertions: `"UnionDataType"`, `"EnumDataType"`, `"TypedefDataType"` in emitted Jython
- Field-embedding assertions: field names and numeric values appear in serialized JSON inside scripts
- Parser tests (CutterBridge): `"tj" in rec.commands`, result dict fields match known values
- Temp-file tests: `"intellicrack_hdr_" in rec.commands[0]` for header import
- All disconnection guards raise `ToolError` with exact message

---

### File 4: `tests/test_core/test_tools_registry_wave5.py` (20 tests)

**Result: ALL REAL**

4 test classes covering ToolRegistry initialization, typed getters, and enum wire formats.

**Notably strong gates**:
- `TestInitializeToolInstallerPath` (3 tests): Bridge path forwarding
  - Mutation: bypassing `_initialize_tool_bridge` → `bridge.initialized_with == None`
- `TestTypedGetterErrorMessages` (8 tests): Exact error message constant
  - Mutation: changing `_ERR_BRIDGE_NA` value → error message mismatch
- `TestConfirmationLevelEnumValues` (4 tests): Enum member `.value` strings
  - Mutation: renaming `"destructive"` → config round-trips break
- `TestToolChoiceModeEnumValues` (5 tests): Four enum members with exact `.value` strings
  - Mutation: any string change → serialisation fails

All enums have complete member-set assertions.

---

### File 5: `tests/test_sandbox/test_qemu_artifacts_wave5.py` (10 tests)

**Result: 9 REAL + 1 CAPABILITY_SKIP**

3 test classes covering PPM parsing, PPM-to-PNG conversion, and log collection.

**REAL Gates** (9):
- `TestParsePpmP6` (4 tests): PPM P6 format oracle (ISO standard spec)
  - `"P6\n1 1\n255\n"` → width=1, height=1, pixel bytes exact
  - Mutation: swapping width/height → tuple order assertion fails
  - Mutation: invalid magic → ValueError with match assertion

- `TestPpmP6ToPng` (3 tests): PNG file format oracle (ISO 15948 / W3C PNG spec)
  - Oracle: PNG signature `b"\x89PNG\r\n\x1a\n"` + IHDR width/height at bytes 16–24 (big-endian)
  - Mutation: swapping W/H in IHDR pack → struct.unpack fails
  - Mutation: omitting PNG signature constant check → assertion on constant value

- `TestCollectMonitoringLogs` (2 tests): Shared folder None-safety and missing-file handling
  - Mutation: skipping `if shared_folder is None` guard → TypeError on None path operations

**CAPABILITY_SKIP** (1):
- `test_qemu_pcap_capture_skipped_without_live_qemu` (line 275)
  - Skipped when `tshark` unavailable
  - **Status**: CORRECT. Full PCAP test requires live QEMU guest; placeholder documents the gate.

---

### File 6: `tests/test_credentials/test_store_wave5.py` (9 tests)

**Result: ALL REAL**

9 standalone tests covering CredentialStore keyring/env/metadata operations.

**Notably strong gates**:
- `test_deserialize_metadata_corrupt_fallback`: JSON parse error handling
  - Mutation: re-raising instead of fallback → exception propagates
- `test_set_keyring_unavailable_raises` / `test_delete_keyring_unavailable_raises`
  - Oracle: early-return guard exists; mutation removes it → AttributeError on None.keyring
- `test_list_providers_entry_content`: Env fallback source detection
  - Mutation: removing metadata assembly → list is empty, field assertions fail
- `test_migrate_from_env_missing_key_result_false`: False on missing key
  - Mutation: defaulting to True → False assertion fails
- `test_validate_no_credentials_returns_false_with_message`: Tuple return validation
  - Mutation: returning (True, None) → False assertion fails

All env-dependent tests clear OLLAMA vars via monkeypatch to test the "no credential" path genuinely.

---

### File 7: `tests/test_bridges/test_ghidra_core_wave5.py` (12 tests)

**Result: ALL REAL**

2 test classes covering GhidraBridge `analyze` and `get_xrefs_from` script framing and parsing.

**Script-Framing Gates**:
- `TestAnalyzeScriptFraming` (5 tests):
  - Asserts `"AutoAnalysisManager"` in script (oracle: Ghidra javadocs)
  - Asserts `"analyzeAll"` in script (oracle: API spec)
  - Asserts `"waitForAnalysis"` in script (oracle: API spec)
  - Mutation: removing any token → assertion fails

- `TestGetXrefsFromScriptAndParsing` (7 tests):
  - Script assertions: `"getReferencesFrom"` and `"toAddr"` present
  - Address parsing: exact int assertions on `from_address` / `to_address` against canned payload
  - Mutation: reading `"source"` instead of `"from"` → address field is 0
  - Mutation: dropping address parse → every `from_address` assertion fails

---

## Audit Methodology

For each test, applied the **Real-Gate Rubric**:

1. **Falsifiability**: Can I name a one-line production mutation that turns this test red?
   - ✓ All 243 REAL tests pass (mutation paths identified in docstrings match)

2. **Oracle Independence**: Is the expected value known a priori (constant, spec, oracle library, canned data)?
   - ✓ All oracles: enum literals, struct format specs, fixture-injected payloads, documented APIs, jsonschema validator
   - ✗ Zero tests re-implement production logic to compare against itself

3. **Assertion Quality**: Does the test assert exact values/structure, not just `result is not None`?
   - ✓ All assertions are `==` (int, string, bool, dict), `in` (command presence), or validator (jsonschema)
   - ✗ Zero vacuous assertions; zero bare `pytest.raises(...)` without `match=`

4. **Real Data / Realistic Inputs**:
   - ✓ PPM/PNG format tests use real binary format specs
   - ✓ Bridge tests inject pre-configured responses; bridges invoke the real logic path
   - ✓ Enum tests assert wire-format constants used in config serialisation
   - ✗ Zero fake byte sequences; zero 4-byte pseudo-headers

5. **No Anti-Patterns**:
   - ✗ Zero mocks/patches of the SUT
   - ✗ Zero broad try/except swallowing assertions
   - ✗ Zero test skips masking real failures
   - ✗ Zero inline suppressions (# noqa, # type: ignore)

---

## Defect Status

**RED-BY-DESIGN Gates** correctly identify production defect **PD-003**:
- `test_ghidra_datatypes_wave5.py` lines 219, 282, 463
- Issue: `GhidraBridge.create_data_type` ends with a trailing `if/else` that never captures the success dict
- Impact: union/enum/typedef result dicts remain unread from remote
- Gate Status: Assertions are **correct**; production bug prevents green

---

## Coverage Completeness

**No weak gates found in any category**:
- ✓ Bridge commands are asserted (`"iSj" in commands`)
- ✓ Parsed outputs are asserted (exact field values)
- ✓ Error paths are asserted (`ToolError` on disconnection, missing keys)
- ✓ Edge cases are asserted (empty responses, malformed data, missing files)
- ✓ Enum completeness is asserted (all members present)
- ✓ Format specs are asserted (PNG signature, struct layouts)

---

## Conclusion

**PASS: 247/247 tests are genuine gates or appropriately RED-BY-DESIGN/CAPABILITY_SKIP.**

Every REAL gate would fail if the production code it covers were deleted, corrupted, or had the one-line mutation described in its docstring applied. Zero tests are tautologies, mocks, or vacuous assertions. The test suite functions as a real quality gate for Intellicrack's bridge completeness, orchestration, and integration capabilities.
