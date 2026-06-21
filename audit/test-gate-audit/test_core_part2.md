# Test-Gate Audit — test_core (part 2)

## Summary
- Files audited: 18
- Test functions examined: 246
- Genuine gates: 240
- Flagged non-gates: 6  (CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 5)

## Coverage checklist
- [x] tests/test_core/test_realcov_06_elevation_windows.py — gates: 12, flagged: 0
- [x] tests/test_core/test_realcov_06_error_logging.py — gates: 3, flagged: 0
- [x] tests/test_core/test_realcov_06_logging_integration.py — gates: 4, flagged: 0
- [x] tests/test_core/test_realcov_06_optional_imports.py — gates: 2, flagged: 0
- [x] tests/test_core/test_realcov_06_subprocess_compat.py — gates: 7, flagged: 0
- [x] tests/test_core/test_realcov_06_types_exceptions.py — gates: 5, flagged: 0
- [x] tests/test_core/test_realcov_07a_disassembler.py — gates: 13, flagged: 0
- [x] tests/test_core/test_realcov_07a_transform_pipeline.py — gates: 38, flagged: 0
- [x] tests/test_core/test_realcov_07a_yara_scanner.py — gates: 10, flagged: 0
- [x] tests/test_core/test_realcov_07b_script_gen.py — gates: 14, flagged: 0
- [x] tests/test_core/test_realcov_07b_template_manager.py — gates: 15, flagged: 0
- [x] tests/test_core/test_realcov_07b_xml_gen.py — gates: 5, flagged: 0
- [x] tests/test_core/test_script_gen.py — gates: 58, flagged: 5
- [x] tests/test_core/test_session_audit6.py — gates: 19, flagged: 0
- [x] tests/test_core/test_tools.py — gates: 25, flagged: 0
- [x] tests/test_core/test_tools_audit6.py — gates: 8, flagged: 1
- [x] tests/test_core/test_types.py — gates: 88, flagged: 0

## Flagged tests

### tests/test_core/test_script_gen.py
#### `test_frida_api_reference_keys` — LOW — existence/count-only (N8)
- **Location:** tests/test_core/test_script_gen.py:945
- **Current behavior:** Calls `get_frida_api_reference()` and asserts `len(ref) == _FRIDA_API_KEYS` (6) plus that four named keys are present. It never asserts any value/content of the reference dict.
- **Why it is not a (strong) gate:** The `len(...) == 6` constant mirrors the implementation; if a maintainer adds/removes an entry the count just needs updating, and the assertion gates dictionary cardinality rather than the reference text the production code actually depends on. Key-presence is a real but shallow check. (The content of these references IS strongly gated elsewhere — `test_realcov_07b_script_gen.py:203-235` embeds and verifies the reference fragments inside generated prompts — so this is a redundant weak gate, not a coverage gap.)
- **Recommended fix:** Replace the bare count with a value assertion on at least one entry whose substring is an independent oracle (e.g. `assert "Interceptor.attach" in ref["interceptor"]`), matching the strength of the companion realcov test.

#### `test_ghidra_api_reference_keys` — LOW — existence/count-only (N8)
- **Location:** tests/test_core/test_script_gen.py:955
- **Current behavior:** Asserts `len(ref) == 5` and presence of `program`/`decompiler`/`patching` keys; no value assertions.
- **Why it is not a (strong) gate:** Same as above — count mirrors the implementation and key-presence does not verify the reference content the generators embed.
- **Recommended fix:** Assert an independent-oracle substring on a value, e.g. `assert "currentProgram" in ref["program"]`.

#### `test_cutter_reference_keys` — LOW — existence/count-only (N8)
- **Location:** tests/test_core/test_script_gen.py:964
- **Current behavior:** Asserts `len(ref) == 6` and presence of `analysis`/`writing`; no value assertions.
- **Why it is not a (strong) gate:** Count-only plus key-presence; the actual command strings are unverified here.
- **Recommended fix:** Assert a value substring, e.g. `assert "aaa" in ref["analysis"]`.

#### `test_x64dbg_reference_keys` — LOW — existence/count-only (N8)
- **Location:** tests/test_core/test_script_gen.py:972
- **Current behavior:** Asserts `len(ref) == 5` and presence of `breakpoints`/`patching`; no value assertions.
- **Why it is not a (strong) gate:** Count-only plus key-presence; the command examples are unverified.
- **Recommended fix:** Assert a value substring, e.g. `assert "bp " in ref["breakpoints"]`.

#### `test_bypass_strategy_count` — LOW — count-only mirrors implementation (N8/N4)
- **Location:** tests/test_core/test_script_gen.py:57
- **Current behavior:** Asserts `len(BypassStrategy) == _BYPASS_STRATEGY_COUNT` (11) only.
- **Why it is not a (strong) gate:** The literal 11 is a copy of the enum member count; the test would only fail if the count drifts, and would be "fixed" by editing the constant. It gates nothing about the meaning of the members. (The member values themselves are strongly gated by the parametrized `test_bypass_strategy_values` at :78 and descriptions at :98, so coverage is not lost.)
- **Recommended fix:** Drop the bare-count test, or convert it into a completeness gate analogous to `test_script_get_extension_coverage_completeness` (:350) that cross-checks the enum against an independently enumerated expected set of strategy names.

### tests/test_core/test_tools_audit6.py
#### `test_cutter_in_initialize_targets_set` — MEDIUM — existence-only membership (N8)
- **Location:** tests/test_core/test_tools_audit6.py:130
- **Current behavior:** Imports the module and asserts `ToolName.CUTTER in _LOCAL_INIT_TOOLS` (a static frozenset). It does not exercise any initialise behavior.
- **Why it is not a (strong) gate:** It only checks that a name appears in a constant collection. A regression where the membership is present but the auto-init loop fails to actually call `CutterBridge.initialize` (the real F-0017 defect) would not fail this test. It gates the constant, not the capability the suite names.
- **Recommended fix:** Rely on the adjacent behavioral test `test_cutter_initialize_invoked_on_registry_initialize` (:155), which drives `registry.initialize()` and asserts Cutter's `initialize` was actually invoked, as the gate for F-0017; if this membership test is kept it should be demoted to a supporting structural assertion, not a standalone gate for the feature.

## Acceptable skips (not flagged)
- tests/test_core/test_realcov_06_elevation_windows.py:56 `pytestmark` — module-level skip when `sys.platform != "win32"`; Windows-only UAC behavior, a legitimate platform-capability skip.
- tests/test_core/test_realcov_06_elevation_windows.py:166 `test_maybe_elevate_when_already_elevated_returns_false` — skips when the process is not elevated because exercising the relaunch path would raise a real, unanswerable UAC prompt; legitimate environment-capability skip (the elevated branch is still asserted when running elevated).
- tests/test_core/test_realcov_06_subprocess_compat.py:149 `test_popen_runs_real_system_executable` — skips when not Windows or System32 `where.exe` is absent; legitimate OS-binary availability skip.
- tests/test_core/test_realcov_06_optional_imports.py:76 `test_require_yara_returns_real_module` — skips only the success path when yara-python is not installed; the failure path (`test_require_yara_raises_sandbox_error_on_real_import_failure`) hard-forces a real import failure regardless, so the capability is still gated. Legitimate optional-dependency skip.
- tests/test_core/test_realcov_07a_disassembler.py:50,141 — `importorskip("capstone")` and `disasm` fixture skip when capstone is unavailable; legitimate optional-engine skip (the bridge wraps a third-party engine that may be absent).
- tests/test_core/test_realcov_07a_yara_scanner.py:46,80,334 — `importorskip("yara")` and scanner-availability skips; legitimate optional-engine skip.
- tests/test_core/test_realcov_07a_transform_pipeline.py:405,419,432,440,465,479 — skip the Rust-hexcore paths when `intellicrack_hexcore` is not built; legitimate native-extension availability skip (the Python-only nodes remain fully gated, and `test_hexcore_unavailable_error_raised_when_missing` asserts the real error path when absent).
- tests/test_core/test_realcov_07b_template_manager.py:31 and :199,220,238,267,285,301 — `importorskip("intellicrack_hexcore")` and content-availability skips for the native HexDocument and the committed vendor pattern collection; legitimate native-module / vendored-asset availability skips.
- tests/test_core/test_realcov_07b_script_gen.py:93,109 — node-runtime skips for JavaScript validation; legitimate external-runtime availability skip.

## Notes on borderline-but-acceptable patterns
- `test_realcov_07b_xml_gen.py` validates re-exported stdlib XML primitives. Because `xml_gen.py` only re-exports, the tests legitimately gate that the re-exported symbols are the working primitives the real consumer (`sandbox.windows`) depends on; a broken/incorrect re-export would fail them. Kept as genuine (low-value) gates, not flagged.
- `test_session_audit6.py` and `test_tools_audit6.py` swap `SessionStore.save` / module `_logger` / use fake bridges, but in every case the unit under test (the auto-save loop, `SessionManager.update` offloading + serialization, `ToolRegistry` get_status/shutdown/initialize) is the real production object — only leaf I/O or the external-tool stand-in is substituted. These are valid integration gates, not N5 mock-validates-mock.
- `test_types.py` pure "construct dataclass and read field back" tests (e.g. PatchInfo bytes, ToolParameter.enum, ProcessInfo composition) gate only field storage on data-carrying classes with no logic; they are weak but acceptable per the rubric (pure data units). The computed-property and `__str__` tests in the same file drive real logic against independent oracles and are strong gates.
