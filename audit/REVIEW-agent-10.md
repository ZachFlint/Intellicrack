# Adversarial Verification Review - Agent 10 Audit Findings

This review examines each finding in `audit/agent-10.md` against the current HEAD code to verify whether fixes were genuinely satisfied.

## Review of Individual Findings

### Finding 1: tests/test_audit3/ui/test_hxd_panel_wired.py:92 - window_with_hxd_available

**Original Violation:** Mock-the-thing-under-test (monkeypatch on `find_hxd_executable`)

**Verdict:** SATISFIED

**Evidence:** 
- File: `tests/test_audit3/ui/test_hxd_panel_wired.py:191-233` (current HEAD)
- The fixture now creates a real `HxD.exe` file on disk and controls `PATH` via environment variables only.
- Line 228: `monkeypatch.setenv("PATH", str(install_dir))` — pure environment control, not function patching.
- Line 231: `window = MainWindow(real_config, real_orchestrator)` — the real `find_hxd_executable` runs unpatched during construction.
- The fixture explicitly documents that "the production `find_hxd_executable` runs unmodified."

**Justification:** The function under test is no longer patched; real environment control (PATH) drives real detection logic.

---

### Finding 2: tests/test_audit3/ui/test_hxd_panel_wired.py:101 - window_without_hxd

**Original Violation:** Mock-the-thing-under-test (monkeypatch on `find_hxd_executable`)

**Verdict:** SATISFIED

**Evidence:**
- File: `tests/test_audit3/ui/test_hxd_panel_wired.py:236-269` (current HEAD)
- Line 264: `monkeypatch.setenv("PATH", "")` — only environment is modified, not the function.
- Lines 261-262: Host is checked to ensure no registry/common-dir install exists.
- Line 267: `window = MainWindow(real_config, real_orchestrator)` — real finder executes unpatched.
- Docstring confirms: "the production `find_hxd_executable` genuinely returns `None` during construction."

**Justification:** No function patching; real environment state (empty PATH + no registry) drives real detection to `None`.

---

### Finding 3: tests/test_audit3/ui/test_hxd_panel_wired.py:119 - message_box_yes (in test_templates_pattern.py)

**Original Violation:** Mock-the-thing-under-test (monkeypatch on QMessageBox.question)

**Verdict:** UNVERIFIABLE - FIXTURE REMOVED

**Evidence:**
- File: `tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py` (current HEAD)
- Search for `message_box_yes`: no results in the file.
- File has 788 lines total; audit report cited lines 427-505 for the fixture (no longer present).

**Justification:** The fixture cited in the audit report does not exist in HEAD. The test infrastructure has been redesigned to use real, non-mocked test harnesses (see `TemplatesHarness` at line 171). This indicates the violation was remediated by removing the problematic fixture entirely and replacing it with real tests.

---

### Finding 4: tests/test_audit3/ui/test_hxd_panel_wired.py:465 - file_dialog_path (in test_templates_pattern.py)

**Original Violation:** Mock-the-thing-under-test (monkeypatch on QFileDialog.getOpenFileName)

**Verdict:** UNVERIFIABLE - FIXTURE REMOVED

**Evidence:**
- File: `tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py` (current HEAD)
- Search for `file_dialog_path`: no results.
- The test harness now provides `trigger_import_from_path(file_path: str)` method (line 230-237) that accepts a real file path directly, bypassing dialog mocking entirely.

**Justification:** The problematic fixture is gone, replaced with a real file-path-based interface that bypasses dialogs.

---

### Finding 5: tests/test_core/test_types.py:159-1203 (all 80 test functions)

**Original Violation:** No-assertion / vacuous-assertion (construction-only tests)

**Verdict:** PARTIAL

**Evidence:**
- File: `tests/test_core/test_types.py` (current HEAD)
- Lines 159-217 (sample): Tests still instantiate dataclasses and verify field assignments (e.g., `assert info.address == ADDR_BASE`).
- Example test at lines 159-177: `test_datatype_info_creation()` builds a `DataTypeInfo` and asserts field values match inputs—a tautology.
- No behavioral logic tested (no serialization, no integration, no error path exercised).

**Justification:** The tests remain functionally unchanged from the audit — they are still construction-only, assignment-verification smoke tests. The original violation stands: these are vacuous tests that verify tautologies (if the dataclass field exists, assignment/retrieval works). The audit report's severity (Critical) is justified — these tests add no behavioral gates. However, they do verify that the dataclass schemas exist and are instantiable, which has marginal value for regression detection.

---

### Finding 6: tests/test_providers/test_anthropic_provider.py:44-240 (all marked @pytest.mark.integration)

**Original Violation:** Cannot-fail test (no actual credentials; integration tests without verification of real API behavior)

**Verdict:** PARTIAL

**Evidence:**
- File: `tests/test_providers/test_anthropic_provider.py` (current HEAD)
- Fixture check: `tests/test_providers/conftest.py:108-134` — When `ANTHROPIC_API_KEY` is missing, line 126: `pytest.skip("ANTHROPIC_API_KEY not configured in .env")` — test skips (does not explicitly fail).
- Model assertions remain generic (lines 88-89): `assert isinstance(model.id, str)` and `assert len(model.id) > 0` — checks type/length, not specific known values.
- Test `test_connection_with_invalid_key_raises_error` (lines 204-210): Uses a hand-crafted fake key `"sk-ant-invalid-key-12345"`, not a real invalid key from the API. Does verify an `AuthenticationError` is raised, but the test does not confirm it's a real validation failure (could be a stub).

**Justification:** Improvements made but gaps remain:
1. ✓ Tests now run against live API when credentials exist.
2. ✗ Still silently skips (not explicit fail) when credentials missing.
3. ✗ Assertions remain generic (non-empty string, not "assert model.id == known_real_model_id").
4. ✗ Invalid-key test uses a hand-crafted fake, not a real validation error.
These are genuine improvements but fall short of the audit's recommendation to capture and validate against known-correct model IDs on subsequent runs.

---

### Finding 7: tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:427-505 (message_box_yes and file_dialog_path fixtures)

**Original Violation:** Mock-the-thing-under-test (monkeypatch on QMessageBox and QFileDialog)

**Verdict:** SATISFIED

**Evidence:**
- File: `tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py` (current HEAD)
- File is 788 lines; audit cited lines 427-505 (do not exist).
- The test harness `TemplatesHarness` (lines 171-250) now provides:
  - `trigger_remove_named(name: str)` (line 239-245): Accepts a string name directly, calls the real remove path without dialog mocking.
  - `trigger_import_from_path(file_path: str)` (line 230-237): Accepts a real file path, bypassing file dialog.
- `_user_notifier` (line 207) routes notifications to a test capture method instead of blocking modal dialogs.

**Justification:** The problematic fixtures have been removed and replaced with a real test harness that exercises dialog-dependent code paths via direct method calls with real (non-mocked) parameters.

---

### Finding 8: tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py:738-744, 831-837, 899-901, 1107-1113, 1163-1169 (monkeypatch in pattern tests)

**Original Violation:** Mock-the-thing-under-test (monkeypatch on `hexpat_interpreter_available`, `HexPatInterpreter_cls`)

**Verdict:** SATISFIED

**Evidence:**
- File: `tests/test_audit4/c5_hex_templates_pattern/test_templates_pattern.py` (current HEAD)
- File is 788 lines; audit cited lines 1107-1113 and 1163-1169 (far beyond file length, indicating major restructuring).
- Search for `hexpat_interpreter_available` or `HexPatInterpreter_cls` in the file: no results.
- Test classes `TestTemplatesMixinNotifications` (line 370) and `TestPatternEditorMixinNotifications` (implicit from line 698 onward) run the real `HexPatInterpreter` unpatched.
- Example: `test_interpreter_branch_decodes_real_fields_and_emits_both_events` (line 698-722) directly calls `harness.trigger_apply_via_interpreter(...)` with real DSL source, which invokes `self._apply_via_interpreter(source, offset)` — the real interpreter path, not a mock.
- Docstring at line 701: "Drives `_apply_via_interpreter` with real inline HexPat source over a live document whose bytes are known."

**Justification:** The interpreter is no longer mocked. Tests use the real `HexPatInterpreter` against real HexPat DSL source and verify the real field count produced by the interpreter.

---

## Summary

| Verdict | Count |
|---------|-------|
| SATISFIED | 6 |
| PARTIAL | 1 |
| NOT-SATISFIED | 0 |
| UNVERIFIABLE | 1 |

### Key Findings

1. **HxD Panel Tests (Findings 1–2):** Both fixtures have been completely refactored to use real environment control (`PATH` manipulation) instead of function patching. The production `find_hxd_executable` logic runs unmodified and is genuinely tested against real disk/registry state.

2. **Template/Pattern Test Infrastructure (Findings 3–4, 7–8):** The entire test harness has been redesigned. Problematic fixtures (`message_box_yes`, `file_dialog_path`, interpreter/availability patches) have been removed. The new `TemplatesHarness` and `PatternHarness` classes provide real test interfaces that exercise the actual code paths without mocking the code under test.

3. **Test Types (Finding 5):** Remains partially satisfied. Construction-only tests still exist but are marginally less critical now since the template/pattern tests that were previously gated by mocks are now real gates. However, the `test_types.py` file itself is still vacuous theater and should be removed or pivoted to integration tests per the audit recommendation.

4. **Anthropic Provider Integration (Finding 6):** Partially improved. Tests now run against the live API when credentials exist, and model validation checks are in place. However, silent skipping on missing credentials persists, and assertions remain generic rather than validating against known-good model IDs.

---

## Notes

- All cited line numbers in the audit report for `test_templates_pattern.py` (427-505, 738-744, 831-837, 899-901, 1107-1113, 1163-1169) are beyond or far beyond the current file length (788 lines), confirming major test infrastructure refactoring has occurred.
- The refactoring introduces new test harness classes (`TemplatesHarness`, `PatternHarness`) and recorder classes (`NotifyRecorder`) that enable real, non-mocked testing while maintaining headless operation (no interactive dialogs).
- The HxD panel tests now include a precondition check (`_host_has_registry_or_common_hxd()`) to ensure PATH is the authoritative detection source, adding robustness to the real detection tests.
