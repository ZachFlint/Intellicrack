# Test-Gate Audit — test_audit5

## Summary
- Files audited: 22 (9 test modules with tests; 13 package `__init__.py` files are empty markers)
- Test functions examined: 145
- Genuine gates: 130
- Flagged non-gates: 15  (CRITICAL: 0, HIGH: 1, MEDIUM: 13, LOW: 1)

## Coverage checklist
- [x] tests/test_audit5/__init__.py — empty package marker (0 tests)
- [x] tests/test_audit5/u1_bridges_cutter/__init__.py — empty package marker (0 tests)
- [x] tests/test_audit5/u1_bridges_cutter/test_cutter_bridge.py — gates: 43, flagged: 0
- [x] tests/test_audit5/u2_bridges_frida/__init__.py — empty package marker (0 tests)
- [x] tests/test_audit5/u2_bridges_frida/test_frida_bridge_audit5.py — gates: 23, flagged: 1
- [x] tests/test_audit5/u3_hexpat_core/__init__.py — empty package marker (0 tests)
- [x] tests/test_audit5/u3_hexpat_core/test_hexpat_core.py — gates: 31, flagged: 2
- [x] tests/test_audit5/u4_hexpat_aux/__init__.py — empty package marker (0 tests)
- [x] tests/test_audit5/u4_hexpat_aux/test_compiler_pragma_propagation.py — gates: 15, flagged: 0
- [x] tests/test_audit5/u4_hexpat_aux/test_parser_aggregate_errors.py — gates: 9, flagged: 0
- [x] tests/test_audit5/u4_hexpat_aux/test_preprocessor_preserves_pragmas.py — gates: 6, flagged: 0
- [x] tests/test_audit5/u4_hexpat_aux/test_pragma_eval_depth_default.py — gates: 9, flagged: 0
- [x] tests/test_audit5/u5_ui_mainwindow/__init__.py — empty package marker (0 tests)
- [x] tests/test_audit5/u5_ui_mainwindow/test_realcov_15_mainwindow_runtime.py — gates: 5, flagged: 0
- [x] tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py — gates: 22, flagged: 11
- [x] tests/test_audit5/u6_ui_tools/__init__.py — empty package marker (0 tests)
- [x] tests/test_audit5/u6_ui_tools/test_function_xref_population.py — gates: 11, flagged: 0
- [x] tests/test_audit5/u7_ui_providerconfig/__init__.py — empty package marker (0 tests)
- [x] tests/test_audit5/u7_ui_providerconfig/test_provider_specific_ui.py — gates: 6, flagged: 0
- [x] tests/test_audit5/u8_ui_config_paths/__init__.py — empty package marker (0 tests)
- [x] tests/test_audit5/u8_ui_config_paths/test_config_paths.py — gates: 9, flagged: 0
- [x] tests/test_audit5/u9_ui_confirmation/__init__.py — empty package marker (0 tests)
- [x] tests/test_audit5/u9_ui_confirmation/test_confirmation_dialog.py — gates: 9, flagged: 0

## Flagged tests

### tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py

The bulk of the flagged tests in this batch share one root cause: they assert
on the *text of the production source* retrieved via
`inspect.getsource(getattr(MainWindow, "_method"))` and a substring match.
This is the N9 anti-pattern (string-presence proxy). The slot is never invoked;
no signal/slot connection, argument order, or runtime behavior is exercised.
A real defect that keeps the matched substring but breaks the wiring (wrong
target slot, wrong argument, dead code after an early return, the `.connect`
call inside an unreachable branch) leaves every one of these green. The file's
own companion runtime test module (`test_realcov_15_mainwindow_runtime.py`)
exists precisely because these source-text checks "cannot detect wrong logic,
wrong argument order, missing-attribute errors, or broken signal/slot wiring"
(its module docstring). They gate only that an identifier literal survives in
the source — MEDIUM weak gates, not behavior gates.

#### `TestXPUStatusMenuWiring.test_help_menu_source_references_xpu_status` — MEDIUM — N9
- **Location:** tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:727
- **Current behavior:** `inspect.getsource(_setup_help_menu)` and asserts the text contains `"XPU Status"` and `"_on_xpu_status"`.
- **Why it is not a gate:** The menu could be wired to the wrong slot, or the action never added to the menu, and the substrings would still appear. The real wiring is already gated by `TestMainWindowConstructionWiresMenu.test_help_menu_contains_xpu_status_action` (genuine), making this redundant text-matching.
- **Recommended fix:** Delete; the construction test already gates the real menu action. If kept, assert the action is reachable on a real window (it already is, elsewhere).

#### `TestToolDialogsReceiveRegistry.test_configure_tools_wires_status_changed` — MEDIUM — N9
- **Location:** tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:1022
- **Current behavior:** Asserts `"status_changed"` appears in `_on_configure_tools` source text.
- **Why it is not a gate:** Presence of the identifier does not prove a connection is made to a live slot, nor that it fires. The string could be in a comment or a dead branch.
- **Recommended fix:** Construct the real `ToolConfigDialog` (or a recording double already used in the sibling test), emit `status_changed`, and assert the MainWindow slot observably ran.

#### `TestOpenSandboxAvoidsDialogProbe.test_open_sandbox_uses_bridge_is_available` — MEDIUM — N9
- **Location:** tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:1041
- **Current behavior:** Asserts `"SandboxConfigDialog()" not in source` and `"bridge.is_available()" in source`. It also asserts `sandbox_dialog_constructed == []`, but the slot is never invoked in this test, so that list is trivially empty regardless of the source.
- **Why it is not a gate:** Both load-bearing assertions are source-text checks; the runtime assertion is vacuous because `_on_open_sandbox` is never called. A refactor to `bridge.is_available( )` (spacing) or to an equivalent helper would falsely fail/pass on text, not behavior.
- **Recommended fix:** Invoke `_on_open_sandbox` against a holder whose `_get_or_create_sandbox_bridge` returns a recording bridge, and assert `is_available` was actually called and no `SandboxConfigDialog` was constructed.

#### `TestApplyProviderSettingsHandlesDisabled.test_source_collects_providers_to_disconnect` — MEDIUM — N9
- **Location:** tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:1194
- **Current behavior:** Asserts `"providers_to_disconnect"` and `"disconnect_provider"` appear in source.
- **Why it is not a gate:** Behavior is already gated by `test_disabled_provider_reflected_in_status_emission` (which runs the slot and checks the "1 disabled" emission). This text check adds no falsifiability for a real defect.
- **Recommended fix:** Delete as redundant; the behavioral sibling is the real gate.

#### `TestOrphanSignalWiringSourceLevel.test_preferences_settings_changed_wired` — MEDIUM — N9
- **Location:** tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:1217
- **Current behavior:** Asserts `"settings_changed.connect"` in `_on_preferences` source.
- **Why it is not a gate:** Connection to the wrong handler, or in an unreachable branch, still matches the string. No emission is driven to a live slot.
- **Recommended fix:** Construct the real `PreferencesDialog` (with `exec` isolated), emit `settings_changed`, assert the MainWindow handler ran.

#### `TestOrphanSignalWiringSourceLevel.test_session_dialog_signals_wired` — MEDIUM — N9
- **Location:** tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:1223
- **Current behavior:** Asserts `"session_loaded.connect"` and `"session_deleted.connect"` in `_on_load_session` source.
- **Why it is not a gate:** Pure substring match. Note the real behavior for `session_deleted` is genuinely gated by `test_session_dialog_deleted_signal_reaches_slot` in the runtime module — this source test is the weaker duplicate.
- **Recommended fix:** Delete `session_deleted` portion (covered by runtime test); add a runtime emission check for `session_loaded`.

#### `TestOrphanSignalWiringSourceLevel.test_provider_dialog_signals_wired` — MEDIUM — N9
- **Location:** tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:1230
- **Current behavior:** Asserts `"provider_updated.connect"` and `"active_provider_changed.connect"` in `_on_configure_providers` source.
- **Why it is not a gate:** Substring presence, no runtime emission to a live slot.
- **Recommended fix:** Drive the dialog's signals against the real slot and assert observable effects.

#### `TestOrphanSignalWiringSourceLevel.test_model_selection_dialog_signal_wired` — MEDIUM — N9
- **Location:** tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:1237
- **Current behavior:** Asserts `"model_selected.connect"` in `_on_browse_models_result` source.
- **Why it is not a gate:** Substring proxy. The constructor-kwargs behavior is separately gated (`test_dialog_constructed_with_provider_name_and_discovery`) but the *connection* is not behaviorally exercised here.
- **Recommended fix:** In the existing recording-dialog test, emit `model_selected` from the recorded dialog and assert `_on_model_selected_from_browse` observably ran.

#### `TestOrphanSignalWiringSourceLevel.test_sandbox_dialog_settings_updated_wired` — MEDIUM — N9
- **Location:** tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:1243
- **Current behavior:** Asserts `"settings_updated.connect"` in `_on_configure_sandbox` source.
- **Why it is not a gate:** Substring proxy; no emission driven.
- **Recommended fix:** Construct the real dialog (exec isolated), emit `settings_updated`, assert the slot ran.

#### `TestOrphanSignalWiringSourceLevel.test_sandbox_monitor_wiring_helper_present` — MEDIUM — N9
- **Location:** tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:1249
- **Current behavior:** Asserts `"sandbox_stopped.connect"` in `_wire_sandbox_monitor_widgets` source.
- **Why it is not a gate:** Substring proxy.
- **Recommended fix:** Call `_wire_sandbox_monitor_widgets` with a real monitor widget, emit `sandbox_stopped`, assert the connected slot fired.

#### `TestOrphanSignalWiringSourceLevel.test_tool_output_panel_signals_wired` — MEDIUM — N9
- **Location:** tests/test_audit5/u5_ui_mainwindow/test_ui_mainwindow.py:1255
- **Current behavior:** Asserts `"embedded_tool_started.connect"` and `"embedded_tool_closed.connect"` in `_connect_signals` source.
- **Why it is not a gate:** Substring proxy across `_connect_signals` source text.
- **Recommended fix:** On a real `MainWindow`, emit the panel's `embedded_tool_started`/`embedded_tool_closed` signals and assert the wired slots run.

### tests/test_audit5/u3_hexpat_core/test_hexpat_core.py

#### `test_vendor_mem_base_address_smoke` — MEDIUM — N3
- **Location:** tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:738
- **Current behavior:** Loads the vendored `mem.pat`, runs a pattern that calls `std::mem::base_address()`, but wraps `execute_bytes` in `try/except HexPatError: pytest.skip(...)`. Only when no exception is raised does it assert `offset == 0x4000`.
- **Why it is not a gate:** The skip is triggered by the *thing under test* (the interpreter parsing/executing the vendored library) failing. A genuine regression in `std::mem::base_address` resolution through the real library, or any parser break, converts a should-be-red into a skip. The direct-call and flat-path variants (`test_mem_base_address_uses_pragma_directly`, `test_mem_base_address_smoke_through_pattern`) are genuine gates, so the capability is covered, but this integration smoke does not gate as written.
- **Recommended fix:** Pin the test to a minimal vendor-equivalent source the audit-scope parser fully supports and assert unconditionally; or, if the `namespace auto` syntax is genuinely out of scope, drop the vendored-file dependency rather than skip-on-failure of the unit under test.

#### `test_vendor_string_parse_int_smoke` — MEDIUM — N3
- **Location:** tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:766
- **Current behavior:** Same pattern as above for `std::string::parse_int` via the vendored `string.pat`; `try/except HexPatError: pytest.skip(...)` masks any interpreter failure, asserting `offset == 123` only on the no-exception path.
- **Why it is not a gate:** A real break in `parse_int` resolution through the vendored library is absorbed as a skip rather than a failure. `test_string_parse_int_registered_in_scope` / `test_string_parse_int_returns_value` cover the unit, so the smoke variant adds skip-masked risk without independent gating value.
- **Recommended fix:** Assert unconditionally against a parser-supported source, or remove the vendored-file dependency.

### tests/test_audit5/u2_bridges_frida/test_frida_bridge_audit5.py

#### `test_f0012_compile_typescript_reuses_compiler_instance` — HIGH — N5
- **Location:** tests/test_audit5/u2_bridges_frida/test_frida_bridge_audit5.py:462
- **Current behavior:** Monkeypatches `frida.Compiler` with `_FakeCompiler` whose `build()` returns the literal `"compiled-js"`, then asserts the result equals `("compiled-js", "compiled-js")` and that exactly one instance was created across two `compile_typescript` calls.
- **Why it is not a gate:** The return-value assertion is N10 (self-fulfilling: it only echoes the fake's hardcoded output and proves nothing about real compilation). The load-bearing assertion (`instance_counter[0] == 1`) is the genuine part — it falsifiably gates the "reuse, do not re-instantiate" fix — but the test is built entirely on a stub of the compiler, the actual TypeScript-compilation behavior is never exercised, and the only thing it can prove is the instance count. It is closer to "mock-validates-mock" than a behavior gate; if the production `compile_typescript` stopped compiling but still reused a (broken) compiler instance, this stays green.
- **Recommended fix:** Keep the instance-count assertion (it is the real fix), but drop the tautological `== ("compiled-js", ...)` echo and instead compile a tiny real TypeScript snippet through the genuine `frida.Compiler` once (covered by `importorskip("frida")`) and assert the emitted JS contains a known-correct artifact, so the test gates that compilation still works in addition to instance reuse.

## Acceptable skips (not flagged)

- tests/test_audit5/u2_bridges_frida/test_frida_bridge_audit5.py:33 module-level
  `pytest.importorskip("frida")` — legitimate dependency-capability skip: frida-python
  is an external runtime, not the Intellicrack bridge logic under test. The bridge
  cannot be exercised at all without it, so skipping when the dependency is absent is
  an environment skip, not masking of a capability defect.
- tests/test_audit5/u3_hexpat_core/test_hexpat_core.py:103 `vendor_std_lib` fixture
  `pytest.skip` — legitimate: skips only when the vendored upstream pattern repository
  is absent from the checkout (sparse checkout), which is an asset-availability
  condition, not the interpreter under test failing. (Note: the two dependent
  `*_smoke` tests are still flagged above for their *additional* skip-on-interpreter-
  failure inside the test body, which is a separate, non-legitimate mask.)
- tests/test_audit5/u5_ui_mainwindow/test_realcov_15_mainwindow_runtime.py:469
  `test_open_sandbox_panel_resolves_via_get_panel` `pytest.skip` — legitimate
  environment-capability skip: the sandbox panel can only be created where a real
  sandbox backend (Windows Sandbox / WDAG) is installed. The test asserts
  `get_panel("sandbox") is None` before invocation (a real precondition gate) and only
  skips the post-creation assertion when the OS backend is unavailable, mirroring the
  project's documented sandbox-suite environment skips.

## Notes on genuine gates worth highlighting
- u1 (cutter), u4 (hexpat aux), u6 (tools), u7 (providerconfig), u8 (paths), u9
  (confirmation) are strong: they drive the real production methods and assert exact
  values (exact rizin command prefixes and hex-encoded search bytes, exact parsed
  field sizes/locations, exact JSON template fields, exact resolved paths, exact
  cached-decision behavior with `exec()` short-circuit). The `_RecordingR2` /
  `_FakeScript` doubles stand in for the *external tool transport* only — the bridge
  logic under test is real — so they are not N5.
- u8 `test_source_has_no_hardcoded_paths` (lines 146, 242) are source-text scans but
  are correctly scoped: the finding (F-0024) is literally "a hardcoded `D:/Intellicrack`
  string exists in the source", so scanning the source for that literal *is* the
  behavior under test. Counted as genuine, narrow gates (not N9 proxies).
- u5 holder/recording-double tests that actually invoke the slot (e.g.
  `test_tool_status_dialog_receives_registry`, `test_set_active_called_for_connected_provider`,
  `test_disabled_provider_reflected_in_status_emission`, `test_threshold_exceeded_stops_timer`)
  are genuine behavior gates: the real `MainWindow` method runs and the assertion would
  fail on a real defect.
