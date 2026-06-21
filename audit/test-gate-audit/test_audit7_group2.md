# Test-Gate Audit — test_audit7 (group 2: orchestration/ui/bridges/providers/config/hexpat)

## Summary
- Files audited: 13 (excluding 7 empty `__init__.py` and 2 fixture-only `conftest.py`, which are listed in the checklist)
- Test functions examined: 84
- Genuine gates: 81
- Flagged non-gates: 3  (CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 2)

## Coverage checklist
- [x] core_orchestration/__init__.py — empty package marker, no tests
- [x] core_orchestration/test_compiled_yara_protocol.py — gates: 4, flagged: 0
- [x] core_orchestration/test_tag_chips_widget.py — gates: 9, flagged: 0
- [x] core_orchestration/test_tool_state_lifecycle.py — gates: 7, flagged: 0
- [x] core_orchestration/test_tool_registry_session.py — gates: 3, flagged: 0
- [x] ui_panels_process/__init__.py — empty package marker, no tests
- [x] ui_panels_process/conftest.py — qapp fixture only, no tests
- [x] ui_panels_process/test_realcov_14a_x64dbg_panel.py — gates: 7, flagged: 0
- [x] ui_panels_process/test_threads_auto_refresh.py — gates: 10, flagged: 1
- [x] ui_wire_sandbox_backend/__init__.py — empty package marker, no tests
- [x] ui_wire_sandbox_backend/conftest.py — qapp fixture only, no tests
- [x] ui_wire_sandbox_backend/test_wire_sandbox_backend.py — gates: 6, flagged: 1
- [x] bridges_hex/__init__.py — empty package marker, no tests
- [x] bridges_hex/test_utf16_scanner.py — gates: 5, flagged: 0
- [x] bridges_hex/test_bps_streaming_export.py — gates: 11, flagged: 0
- [x] providers_meta/__init__.py — empty package marker, no tests
- [x] providers_meta/test_discover_all_cache.py — gates: 4, flagged: 0
- [x] config_pyproject/__init__.py — empty package marker, no tests
- [x] config_pyproject/test_runtime_deps.py — gates: 3, flagged: 0
- [x] u12_hexpat_print_sink/__init__.py — empty package marker, no tests
- [x] u12_hexpat_print_sink/test_bridge_print_sink.py — gates: 8, flagged: 1
- [x] u12_hexpat_print_sink/test_ui_print_sink.py — gates: 4, flagged: 0

## Flagged tests

### ui_panels_process/test_threads_auto_refresh.py
#### `test_button_text_reflects_state` — LOW — log/string-presence proxy (N9)
- **Location:** tests/test_audit7/ui_panels_process/test_threads_auto_refresh.py:363
- **Current behavior:** Toggles auto-refresh on/off and asserts the button label is exactly `"Auto-Refresh: ON"` / `"Auto-Refresh: OFF"`.
- **Why it is weaker than it should be:** This is a real gate but it gates only the cosmetic label string, not the behavior the file is about (timer-driven polling). It is paired in the same file with strong timer/interval/cleanup gates, so it is not a fake gate — it is simply a narrow string-presence check that would still pass if the label text were correct while the toggle did nothing functional. The functional half of the toggle is covered by `test_toggling_on_starts_timer_and_increments_call_count` and `test_toggling_off_stops_timer_and_plateaus_calls`, so this entry is flagged only as a hardening note, not a coverage hole.
- **Recommended fix:** Either fold the label assertion into the functional toggle tests, or add to this test an assertion that the timer's `isActive()` state matches the labelled state, so the string and the behavior cannot diverge.

### ui_wire_sandbox_backend/test_wire_sandbox_backend.py
#### `test_call_count_matches_forwarded_invocation` — MEDIUM — existence/forwarding-only (N8)
- **Location:** tests/test_audit7/ui_wire_sandbox_backend/test_wire_sandbox_backend.py:198
- **Current behavior:** Monkeypatches `tool_panel.wire_sandbox_backend` with a recording wrapper that still calls the original, then asserts the wrapper was invoked exactly once with the same sandbox object.
- **Why it is weaker than it should be:** The load-bearing assertion is the call count plus identity of the forwarded argument — it verifies the delegation happened but does not assert the resulting wired state (that the bridge now exposes the sandbox). Because the wrapper calls `original`, the real wiring does run, but the assertions in this test alone would still pass even if `original` silently dropped the sandbox; the count/identity check cannot detect a broken downstream. The genuine state gate lives in the sibling `test_public_method_forwards_to_tool_panel`, so this is a partial gate, not a fake one.
- **Recommended fix:** After the forwarded call, also assert `main_window.tool_panel.get_sandbox_bridge()` exposes the injected sandbox (mirroring `test_public_method_forwards_to_tool_panel`), so a regression that forwards-but-drops is caught by this test directly.

### u12_hexpat_print_sink/test_bridge_print_sink.py
#### `test_omitting_print_sink_does_not_raise` — LOW — existence-only for a behavior test (N8)
- **Location:** tests/test_audit7/u12_hexpat_print_sink/test_bridge_print_sink.py:161
- **Current behavior:** Calls `execute_pattern(_PRINT_PATTERN)` without a `print_sink` and asserts the result `isinstance(fields, list)`.
- **Why it is weaker than it should be:** The only assertion is a type check on the return value; it verifies the optional-argument call shape executes without raising but does not validate the decoded field content. A regression that returned an empty/garbage field list for the same valid pattern would still pass. The companion tests in the file do assert real decoded content via the `_with_output` path, so this is a narrow smoke check rather than a fake gate.
- **Recommended fix:** Assert the returned `fields` is non-empty and contains the `__mark` u8 anchor record (mirroring `test_response_payload_preserves_fields_list_shape`), so the no-sink path validates the same real output the sink path does.

## Acceptable skips (not flagged)
- tests/test_audit7/ui_panels_process/test_realcov_14a_x64dbg_panel.py:71 `pytestmark` — module-level `skipif(sys.platform != "win32")`. Legitimate environment-capability skip: the tests deliberately render real System32 PE binaries (kernel32.dll) through Capstone/LIEF, which only exist on Windows. On the target platform (Windows) the tests run as hard gates.
- tests/test_audit7/ui_panels_process/test_realcov_14a_x64dbg_panel.py:236,260,263,283,345,367,411 various `pytest.skip` calls inside `_resolve_kernel32` / `_real_disassembly_lines` / `_real_pe_sections` / `_real_pe_exports` — legitimate environment-capability skips guarding against an absent or unparseable System32 DLL. They skip the test fixture data source, not the capability under test; on a normal Windows host the real DLL is present and Capstone/LIEF parse it, so the assertions execute. These are not masking the production code under test (the panel render methods), only the availability of real input data.
- tests/test_audit7/u12_hexpat_print_sink/test_bridge_print_sink.py:43 `pytest.importorskip("intellicrack.core.hexpat")` — legitimate dependency-availability skip on the pure-Python HexPat interpreter package. If the interpreter module imports, the tests drive the real interpreter end-to-end and gate the `std::print` sink contract. The skip masks only a missing optional component, not a regression in the wired sink.
- tests/test_audit7/ui_panels_process/conftest.py / ui_wire_sandbox_backend/conftest.py / u12 qapp fixtures — `QApplication.instance()` reuse is standard Qt single-instance handling, not a capability skip.

## Notes on strong gates that warranted source verification (not flagged)
- `test_bps_streaming_export.py` — the `_patch_builder` / `_LegacyDoc` shims replace the *encoder* (`_build_bps_patch` / the Rust byte-slice entry) only to capture the runtime type of the source object the production export path hands it. The object under assertion (`mmap.mmap` vs `bytes`) is produced by the real, un-stubbed `_export_patches_*_pyfallback` / `_export_patches_*_via_backend` body. This is a legitimate capture seam for the F-0042 zero-copy invariant, not an N5 mock-validates-mock: a regression that re-introduced `bytes(...)` materialisation would change the captured type and trip the assertion. The roundtrip and path-based tests additionally apply real patches and assert exact reconstructed bytes.
- `test_discover_all_cache.py` — verified against `src/intellicrack/providers/discovery.py:691-701`. With `use_cache=False`, the raising provider's uncaught `AttributeError`/`TypeError` reaches the `isinstance(result, BaseException)` branch which calls `ainvalidate(provider_name)` (line 695). The tests seed the cache, run discovery, and assert the seeded entry is dropped; deleting line 695 would leave the seeded entry intact and fail the assertion. Genuine gate, not N10.
- `test_tool_state_lifecycle.py` / `test_tool_registry_session.py` — verified against `src/intellicrack/bridges/base.py` (`_orchestrator_session`, `set_session`, `_publish_tool_state`, `_finalize_shutdown`). The `_FakeBridge`/`_CountingBridge` are concrete subclasses driving the real base-class lifecycle plumbing; assertions target `Session.tool_states` written by production code, so a broken publish/detach would fail them. The `test_set_session_none_detaches_all_bridges` falsifiability is documented and correct.
- `test_threads_auto_refresh.py` timer tests — the `_refresh_threads` override removes only the async bridge call; the QTimer wiring, interval (3000 ms), toggle slot, and `cleanup()` are real production code and are asserted directly (interval value, active state, observed inter-call wall-clock gap, plateau after off). The combo-propagation tests drive real `update_thread_list` production code with synthetic `ThreadInfo`, which is the correct seam for a unit test with no live attached process.
- `test_ui_print_sink.py` — stubs the HexPat interpreter to assert the `PatternEditorMixin` consumer wiring (constructs with callable `print_sink`, reinstalls via `set_print_sink` on the cached interpreter, clears stale output, appends sink output to the real `QPlainTextEdit`). The append callback under assertion is real production UI code; the end-to-end interpreter routing is gated separately by the bridge-level tests.
