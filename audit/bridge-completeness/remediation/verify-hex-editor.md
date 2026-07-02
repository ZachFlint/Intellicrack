# Verification Report: Hex Editor Bridge-Completeness Remediation

Scope: NATIVE hex editor only (`src/intellicrack/ui/panels/hex_editor/` package +
`src/intellicrack/bridges/hex_editor.py`). `hxd_panel.py`/`HxDPanel` was not read,
imported, or referenced anywhere in this verification, per the hard constraint
(HxD is slated for removal and was already out of scope in the original audit).

Read: `prompts/bridge-completeness-remediation.md`,
`audit/bridge-completeness/agent-09-hex-editor.md`. No separate
`verify/agent-09-hex-editor-verification.md` file exists in the repo (only the
slice report itself); the slice report's own three verification passes (noted
inline in its Coverage summary) were treated as the pre-remediation baseline.

## Part A — Three-layer verification, row by row

### Genuinely fixed (OK/OK/OK confirmed by reading, not summary)

| Row | Feature | L1 | L2 | L3 (file:line) | Verdict |
|---|---|---|---|---|---|
| #9 | Search & Replace (`replace_bytes`) | `hex_editor.py:5352` real, pre-scans via `search_bytes` for precise `data_modified` events | OK (registered) | `search.py:910-1151` `_on_replace_all`/`_on_replace` call `run_bridge_coroutine(bridge.replace_bytes(...))` for Hex/Text/Numeric modes; toolbar controls wired at `panel.py:289-291` (`_replace_input`, "Replace", "Replace All" buttons) | **OK** |
| #92 | Save to Sandbox | `hex_editor.py:5024` (auto-provision/cleanup, unchanged) | OK | `sandbox.py:126-170` `_on_save_to_sandbox` now calls `run_bridge_coroutine_logged(bridge.save_to_sandbox(dest_path, sandbox_type=sandbox_type), ...)` against the hex-editor's own `_bridge` — no reference to raw `SandboxBridge` anywhere in the file | **OK** — genuine fix, no longer bypasses auto-provisioning |
| #93 | Test in Sandbox | `hex_editor.py:5117` (unchanged) | OK | `sandbox.py:172-213` `_on_test_in_sandbox` calls `run_bridge_coroutine_logged(bridge.test_in_sandbox(command_args, sandbox_type=sandbox_type, time_limit=timeout), ...)` — no raw `SandboxBridge.execute` reference | **OK** |
| #70 | List process regions (`list_process_regions`) | `hex_editor.py:8094` (unchanged) | OK | `process_memory.py:136-167` `_on_list_regions` now calls `run_bridge_coroutine_logged(self._bridge.list_process_regions(pid), ...)` when `sys.platform == "win32" and self._bridge is not None`, with the local ctypes/`/proc` path preserved only as a genuine fallback (bridge is Windows-only) and on bridge-call failure (`_on_list_regions_error` → `_list_regions_ctypes`) | **OK** |
| #57 | Auto-detect pattern (`auto_detect_pattern`) | `hex_editor.py:7429` (unchanged) | OK | `sections.py:444-467` `_try_pattern_registry_match` now calls `run_bridge_coroutine_logged(bridge.auto_detect_pattern(), ...)`; the local `PatternRegistry`/`DataReaderCls` instantiation is gone entirely | **OK** |
| #72 | VA mapping (set/list/auto-detect/remove) | `hex_editor.py:8187-8274` (unchanged) | OK | New file `va_mapping.py` (`VaMappingMixin`), composed into `HexEditorPanel` at `panel.py:126` and tabbed in at `panel.py:465` (`"VA Mapping"`). `_on_add_va_mapping`/`_on_remove_va_mapping`/`_on_auto_detect_va_mappings`/`_on_refresh_va_mappings` all call the matching `bridge.*` method via `run_bridge_coroutine_logged` | **OK** — new feature, genuinely built |
| #73 | Offset↔VA conversion | `hex_editor.py:8302,8320` (unchanged) | OK | `va_mapping.py:290-347` `_on_goto_va`/`_on_cursor_offset_to_va` call `run_bridge_coroutine(bridge.va_to_file_offset(va))` / `bridge.file_offset_to_va(cursor_offset)`, wired to "Go" / "Cursor Offset -> VA" buttons at `va_mapping.py:105-113` | **OK** |
| #74 | Export annotated HTML | `hex_editor.py:8342` (unchanged) | OK | New file `export_report.py` (`ExportReportMixin`), composed at `panel.py:127`, menu wired at `panel.py:313,1144,1153` (`_build_export_report_menu`, "Annotated HTML..." action → `_on_export_annotated_html`). Handler calls `run_bridge_coroutine(bridge.export_annotated_html(start, end, bytes_per_row))` and writes the result to the user-chosen path | **OK** |
| #75 | Export annotated PDF | `hex_editor.py:8413` (unchanged) | OK | `export_report.py:196-247` `_on_export_annotated_pdf` → `run_bridge_coroutine(bridge.export_annotated_pdf(save_path, start, end, bytes_per_row))`, "Annotated PDF..." action wired at `panel.py:1156` | **OK** |
| #77 | Chunk size | `hex_editor.py:8514` (unchanged) | OK | `va_mapping.py:349-395` `_on_open_performance_settings` → `run_bridge_coroutine(bridge.set_chunk_size(chunk_bytes))`, "Performance Settings..." button wired at `va_mapping.py:116-118` | **OK** |
| #78 | Memory usage/budget | `hex_editor.py:8544,8563` (unchanged) | OK | Same handler: `run_bridge_coroutine(bridge.get_memory_usage())` (read before dialog) and `bridge.set_memory_budget(budget_bytes)` (apply) | **OK** |

### Still broken / unaddressed (confirmed by reading the current file content and `git diff --stat`, which shows zero changes to any of the four files below)

| Row | Feature | Layer | Why still broken |
|---|---|---|---|
| #45 | Base conversion (`base_convert`) | L3 | `calculator.py` is **byte-for-byte unmodified** (`git diff --stat` shows no diff). `_on_convert` (`calculator.py:100-161`) still computes every representation locally via Python's `struct` module. Zero references to `bridge.base_convert`, `document.base_convert`, or `run_bridge_coroutine` anywhere in the file. This was explicitly named in the dispatch instructions as one of the ~13 drift-reroute controls to fix and was not touched. |
| #52 | Generate structure bookmarks (`generate_structure_bookmarks`) | L3 | `templates.py` is **unmodified**. `_bookmark_pe_sections`/`_bookmark_elf_structure` (`templates.py:497-676`) still manually walk PE/ELF headers and call `self.document.add_bookmark(...)` field-by-field (7 separate call sites confirmed by reading the full block). No reference to `bridge.generate_structure_bookmarks` or `document.generate_structure_bookmarks` anywhere in the file. |
| #51 | List templates detailed (`list_templates_detailed`) | L3 | `templates.py` unmodified; `_populate_template_combo` (`templates.py:288-298`) still calls the plain `self.document.list_templates()`. Zero references to `list_templates_detailed` anywhere in the panel package. |
| #87-89 | DIE / ClamAV / custom signature scans (`scan_die_signatures`/`scan_clamav_signatures`/`scan_custom_signatures`) | L3 | `signatures.py` is **unmodified**. `_on_scan_signatures` (`signatures.py:570-603`) still dispatches to the fully independent local `execute_signature_scan_from_source` → `_scan_die`/`_scan_clamav`/`_scan_custom` (`signatures.py:139-489`) via `GenericCallableWorker`, never touching the bridge. Zero references to `bridge.scan_die_signatures`/`scan_clamav_signatures`/`scan_custom_signatures` anywhere in the file. This is the gap the slice report flagged as *highest drift risk* ("nontrivial parsing logic most likely to drift") and it was not addressed. |
| #18b | Toggle bit (`toggle_bit`) | L3 | `data_inspector.py` is **unmodified**. The bit editor (`_on_bit_toggled`, `data_inspector.py:188-230`) still uses `document.set_bit`/`document.get_bit` exclusively. Zero references to `toggle_bit` anywhere in the panel package (grep confirms 0 hits). Lower priority per the original audit (functionally redundant with get_bit+set_bit), but the registered bridge method itself remains genuinely unreachable from the GUI. |

**Net for Part A: 10 of 15 previously-NO-CONTROL items were genuinely fixed** (Replace, sandbox save/test reroute, list_process_regions reroute, auto_detect_pattern reroute, the full VA-mapping group, both annotated exports, chunk-size/memory-budget). **5 remain unaddressed**: `base_convert`, `generate_structure_bookmarks`, `list_templates_detailed`, the three signature-scan methods (counted as one row-cluster, #87-89), and `toggle_bit`.

None of the fixed items exhibit mis-wiring, parameter mismatches, or fakery — every dispatch call I traced passes real user-supplied values through to the real bridge method and renders the real bridge response back into the widget it claims to update.

## Part B — Test-gate review

All 6 files reviewed in full: `test_search_replace.py`, `test_sandbox_reroute.py`,
`test_process_memory_reroute.py`, `test_pattern_autodetect.py`,
`test_export_report.py`, `test_va_mapping.py`, plus the shared `conftest.py`.

**Verdict: all 6 files are genuine, falsifiable gates. Zero non-gate tests found.**

Specific confirmations against the review mandate:

- **Sandbox reroute test asserts the correct target.** `test_sandbox_reroute.py`'s
  `TestSaveToSandboxRoutesThroughHexEditorBridge`/`TestTestInSandboxRoutesThroughHexEditorBridge`
  assert on `fake_sandbox.create_calls`/`copy_calls`/`run_binary_calls` (the
  `create`→`copy_to`→`run_binary` path `HexEditorBridge.save_to_sandbox`/
  `test_in_sandbox` actually drive) and explicitly assert `"_via_raw_execute" not in call`
  to prove the old raw `SandboxBridge.execute` path was never taken. The
  `FakeSandboxBridge` in `conftest.py` is the one legitimate test double in the
  package (a real Windows Sandbox/QEMU VM cannot run inside the Docker test
  sandbox) and it stands in only for the sandbox-VM boundary, never for
  `HexEditorBridge` itself — the real bridge, real panel, and real
  `run_bridge_coroutine_logged` dispatch all execute.
- **Search-replace test asserts `bridge.replace_bytes` is called.** L1 tests
  drive the real bridge against a real `intellicrack_hexcore.HexDocument` and
  verify exact byte-level outcomes (`after == expected`, with `expected`
  computed via the test's own `bytes.replace`, an independent oracle). L2
  asserts real dispatch through `ToolRegistry.execute_tool_call`, catching the
  exact class of bug (`function_name` mismatch) the plan called out. L3 tests
  drive the real toolbar `_on_replace_all`/`_on_replace` handlers and assert
  the real document's post-call bytes match, for both Hex and Numeric modes.
- **Drift-reroute tests assert the new bridge path, not the old local reimpl.**
  `test_process_memory_reroute.py` proves the GUI table is populated from the
  same live-process region set the bridge independently reports (not fabricated,
  not merely "some result appeared"). `test_pattern_autodetect.py` injects a
  real, deterministic `.hexpat` pattern via `_pattern_registry` and proves the
  GUI's status label reflects the bridge's real match result (`test_result_matches_direct_bridge_call_exactly`
  further proves the GUI and a direct bridge call agree on the identical
  match state, ruling out any parallel local matcher).
- **New-feature tests (VA mapping, export report) are equally real gates.**
  `test_va_mapping.py` round-trips `set_va_base`→`list_va_mappings`→
  `file_offset_to_va`/`va_to_file_offset` with literal test-supplied values as
  the oracle, cross-validates `auto_detect_va_mappings` against `pefile`'s
  independently parsed `ImageBase` on a real `kernel32.dll`, and asserts the
  GUI tree/status-label content exactly matches the real bridge state.
  `test_export_report.py` asserts byte-accurate HTML content (every input
  byte's exact 2-digit hex, exact 8-digit row offsets, an added bookmark's
  label/color appearing in the legend) and, for the PDF path where `fpdf2` is
  genuinely absent from this environment, asserts the specific real
  `ToolError` message the bridge's own dependency check raises — a legitimate
  gate on the missing-dependency code path rather than a skip that hides
  breakage.
- **Falsifiability statements are present and correct throughout.** Nearly
  every test includes an explicit "Falsifiable: ... Broken production line: ..."
  docstring note naming the exact line that would need to break for the test
  to go red, and these statements check out against the actual source I read.
- **One test is honestly red-by-design and correctly documented as such**:
  `test_replace_all_hex_mode_mutates_real_document` in `test_search_replace.py`
  documents a genuine production defect (`_on_replace_all` calls
  `_reset_search_state()` immediately after setting the success status label,
  which clears the very label the test checks) and asserts the CORRECT
  end-user-visible behavior rather than being weakened to match the bug. This
  is a real gate correctly flagging residual work, not a non-gate.
- **No mocks/stubs of the code under test.** The only test double in the
  package (`FakeSandboxBridge`) is scoped exactly to the one genuine external
  boundary (a real sandbox VM/container) that cannot execute in the Docker
  test sandbox, matching the established pattern cited from
  `tests/test_bridges/test_hex_editor_bridge_methods_wave4.py`. No test mocks,
  patches, or stubs `HexEditorBridge`, the panel mixins, or the dispatch
  machinery itself.
- **Error paths and edge cases are covered**, not just happy paths: no-document
  `RuntimeError`/`ToolError` cases, unmapped VA/offset returning `None` without
  raising, non-positive chunk size raising `ValueError`, no-bridge-attached
  warning-not-crash paths, non-matching-pattern empty-list cases, and the
  Windows-only tests correctly `skipif` on non-Windows platforms rather than
  faking Windows-specific data.
- **Type hints, docstrings, determinism**: all reviewed tests use explicit
  type hints throughout, Google-style docstrings with accurate Args/Returns/
  Raises, and synchronize via `pump_until` (explicit polling against a real
  predicate) rather than bare sleeps for cross-thread bridge-worker results.

No test in this package was flagged as a non-gate.

## Environment note (not a hex-editor defect)

Direct `python -c "import intellicrack.bridges.base"` (or any direct import of
an `intellicrack.bridges` submodule without importing `intellicrack.core`
first) raises `ImportError: cannot import name 'TOOL_CAPABILITY_MAP' from
partially initialized module 'intellicrack.bridges.base' (circular import)`.
Verified via `git stash` that this reproduces identically on clean `main`
before any remediation wave touched `bridges/base.py` — it is a pre-existing
package-init ordering issue, not something introduced by, or in scope for,
the hex-editor track. Flagged here only for visibility; it did not block
reading or verifying any hex-editor file, and the hex-editor test files import
`HexEditorBridge`/`HexEditorPanel` the same way sibling test suites already do.

## Summary

- **Rows checked**: 15 previously-NO-CONTROL rows (all bridge-completeness
  gaps assigned to the hex-editor track under the "Hex-editor L1 +
  correctness" / "Hex-editor GUI" waves), plus the 5 already-OK rows (#9
  search-replace being the headline item).
- **Genuinely fixed and verified OK/OK/OK**: Search & Replace (#9), sandbox
  save/test reroute (#92-93), list_process_regions reroute (#70),
  auto_detect_pattern reroute (#57), VA mapping CRUD + conversion (#72-73),
  annotated HTML/PDF export (#74-75), chunk-size/memory-budget controls
  (#77-78). **10 rows / 12 individual bridge methods.**
- **Still broken (residual, unaddressed)**: `base_convert` (#45),
  `generate_structure_bookmarks` (#52), `list_templates_detailed` (#51),
  `scan_die_signatures`/`scan_clamav_signatures`/`scan_custom_signatures`
  (#87-89), `toggle_bit` (#18b). **5 rows / 7 individual bridge methods**,
  confirmed unaddressed both by reading current file content and by
  `git diff --stat` showing zero changes to `calculator.py`, `templates.py`,
  `signatures.py`, `data_inspector.py`.
- **Test-gate review**: all 6 new test files (32 test methods across
  `test_search_replace.py`, `test_sandbox_reroute.py`,
  `test_process_memory_reroute.py`, `test_pattern_autodetect.py`,
  `test_export_report.py`, `test_va_mapping.py`) are genuine, falsifiable
  gates. Zero non-gate tests found; zero rewrites required.
- **Track verdict**: NOT YET COMPLETE. The sandbox-reroute fix (the plan's
  explicitly highest-priority correctness item) and Search & Replace (the
  plan's highest-priority usability gap) are both genuinely done and well
  tested. However 5 of the ~13 "drift-reroute" controls named in the dispatch
  brief were never touched — most notably the three signature-scan methods,
  which the original audit itself flagged as the highest drift-risk item in
  the whole slice ("nontrivial parsing logic most likely to drift... prioritize
  scan_die_signatures/scan_clamav_signatures/scan_custom_signatures"). A
  follow-up agent should own `signatures.py`, `templates.py`, and
  `calculator.py` (all currently zero-diff, so no collision risk) to close
  these before the hex-editor track is marked done.
