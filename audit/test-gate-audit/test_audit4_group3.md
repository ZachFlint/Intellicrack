# Test-Gate Audit — test_audit4 (group 3: hex routes c8-c16 + pyproject)

## Summary
- Files audited: 13 (test files; 10 `__init__.py` and 1 `conftest.py` also read)
- Test functions examined: 137
- Genuine gates: 131
- Flagged non-gates: 6  (CRITICAL: 0, HIGH: 0, MEDIUM: 5, LOW: 1)

## Coverage checklist
- [x] c8_hex_signatures_offload/__init__.py — package marker, no tests
- [x] c8_hex_signatures_offload/conftest.py — session qapp fixture, no tests
- [x] c8_hex_signatures_offload/test_signatures_offload.py — gates: 23, flagged: 0
- [x] c9_hex_disassembly_debounce/__init__.py — package marker, no tests
- [x] c9_hex_disassembly_debounce/test_follow_cursor_debounce.py — gates: 11, flagged: 0
- [x] c9_hex_disassembly_debounce/test_realcov_13a_statistics.py — gates: 7, flagged: 0
- [x] c9_hex_disassembly_debounce/test_realcov_13a_calculator.py — gates: 8, flagged: 0
- [x] c9_hex_disassembly_debounce/test_realcov_13a_disassembly_output.py — gates: 4, flagged: 0
- [x] c9_hex_disassembly_debounce/test_realcov_13a_sections.py — gates: 6, flagged: 0
- [x] c9_hex_disassembly_debounce/test_realcov_13a_widgets.py — gates: 6, flagged: 0
- [x] c10_hex_scripting/__init__.py — package marker, no tests
- [x] c10_hex_scripting/test_scripting_encoding_print.py — gates: 13, flagged: 0
- [x] c11_hex_process_memory/__init__.py — package marker, no tests
- [x] c11_hex_process_memory/test_bridge_route.py — gates: 5, flagged: 0
- [x] c12_hex_sandbox_route/__init__.py — package marker, no tests
- [x] c12_hex_sandbox_route/test_sandbox_route.py — gates: 3, flagged: 0
- [x] c13_hex_patches_route/__init__.py — package marker, no tests
- [x] c13_hex_patches_route/test_patches_bridge_route.py — gates: 6, flagged: 0
- [x] c14_hex_ips_dead_removal/__init__.py — package marker, no tests
- [x] c14_hex_ips_dead_removal/test_ips_dead_removal.py — gates: 16, flagged: 4
- [x] c15_hex_comparison_tempfile/__init__.py — package marker, no tests
- [x] c15_hex_comparison_tempfile/test_diff_temp_cleanup.py — gates: 5, flagged: 0
- [x] c16_hex_panel_selection_dispatch/__init__.py — package marker, no tests
- [x] c16_hex_panel_selection_dispatch/test_selection_dispatch.py — gates: 15, flagged: 0
- [x] d1_pyproject/__init__.py — package marker, no tests
- [x] d1_pyproject/test_runtime_extras_separation.py — gates: 3, flagged: 2

## Flagged tests

### c14_hex_ips_dead_removal/test_ips_dead_removal.py
#### `test_method_exists_on_bridge` — MEDIUM — existence-only (N8)
- **Location:** tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:125
- **Current behavior:** Asserts `callable(getattr(HexEditorBridge, "_build_ips_from_patches", None))`. Only proves the attribute exists and is callable.
- **Why it is not a gate:** The IPS payload builder could be replaced by `def _build_ips_from_patches(*a): return b""` (or any garbage) and this test would still pass. It gates the symbol's presence, not the IPS-format behavior the file claims to verify. The same method's real behavior is already fully gated by the sibling tests (`test_ips_header_is_patch_magic`, `test_ips_footer_is_eof_marker`, etc.), so this adds no falsifiability.
- **Recommended fix:** Delete it as redundant, or fold the existence check into a behavioral assertion that constructs a known patch list and asserts exact bytes (the sibling behavioral tests already do this).

#### `test_method_is_static` — MEDIUM — existence-only (N8)
- **Location:** tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:129
- **Current behavior:** Asserts `_build_ips_from_patches` is a `staticmethod` via `inspect.getattr_static`.
- **Why it is not a gate:** Whether the method is declared `staticmethod` vs a plain/`classmethod` is an implementation detail, not the IPS capability. The IPS output could be entirely broken and this test stays green; conversely a correct refactor to a module-level function or classmethod would falsely fail it. It does not gate any real operation.
- **Recommended fix:** Remove it. If call-shape matters, assert behavior through the documented call form (`HexEditorBridge._build_ips_from_patches(patches)`) and the resulting bytes instead of the descriptor type.

#### `test_returns_bytes_type` — MEDIUM — existence-only / type-only (N8)
- **Location:** tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:134
- **Current behavior:** Calls the builder with one patch and asserts `isinstance(result, bytes)`.
- **Why it is not a gate:** A stub returning `b""` (no PATCH magic, no patch records, no EOF) passes. The return type is not the behavior under test; the IPS structure is. Real behavior is gated by the header/footer/size/multi-patch sibling tests, so this is a weak duplicate.
- **Recommended fix:** Drop the standalone type check or extend it to assert the full minimal payload bytes for the given single patch (offset/size/data encoding), not just the container type.

#### `test_export_patches_ips_callable_on_document` — MEDIUM — existence-only (N8)
- **Location:** tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:206
- **Current behavior:** Asserts `callable(getattr(hexcore.HexDocument, "export_patches_ips", None))`.
- **Why it is not a gate:** Only proves the native binding is exported. A binding that returns wrong/empty bytes still passes. The sibling tests (`..._returns_bytes`, `..._starts_with_patch_magic`, `..._ends_with_eof_marker`, `..._minimum_size`) already gate the real document-level IPS output, making this redundant and non-gating on its own.
- **Recommended fix:** Remove it, or merge into a behavioral test that opens a real document, writes a known patch, and asserts the exact magic/footer/length of `export_patches_ips()`.

### d1_pyproject/test_runtime_extras_separation.py
#### `test_pyproject_parses` — LOW — weak/structural gate (N8)
- **Location:** tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py:177
- **Current behavior:** Asserts the file parses as a dict and contains the `"project"` and `"build-system"` keys.
- **Why it is weak:** It does not gate the F-0001 fix (runtime/extras separation) at all; it only proves the TOML is well-formed and has two top-level tables, which would remain true even if every dev tool were re-added to runtime deps. The real F-0001 regression is fully gated by `test_dev_tools_absent_from_runtime_deps` and `test_runtime_deps_are_modest_in_size` in the same file, so this is a low-value structural check rather than a non-gate of those behaviors. Worth keeping but acknowledged as narrow.
- **Recommended fix:** Acceptable as a smoke check; if hardening is desired, assert the presence of `[project].dependencies` and `[project.optional-dependencies]` tables specifically rather than only `project`/`build-system`.

#### `test_pyproject_parses_under_active_interpreter` — MEDIUM — partial-overlap structural gate (N8)
- **Location:** tests/test_audit4/d1_pyproject/test_runtime_extras_separation.py:202
- **Current behavior:** Asserts `sys.version_info >= (3, 11)`, that the file parses, and that `project["name"] == "intellicrack"`.
- **Why it is not a gate (for the file's stated purpose):** The interpreter-version assertion gates the test environment, not Intellicrack; the project-name assertion gates metadata unrelated to the F-0001 runtime/extras separation the module exists to verify. None of these assertions would go red if dev tooling leaked back into `[project].dependencies`. It is a green-regardless check with respect to the defect under test.
- **Recommended fix:** Either remove it (the dependency-content tests carry the real gate) or repoint it at the separation invariant — e.g. assert that no name appearing in `optional-dependencies.dev/test/docs/profile` also appears in `[project].dependencies`, which would catch double-declaration regressions the current tests miss.

## Acceptable skips (not flagged)
- tests/test_audit4/c14_hex_ips_dead_removal/test_ips_dead_removal.py:31 module-level `pytest.importorskip("intellicrack_hexcore", ...)` — legitimate build-capability skip: the document-level IPS tests require the native Rust extension to be compiled. The bridge-level IPS tests (`TestBridgeBuildIpsFromPatches`) and the dead-module-removal tests run regardless, so the core capability is still hard-gated when hexcore is present.
- tests/test_audit4/c16_hex_panel_selection_dispatch/test_selection_dispatch.py:70,83 `pytest.importorskip("intellicrack_hexcore", ...)` inside `hexcore_doc` / `_make_hexcore_doc` — legitimate native-build-capability skip for the DOCUMENT_OPENED tests that need a real `HexDocument`. The selection-propagation and clipboard tests do not depend on it and remain active.
- tests/conftest.py:529 `real_pe_dll` fixture skips via `FixtureUnavailableError` when System32 DLLs cannot be resolved — legitimate OS-resource skip (non-Windows / locked-down host); the c9 real-PE coverage tests genuinely require a real Windows PE on disk.

## Notes on mock usage (reviewed, not flagged)
- c11/c13/c16 use `_FakeBridge`/`_StubBridge`/`MagicMock`, but in every case the unit under test is real production code (the panel mixin handler or `HexEditorPanel._on_selection_changed` / `_do_copy_as` borrowed via `getattr`). The fakes sit at the bridge or OS-clipboard boundary, and assertions verify the production code's routing/decoding/state-mirroring decisions (e.g. `bridge.copy_to` args, base64 decode-to-disk, `bridge.document` adoption, exact warning title/message). These are not mock-validates-mock (N5).
- c12 `_patch_dispatch` replaces `run_bridge_coroutine_async` (the dispatch primitive) and drains the coroutine synchronously; the save-routing logic that chooses `bridge.copy_to` over subprocess/shutil is real, and the negative traps (subprocess.Popen/run, shutil.copy2, asyncio.new_event_loop raising/counting) are genuine falsifiable gates for F-0006/F-0018/F-0019.
- c8/c9/c10 are strong real-data gates: c8 measures real UI-thread allocation and off-thread read identity; c9 drives real PE bytes through the real disassembler/statistics/widgets with independent oracles (struct, recomputed Shannon entropy, instruction-size address advance); c10 records the production-resolved encoding and real print-capture output.
