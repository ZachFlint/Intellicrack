# Test-Gate Audit — test_hexcore_e2e (part 1)

## Summary
- Files audited: 36
- Test functions examined: 430
- Genuine gates: 395
- Flagged non-gates: 35  (CRITICAL: 1, HIGH: 11, MEDIUM: 13, LOW: 10)

## Coverage checklist
- [x] tests/test_hexcore_e2e/__init__.py — gates: 0, flagged: 0 (package docstring only, no tests)
- [x] tests/test_hexcore_e2e/conftest.py — gates: 0, flagged: 0 (fixtures/binary builders only, no tests; module `importorskip("intellicrack_hexcore")` is a legitimate native-module skip)
- [x] tests/test_hexcore_e2e/test_binary_diff.py — gates: 14, flagged: 0
- [x] tests/test_hexcore_e2e/test_bookmarks.py — gates: 9, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_ai_context.py — gates: 6, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_alignment_color.py — gates: 8, flagged: 2
- [x] tests/test_hexcore_e2e/test_bridge_arithmetic.py — gates: 11, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_base_convert.py — gates: 9, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_bit_ops.py — gates: 12, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_block_ops.py — gates: 7, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_bps_ups.py — gates: 9, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_compare_files.py — gates: 12, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_concurrent.py — gates: 14, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_copy_as.py — gates: 9, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_copy_as_complete.py — gates: 11, flagged: 2
- [x] tests/test_hexcore_e2e/test_bridge_disassembly.py — gates: 5, flagged: 2
- [x] tests/test_hexcore_e2e/test_bridge_disassembly_deep.py — gates: 9, flagged: 4
- [x] tests/test_hexcore_e2e/test_bridge_display.py — gates: 11, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_display_modes_complete.py — gates: 20, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_document_info.py — gates: 16, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_encoding_decoding.py — gates: 16, flagged: 2
- [x] tests/test_hexcore_e2e/test_bridge_error_handling.py — gates: 10, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_hash_advanced.py — gates: 19, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_html_export_largefile.py — gates: 8, flagged: 3
- [x] tests/test_hexcore_e2e/test_bridge_lifecycle.py — gates: 13, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_new_capabilities.py — gates: 26, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_patches.py — gates: 4, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_pattern_engine.py — gates: 16, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_pe_checksum.py — gates: 9, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_pe_introspection.py — gates: 17, flagged: 3
- [x] tests/test_hexcore_e2e/test_bridge_sandbox.py — gates: 11, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_scripting.py — gates: 5, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_search.py — gates: 13, flagged: 1
- [x] tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py — gates: 10, flagged: 3
- [x] tests/test_hexcore_e2e/test_bridge_signatures.py — gates: 9, flagged: 0
- [x] tests/test_hexcore_e2e/test_bridge_state_integration.py — gates: 19, flagged: 1

## Flagged tests

### tests/test_hexcore_e2e/test_bookmarks.py
#### `test_add_bookmark_returns_index` — LOW — existence/type-only(N8)
- **Location:** tests/test_hexcore_e2e/test_bookmarks.py:27
- **Current behavior:** Calls `add_bookmark(0, 4, "header", "#FF0000")` and asserts `isinstance(idx, int)` and `idx >= 0`.
- **Why it is not a gate:** The native `add_bookmark` (src/intellicrack-hexcore/src/lib.rs:365) returns `usize`, which is always a non-negative int by type. A broken add (e.g. one that never pushes the Bookmark) still returns a valid index, so neither assertion can fail on a real storage defect. The actual storage is gated only by the sibling field-value tests.
- **Recommended fix:** Assert the returned index actually addresses the new bookmark, e.g. after add assert `idx == 0` for the first add and `list_bookmarks()[idx][2] == "header"`, so a no-op add trips the assertion.

### tests/test_hexcore_e2e/test_bridge_ai_context.py
#### `test_get_context_for_ai_bookmarks_contain_expected_fields_when_present` — MEDIUM — existence-only(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_ai_context.py:110
- **Current behavior:** Adds a bookmark, fetches the AI context, asserts each bookmark dict merely contains keys `offset`, `length`, `label`; never checks values.
- **Why it is not a gate:** If the production code reported bookmarks with wrong offsets/lengths/labels (garbage, swapped fields, wrong placement) the test still passes — only key presence is verified. The name claims "expected fields" but checks existence.
- **Recommended fix:** Assert `bms[0]["offset"] == 0`, `bms[0]["length"] == 2`, `bms[0]["label"] == "MZ_magic"` so a corrupted bookmark payload trips the assertion.

### tests/test_hexcore_e2e/test_bridge_alignment_color.py
#### `test_set_alignment_grid` — CRITICAL — tautological(N4)
- **Location:** tests/test_hexcore_e2e/test_bridge_alignment_color.py:200
- **Current behavior:** Opens a file, calls `set_alignment_grid(4096)`, asserts `result is True`.
- **Why it is not a gate:** `HexEditorBridge.set_alignment_grid` (hex_editor.py:5984) is hardcoded `return True` ("True always"); `self._alignment_grid_size` is never read back. The assertion can never fail regardless of whether the grid size is stored or honored.
- **Recommended fix:** Read the value back (assert `bridge._alignment_grid_size == 4096` or via a getter) and/or assert the state holder received the change (`state.alignment_grid_size == 4096`) using the `set_state_holder` oracle.
#### `test_set_color_mode` — MEDIUM — existence-only(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_alignment_color.py:217
- **Current behavior:** Calls `set_color_mode("entropy")`, asserts `result is True`.
- **Why it is not a gate:** `set_color_mode` returns `True` for any valid mode (hex_editor.py:8593); `"entropy"` is always valid, so the boolean is constant for this input and the mode is never read back. A setter that stored the wrong value still passes.
- **Recommended fix:** Follow with `assert _run(bridge.get_color_mode()) == "entropy"` (as `test_color_mode_roundtrip` does).

### tests/test_hexcore_e2e/test_bridge_base_convert.py
#### `test_result_has_base_keys` — MEDIUM — existence-only(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_base_convert.py:104
- **Current behavior:** Calls `base_convert("42")`, asserts the dict contains keys `decimal`, `hex`, `octal`, `binary`.
- **Why it is not a gate:** Checks key presence only; a wrong conversion (e.g. `hex == "0x99"`) still passes. Value correctness is never asserted.
- **Recommended fix:** Assert values for 42: `result["decimal"] == "42"`, `result["hex"] == "0x2a"`, `result["octal"] == "0o52"`, `result["binary"] == "0b101010"`.

### tests/test_hexcore_e2e/test_bridge_block_ops.py
#### `test_copy_block_overlapping_forward` — HIGH — length-only on rich output(N8/N6)
- **Location:** tests/test_hexcore_e2e/test_bridge_block_ops.py:121
- **Current behavior:** Writes `01..08` at offset 0, calls `copy_block(0, 8, 4)` (overlapping), reads 8 bytes at offset 4, asserts only `len(raw) == 8`.
- **Why it is not a gate:** `read_bytes(4, 8)` returns 8 bytes from a 64-byte file regardless of what copy_block wrote. A wrong/smeared/no-op overlapping copy still passes; copied content is never compared.
- **Recommended fix:** Compute the expected post-copy 8 bytes by hand from the documented overlap semantics and assert `bytes.fromhex(result.replace(" ", "")) == <expected>`.

### tests/test_hexcore_e2e/test_bridge_copy_as.py
#### `test_copy_as_hex_contains_spaces` — LOW — shape-only(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_copy_as.py:61
- **Current behavior:** Selects `DE AD BE EF`, calls `copy_as("hex")`, asserts a space is present and each token is length 2; never checks byte values.
- **Why it is not a gate:** A corrupted encoder emitting wrong bytes (e.g. `00 00 00 00`) passes — only shape is constrained. Value correctness is gated separately by `test_copy_as_hex_expected_value`.
- **Recommended fix:** Add `assert result == "DE AD BE EF"` (or decode tokens and compare to `b"\xde\xad\xbe\xef"`).

### tests/test_hexcore_e2e/test_bridge_copy_as_complete.py
#### `test_csharp_array_starts_with_new_byte_array` — LOW — shape-only prefix(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_copy_as_complete.py:79
- **Current behavior:** Asserts only that the csharp_array output `startswith("new byte[] {")`.
- **Why it is not a gate:** A correct prefix with wrong/empty byte literals still passes. Byte correctness is gated separately by `test_csharp_array_contains_correct_hex_values`; this asserts only the hardcoded wrapper prefix.
- **Recommended fix:** Also assert the contained `0xNN` tokens decode to `_PAYLOAD_ALL_LOW`, or merge with the value test.
#### `test_javascript_array_starts_with_new_uint8array` — LOW — shape-only prefix(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_copy_as_complete.py:174
- **Current behavior:** Asserts only that javascript_array output `startswith("new Uint8Array([")`.
- **Why it is not a gate:** A wrong/empty byte body with the correct prefix passes; byte correctness is gated separately by `test_javascript_array_contains_correct_hex_values`.
- **Recommended fix:** Also assert the `0xNN` tokens decode to the input payload, or merge with the value test.

### tests/test_hexcore_e2e/test_bridge_disassembly.py
#### `test_disassemble_returns_list` — MEDIUM — type-only(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_disassembly.py:55
- **Current behavior:** Disassembles 4 INT3 bytes, asserts only `isinstance(result, list)`.
- **Why it is not a gate:** `disassemble` always returns `list` (returns `[]` on any failure). Garbage instructions, wrong mnemonics, or an empty list all satisfy the type check. Real INT3 correctness is gated by `test_disassemble_int3_mnemonic`.
- **Recommended fix:** Assert non-empty and `result[0]["mnemonic"] == "int3"`.
#### `test_disassemble_pe_section_code_with_auto_arch` — HIGH — existence-only for behavior(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_disassembly.py:143
- **Current behavior:** Calls `disassemble(0, count=4, arch="auto")` on the loaded PE, asserts only `isinstance(result, list)`. Docstring claims it verifies auto-detection resolves AMD64 to x86-64.
- **Why it is not a gate:** A wrong auto-detected arch/mode or a nonsense result still passes; nothing constrains the detected arch or the instructions. The claimed auto-detect behavior is untested.
- **Recommended fix:** Compare the auto run against an explicit `x86`/`64` run (assert same first-instruction mnemonic/size), as the deep file's matching test does.

### tests/test_hexcore_e2e/test_bridge_disassembly_deep.py
#### `test_disassemble_pe_text_with_auto_arch` — HIGH — existence-only for behavior(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_disassembly_deep.py:104
- **Current behavior:** `disassemble(0, count=4, arch="auto")` then asserts only `isinstance(results, list)`. Docstring claims auto-detection from the PE header.
- **Why it is not a gate:** `disassemble` always returns a list (including `[]`). A broken `auto_detect_arch` or garbage instructions still pass; the auto-detect behavior is unconstrained.
- **Recommended fix:** Assert non-empty and first mnemonic matches the explicit x86/64 run (proven possible by `test_disassemble_pe_text_explicit_x86_64_matches_auto`).
#### `test_disassemble_at_mz_header_does_not_crash` — MEDIUM — type-only(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_disassembly_deep.py:142
- **Current behavior:** Disassembles offset 0, asserts only `isinstance(results, list)`.
- **Why it is not a gate:** Any value (including `[]` from a broken disassembler) satisfies the type check; "does not crash" gates only that no exception is raised.
- **Recommended fix:** Assert `results` non-empty, first instruction `address == 0`, and coherent `size`/`bytes`.
#### `test_disassemble_mz_header_address_starts_at_zero` — HIGH — vacuously-satisfiable conditional(N6)
- **Location:** tests/test_hexcore_e2e/test_bridge_disassembly_deep.py:151
- **Current behavior:** `if results := disassemble(0, count=1, ...): assert results[0]["address"] == 0`.
- **Why it is not a gate:** A defect returning an empty list makes the `if` falsy and skips the assertion, so the test passes green despite disassembly being broken.
- **Recommended fix:** Assert `results` non-empty first, then `assert results[0]["address"] == 0`.
#### `test_disassemble_at_end_of_file_returns_empty_or_partial` — MEDIUM — weak upper bound(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_disassembly_deep.py:254
- **Current behavior:** Disassembles at `doc_len - 1` with count=10, asserts `isinstance(results, list)` and `len(results) <= 1`.
- **Why it is not a gate:** A disassembler that always returns `[]` satisfies both checks; the upper-bound-only assertion accepts the empty/failure case and never gates that the trailing byte is actually disassembled.
- **Recommended fix:** Assert `len(results) == 1` (or `>= 1` with expected address `== near_end`) to gate the boundary read.

### tests/test_hexcore_e2e/test_bridge_document_info.py
#### `test_undo_after_write_may_clear_modified` — HIGH — vacuously-satisfiable conditional(N6)
- **Location:** tests/test_hexcore_e2e/test_bridge_document_info.py:220
- **Current behavior:** Writes 0xAA at offset 0, asserts modified True, calls `undo()`; only `if undone:` asserts the byte was restored.
- **Why it is not a gate:** The core claim (undo restores the original byte) is guarded by `if undone:`. If `undo()` is broken and returns `False`/no-ops, the restoration assertion is skipped and the test passes green.
- **Recommended fix:** Assert `undo()` returns True for a single pending write, then unconditionally assert `read_bytes(0,1) == original` and `get_document_info()["modified"] is False`.

### tests/test_hexcore_e2e/test_bridge_encoding_decoding.py
#### `test_decode_text_invalid_encoding_handles_gracefully` — HIGH — accepts-both-outcomes(N7)
- **Location:** tests/test_hexcore_e2e/test_bridge_encoding_decoding.py:159
- **Current behavior:** Calls `decode_text` with `"bogus-encoding-xyz"`. Catches LookupError/ValueError/RuntimeError into `raised`; only `if raised is None` asserts a non-None str. If an exception was raised, no assertion runs.
- **Why it is not a gate:** Passes whether the call raises (caught, no assert) OR returns any string; no branch in which a real defect fails it. Correct graceful handling and broken behavior are indistinguishable.
- **Recommended fix:** Pick the contract: assert `pytest.raises((LookupError, ValueError))` for an unknown codec, or assert the specific fallback string. Do not accept both.
#### `test_list_encodings_with_open_document` — LOW — non-comparing(N6)
- **Location:** tests/test_hexcore_e2e/test_bridge_encoding_decoding.py:296
- **Current behavior:** Gets `list_encodings()` without and with a doc open; asserts only both lists non-empty.
- **Why it is not a gate:** The docstring claims it verifies the catalog "works the same way with or without an open document" but never compares the two; a regression returning a different/truncated set with a doc open still passes.
- **Recommended fix:** Assert `with_doc == without_doc` (the catalog is document-independent).

### tests/test_hexcore_e2e/test_bridge_error_handling.py
#### `test_write_bytes_beyond_length_on_loaded_doc` — HIGH — accepts-both-outcomes(N7)
- **Location:** tests/test_hexcore_e2e/test_bridge_error_handling.py:69
- **Current behavior:** Calls `write_bytes(size+100, "FF")` on a loaded doc. If it returns, asserts `isinstance(result, bool)`; if it raises RuntimeError/ValueError/OverflowError, the `except` block `pass`es.
- **Why it is not a gate:** `write_bytes` always returns literal `True` (hex_editor.py:5276), so the bool branch is a tautology, and `except: pass` swallows the raise branch. Correct rejection, silent clip, or unexpected `True` all pass; no out-of-range-write defect can make it fail.
- **Recommended fix:** Decide the contract: either `with pytest.raises((RuntimeError, ValueError, OverflowError)):`, or if clipping is allowed assert document length unchanged and boundary bytes untouched. Remove the accept-both try/except.

### tests/test_hexcore_e2e/test_bridge_html_export_largefile.py
#### `test_set_chunk_size` — LOW — literal-return(N4/N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:154
- **Current behavior:** Opens a 64-byte file, calls `set_chunk_size(65536)`, asserts `result is True`.
- **Why it is not a gate:** `set_chunk_size` returns literal `True` on success (hex_editor.py:8542); the assertion cannot distinguish a working hint from a no-op that returns True.
- **Recommended fix:** After setting, call `get_memory_usage()` and assert `chunk_size == 65536` (round-trips the hint through the backend).
#### `test_set_memory_budget` — LOW — literal-return(N4/N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:182
- **Current behavior:** Calls `set_memory_budget(...)`, asserts `result is True`.
- **Why it is not a gate:** Identical literal-`True` pattern as `set_chunk_size`; a no-op store still returns True.
- **Recommended fix:** Round-trip via `get_memory_usage()` and assert `memory_budget` equals the value set.
#### `test_get_memory_usage` — MEDIUM — dict-key existence on self-built literal(N8/N10)
- **Location:** tests/test_hexcore_e2e/test_bridge_html_export_largefile.py:167
- **Current behavior:** Asserts `"usage_bytes"`, `"chunk_size"`, `"memory_budget"` are keys in the result.
- **Why it is not a gate:** `get_memory_usage` always constructs `{"usage_bytes": ..., "chunk_size": ..., "memory_budget": ...}` (hex_editor.py:8561), defaulting every value to 0 when the backend getter is missing. The keys are present even with a None document and broken getters; a real memory-accounting defect stays green.
- **Recommended fix:** Open a known-size file and assert `result["usage_bytes"] > 0`, or set a chunk size first and assert `result["chunk_size"]` equals the set value (proving the native getter path runs, not the 0 default).

### tests/test_hexcore_e2e/test_bridge_new_capabilities.py
#### `test_list_process_regions_raises_without_hexcore` — MEDIUM — existence-only for behavior(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_new_capabilities.py:754
- **Current behavior:** Constructs and initializes a bridge, then asserts `hasattr(bridge, "list_process_regions")`.
- **Why it is not a gate:** The name/docstring claim it verifies the method raises RuntimeError when hexcore is unavailable, but it never calls the method or triggers the raise path. The guard logic (hex_editor.py:8112-8119) is unexercised; deleting it would not fail this test.
- **Recommended fix:** On non-Windows assert it raises with "Windows-only"; on Windows monkeypatch the module guard to simulate unavailability and assert `pytest.raises(RuntimeError, match="hexcore native module not available")`.

### tests/test_hexcore_e2e/test_bridge_patches.py
#### `test_import_patches_returns_integer_count` — MEDIUM — accepts-zero/type-only(N7/N6)
- **Location:** tests/test_hexcore_e2e/test_bridge_patches.py:95
- **Current behavior:** Exports IPS patches from a modified doc, imports into a fresh doc, asserts `isinstance(count, int)` and `count >= 0`.
- **Why it is not a gate:** `count >= 0` is satisfied by `count == 0` (importing nothing). A no-op import (empty parse, wrong offset) still passes; imported bytes are never compared to what was exported.
- **Recommended fix:** Assert `count >= 1` and read back the patched bytes to confirm they equal the exported edit (as `test_patch_roundtrip_data_matches` does).

### tests/test_hexcore_e2e/test_bridge_pattern_engine.py
#### `test_list_hexpat_patterns_items_have_required_keys` — MEDIUM — vacuously-satisfiable on empty list(N6)
- **Location:** tests/test_hexcore_e2e/test_bridge_pattern_engine.py:317
- **Current behavior:** Iterates `list_hexpat_patterns()` and asserts each entry has `name`/`description`/`category` keys.
- **Why it is not a gate:** The loop body never runs for an empty list. If the built-in pattern catalog were broken/deleted/returned `[]`, the test stays green; the companion list test only asserts it is a list (also passes on `[]`).
- **Recommended fix:** Assert `result` non-empty first (the bridge ships built-in patterns), then validate keys; or assert a specific known built-in pattern name is present.

### tests/test_hexcore_e2e/test_bridge_pe_introspection.py
#### `test_get_pe_sections_signature` — MEDIUM — type/existence-only(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_pe_introspection.py:587
- **Current behavior:** Invokes `bridge.get_pe_sections()` without awaiting, asserts `asyncio.iscoroutine(coro)`, then closes it. No section parsing is exercised.
- **Why it is not a gate:** Only proves the method is declared `async def`. A rewrite returning garbage/`[]` or parsing the section table wrong stays green; real behavior is gated by `TestGetPeSectionsSyntheticPe32`.
- **Recommended fix:** Remove (behavior covered elsewhere) or assert `inspect.iscoroutinefunction(...)` plus an awaited result assertion in the same test.
#### `test_get_pe_imports_signature` — MEDIUM — type/existence-only(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_pe_introspection.py:599
- **Current behavior:** Invokes `bridge.get_pe_imports()` un-awaited, asserts it is a coroutine, closes it.
- **Why it is not a gate:** Proves only `async def`; a broken import parser returning wrong/empty data passes.
- **Recommended fix:** Remove or fold into `TestGetPeImportsSyntheticPe` with an awaited assertion.
#### `test_get_pe_exports_signature` — MEDIUM — type/existence-only(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_pe_introspection.py:611
- **Current behavior:** Invokes `bridge.get_pe_exports()` un-awaited, asserts it is a coroutine, closes it.
- **Why it is not a gate:** Proves only `async def`; a broken export parser passes.
- **Recommended fix:** Remove or fold into `TestGetPeExportsSyntheticPe` with an awaited assertion.

### tests/test_hexcore_e2e/test_bridge_search.py
#### `test_search_hex_max_results_respected` — HIGH — vacuously-satisfiable(N6)
- **Location:** tests/test_hexcore_e2e/test_bridge_search.py:106
- **Current behavior:** Writes 200 repeats of `AA BB`, searches with `max_results=5`, asserts only `len(results) <= 5`.
- **Why it is not a gate:** Upper-bound-only. A broken search returning `[]` passes (`0 <= 5`); truncation is never proven, and a cap that is a no-op when fewer than 5 match is not caught.
- **Recommended fix:** First assert the uncapped search returns `> 5` matches, then assert the capped call returns exactly `5`.

### tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py
#### `test_search_with_alignment_4_returns_only_aligned_offsets` — HIGH — vacuously-satisfiable(N6)
- **Location:** tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:198
- **Current behavior:** Plants the target at aligned offsets 0,4,8,12,20 and misaligned offset 6, searches with `alignment=4`, loops `for r in results: assert r["offset"] % 4 == 0`.
- **Why it is not a gate:** The assertion lives inside a `for` over `results`. A search returning `[]` (broken) passes vacuously; it catches "alignment ignored" (offset 6 trips `6 % 4`) but not "finds nothing" or "drops aligned matches it should report."
- **Recommended fix:** Add `assert results` and `assert {r["offset"] for r in results} == {0, 4, 8, 12, 20}`.
#### `test_search_max_results_caps_returned_matches` — HIGH — vacuously-satisfiable(N6)
- **Location:** tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:232
- **Current behavior:** Plants the target at every 4-byte slot (16 matches), searches with `max_results=1`, asserts `len(results) <= 1`.
- **Why it is not a gate:** Upper-bound-only. A search returning `[]` passes; the cap is never proven to have truncated anything.
- **Recommended fix:** Assert `len(results) == 1` (exact), and optionally first assert the uncapped search returns 16.
#### `test_search_on_minimal_data_does_not_crash` — HIGH — conditional skips real check(N6)
- **Location:** tests/test_hexcore_e2e/test_bridge_search_numeric_deep.py:278
- **Current behavior:** Writes a 4-byte buffer holding exactly `0xDEADBEEF`, searches for it, asserts `isinstance(results, list)`, then `if results: assert results[0]["offset"] == 0 and length == 4`.
- **Why it is not a gate:** The value is definitely present (it is the whole buffer), so a correct search must return one match at offset 0; but the offset/length assertions are guarded by `if results:`, so a broken search returning `[]` passes via the only unconditional check (`isinstance`).
- **Recommended fix:** Drop the guard: `assert len(results) == 1`, `assert results[0]["offset"] == 0`, `assert results[0]["length"] == 4`.

### tests/test_hexcore_e2e/test_bridge_state_integration.py
#### `test_state_holder_accessible_after_set` — LOW — weaker duplicate(N8)
- **Location:** tests/test_hexcore_e2e/test_bridge_state_integration.py:88
- **Current behavior:** Calls `set_state_holder(state)` then asserts `bridge.state_holder is not None`.
- **Why it is not a gate:** It fails only if `set_state_holder` stored nothing; the immediately preceding test (:78) already asserts `bridge.state_holder is state`. A regression storing the wrong object slips past `is not None`. As written it gates almost nothing the stronger test does not.
- **Recommended fix:** Tighten to `assert bridge.state_holder is state` (identity), or remove as redundant.

## Acceptable skips (not flagged)
- tests/test_hexcore_e2e/conftest.py:36 module `importorskip("intellicrack_hexcore")` — native module not built; the whole suite depends on it. Legitimate.
- All per-file module-level `importorskip("intellicrack_hexcore")` guards (alignment_color:22, arithmetic:21, base_convert:20, bit_ops:30, block_ops:21, bps_ups:22, compare_files:31, copy_as_complete:21, disassembly_deep:21, display_modes_complete:20, document_info:21, encoding_decoding:27, html_export_largefile:21, new_capabilities, patches, pattern_engine:22, pe_checksum:22, sandbox:33, scripting:33, search_numeric_deep:22, signatures:21, state_integration:36) — legitimate native-module-not-built environment skips, not capability-masking.
- tests/test_hexcore_e2e/test_bridge_disassembly.py:21 and test_bridge_disassembly_deep.py:22 `importorskip("capstone")` — legitimate optional-dependency skip.
- tests/test_hexcore_e2e/test_bridge_pe_introspection.py:47 `importorskip("pefile")` — legitimate optional-dependency skip; :286/:299 `kernel32_dll`/`notepad_exe` fixtures skip when not on Windows / file absent — environment-capability skip (synthetic-PE tests still cover the parsing logic cross-platform).
- tests/test_hexcore_e2e/test_bridge_new_capabilities.py:671/:688/:702/:730 `skipif(os.name != "nt")` plus the inner "No read-write regions available" skip — legitimate Windows-only process-memory environment skips; the core read assertion (`len(clean_hex) == 32`) still gates a successful read when a region exists.
- tests/test_hexcore_e2e/test_bridge_state_integration.py:364/:375 `test_execute_pattern_fires_pattern_executed` skips when the HexPat interpreter is unavailable — legitimate optional-component skip; all other event paths remain gated.

## Notes
- The two production-defect-related files (test_bridge_pe_checksum.py, test_bridge_sandbox.py) are genuinely strict gates, not intentionally-red placeholders: pe_checksum uses an independent oracle (offset 216, calculated 60996) with exact-equality assertions; sandbox asserts the exact guard error message AND the boundary (guard satisfied -> proceeds into the real SandboxBridge raising `Invalid sandbox_type`).
- The dominant non-gate pattern across part 1 is **N6 upper-bound / conditional-guarded assertions in the search and disassembly tests** (`len(results) <= cap`, `if results:`, `if undone:`), where a totally broken operation that returns `[]`/`False` stays green. The second pattern is **N8 type/existence/shape-only checks** (`isinstance(result, list)`, `iscoroutine(...)`, dict-key presence, literal-`True` returns) on methods whose claimed behavior is never observed.
