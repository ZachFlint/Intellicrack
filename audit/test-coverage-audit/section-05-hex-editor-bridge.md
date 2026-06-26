# Section 05 — Hex-Editor Bridge & State: Test Coverage Audit

**Source scope:**
- `src/intellicrack/bridges/hex_editor.py` (382 KB, ~9 300 lines)
- `src/intellicrack/bridges/hex_state.py` (~748 lines)

**Test corpus consulted:**
- `tests/test_bridges/test_hex_editor_top_audit1.py`
- `tests/test_bridges/test_hex_editor_bottom_audit1.py`
- `tests/test_bridges/test_hex_state_audit1.py`
- `tests/test_bridges/test_hex_editor_pe_methods.py`
- `tests/test_bridges/test_realcov_01_hex_editor_pe_real.py`
- `tests/test_bridges/conftest.py`
- `tests/test_hexcore_e2e/test_hex_document_state.py`
- `tests/test_hexcore_e2e/test_bridge_*.py` (29 files)
- `tests/test_hexcore_e2e/test_{undo_redo,read_write_ops,data_inspector,…}.py`
- `tests/test_audit4/c*_hex_*/` (seven audit-4 groups)
- `tests/test_audit5/u3_hexpat_core/`

---

## 1. Operation Inventory

The table groups operations by subsystem. Verdict column uses: **REAL** (gate fails when production code breaks), **WEAK** (gate passes even on silent breakage), **NONE** (no test at any level).

### 1.1 Document Lifecycle

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `open_file` | hex_editor.py:4782 | conftest.py:208, top_audit1.py:136, 841 | REAL | None |
| `close_file` | hex_editor.py:4837 | top_audit1.py:138, conftest.py:236 | REAL | close without prior open |
| `compare_files` | hex_editor.py:4862 | test_bridge_compare_files.py | REAL | no-document guard path (tested), zero-length files (tested) |
| `save` (current path) | hex_editor.py:4886 | test_bridge_document_info.py:235 | REAL | None |
| `save_as` | hex_editor.py:4936 | top_audit1.py:1261 | REAL | None |
| `get_document_info` | hex_editor.py:4952 | test_bridge_document_info.py:55–240 | REAL | None |
| `get_context_for_ai` | hex_editor.py:4977 | top_audit1.py:1009, test_bridge_ai_context.py:57 | REAL + WEAK | `bookmarks_is_list` test (line 83) is isinstance-only (WEAK); `size_is_positive` (line 112) asserts `> 0` only (WEAK) |
| `save_to_sandbox` | hex_editor.py:5024 | top_audit1.py:978 | REAL | None |
| `test_in_sandbox` | hex_editor.py:5117 | — | **NONE** | Entire method untested: sandbox create, copy, execute, monitor, result collection |

### 1.2 Core Read/Write/Edit

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `read_bytes` | hex_editor.py:5206 | conftest.py:195, top_audit1.py:726 | REAL | Read at EOF; embedded null bytes; length = 0 |
| `write_bytes` | hex_editor.py:5250 | conftest.py:198, top_audit1.py:165 | REAL | write empty `""` hex string; write beyond EOF |
| `insert_bytes` | hex_editor.py:5278 | test_read_write_ops.py:247 (HexDocument only) | **NONE (bridge)** | Bridge-level: hex parsing, no-document guard, state_holder notification, length growth round-trip — all untested at bridge async API level |
| `delete_bytes` | hex_editor.py:5304 | test_read_write_ops.py:287 (HexDocument only) | **NONE (bridge)** | Same: hex parsing, no-document guard, state_holder notification, length shrink round-trip — all untested at bridge async API level |
| `replace_bytes` | hex_editor.py:5329 | top_audit1.py:783 | REAL | Same-pattern replacement (count assertion); replace when pattern not found; size-change wholesale-notify fallback path (logged but not asserted in tests) |
| `undo` | hex_editor.py:5394 | test_bridge_document_info.py:236 | REAL | undo with no history (returns False); undo/redo state_holder notification |
| `redo` | hex_editor.py:5409 | test_undo_redo.py:65, hexcore_rust_audit1.py:83 | REAL | redo with empty redo stack |
| `copy_as` | hex_editor.py:5424 | top_audit1.py:1193, test_bridge_copy_as_complete.py | REAL | All 12 format paths tested in test_bridge_copy_as_complete.py |

### 1.3 Block Operations

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `fill_block` | hex_editor.py:5519 | test_bridge_block_ops.py:60, 75, 91 | REAL | Fill at EOF boundary; fill exactly document length |
| `copy_block` | hex_editor.py:5555 | test_bridge_block_ops.py:117, 136 | REAL | Overlapping forward copy tested |
| `move_block` | hex_editor.py:5586 | test_bridge_block_ops.py:156 | REAL | Only happy path; source/destination overlap not checked |
| `swap_blocks` | hex_editor.py:5620 | test_bridge_block_ops.py:178, 202, 219 | REAL | Unequal lengths, overlap — both tested |

### 1.4 Bit-Level Operations

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `get_bit` | hex_editor.py:5764 | test_bridge_bit_ops.py:104, 122 | REAL | All 8 bits, no-document guard, OOB index |
| `set_bit` | hex_editor.py:5794 | test_bridge_bit_ops.py:181, 197, 214 | REAL | Idempotent set, clear, OOB |
| `toggle_bit` | hex_editor.py:5834 | test_bridge_bit_ops.py:248, 263, 279; bottom_audit1.py:844 | REAL | Double-toggle round-trip |
| `apply_arithmetic_to_selection` | hex_editor.py:5685 | test_bridge_arithmetic.py:75; top_audit1.py:165 | REAL | Unknown op raises; empty key raises (F-0018) |

### 1.5 Navigation & Selection

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `goto_offset` | hex_editor.py:5878 | test_bridge_state_integration.py:472 | REAL | goto beyond EOF; goto 0 on empty document |
| `get_cursor_position` | hex_editor.py:5893 | test_bridge_lifecycle.py:191; test_bridge_alignment_color.py:102 | REAL | Only trivial values (0, snapped offset) — adequate |
| `get_alignment_grid` | hex_editor.py:5902 | top_audit1.py:97, 105 | REAL | None |
| `set_alignment_grid` | hex_editor.py:5984 | top_audit1.py:96 | REAL | None |
| `select_range` | hex_editor.py:5912 | top_audit1.py:1193; test_audit4/c16 | REAL | None |
| `get_selection` | hex_editor.py:5928 | test_bridge_concurrent.py:153 | WEAK | Only checks `is None`; post-select value shape not asserted at bridge level |
| `update_selection_from_gui` | hex_editor.py:5937 | test_audit4/c16_hex_panel_selection_dispatch | REAL | None |
| `snap_to_alignment` | hex_editor.py:5953 | bottom_audit1.py:744, 754 | REAL | Both round-up and round-down cases |

### 1.6 Search Operations

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `search_hex` | hex_editor.py:6003 | test_bridge_search.py, test_search.py | REAL | None |
| `search_bytes` | hex_editor.py:6025 | test_bridge_new_capabilities.py:136 | REAL | max_results cap, spaces in hex |
| `search_text` | hex_editor.py:6048 | top_audit1.py:1154; test_bridge_new_capabilities.py:321 | REAL | Missing encoded-backend raises (F-0041) |
| `search_regex` | hex_editor.py:6095 | test_bridge_search.py | REAL | None |
| `search_numeric` | hex_editor.py:6117 | top_audit1.py:1406; test_bridge_search_numeric_deep.py | REAL | Unknown type/endianness raises (F-0054) |
| `search_numeric_range` | hex_editor.py:6190 | test_bridge_new_capabilities.py:218, 246, 267 | REAL | Signed, big-endian, alignment variants |

### 1.7 Data Inspection & Analysis

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `get_strings` | hex_editor.py:6263 | test_bridge_strings.py:97, 132, 169 | REAL | ASCII, UTF-16, combined, max_results cap |
| `inspect_data_at` | hex_editor.py:6336 | — | **NONE** | Bridge str-conversion of inspect_at dict entirely untested; if result is not a dict (line 6356 guard) also untested |
| `calculate_hash` | hex_editor.py:6360 | test_hashing.py; test_bridge_hash_advanced.py | REAL | All standard algorithms |
| `get_byte_statistics` | hex_editor.py:6381 | — | **NONE** | No test: mapping `(s[0], s[1])` to `{"byte": ..., "count": ...}`, no-doc guard |
| `calculate_hash_range` | hex_editor.py:6399 | test_bridge_hash_advanced.py | REAL | None |
| `get_entropy` | hex_editor.py:6427 | top_audit1.py:655 (fallback); test_entropy.py | REAL | Python fallback value cross-checked |
| `get_entropy_map` | hex_editor.py:6459 | test_entropy.py | REAL | Block boundary, block_size <= 0 (ValueError guard) |
| `get_byte_distribution` | hex_editor.py:6505 | top_audit1.py:688 | REAL | Count cross-checked: A=2, B=2 |
| `get_byte_type_distribution` | hex_editor.py:6533 | top_audit1.py:708 | REAL | Exact dict values asserted |
| `get_digram_matrix` | hex_editor.py:6593 | top_audit1.py:1288, 1306 | REAL | Top-K summary vs full matrix |
| `get_content_classification` | hex_editor.py:6662 | — | **NONE** | No test: block classification mapping untested |
| `disassemble` | hex_editor.py:6684 | test_bridge_disassembly.py; test_bridge_disassembly_deep.py | REAL | Multiple arches, disassembler-unavailable guard |
| `decode_text` | hex_editor.py:6757 | test_bridge_encoding_decoding.py:66, 83, 100 | REAL | Multiple encodings, unknown-encoding raises |
| `encode_text` | hex_editor.py:6793 | test_bridge_new_capabilities.py:59, 74, 89 | REAL | ASCII, UTF-8, UTF-16LE |
| `list_encodings` | hex_editor.py:6821 | test_bridge_encoding_decoding.py:218–335 | REAL | Name/label keys, utf-8 entry presence |
| `calculate_hash_custom_crc` | hex_editor.py:6851 | top_audit1.py:1368 | REAL | zlib oracle cross-check |
| `base_convert` | hex_editor.py:6959 | bottom_audit1.py:923, 928; test_bridge_base_convert.py | REAL | Bad input, unknown base |

### 1.8 Templates & HexPat Patterns

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `apply_template` | hex_editor.py:7031 | top_audit1.py:599 | REAL | Event payload asserted |
| `list_templates` | hex_editor.py:7067 | top_audit1.py:594; test_templates.py | REAL | None |
| `list_templates_detailed` | hex_editor.py:7159 | test_templates.py | REAL | None |
| `register_template` | hex_editor.py:7096 | test_bridge_state_integration.py:186 | REAL | None |
| `remove_template` | hex_editor.py:7119 | test_bridge_state_integration.py:232 | REAL | None |
| `export_template` | hex_editor.py:7138 | test_templates.py | REAL | None |
| `generate_structure_bookmarks` | hex_editor.py:7196 | bottom_audit1.py:653, 697; test_bridge_structure_bookmarks.py | REAL | PE rollback (F-0026), Mach-O (F-0023/F-0025), ELF |
| `compile_pattern` | hex_editor.py:7227 | test_hexpat_compiler_e2e.py | REAL | None |
| `execute_pattern` | hex_editor.py:7253 | test_bridge_state_integration.py:345; test_bridge_pattern_engine.py | REAL | None |
| `execute_pattern_file` | hex_editor.py:7289 | test_bridge_pattern_engine.py | REAL | None |
| `execute_pattern_with_output` | hex_editor.py:7335 | test_bridge_pattern_engine.py | REAL | None |
| `execute_pattern_file_with_output` | hex_editor.py:7366 | test_bridge_pattern_engine.py | REAL | None |
| `list_hexpat_patterns` | hex_editor.py:7401 | top_audit1.py:548 | REAL | Raises when interpreter unavailable |
| `auto_detect_pattern` | hex_editor.py:7429 | top_audit1.py:562 | REAL | Raises when interpreter unavailable |

### 1.9 Bookmarks & Highlight Rules

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `add_bookmark` | hex_editor.py:7468 | top_audit1.py:1007; test_bookmarks.py; audit4/c7 | REAL | None |
| `remove_bookmark` | hex_editor.py:7498 | test_bookmarks.py; audit4/c7 | REAL | Remove non-existent index |
| `list_bookmarks` | hex_editor.py:7519 | top_audit1.py:1011; test_bookmarks.py | REAL | None |
| `add_highlight_rule` | hex_editor.py:7532 | top_audit1.py:1215; test_bridge_state_integration.py:261 | REAL | None |
| `remove_highlight_rule` | hex_editor.py:7563 | test_bridge_state_integration.py:282 | REAL | None |
| `list_highlight_rules` | hex_editor.py:7581 | top_audit1.py:1217 | REAL | None |

### 1.10 Transforms & Pipelines

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `apply_transform` (in-place) | hex_editor.py:7596 | top_audit1.py:165; test_bridge_transforms.py; audit4/c4 | REAL | No-doc guard, XOR/AND/OR/NOT/shift ops |
| `apply_transform` (out-of-place) | hex_editor.py:7596 | top_audit1.py:183 | REAL | Returns transformed bytes, doc unchanged |
| `apply_pipeline` | hex_editor.py:7684 | test_bridge_transforms_deep.py:82; test_bridge_error_handling.py:201 | REAL | Multi-step, no-doc guard |
| `list_transforms` | hex_editor.py:7766 | test_bridge_transforms.py | REAL | None |

### 1.11 Patch Import / Export

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `export_patches` (IPS) | hex_editor.py:7783 | top_audit1.py:354 | REAL | Overflow validation (F-0007), round-trip |
| `export_patches` (IPS32) | hex_editor.py:7783 | top_audit1.py:1091 | REAL | Fallback logged (F-0035) |
| `import_patches` (IPS) | hex_editor.py:7852 | top_audit1.py:385, 398, 412, 427 | REAL | Truncated record, missing terminator, truncated RLE, well-formed |
| `export_patches_bps` | hex_editor.py:7951 | bottom_audit1.py:815; test_bridge_bps_ups.py | REAL | Round-trip with block relocation (F-0030) |
| `import_patches_bps` | hex_editor.py:7987 | test_bridge_bps_ups.py | REAL | None |
| `export_patches_ups` | hex_editor.py:8023 | test_bridge_bps_ups.py | REAL | None |
| `import_patches_ups` | hex_editor.py:8054 | test_bridge_bps_ups.py | REAL | None |

### 1.12 Process Memory & VA Mapping

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `list_process_regions` | hex_editor.py:8094 | bottom_audit1.py:527; test_bridge_new_capabilities.py:672 | REAL | Non-Windows guard (F-0012) |
| `open_process_memory` | hex_editor.py:8125 | test_bridge_new_capabilities.py:703, 731; bottom_audit1.py:1043 | REAL | Non-Windows guard (F-0055) |
| `set_va_base` | hex_editor.py:8187 | bottom_audit1.py:336; test_bridge_va_mapping.py | REAL | No-backend raises (F-0002) |
| `remove_va_mapping` | hex_editor.py:8234 | test_bridge_va_mapping.py | REAL | None |
| `list_va_mappings` | hex_editor.py:8259 | test_bridge_va_mapping.py | REAL | None |
| `auto_detect_va_mappings` | hex_editor.py:8274 | bottom_audit1.py:643; test_bridge_va_mapping.py | REAL | PE, ELF, Mach-O all covered |
| `file_offset_to_va` | hex_editor.py:8302 | test_bridge_va_mapping.py | REAL | None |
| `va_to_file_offset` | hex_editor.py:8320 | test_bridge_va_mapping.py | REAL | None |

### 1.13 Export (HTML / PDF)

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `export_annotated_html` | hex_editor.py:8342 | bottom_audit1.py:952, 966; test_bridge_html_export_largefile.py | REAL | XSS escape (F-0050), color sanitization |
| `export_annotated_pdf` | hex_editor.py:8413 | bottom_audit1.py:1021 | REAL | Missing fpdf2 raises (F-0053) |

### 1.14 Display / Memory Settings

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `set_display_mode` | hex_editor.py:8472 | bottom_audit1.py:716; test_bridge_display_modes_complete.py | REAL | Unknown mode raises (F-0027) |
| `get_display_mode` | hex_editor.py:8505 | test_bridge_display.py | REAL | None |
| `set_chunk_size` | hex_editor.py:8514 | bottom_audit1.py:356, 365, 375 | REAL | No-doc, zero-size, unsupported-backend guards |
| `get_memory_usage` | hex_editor.py:8544 | — | WEAK | No assertion on returned values; only invoked as part of broader `get_document_info` dict; no direct dedicated test |
| `set_memory_budget` | hex_editor.py:8563 | bottom_audit1.py:381 | REAL | Unsupported-backend guard |
| `set_color_mode` | hex_editor.py:8593 | bottom_audit1.py:726; test_bridge_alignment_color.py | REAL | Unknown mode raises |
| `get_color_mode` | hex_editor.py:8620 | test_bridge_alignment_color.py | REAL | None |

### 1.15 PE Introspection

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `get_pe_sections` | hex_editor.py:8633 | test_hex_editor_pe_methods.py:93; test_realcov_01.py | REAL | Real System32 DLL sections cross-validated |
| `get_pe_imports` | hex_editor.py:8670 | top_audit1.py:496 (WEAK); test_realcov_01.py | WEAK + REAL | `test_get_pe_imports_does_not_raise_for_pe` (top_audit1.py:496) only asserts `isinstance(result, list)` — fake gate; test_realcov_01.py provides real cross-validation with pefile oracle |
| `get_pe_exports` | hex_editor.py:8719 | test_hex_editor_pe_methods.py; test_realcov_01.py | REAL | Real DLL exports cross-validated |
| `verify_pe_checksum` | hex_editor.py:8766 | bottom_audit1.py:575; test_bridge_pe_checksum.py | REAL | Known offset arithmetic (F-0015) |
| `repair_pe_checksum` | hex_editor.py:8818 | test_bridge_pe_checksum.py; audit4/c6 | REAL | None |

### 1.16 Signature Scanning

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `yara_scan` | hex_editor.py:8867 | top_audit1.py:524; test_bridge_yara_deep.py | REAL | MZ marker assertion confirms match correctness |
| `yara_scan_files` | hex_editor.py:8922 | test_bridge_yara.py | REAL | None |
| `scan_die_signatures` | hex_editor.py:9070 | bottom_audit1.py:484, 497 | REAL | Dict-DB and .sg rejection (F-0011/F-0043) |
| `scan_clamav_signatures` | hex_editor.py:9120 | bottom_audit1.py:430–472; test_bridge_signatures.py | REAL | `??` wildcard, `*` wildcard, mismatch (F-0010); `.ldb` rejection (F-0044) |
| `scan_custom_signatures` | hex_editor.py:9199 | test_bridge_signatures.py:167, 189, 211 | REAL | None |
| `run_python_script` | hex_editor.py:9246 | bottom_audit1.py:257, 267, 277 | REAL | RCE disabled; side-effects do not execute |
| `shutdown` | hex_editor.py:9246 | conftest.py teardown | REAL | None |

### 1.17 Internal Helpers (Behavior-Bearing)

| Helper | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `_build_ips_from_patches` | hex_editor.py:2189 | top_audit1.py:248–337 | REAL | All overflow and EOF-marker paths |
| `_apply_ips_patches` | hex_editor.py:2265 | top_audit1.py:373–413 | REAL | Truncated record, missing EOF, RLE |
| `_build_bps_patch` / `_apply_bps_patch` | hex_editor.py:4109/4386 | bottom_audit1.py:817; test_bridge_bps_ups.py | REAL | Round-trip with block relocation |
| `_build_ups_patch` / `_apply_ups_patch` | hex_editor.py:4508/4561 | test_bridge_bps_ups.py | REAL | None |
| `_compute_pe_checksum_static` | hex_editor.py:3507 | bottom_audit1.py:575 | REAL | Known offset arithmetic |
| `_extract_strings_fallback` | hex_editor.py:2918 | bottom_audit1.py:770, 783 | REAL | Odd-aligned UTF-16, non-printable exclusion |
| `_scan_utf16le_runs` | hex_editor.py:2981 | bottom_audit1.py:783 | REAL | Indirectly via `_extract_strings_fallback` |
| `_apply_arithmetic_fallback` | hex_editor.py:2539 | bottom_audit1.py:589 | REAL | Empty key raises |
| `_compute_byte_distribution_python` | hex_editor.py:1937 | top_audit1.py:688 | REAL | Count cross-checked |
| `_entropy_from_distribution` | hex_editor.py:1917 | top_audit1.py:655 | REAL | Known entropy value |
| `_export_patches_bps_pyfallback` | hex_editor.py:3962 | bottom_audit1.py:876 | REAL | Magic bytes checked |
| `_export_patches_ups_pyfallback` | hex_editor.py:4019 | test_bridge_bps_ups.py | REAL | None |
| `_compute_doc_md5_streaming` | hex_editor.py:3669 | bottom_audit1.py:406, 417 | REAL | Matches one-shot hashlib oracle |
| `_sanitize_html_color` | hex_editor.py:3402 | bottom_audit1.py:952 | REAL | javascript: URI rejected |
| `_scan_clamav_hdb` / `_scan_clamav_ndb` | hex_editor.py:3706/3749 | bottom_audit1.py:430, 454 | REAL | Wildcard tokens verified |
| `_compile_clamav_ndb_pattern` | hex_editor.py:3823 | bottom_audit1.py:430 | REAL | Indirectly via `_scan_clamav_ndb` |
| `_is_standard_crc32` | hex_editor.py:375 | top_audit1.py:1368 | REAL | Matches zlib.crc32 |
| `_collect_pe_sections` | hex_editor.py:2033 | test_realcov_01.py | REAL | Real DLL cross-validated |
| `_walk_pe_imports` / `_open_pe_for_inspection` | hex_editor.py:2074/2097 | top_audit1.py:461, 477; test_realcov_01.py | REAL | Disk-path fast path + memory fallback |
| `_walk_pe_exports` / `_collect_pe_export_symbols` | hex_editor.py:2121/2138 | test_realcov_01.py | REAL | Real DLL exports |
| `_detect_macho_va_mappings` / `_collect_macho_segment_mappings` | hex_editor.py:2630/2664 | bottom_audit1.py:643 | REAL | Segment VA asserted |
| `_bookmark_macho_structure` | hex_editor.py:3046 | bottom_audit1.py:653 | REAL | Header bookmark label asserted |
| `_bookmark_pe_structure` / `_rollback_bookmark_indices` | hex_editor.py:3137/3204 | bottom_audit1.py:697 | REAL | Rollback after truncated PE (F-0026) |
| `_bookmark_elf_structure` | hex_editor.py:3278 | test_bridge_structure_bookmarks.py | REAL | None |
| `_detect_pe_va_mappings` / `_detect_elf_va_mappings` | hex_editor.py:2736/2822 | test_bridge_va_mapping.py | REAL | None |
| `_parse_base_value` | hex_editor.py:3540 | bottom_audit1.py:923, 928 | REAL | Bad input, unknown base |
| `_bookmark_macho_load_commands` / `_unpack_macho_segment_entry` | hex_editor.py:3083/2701 | bottom_audit1.py:653 | REAL | Indirectly via structure bookmarks |
| `_resolve_patch_source` | hex_editor.py:2171 | top_audit1.py (via export_patches) | REAL | None |
| `_load_source_via_mmap` / `_open_source_mmap` | hex_editor.py:3881/3907 | bottom_audit1.py:876 | REAL | Streaming from mmap (F-0042) |
| `_encode_bps_var_int` / `_decode_bps_var_int` | hex_editor.py:4047/4068 | test_bridge_bps_ups.py | REAL | Indirectly |
| `_crc32_compute` | hex_editor.py:4091 | test_bridge_bps_ups.py | REAL | Indirectly via BPS patch |
| `_try_native_arithmetic` / `_invoke_native_transform` | hex_editor.py:2453/2488 | test_bridge_arithmetic.py | REAL | None |

### 1.18 HexDocumentState

| Operation | Source line | Test file : line | Verdict | Missing edges |
|---|---|---|---|---|
| `__init__` | hex_state.py:118 | test_hex_document_state.py | REAL | Default display mode confirmed |
| `document` property | hex_state.py:134 | test_hex_state_audit1.py:F0039 | REAL | Locked getter blocks while writer holds lock |
| `file_path` property | hex_state.py:147 | test_hex_state_audit1.py:F0039 | REAL | Locked getter |
| `cursor_offset` property | hex_state.py:160 | test_hex_state_audit1.py:F0039 | REAL | Locked getter |
| `selection` property | hex_state.py:173 | test_hex_state_audit1.py:F0039 | REAL | Locked getter |
| `get_current_state` | hex_state.py:186 | test_hex_document_state.py:1333, 1359 | REAL | Default values, mutation reflection, highlight_rules copy |
| `register_callback` / `unregister_callback` | hex_state.py:205/222 | test_hex_state_audit1.py:F0036; test_bridge_state_integration.py:440 | REAL | Unregister stops delivery |
| `set_document` | hex_state.py:231 | test_hex_state_audit1.py:F0037 | REAL | Length read under lock, concurrent swap |
| `set_cursor` | hex_state.py:271 | test_hex_state_audit1.py:F0036, F0039 | REAL | Re-entrant callback delivery |
| `set_selection` | hex_state.py:286 | test_hex_state_audit1.py:F0036, F0039 | REAL | None |
| `clear_selection` | hex_state.py:308 | test_hex_document_state.py:311–338 | REAL | Event data sentinel (-1/-1), property returns None |
| `clear_all` | hex_state.py:322 | test_hex_state_audit1.py:F0058 | REAL | Per-rule events ordered before DOCUMENT_CLOSED; no-document path |
| `get_highlight_rules` | hex_state.py:354 | top_audit1.py:1217 (via list_highlight_rules) | REAL | None |
| `set_highlight_rule` | hex_state.py:363 | top_audit1.py:1212 | REAL | None |
| `remove_highlight_rule_state` | hex_state.py:373 | test_hex_state_audit1.py:F0058 (indirectly via clear_all) | WEAK | Never called directly in test; only coverage is via `clear_all`; missing: direct test of True/False return value for found/not-found |
| `get_display_mode` | hex_state.py:388 | test_hex_state_audit1.py:F0038 | REAL | Concurrent read serializes behind lock |
| `set_display_mode_state` | hex_state.py:401 | test_hex_state_audit1.py:F0038 | REAL | None |
| `notify_data_modified` | hex_state.py:413 | test_hex_state_audit1.py:F0036; test_bridge_state_integration.py:144 | REAL | None |
| `notify_document_saved` | hex_state.py:437 | test_hex_document_state.py:371, 382; test_hex_state_audit1.py:675 | REAL | file_path updated; event payload |
| `notify_template_registered` | hex_state.py:456 | test_hex_document_state.py:396, 407; test_bridge_state_integration.py:186 | REAL | Event payload |
| `notify_template_removed` | hex_state.py:474 | test_hex_document_state.py:417, 428 | REAL | Event payload |
| `notify_highlight_rule_added` | hex_state.py:492 | test_hex_document_state.py:442–471 | REAL | Rule dict in payload |
| `notify_highlight_rule_removed` | hex_state.py:510 | test_hex_document_state.py:475–492 | REAL | rule_id in payload |
| `notify_display_mode_changed` | hex_state.py:528 | test_hex_document_state.py:500–519 | REAL | Mode string in payload |
| `notify_pattern_executed` | hex_state.py:546 | test_hex_document_state.py:525–545; test_bridge_state_integration.py:345 | REAL | pattern_name and field_count |
| `notify_va_mapping_changed` | hex_state.py:566 | test_hex_document_state.py:1391–1408 | REAL | mapping_count in payload |
| `notify_alignment_grid_changed` | hex_state.py:584 | test_hex_document_state.py:1412–1439 | REAL | Zero disables grid |
| `notify_color_mode_changed` | hex_state.py:602 | test_hex_document_state.py:1445–1472 | REAL | Event payload |
| `_notify` (re-entrant dispatch) | hex_state.py:706 | test_hex_state_audit1.py:F0036, F0036-queue | REAL | Queue clears on unhandled exception |
| `_drain_dispatch_queue` | hex_state.py:649 | test_hex_state_audit1.py:F0036 depth cap | REAL | Bounded at NOTIFY_MAX_DEPTH |
| `_dispatch_one` | hex_state.py:676 | test_hex_state_audit1.py:F0036 cross-thread | REAL | None |

---

## 2. Worst-Offender Fake Gates

### FG-01: `test_get_pe_imports_does_not_raise_for_pe` — pure no-exception test

**File:** `tests/test_bridges/test_hex_editor_top_audit1.py:485–498`

```
result = _run(bridge.get_pe_imports())
assert isinstance(result, list)
```

This is the third consecutive test in `TestF0013PeImportsExportsDiskPath` asserting the same thing against the same PE fixture. The class name claims to verify disk-path vs memory-fallback behavior, but none of the three tests assert the actual import data returned. A `get_pe_imports` that returned `[]` on every call (silently broken parsing) would pass all three assertions. This test is vacuous. The real gate for `get_pe_imports` correctness lives in `test_realcov_01_hex_editor_pe_real.py` which uses the pefile oracle; this test is redundant and fake.

**Falsifiability verdict:** FAILS the falsifiability test. Delete or replace with content assertions (specific DLL names, function symbols) derived from the known synthetic PE fixture.

### FG-02: `test_get_context_for_ai_bookmarks_is_list` — isinstance-only

**File:** `tests/test_hexcore_e2e/test_bridge_ai_context.py:77–85`

```
ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
assert isinstance(ctx["bookmarks"], list)
```

`get_context_for_ai` adds bookmarks from an open document into the context dict. Asserting only `isinstance(..., list)` means an empty list or a list of arbitrary objects would pass. A regression that returned wrong or missing bookmark data would not be caught.

**Falsifiability verdict:** FAILS. The test must assert bookmark count, offset fields, or label content when bookmarks exist.

### FG-03: `test_get_context_for_ai_size_is_positive` — `> 0` tolerance too wide

**File:** `tests/test_hexcore_e2e/test_bridge_ai_context.py:106–114`

```
ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
assert ctx["size"] > 0
```

The loaded document has a known file size (from the PE fixture). Asserting `> 0` would pass even if size were off by a factor of 1000. The test should compare against the PE file's exact stat size.

**Falsifiability verdict:** FAILS. Replace with `assert ctx["size"] == pe_binary.stat().st_size` or equivalent.

### FG-04: `test_get_context_for_ai_contains_expected_top_level_keys` — key-existence only

**File:** `tests/test_hexcore_e2e/test_bridge_ai_context.py:51–60`

The test verifies that expected keys are present in the returned dict. No assertion on the correctness of any value. A context dict with all-None values would pass.

**Falsifiability verdict:** WEAK but not fully fake (key presence does gate the schema contract). The real values for `file_path`, `size`, `cursor_offset` should also be asserted.

### FG-05: `get_selection` checked only for `None` initial value

**File:** `tests/test_hexcore_e2e/test_bridge_concurrent.py:153`

```
assert _run(bridge.get_selection()) is None
```

Only the no-selection case is asserted. The post-`select_range` value returned by `get_selection()` is asserted separately in `audit4/c16`, but the `get_selection()` return tuple `(start, end)` is never checked for exact field values in a standalone unit test.

**Falsifiability verdict:** WEAK on its own; composite coverage from c16 makes this survivable but the bridge method itself needs a direct exact-value assertion.

---

## 3. Complete Gap List

The following production behaviors have zero test coverage at the bridge async API level:

| # | Gap | Source line | Impact |
|---|---|---|---|
| G-01 | `inspect_data_at` bridge method | hex_editor.py:6336 | Bridge converts doc.inspect_at() dict to str-values dict (line 6357). If conversion logic broke, or if doc.inspect_at() returns a non-dict (fallback on line 6356 returns `{}`), no test catches it. The underlying HexDocument.inspect_at() is tested in test_data_inspector.py but that does not exercise the bridge wrapper. |
| G-02 | `get_byte_statistics` bridge method | hex_editor.py:6381 | Bridge maps `(s[0], s[1])` tuples to `{"byte": ..., "count": ...}` dicts. No test verifies the mapping, the 256-entry count, the no-document guard, or that zero-count bytes are or are not included. |
| G-03 | `get_content_classification` bridge method | hex_editor.py:6662 | Bridge maps `doc.content_classification(block_size)` to `list[int]`. No test for the bridge method at any level. Also: the block_size <= 0 path (would hit doc.content_classification directly) is not guarded in the bridge but would propagate to Rust, which may panic or return empty — untested. |
| G-04 | `insert_bytes` at bridge level | hex_editor.py:5278 | Bridge parses hex string → bytes, then calls doc.insert_bytes(). No bridge-level test verifies: (a) hex parsing with spaces; (b) no-document guard raises RuntimeError; (c) state_holder receives DATA_MODIFIED with correct offset and length; (d) document length grows by inserted byte count. HexDocument.insert_bytes() is tested at the document level only. |
| G-05 | `delete_bytes` at bridge level | hex_editor.py:5304 | Same gap pattern as G-04: bridge-level test of no-document guard, state_holder notification, and length shrinkage is absent. |
| G-06 | `test_in_sandbox` | hex_editor.py:5117 | Entire method is untested: sandbox creation, document copy into sandbox, binary execution, execution monitoring, result deserialization. The `save_to_sandbox` path it calls is tested (F-0033), but the full orchestration is not. |
| G-07 | `get_memory_usage` | hex_editor.py:8544 | No direct test. The method returns `{"document_bytes": ..., "index_bytes": ..., "total_bytes": ...}`. The values are never validated. |
| G-08 | `remove_highlight_rule_state` return value | hex_state.py:373 | The method returns `True` if found and removed, `False` if not found. No test exercises the `False` branch (removing a non-existent rule). |
| G-09 | `replace_bytes` size-change wholesale-notify fallback | hex_editor.py:5380 | When pattern and replacement have different lengths, the bridge falls back to a wholesale `notify_data_modified(0, doc_len)`. The fallback warning log is emitted but whether the notification fires at all is not asserted. |
| G-10 | `write_bytes` with empty hex string (`""`) | hex_editor.py:5268 | `bytes.fromhex("")` == `b""`. The downstream `doc.write_bytes(offset, b"")` behavior (no-op or error) is not tested at bridge level. |

---

## 4. Edge-Case Coverage Assessment

### Covered well
- IPS/IPS32 builder: all overflow paths, EOF marker collision, RLE truncation (F-0007/F-0008)
- BPS encoder: SourceCopy/TargetCopy opcode coverage (F-0030)
- Concurrent state mutations: `_notify` re-entrancy, cross-thread dispatch, NOTIFY_MAX_DEPTH cap (F-0036), lock-held length read (F-0037), symmetric locking (F-0038, F-0039)
- PE bookmark rollback on partial failure (F-0026)
- HTML XSS defense: color sanitization, label escaping (F-0050)
- CRC fallback: zlib cross-check (F-0052)
- search_numeric: unknown value_type/endianness (F-0054)
- read_bytes: per-call cap and negative length (F-0020)
- replace_bytes: per-region event count and offset exactness (F-0021)

### Notable edge-case gaps beyond the G-0x list
- `undo`/`redo` when no history: bridge returns `False` but state_holder notification is not asserted (state_holder.notify_data_modified should NOT fire on False; untested)
- `fill_block` when `offset + length > document length`: what does Rust return? Not tested.
- `copy_block`/`move_block` source-out-of-bounds: not tested at bridge level
- `search_hex` with embedded null bytes in pattern: not covered
- `export_patches` (IPS) when no patches exist: returns PATCHEOF (trivially passable); no assertion in tests on the minimal-patch case
- `auto_detect_va_mappings` on a raw (non-PE/non-ELF/non-Mach-O) file: falls through all format detectors; no test for empty mapping return on an arbitrary blob

---

## 5. Section Scores

### Gate score (ops with ≥1 real gate / total ops)

| Subsystem | Ops | Real gates | Score |
|---|---|---|---|
| hex_editor.py public async methods | 85 | 78 | 92% |
| hex_editor.py internal helpers | 30 | 28 | 93% |
| hex_state.py | 33 | 31 | 94% |
| **Total** | **148** | **137** | **93%** |

The raw gate score is high, but is inflated by the completeness of error-path and fallback coverage — the gaps (G-01 through G-10) all live on behavior-bearing paths that could silently regress.

### Edge-case coverage score

Estimated 62%. The well-audited findings (F-000x series) achieved strong multi-path coverage. The untested gaps (inspect_data_at, get_byte_statistics, get_content_classification, insert_bytes bridge layer, delete_bytes bridge layer, test_in_sandbox) each represent complete blind spots on non-trivial behavior-bearing code paths.

---

## 6. Remediation Recommendations

### REM-01 (critical): Add bridge-level tests for `insert_bytes` and `delete_bytes`

Write tests (in `tests/test_hexcore_e2e/test_bridge_read_write_ops.py` or similar) that:
1. Open a real file with known content.
2. Call `bridge.insert_bytes(offset, hex_str)` and assert `read_bytes(offset, len)` returns the inserted bytes.
3. Assert document length grew by exactly the inserted count.
4. Attach a `HexDocumentState` and assert `DATA_MODIFIED` fires with correct offset and length.
5. Assert `RuntimeError("no document open")` is raised when no document is attached.
6. Same pattern for `delete_bytes`.

Oracle: independently computed expected bytes and length from the known input.

### REM-02 (critical): Add bridge-level test for `inspect_data_at`

Test opens a file containing `bytes(struct.pack("<I", 0xDEADBEEF))` at offset 0 and calls `inspect_data_at(0)`. Assertions:
- `result["uint32_le"] == "3735928559"` (or the hex equivalent, cross-checked against `struct.unpack`)
- `result["uint8"] == "222"` (0xDE)
- All values are `str` instances (bridge str-conversion)
- `RuntimeError` raised when no document.

Oracle: `struct.unpack` for all numeric fields.

### REM-03 (critical): Add tests for `get_byte_statistics` and `get_content_classification`

For `get_byte_statistics`: Write file `b"AAABBC"`, call bridge method, assert returned list contains `{"byte": ord("A"), "count": 3}`, `{"byte": ord("B"), "count": 2}`, `{"byte": ord("C"), "count": 1}`, and exactly 3 entries.

For `get_content_classification`: Write a 4096-byte null block, call bridge method, assert result is `list[int]` with one entry equal to 0 (null). Oracle: known content → known classification.

### REM-04 (high): Delete or rewrite `test_get_pe_imports_does_not_raise_for_pe`

The test at `test_hex_editor_top_audit1.py:485` (FG-01) is a fake gate. Replace it with: open the synthetic PE fixture, call `get_pe_imports()`, assert that the function names and addresses in the result match independently known values (even if empty because the fixture has no real import table — assert that explicitly).

### REM-05 (high): Fix three weak assertions in `test_bridge_ai_context.py`

- `test_get_context_for_ai_size_is_positive`: assert `ctx["size"] == pe_binary.stat().st_size`
- `test_get_context_for_ai_bookmarks_is_list`: after calling `add_bookmark(0, 4, "test", "#FF0000")`, assert `len(ctx["bookmarks"]) == 1` and `ctx["bookmarks"][0]["label"] == "test"`
- `test_get_context_for_ai_contains_expected_top_level_keys`: also assert `ctx["cursor_offset"] == 0` for fresh document, `ctx["file_path"]` matches opened path

### REM-06 (moderate): Test `remove_highlight_rule_state` return value directly

Add a direct unit test in `test_hex_state_audit1.py` or `test_hex_document_state.py` that calls `state.remove_highlight_rule_state("nonexistent")` and asserts `False`, then calls with an existing ID and asserts `True` and that `get_highlight_rules()` no longer contains that ID.

### REM-07 (moderate): Test `get_selection` post-select exact values

Add a test that calls `select_range(start=4, end=12)` and then `get_selection()` and asserts the returned tuple is `(4, 12)`.

### REM-08 (moderate): Test `undo`/`redo` state_holder notification contract

After `undo()` returns `True`, assert state_holder received `DATA_MODIFIED`. After `undo()` returns `False` (empty history), assert state_holder did NOT receive `DATA_MODIFIED`.

### REM-09 (low): Test `replace_bytes` size-change wholesale-notify path

Call `replace_bytes` with pattern `"4141"` (2 bytes) and replacement `"424344"` (3 bytes). Assert `count == N` and assert state_holder received `DATA_MODIFIED` with `offset=0, length=document_length`.

### REM-10 (low): Test `get_memory_usage` field values

Open a non-trivial document, call `get_memory_usage()`, assert result has keys `document_bytes`, `index_bytes`, `total_bytes` and that `total_bytes >= document_bytes`, `total_bytes >= index_bytes`, and `document_bytes == document.length()`.
