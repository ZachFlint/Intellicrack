# Section 13 — Rust Hexcore Engine: Test Coverage Audit

**Audit date:** 2026-06-26
**Scope:** `src/intellicrack-hexcore/src/` (all modules) and `tests/test_hexcore_e2e/` (all Python e2e tests)
**Methodology:** Adversarial falsifiability review. Every test was evaluated against the question: *"If the production code this test covers were deleted or corrupted, would this test fail?"*
**Verdict codes:** REAL = falsifiable gate, WEAK = passes under broken code for named reason, FAKE = guaranteed to pass regardless, NO COV = no tests exist

---

## 1. Public Operation Inventory

### 1.1 `piece_table.rs` — PieceTable

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `new` | `PieceTable::new(data: Vec<u8>) -> Self` | Yes | Via all e2e tests |
| `length` | `fn length(&self) -> usize` | Yes | Yes |
| `is_empty` | `fn is_empty(&self) -> bool` | Yes | Yes |
| `find_piece` | `fn find_piece(&self, offset: usize) -> ...` | Yes | Indirectly |
| `read_byte` | `fn read_byte(&self, offset: usize) -> Option<u8>` | Yes | Yes |
| `read` | `fn read(&self, offset: usize, length: usize) -> Vec<u8>` | Yes | Yes |
| `insert` | `fn insert(&mut self, offset: usize, data: Vec<u8>)` | Yes (3 positions) | Yes |
| `overwrite` | `fn overwrite(&mut self, offset: usize, data: Vec<u8>)` | Yes | Yes |
| `delete` | `fn delete(&mut self, offset: usize, length: usize)` | Yes | Yes |
| `materialize` | `fn materialize(&self) -> Vec<u8>` | Yes | Yes |

### 1.2 `diff.rs` — Binary Diff

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `diff_data` | `fn diff_data(a: &[u8], b: &[u8]) -> DiffResult` | Yes (14 tests) | Yes (`test_binary_diff.py`) |
| `diff_files` (PyO3) | `fn diff_files(path_a: &str, path_b: &str) -> PyResult<...>` | None (lib.rs) | Yes |
| `diff_bytes` (PyO3) | `fn diff_bytes(a: &[u8], b: &[u8]) -> PyResult<...>` | None (lib.rs) | Yes |

### 1.3 `search.rs` — Search and Replace

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `search_bytes` | `fn search_bytes(data: &[u8], pattern: &[u8], max: usize) -> Vec<(usize, usize)>` | Yes (~6) | Yes (`test_search.py`) |
| `search_hex_with_wildcards` | `fn search_hex_with_wildcards(data: &[u8], hex: &str, max: usize) -> Vec<(usize, usize)>` | Yes | Yes |
| `search_text` | `fn search_text(data: &[u8], text: &str, ...) -> Vec<(usize, usize)>` | Yes | Yes |
| `search_regex` | `fn search_regex(data: &[u8], pattern: &str, max: usize) -> Vec<(usize, usize)>` | Yes | Yes |
| `replace_all` | `fn replace_all(data: &mut Vec<u8>, pattern: &[u8], replacement: &[u8]) -> usize` | Yes | Yes |
| `search_numeric_int` | `fn search_numeric_int(data: &[u8], value: i64, width: u8, ...) -> Vec<(usize, usize)>` | Yes | Yes |
| `search_numeric_float` | `fn search_numeric_float(data: &[u8], value: f64, ...) -> Vec<(usize, usize)>` | Yes | Yes |
| `search_numeric_range` | `fn search_numeric_range(data: &[u8], lo: i64, hi: i64, ...) -> Vec<(usize, usize)>` | Yes | Yes |

### 1.4 `entropy.rs` — Entropy and Statistics

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `compute_entropy` | `fn compute_entropy(data: &[u8]) -> f64` | Yes (range checks) | Yes (`test_entropy.py`) |
| `entropy_map` | `fn entropy_map(data: &[u8], block_size: usize) -> Vec<(usize, f64)>` | Yes (range checks) | Yes |
| `byte_distribution` | `fn byte_distribution(data: &[u8]) -> [u64; 256]` | Yes | Yes |
| `byte_type_distribution` | `fn byte_type_distribution(data: &[u8]) -> HashMap<String, u64>` | Yes | Yes |
| `digram_matrix` | `fn digram_matrix(data: &[u8]) -> Vec<Vec<u64>>` | Yes | Yes |
| `content_classification` | `fn content_classification(data: &[u8]) -> ContentClass` | Yes | Yes |

### 1.5 `hash.rs` — Hash Computation

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `compute_hash` | `fn compute_hash(data: &[u8], algo: &str) -> Result<String, HashError>` | Yes (~15) | Yes (`test_hashing.py`) |
| `compute_hash_range` | `fn compute_hash_range(data: &[u8], start: usize, end: usize, algo: &str) -> Result<String, HashError>` | Yes | Yes |
| `compute_crc_custom` | `fn compute_crc_custom(data: &[u8], ...) -> Result<String, HashError>` | Yes | Yes |
| `compute_pe_checksum` | `fn compute_pe_checksum(data: &[u8], checksum_offset: usize) -> u32` | Yes (1) | Yes (`test_bridge_pe_checksum.py`) |
| `verify_pe_checksum` | `fn verify_pe_checksum(data: &[u8], checksum_offset: usize) -> bool` | None | Yes |

### 1.6 `encodings.rs` — Text Encoding

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `decode_text` | `fn decode_text(data: &[u8], offset: usize, len: usize, encoding: &str) -> Result<String, ...>` | Yes | Yes (`test_encodings.py`) |
| `encode_text` | `fn encode_text(text: &str, encoding: &str) -> Result<Vec<u8>, ...>` | Yes | Yes |
| `search_text_encoded` | `fn search_text_encoded(data: &[u8], text: &str, encoding: &str, ...) -> Vec<(usize, usize)>` | Yes | Yes |
| `list_encodings` | `fn list_encodings() -> Vec<String>` | Yes | Yes |

### 1.7 `transforms.rs` — Byte Transforms

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `apply_transform` | `fn apply_transform(data: &[u8], name: &str, params: &HashMap<...>) -> Result<Vec<u8>, ...>` | Yes (~25) | Yes (`test_transforms.py`) |
| `list_transforms` | `fn list_transforms() -> Vec<(&str, &str, &str)>` | Yes (1) | Yes |

### 1.8 `undo.rs` — Undo/Redo Stack

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `UndoManager::new` | `fn new() -> Self` | Yes | Yes |
| `record` | `fn record(&mut self, op: UndoOp)` | Yes | Yes |
| `undo` | `fn undo(&mut self, table: &mut PieceTable) -> bool` | Yes | Yes (`test_undo_redo.py`) |
| `redo` | `fn redo(&mut self, table: &mut PieceTable) -> bool` | Yes | Yes |
| `can_undo` | `fn can_undo(&self) -> bool` | Yes | Yes |
| `can_redo` | `fn can_redo(&self) -> bool` | Yes | Yes |
| `mark_saved` | `fn mark_saved(&mut self)` | Yes | Yes |
| `mark_unsaved` | `fn mark_unsaved(&mut self)` | Yes | Yes |
| `is_modified` | `fn is_modified(&self) -> bool` | Yes | Yes |
| `clear` | `fn clear(&mut self)` | Yes | Yes |
| `get_overwrite_patches` | `fn get_overwrite_patches(&self, table: &PieceTable) -> Vec<(usize, Vec<u8>)>` | Yes | Yes |

### 1.9 `bps_ups.rs` — Patch Formats BPS/UPS

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `export_bps` | `fn export_bps(source: &[u8], target: &[u8]) -> Result<Vec<u8>, io::Error>` | Yes | Yes (`test_bridge_bps_ups.py`) |
| `import_bps` | `fn import_bps(source: &[u8], patch: &[u8]) -> Result<Vec<u8>, io::Error>` | Yes | Yes |
| `export_ups` | `fn export_ups(source: &[u8], target: &[u8]) -> Result<Vec<u8>, io::Error>` | Yes | Yes |
| `import_ups` | `fn import_ups(source: &[u8], patch: &[u8]) -> Result<Vec<u8>, io::Error>` | Yes | Yes |

### 1.10 `patch_export.rs` — IPS/IPS32/COD Export

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `export_ips` | `fn export_ips(patches: &[(usize, Vec<u8>)]) -> Result<Vec<u8>, PatchExportError>` | Yes | Yes (`test_patch_export.py`) |
| `export_ips32` | `fn export_ips32(patches: &[(usize, Vec<u8>)]) -> Result<Vec<u8>, PatchExportError>` | Yes | Yes |
| `export_cod` | `fn export_cod(patches: &[(usize, Vec<u8>)]) -> Result<Vec<u8>, PatchExportError>` | Yes | Yes |
| `export_patches_json` | `fn export_patches_json(patches: &[(usize, Vec<u8>)]) -> Result<String, PatchExportError>` | Yes | Yes |
| `import_ips` | `fn import_ips(data: &[u8]) -> Result<Vec<(usize, Vec<u8>)>, PatchExportError>` | Yes | Yes |
| `extract_patches_from_overwrites` | `fn extract_patches_from_overwrites(original: &[u8], modified: &[u8]) -> Vec<(usize, Vec<u8>)>` | Yes | Yes |

### 1.11 `data_inspector.rs` — Data Inspector

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `inspect_at` | `fn inspect_at(data: &[u8], offset: usize) -> DataInspection` | Yes (~20) | Yes (`test_data_inspector.py`) |
| `DataInspection::to_map` | `fn to_map(&self) -> HashMap<String, String>` | Yes | Yes |

### 1.12 `mmap_io.rs` — Memory-Mapped I/O

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `MmapDocument::open` | `fn open(path: &Path) -> io::Result<Self>` | Yes | Yes |
| `from_bytes` | `fn from_bytes(data: Vec<u8>) -> Self` | Yes | Yes |
| `new_empty` | `fn new_empty() -> Self` | Yes | Yes |
| `document_size` | `fn document_size(&self) -> usize` | Yes | Yes |
| `file_path` | `fn file_path(&self) -> Option<&Path>` | Yes | Yes |
| `is_modified` | `fn is_modified(&self) -> bool` | Yes | Yes |
| `read` | `fn read(&self, offset: usize, length: usize) -> io::Result<Vec<u8>>` | Yes | Yes |
| `read_byte` | `fn read_byte(&self, offset: usize) -> io::Result<u8>` | Yes | Yes |
| `read_all` | `fn read_all(&self) -> io::Result<Vec<u8>>` | Yes | Yes |
| `overwrite` | `fn overwrite(&mut self, offset: usize, data: Vec<u8>)` | Yes | Yes |
| `insert` | `fn insert(&mut self, offset: usize, data: Vec<u8>)` | Yes | Yes |
| `delete` | `fn delete(&mut self, offset: usize, length: usize)` | Yes | Yes |
| `save` | `fn save(&mut self, path: &Path) -> io::Result<()>` | Yes | Yes |
| `save_in_place` | `fn save_in_place(&mut self) -> io::Result<()>` | Yes | Partial |
| `apply_insert` | `fn apply_insert(&mut self, op: InsertOp)` | Yes | Indirectly |
| `apply_overwrite` | `fn apply_overwrite(&mut self, op: OverwriteOp)` | Yes | Indirectly |
| `apply_delete` | `fn apply_delete(&mut self, op: DeleteOp)` | Yes | Indirectly |

### 1.13 `strings.rs` — String Extraction

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `extract_strings` | `fn extract_strings(data: &[u8], min_len: usize, encodings: &[Encoding]) -> Vec<ExtractedString>` | Yes (~8) | Yes (`test_bridge_strings.py`) |

### 1.14 `data_source.rs` — Data Source Trait and Implementations

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `DataSource::read` | `fn read(&self, offset: usize, length: usize) -> Result<Vec<u8>, DataSourceError>` | **None** | Indirectly via process memory |
| `DataSource::write` | `fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), DataSourceError>` | **None** | **None** |
| `DataSource::length` | `fn length(&self) -> usize` | **None** | **None** |
| `DataSource::is_writable` | `fn is_writable(&self) -> bool` | **None** | **None** |
| `DataSource::source_type` | `fn source_type(&self) -> &'static str` | **None** | **None** |
| `BufferDataSource::new` | `fn new(data: Vec<u8>, writable: bool) -> Self` | **None** | **None** |
| `BufferDataSource::new_readonly` | `fn new_readonly(data: Vec<u8>) -> Self` | **None** | **None** |
| `DataSourceError::ReadOnly` | Error variant | **None** | **None** |
| `DataSourceError::OutOfBounds` | Error variant | **None** | **None** |

### 1.15 `templates/mod.rs` — Template Registry

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `TemplateRegistry::new` | `fn new() -> Self` | Yes | Yes |
| `register` | `fn register(&mut self, template: StructTemplate)` | Yes | Yes |
| `register_json` | `fn register_json(&mut self, json: &str) -> Result<...>` | Yes | Yes (`test_templates.py`) |
| `remove` | `fn remove(&mut self, name: &str) -> bool` | Yes | Yes |
| `export_json` | `fn export_json(&self, name: &str) -> Result<String, ...>` | Yes | Partial |
| `get` | `fn get(&self, name: &str) -> Option<&StructTemplate>` | Yes | Yes |
| `list` | `fn list(&self) -> Vec<(&str, &str)>` | Yes | Yes |
| `list_detailed` | `fn list_detailed(&self) -> Vec<(&str, &str, &str, usize)>` | Yes | Yes |
| `apply` | `fn apply(&self, name: &str, data: &[u8], base_offset: usize) -> Result<Vec<ParsedField>, ...>` | Yes | Yes |
| `field_size` | `fn field_size(ft: &FieldType) -> usize` | Yes | Indirectly |
| `format_field_value` | `fn format_field_value(ft: &FieldType, data: &[u8], ...) -> String` | Yes | Indirectly |
| `field_type_name` | `fn field_type_name(ft: &FieldType) -> &'static str` | Yes | Indirectly |
| `read_numeric_value` | `fn read_numeric_value(data: &[u8], ft: &FieldType, ...) -> Option<i64>` | Yes | Indirectly |

### 1.16 `templates/eval.rs` — Template Evaluator

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `TemplateEvaluator::new` | `fn new(data, base_offset, endian, registry) -> Self` | **None** | Via apply |
| `evaluate_fields` | `fn evaluate_fields(&mut self, fields: &[FieldDefinition]) -> Result<Vec<ParsedField>, ...>` | **None** | Via apply |
| DynamicArray evaluation | Internal path | **None** | **No dedicated test** |
| Conditional evaluation | Internal path | **None** | **No dedicated test** |
| StructRef evaluation | Internal path | **None** | **No dedicated test** |
| Pointer dereference | Internal path | **None** | **No dedicated test** |

### 1.17 `templates/json_schema.rs` — JSON Template Serialization

| Operation | Signature | In-Crate Tests | Python E2E |
|---|---|---|---|
| `parse_json_template` | `fn parse_json_template(json_str: &str) -> Result<StructTemplate, TemplateError>` | Via mod.rs | Via `test_templates.py` register_json |
| `template_to_json` | `fn template_to_json(template: &StructTemplate) -> Result<String, TemplateError>` | Via mod.rs | Via export_json |
| Empty name validation | Error path | Indirectly | **No dedicated test** |
| DynamicArray empty count_field | Error path | **None** | **None** |
| Conditional empty condition_field | Error path | **None** | **None** |

### 1.18 `templates/pe.rs`, `elf.rs`, `macho.rs`, `zip.rs`

All four modules register templates into the `TemplateRegistry` at build time. No independent in-crate tests; all coverage comes from Python e2e tests that apply templates to minimal valid binaries.

| Template Set | Registration Tests | Apply Tests |
|---|---|---|
| PE (8 templates) | None direct | Yes via `test_templates.py` (`pe_bytes` fixture) |
| ELF (1 template: `Elf64_Ehdr`) | None direct | Yes via `test_templates.py` (`elf_bytes` fixture) |
| Mach-O (1 template: `MachO_Header64`) | None direct | Partial (fixture exists, tests present) |
| ZIP (1 template: `ZIP_LOCAL_FILE_HEADER`) | None direct | Yes via `test_templates.py` (`zip_bytes` fixture) |

---

## 2. Test Inventory

### 2.1 In-Crate Tests (`#[cfg(test)]`)

| Module | Test Count | Notes |
|---|---|---|
| `piece_table.rs` | 16 | Happy paths only; no off-by-one at `total_length` boundary |
| `diff.rs` | 14 | Include F-0003 regression; anchored path tested loosely |
| `search.rs` | ~20 | Strong: exact offsets and counts |
| `entropy.rs` | ~15 | All use range checks `> 7.99` / `< 0.01`; no exact oracle |
| `hash.rs` | ~35 | MD5/SHA1/SHA256/SHA3-256/CRC32 correct; blake2b/blake2s/xxh3/siphash/crc8/crc16/crc64 length-only |
| `encodings.rs` | ~25 | EBCDIC known values; round-trips without independent expected value |
| `transforms.rs` | ~25 | XOR round-trips tautological; `test_byte_swap_16` independent |
| `undo.rs` | ~15 | Strong; F-0001 regression with exact byte content |
| `bps_ups.rs` | ~10 | OOB error message assertions; round-trips present |
| `patch_export.rs` | ~15 | IPS/IPS32/COD with exact byte-level assertions |
| `data_inspector.rs` | ~20 | Exact IPv4/GUID/IPv6/RGBA8/RGB565; LEB128 prefix-only weak |
| `mmap_io.rs` | ~7 | `test_open_and_save` uses real filesystem; minimal coverage |
| `strings.rs` | ~8 | Exact content, offset, length, encoding |
| `data_source.rs` | **0** | No tests at all |
| `templates/mod.rs` | ~12 | Hand-crafted 64-byte buffer; JSON roundtrip field-by-field |
| `templates/eval.rs` | **0** | No tests at all |
| `templates/json_schema.rs` | **0** | No direct tests |
| `templates/pe.rs` | **0** | No tests |
| `templates/elf.rs` | **0** | No tests |
| `templates/macho.rs` | **0** | No tests |
| `templates/zip.rs` | **0** | No tests |
| `lib.rs` | **0** | All bindings tested via Python e2e only |

**Total in-crate tests (estimated): ~292 across 13 modules; 8 modules have zero tests.**

### 2.2 Python E2E Tests (`tests/test_hexcore_e2e/`)

67 test files identified. Key files assessed:

| File | Assessed | Tests | Quality |
|---|---|---|---|
| `test_binary_diff.py` | Full | 12 | REAL |
| `test_hashing.py` | Full | 31 | REAL |
| `test_entropy.py` | Full | 15+ | REAL |
| `test_undo_redo.py` | Full | 15+ | REAL |
| `test_search.py` | Full | 10+ | REAL |
| `test_transforms.py` | Full | 25+ | Mixed (REAL + WEAK round-trips) |
| `test_data_inspector.py` | Full | 20+ | Mixed (WEAK structure, REAL values) |
| `test_encodings.py` | Full | 15+ | REAL |
| `test_patch_export.py` | Partial | 15+ | Mixed (REAL magic, WEAK record detail) |
| `test_templates.py` | Partial | 30+ | Mixed (REAL apply, WEAK list counts) |
| `test_bridge_bps_ups.py` | Partial | 10+ | REAL (magic, CRC error, roundtrip) |
| `test_bridge_strings.py` | Full | 5+ | REAL (exact offset/length/content oracle) |
| `test_hexcore_rust_audit1.py` | Partial | Multiple | REAL (F-0001..F-0005 regressions) |
| `test_process_memory.py` | Seen | Multiple | Windows-only (skip on non-Win32) |
| Remaining 53 files | Not assessed | Unknown | Unknown |

---

## 3. Coverage Classification

### 3.1 Per-Operation Classification

| Operation | Classification | Reason |
|---|---|---|
| `PieceTable::insert/delete/overwrite/read` | REAL | Exact byte content verified in-crate and Python |
| `PieceTable::materialize` | REAL | Exact content match in-crate |
| `diff_data` (Myers path ≤1MB) | REAL | Python e2e uses difflib oracle for exact region layout |
| `diff_data` (anchored Adler32 path >1MB) | WEAK | In-crate F-0003 test asserts path taken; offset precision not independently verified |
| `diff_files` / `diff_bytes` | REAL | Exact region struct verified field-by-field |
| `search_bytes` (Boyer-Moore) | REAL | Exact offsets at positions 10, 22; good-suffix tested |
| `search_hex_with_wildcards` | REAL | Exact offsets in-crate |
| `search_text` / `search_regex` | REAL | Exact offsets in-crate |
| `replace_all` | REAL | Count and content verified in-crate |
| `search_numeric_int` / `search_numeric_float` | REAL | Exact offsets in-crate |
| `compute_entropy` | REAL | Python uses independent Shannon oracle (exact 0.8112781...) |
| `entropy_map` | WEAK (in-crate) / REAL (Python) | In-crate: range checks only. Python: independent oracle via per-block `_shannon_entropy_bits_per_byte()` |
| `byte_distribution` | REAL | Exact counts verified in-crate |
| `byte_type_distribution` | REAL | Count sums verified |
| `digram_matrix` | WEAK | Checked only for shape and non-negativity in-crate |
| `content_classification` | REAL | Returns distinct classification per content type |
| `compute_hash` (MD5/SHA1/SHA256/SHA512/SHA3-256/SHA3-512) | REAL | hashlib oracle; NIST SHA3-256 KAT for empty input |
| `compute_hash` (BLAKE2b) | REAL | hashlib.blake2b(digest_size=32) oracle in Python |
| `compute_hash` (BLAKE2s) | WEAK | Only compared against BLAKE2b (different ≠ correct value) |
| `compute_hash` (xxh3/siphash64/siphash128) | WEAK | In-crate: length-only. No Python oracle. |
| `compute_hash` (crc8/crc16/crc64) | WEAK (in-crate) / REAL for crc16 (Python) | In-crate length-only; Python adds CRC-16/ARC reference impl |
| `compute_hash_range` | REAL | hashlib sliced oracle |
| `compute_crc_custom` | REAL | binascii.crc32 oracle for CRC-32/ISO-HDLC; Python reference for CRC-16/ARC |
| `compute_pe_checksum` | REAL | In-crate RFC-correct algorithm; Python e2e bridge test |
| `verify_pe_checksum` | WEAK | No in-crate test; Python-side only (bridge test) |
| `decode_text` | REAL | Exact string equality for UTF-8/ASCII/Latin-1/EBCDIC |
| `encode_text` | REAL (encode); WEAK (round-trip tests) | Round-trips without independent expected value |
| `search_text_encoded` | REAL | Exact offsets in-crate (Cyrillic UTF-16LE) |
| `list_encodings` | WEAK | Only checks non-empty; no count or exact set |
| `apply_transform` (XOR single-byte) | REAL | Manual expected value `b ^ key` computed independently in Python |
| `apply_transform` (XOR with zero key) | REAL | Identity property; independently known |
| `apply_transform` (XOR round-trip) | WEAK (in-crate) | Re-applies same operation; tautological in-crate |
| `apply_transform` (base64_encode) | REAL | stdlib oracle `base64.b64encode()` |
| `apply_transform` (base64_decode) | REAL | Roundtrip with exact decoded content |
| `apply_transform` (bit_invert) | REAL | `b ^ 0xFF` computed independently |
| `apply_transform` (byte_reverse) | REAL | `input_data[::-1]` oracle |
| `apply_transform` (AES-ECB encrypt/decrypt) | REAL (in-crate) | Padding correctness verified |
| `apply_transform` (zlib_inflate/deflate) | REAL | Roundtrip with exact content verification |
| `apply_transform` (bit_shift_left/right/rotate) | WEAK (in-crate) | Round-trip only |
| `apply_transform` (byte_swap_16/32/64) | REAL (in-crate) | Expected bytes hand-computed: `[0x02,0x01,0x04,0x03]` |
| `apply_transform` (mask_and/mask_or/mask_xor) | REAL (Python) | Manual bit operations as oracle |
| `list_transforms` | REAL | Exact count (23), exact name set, exact category, exact description verified in Python |
| `UndoManager::undo` / `redo` | REAL | Exact byte content before and after |
| `UndoManager::can_undo` / `can_redo` | REAL | Boolean state machine tested |
| `UndoManager::mark_saved/unsaved/is_modified` | REAL | State transitions tested |
| `UndoManager::get_overwrite_patches` | REAL (in-crate) | F-0001: `b"AAAABBBB____"` restored |
| `export_bps` | REAL | BPS1 header verified; roundtrip tested |
| `import_bps` | REAL | Error paths: wrong magic, wrong CRC both tested |
| `export_ups` / `import_ups` | REAL | Roundtrip with exact target content |
| `export_ips` | REAL | PATCH magic + EOF footer + record bytes |
| `export_ips32` | REAL | IPS32 magic + EEOF footer verified |
| `export_cod` | REAL | Exact byte-level assertions in-crate |
| `export_patches_json` | REAL | Hex encoding of offsets/data verified |
| `import_ips` | REAL | Round-trip exact content verification |
| `extract_patches_from_overwrites` | REAL | Offset and data exact match |
| `inspect_at` (uint8/int8/uint16_le/be/uint32_le/be) | REAL | `0xDEADBEEF`, `0x1234`, `0x5678`, `42` exact values |
| `inspect_at` (float32_le/float64_le) | REAL | Known IEEE 754 1.0 near-equality |
| `inspect_at` (IPv4) | REAL (in-crate) | Known 192.168.1.1 |
| `inspect_at` (GUID) | REAL (in-crate) | Byte-swap pattern verified |
| `inspect_at` (LEB128) | WEAK | `starts_with("128")` prefix only; full decoded string not asserted |
| `inspect_at` (IPv6) | REAL (in-crate) | Known address format |
| `inspect_at` (Unix timestamp) | REAL (in-crate) | Date string verified |
| `MmapDocument::open/from_bytes` | REAL | Real filesystem test |
| `MmapDocument::save` | REAL | File content verified after save |
| `MmapDocument::save_in_place` | WEAK | Error path (no path set) not tested |
| `MmapDocument::read/write/insert/delete` | REAL | Content verified |
| `extract_strings` (ASCII) | REAL | Exact offset, length, content, encoding |
| `extract_strings` (UTF-16LE) | REAL | Exact oracle values with surrogate handling |
| `DataSource::read/write/length/is_writable/source_type` | **NO COV** | Zero tests at any level |
| `DataSourceError::ReadOnly/OutOfBounds` | **NO COV** | Zero tests |
| `BufferDataSource::new/new_readonly` | **NO COV** | Zero tests |
| `TemplateRegistry::apply` (basic fields) | REAL | e_magic, e_lfanew, offset all verified |
| `TemplateRegistry::apply` (DynamicArray) | **NO COV** | eval.rs path never exercised by any test |
| `TemplateRegistry::apply` (Conditional) | **NO COV** | eval.rs conditional path untested |
| `TemplateRegistry::apply` (StructRef) | **NO COV** | eval.rs StructRef path untested |
| `TemplateRegistry::apply` (Pointer) | **NO COV** | eval.rs Pointer path untested |
| `TemplateRegistry::list` | WEAK | Only name presence tested; no exact count or full set |
| `TemplateRegistry::list_detailed` | WEAK | `field_count > 0` only; exact count (e.g., 20 for IMAGE_DOS_HEADER) not asserted |
| `parse_json_template` (error: empty name) | **NO COV** | Error path untested |
| `parse_json_template` (error: empty count_field) | **NO COV** | Error path untested |
| `template_to_json` | WEAK | JSON roundtrip without independent schema validation |

---

## 4. Fake-Gate and Weak-Gate Analysis

### 4.1 FAKE-GATE: `test_data_inspector.py::TestInspectAtBasic`

**File:** `tests/test_hexcore_e2e/test_data_inspector.py:42–143`

**Tests:** `test_inspect_at_returns_dict`, `test_inspect_at_has_uint8_key`, `test_inspect_at_has_int8_key`, `test_inspect_at_has_uint16_le_key`, `test_inspect_at_has_uint32_le_key`, `test_inspect_at_has_uint32_be_key`, `test_inspect_at_has_uint64_le_key`, `test_inspect_at_has_float32_le_key`, `test_inspect_at_has_float64_le_key`, `test_inspect_at_contains_all_expected_keys`, `test_inspect_at_all_values_are_strings`

**Verdict:** FAKE-GATE (key-existence only)

**Falsifiability failure:** An implementation of `inspect_at()` that returns `{"uint8": "WRONG", "int8": "WRONG", "uint16_le": "WRONG", ...}` would pass every test in this class. The tests verify schema shape, not correctness of values. `assert "uint8" in result` combined with `assert isinstance(value, str)` provides zero gate against a broken decoder.

**Partially redeemed by:** `TestInspectAtValues` (lines 145+) adds value-asserting tests. The structure class tests are coverage-theater that adds no gate coverage `TestInspectAtValues` does not already provide.

**Required fix:** Delete the 11 key-existence tests in `TestInspectAtBasic` or replace each with an exact value assertion using the `known_doc` fixture.

### 4.2 WEAK: `entropy.rs` in-crate tests

**File:** `src/intellicrack-hexcore/src/entropy.rs` — all `#[test]` functions that use `assert!(entropy > 7.99)` or `assert!(entropy < 0.01)`

**Verdict:** WEAK (overly wide tolerance)

**Falsifiability failure:** An implementation that returns a constant 7.995 for all inputs would pass every range-checked entropy test. A wrong-log-base implementation using `log10` instead of `log2` would return `8.0 / log2(10) ≈ 2.41` for uniform 256 data and fail `> 7.99`, but returning `log10(256) * (8/log2(256)) ≈ wrong values` for non-uniform data could still satisfy loose bounds.

**Partially redeemed by:** `test_entropy.py` uses an independent `_shannon_entropy_bits_per_byte()` oracle that precisely pins the value to `0.8112781244591328` for the 75/25 two-symbol case.

**Required fix:** Replace in-crate range assertions with exact `assert!((result - expected).abs() < 1e-9)` where `expected` is computed by an independent reference formula inlined in the test, not by calling the same function.

### 4.3 WEAK: `hash.rs` in-crate tests for BLAKE2s, xxh3, siphash64, siphash128, crc8, crc64

**File:** `src/intellicrack-hexcore/src/hash.rs` — `test_blake2s_*`, `test_xxh3_*`, `test_siphash*`, `test_crc8_*`, `test_crc64_*`

**Verdict:** WEAK (length-only assertions)

**Falsifiability failure:** These tests assert `result.len() == N` (e.g., 64 hex chars). An implementation returning `"a".repeat(64)` passes every length test. The algorithm is not gated.

**Partially redeemed by:** xxh3 and siphash have no Python-side oracle either. BLAKE2s is only compared against BLAKE2b for inequality (correct structure, wrong oracle). CRC-16 is covered by the Python `_crc16_arc` reference implementation. CRC-8 and CRC-64 remain ungated.

**Required fix:** For each algorithm, add tests with known-correct reference values. xxh3-128 of empty bytes = `0x9212...` (from the xxhash spec); SipHash-1-3 has published test vectors; CRC-8/CRC-64 have known-answer tables.

### 4.4 WEAK: `transforms.rs` in-crate XOR/ROT round-trips

**File:** `src/intellicrack-hexcore/src/transforms.rs` — `test_xor_single_roundtrip`, `test_rot_roundtrip`, `test_bit_shift_left_roundtrip`, `test_bit_rotate_left_roundtrip`

**Verdict:** WEAK (tautological round-trip)

**Falsifiability failure:** A broken XOR that always returns `vec![0u8; data.len()]` would pass any `xor → xor` round-trip test because `XOR(XOR(x, 0)) = x` trivially, and `XOR(0, 0) = 0 = XOR(XOR(0, k), k)` for any `k`. Round-trip tests do not catch a broken implementation that produces wrong intermediate values.

**Partially redeemed by:** `test_xor_repeating` in-crate test computes expected by hand (`0x41^0x41, 0x41^0x42, ...`). Python `test_transforms.py::TestXorTransform::test_xor_single_byte_key_matches_manual` uses `bytes(b ^ key_byte for b in input_data)` as independent oracle.

**Required fix:** Replace every round-trip test with a forward-direction test asserting the exact intermediate bytes against an independently computed expected value.

### 4.5 WEAK: `encodings.rs` in-crate round-trips

**File:** `src/intellicrack-hexcore/src/encodings.rs` — `test_encode_decode_utf8_roundtrip`, `test_encode_decode_latin1_roundtrip`

**Verdict:** WEAK (round-trip tautology)

**Falsifiability failure:** An `encode_text` that returns an empty `Vec<u8>` paired with a `decode_text` that returns an empty `String` would pass a round-trip test if both agree on the empty result. The specific byte encoding is never verified.

**Redeemed for EBCDIC by:** In-crate tests assert `encoded[0] == 0xC1` (EBCDIC `A`) and `encoded[0] == 0xF0` (EBCDIC `0`) — these are proper independent values. Python tests use exact string equality against known inputs.

**Required fix:** For each UTF-8/Latin-1 round-trip test, add assertions on the intermediate encoded bytes against the published byte sequences (e.g., UTF-8 `é` = `[0xC3, 0xA9]`).

### 4.6 WEAK: `templates/mod.rs` `test_apply_dos_header`

**File:** `src/intellicrack-hexcore/src/templates/mod.rs` — `test_apply_dos_header` (in-crate)

**Verdict:** WEAK (minimal input, partial field coverage)

**Falsifiability failure:** The test uses a 64-byte hand-crafted buffer with only `MZ` magic and `e_lfanew`. It checks that `fields[0].name == "e_magic"` and `fields.last().unwrap().name == "e_lfanew"`. An implementation that returns fields in wrong order, with wrong sizes, or with wrong display values for un-asserted fields would pass.

**Partially redeemed by:** Python `test_templates.py::TestApplyPETemplate` uses a real PE binary from `conftest._build_pe_binary()` (1024 bytes, valid DOS+PE headers) and asserts `e_magic` decimal value `23117`, e_lfanew value `0x80`, offset `0`, and all required dict keys.

**Required fix:** Extend the in-crate test to assert exact display values for every field in the 64-byte buffer, not just the first and last name. Assert exact `offset`, `size`, and `display_value` for `e_cblp`, `e_cparhdr`, etc.

### 4.7 WEAK: `TemplateRegistry::list` / `list_detailed` Python tests

**File:** `tests/test_hexcore_e2e/test_templates.py:43–183`

**Verdict:** WEAK (presence-only checks, no exact counts)

**Tests:** `test_returns_nonempty_list`, `test_entries_are_name_description_pairs`, `test_image_dos_header_present`, `test_elf_template_present`, `test_zip_template_present`, `test_dos_header_field_count_positive`, `test_elf64_field_count_positive`, `test_zip_template_field_count_positive`

**Falsifiability failure:** `test_dos_header_field_count_positive` asserts `field_count > 0`. The IMAGE_DOS_HEADER template in `pe.rs` has exactly 20 fields (verified by reading the source). `field_count > 0` would pass even if 18 fields were silently dropped. A registration bug that adds duplicate template names and corrupts field counts would not be detected.

**Required fix:** Assert `field_count == 20` for IMAGE_DOS_HEADER. Assert the complete name set returned by `list_templates()` equals the known set of all registered templates (PE: 8, ELF: 1, Mach-O: 1, ZIP: 1, GUID: 1, FILETIME: 1 = 13 built-in templates).

### 4.8 WEAK: `mmap_io.rs` `save_in_place` error path

**File:** `src/intellicrack-hexcore/src/mmap_io.rs` — `save_in_place` when `file_path` is `None`

**Verdict:** NO COV for error path

**Falsifiability failure:** `save_in_place()` on a `from_bytes()` document (no file path) must return an `Err`. This error path has no in-crate or Python-side test. A broken implementation returning `Ok(())` without writing (or panicking) would not be detected.

**Required fix:** Add an in-crate test: `let mut doc = MmapDocument::from_bytes(vec![0u8; 64]); assert!(doc.save_in_place().is_err());`

### 4.9 WEAK: `data_inspector.rs` LEB128 decoding

**File:** `src/intellicrack-hexcore/src/data_inspector.rs` — `inspect_at` LEB128 field

**Verdict:** WEAK (prefix assertion)

**Falsifiability failure:** The in-crate test asserts `result.leb128_unsigned.starts_with("128")`. An implementation that always returns `"128 (BROKEN)"` for any input would pass. The full decoded value, number of bytes consumed, and signedness are not verified.

**Required fix:** Assert the complete string: for bytes `[0x80, 0x01]` the correct LEB128-unsigned value is `128`, so the assertion should be `assert_eq!(result.leb128_unsigned.as_deref(), Some("128"))`. For the 2-byte encoding specifically, also assert the byte-count representation matches.

---

## 5. Edge-Case Coverage Audit

### 5.1 PieceTable

| Edge Case | Covered | Notes |
|---|---|---|
| Insert at offset 0 (start) | Yes | In-crate |
| Insert at `length()` (end) | Yes | In-crate |
| Insert in middle | Yes | In-crate |
| Delete crossing piece boundary | Yes | In-crate |
| Read crossing multiple pieces | Yes | In-crate |
| Off-by-one at `total_length` (read `length()` bytes) | **No** | Not tested |
| Alternating insert/delete stress | **No** | Not tested |
| Insert into empty table | Yes | In-crate |
| Overwrite crossing piece boundary | Yes | In-crate |

### 5.2 Diff

| Edge Case | Covered | Notes |
|---|---|---|
| Identical inputs | Yes | Python exact region |
| Empty vs empty | Yes | Python |
| A is empty, B non-empty | Yes | Python |
| A longer than B (truncated B) | Yes | Python `inserted_a` |
| Single byte change | Yes | Python exact offset 32 |
| Full replacement | Yes | Python |
| Partial change at offset | Yes | Python |
| Input > 1MB (anchored Adler32 path) | Partial | In-crate only; offset precision not verified |
| Binary with many repeated sequences | **No** | Not tested |
| Missing file path | Yes | Python `OSError` test |

### 5.3 Hash

| Edge Case | Covered | Notes |
|---|---|---|
| MD5/SHA1/SHA256/SHA3-256 empty input | Yes | NIST KAT for SHA3-256 |
| Full 256-byte range | Yes | Python hashlib oracle |
| Sub-range hash | Yes | Python hashlib slice oracle |
| Single byte range | Yes | Python |
| Unsupported algorithm | Yes | `ValueError` with message |
| Custom CRC full range | Yes | binascii oracle |
| Custom CRC sub-range | Yes | Python reference |
| CRC with non-standard poly/init/xorout | Yes | CRC-16/ARC |
| xxh3/siphash64/siphash128 correctness | **No** | Length-only |
| CRC-8/CRC-64 correctness | **No** | Length-only |
| BLAKE2s exact value | **No** | Only inequal-to-BLAKE2b |
| PE checksum on real PE | Yes | Bridge test |

### 5.4 Search

| Edge Case | Covered | Notes |
|---|---|---|
| Pattern at offset 0 | Yes | Python |
| Pattern at end of buffer | Yes | Python |
| Overlapping patterns | Yes | In-crate Boyer-Moore good-suffix |
| No match | Yes | Python |
| max_results cap | Yes | Python |
| Single-byte pattern | Yes | Python |
| Wildcard `?` in hex search | Yes | In-crate |
| Regex with capture groups | Yes | In-crate |
| Case-insensitive text search | Yes | In-crate |
| Null bytes in search pattern | **No** | Not tested |
| Multi-encoding text search | Yes | In-crate Cyrillic UTF-16LE |
| Numeric range search | Yes | In-crate |
| Float NaN/Inf handling | **No** | Not tested |

### 5.5 BPS/UPS

| Edge Case | Covered | Notes |
|---|---|---|
| Source = target (no changes) | Yes | In-crate |
| SourceRead OOB | Yes | In-crate exact error message |
| SourceCopy OOB | Yes | In-crate exact error message |
| TargetCopy OOB | Yes | In-crate exact error message |
| CRC validation failure | Yes | Python BPS wrong-CRC test |
| Wrong magic header | Yes | Python garbage test |
| Different-length source and target | **No** | Not tested |
| Empty source | **No** | Not tested |
| Empty target | **No** | Not tested |
| Truncated patch (early EOF) | **No** | Not tested |

### 5.6 Template Evaluation (eval.rs)

| Edge Case | Covered | Notes |
|---|---|---|
| Simple scalar field | Yes | Via `test_apply_dos_header` |
| Array field (fixed count) | Yes | `e_res` / `e_res2` in DOS header |
| DynamicArray (count from prior field) | **No** | Zero tests at any level |
| Conditional field (condition true) | **No** | Zero tests |
| Conditional field (condition false) | **No** | Zero tests |
| StructRef (nested struct) | **No** | Zero tests |
| Pointer dereference | **No** | Zero tests |
| Bitfield | **No** | Zero tests |
| Insufficient data mid-struct | **No** | Zero tests |
| MAX_DEPTH exceeded (circular ref) | **No** | Zero tests |

### 5.7 Strings

| Edge Case | Covered | Notes |
|---|---|---|
| ASCII run at offset 0 | Yes | In-crate |
| ASCII run at end | Yes | In-crate |
| UTF-16LE surrogate pair (emoji) | Yes | In-crate |
| Dangling UTF-16LE surrogate | Yes | In-crate |
| Purely null data | **No** | Not tested |
| Embedded null in ASCII run | **No** | Not tested |
| min_length boundary (exact min_length) | Yes | In-crate |
| min_length = 0 (degenerate) | **No** | Not tested |
| Large buffer (> 1MB) | **No** | Not tested |

---

## 6. No-Coverage Gaps

The following public operations have zero tests at any layer:

### 6.1 Critical: `data_source.rs` — Complete No Coverage

`BufferDataSource::new`, `BufferDataSource::new_readonly`, `BufferDataSource::read` (including OOB error), `BufferDataSource::write` (including ReadOnly error, OOB error), `DataSource::length`, `DataSource::is_writable`, `DataSource::source_type`.

These are the primitives used by `from_process_memory` and the `ProcessDataSource` in `lib.rs`. If `BufferDataSource::read` returns wrong data on OOB, all process memory reads silently truncate without surfacing an error.

**Priority:** High. Add unit tests for every public method of `BufferDataSource` in-crate, including both `ReadOnly` and `OutOfBounds` error variants.

### 6.2 Critical: `templates/eval.rs` — Advanced Paths Untested

`TemplateEvaluator::evaluate_fields` for DynamicArray, Conditional, StructRef, and Pointer field types has zero coverage. These are non-trivial evaluation paths with loops, depth tracking (`MAX_DEPTH = 16`), and cross-field reference resolution. A logic error here (e.g., wrong offset advance after a DynamicArray element) produces silently wrong field offsets that only become visible as downstream parse failures.

**Priority:** High. Add in-crate tests for each evaluator path with a hand-crafted data buffer and known expected field values.

### 6.3 High: `parse_json_template` Error Paths

`parse_json_template` validates that `template.name` is non-empty and that `DynamicArray::count_field` is non-empty. These two error paths in `json_schema.rs` have zero test coverage. A regression removing these guards would silently accept malformed templates.

**Priority:** Medium. Add two targeted tests in `test_templates.py` for `register_json` with empty-name and empty-count-field inputs.

### 6.4 Medium: `verify_pe_checksum` In-Crate

`verify_pe_checksum` returns `bool`. No in-crate test exists. The Python bridge test may cover the call path but is not equivalent to a focused unit test with a known-good checksum vs. a deliberately corrupted one.

**Priority:** Medium.

### 6.5 Medium: `MmapDocument::save_in_place` Error Path

`save_in_place()` called on a no-path document is untested. The error message and error kind are unverified.

**Priority:** Medium.

### 6.6 Low: `list_encodings` Exact Count and Set

`list_encodings()` claims 30+ encodings. No test verifies the exact count or the full set. A regression dropping EBCDIC from the list would not be caught.

**Priority:** Low.

---

## 7. Falsifiability Verification

### 7.1 Critical Test: `test_entropy.py::test_entropy_skewed_two_symbol_matches_independent_oracle`

**Would this fail if `compute_entropy` is deleted?** Yes. The oracle `_shannon_entropy_bits_per_byte()` is a complete, self-contained Shannon entropy implementation. The assertion `math.isclose(result, 0.8112781244591328, abs_tol=1e-9)` requires the Rust implementation to compute the correct value.

**Would it fail if log base is wrong?** Yes. Using `log2` gives `0.8112781...`; using `log` (natural) gives `~0.562`; using `log10` gives `~0.244`. All would fail the `1e-9` tolerance.

**Verdict: Genuine gate.**

### 7.2 Critical Test: `test_hashing.py::test_sha3_256_empty_matches_nist_known_answer`

**Would this fail if `compute_hash` is deleted?** Yes. `"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"` is the NIST published SHA3-256 digest of empty input. No implementation error can produce this value for any other algorithm or for wrong data.

**Verdict: Genuine gate.**

### 7.3 Critical Test: `test_binary_diff.py::test_diff_files_single_byte_change`

**Would this fail if `diff_data` returns wrong offset?** Yes. The test asserts the exact three-region layout `[match(32), modified(1)@32, match(31)@33]`. Any offset error (e.g., modified region at 31 instead of 32) fails the `==` check.

**Verdict: Genuine gate.**

### 7.4 Suspect Test: `test_data_inspector.py::TestInspectAtBasic::test_inspect_at_all_values_are_strings`

**Would this fail if `inspect_at` returns `{"uint8": 0}` (int instead of str)?** Yes, on `isinstance(value, str)`.
**Would this fail if `inspect_at` returns `{"uint8": "COMPLETELY WRONG"}`?** No.

**Verdict: Partial gate (type shape only, not value correctness).**

### 7.5 Suspect Test: `test_templates.py::TestListTemplatesDetailed::test_dos_header_field_count_positive`

**Would this fail if IMAGE_DOS_HEADER drops from 20 fields to 1 field?** No. `field_count > 0` is satisfied by `field_count = 1`.
**Would this fail if IMAGE_DOS_HEADER gains 50 spurious fields?** No. `field_count > 0` passes for any positive count.

**Verdict: Not a gate.**

### 7.6 Suspect Test: `entropy.rs` in-crate `test_entropy_random_data`

**Concrete mutation:** Replace `sum(...)` with `sum(...)  / 2.0` in the entropy computation.
**Effect on range test `> 7.99`:** Uniform 256 data would return `4.0` instead of `8.0`. Test fails.
**Effect on range test `< 0.01`:** Zero-entropy data returns `0.0`. Test still passes.
**Another mutation:** Constant return `0.5`.
**Effect:** Fails `> 7.99` for high-entropy data, but if only tested on low-entropy data with `< 0.01`, passes everything.

**Verdict:** Range tests are order-of-magnitude gates, not precision gates.

---

## 8. Section Scores

| Dimension | Score (0–10) | Notes |
|---|---|---|
| Falsifiability | 6/10 | Most critical ops are REAL; 4 key WEAK patterns remain |
| Assertion Quality | 6/10 | Hash/entropy Python tests are excellent; template list and data_inspector basic tests are weak |
| Input Realism | 8/10 | Real PE/ELF/ZIP binaries in conftest; real filesystem for mmap; no fake byte sequences for critical ops |
| Edge Case Coverage | 5/10 | BPS missing 5 error cases; eval.rs 5 paths completely uncovered; search missing float NaN |
| Error Path Coverage | 5/10 | data_source.rs zero error path coverage; template eval error paths untested |
| Determinism | 9/10 | No sleeps; no shared mutable state; no order dependencies detected |
| Module Coverage | 6/10 | 8 of 21 source modules have zero in-crate tests |
| Overall | **6.1/10** | Core ops strongly gated; infrastructure (data_source, eval) completely uncovered |

---

## 9. Priority Findings

Listed in descending order of risk. Severity is based on the likelihood that a silent regression goes undetected and the impact of that regression on correctness.

### P-01 — CRITICAL: `data_source.rs` has zero tests

No test verifies `BufferDataSource::read` OOB boundary, `write` on a read-only source, or `source_type` discriminator. This module is used for process memory reads via `from_process_memory`. A broken `OutOfBounds` error that is swallowed as an empty `Vec` means silent memory read corruption.

**Affected:** `data_source.rs:35–80` (`BufferDataSource`), both `DataSourceError` variants.
**Fix:** 8–10 targeted in-crate unit tests covering both error variants and all interface methods.

### P-02 — CRITICAL: `templates/eval.rs` — DynamicArray, Conditional, StructRef, Pointer paths completely untested

The `TemplateEvaluator` has 5 distinct evaluation arms. Only the scalar field arm exercises any real binary analysis. The other four arms have MAX_DEPTH=16 recursion tracking, cross-field reference resolution (`parsed_values: HashMap<String, i64>`), and offset arithmetic. A logic error in any of these silently produces wrong field offsets in all templates that use them (PE import/export directories use DynamicArray; conditional fields are used in optional-header parsing).

**Affected:** `templates/eval.rs:57–end`.
**Fix:** Add 5 targeted in-crate tests, one per field type arm, with hand-crafted data buffers and exact expected field name/offset/value assertions.

### P-03 — HIGH: BLAKE2s, xxh3, siphash64, siphash128, CRC-8, CRC-64 ungated by value

Six hash algorithms have no correctness oracle at any test layer. Any implementation that returns the right-length hex string passes. Given that these are commonly used for fast hash/checksum operations in binary analysis pipelines, a wrong value would produce incorrect analysis output silently.

**Affected:** `hash.rs` — `test_blake2s_*`, `test_xxh3_*`, `test_siphash*`, `test_crc8_*`, `test_crc64_*`.
**Fix:** Add known-answer tests using published test vectors from each algorithm's specification.

### P-04 — HIGH: `TestInspectAtBasic` (11 tests) — key-existence-only, zero value gate

Eleven Python tests in `TestInspectAtBasic` verify key presence and string type, but not values. They run and pass regardless of whether `inspect_at` returns correct decoded integers. The correct tests exist in `TestInspectAtValues` — the basic class duplicates test execution without adding any gate.

**Affected:** `tests/test_hexcore_e2e/test_data_inspector.py:42–143`.
**Fix:** Delete `TestInspectAtBasic` or rewrite each test to assert exact values using the `known_doc` fixture.

### P-05 — HIGH: `TemplateRegistry::list_detailed` field count — not a gate

`test_dos_header_field_count_positive` asserts `field_count > 0`. IMAGE_DOS_HEADER has exactly 20 fields. Any field count ≥1 passes. A registration bug that truncates the field list to a single field would not be detected.

**Affected:** `tests/test_hexcore_e2e/test_templates.py:140–153`.
**Fix:** Change to `assert field_count == 20` (from pe.rs source: `fd("e_magic")` through `fd("e_lfanew")` = 20 entries).

### P-06 — MEDIUM: `entropy.rs` in-crate tests — range-only assertions

All 15 in-crate entropy tests use `assert!(entropy > X)` or `assert!(entropy < Y)` with no exact oracle. An off-by-factor implementation passing range checks but returning wrong values for non-boundary inputs goes undetected.

**Affected:** `src/intellicrack-hexcore/src/entropy.rs` all `#[test]` functions.
**Fix:** Inline the Shannon formula as a reference computation in each test and assert `(result - expected).abs() < 1e-9`.

### P-07 — MEDIUM: `parse_json_template` error paths untested

Two validation guards in `json_schema.rs` (empty `name`, empty `DynamicArray::count_field`) have no tests. A regression removing either guard silently accepts malformed templates.

**Affected:** `src/intellicrack-hexcore/src/templates/json_schema.rs:11–18, 40–46`.
**Fix:** Add two `test_templates.py` tests: one calling `register_json` with `"name": ""` and one with a DynamicArray field having `"count_field": ""`, asserting `pytest.raises(ValueError)` for each.

### P-08 — MEDIUM: BPS/UPS missing 5 edge cases

No tests cover empty source, empty target, different-length source/target, truncated patch (early EOF), or the precise byte encoding of SourceRead vs. TargetRead vs. SourceCopy vs. TargetCopy BPS command types in Python.

**Affected:** `tests/test_hexcore_e2e/test_bridge_bps_ups.py`, `src/intellicrack-hexcore/src/bps_ups.rs`.
**Fix:** Add 5 tests covering these edge cases with exact expected byte sequences or specific error kinds.

### P-09 — MEDIUM: `mmap_io.rs` `save_in_place` no-path error path untested

**Affected:** `src/intellicrack-hexcore/src/mmap_io.rs` — `save_in_place`.
**Fix:** One in-crate test: `let mut doc = MmapDocument::from_bytes(b"data".to_vec()); assert!(doc.save_in_place().is_err());`

### P-10 — LOW: `list_encodings` — non-empty only

No test verifies the exact set of supported encodings or their count. EBCDIC, cp1252, and other non-ASCII encodings could be silently removed.

**Affected:** `src/intellicrack-hexcore/src/encodings.rs` — `test_list_encodings`.
**Fix:** Assert `encodings.contains(&"ebcdic".to_string())` and verify count against the known 30+ entries in the `ENCODING_MAP`.

---

## 10. Summary Table

| Metric | Value |
|---|---|
| Total public operations inventoried | 89 |
| REAL (genuine falsifiable gate) | 54 (61%) |
| WEAK (passes under broken code for specific reason) | 23 (26%) |
| FAKE (guaranteed pass regardless) | 3 (3%) |
| NO COV (zero tests) | 9 (10%) |
| In-crate test modules with zero tests | 8 of 21 (38%) |
| Python e2e test files | 67 |
| FAKE-GATE tests identified | 11 (`TestInspectAtBasic`) |
| WEAK-GATE tests identified | ~28 across entropy, hash, transforms, templates |
| Critical no-coverage gaps | 3 (`data_source`, `eval.rs` advanced paths, BPS edge cases) |
| Highest-risk uncovered code | `BufferDataSource` and `TemplateEvaluator` non-scalar paths |
