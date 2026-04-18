# Needed Fixes — Intellicrack Production-Readiness Remediation

This document aggregates every finding from the partitioning audit into
execution-ordered groups. Each group's full orchestrator prompt (role, scope,
standards, workflow, orchestration directives, findings, and final gate) is
preserved verbatim so it can be handed to the responsible agent without
rewriting.

---

## Partitioning Summary

| Group | Scope | Findings | Files |
|-------|-------|----------|-------|
| A | `src/intellicrack/bridges/**` | 77 | ghidra, x64dbg, frida, hex_editor, process, sandbox_bridge, cutter, schemas, installer, base, named_pipe_client, _win32_types, hex_state, init |
| B | `src/intellicrack/core/**` | 55 | orchestrator, session, tools, analysis_aggregator, config, logging, process_manager, types, _subprocess, _xml_gen, disassembler, script_gen, yara_scanner, transform_pipeline, template_manager, hexpat_compiler, hexpat/* |
| C | `src/intellicrack/providers/**` + `src/intellicrack/credentials/**` | 34 | all providers + creds |
| D | `src/intellicrack/sandbox/**` | 19 | windows, qemu, manager, analysis, base, scripts/*.ps1 |
| E | `src/intellicrack/ui/**` + main.py, __main__.py, _metadata.py | 76 | shell, chat, all dialogs, all panels |
| F | `src/intellicrack-hexcore/**` | 23 | lib.rs, all sub-crates, templates/, .pyi |

---

## Execution Order & Rationale

The groups are ordered below to minimise rework from cross-group coordination:

1. **Group F — Rust hexcore** — foundation layer, no Python dependencies; its
   API and `.pyi` stubs must be stable before bridge and UI migrations land.
2. **Group B — Core + Hexpat** — orchestrator, session, core types, and the
   hexpat language are consumed by providers, bridges, and UI. Must be done
   before C and E, and before any bridge or UI finding that references
   `core/types.py`, `core/orchestrator.py`, or `core/session.py`.
3. **Group A — Bridges** — consumes hexcore (F) and core types (B); must be
   complete before UI panels (E) that use new bridge surface (`SegmentInfo`,
   thread suspend/resume, etc.).
4. **Group D — Sandbox** — subsystem with UI consumers; adds
   `SandboxManager.update_default_config` and related APIs that Group E
   dialogs depend on.
5. **Group C — Providers + Credentials** — needs `Message.usage` from Group B;
   new Grok / Ollama / HF behaviour must land before UI provider dialogs in E.
6. **Group E — UI** — sits on top of all other subsystems; fixed last so that
   bridges, core, sandbox, and providers all expose the APIs it requires.

Cross-group notes kept in the original prompts (e.g. B22 deferring `main.py`
edits to E, E6/E15 waiting on D's `update_default_config`, E20 waiting on B's
`start_session` extension, C9 waiting on B's `Message.usage`, E73 waiting on
A's thread suspend/resume, F3 aligning with A53 Python callers) remain in
place in each group section below.

---
---

```
================================================================================
================================================================================

                       G R O U P   F  —  R U S T   H E X C O R E
                                (Execute FIRST)

================================================================================
================================================================================
```

ROLE: Orchestrator for Group F (Rust hexcore crate + PyO3 stubs).

SCOPE:
- src/intellicrack-hexcore/**

OUT OF SCOPE:
- All src/intellicrack/** (Python side).
- Only exception: you may NOT modify Python callers even if they call the updated Rust API. Python callers today already pass the shapes Rust
expects (per worker verifications); .pyi fixes align stubs with reality, not the other way around.

CLAUDE.md STANDARDS: production only; no placeholders; all Rust must pass `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`; all
 .pyi must be basedpyright-coherent.

WORKFLOW per finding:
1. Read surrounding Rust/pyi context.
2. Apply Working fix.
3. Run `cargo build`, `cargo clippy --all-targets --no-deps -- -D warnings`, `cargo fmt --check`, `cargo test` inside src/intellicrack-hexcore/.
4. If .pyi changes, cross-check with Python callers via `rg <symbol>` in src/intellicrack/ (read-only — do not modify).
5. Re-read diff; commit per file or tight cluster.

ORCHESTRATION: verify every subagent diff yourself; re-run cargo clippy + tests after each change.

FINDINGS (23 total):

=== RUST CORE FOUNDATION (6 findings) ===

F1. W23 F1 [intellicrack_hexcore.pyi:72] signature-drift high — search_numeric_range stub declares 7 scalar args; Rust accepts (i64, i64) tuple +
6 args. Fix: `def search_numeric_range(self, value_range: tuple[int, int], size: int, signed: bool, big_endian: bool, alignment: int, max_results:
 int) -> list[tuple[int, int]]: ...`
F2. W23 F2 [intellicrack_hexcore.pyi:73] signature-drift high — compute_hash_custom_crc stub declares 8 scalars; Rust accepts 2 tuples + 4
scalars. Fix: `def compute_hash_custom_crc(self, byte_range: tuple[int, int], poly: int, init: int, width: int, reflect: tuple[bool, bool],
xorout: int) -> str: ...`
F3. W23 F3 [intellicrack_hexcore.pyi:39, 84] signature-drift medium — replace_bytes/fill_block/import_patches_* stubs declare list[int] pattern
param; Rust accepts &[u8] (Python bytes). Fix: change param types to `bytes`; bridge callers should ensure they pass `bytes(...)` (see A53 for
coordination — already fixed there on Python side).
F4. W23 F5 [src/piece_table.rs:185-246, 54-67] happy-path-only medium — delete() fallback when find_piece(end) returns None silently masks state
corruption. Fix: replace match fallback with `.expect("find_piece(end) must succeed when end < total_length")`.
F5. W23 F6 [src/lib.rs:848-873, 1015-1023] happy-path-only high — swap_blocks and repair_pe_checksum don't record undo entries. Fix: after each
overwrite in swap_blocks push Operation::Overwrite with old_data / new_data per region (two records); similarly in repair_pe_checksum with 4
stored bytes + checksum_bytes.
F6. W23 F7 [src/undo.rs:28-34, 115-121 + src/lib.rs:762-782] other low — BPS/UPS import resets UndoManager via new() which marks saved_index=0
meaning not-modified — but document IS modified. Fix: add pub fn mark_unsaved(&mut self) that sets saved_index=None; call after constructing fresh
 UndoManager in import_patches_bps/ups. Or set self.inner.modified=true via MmapDocument helper.

=== RUST ANALYSIS OPS (6 findings) ===

F7. W24 F1 [src/strings.rs:91-149] happy-path-only high — UTF-16LE extractor only accepts ASCII code points + TAB/LF/CR; silently misses all
localized strings. Fix: generalize printable test to operate on Unicode code points using char::from_u32 with char::is_control/is_whitespace
policy; handle UTF-16 surrogate pairs for supplementary-plane chars; push decoded char directly.
F8. W24 F2 [src/transforms.rs:278-336] happy-path-only high — AES-ECB decrypt silently zero-pads misaligned ciphertext. Fix: return
Err(TransformError::InvalidParameter("data length must be multiple of 16 for AES decrypt")) for non-multiple-of-16 decrypt; if partial-block
support wanted, add explicit padding-mode parameter (PKCS7/Zero/ISO10126).
F9. W24 F3 [src/encodings.rs:193-249, src/search.rs:281-330] happy-path-only high — case-insensitive search matches only 3 cased variants
(original/all-lower/all-upper); misses mixed-case. Fix: normalize at comparison stage. Single-byte encodings: decode each data window, compare via
 str::to_lowercase. Multi-byte (UTF-16LE/BE, Shift-JIS): decode sliding windows via encoding_rs; compare decoded strings with .to_lowercase()
equality.
F10. W24 F4 [src/encodings.rs:162-168] happy-path-only medium — ASCII encoder `text.chars().map(|c| (c as u32).to_le_bytes()[0])` silently
truncates non-ASCII to low byte. Fix: return Err(EncodingError::EncodeFailed(format!("U+{:04X} cannot be encoded in ASCII", ch as u32))) on first
non-ASCII char; otherwise collect via c as u8.
F11. W24 F5 [src/transforms.rs:186-193] happy-path-only low — bit_shift_left/right silently clamp count to 7. Fix: validate count <= 7; return
Err(TransformError::InvalidParameter(format!("shift count {count} exceeds byte width"))). Keep modulo-8 for rotations.
F12. W24 F6 [src/search.rs:74-79, 219-223] dead-code low — overlap / plen computed in early-return branch before used. Fix: move `let overlap =
plen.saturating_sub(1);` inside multi-chunk else branch.

=== RUST PATCHING + DIFFING + TEMPLATES (11 findings) ===

F13. W25 F1 [src/templates/elf.rs:27, 90, 149, 171, 193, 225] happy-path-only high — all 6 ELF templates default_endianness: Endianness::Little;
BE ELF (PowerPC/SPARC/MIPS-BE/s390) completely mis-parsed. Fix: register dual variants per structure (Elf32_Ehdr_LE, Elf32_Ehdr_BE) dispatched via
 e_ident[EI_DATA]; OR extend MagicDetection with post-read endianness probe; OR add FieldType::EndiannessFromField to flip evaluator default after
 reading e_ident.
F14. W25 F2 [src/diff.rs:36-126, 128-229] happy-path-only high — diff_data_byte_level does prefix+suffix+single modified span (no real edit
script); diff_data_block compares positionally, any insertion desyncs everything after. Fix: use `similar` crate (Myers) or `imara-diff`
(histogram) for byte-level path. For >1MiB use rolling-hash anchors rsync-style, then run byte-level diff between anchors. Drop positional block
compare.
F15. W25 F3 [src/templates/macho.rs:3-8, 94-149] happy-path-only medium — no fat/universal binary (0xCAFEBABE/0xBEBAFECA) or 32-bit LC_SEGMENT
templates. Fix: add fat_header (magic + nfat_arch), fat_arch (cputype/cpusubtype/offset/size/align), segment_command (32-bit LC_SEGMENT=0x1),
section (32 and 64), common load commands (LC_SYMTAB/LC_DYLIB/LC_DYLD_INFO_ONLY/LC_MAIN). Register LE and BE magic for non-fat headers.
F16. W25 F4 [src/templates/zip.rs:3-7] happy-path-only medium — no ZIP64 structures. Fix: add ZIP64_EOCD_RECORD (56+variable), ZIP64_EOCD_LOCATOR
(20), ZIP64_EXTRA_FIELD (header ID 0x0001 with 8-byte compressed/uncompressed sizes). Also Data Descriptor (0x08074B50) when bit 3 of
general-purpose flags is set.
F17. W25 F5 [src/bps_ups.rs:233-288] swallowed-exception medium — BPS import SourceRead/TargetRead/SourceCopy/TargetCopy silently skip OOB bytes
and produce garbage bytes that trigger misleading CRC-mismatch error. Fix: replace each bounds guard with early return of io::Error::InvalidData
naming the offending action + offset. For TargetRead also assert pos < footer_start.
F18. W25 F6 [src/bps_ups.rs:67-137] test-fixture-leak medium — BPS encoder never emits SourceCopy (cmd 2) or TargetCopy (cmd 3); decoder paths
untested; output larger than reference encoders. Fix: suffix-array or rolling-hash match search over source + already-written target; emit cmd 2
when non-aligned-source match longer; emit cmd 3 for repeats within target. Add roundtrip tests requiring SourceCopy and TargetCopy.
F19. W25 F7 [src/diff.rs:128-229] happy-path-only medium — block branch positional compare broken on insertions (covered by F14; same fix).
F20. W25 F8 [src/patch_export.rs:1-341 + src/lib.rs PyO3 + pyi] missing-rpc low — COD and JSON export formats advertised but not implemented. Fix:
 add `pub fn export_cod(records: &[PatchRecord]) -> Vec<u8>` (4-byte BE offset + 4-byte BE length + data) and `pub fn export_patches_json(records:
 &[PatchRecord]) -> Result<String, serde_json::Error>` using serde_json::to_string_pretty. Wire into lib.rs PyO3 + .pyi. Or remove COD/JSON from
scope docs.
F21. W25 F9 [src/templates/elf.rs:3-10] happy-path-only low — ELF templates missing Sym/Rel/Rela/Dyn. Fix: add elf{32,64}_sym (24/24 bytes),
elf{32,64}_rel (8/16), elf{32,64}_rela (12/24), elf{32,64}_dyn (8/16), note record. ELF category.
F22. W25 F10 [src/patch_export.rs:30-48] happy-path-only low — IPS offset 0x454F46 ("EOF") collides with terminator. Fix: in export_ips split
offending record so EOF-matching offset avoided (emit one byte at 0x454F45 + remainder at 0x454F47, or pre-emit byte at 0x454F45 to shift
alignment).
F23. W25 F11 [src/patch_export.rs:59-83, 156-212] happy-path-only low — IPS32 offset 0x45454F46 ("EEOF") collides with terminator; reachable in
>1GiB binaries. Fix: in export_ips32 split record before/after offending offset. Add unit test with offset 0x45454F46 as regression guard.

FINAL GATE:
- All 23 addressed.
- `cargo clippy --all-targets --no-deps -- -D warnings` inside src/intellicrack-hexcore/ → 0.
- `cargo fmt --check` → 0.
- `cargo test` → all pass including new BPS round-trip tests for cmd 2/3 and IPS/IPS32 offset-collision tests.
- basedpyright on .pyi stub alone → 0.
- No files outside src/intellicrack-hexcore/ modified.

---
---

```
================================================================================
================================================================================

                      G R O U P   B  —  C O R E   +   H E X P A T
                                (Execute SECOND)

================================================================================
================================================================================
```

ROLE: You are the orchestrator for Group B (Core + Hexpat language) of Intellicrack's production-readiness remediation.

SCOPE (only modify files in):
- src/intellicrack/core/**
  - including src/intellicrack/core/hexpat/**

OUT OF SCOPE (must not touch):
- src/intellicrack/bridges/**
- src/intellicrack/providers/**
- src/intellicrack/ui/**
- src/intellicrack/sandbox/**
- src/intellicrack-hexcore/**

CLAUDE.md STANDARDS: Production only, no stubs/mocks/placeholders, no type-ignore, basedpyright config locked, Google docstrings,
ruff/pydoclint/pydocstyle clean.

WORKFLOW per finding: read ≥30 lines of context; apply Working fix; validate (ruff check, ruff format, basedpyright, pydoclint, pydocstyle); if
validator fails fix root cause; read diff and confirm match; commit per file or tight cluster.

ORCHESTRATION: Delegate clusters to subagents when beneficial, ALWAYS re-read diff and re-run validators yourself. Never trust subagent completion
 claims without verifying.

FINDINGS (55 total):

=== ORCHESTRATOR + SESSION + TOOLS + AGGREGATOR (10 findings) ===

B1. W7 F1 [core/session.py:481-507] happy-path-only high — cleanup_old uses tz-aware ISO timestamp that SQLite julianday may reject; silent
zero-row delete. Fix: use `datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S")` or precompute cutoff timestamp and use `WHERE updated_at < ?`.
B2. W7 F2 [core/tools.py:500-510] dead-code medium — capability check derives `capability_name = function_name.split("_",1)[0]` which never
matches flags like supports_decompilation. Fix: either remove the dead check or add explicit tool→capability map and raise ToolError on mismatch.
B3. W7 F3 [core/orchestrator.py:780-801] hardcoded-return medium — _get_model_context_window returns hardcoded 128000 on any lookup failure. Fix:
require providers to expose get_model_context_window or add per-session override; surface failure to UI; log at warning.
B4. W7 F4 [core/orchestrator.py:1708-1768] swallowed-exception medium — shutdown catches only (OSError, RuntimeError, ValueError);
sqlite3.DatabaseError and aiohttp.ClientError propagate and halt teardown. Fix: catch Exception (except BaseException) in shutdown paths; keep
specific handling for CancelledError; finalize state clearing before re-raise.
B5. W7 F5 [core/orchestrator.py:1110-1180] swallowed-exception low — _execute_single_tool_call catches TypeError/KeyError (hiding bugs) and omits
ToolError. Fix: add ToolError to catch; remove TypeError/KeyError so programming errors surface.
B6. W7 F6 [core/orchestrator.py:1647-1650] signature-drift low — refresh_session_state docstring claims "including" but body only calls
reanalyze_bridge_analysis. Fix: tighten docstring, or expand method to reload session from disk + reanalyze.
B7. W7 F7 [core/orchestrator.py:1556-1584] swallowed-exception low — get_typed_bridge missing "hex_editor" in getter_map. Fix: add `"hex_editor":
"get_hex_editor_bridge"`; log warning when tool_name not in map.
B8. W7 F8 [core/session.py:283-376, 697-772] hardcoded-return high — SessionStore save/load/export/import never writes bridge_analyses despite it
being on Session dataclass. Fix: add `bridge_analyses` to session_data dict in save; deserialize in load via `BridgeAnalysisSummary(**v)` with
nested StringInfo/FunctionInfo reconstruction; include in export_to_json / import_from_json.
B9. W7 F9 [core/session.py:283-328] other low — save clears session_tags then re-inserts without transaction; race with auto_save. Fix: wrap save
body in `BEGIN IMMEDIATE` transaction or add asyncio.Lock in SessionStore.
B10. W7 F10 [core/orchestrator.py:495-498] happy-path-only medium — _run_agent_loop breaks on all-tools-failed without giving LLM a follow-up
turn. Fix: after appending tool_message, continue one more iteration with ToolChoice.NONE so LLM can summarize the failures, or synthesize final
assistant message before breaking.

=== CORE INFRASTRUCTURE (9 findings) ===

B11. W8 F1 [core/process_manager.py:762-789] happy-path-only high — run_tracked crashes when capture_output=False because communicate() returns
(None, None) then .decode() raises. Fix: decode only when data is not None; return "" / b"" based on text flag in other branch.
B12. W8 F2 [core/logging.py:33, 344-368] hardcoded-return high — _DEFAULT_LOG_DIR hardcoded to D:/Intellicrack/logs ignores Config.logs_directory.
 Fix: add logs_directory to LogConfig OR change setup_logging to accept Config or explicit log_dir; pass config.logs_directory from main.
B13. W8 F3 [core/process_manager.py:381-405] happy-path-only high — _terminate_tree_with_psutil raises NoSuchProcess unguarded, aborts atexit
cleanup loop. Fix: wrap psutil.Process(pid) and parent.children(recursive=True) in try/except psutil.NoSuchProcess: return.
B14. W8 F4 [core/process_manager.py:70, 896] signature-drift medium — TrackedProcess.registered_at uses naive datetime.now() while _external_pids
uses tz=UTC. Fix: default_factory=lambda: datetime.now(tz=UTC); update UI consumers if needed.
B15. W8 F5 [core/_subprocess.py:21-26] platform-broken medium — CREATE_NEW_CONSOLE etc exported unconditionally, fails import on non-Windows. Fix:
 guard with `if sys.platform == "win32":`; assign 0 fallbacks outside; or use getattr(_sp, "CREATE_NEW_CONSOLE", 0).
B16. W8 F6 [core/process_manager.py:804-809] swallowed-exception medium — run_tracked forges returncode=-1 when None. Fix: raise
RuntimeError/ProcessStateError naming the subprocess and PID; do not fabricate.
B17. W8 F7 [core/config.py:390-399] swallowed-exception low — _parse_tools raises ValueError on non-numeric port with no graceful fallback;
_parse_general logs warnings. Fix: wrap int(port_val) in try/except, log warning + fall back to tool_base.port; type-check path_str is str.
B18. W8 F8 [core/logging.py:386-398] dead-code low — get_structlog_logger has zero callers. Fix: delete.
B19. W8 F9 [core/config.py:479-524] test-fixture-leak low — public from_dict / parse_providers / parse_tools / parse_sub_configs are test-only
wrappers for private methods. Fix: un-prefix internal methods so tests call them directly; delete wrappers.

=== CORE ANALYSIS UTILITIES (7 findings) ===

B20. W9 F1 [core/transform_pipeline.py:242-256] happy-path-only high — TransformNode base.process returns data unchanged silently. Fix: make base
class abc.ABC with abstractmethod process; `name`/`category` abstract too.
B21. W9 F2 [core/template_manager.py:63-381] disconnected-wiring high — TemplateManager has zero importers outside the file. Fix: wire
bootstrap_builtins into main.py startup; route HexDocument template calls through it; OR delete and keep only PatternRegistry helpers.
B22. W9 F3 [core/script_gen.py:762-795, main.py:541] disconnected-wiring high — ScriptGenerator instance discarded in main.py; only tests call
prepare_ai_prompt. NOTE: main.py:541 edit belongs to Group E. Within Group B scope: ensure ScriptGenerator is ready to be wired (stable API),
document expected integration; do not modify main.py here.
B23. W9 F4 [core/hexpat_compiler.py:1479-1505] happy-path-only medium — HexPatCodegen._eval_const_expr silently returns 0 for
shift/bitwise/identifier/sizeof. Fix: raise HexPatError for unsupported const expressions; reserve runtime-evaluated cases for the interpreter
path.
B24. W9 F5 [core/hexpat_compiler.py:1410-1441] simulated-output medium — Conditional false_fields inversion wrong for BitAnd: inverted op Eq with
value 0 becomes field==0 not (field&mask)==0. Fix: introduce BitAndZero Rust primitive and route inverted branch to it; or emit paired If/Else
primitive evaluated once.
B25. W9 F6 [core/template_manager.py:122-141, 282-302] swallowed-exception medium — bootstrap_builtins + _parse_template_file log failures at
debug and return None/zero. Fix: aggregate failures and raise TemplateBootstrapError; log at warning; expose failed_templates; only skip bootstrap
 when ALL names exist.
B26. W9 F7 [core/script_gen.py:378-415] swallowed-exception low — JavaScript validator returns (True, None) on any
non-timeout/non-FileNotFoundError. Fix: distinguish tempfile-write failure from subprocess absence; only return True for real success; Java
validator—replace string-contains with real parsing or require explicit class declaration.

=== HEXPAT PARSER + LEXER + AST (12 findings) ===

B27. W10 F1 [core/hexpat/parser.py:1120-1146] happy-path-only critical — _parse_struct doesn't accept `<T, auto size, PointerSize>` template
params. Fix: parse template parameter list after struct/using/function name; store on StructDecl/UsingDecl/NamedType; evaluator substitutes at
instantiation.
B28. W10 F2 [core/hexpat/parser.py:1260-1285] missing-rpc critical — `auto ... args` variadic params not parsed. Fix: after param type, check for
ELLIPSIS and consume; add is_varargs: bool to FunctionParam.
B29. W10 F3 [core/hexpat/parser.py:1226-1239] happy-path-only critical — `padding : N;` fails because PADDING not IDENTIFIER token. Fix: accept
PADDING, SIGNED, UNSIGNED, primitive-type tokens in bitfield entry; extend BitfieldEntry with type_hint/is_padding.
B30. W10 F4 [core/hexpat/parser.py:1183-1199] missing-rpc high — enum range `Name = 0 ... 7` breaks because ELLIPSIS not in _INFIX_BP. Fix: after
first expression, check for ELLIPSIS; parse second expression; add EnumEntry.value_end.
B31. W10 F5 [core/hexpat/parser.py:156-172, 1171] signature-drift high — annotations before enum discarded; EnumDecl has no annotations field.
Fix: add annotations tuple to EnumDecl; update _parse_enum to receive and store; fix top-level + namespace dispatch sites.
B32. W10 F6 [core/hexpat/interpreter.py:116-127, 189-200] signature-drift high — PragmaInfo rebuild drops pointer_size + bitfield_order when
base_address offset applied. Fix: use dataclasses.replace(pragma, base_address=offset) or explicitly include all remaining fields.
B33. W10 F7 [core/hexpat/lexer.py:519, tokens.py:93] dead-code medium — HASH token emitted but parser never references; stray `#` becomes cryptic
unexpected-token error. Fix: remove HASH from TokenType and lexer singles; lexer raises HexPatParseError with directive hint on surviving `#`.
B34. W10 F8 [core/hexpat/preprocessor.py:340-346] swallowed-exception high — unresolved include returns "" inline. Fix: raise
HexPatPreprocessorError with include_path + originating file + line, matching #error path.
B35. W10 F9 [core/hexpat/data_reader.py:44-65] happy-path-only medium — `doc_length()` invocation assumes callable but some shims expose as
property. Fix: `v = document.length() if callable(document.length) else document.length`; or adapter that normalizes interface with clear error.
B36. W10 F10 [core/hexpat/errors.py:54-56] swallowed-exception medium — HexPatParseError has only (line, column); consumers (LSP, Qt squiggles)
need span. Fix: add optional end_line/end_column (and end_offset on HexPatRuntimeError); parser passes consumed-token end position; runtime
attaches last-read byte range.
B37. W10 F11 [core/hexpat/parser.py:300-350] happy-path-only medium — _parse_type endianness consumed but only attached to PrimitiveType; dropped
for NamedType/ArrayType/PointerType. Fix: add endianness: str | None to NamedType/ArrayType/PointerType; propagate.
B38. W10 F12 [core/hexpat/parser.py:170-171, 795-828] happy-path-only medium — parse() aborts on first top-level error with no recovery. Fix:
introduce _synchronise() advancing to SEMICOLON/RBRACE after HexPatParseError; collect errors list; expose on interpreter result.

=== HEXPAT RUNTIME (17 findings) ===

B39. W11 F1 [hexpat/stdlib.py:508-519, hexpat/evaluator.py:1936-1937] hardcoded-return high — builtin print / _io_print drop formatted output.
Fix: _io_print interprets args[0] as format string and applies _io_format; emit via logger AND to UI message channel. Remove bare `print` builtin
or delegate to formatted path.
B40. W11 F2 [hexpat/stdlib.py:80-144] missing-rpc critical — builtin::std::error and builtin::std::warning never registered. Fix: register
callable raising HexPatRuntimeError(str(args[0])) for error; _logger.warning+return None for warning. Register under both `builtin::` and
non-`builtin::` namespaces.
B41. W11 F3 [hexpat/stdlib.py:193-211] signature-drift critical — _mem_find_sequence uses wrong schema; treats args[0] as start not
occurrence_index. Fix: unpack (occurrence_index, offsetFrom, offsetTo, pattern_bytes); loop calling find_sequence advancing pos = result+1 until
Nth occurrence; stop if result+len(pattern) > offsetTo.
B42. W11 F4 [hexpat/stdlib.py:146-174] signature-drift high — _mem_read_unsigned/_signed ignore explicit endian arg (arg 3: 0=Native, 1=Big,
2=Little). Fix: extract args[2] endian tag, map to "big"/"little" (Native falls back to interpreter endian), pass to from_bytes.
B43. W11 F5 [hexpat/stdlib.py:115-130] missing-rpc high — 18+ std::math functions missing (sin/cos/tan/log10/ln/fmod/round/trunc/accumulate +
hyperbolics). Fix: thin wrapper calling math.* for each; accumulate reads range in valueSize-byte chunks and folds per
Add/Multiply/Modulo/Min/Max.
B44. W11 F6 [hexpat/stdlib.py:80-141] missing-rpc high — entire categories missing: hash (crc8/16/32/64), time (epoch/to_local/to_utc/format),
file (open/close/read/write/seek/size/resize/flush/remove), random (set_seed/generate), env/sizeof_pack, core reflection (has_attribute,
get_attribute_argument, member_count, has_member, formatted_value, is_valid_enum, set_pattern_color, set_display_name, set_pattern_comment,
set_pattern_palette_colors, reset_pattern_palette, execute_function). Fix: implement each. Use zlib.crc32 + crccheck.crc for hashes;
time.time/localtime/strftime for time; sandboxed Path.open for file; random.Random for random; os.environ.get for env; thread pattern-node
metadata through evaluator for reflection helpers.
B45. W11 F7 [hexpat/preprocessor.py:319-346] swallowed-exception critical — missing #include logs warning and inlines "". Fix: raise
HexPatPreprocessorError(f"include not found: {include_path}", line=line).
B46. W11 F8 [hexpat/preprocessor.py:402-415] happy-path-only medium — _process_defines uses re.sub with word boundary; no function-like macros, no
 re-scan, expands inside string literals. Fix: token-aware expander distinguishing strings/comments; function-like macro parameter parsing;
iterate to fixed point with recursion cap.
B47. W11 F9 [hexpat/evaluator.py:743-750, 1119-1150] happy-path-only high — PointerType evaluated as opaque u64, never dereferences pointee. Fix:
after reading storage integer, save $, set $ to decoded address, recursively _instantiate_type(type_node.pointee, var_name, decoded_addr, ...)
attach as single child, restore $. Respect PointerType.storage_type not hardcoded u64.
B48. W11 F10 [hexpat/interpreter.py:116-127, 189-200] disconnected-wiring high — execute/execute_bytes PragmaInfo rebuild drops pointer_size +
bitfield_order (also covered by B32; ensure consistent fix).
B49. W11 F11 [hexpat/evaluator.py:941-1001] dead-code high — bitfield_order pragma extracted but _eval_bitfield_instance hardcodes LSB-first. Fix:
 branch on self._pragma.bitfield_order; left_to_right uses `(int_value >> (total_bits - bit_pos - width)) & mask`; right_to_left uses `(int_value
>> bit_pos) & mask`. Honor per-bitfield [[bitfield_order]] annotation overrides.
B50. W11 F12 [hexpat/evaluator.py:1787-1796] happy-path-only medium — _sizeof_struct sums only FieldDecl, skips
PlacementStmt/ConditionalField/arrays/parent. Fix: mirror _eval_struct_instance logic: include parent recursively; for FieldDecl with array_size
compute size*elements; PlacementStmt uses at_offset; ConditionalField picks statically-visible branch; for while-sized arrays return lower bound
flagged for Rust-path refusal.
B51. W11 F13 [hexpat/evaluator.py:1830-1870] happy-path-only medium — _eval_cast silently returns value unchanged when target is
enum/bitfield/struct. Fix: when target resolves to EnumTypeInfo, coerce to int and wrap in PatternValue with enum backing primitive; same for
BitfieldTypeInfo; catch OverflowError/ValueError on float→int and raise HexPatRuntimeError.
B52. W11 F14 [hexpat/evaluator.py:1599-1616] happy-path-only high — _eval_member_access fails on plain-field PatternValue because
_eval_plain_field doesn't populate .members. Fix: in _eval_struct_instance/_eval_union_instance build members dict keyed by field name as children
 produced; attach to bound PatternValue; thread through _eval_stmt_collect.
B53. W11 F15 [hexpat/evaluator.py:670-678] dead-code low — duplicated self._offset assignment from identical sources. Fix: remove the first
assignment (and unused field_size local); keep the assignment after _pattern_count increment.
B54. W11 F16 [hexpat/evaluator.py:819-849, 878-903] happy-path-only medium — _eval_struct_instance / _eval_union_instance don't restore
_offset/_scope/_depth on raise. Fix: wrap body in try/finally; move the three restore lines into finally. Match pattern used in
_call_user_function.
B55. W11 F17 [hexpat/pattern_registry.py:138-186] happy-path-only low — match_file scan-loop to compute max_magic_end is effectively dead work.
Fix: cache _max_magic_end on registry, update on scan(); drop per-call loop.

ORCHESTRATION: Group findings that share a file. Fix parser findings before running interpreter findings (one PR / commit cluster per file makes
sense). For stdlib expansion (B44), implement one category at a time and run interpreter tests between categories.

FINAL GATE:
- All 55 addressed.
- `pixi run ruff check src/intellicrack/core/` → 0.
- basedpyright / pydoclint / pydocstyle clean on core/.
- No modifications outside src/intellicrack/core/.
- Sample hexpat patterns from vendor/ImHex-Patterns/patterns round-trip without regression.

---
---

```
================================================================================
================================================================================

                         G R O U P   A  —  B R I D G E S
                                (Execute THIRD)

================================================================================
================================================================================
```

ROLE: You are the orchestrator for Group A (Bridges layer) of Intellicrack's production-readiness remediation.

SCOPE (only modify files in):
- src/intellicrack/bridges/**

OUT OF SCOPE (must not touch):
- src/intellicrack/core/**
- src/intellicrack/providers/**
- src/intellicrack/ui/**
- src/intellicrack/sandbox/**
- src/intellicrack-hexcore/**

CLAUDE.md STANDARDS (non-negotiable):
- Production code only. NO placeholders, mocks, stubs, hardcoded fixtures, silent swallows, or simulated output.
- Every fix must perform the real operation described, handling edge cases and Windows-priority platform concerns.
- NEVER use type: ignore / pyright: ignore / noqa for type issues. Fix the real type error.
- NEVER edit [tool.basedpyright] in pyproject.toml.
- Full pydoclint / pydocstyle / ruff compliance. Zero findings.
- Google-style docstrings matching signatures exactly.
- NO comments, emojis, or TODO markers unless explicitly requested.

WORKFLOW (for each finding below, in order):
1. Read the file at the cited line range and surrounding 30+ lines.
2. Apply the "Working fix" concretely.
3. Validate:
   - `pixi run ruff check <file>` → 0 findings
   - `pixi run ruff format <file>` → formatted
   - basedpyright type check (via dev-tools) → 0 findings
   - pydoclint / pydocstyle → 0 findings
4. If any validator fails, FIX THE ROOT CAUSE. Never suppress.
5. After each finding, read the resulting diff and confirm it matches the Working fix description.
6. When all findings for a file are done, re-run full-file validators one more time.
7. Commit per bridge (one commit per file or per tight cluster).

ORCHESTRATION:
- For findings that cluster (e.g. all ctypes restype fixes in x64dbg), you MAY spawn a focused subagent via the Agent tool (subagent_type:
general-purpose) with a narrow scope.
- After any subagent returns, ALWAYS read the diff yourself and re-run validators. Do not trust "completed" claims — verify.
- If a finding requires a new bridge capability (e.g. new RPC), implement it fully; do not leave stubs.

QUALITY GATES (must all pass before final commit):
- `pixi run ruff check src/intellicrack/bridges/` → 0
- `pixi run ruff format src/intellicrack/bridges/` → clean
- basedpyright on bridges/ → 0
- pydoclint / pydocstyle on bridges/ → 0
- Any existing bridge tests under tests/ must still pass (do not run sandbox/network-dependent tests)

FINDINGS (77 total, grouped by bridge):

=== GHIDRA BRIDGE (src/intellicrack/bridges/ghidra.py, 10 findings) ===

A1. F1 [ghidra.py:1277-1342] swallowed-exception high — load_binary swallows Ghidra importFile failure then sets
state.connected/tool_running/binary_loaded=True. Fix: re-raise ToolError on importFile failure; only set binary_loaded=True after
_extract_binary_metadata succeeds; clear flags on any failure.
A2. F2 [ghidra.py:1511-1541] simulated-output high — _detect_architecture fabricates arch locally, mis-reports ARM64/MIPS/PPC/RISC-V ELF64 as
x86_64, ignores Mach-O. Fix: query currentProgram.getLanguage().getLanguageID() and getDefaultPointerSize() via Ghidra RPC; keep
_detect_architecture only as pre-Ghidra fallback; extend fallback with ARM/AARCH64/MIPS/PPC/RISC-V e_machine values and Mach-O cputype.
A3. F3 [ghidra.py:3027-3059] happy-path-only high — write_bytes passes 0-255 bytes into jarray('b') which requires signed -128..127; 0x80+ bytes
throw. Fix: apply sign-fold `bj = (b - 256) if b > 127 else b` matching search_bytes. Wrap in startTransaction/endTransaction. Read bytes back to
confirm write before returning success:True.
A4. F4 [ghidra.py:4543-4578] missing-rpc high — set_color calls non-existent CodeUnit.setBackgroundColor. Fix: in headless, persist color via
IntPropertyMap on program, or create bookmarks with colorizer category. When PluginTool available, use
state.getTool().getService(ColorizingService).setBackgroundColor.
A5. F5 [ghidra.py:4238-4285] simulated-output medium — set_decompiler_options configures a throwaway DecompInterface;
decompile/get_pcode/get_slice each construct fresh interfaces with defaults. Fix: store simplification + max_instructions on bridge instance;
interpolate into every DecompInterface-using script; verify via opts.getSimplificationStyle() readback.
A6. F6 [ghidra.py:3467-3522] signature-drift medium — import_debug_info DWARF branch never uses debug_path; PDB branch imports PdbAnalyzer but
only sets option string. Fix: for DWARF, use DWARFProgram with ByteProvider wrapping debug_path, call DWARFAnalyzer; for PDB, use PdbApplicator
with PdbParser.parse; return success reflecting actual symbol count delta.
A7. F7 [ghidra.py:2873-2949] signature-drift medium — get_call_graph returns callees only despite docstring promising callers+callees;
failure-path dict has both keys, success-path has only callees. Fix: either narrow docstring/tool_definition to callees-only and redirect
bidirectional callers to get_call_tree, or add getReferencesTo traversal filtered by isCall().
A8. F8 [ghidra.py:2545-2573] swallowed-exception medium — delete_function returns success:True even when no function existed at address. Fix: have
 Jython script return boolean; raise ToolError("No function at {hex(address)}") when remote returned False.
A9. F9 [ghidra.py:4634-4716] signature-drift low — manage_thunks / manage_external_references named "manage_*" but are read-only. Fix: rename to
get_thunk_info / get_external_references; update tool_definition names; if management is needed, add set_thunk_target / remove_thunk /
add_external_reference / remove_external_reference.
A10. F10 [ghidra.py:4427-4458] happy-path-only low — get_program_tree returns only direct children of root module, flattening recursive tree. Fix:
 recursive Jython helper descending ProgramModule.getChildren(); for ProgramFragment include AddressRange list; depth cap 6.

=== X64DBG BRIDGE (src/intellicrack/bridges/x64dbg.py + named_pipe_client.py + _win32_types.py, 16 findings) ===

A11. F1 [x64dbg.py:2124-2132] missing-rpc critical — hardware BP sends "bphws" pipe command but plugin only registers
bp_set/bp_remove/bp_list/bp_enable/bp_disable. Fix: use bp_set with type:"hardware"; plugin's bp_set handler (command_handler.cpp:286) already
maps that to bphws via DbgCmdExec.
A12. F2 [x64dbg.py:2920-2953] simulated-output high — scan_memory caps each region at MAX_MEMORY_READ_SIZE (1 MiB), silently misses matches past
that. Fix: chunked iteration across region with rolling tail of len(pattern)-1 bytes at seams; walk until region.base_address + region.size.
A13. F3 [x64dbg.py:2724-2733] simulated-output high — MemoryRegion.type inverted (MEM_MAPPED labelled private); MEM_IMAGE never distinguished;
module_name hardcoded None. Fix: correct lookup map for MEM_PRIVATE/MEM_MAPPED/MEM_IMAGE per MSDN; resolve module_name by matching
mbi.AllocationBase against get_modules().
A14. F4 [x64dbg.py:3117-3128] hardcoded-return medium — ModuleInfo.entry_point always 0. Fix: reuse existing _read_pe_header; read
AddressOfEntryPoint at PE offset+24+16; add base_address.
A15. F5 [x64dbg.py:4436-4444] hardcoded-return high — get_handles fires GUI-only "handlelist" command and returns [{success:True, note:...}]. Fix:
 call NtQuerySystemInformation with SystemExtendedHandleInformation, filter by attached PID, return per-entry dicts using
SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX already in _win32_types.py.
A16. F6 [x64dbg.py:3791-3815, 3850-3878, 4506] hardcoded-return high — find_string_references / find_intermodular_calls / find_references /
reconstruct_imports / save_database / load_database / clear_database return fake success. Fix: after enqueuing x64dbg command, call plugin
ref_search (already registered) that iterates Script::Ref::GetList() and returns structured entries.
A17. F7 [x64dbg.py:4305-4331] hardcoded-return high — yara_scan returns [{success:True}] placeholder when rule_path provided or address/size
missing. Fix: always load rule via yara-python, iterate regions via get_memory_regions, call rules.match(data=...) per region; drop yarascan
native command path.
A18. F8 [x64dbg.py:2456-2460, 2510-2514, 2578-2582, 3022, 3101-3104, 4875] platform-broken high — missing restype/argtypes on
OpenProcess/CreateToolhelp32Snapshot/ReadProcessMemory etc. HANDLEs truncated on 64-bit. Fix: set restype=wintypes.HANDLE,
argtypes=[wintypes.HANDLE, ...] on every Win32 call; use wintypes.HANDLE(-1).value for INVALID_HANDLE_VALUE consistently.
A19. F9 [named_pipe_client.py:377, 386-401, 439, 447-462] platform-broken medium — ReadFile/WriteFile use ctypes.windll.kernel32 without
use_last_error, so get_last_error() returns 0 instead of real Win32 error. Fix: lift kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) to
module-level and reuse; or let ctypes raise WinError() naturally.
A20. F10 [x64dbg.py:334] other low — _read_unicode_string_from_params uses PE_MAGIC_OFFSET (0x40) as 32-bit RTL_USER_PROCESS_PARAMETERS offset
(accidentally correct). Fix: introduce CMD_LINE_OFFSET_32 = 0x40 constant; use instead of PE_MAGIC_OFFSET.
A21. F11 [x64dbg.py:2915-2919] happy-path-only low — scan_memory warns on short pattern but proceeds anyway. Fix: raise ToolError("pattern too
short for reliable scan") or drop check.
A22. F12 [x64dbg.py:4493-4504] swallowed-exception medium — patch_anti_debug returns success:True when checks list contains only unknown checks.
Fix: set success=False when patched list is empty; wrap each write_memory in try/except; return per-check status map.
A23. F13 [x64dbg.py:2977-2980] happy-path-only medium — spawn joins args with " " losing quoting for paths-with-spaces. Fix: use
subprocess.list2cmdline(args); escape embedded quotes in the resulting string.
A24. F14 [x64dbg.py:1748-1750] happy-path-only medium — _start_debugger sleeps 3s unconditionally. Fix: replace with WaitNamedPipeW polling loop
up to 15s deadline, then ping plugin to confirm end-to-end readiness.
A25. F15 [x64dbg.py:1597-1603, 1330-1344, 1449-1458] signature-drift medium — adjust_privilege / set_logging_breakpoint / yara_scan use
keyword-only syntax that tool_definition doesn't reflect. Fix: drop `*,` to match convention.
A26. F16 [x64dbg.py:2762-2799 and 12 similar sites] swallowed-exception medium — disassemble_at / get_stack_trace / get_patches / read_peb /
read_teb / get_seh_chain / get_labels / get_comments / plugin_list / get_trace_record / get_pe_directories / get_watches use `except ToolError:
pass`. Fix: keep last_error on bridge; only fall back on specific errors (ERROR_FILE_NOT_FOUND/pipe disconnect); re-raise all other ToolError.

=== FRIDA BRIDGE (src/intellicrack/bridges/frida_bridge.py, 18 findings) ===

A27. F1 [frida_bridge.py:1658-1665] hardcoded-return high — scan_memory returns context_before/after = "" always. Fix: extend embedded JS to read
~16 bytes before/after via Memory.readByteArray; base64-encode; populate real fields.
A28. F2 [frida_bridge.py:1847-1872] swallowed-exception critical — hook_function returns HookInfo(active=True, address=None) even when
Interceptor.attach fails. Fix: inspect messages for {type:"error"} or missing "hooked" payload; unload script; raise ToolError(_ERR_HOOK_FAILED).
Replace fixed sleep(0.1) with asyncio.Event.
A29. F3 [frida_bridge.py:5208-5226] happy-path-only high — sqlite_open returns script_id even when no reply arrived. Fix: use asyncio.Event +
wait_for("sqlite_opened" payload); on timeout unload and raise ToolError(_ERR_SQLITE_FAILED).
A30. F4 [frida_bridge.py:2098-2113] happy-path-only high — _execute_script_and_wait unconditionally event.set() on any message, including "log";
premature unblock. Fix: move event.set() inside send and error branches only; optionally gate on expected payload type.
A31. F5 [frida_bridge.py:2726-2744 + callers] other high — _resolve_target_js interpolates target into single-quoted JS without escaping; enables
JS injection and breaks on names with '. Fix: all interpolations in
enumerate_exports/imports/find_base_address/find_functions_named/enumerate_modules use _escape_js_string. replacement_code / on_enter / on_leave
fragments must be passed via script.post + recv / rpc.exports instead of interpolated.
A32. F6 [frida_bridge.py:1740-1780, 2192-2236] swallowed-exception medium — enumerate_exports/imports silently return [] when module not found.
Fix: emit {error:"module_not_found"} from JS; Python raises ToolError(_ERR_MODULE_NOT_FOUND).
A33. F7 [frida_bridge.py:3282-3308] disconnected-wiring high — create_cancellable stores frida.Cancellable but never passes it to any Frida call.
Fix: either wire it into attach/spawn/create_script/compiler.build via optional cancellable_id param, or drop the token registry.
A34. F8 [frida_bridge.py:5438-5463] signature-drift medium — compile_typescript docstring says accepts source or path; frida.Compiler.build
accepts only path. Fix: write source to temp .ts file, build, delete; or tighten contract to path-only.
A35. F9 [frida_bridge.py:5308-5321] hardcoded-input medium — write_code hardcodes 256-byte Memory.patchCode window. Fix: two-phase: probe
Memory.alloc(4096) to measure w.offset, then patchCode with measured size. Or add max_size param.
A36. F10 [frida_bridge.py:3135] dead-code low — `_ = self.state` no-op. Fix: delete line or decorate method @staticmethod.
A37. F11 [frida_bridge.py:1406-1420, 1463] signature-drift medium — resume/detach reuse _ERR_NOT_ATTACHED on device.resume/detach failures. Fix:
add _ERR_RESUME_FAILED / _ERR_DETACH_FAILED constants; use for those branches; keep _ERR_NOT_ATTACHED for precondition only.
A38. F12 [frida_bridge.py:3695-3710] happy-path-only medium — get_backtrace uses this.context in top-level script where this is undefined. Fix:
default ctx_js to literal `null` when context_address is None; Frida interprets null as current thread.
A39. F13 [frida_bridge.py:1850, 2336, 2674, 3397, 4328, 4559, 4659, 5210] happy-path-only medium — 8 methods use fixed asyncio.sleep(0.1). Fix:
each site uses asyncio.Event set inside on_message for expected payload type + asyncio.wait_for with method-appropriate timeout (5s alloc, 15s
java hooks).
A40. F14 [frida_bridge.py:3201-3221] signature-drift low — post_message docstring claims ToolError only but json.loads can raise JSONDecodeError.
Fix: wrap json.loads in try/except (json.JSONDecodeError, TypeError), raise ToolError("invalid JSON message").
A41. F15 [frida_bridge.py:2378-2385 + 1549, 4900, 4745, 4929, 4979] other medium — protect_memory / get_memory_regions / kernel_protect /
kernel_enumerate_ranges / socket_listen / socket_connect interpolate params without escape. Fix: add _VALID_PROTECTION_FLAGS set; validate
protection; apply _escape_js_string uniformly.
A42. F16 [frida_bridge.py:4525-4541] happy-path-only medium — java_hook_method uses this[method].apply(this, args) risking infinite recursion /
overload-ambiguous calls. Fix: capture `var original = cls[method][overload].implementation;` once, call original.apply(this, args) inside hook.
A43. F17 [frida_bridge.py:2895-2912] swallowed-exception medium — stalker_follow doesn't propagate JS-side runtime errors. Fix: require
{type:"stalker_started"} before return; collect errors, raise ToolError(_ERR_STALKER_FAILED) on timeout or missing started.
A44. F18 [frida_bridge.py:2275-2287] hardcoded-return low — enumerate_threads uses pc as start_address and hardcodes priority=0. Fix: either add
current_pc field to ThreadInfo and call GetThreadPriority via NativeFunction, or clearly separate start_address (unknown) from current_pc.

=== HEX EDITOR BRIDGE (src/intellicrack/bridges/hex_editor.py + hex_state.py, 10 findings) ===

A45. F1 [hex_editor.py:967-979, 3256-3282] signature-drift high — tool_definition for import_patches advertises bps/ups/original_path but method
accepts only data_b64 IPS. Fix: split tool_definition into format-specific entries, OR broaden import_patches to accept original_path and dispatch
 on magic header to import_patches_ips/bps/ups.
A46. F2 [hex_editor.py:947-965, 3225-3254] signature-drift high — export_patches tool_def enum includes bps/ups but method only handles ips/ips32.
 Fix: either tighten enum to ips/ips32, or route to export_patches_bps/ups with original_path source.
A47. F3 [hex_state.py:187-216, 343-355] other medium — set_document / notify_document_saved mutate state without holding self._lock. Fix: wrap
mutations in `with self._lock:` storing locals first then _notify outside lock.
A48. F4 [hex_editor.py:1463-1470] disconnected-wiring medium — shutdown() nulls self.document but never clears state_holder. Fix: call
self.state_holder.set_document(None, None, source="bridge") before nulling, mirroring close_file.
A49. F5 [hex_editor.py:3990-4005] swallowed-exception medium — apply_arithmetic_to_selection catches TypeError/ValueError/RuntimeError from
transform_data and silently falls back; unknown ops silently copy bytes unchanged. Fix: validate operation against transform_map; raise ValueError
 on unknown; log warning before fallback; feature-probe via list_transforms.
A50. F6 [hex_editor.py:2223-2303] swallowed-exception medium — copy_as returns "" for unknown format. Fix: raise ValueError(f"unsupported copy_as
format: {fmt}").
A51. F7 [hex_editor.py:3317-3363] happy-path-only medium — _apply_ips_patches fallback treats IPS RLE size=0 as zero-copy. Fix: extend parser to
read 2-byte RLE length + 1-byte value on size==0; call state_holder.notify_data_modified after loop. Or remove the Python fallback since
import_patches_ips hexcore exists.
A52. F8 [hex_editor.py:3420-3437, 3487-3503] happy-path-only medium — search_numeric fallback seam advance `chunk_len - size + 1` wrong for short
trailing chunks; alignment reset ignored at seams. Fix: `pos += max(chunk_len - (size-1), alignment)`; reset idx to `(-pos) % alignment` per
chunk. Prefer native hexcore; raise if unavailable.
A53. F9 [hex_editor.py:4012-4054] simulated-output low — _apply_arithmetic_fallback's final `else: result[i] = b` silently returns input unchanged
 for unknown op / empty key. Fix: raise ValueError in the else branch; validate upstream in apply_arithmetic_to_selection.
A54. F10 [hex_editor.py:1913-1923, 2180-2198] swallowed-exception low — list_templates / list_templates_detailed catch TypeError on HexDocument()
init and return []. Fix: let exception propagate, or return sentinel {error: str} for detailed variant.

=== PROCESS + SANDBOX BRIDGES (src/intellicrack/bridges/process.py + sandbox_bridge.py, 14 findings) ===

A55. F1 [process.py:210-225, 227-241] disconnected-wiring critical — tool_definition names "process.list", "list_detailed", "open" don't map to
bridge methods list_processes / list_processes_detailed / open_process. Fix: rename tool_definition suffixes OR add dispatch methods list /
list_detailed / open forwarding to real ones. Align with convention used by get_modules/get_threads.
A56. F2 [process.py:2719-2832] platform-broken critical — stack_walk hardcodes CONTEXT64 + IMAGE_FILE_MACHINE_AMD64; broken for all 32-bit/WOW64
targets. Fix: detect target bitness via IsWow64Process2; for WOW64 use Wow64GetThreadContext + WOW64_CONTEXT +
StackWalk64(IMAGE_FILE_MACHINE_I386, ...) seeded from Eip/Ebp/Esp.
A57. F3 [process.py:1660-1701] happy-path-only high — _query_thread_state uses OpenThread(THREAD_QUERY_INFORMATION) then SuspendThread which needs
 THREAD_SUSPEND_RESUME. Fix: add THREAD_SUSPEND_RESUME to access mask; cast suspend count to signed int; return "unknown" on -1. Or use
NtQueryInformationThread(ThreadSuspendCount).
A58. F4 [process.py:1027-1056] platform-broken high — detect_architecture falls back to host pointer size via struct.calcsize("P") when
IsWow64Process returns False. Fix: use IsWow64Process2 on Win10+; fall back to PE-header Machine read.
A59. F5 [process.py:2341, 2436, 3077] platform-broken high — PEB/TEB parsers use host pointer size not target. Fix: use
NtQueryInformationProcess(ProcessWow64Information) for WOW64 target PEB; apply 32-bit offsets; same for TEB / RTL_USER_PROCESS_PARAMETERS.
A60. F6 [process.py:3464-3504] signature-drift high — get_job_info returns only {in_job} despite promising limit info. Fix: on IsProcessInJob
TRUE, OpenJobObjectW + QueryInformationJobObject(JobObjectBasicLimitInformation, JobObjectExtendedLimitInformation); fill
LimitFlags/ActiveProcessLimit/ProcessMemoryLimit etc; raise ToolError on IsProcessInJob failure.
A61. F7 [process.py:1497-1504] happy-path-only high — search_pattern silently truncates each region to 1 MiB. Fix: overlapping chunks of 1 MiB
with len(pattern)-1 overlap; honor start_address/end_address; expose bounds in tool_definition.
A62. F8 [process.py:335-339, 340-347, 534-541 + sandbox_bridge.py:359-370] signature-drift medium — tool_def drift: search_pattern missing
start/end params, get_memory_map missing resolve_names, detect_dotnet runtime_dll vs runtime_dlls, snapshot_list returns dict vs advertised list.
Fix: regenerate tool_defs to match methods; describe real return shape.
A63. F9 [sandbox_bridge.py:1233-1240] swallowed-exception medium — get_pending_messages silently returns [] when _agent is None. Fix: raise
ToolError(f"{_ERR_MESSAGES_FAILED}: guest agent not connected").
A64. F10 [sandbox_bridge.py:728, 805] happy-path-only medium — create/run_binary coerce unknown sandbox_type to "qemu". Fix: `if sandbox_type not
in {"windows","qemu"}: raise ToolError("Invalid sandbox_type")`.
A65. F11 [process.py:2407-2417] swallowed-exception medium — read_teb returns partial dict on RPM failure; downstream
get_seh_chain/get_tls_values/get_fiber_data silently see missing keys. Fix: raise ToolError on RPM failure, or return {"partial":True,
"error":...} and update consumers.
A66. F12 [process.py:1625-1658] swallowed-exception low — _query_thread_start_address returns 0 on negative NTSTATUS with no log. Fix: log DEBUG
with status code; consider returning None and making ThreadInfo.start_address optional.
A67. F13 [process.py:540, 3342, 3365] signature-drift low — detect_dotnet tool_def and docstring say runtime_dll singular; actual return key
runtime_dlls. Fix: align tool_def / docstring.
A68. F14 [sandbox_bridge.py:1764-1783, 128-641] disconnected-wiring low — get_vnc_port exists + wired to panel but absent from tool_definition.
Fix: add ToolFunction(name="sandbox.get_vnc_port", parameters=[instance_id], returns="VNC port number or null").

=== CUTTER + INFRASTRUCTURE (src/intellicrack/bridges/cutter.py + schemas.py + installer.py + base.py + __init__.py, 9 findings) ===

A69. F1 [cutter.py:2277-2295] missing-rpc critical — import_c_header sends `"to -" <<< "..."` shell heredoc to rizin. Fix: write header to temp
file; call `to <tempfile>` via r2 cmd; delete temp in finally.
A70. F2 [cutter.py:2819-2837] missing-rpc high — compare_disassembly uses `cd` which is change-directory. Fix: use rizin `cD` or cCj (JSON
compare). Read file bytes, convert to hex, run `cmp.hex=<hex>; cD @ <address>`.
A71. F3 [cutter.py:1634-1660] happy-path-only high — assemble_at writes via `wa` BEFORE verifying with `pa`. Fix: call `pa <instruction>` first to
 validate and capture bytes; only on success run `wa` (or `wx <hex>` from captured bytes).
A72. F4 [cutter.py:2557-2621] happy-path-only high — write_xor/write_add/write_sub set global block size via `b <length>` then perform op;
pollutes session state. Fix: use temporary block size suffix `wox {key:#x} @!{length} @ {address}`. Same for woa, wos.
A73. F5 [cutter.py:1459-1525, 1674-1700] swallowed-exception high — _get_sections_internal / _get_imports_internal / _get_exports_internal /
_cmd_json silently return [] when _r2 is None. Fix: raise ToolError(_ERR_NO_BINARY) on None; replace `[] if not self._analyzed` wrappers with
explicit check-and-raise.
A74. F6 [cutter.py:2159-2179] happy-path-only medium — resolve_flag heuristic mis-handles `fd` output containing `+offset`. Fix: use `fdj @
{address}` (JSON) and parse name/offset fields explicitly.
A75. F7 [installer.py:619-658] platform-broken medium — _download_file streams then buffers chunks in Python list, defeating streaming. Fix: open
temp_path for incremental writes in a thread; write each chunk as it arrives.
A76. F8 [installer.py:694-703] platform-broken medium — _extract_zip calls zf.extractall with no path validation (Zip Slip). Fix: iterate
infolist, resolve target = (dest_dir/member.filename).resolve(), require is_relative_to(dest_dir.resolve()); reject CON/AUX/NUL reserved names.
A77. F9 [base.py:164-195] dead-code low — has_capability checks `supports_<first_word_before_underscore>` which rarely matches declared flags;
result only logged. Fix: either remove the system entirely, or add an explicit tool→capability map and enforce via raise ToolError when
has_capability is False.

ORCHESTRATOR VERIFICATION AFTER EACH FINDING:
- Re-read the modified file at the finding's line range.
- Run: ruff check, ruff format --check, basedpyright, pydoclint on the file.
- Confirm the diff implements the Working fix, not a rewording.
- If a subagent returns with unchanged file or partial fix, reopen and complete it yourself.

FINAL GATE BEFORE DONE:
- All 77 findings addressed.
- `pixi run ruff check src/intellicrack/bridges/` clean.
- basedpyright / pydoclint / pydocstyle on bridges/ → 0 findings.
- Git log shows one coherent commit per bridge (or tight cluster).
- No files outside bridges/ modified.

---
---

```
================================================================================
================================================================================

                         G R O U P   D  —  S A N D B O X
                                (Execute FOURTH)

================================================================================
================================================================================
```

ROLE: Orchestrator for Group D (Sandbox subsystem).

SCOPE:
- src/intellicrack/sandbox/**
- src/intellicrack/sandbox/scripts/*.ps1

OUT OF SCOPE:
- All other src/intellicrack/ subpackages.

CLAUDE.md STANDARDS: production only; Windows priority; no placeholders; ruff / basedpyright / pydoclint / pydocstyle clean; PowerShell scripts
must call real Windows APIs/cmdlets.

WORKFLOW per finding: read context; apply Working fix; validate Python with ruff/basedpyright/pydoclint/pydocstyle; validate PowerShell with `pwsh
 -NoProfile -Command "Test-Script <file>"` (PSScriptAnalyzer via `Invoke-ScriptAnalyzer` if available); re-read diff; commit per logical cluster.

ORCHESTRATION: re-verify every subagent change; execute root-cause fixes over suppression.

FINDINGS (19 total):

=== WINDOWS SANDBOX (6 findings) ===

D1. W15 F1 [sandbox/windows.py:518-584] disconnected-wiring critical — run_command writes trigger.cmd to shared folder but nothing inside guest
executes it. Fix: bake a permanent in-guest dispatcher (PowerShell + .cmd) into .wsb LogonCommand that tails input folder for trigger/*.cmd and
exec_*.cmd, captures stdout/stderr/exit code into result_<ts>.txt. Compose startup_commands from user into that bootstrap.
D2. W15 F2 [sandbox/windows.py:556-582] hardcoded-return critical — run_command discards stdout/stderr, always returns ("", ""). Fix: guest script
 redirects stdout to out_<ts>.txt and stderr to err_<ts>.txt (`> "out.txt" 2> "err.txt"`); run_command reads both files alongside result; returns
real tuple.
D3. W15 F9 [sandbox/windows.py:110-111, 220-226, 274-288] platform-broken high — SANDBOX_EXE="WindowsSandbox.exe" + kills launcher PID not
vmwp.exe. Fix: use WindowsSandboxClient.exe via its documented entry; after polling for vmwp.exe worker PID, register it; on stop send WM_CLOSE
then kill vmwp.exe only if graceful fails.
D4. W15 F10 [sandbox/windows.py:1086-1152] simulated-output critical — dump_memory writes zero-byte file. Fix: use MiniDumpWriteDump via ctypes
P/Invoke (dbghelp.dll) with MiniDumpWithFullMemory flag; OpenProcess with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ; or shell to procdump64.exe
-ma <pid> <path> if available. Write real dumps then run yara_scan.
D5. W15 F14 [sandbox/windows.py:749-787] hardcoded-return medium — _parse_network_log hardcodes direction="outbound", protocol="tcp", bytes=0.
Fix: derive direction from $conn.State (Listen→inbound, Established→outbound); parse protocol including udp via Get-NetUDPEndpoint; read
bytes_sent/received from netstat -b -o -n or Get-NetAdapterStatistics; include ProcessName.
D6. W15 F17 [sandbox/windows.py:332-389, 622-632] disconnected-wiring high — monitor bootstrap uses run_command (F1 broken); .wsb LogonCommand
emitted only if startup_commands set. Fix: always emit LogonCommand that launches in-guest dispatcher AND monitors (must run BEFORE binary);
compose user startup_commands into same bootstrap.

=== QEMU SANDBOX (5 findings) ===

D7. W15 F8 [sandbox/qemu.py:2621-2635] missing-rpc high — apply_anti_evasion sends invalid HMP commands `smbios -e` and `cpu-add
model=host,hv-vendor-id=AuthenticAMD`. Fix: move SMBIOS/CPUID customization into _build_qemu_command launch args: -smbios
type=1,manufacturer=...,product=...,serial=...; -cpu host,hv-vendor-id=AuthenticAMD,kvm=off,hypervisor=off. Remove HMP calls.
D8. W15 F11 [sandbox/qemu.py:2551-2569] happy-path-only medium — screendump sleep(0.5) race before PPM read; partial PPM silently returned. Fix:
poll for file stability (read size, sleep, re-read; completed when two consecutive reads match) then convert; raise SandboxError on conversion
failure, do not silently return partial.
D9. W15 F12 [sandbox/qemu.py:2741-2748, 740] platform-broken high — GUEST_SHARED_PATH_WINDOWS = "Z:\\" but Z: never mounted inside guest. Fix:
agent.ps1 bootstrap runs `net use Z: \\10.0.2.4\qemu /persistent:no` on startup before any file polling; or switch to virtio-9p-pci with
WinFsp/spice-guest-tools; or standardize on SSH+SCP via forwarded ssh_port.
D10. W15 F15 [sandbox/qemu.py:1999-2037] hardcoded-return medium — _parse_network_log (QEMU side) same hardcoded direction/protocol/bytes. Fix:
extend agent.ps1/agent.py network log schema with protocol, direction, bytes; update parser.
D11. W15 F19 [sandbox/qemu.py:1343-1353] other low — Windows agent uses Invoke-Expression on attacker-controlled `$request.command`. Fix: replace
with Start-Process / `&` operator using argv list (`& $command @args`); validate command against allowlist; bind to loopback adapter only
(reachable via host forward, not 0.0.0.0).

=== MANAGER + ANALYSIS (2 findings) ===

D12. W15 F13 [sandbox/analysis.py:223-248, 427-518 + qemu.py/windows.py run_binary] disconnected-wiring high — analysis.py functions consume only
ExecutionReport which run_binary never populates with
api_calls/service_changes/kernel_objects/dll_loads/injection_events/resource_samples/clipboard_events. Fix: after run_binary completes, call all
11 _parse_*_log methods to populate full report; OR refactor analysis.py to add aggregate_from_logs(shared_folder: Path) -> ExecutionReport
invoked from run_binary post-processing.
D13. W15 F16 [sandbox/manager.py:174-218, 354-369] happy-path-only medium — create destroys oldest "idle" running instance (no real idleness
tracking), killing concurrent analyses. Fix: track is_busy on SandboxInstance (set during run_binary, cleared after); find oldest is_busy=False;
if none found raise SandboxError instead of evicting.

=== POWERSHELL MONITOR SCRIPTS (6 findings) ===

D14. W15 F3 [sandbox/scripts/*.ps1 (all 7) + qemu.py/windows.py wiring] dead-code critical — 7 monitor scripts orphaned: never copied to shared
folder, never started, logs never read. Corresponding _parse_*_log in qemu.py:2075-2315 never called. Fix: in qemu._create_guest_agent_script and
windows._create_monitor_scripts copy these .ps1 files into the guest monitor folder; rewrite $logDir to actual guest-side shared path
(C:\Users\WDAGUtilityAccount\Desktop\Shared\logs for WSB, or Z:\logs for QEMU); start each via start_monitors.cmd; invoke all _parse_*_log methods
 in run_binary.
D15. W15 F4 [sandbox/scripts/kernel_object_monitor.ps1:11-50] simulated-output critical — queries Win32_Mutex/Win32_Event/Win32_Semaphore which
don't exist in WMI. Fix: use NtQuerySystemInformation with SystemExtendedHandleInformation (class 64) via Add-Type P/Invoke; enumerate handles;
filter by object type; resolve names via NtQueryObject(ObjectNameInformation). Or integrate Sysinternals handle.exe -u. Emit
`timestamp|type|name|pid|procname|operation`.
D16. W15 F5 [sandbox/scripts/api_trace.ps1:11-77] simulated-output critical — uses fabricated *-EtwTraceSession cmdlets; channel
Microsoft-Windows-Kernel-Audit-API-Calls/Operational requires explicit AuditPol config; fallback branch writes fake "API match" for every loaded
module. Fix: use logman create trace + logman start/stop with provider GUID, parse .etl with Microsoft.Diagnostics.Tracing.TraceEventSession
(Add-Type). Or use Frida/Detours for cross-process API tracing.
D17. W15 F6 [sandbox/scripts/dll_monitor.ps1:11-72] simulated-output high — same fabricated *-EtwTraceSession cmdlets; both ETW and "fallback"
branches are identical polling of Get-Process|Modules. Fix: use Microsoft-Windows-Kernel-Process ETW provider (GUID
{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}) ImageLoad keyword 0x40 via logman+TraceEventSession; or Register-WmiEvent Win32_ModuleLoadTrace. Emit
events with real BaseAddress/ImageSize from ETW payload.
D18. W15 F7 [sandbox/scripts/injection_monitor.ps1:39-66] simulated-output critical — Win32_Thread returns nothing on modern Windows; logic treats
 parent-of-owner as injector (every normal process start flagged); any DLL from \Temp\ flagged as injection. NtQueryHelper type declared but never
 called. Fix: use Microsoft-Windows-Kernel-Process ETW provider ThreadStart keyword; correlate ThreadID/ProcessID where ThreadStartAddress outside
 target's loaded modules; or hook NtCreateThreadEx / CreateRemoteThread via Frida. True injection detection also needs memory-protection events
correlated with thread starts.
D19. W15 F18 [sandbox/scripts/resource_monitor.ps1 + service_monitor.ps1 + clipboard_monitor.ps1] disconnected-wiring high — these 3 scripts emit
correct telemetry matching parser schemas, but are never started or consumed. Fix: same as D14 wiring — copy into monitor folder, extend
start_monitors.cmd to launch, call _parse_*_log for each in run_binary before building ExecutionReport.

FINAL GATE:
- All 19 addressed.
- ruff/basedpyright/pydoclint/pydocstyle on sandbox/ → 0.
- PSScriptAnalyzer on all .ps1 → 0 warnings.
- No files outside sandbox/ modified.
- Running the fixed WSB dispatcher against a known harmless binary produces non-empty stdout/stderr/telemetry.

---
---

```
================================================================================
================================================================================

                G R O U P   C  —  P R O V I D E R S   +   C R E D E N T I A L S
                                (Execute FIFTH)

================================================================================
================================================================================
```

ROLE: Orchestrator for Group C (AI Providers + Credentials).

SCOPE:
- src/intellicrack/providers/**
- src/intellicrack/credentials/**

OUT OF SCOPE:
- All other src/intellicrack/ subpackages.
- src/intellicrack-hexcore/.

CLAUDE.md STANDARDS: production only, no suppressions, basedpyright clean, Google docstrings, ruff/pydoclint/pydocstyle.

WORKFLOW per finding: read context, apply fix, validate, re-read diff, commit per provider.

ORCHESTRATION: verify every subagent result; run validators in the orchestrator; never trust "done" without re-reading the diff.

FINDINGS (34 total):

=== ANTHROPIC (3 findings) ===

C1. W12 F1 [providers/anthropic.py:107,122,136,358,452] disconnected-wiring critical — writes self._connected; base.is_connected reads
self.connected. After connect() succeeds is_connected always False → registry rejects Anthropic. Fix: rename all 5 sites self._connected →
self.connected. (Also mirror in disconnect/base.)
C2. W12 F2 [providers/anthropic.py:485-504] happy-path-only high — streaming thinking blocks only debug-logged, never surfaced. Fix: add
self._pending_thinking buffer on LLMProviderBase.__init__ (this lives in base.py, see C23); accumulate block.thinking; add get_pending_thinking()
method. Orchestrator pulls it after async-for loop and sets assistant message thinking_content.
C3. W12 F3 [providers/anthropic.py:509-512] swallowed-exception high — stream error handler only logs when not cancelled; no log for cancel path
with OSError/APIError. Fix: always log; only re-raise when not cancelled; add APIStatusError arm for 5xx retry.

=== GOOGLE (5 findings) ===

C4. W12 F4 [providers/google.py:416-434] platform-broken high — chat_stream wraps next() on sync iterator via asyncio.to_thread per chunk. Fix:
use client.aio.models.generate_content_stream returning AsyncIterator[GenerateContentResponse]; iterate natively with async for.
C5. W12 F5 [providers/google.py:69, 469-481] dead-code high — _current_task never assigned. Fix: either remove dead branch, or wrap
chat/chat_stream entry with self._current_task = asyncio.current_task() cleared in finally.
C6. W12 F6 [providers/google.py:172-180] happy-path-only high — list_models reads supported_generation_methods (legacy SDK field). google-genai
exposes supported_actions. Fix: use getattr(model_data, "supported_actions", []); or default to supports_tools=True + supports_streaming=True on
modern Gemini chat model name prefixes (gemini-1.5/2.0/2.5) and derive supports_vision from name.
C7. W12 F7 [providers/google.py:549-583] happy-path-only medium — response.text raises ValueError when no text parts; function-call-only response
crashes. Fix: wrap response.text in try/except ValueError → "" OR iterate candidates[0].content.parts directly accumulating text/function_call.
C8. W12 F8 [providers/google.py:671-686] happy-path-only medium — _build_tool_declarations splats properties into types.Schema including unknown
"default" key. Fix: pop "default" before splat; explicitly map type string to types.Type[param_type.upper()]; or construct Schema field-by-field
from ToolDefinition.

=== OPENAI + GROK (3 findings) ===

C9. W12 F11 [providers/openai.py:541-558, providers/grok.py:500-517, providers/openrouter.py usage path] happy-path-only medium — stream skips
chunks with empty choices, losing chunk.usage. Fix: pass stream_options={"include_usage": True}; capture chunk.usage when not chunk.choices
instead of continue; add usage: UsageInfo | None = None to Message in core/types.py (coordinate with Group B, but you may add the field here since
 providers/ is your scope — actually Group B owns core/types.py, so request that Group B expose a Message.usage field; in the provider code
reference the existing Message as you pass data — add a _pending_usage attr on LLMProviderBase and document in base.py for when the core field
lands).
C10. W12 F12 [providers/grok.py:345-370] hardcoded-return medium — max_tokens passed to grok-4 reasoning models that require max_completion_tokens
 + reasoning_effort; _infer_context_window hardcodes grok-1/2/3 only. Fix: route to max_completion_tokens when
model.startswith(("grok-4","grok-3-mini")); forward thinking.budget_tokens as reasoning_effort high (>=10000) or low; extend _infer_context_window
 with grok-4 arm (256K).
C11. W12 F13 [providers/grok.py:530-534] happy-path-only low — cancel_request has no info log; sibling providers log. Fix: add
self._logger.info("grok_request_cancelled", had_active_task=...).

=== OPENROUTER (2 findings) ===

C12. W12 F9 [providers/openrouter.py:97-106] platform-broken medium — connect() overwrites self.client without closing prior; HTTP-Referer header
uses api_base (endpoint URL) instead of app identity. Fix: guard with `if self.client is not None: await self.client.aclose()` at top of
connect(); use dedicated "https://github.com/zackiles/intellicrack" (or pkg metadata) for HTTP-Referer; keep api_base for base_url= only.
C13. W12 F10 [providers/openrouter.py:452-457, 292-320] swallowed-exception medium — stream raise_for_status inside async-with-stream block closes
 response before body read; error body lost. Fix: `await response.aread()` before raise_for_status; branch on status: 429 → RateLimitError(body),
401 → AuthenticationError(body), else → ProviderError(body["error"]["message"]). Apply symmetrically to chat().

=== OLLAMA (2 findings) ===

C14. W13 F4 [providers/ollama.py:167-171, 297-307] missing-rpc high — cloud endpoint hits ollama.com/api/tags; cloud exposes /v1/models
OpenAI-compat. Fix: for cloud requests route through /v1/models and /v1/chat/completions; keep /api/* for local; OR require
INTELLICRACK_OLLAMA_CLOUD_URL to be OpenAI-compat base (e.g. https://ollama.com/v1) and document.
C15. W13 F7 [providers/ollama.py:625-637, 653-676] happy-path-only medium — streaming with tools shortcut-falls-back to blocking self.chat(). Fix:
 remove shortcut; always stream; accumulate last_chunk_data; parse tool calls from final chunk with done:true.
C16. W13 F8 [providers/ollama.py:457-458, 618-619] happy-path-only low — tool_choice silently dropped despite Ollama >=0.3.3 supporting it. Fix:
add `request_body["tool_choice"] = self._convert_tool_choice_to_openai_format(tool_choice)` in both chat and chat_stream when tools supplied.

=== HUGGINGFACE (3 findings) ===

C17. W13 F5 [providers/huggingface.py:67, 362-363, 506] missing-rpc high — BASE_URL targets deprecated api-inference.huggingface.co. Fix: switch
BASE_URL to router endpoint `https://router.huggingface.co/hf-inference/v1/chat/completions` (simple form) or use huggingface_hub.InferenceClient
with provider="auto".
C18. W13 F6 [providers/huggingface.py:178-200] happy-path-only medium — list_models filter="text-generation-inference" vs pipeline_tag accept-list
 {"text-generation","conversational"} contradict. Fix: change filter to text-generation; drop conversational gate or accept text-generation as
primary.
C19. W13 F9 [providers/huggingface.py:380-383] happy-path-only medium — 503 branch calls response.json() unguarded; HTML body raises DecodingError
 uncaught. Fix: try/except (json.JSONDecodeError, ValueError) wrap; fallback "Model is loading".

=== LOCAL TRANSFORMERS + XPU (3 findings) ===

C20. W13 F1 [providers/local_transformers.py:273, 294, 312, 398, 490] signature-drift critical — self._connected vs base self.connected. Fix:
rename all 5 sites to self.connected.
C21. W13 F3 [providers/local_transformers.py:710-717] disconnected-wiring high — torch.no_grad() context-manager around asyncio.to_thread; no_grad
 is thread-local, doesn't cross. Fix: move `with _torch.no_grad():` inside _forward_pass closure OR decorate _forward_pass with
@torch.inference_mode().
C22. W13 F2 [providers/xpu_utils.py:563-565] swallowed-exception high — _check_rebar_status returns (True, "") on exception. Fix: return (False,
"Could not verify Resizable BAR status; check system permissions") so operators see probe failed.
C23. W13 F10 [providers/local_transformers.py:1031-1033] hardcoded-return low — get_device_info hardcodes 12.0 GiB when XPU query fails,
clobbering earlier total_memory_gb. Fix: preserve earlier value from device_info.total_memory_bytes; only override when missing; or call
_estimate_memory_from_name(device_info.device_name).
C24. W13 F11 [providers/xpu_utils.py:24-28, 87-103] swallowed-exception low — torch-missing logs DEBUG silently. Fix: promote to WARNING at module
 import; in LocalTransformersProvider.connect explicitly log actionable message when _torch is None.

=== DISCOVERY + REGISTRY + __INIT__ (1 finding) ===

C25. W14 F8 [providers/registry.py:231-245, credentials/store.py:603-618, credentials/oauth.py:947-962] happy-path-only low — singleton holders
not thread-safe; background threads can create duplicate instances. Fix: guard instance-is-None+instantiation with module-level threading.Lock
double-checked locking; or @functools.lru_cache(maxsize=1) helpers.

=== CREDENTIALS STORE (5 findings) ===

C26. W14 F10 [credentials/store.py:462-489, 369-398] happy-path-only critical — list_providers holds self._lock while awaiting self.get(provider)
which re-acquires the same lock → asyncio.Lock is NOT re-entrant → deadlock on first credentials dialog open. Fix: split get() into private
_get_unlocked(); call that inside list_providers; or implement re-entrant primitive keyed by asyncio.current_task().
C27. W14 F2 [credentials/store.py:136-143, 276-278, 327-330, 354-356, 447-453] swallowed-exception high — keyring.errors.KeyringError never caught
 (not OSError/KeyError/ValueError). Fix: import keyring.errors; broaden except tuple to include keyring.errors.KeyringError at all 5 sites; fall
back to env loader for reads, raise CredentialStoreError for writes.
C28. W14 F1 [credentials/store.py:593-598] dead-code medium — ENV_VAR branch unreachable because validate_credentials returns (True, None). Fix:
add real source probe — after validate True, compare os.environ.get(mapping.api_key_var) vs self._env_vars.get(...) to decide ENV_VAR vs ENV_FILE.
 Or add CredentialLoader.get_credential_source(provider) returning enum.
C29. W14 F6 [credentials/store.py:126-143] platform-broken low — _check_keyring writes/reads/deletes a test secret on every construction;
fragments Credential Manager. Fix: replace destructive probe with keyring.get_keyring() class inspection against
WinVaultKeyring/macOSKeychain/SecretService; cache in module-level _KEYRING_STATUS.

=== CREDENTIALS OAUTH + ENV_LOADER (5 findings) ===

C30. W14 F3 [credentials/oauth.py:71-79, 262-276] missing-rpc medium — OAuthProvider enum only has GOOGLE; UI generically builds
OAuthProvider(provider_id) for any ProviderName → ValueError for non-Google. Fix: extend OAuthProvider enum with ANTHROPIC, HUGGINGFACE, OPENAI;
add OAUTH_CONFIGS entries with real authorization_url / token_url / scopes / revoke_url; back client_id/secret with OAUTH_CLIENT_ID_{PROVIDER} env
 convention.
C31. W14 F4 [credentials/oauth.py:160-169, 775-782] happy-path-only medium — needs_refresh (10-min buffer) defined but get_token refreshes only on
 is_expired (5-min). Fix: predicate `token.needs_refresh and auto_refresh and token.refresh_token`; keep is_expired as final gate for returning
None.
C32. W14 F5 [credentials/oauth.py:279-310, 372-388] platform-broken medium — OAuthCallbackHandler stores callback data on class attributes —
global per process, collides between concurrent OAuth flows. Fix: handler factory subclassing BaseHTTPRequestHandler per server instance; state
via self.server.flow_state; or functools.partial closure.
C33. W14 F9 [credentials/oauth.py:852-884] swallowed-exception medium — revoke_token returns True even when HTTP revoke fails (no
raise_for_status) or keyring delete raises KeyringError. Fix: response.raise_for_status() on revoke response; track revoke_ok + delete_ok
separately; return revoke_ok and delete_ok; broaden delete except to include CredentialStoreError and keyring.errors.KeyringError.
C34. W14 F7 [credentials/env_loader.py:402-443] happy-path-only medium — save_to_env_file writes values without quoting; `#`, spaces, newlines,
`"`, `'` break round-trip. Fix: if value contains any whitespace/`#`/quote/`\n`/`=`, wrap in double quotes and escape embedded `"` + `\`; mirror
parser's round-trip contract; reject embedded newlines.

FINAL GATE:
- All 34 addressed.
- ruff/basedpyright/pydoclint/pydocstyle on providers/ and credentials/ → 0.
- No modifications outside providers/, credentials/.

---
---

```
================================================================================
================================================================================

                      G R O U P   E  —  U I  (SHELL + PANELS)
                                (Execute LAST)

================================================================================
================================================================================
```

ROLE: Orchestrator for Group E (entire UI layer + app entry points).

SCOPE:
- src/intellicrack/ui/**
- src/intellicrack/main.py
- src/intellicrack/__main__.py
- src/intellicrack/_metadata.py

OUT OF SCOPE:
- bridges, core, providers, credentials, sandbox, intellicrack-hexcore.

CLAUDE.md STANDARDS: production only, no suppressions, basedpyright clean, Google docstrings, ruff/pydoclint/pydocstyle.

WORKFLOW per finding: read context; apply fix; validate; verify diff; commit per panel or tight cluster.

ORCHESTRATION: For this large group (76 findings across ~60 files), dispatch parallel subagents per panel. Re-verify every returned diff yourself;
 re-run validators; never trust subagent claims.

FINDINGS (76 total):

=== APP SHELL + CHAT + ENTRIES (13 findings) ===

E1. W16 F1 [ui/app.py:1242-1260] disconnected-wiring critical — _on_import_session uses wrong attribute `_session_manager` (actual: `_sessions`)
AND calls async SessionManager.import_json synchronously. Fix: `_sessions` name; invoke via self._run_async(...) with completion callback for
success dialog; show success dialog only on real completion.
E2. W16 F2 [ui/app.py:1225-1241] disconnected-wiring critical — _on_export_session fires QMessageBox.information before AsyncWorker completes.
Fix: move success dialog into worker's finished signal handler; show failure dialog via error signal.
E3. W16 F3 [ui/app.py:1884-1895] signature-drift high — guard reads `_process_attached_wired` (underscore) but sets `process_attached_wired`. Fix:
 rename assignment to `self._process_attached_wired = True`; or use Qt.UniqueConnection.
E4. W16 F4 [ui/chat.py:491-500] happy-path-only high — add_streaming_message finds content QLabel by excluding role-starts-with strings. Fragile.
Fix: expose bubble.content_label public attribute on MessageBubble; use it directly.
E5. W16 F5 [ui/chat.py:248-291] happy-path-only high — hint_text "Type a message..." lives in QTextEdit content; equality check suppresses
submission; user typing "Type a message..." silently swallowed. Fix: use `self._text_edit.setPlaceholderText("Type a message...")`; delete
_hint_text/_show_hint/_clear_hint.
E6. W16 F6 [ui/app.py:1629-1640] hardcoded-return high — _apply_sandbox_settings is no-op; discards dialog output; status line lies. Fix: call
self.sandbox_manager.update_default_config(SandboxConfig(...)) (method depends on Group D adding it — if not yet present on main, tear down active
 sandboxes matching stale selection + rebuild manager).
E7. W16 F7 [ui/app.py:1242-1260] swallowed-exception medium — import_session has no try/except for ValueError (duplicate) or JSONDecodeError. Fix:
 try/except around call; on ValueError show QMessageBox.question offering replace + retry with replace=True; friendly "Invalid session file"
dialog for JSON errors.
E8. W16 F8 [main.py:306-340] platform-broken medium — QApplication(sys.argv) called before any high-DPI policy. Fix: before _QApp(sys.argv), call
`_QApp.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)`; optionally set AA_ShareOpenGLContexts.
E9. W16 F9 [main.py:478-479] hardcoded-return medium — `Path("config.toml")` relative to CWD bypasses get_config_dir(). Fix: `get_config_dir() /
"config.toml"`; add `--config PATH` CLI override.
E10. W16 F10 [main.py:140-152] happy-path-only low — --no-console-log + --no-file-log silently disables all logging. Fix: if both disabled,
sys.stderr.write("Warning: all log output disabled\n").
E11. W16 F11 [ui/app.py:143-156] happy-path-only low — AsyncWorker except filter omits CancelledError → can leak tasks. Fix: before loop.close()
run asyncio.all_tasks(loop=loop) cancel each + gather(return_exceptions=True); broaden except to BaseException excluding SystemExit.
E12. W16 F12 [ui/__init__.py:13-85] dead-code low — ToolConfirmationDialog + PreferencesDialog used via importlib but not in __all__. Fix: static
imports + append to __all__.
E13. W16 F13 [ui/app.py:1766-1778, _metadata.py:16-17] other low — About text + __summary__ narrow scope to "defeating software licensing
protections" conflicting with CLAUDE.md orchestration framing. Fix: rewrite both to "Unified workspace that bridges binary-analysis tools and AI
providers."

=== UI CONFIGURATION DIALOGS (9 findings) ===

E14. W17 F1 [ui/session_manager.py:787-805] disconnected-wiring critical — _save_session_to_disk writes JSON sidecar files that core/session.py
SessionStore never reads. Fix: when _manager provided, route _import_session through run_bridge_coroutine(self._manager.import_json(Path(path)))
and delete through self._manager.delete(session_id). Remove sidecar directory or treat strictly as export artifact.
E15. W17 F2 [ui/sandbox_config.py:684-720] disconnected-wiring critical — dialog writes sandbox.json but SandboxManager has no loader reading that
 file. Fix: call self._manager.update_default_config(SandboxConfig(...)) on save (Group D adds the method); add SandboxManager.load_from_file at
startup in main.py.
E16. W17 F3 [ui/provider_config.py:336-356, 573-605, 1008] missing-rpc critical — Grok listed but _test_provider_connection + _fetch_models have
no "grok" branch → "Unknown provider: grok". Fix: add _test_grok (GET https://api.x.ai/v1/models with Authorization: Bearer <key>) and
_fetch_grok_models; wire into dispatch tables.
E17. W17 F4 [ui/provider_config.py:2330-2345] signature-drift critical — pull_ollama_model calls async-generator provider.pull_model
synchronously; returns unused generator. Fix: rewrite to run via run_bridge_coroutine executing `await provider.connect(...)` then `async for
status in provider.pull_model(model_name)`; forward progress to dialog.
E18. W17 F5 [ui/tool_config.py:100-103] happy-path-only high — x64dbg auto-install URL hardcoded to fake snapshot_2024-01-01_00-00.zip. Fix: GET
https://api.github.com/repos/x64dbg/x64dbg/releases/tags/snapshot; parse assets[].browser_download_url for first *.zip; download that.
E19. W17 F6 [ui/tool_config.py:104-107] happy-path-only high — Cutter URL points at /releases/latest HTML page. Fix: GET
https://api.github.com/repos/rizinorg/cutter/releases/latest; extract assets[].browser_download_url matching current platform
(*Windows-x86_64.zip).
E20. W17 F7 [ui/session_manager.py:866-878, ui/app.py:1139-1165] disconnected-wiring high — NewSessionDialog collects name+description but
orchestrator.start_session never receives them. Fix: capture `name = dialog.get_session_name()` + description; extend orchestrator.start_session
(Group B) to accept name; forward to SessionManager.create(provider, model, name=name). Store description in Session.notes.
E21. W17 F8 [ui/provider_config.py:1666-1745] dead-code medium — XPU memory QTimer starts unconditionally even when is_xpu_available is False;
3-second hot loop forever. Fix: after first _refresh_xpu_memory(), if XPU unavailable call self._xpu_mem_timer.stop() and hide XPU widgets;
otherwise interval 10-30s.
E22. W17 F9 [ui/preferences.py:247-290] happy-path-only medium — font family combo fixed list; findText(-1) clobbers user-set font on save. Fix:
QFontComboBox with setFontFilters(QFontComboBox.FontFilter.MonospacedFonts); or addItem(current) + setCurrentText(current) when findText returns
-1.

=== UI UTILITY SURFACES (8 findings) ===

E23. W18 F1 [ui/tools.py:1625-1664] disconnected-wiring high — panel_registry uses `"_sandbox_panel"` but attribute is `sandbox_panel`. Fix:
rename to `"sandbox_panel"`.
E24. W18 F2 [ui/tools.py:2010-2024] happy-path-only high — get_code_highlighter dereferences None findChild. Fix: `if code_display is None: return
 None`; or traverse current ToolTab and call tab.code_display.get_highlighter().
E25. W18 F3 [ui/win32_embed.py:100-131] platform-broken high — QWindow.fromWinId(voidptr(hwnd)) wrong; fromWinId expects raw int HWND. Fix: pass
hwnd directly (int); coerce foreign window with ctypes.windll.user32.SetWindowLongPtrW(hwnd, GWL_STYLE, WS_CHILD | WS_VISIBLE) + SetParent(hwnd,
int(parent.winId())).
E26. W18 F4 [ui/win32_embed.py:59-97] happy-path-only medium — No argtypes/restype on user32 functions → handles >INT_MAX mis-signed. Fix: set
GetWindowThreadProcessId.argtypes=[wintypes.HWND, POINTER(wintypes.DWORD)]; .restype=wintypes.DWORD; IsWindowVisible, GetWindow, GetWindowTextW,
EnumWindows similarly.
E27. W18 F5 [ui/highlighter.py:249-272, 1053-1076, 1251-1274] happy-path-only medium — C/JS/HexPat highlightBlock state-carry subtly wrong for
comment-close-mid-line. Fix: add explicit setCurrentBlockState(0) at end of successful close-on-same-line path; replace the end_match.hasMatch()
block with explicit state-0 after closed region.
E28. W18 F6 [ui/highlighter.py:275-601] happy-path-only low — AssemblySyntaxHighlighter INSTRUCTIONS lacks SSE/AVX/FPU; no directives; REGISTERS
missing ymm8-15 / zmm0-31 / k0-7. Fix: extend mnemonic + register tuples; add directive rule `^\s*\.(text|data|bss|section|globl?|extern)\b`; add
data-def rule `\b(db|dw|dd|dq|resb|resw|resd|resq)\b`.
E29. W18 F7 [ui/xpu_status.py:258-283] happy-path-only low — `info: object` annotation masks dataclass contract under basedpyright. Fix: `info:
XPUDeviceInfo | None = get_xpu_device_info(0)`; import XPUDeviceInfo from providers.xpu_utils.
E30. W18 F8 [ui/panel_dock.py:128-138, ui/tools.py:1797] happy-path-only low — DetachedPanelWindow.closeEvent always ignores; _reattach_panel
hides but never deleteLater → leak per cycle. Fix: `window.deleteLater()` after `window.hide()` in _reattach_panel. Or accept close when
receivers(reattach_requested) > 0.

=== DISASSEMBLER PANELS (11 findings) ===

E31. W19 F1 [ui/panels/ghidra_panel.py:2564-2580] simulated-output high — _apply_program_info dir() fallback serializes method bound-refs. Fix:
require dict; on non-dict raise error row or use dataclasses.asdict() + is_dataclass guard.
E32. W19 F2 [ui/panels/cutter_panel.py:1040-1048, 1071] happy-path-only medium — address parsing rejects "0X" uppercase. Fix: introduce
_parse_address static helper accepting `0x`/`0X`/decimal/whitespace; apply everywhere.
E33. W19 F3 [ui/panels/ghidra_panel.py:2255-2271] happy-path-only low — _on_create_bookmark allows empty category/comment. Fix:
`self._set_status("Bookmark category required")` when category empty.
E34. W19 F4 [ui/panels/ghidra_panel.py:2027-2082, ui/panels/cutter_panel.py:740-792] dead-code low — _refresh_imports/exports/sections on_error
lambda only logs. Fix: also call _set_status(f"Imports refresh failed: {e}").
E35. W19 F5 [ui/panels/ghidra_panel.py:1672-1679, cutter_panel.py:704-711] happy-path-only medium — _apply_decompiled treats "" same as None;
stale decompilation remains. Fix: `if result is None or not str(result).strip(): setPlainText("// No decompilation available at this address");
return`.
E36. W19 F6 [ui/panels/ghidra_panel.py:3038-3052] signature-drift medium — _on_configure_analysis never passes options dict. Fix: add JSON-text
options editor; parse via json.loads with error status; forward to bridge.configure_analysis(analyzer_name, enabled=enabled, options=parsed).
E37. W19 F7 [ui/panels/ghidra_panel.py:2164-2200, cutter_panel.py:915-951] happy-path-only low — _apply_xrefs_to/_from silently returns on empty.
Fix: replace `if not result: return` with always-append placeholder row `QTreeWidgetItem(["To","—","—","(no callers)"])` when no rows added.
E38. W19 F8 [ui/panels/cutter_tabs.py:94-101 + 9 sibling tabs] happy-path-only high — 10 tabs pass None as error callback; bridge errors silently
swallowed. Fix: shared `_log_error(label)` helper or per-tab lambda `lambda e: _logger.warning("cutter_tab_refresh_failed",
tab=type(self).__name__, error=str(e))` + optional tab-local status banner.
E39. W19 F9 [ui/panels/cutter_tabs.py:829-853] other low — SegmentsTab uses blind getattr on unknown SegmentInfo attribute names. Fix:
define/confirm SegmentInfo dataclass in bridges/cutter.py (Group A responsibility); use typed access.
E40. W19 F10 [ui/panels/cutter_tabs.py:550-558, 637] missing-rpc medium — HexdumpTab + ESILConsoleTab refresh just stashes bridge reference; shows
 empty widget. Fix: HexdumpTab auto-dump from binary entry point (or first executable section) and populate. ESILConsoleTab auto-run `aeim` +
welcome banner.
E41. W19 F11 [ui/panels/ghidra_panel.py:2762-2771] happy-path-only high — _on_load_all_comments no progress/cancel; _apply_comments uses insertRow
 per row freezing UI. Fix: disable button on entry, re-enable on completion; `setUpdatesEnabled(False)` / `setRowCount(len(comments))` batch
populate; status "Loading all comments..." at start.

=== DYNAMIC ANALYSIS PANELS (9 findings) ===

E42. W20 F1 [ui/panels/stack_viewer.py:154-182] missing-rpc critical — X64DbgStackSource.get_stack_frames calls async bridge.get_stack_trace
synchronously via getattr(..., lambda: []); also treats result as list[dict] instead of list[StackFrame]. Fix: use
run_bridge_coroutine(self._bridge.get_stack_trace()) from async_bridge; access StackFrame dataclass attributes (not dict .get).
E43. W20 F2 [ui/panels/stack_viewer.py:227-263] missing-rpc critical — FridaStackSource.get_stack_frames same pattern: async bridge.get_backtrace
called sync; returns SymbolInfo dataclass not dict. Fix: run_bridge_coroutine(self._bridge.get_backtrace()); map
SymbolInfo.address/.name/.module_name to StackFrame.
E44. W20 F3 [ui/panels/stack_viewer.py:184-277] hardcoded-return high — is_connected probes `is_connected()` (doesn't exist on X64DbgBridge) and
`is_attached()` (doesn't exist on FridaBridge). Fix: X64Dbg path use self._bridge.state.is_ready(); Frida path use
self._bridge.state.process_attached. Remove `lambda: False` fallback.
E45. W20 F4 [ui/panels/stack_viewer.py:101-133] signature-drift high — StackDataSource Protocol declares methods @staticmethod but concrete
classes use self. Fix: remove @staticmethod from Protocol; declare as instance methods with self.
E46. W20 F5 [ui/panels/script_manager.py:418-425] hardcoded-return medium — ScriptEditor.set_language body is `_ = language` (no-op). Fix: import
get_highlighter_for_language from intellicrack.ui.highlighter; instantiate attached to self.document(); store on instance attribute.
E47. W20 F6 [ui/panels/script_manager.py:704-731] other medium — _on_save uses name as persistent ID; rename creates duplicates in backend and
list. Fix: on successful add_script, if current_script_id != name remove old list entry + backend delete_script(old_id); add new entry. Or block
name change after first save and add explicit Rename action.
E48. W20 F7 [ui/panels/script_manager.py:824-836] disconnected-wiring medium — Execute button only emits signal; no bridge dispatch, no result
pane, no timeout. Fix: route execution through bridge matching script_type (inject via set_backend); or if owner wires signal, require
acknowledge-signal to update persistent spinner.
E49. W20 F8 [ui/panels/frida_panel.py:606-656] happy-path-only high — persistent-script stop flow: _active_script_id stringified; falsy path falls
 back to unload_all_scripts killing unrelated scripts. Fix: on error in persistent mode reset _stop_btn disabled; preserve exact handle from
bridge (no str()); if handle None after persistent load raise "unable to track script handle" — never fallback to unload_all_scripts.
E50. W20 F9 [ui/panels/frida_panel.py:1045-1063] happy-path-only medium — _on_stalker_stop silently converts invalid thread_id to None, which
unfollows wrong thread. Fix: mirror _on_stalker_start — abort on invalid tid with user-visible message; restore button state; return.

=== HEX EDITOR PANELS (18 findings — systematic UI→hexcore migration) ===

E51. W21 F1 [ui/panels/hex_editor/_sections.py:160-215] missing-rpc high — _populate_strings reimplements ASCII string extraction. Fix: replace
with self.document.extract_strings(min_length=4, include_ascii=True, include_utf16=True, max_results=5000); move call into QThread worker.
E52. W21 F2 [ui/panels/hex_editor/_patches.py:96-140] missing-rpc high — _export_patches hand-crafts IPS records. Fix: dispatch on file extension
to self.document.export_patches_ips()/ips32()/bps(source_data)/ups(source_data); return hexcore bytes verbatim.
E53. W21 F3 [ui/panels/hex_editor/_patches.py:142-207] missing-rpc high — _import_patches hand-parses IPS, skips BPS/UPS. Fix: dispatch on suffix
to self.document.import_patches_ips(bytes) / import_patches_bps(data, source_data) / import_patches_ups(data, source_data); load source via
document.read(0, doc_len) when needed.
E54. W21 F4 [ui/panels/hex_editor/_comparison.py:82-143] missing-rpc high — DiffWorker reimplements byte-diff in Python. Fix: call
hexcore.diff_files(str(self.file_path), compare_path) or route through bridge.compare_files; display returned regions. Delete Python scanner.
E55. W21 F5 [ui/panels/hex_editor/_transforms.py:341-455] missing-rpc high — _run_single_transform uses Python TransformPipeline. Fix:
self.document.transform_data(node.name, offset, length, params); populate _transform_nodes_cache from self.document.list_transforms().
E56. W21 F6 [ui/panels/hex_editor/_transforms.py:609-714] missing-rpc high — block ops (fill/copy/move/swap) do read+write. Fix:
self.document.fill_block(offset, length, list(pattern)); copy_block(src, length, dst); move_block(src, length, dst); swap_blocks(off_a, len_a,
off_b, len_b).
E57. W21 F7 [ui/panels/hex_editor/_data_inspector.py:174-211] missing-rpc medium — bit editor read-modify-write. Fix:
self.document.set_bit(offset, bit_index, checked); refresh via get_bit.
E58. W21 F8 [ui/panels/hex_editor/_data_inspector.py:269-312] missing-rpc medium — text decode uses Python codec. Fix:
self.document.decode_text(cursor_offset, length, encoding); self.document.encode_text_to_bytes(text, encoding); populate combos from
document.list_encodings().
E59. W21 F9 [ui/panels/hex_editor/_hashing.py:47-62, 98-121] missing-rpc medium — reads full file into Python to hash. Fix:
self.document.compute_hash(algo) full-doc; self.document.compute_hash_range(start, end, algo) selection.
E60. W21 F10 [ui/panels/hex_editor/_hashing.py:122-210] missing-rpc medium — PE checksum verify/repair reads full file. Fix:
self.document.verify_pe_checksum() returning dict; self.document.repair_pe_checksum(); delete Python _compute_pe_checksum.
E61. W21 F11 [ui/panels/hex_editor_widget.py:1125-1161, _highlighting.py:186-188] happy-path-only medium — highlight rule pattern-type store
{"pattern": hex} but widget reads {"offsets": set}. Fix: in _on_add_highlight_rule call self.document.search_hex(pattern, max_results) to resolve
offsets; store params={"offsets": {off for off,_ in matches}}. Update rule when document changes.
E62. W21 F12 [ui/panels/hex_editor/_transforms.py:716-812] missing-rpc medium — apply_arithmetic reads+writes in Python. Fix: await
self._bridge.apply_arithmetic_to_selection(op, sel_start, sel_end, key_hex, count); delete duplicate Python _apply_arithmetic_op.
E63. W21 F13 [ui/panels/hex_editor/panel.py:873-899, _data_inspector.py:278, 305] platform-broken medium — encoding combo `lower().replace("-",
"")` produces invalid codec names; EBCDIC has no stdlib codec. Fix: populate combo from hexcore.HexDocument.list_encodings(); pass untransformed
name to decode_text. In _paint_ascii_byte call document.decode_text(offset, bytes_in_row, encoding) per row.
E64. W21 F14 [ui/panels/hex_editor_widget.py:487-514] swallowed-exception medium — set_color_mode caches entropy but never invalidates on document
 change. Fix: _invalidate_color_caches hook connected to data_changed and set_document; log warning on entropy_map failure; lazy recalc in paint.
E65. W21 F15 [ui/panels/hex_editor_widget.py:1284-1310] happy-path-only low — _move_cursor silently clamps out-of-range offset. Fix: validate in
_on_goto_offset before dispatch; display status ("Offset beyond EOF"); or emit status from _move_cursor when new_offset != original.
E66. W21 F16 [ui/panels/hxd_panel.py:192-232] disconnected-wiring medium — hxd_panel claims "process-based embedding" but never reparents HWND.
Fix: on Windows after waitForStarted enumerate child top-level windows of HxD PID via EnumWindows; pick main; QWindow.fromWinId(hwnd) +
createWindowContainer(win, self._embed_host); drive from _embed_timer with _EMBED_MAX_RETRIES. Or clear constants if out of scope.
E67. W21 F17 [ui/panels/hex_editor/_scripting.py:546-571] happy-path-only medium — "sandbox" pops __import__/open but leaves getattr — trivial
jailbreak. Fix: use RestrictedPython.compile_restricted + AST whitelist forbidding attribute chains reaching __class__/__mro__/__subclasses__.
Gate doc.write/insert/delete on confirmation dialog or read-only mode.
E68. W21 F18 [ui/panels/hex_editor/_search.py:365-372, 612-619] swallowed-exception low — dead except around highlight_offsets call; hides real
regressions. Fix: drop try/except; let failures surface to search-error path.

=== PROCESS + SANDBOX + MISC PANELS (8 findings) ===

E69. W22 F1 [ui/panels/vnc_widget.py:170-184] happy-path-only high — VNC auth echoes challenge verbatim; real RFB6143 requires DES
mirror-bit-reversed key encryption. Fix: add password param to RFBClient.connect + VNCWidget.connect_to_server; implement DES encryption of
16-byte challenge with bit-reversed 8-byte key (cryptography.hazmat.primitives.ciphers DES ECB); transmit ciphertext. Or drop _SECURITY_VNC
entirely if only _SECURITY_NONE needed (QEMU/WSB).
E70. W22 F2 [ui/panels/vnc_widget.py:328-360] happy-path-only high — raw rect decoder O(w·h) QColor + setPixelColor. Fix: bulk blit via
QImage.scanLine(y) per row with struct.unpack_from/memcpy; or sub-rectangle QImage.fromData(raw, Format_RGB32) + QPainter.drawImage at (x,y).
Consider supporting CopyRect/Hextile/ZRLE.
E71. W22 F3 [ui/panels/vnc_widget.py:528-542, 606-678] happy-path-only high — _on_update_tick + mouseMoveEvent + key events all call blocking
run_bridge_coroutine on Qt thread. Fix: convert user-event sends to run_bridge_coroutine_async (fire-and-forget). For tick, start long-lived
background asyncio.Task in bridge loop pumping request_framebuffer_update + handle_server_message; emit Qt signal when framebuffer mutates.
E72. W22 F4 [ui/panels/sandbox_panel.py:318-320, 1629] disconnected-wiring medium — Instances tab never populated. Fix: extend
_on_poll_status_success to inspect result.get("instances") and repopulate _instances_tree each tick; key rows by instance_id for incremental
update.
E73. W22 F5 [ui/panels/process_panel/_threads_tab.py:135-144, 375-385] signature-drift medium — Suspend/Resume Selected buttons ignore thread
selection, operate on whole process. Fix: either (a) add ProcessBridge.suspend_thread(tid)/resume_thread(tid) wrapping SuspendThread/ResumeThread
(Group A scope — coordinate), or (b) relabel buttons "Suspend/Resume Process" and move to ProcessTab.
E74. W22 F6 [ui/panels/process_panel/_system_tab.py:94-102, 591-608] disconnected-wiring medium — SystemTab.update_thread_list never called; TEB
combobox always empty. Fix: in ThreadsTab._refresh_threads (or ProcessPanel _base) also call self._system_tab.update_thread_list(result). Or on
_on_read_teb fetch via bridge and show thread picker.
E75. W22 F7 [ui/panels/sandbox_panel.py:910-914] simulated-output low — snapshot row hardcodes "now" and "manual_snapshot". Fix:
datetime.now(tz=timezone.utc).isoformat() at row creation; capture user name via QInputDialog.getText before snapshot_create; surface bridge's
created_at field if returned.
E76. W22 F8 [ui/panels/async_bridge.py:59-80] other low — _ensure_loop race between thread.start() and loop.run_forever(); two loops can be
created under parallel panel construction. Fix: threading.Event sentinel; _run_loop calls event.set() as first line after set_event_loop;
_ensure_loop event.wait(timeout=2.0) before returning. Or check `_state.loop is not None` only (not is_running) inside lock.

FINAL GATE:
- All 76 addressed.
- ruff / basedpyright / pydoclint / pydocstyle on ui/, main.py, __main__.py, _metadata.py → 0.
- No files outside UI scope modified.
- Smoke-launch the GUI locally to confirm no regressions in window/panel construction.

---
---

## Totals

| Group | Findings |
|-------|----------|
| F — Rust hexcore | 23 |
| B — Core + Hexpat | 55 |
| A — Bridges | 77 |
| D — Sandbox | 19 |
| C — Providers + Credentials | 34 |
| E — UI | 76 |
| **Total** | **284** |
