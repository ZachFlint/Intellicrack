# Shard 20 — hex editor sub-module forest

- **Files audited**: 19
- **Total LOC**: 7660
- **Generated**: 2026-05-22T22:54:56Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 17    |
| MEDIUM   | 31    |
| LOW      | 14    |

- Files missing module-level `_logger`: 2 (`_bookmarks.py`, `_calculator.py`)
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0 (note: `_base.py` imports `contextlib` but only uses `contextlib.closing` to close an mmap — this is NOT `contextlib.suppress`, so does not violate §3.3)
- Files with bare `except` (no log): 17 (counted at file level — see findings)

## Findings by file

### src/intellicrack/ui/panels/hex_editor/_base.py — LOC 730

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L663-664 — `except (ValueError, TypeError, OSError, RuntimeError, ImportError) as exc:` in `compute_hash()` returns formatted error string with no log call. The exception details are surfaced to the user via return value but lost from observability. Fix: add `_logger.exception("compute_hash_failed", algo=algo)` before returning.
- [LOW] L172-175 — `format_size()` uses f-strings inside `return` statements; these are display strings (not log calls), so acceptable. No finding required; noted for completeness.

### src/intellicrack/ui/panels/hex_editor/_widgets.py — LOC 728

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L447-449 — `except ValueError as exc:` in `_calculate()` silently sets error label without logging. Fix: add `_logger.warning("custom_crc_invalid_input", error=str(exc))` before the early return.
- [LOW] L497 — `_logger.warning("custom_crc_worker_failed", ...)` uses `.warning()` for an exception path where the exception object is provided. Although TRY400 may flag the opposite, here `_logger.exception(...)` would preserve the traceback; consider whether `.warning()` is correct given no re-raise. Marked LOW since the error_type and error kwargs are present.

### src/intellicrack/ui/panels/hex_editor/_pattern_editor.py — LOC 701

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L460-490 — `_on_pattern_save()` performs `Path.write_text()` (file write per §2.3). The success path logs `"pattern_saved"` at L494 but there is no pre-write log indicating the path/size of the write. Add `_logger.info("pattern_save_begin", path=str(path))` before the write.
- [MEDIUM] L496-529 — `_on_pattern_open()` performs `Path.read_text()` of a user-selected file (operationally significant read per §2.3). Add a pre-read `_logger.info("pattern_open_begin", path=str(path))`; only post-read log exists.
- [LOW] L583-606 — `_load_hexpat_from_library()` also reads a user-specified file via `Path.read_text()` without a pre-read log; only logs on failure.

### src/intellicrack/ui/panels/hex_editor/_search.py — LOC 623

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L545-548 — `except ValueError as exc:` in `_on_numeric_search()` shows a QMessageBox but does NOT log. Per §2.2, every except block needs a log call. Fix: add `_logger.warning("numeric_search_invalid_input", error=str(exc))` before `QMessageBox.warning`.
- [MEDIUM] L244-279 — `_on_search()` dispatches a worker (real work via FFI `search_hex/search_text/search_regex`) but logs neither entry (intent) nor a "search_started" marker. Only the result is logged at L321.
- [MEDIUM] L492-571 — `_on_numeric_search()` similarly omits an entry log; only the result is logged at L611.
- [LOW] L621 — `_logger.warning("numeric_search_failed")` has no context kwargs (no error type, no error message); `exc` is in scope.

### src/intellicrack/ui/panels/hex_editor/_signatures.py — LOC 620

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L527-553 — `_on_scan_signatures()` starts a `GenericCallableWorker` that runs `execute_signature_scan_from_source()` against a database file selected by the user. No "sig_scan_started" entry log; only completion (`sig_scan_complete` at L594) and failure (`sig_scan_failed` at L602) are logged.
- [MEDIUM] L169 — `_scan_die()` performs `Path(db_path).read_text()` (file read of operationally-significant user-selected DB) with no surrounding log.
- [MEDIUM] L259 — `_scan_clamav()` performs `db_file.read_text()` (file read) with no surrounding log.
- [MEDIUM] L386 — `_scan_custom()` performs `Path(db_path).read_text()` (file read) with no surrounding log.
- [LOW] L51-52 — `read_file_for_scan()` performs mmap read of user-supplied file (operationally significant) without log; acceptable since caller's worker context may log, but a single debug-level entry would help trace.

### src/intellicrack/ui/panels/hex_editor/_templates.py — LOC 591

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L377-378 — `except (AttributeError, ValueError):` in `_on_auto_bookmark_structure()` silently `return`s without logging. Fix: `_logger.exception("auto_bookmark_magic_read_failed")` before return.
- [HIGH] L419-420 — `except (AttributeError, ValueError):` in `_bookmark_pe_structure()` (DOS header read) silently returns. Fix: add `_logger.exception("pe_dos_read_failed")`.
- [HIGH] L439-440 — `except (AttributeError, ValueError):` in `_bookmark_pe_structure()` (COFF header read) silently returns. Fix: add `_logger.exception("pe_coff_read_failed", e_lfanew=e_lfanew)`.
- [HIGH] L489-490 — `except (AttributeError, ValueError):` in `_bookmark_pe_sections()` (section read) silently sets fallback name. Fix: add `_logger.exception("pe_section_read_failed", section_index=i)` before the fallback assignment.
- [HIGH] L513-514 — `except (AttributeError, ValueError):` in `_bookmark_elf_structure()` (EI_CLASS read) silently returns. Fix: add `_logger.exception("elf_ident_read_failed")`.
- [HIGH] L529-530 — `except (AttributeError, ValueError):` in 64-bit ELF header read silently returns. Fix: add `_logger.exception("elf64_header_read_failed")`.
- [HIGH] L545-546 — `except (AttributeError, ValueError):` in ELF program/section header counts read silently returns. Fix: add `_logger.exception("elf64_counts_read_failed")`.
- [HIGH] L561-562 — `except (AttributeError, ValueError):` in 32-bit ELF header read silently returns. Fix: add `_logger.exception("elf32_header_read_failed")`.
- [MEDIUM] L335-336 — `Path(save_path).write_text(json_str, ...)` in `_on_export_template()` is logged with `file_written` at L335 but ordering shows the log occurs BEFORE the write. If the write throws, the log already says success. Move the success log to after the write succeeds (the `except` already logs failure). The existing template_exported at L341 is also there, so this is only a minor ordering nit — marked MEDIUM.

### src/intellicrack/ui/panels/hex_editor/_highlighting.py — LOC 527

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- Findings: none material. Bridge calls (L240-245, L287-292) properly route through `run_bridge_coroutine_async` with success/error callbacks that log; pattern resolution (L188-192) logs on failure; widget rule application (L349-350, L384-385) logs on failure. All except blocks log. This is the cleanest file in the shard.

### src/intellicrack/ui/panels/hex_editor/_sections.py — LOC 455

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L389-392 — `except ValueError: pass` in `_on_string_double_clicked()` silently swallows the parse error. Fix: replace `pass` with `_logger.warning("string_offset_parse_failed", offset_text=offset_text)`.
- [MEDIUM] L298-325 — `_populate_strings()` starts a `GenericCallableWorker` for `execute_strings_extraction()` (a bridge to hexcore extract_strings) with no entry log indicating intent / parameters. Add `_logger.info("strings_extract_started", min_length=_STRINGS_MIN_LENGTH, max_results=_STRINGS_MAX_RESULTS)`.
- [LOW] L121, L127 — `goto_offset()` and `_select_template()` are declared as Protocol-style stubs with empty bodies in this mixin; they appear here for typing only. Not a finding, just noted.

### src/intellicrack/ui/panels/hex_editor/_statistics.py — LOC 422

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L200-232 — `_update_statistics()` launches a worker but has no entry-level info log indicating the document length / block size. Has a `warning` at L211 for skip-because-running, but no "statistics_update_started" event for the successful start. Coverage at completion (L282) and skip (L211) is present.

### src/intellicrack/ui/panels/hex_editor/_process_memory.py — LOC 391

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [MEDIUM] L162-202 — `_list_regions_ctypes()` performs direct Win32 API calls via `ctypes.windll.kernel32`: `OpenProcess` (L167), `VirtualQueryEx` (L180), `CloseHandle` (L197). Per §2.3 these are Registry/Win32 calls that must have surrounding logs. There is an `except` log at L202 but no PRE-call log (`_logger.info("ctypes_openprocess", pid=pid, access=...)`) and no post-call success log. Currently only `process_regions_hexcore_failed` (L149) and `process_regions_ctypes_failed` (L202) exist, both error-path only.
- [MEDIUM] L131-154 — `_on_list_regions()` is a public-style handler doing real work (hexcore RPC + Win32/procfs scan dispatch) but has no entry log indicating which PID is being queried; only the failure path on L149 captures the PID.
- [MEDIUM] L204-241 — `_list_regions_procfs()` performs `maps_path.read_text()` on `/proc/{pid}/maps` (operationally significant read) without a pre-read log. Error path logged at L237.
- [LOW] L268-274 — `_on_open_region()` `except ValueError` properly logs at L273; OK. No finding.

### src/intellicrack/ui/panels/hex_editor/_data_inspector.py — LOC 380

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L327-330 — `except (AttributeError, TypeError, ValueError):` in `_on_decode_text()` silently sets `doc_len = 0`. No log. Fix: `_logger.warning("decode_text_doc_length_unavailable")` before assignment.
- [HIGH] L337-342 — `except (AttributeError, ValueError, OverflowError) as exc:` sets the output text field but does NOT log. Fix: add `_logger.warning("decode_text_failed", encoding=encoding, length=length, error=str(exc))` before setting label.
- [HIGH] L370-373 — `except (...) as exc:` in `_on_encode_text()` uses `_logger.warning("encode_text_bridge_failed", encoding=encoding)` — context is partial (no `error=str(exc)` kwarg, no traceback). Per §3 #6, `_logger.exception(...)` should be used to preserve the traceback. Marked HIGH because `error=str(exc)` is missing and the exception is in scope.
- [MEDIUM] L310-342 — `_on_decode_text()` makes a real bridge-equivalent call (`document.decode_text`) with no entry log.
- [MEDIUM] L344-380 — `_on_encode_text()` makes a real bridge call (`bridge.encode_text` via `run_bridge_coroutine`) with no pre-call info log; only post-failure warning.
- [LOW] L329-330 — fallback `doc_len = 0` should at minimum be `debug` logged.

### src/intellicrack/ui/panels/hex_editor/_disassembly.py — LOC 355

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L350-353 — `except ValueError: pass` in `_on_disasm_row_double_clicked()` silently swallows the parse error. Fix: replace `pass` with `_logger.warning("disasm_addr_parse_failed", addr_text=addr_text)`.
- [LOW] L248-251 — inner `except (TypeError, ValueError): address_int = 0` silently falls through with 0; the address is then displayed in the table. Acceptable as a defensive fallback, but a debug log would help trace bridge result drift. Marked LOW.

### src/intellicrack/ui/panels/hex_editor/_sandbox.py — LOC 291

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- Findings: none material. Per the recent commit `e55a4f38` (forward timeout to SandboxBridge.copy_to) the bridge invocation flow logs entry (`sandbox_save_dispatched` L164 with instance_id / source / dest), completion (`sandbox_operation_complete` L277), and failure (`sandbox_operation_failed` L291). `_copy_to_with_timeout()` properly wraps the bridge call under `asyncio.timeout`. `_on_test_in_sandbox` similarly logs `sandbox_test_dispatched` at L237. Logging coverage around the `SandboxBridge.copy_to` and `bridge.execute` calls satisfies §2.3.

### src/intellicrack/ui/panels/hex_editor/_hashing.py — LOC 282

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L96-97 — `except (OSError, RuntimeError, ValueError):` in `_resolve_custom_crc_file_path()` sets `doc_path = None` silently. Fix: `_logger.debug("custom_crc_doc_path_unavailable", error_type=...)` before assignment.
- [HIGH] L113-115 — `except OSError: continue` silently skips a candidate. Fix: `_logger.debug("custom_crc_candidate_unreadable", path=path_str)` before continue.
- [HIGH] L143-146 — `except (RuntimeError, OSError, ValueError, AttributeError) as exc:` in `_on_custom_crc()` shows a QMessageBox but does NOT log. Add `_logger.warning("custom_crc_length_unavailable", error=str(exc))`.
- [HIGH] L264-265 — `except (RuntimeError, OSError, ValueError, AttributeError) as exc:` in `_on_repair_pe_checksum()` (post-repair verify path) silently updates label without logging. Add `_logger.warning("pe_checksum_post_repair_verify_failed", error=str(exc))`.
- [MEDIUM] L188-195 — `_on_hash_selection()` successful path (else branch L192-195) does NOT log success, unlike `_on_calculate_hash()` (which logs `hash_calculated` at L130). Add `_logger.info("hash_selection_calculated", algo=algo, start=sel_start, end=sel_end)`.

### src/intellicrack/ui/panels/hex_editor/_yara.py — LOC 278

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L273-276 — `except ValueError: pass` in `_on_yara_result_double_clicked()` silently swallows parse error. Fix: replace `pass` with `_logger.warning("yara_offset_parse_failed", offset_text=offset_text)`.
- [HIGH] L197-200 — inner `except (TypeError, ValueError): continue` silently skips an entry without logging. Fix: `_logger.debug("yara_match_offset_unparseable")` before continue.
- [MEDIUM] L126-167 — `_on_yara_scan()` makes bridge calls (`bridge.yara_scan(inline_source)` at L153 OR `bridge.yara_scan_files(rule_paths_arg)` at L163) with no entry log. Only the result/error callbacks log. Add `_logger.info("yara_scan_dispatched", source_mode="inline"|"files", rule_count=...)`.

### src/intellicrack/ui/panels/hex_editor/_patches.py — LOC 269

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- Findings: none material. Bridge calls (`bridge.export_patches`, `bridge.import_patches`) have surround logging: pre-write `patches_export_write_begin` (L182-188 with size + sha256), success `patches_exported` (L196-202), failure on bridge (L166), failure on b64 decode (L178), failure on write (L192), unexpected payload type (L171), import_b64 unexpected_type (L259), import success (L268). All except blocks log. Coverage exemplary.

### src/intellicrack/ui/panels/hex_editor/_comparison.py — LOC 265

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L194-195 — `except FileNotFoundError: pass` in `_cleanup_diff_temp()` is a defensible idempotent cleanup; not flagged. A `_logger.debug("diff_temp_already_gone")` would help observability but is not required.
- [MEDIUM] L150-156 — `tempfile.NamedTemporaryFile(prefix="intellicrack_diff_", delete=False)` creates a temp file then `tmp.write(data_a)` (file-write per §2.3). Error path logged at L155 (`diff_temp_write_failed`) but no pre-write info log; the write size and path would be useful diagnostics. Add `_logger.info("diff_temp_write_begin", size=len(data_a))` before the with-block.
- [LOW] L111-166 — `_on_compare()` is a public-style handler that performs significant work (potentially reads the entire document, writes a tempfile, dispatches a worker) but logs only `diff_bridge_unavailable` at L118. Consider adding an entry log when the worker is actually started.

### src/intellicrack/ui/panels/hex_editor/_calculator.py — LOC 241

**Logger status**: `missing`

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**:

- [HIGH] L1-242 — No module-level `_logger`. The module has no `from intellicrack.core.logging import get_logger` import. Per §3 #5, missing `_logger` is HIGH severity when the module has any operations that should be logged. This file has several silent `except` blocks (see below) where logging IS warranted.
- [MEDIUM] L106-112 — `except ValueError as exc:` in `_on_convert()` adds the error to a tree widget but cannot log because no `_logger` is defined. Once `_logger` is introduced, add `_logger.debug("calc_input_parse_failed", text=text, error=str(exc))`.
- [MEDIUM] L140-141 — `except (struct.error, OverflowError):` silently sets "overflow" in the table; no log. Need `_logger.debug("calc_int_overflow", label=label, value=value)` once logger exists.
- [MEDIUM] L150-151 — `except (struct.error, OverflowError):` silently sets "N/A". Need `_logger.debug("calc_float_pack_failed", label=label)`.
- [LOW] L226-227, L240-241 — `except struct.error:` silently sets "N/A" in the IEEE 754 display labels. Pure UI; LOW severity.

Note: this file is intentionally pure (computational, deterministic, no external I/O). The HIGH for missing logger stands because the module silently swallows exceptions; the severity could be argued down if the maintainer chooses to keep this file logger-free and the except branches are considered defensive UI fallbacks.

### src/intellicrack/ui/panels/hex_editor/_bookmarks.py — LOC 112

**Logger status**: `missing`

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**:

- [HIGH] L1-113 — No module-level `_logger`. No `get_logger` import. Per §3 #5, this is HIGH because the module has document-mutation operations (`document.add_bookmark`, `document.remove_bookmark`, `document.list_bookmarks`) that are state mutations per §2.4.
- [HIGH] L74 — `self.document.add_bookmark(cursor_offset, 1, name, color.name())` is a document state mutation with NO logging (entry or exit) and NO try/except. Per §2.4 every state mutation must be logged. Fix: wrap in try/except, log `_logger.info("bookmark_added", offset=cursor_offset, name=name, color=color.name())`.
- [HIGH] L96 — `self.document.remove_bookmark(index)` is a state mutation with NO logging. Fix: log `_logger.info("bookmark_removed", index=index, offset=bm_offset, length=bm_length)`.
- [HIGH] L89, L106 — `self.document.list_bookmarks()` is a bridge/document call with NO logging and NO exception handling. If the document throws, the panel crashes silently. Wrap and log.
- [MEDIUM] L51-76 — `_on_add_bookmark()` is a public-style handler doing real work (cursor read + user prompts + document mutation + state-holder notify + tree refresh) with no entry/exit logging.
- [MEDIUM] L78-98 — `_on_remove_bookmark()` similarly has no entry/exit logging.
- [MEDIUM] L100-112 — `_refresh_bookmarks()` calls `self.document.list_bookmarks()` (a bridge call) without logging.

## Aggregate notes

- **Two files entirely lack `_logger`**: `_bookmarks.py` (112 LOC, high-impact — handles document mutations) and `_calculator.py` (241 LOC, lower-impact — pure computational). Both should add `from intellicrack.core.logging import get_logger` and `_logger = get_logger(__name__)` at module level.

- **Recurring anti-pattern: "except → return"** silently swallows errors throughout `_templates.py` (8 instances), `_disassembly.py`, `_yara.py`, `_sections.py`, `_data_inspector.py`, `_hashing.py`. These are all in the form `except (AttributeError, ValueError): return` (or `pass`) for document.read fallbacks. While defensive, every one of them needs a `_logger.exception(...)` or `_logger.debug(...)` call before the early return, per §2.2.

- **Recurring anti-pattern: missing pre-call (entry) logs around bridge invocations.** Many `_on_*` handlers dispatch to bridge coroutines / GenericCallableWorker without logging the dispatch intent. The success and failure callbacks log, but the dispatch itself is invisible. Examples: `_on_search`, `_on_numeric_search`, `_on_scan_signatures`, `_on_yara_scan`, `_on_decode_text`, `_on_encode_text`, `_populate_strings`. Best-in-class examples in this shard that DO log dispatch: `_on_save_to_sandbox` (`sandbox_save_dispatched`), `_on_test_in_sandbox` (`sandbox_test_dispatched`), `_on_open_process_memory` (`process_memory_dispatch`), `_on_disassemble` (`disasm_invoke`), and the entire `_patches.py` flow. The shard would benefit from a consistent "dispatched" event per bridge call.

- **Recurring pattern: `except ValueError: pass` in `_on_*_double_clicked` handlers** for parsing the displayed hex offset back to int. Found in: `_yara.py` L275, `_disassembly.py` L352, `_sections.py` L391. All three should be replaced with a `_logger.warning("offset_parse_failed", offset_text=...)` log call.

- **Exemplary files**: `_highlighting.py`, `_patches.py`, and `_sandbox.py` (after commit `e55a4f38`) are well-instrumented and demonstrate the pattern the rest of the shard should converge on: bridge call dispatch is logged with relevant kwargs, every except path logs, and success paths emit a structured event with result-summary kwargs (count, size, hash, etc.).

- **No stdlib `logging` usage, no `contextlib.suppress`, no `print(...)` runtime output, no `# noqa`/`# type: ignore`/`# pyright: ignore` suppressions** detected anywhere in the shard. The canonical structlog wrapper is used consistently in the 17 files that DO have `_logger`.

- **Win32 surface in `_process_memory.py`**: this file is the only place in the shard that exercises ctypes/Win32 APIs directly. Pre-call logging around `OpenProcess`, `VirtualQueryEx`, and `CloseHandle` would bring it in line with §2.3's "external call must be logged" rule.
