# Shard 01 — Bridges: hex editor

- **Files audited**: 1
- **Total LOC**: 8842
- **Generated**: 2026-05-22

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 0     |
| MEDIUM   | 14    |
| LOW      | 9     |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 0

## Findings by file

### src/intellicrack/bridges/hex_editor.py — LOC 8842

**Logger status**: `module-level _logger`

**Imports `from intellicrack.core.logging import get_logger`**: yes (L48; `_logger = get_logger(__name__)` at L167)

**Findings**:

#### Coverage gaps (MEDIUM)

- [MEDIUM] L1726-1777 — public method `open_file()` performs a significant external file open via `_hexcore_mod.HexDocument.open(path)` (L1752) and replaces the active document. Has exit log at L1768 (`file_opened`) but no entry log for the `open_file_started` operation (`open_file_closing_previous_document` at L1749 only fires in the close-prior branch). Add `_logger.info("open_file_started", path=path)` near the top so the start of every file-open attempt is observable, especially since `_hexcore_mod.HexDocument.open` can raise.

- [MEDIUM] L2917-2963 — public method `save()` performs a significant file-write via `self.document.save(saved_path)` (L2942/L2947). Only has exit log at L2960 (`file_saved`). Missing entry log such as `_logger.info("save_started", path=path)` before the write so the intent is recorded prior to the I/O.

- [MEDIUM] L3161-3259 — public method `save_to_sandbox()` is a bridge-to-bridge invocation (it calls into the sandbox bridge through `tool_registry.get(ToolName.SANDBOX)`, then `create`/`copy_to`/`destroy`). Per §2.3, bridge invocations require log statements before AND after each external bridge call. The bridge-to-bridge `create_fn`/`copy_fn`/`destroy_fn` invocations at L3215-3217, L3225-3232, L3240-3242 have no surrounding `_logger.info(...)`/`_logger.debug(...)` calls describing the bridge-call intent. Final completion log at L3258 exists. Add entry log at start (`save_to_sandbox_started`) and per bridge-call hops.

- [MEDIUM] L3197-3203 — inside `save_to_sandbox`, `self.document.save(tmp_path)` is a significant file-write to a tempfile created on L3200 (`tempfile.mkstemp`); both the temp-file creation and the document save are unlogged. Add a `_logger.info("save_to_sandbox_temp_saved", tmp_path=tmp_path)` or similar before/after the save.

- [MEDIUM] L3261-3333 — public method `test_in_sandbox()` is a bridge-to-bridge invocation (calls sandbox bridge's `run_binary`). Only has exit log at L3326 (`sandbox_test_completed`). Missing entry log such as `_logger.info("sandbox_test_started", binary_path=file_path_str, sandbox_type=sandbox_type, time_limit=time_limit, args=args)` before the cross-bridge call at L3311-3324.

- [MEDIUM] L5128-5156 — public method `list_process_regions()` performs a Win32 process-region enumeration via `_hexcore_mod.HexDocument.list_process_memory_regions(pid)` at L5154 (covered by §2.3 "Process attachment / debugging"). Only has debug exit log at L5155. Missing entry log such as `_logger.info("list_process_regions_started", pid=pid)`; given the Windows-API nature of the call, entry/exit should both be info-level for operator visibility.

- [MEDIUM] L5158-5213 — public method `open_process_memory()` attaches a hex document to a process memory region (§2.3 "Process attachment / debugging"). Only logs exit at L5206 (`process_memory_opened`). Missing entry log such as `_logger.info("open_process_memory_started", pid=pid, address=hex(address), size=size)` before the native call at L5199.

- [MEDIUM] L6754-6800 — public method `export_annotated_pdf()` orchestrates a significant file write to `output_path` (the PDF is written to disk in `_generate_pdf` via `pdf.output(output_path)` at L8765). The bridge has only a debug exit log at L6799 (`annotated_pdf_exported`) and no entry log. For a file-write operation this should be `_logger.info("export_annotated_pdf_started", output_path=output_path, start=actual_start, end=actual_end)` at entry, with the exit log promoted to info-level since it is a successful significant state mutation.

- [MEDIUM] L8698-8766 — module-level helper `_generate_pdf()` calls `pdf.output(output_path)` at L8765, which writes a PDF file to disk. No log surrounding the write call. Per §2.3, file-write operations must be logged before and after.

- [MEDIUM] L7311-7407 — public method `scan_die_signatures()` reads a user-provided DB file via `Path(db_path).read_text(...)` at L7360 (an operationally significant configuration/signature read on a user-supplied path). Has exit log at L7406 but no entry log. Add `_logger.info("scan_die_started", db_path=db_path)` before the file read.

- [MEDIUM] L7520-7567 — public method `scan_clamav_signatures()` reads a user-provided DB file via `path.read_text(...)` at L7549 (operationally significant signature DB read). No entry log present. The children `_scan_clamav_hdb`/`_scan_clamav_ndb` log only at completion. Add `_logger.info("scan_clamav_started", db_path=str(path), suffix=suffix)` near the top.

- [MEDIUM] L7744-7815 — public method `scan_custom_signatures()` reads a user-supplied JSON signature file via `Path(sig_file).read_text(...)` at L7761. Only exits with `custom_sig_scan_completed` log at L7814. No entry log such as `_logger.info("scan_custom_signatures_started", sig_file=sig_file)`.

- [MEDIUM] L4641-4655 — `_resolve_patch_source()` (private helper but on a user-supplied `original_path`) reads the file via `Path(original_path).read_bytes` at L4655. The caller `import_patches` (L4574 onward) logs `import_patches_started`, but the file-read side-effect itself is invisible. Either log inside `_resolve_patch_source` or at the call sites L4606/L4618 where `await self._resolve_patch_source(original_path)` is invoked.

- [MEDIUM] L7960-7992 / L8080-8112 — public methods `import_patches_bps()` and `import_patches_ups()` both read user-supplied source files via `Path(original_path).read_bytes` at L7979 and L8099 respectively, with no log before the read. Exit logs exist (`bps_patch_imported` / `ups_patch_imported`). Add entry logs documenting the source-file read intent.

#### Style / context (LOW)

- [LOW] L450-457 — `set_state_holder()` logs `"set_state_holder_started"` but does not log on completion. The state mutation (binding a shared state holder) is recorded at intent only; either drop the `_started` suffix (since there is no `_completed` counterpart) or add the completion log. Same observation for `set_tool_registry()` at L459-466.

- [LOW] L1709-1724 — `shutdown()` logs only `_logger.info("hex_editor_shutdown")` at L1723 without context kwargs even though `self.document` (was-it-open) and selection state are in scope. Add `had_document=self.document is not None` style kwargs before clearing for diagnostic value.

- [LOW] L2613-2632 — `list_hexpat_patterns()`: exit log at L2631 (`hexpat_patterns_listed`) lacks context for what registry was queried; no entry log. Minor.

- [LOW] L2456 — `_get_pattern_registry()` raises after `_logger.error("get_pattern_registry_failed_unavailable")`. Lazy logger usage inside a function is acceptable here (consistent with pattern), but the event name does not match the project's convention used elsewhere where errors include a `_failed` suffix and a context kwarg. Style nit only.

- [LOW] L5510 — `arithmetic_applied` info log uses `op=operation` which is fine, but the preceding `_logger.info("file_written", ...)` at L5494 and L5507 use `op=operation` while operation name should also be in entry log. The entry log for `apply_arithmetic` is implicit through the `file_written` event — no explicit `arithmetic_apply_started` at entry. LOW because the operation is mostly traceable from `file_written`.

- [LOW] L5856-5859, L5976-5977, L6038-6039 — three large `except` blocks log via `_logger.warning("..._failed", error=str(exc))` rather than `_logger.exception(...)`. The traceback is dropped. Project memory notes TRY400 can be in tension with re-raise patterns, but these are non-re-raising `except` blocks (they return `[]`). Per §3 item 6 these should be `.exception()` so the traceback is preserved. Marked LOW because the error string is captured; tracebacks would aid debugging native binary parse failures.

- [LOW] L3945, L3995, L4007, L4057, L4081 — same pattern as above (`_logger.warning(..._failed, error=str(exc))` inside an `except` block that returns instead of re-raising). Tracebacks lost. Convert to `_logger.exception(...)` per §3 item 6. LOW.

- [LOW] L6382, L6482, L6610 — three `_logger.warning` inside `except` blocks that return an empty list (rollback path); traceback context lost. Convert to `.exception(...)`. LOW.

- [LOW] L6155-6196 — `extract_strings()` has a `_logger.debug("strings_extracted", count=len(raw_strings), backend="rust")` log on the native path at L6162 but no equivalent log on the pure-Python fallback path that follows at L6188-6195. Operators cannot distinguish which backend produced the result. Add a symmetric log at the fallback exit.

#### Notes on patterns I deliberately did NOT flag

- The seven module-level `try/except (ImportError, OSError)` import blocks (L172-247) all correctly log at debug level on failure. These guard optional dependencies and are not coverage gaps.
- `inspect_at_failed` at L3116, `clamav_hdb_invalid_size` at L7598, `clamav_ndb_invalid_offset` at L7668, `clamav_ndb_pattern_truncated` at L7722, `clamav_ndb_pattern_bad_hex` at L7732, `clamav_ndb_pattern_regex_error` at L7740, `custom_signature_invalid_hex` at L7775, `custom_signature_invalid_offset` at L7802, `die_pattern_invalid_hex` at L7438, `die_pattern_invalid_offset` at L7467, `transform_param_not_hex` at L4137, `search_numeric_range_unpack_failed` at L4967, `bookmark_rollback_failed` at L6507, `base_convert_float_unpack_failed` at L7155, `tmp_file_cleanup_failed` at L3256 — all are `except` blocks that log appropriately and continue / return. Not flagged.
- `compile_pattern_syntax_error` at L2404, `scan_die_db_invalid_json` at L7364, `save_to_sandbox_failed_to_destroy_orphan_instance` at L3248, `import_patches_ips_native_failed`/`import_patches_ips_python_failed`/`import_patches_bps_failed`/`import_patches_ups_failed` at L4595/4602/4610/4622, `export_annotated_pdf_fpdf_missing` at L8729 — all use `_logger.exception(...)` (preserves traceback) and re-raise. Correct.
- The bridge does not use stdlib `logging`, `print`, `contextlib.suppress`, f-string-formatted log messages, `% formatting`, `.format()` in log messages, `# noqa`, or `# type: ignore`. None of those HIGH-severity patterns are present.
- `contextlib` is imported (L15) but only used at L7879 as `@contextlib.contextmanager`. Not a `contextlib.suppress` violation.

## Aggregate notes

- The file is unusually well-instrumented for its size (8842 LOC). The module-level `_logger` is established correctly, every observed `except` clause has an accompanying log call, and there are no stdlib-logging, `print`, `contextlib.suppress`, or string-formatting violations in log calls. The author has clearly adopted the structured-kwargs convention pervasively.
- The dominant gap is **missing entry-level logs** for public methods that perform significant external operations: file-writes (PDF export, document save), file-reads of user-supplied DBs (DIE / ClamAV / custom signature scanners), bridge-to-bridge invocations (`save_to_sandbox`, `test_in_sandbox`), and process-attachment APIs (`list_process_regions`, `open_process_memory`). In every case there is a completion log but no "started" log, so an operator sees the outcome but not the intent — which makes it hard to correlate diagnostics when an external call hangs or never returns.
- A secondary recurring style nit is the use of `_logger.warning(..._failed, error=str(exc))` inside `except` blocks that swallow the exception and return a default value (e.g. PE/Mach-O/ELF parse failures returning `[]`). Per §3 item 6 those should be `_logger.exception(...)` so the traceback is preserved. The error message survives but the traceback context — where the parse actually broke inside `struct.unpack_from` / native code — is lost.
- No HIGH-severity violations. The file is operationally instrumented at production quality; the gaps are about completeness of observability rather than correctness of the existing log calls.
- The file is large but well-structured; the audit was straightforward via Grep-led navigation. Reading the whole file linearly would not have surfaced additional findings.
