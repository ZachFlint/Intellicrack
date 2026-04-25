# False Positive Report - semgrep-logging/ui-hex-panels

## Scope

`src/intellicrack/ui/panels/hex_editor/**/*.py` (Unit 11)

## Summary

After remediation, 9 inherent false positives remain. All are inherent rule limitations
where the rule fires unconditionally on a syntactic match without checking for the
documented adjacent-log compensation that the rule message itself recommends. Each
flagged site has the required adjacent log call.

## Flagged False Positives

### intellicrack-logging-d7-subprocess-without-log (1 finding)

**File**: `src/intellicrack/ui/panels/hex_editor/_sandbox.py:63`
**Site**: `asyncio.create_subprocess_exec(*args, ...)`
**Rule message**: "Confirm a surrounding `_logger.info('subprocess_spawning', argv=...)` exists - if so this finding is a reviewable non-issue."

**Compensation present**: Lines 58-62 emit `_logger.info("sandbox_subprocess_invoke", argv=args, timeout=max_seconds)` immediately before the subprocess spawn. The rule has no `pattern-not-inside` clause, so it cannot detect this adjacent log.

### intellicrack-logging-d8-binary-write-without-log (8 findings, 5 reported lines)

**Rule message**: "Confirm an adjacent `_logger.info('file_written', path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue."

Each flagged site has an adjacent `_logger.info("file_written", ...)` (or equivalent named log) immediately preceding the write call:

1. **`_patches.py:142`**: `Path(save_path).write_bytes(patch_data)` - preceded by `_logger.info("patches_export_write_begin", path=save_path, data_size=len(patch_data), data_sha256=hashlib.sha256(patch_data).hexdigest()[:12], suffix=suffix)` at lines 134-140.

2. **`_pattern_editor.py:354,356-359`**: `path.write_text(...)` calls - preceded by `_logger.info("file_written", path=str(path), size=..., kind=...)` at lines 353 and 355.

3. **`_scripting.py:529`**: `self._doc.write_bytes(offset, data)` - preceded by `_logger.info("file_written", path="<scripted_doc>", offset=offset, size=len(data), data_size=len(data), data_sha256=...)` at lines 521-528.

4. **`_scripting.py:1188-1191`**: `Path(save_path).write_text(script_text, encoding="utf-8")` - preceded by `_logger.info("file_written", path=save_path, size=len(script_text), kind="script")` at lines 1182-1187.

5. **`_templates.py:246`**: `Path(save_path).write_text(json_str, encoding="utf-8")` - preceded by `_logger.info("file_written", path=save_path, size=len(json_str), kind="template_json")` at line 245.

6. **`_transforms.py:555,717`**: `self.document.write_bytes(cursor_offset, write_payload)` - both preceded by `_logger.info("file_written", path="<document>", offset=cursor_offset, size=write_len, data_size=write_len, data_sha256=..., kind=...)` at lines 545-553 and 707-715 respectively.

The d8 rule has no `pattern-not-inside` clause for the `file_written` log it requests, so it fires syntactically on every write call regardless of compensating adjacent logs. The base report's d8 findings exhibited the same pattern.
