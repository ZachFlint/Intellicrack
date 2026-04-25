# False-Positive Findings Report

This file documents semgrep-logging findings in `src/intellicrack/bridges/hex_editor.py` that cannot be eliminated through in-scope code changes. Each entry below is a finding from `intellicrack-logging-d8-binary-write-without-log` whose pattern matches the `.write_bytes()` call site itself, with no `pattern-not` clause to recognize an adjacent `_logger.info(...)` call. Per the rule's own `message` ("Confirm an adjacent log call exists - if so this finding is a reviewable non-issue"), these are flagged for human review rather than mechanical fix. All call sites listed below have a paired `_logger.info(...)` log line emitted immediately before or after the write.

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:1630

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
data = bytes.fromhex(data_hex.replace(" ", ""))
_logger.info("bytes_write_started", offset=hex(offset), length=len(data))
self.document.write_bytes(offset, data)
_logger.info("bytes_written", offset=hex(offset), length=len(data))
```

**Why this is a false positive:** The d8 rule's `pattern-either` matches every `$P.write_bytes(...)` call without a `pattern-not` clause to recognise adjacent log calls. The bridge already emits `bytes_write_started` immediately before and `bytes_written` immediately after the call, satisfying the audit-trail intent expressed in the rule message.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:3505

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
_logger.info("bps_patch_write_started", target_size=len(target))
self.document.write_bytes(0, target)
_logger.info("file_written", path="document", size=len(target), patch_format="bps")
```

**Why this is a false positive:** The d8 rule fires on every `.write_bytes()` call regardless of surrounding logs. An explicit `_logger.info("file_written", ...)` is emitted immediately after the write, matching the rule's stated remediation pattern.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:3517

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
_logger.info("ups_patch_write_started", target_size=len(target))
self.document.write_bytes(0, target)
_logger.info("file_written", path="document", size=len(target), patch_format="ups")
```

**Why this is a false positive:** The d8 rule has no `pattern-not` for adjacent log calls. An explicit `_logger.info("file_written", ...)` is emitted immediately after this write.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:3640

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
if self.document is not None:
    _logger.info("ips_patch_record_write", offset=hex(offset), length=len(patch_data))
    self.document.write_bytes(offset, patch_data)
```

**Why this is a false positive:** The d8 rule fires on every `.write_bytes()` call. An adjacent `_logger.info("ips_patch_record_write", ...)` records the offset and length before each write, satisfying the audit intent.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:4006

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
fill_data = bytes(islice(cycle(pattern), length))
_logger.info("file_written", path="document", offset=hex(offset), size=len(fill_data), op="fill_block")
self.document.write_bytes(offset, fill_data)
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` immediately precedes the write call.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:4037

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
data = self._read_doc_bytes(src_offset, length)
_logger.info("file_written", path="document", offset=hex(dst_offset), size=len(data), op="copy_block")
self.document.write_bytes(dst_offset, data)
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` immediately precedes the write call.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:4068

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
_logger.info("file_written", path="document", offset=hex(src_offset), size=length, op="move_block_clear_src")
self.document.write_bytes(src_offset, bytes(length))
_logger.info("file_written", path="document", offset=hex(dst_offset), size=len(data), op="move_block_write_dst")
self.document.write_bytes(dst_offset, data)
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` precedes each write.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:4070

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
_logger.info("file_written", path="document", offset=hex(dst_offset), size=len(data), op="move_block_write_dst")
self.document.write_bytes(dst_offset, data)
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` precedes the write call.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:4118

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
_logger.info("file_written", path="document", offset=hex(offset_a), size=len(data_b), op="swap_blocks_a")
self.document.write_bytes(offset_a, data_b)
_logger.info("file_written", path="document", offset=hex(offset_b), size=len(data_a), op="swap_blocks_b")
self.document.write_bytes(offset_b, data_a)
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` precedes each write.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:4120

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
_logger.info("file_written", path="document", offset=hex(offset_b), size=len(data_a), op="swap_blocks_b")
self.document.write_bytes(offset_b, data_a)
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` precedes the write call.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:4200

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
_logger.info("file_written", path="document", offset=hex(start), size=len(result_data), op=operation)
self.document.write_bytes(start, result_data)
used_native = True
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` precedes the write.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:4213

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
result_data = bytes(self._apply_arithmetic_fallback(data, operation, key, count))
_logger.info("file_written", path="document", offset=hex(start), size=len(result_data), op=operation)
self.document.write_bytes(start, result_data)
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` precedes the write.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:4335

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
_logger.info("file_written", path="document", offset=hex(offset), size=1, op="set_bit")
self.document.write_bytes(offset, bytes([byte_val]))
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` precedes the write.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:4374

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
_logger.info("file_written", path="document", offset=hex(offset), size=1, op="toggle_bit")
self.document.write_bytes(offset, bytes([byte_val]))
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` precedes the write.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:5303

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
_logger.info("file_written", path="document", offset=hex(checksum_offset), size=4, op="pe_checksum_repair")
self.document.write_bytes(checksum_offset, struct.pack("<I", new_checksum))
_logger.info("pe_checksum_repaired", old=hex(old_checksum), new=hex(new_checksum))
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` and a subsequent `_logger.info("pe_checksum_repaired", ...)` flank the write.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:5470

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
if isinstance(data, list):
    data = bytes(data)
_logger.info("file_written", path="document", offset=hex(offset), size=len(data), op="script_doc_write")
doc.write_bytes(offset, data)
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` precedes the write inside the `_DocAPI.write` static method exposed to user scripts.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:6052

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
target = self._apply_bps_patch(patch_data, source_data)
_logger.info("file_written", path="document", offset=hex(0), size=len(target), op="bps_patch_apply")
self.document.write_bytes(0, target)
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` precedes the write.

**Proposed resolution:** manual re-review

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/bridges/hex_editor.py:6114

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code (3-5 lines context):**
```python
target = self._apply_ups_patch(patch_data, source_data)
_logger.info("file_written", path="document", offset=hex(0), size=len(target), op="ups_patch_apply")
self.document.write_bytes(0, target)
```

**Why this is a false positive:** Adjacent `_logger.info("file_written", ...)` precedes the write.

**Proposed resolution:** manual re-review
