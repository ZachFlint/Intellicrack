# False Positive Report: Sandbox Unit (Unit 8)

Scope: `src/intellicrack/sandbox/{windows,qemu,analysis,base,manager}.py`

## Summary

Two findings remain after remediation. Both are flagged as "reviewable non-issue" by the rule's own guidance text because the rule patterns cannot match adjacent log calls but the required logs are present.

## Flagged False Positives

### 1. `intellicrack-logging-d8-binary-write-without-log`

- **File**: `src/intellicrack/sandbox/qemu.py`
- **Line**: 252 (`png_path.write_bytes(png_bytes)` in `_ppm_p6_to_png`)
- **Rule message**: "Confirm an adjacent `_logger.info("file_written", ...)` call exists - if so this finding is a reviewable non-issue."
- **Justification**: Immediately after the `write_bytes` call we emit `_logger.info("screenshot_png_written", png_path=str(png_path), size=len(png_bytes), width=width, height=height)`. The rule fires purely on the AST shape of the write expression and cannot see the adjacent log statement.

### 2. `intellicrack-logging-d7-subprocess-without-log`

- **File**: `src/intellicrack/sandbox/qemu.py`
- **Line**: 1281 (`asyncio.create_subprocess_exec` in `QEMUSandbox.start`)
- **Rule message**: "Confirm a surrounding `_logger.info("subprocess_spawning", argv=...)` exists - if so this finding is a reviewable non-issue."
- **Justification**: The two lines preceding this call emit `_logger.info("qemu_starting", command=...)` and `_logger.info("subprocess_spawning", argv=cmd, executable=cmd[0] if cmd else None)`. The rule fires purely on the call-site of `create_subprocess_exec` and cannot inspect surrounding statements.
