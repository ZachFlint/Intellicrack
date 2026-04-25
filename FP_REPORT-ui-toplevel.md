# False Positive Report — Unit 10 (UI top-level + dialogs + resources)

The remediation pass for unit 10 resolves all actionable semgrep-logging
findings. The findings retained below are confirmed false positives. Each
entry documents the file, line, rule, and reason the rule does not apply.

## c5-exception-call-outside-except (semantic FP)

### `src/intellicrack/ui/app.py`

- **L165** — `_logger.exception("async_worker_failed")` resides directly
  inside the `except BaseException as exc:` arm of the
  `WorkerThread._run` body. The `c5` rule's `pattern-not-inside`
  exclusion does not match `BaseException as exc` in this nested layout
  because the surrounding function contains an inner `try/except` block
  before the outer except, and semgrep's structural matcher cannot
  resolve the nesting. The active exception is real and the call is
  correct.

### `src/intellicrack/ui/sandbox_config.py`

- **L161** — `_logger.exception("sandbox_test_error", failure_reason="subprocess_error")`
  is the body of `except SubprocessError as e:` at line 160.
- **L168** — `_logger.exception("sandbox_test_error", failure_reason="windows_sandbox_not_found")`
  is the body of `except FileNotFoundError:` at line 167.
- **L178** — `_logger.exception("sandbox_test_error", failure_reason="permission_denied")`
  is the body of `except PermissionError:` at line 177.
- **L188** — `_logger.exception("sandbox_test_error", failure_reason="os_error")`
  is the body of `except OSError as e:` at line 187.

  Each call is inside a real `except` block. The same nested-try
  structural limitation observed in `app.py:165` causes semgrep's
  `pattern-not-inside` exclusion to miss these despite the active
  exception being well-defined. Behaviour is correct.

## e4-critical-outside-allowlist (off-target match)

### `src/intellicrack/ui/app.py`

- **L1115** — `QMessageBox.critical(self, "Error", str(error))`
- **L1985** — `QMessageBox.critical(self, "Error", str(e))`

### `src/intellicrack/ui/provider_config.py`

- **L1284** — `QMessageBox.critical(self, "Error", f"Unknown provider: {self._current_provider}")`
- **L1287** — `QMessageBox.critical(self, "Error", f"Failed to set active provider: {e}")`

  The `e4` rule pattern `$L.critical(...)` matches any callable named
  `critical`. These are PyQt6 modal dialog calls — not structured
  logger calls — and convey severity to the end user, not to the log
  aggregator. They do not desensitize the operator-facing CRITICAL
  signal the rule is guarding.

## d8-binary-write-without-log (reviewable non-issue)

### `src/intellicrack/ui/tool_config.py`

- **L430** — `script_path.write_text(...)` (preceded by
  `_logger.info("ghidra_bridge_script_writing", path=..., size=...)`)
- **L437** — `ext_script_path.write_text(...)` (preceded by
  `_logger.info("ghidra_bridge_extension_writing", ...)`)
- **L441** — `install_script_path.write_text(...)` (preceded by
  `_logger.info("ghidra_bridge_install_script_writing", ...)`)
- **L464** — `headless_script_path.write_text(...)` (preceded by
  `_logger.info("ghidra_headless_script_writing", ...)`)
- **L489** — `verify_script_path.write_text(...)` (preceded by
  `_logger.info("ghidra_verify_script_writing", ...)`)

  The `d8` rule fires unconditionally on `write_text` / `write_bytes`
  and explicitly notes in its message: "Confirm an adjacent
  `_logger.info(...)` call exists — if so this finding is a
  reviewable non-issue." Each write here has the required adjacent log
  call with `path=str(...)`.

## d9-destructive-op-without-log (reviewable non-issue)

### `src/intellicrack/ui/sandbox_config.py`

- **L208** — `self._wsb_file.unlink()` is preceded by
  `_logger.info("wsb_file_unlinking", path=str(self._wsb_file))`.

### `src/intellicrack/ui/session_manager.py`

- **L591** — `session_file.unlink()` is preceded by
  `_logger.info("session_file_unlinking", session_id=session_id, path=str(session_file))`.

  As with `d8`, the `d9` rule fires on every `unlink()` /
  `rmtree()` call and the rule message instructs reviewers to confirm
  an adjacent log with the target path is emitted. Both unlink call
  sites have that log in the immediately preceding statement.
