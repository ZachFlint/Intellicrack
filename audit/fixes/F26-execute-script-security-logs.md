# F26 — `execute_script` security-sensitive surface logging

## Fix description

`src/intellicrack/ui/panels/hex_editor/_scripting.py:execute_script` runs **user-provided Python code** in a sandboxed namespace via `exec(compiled, namespace)`. This is the most security-sensitive external call in the entire UI layer. Currently:

- No entry log of script invocation
- The `except BaseException as exc:` branch at L1196 captures the exception into `error_message` but emits **no log call**
- No completion log
- The only failure log is emitted in the Qt thread by `_on_script_finished` at L1496 when the panel renders the traceback — too late for forensic timeline reconstruction

## Fix template

In `_scripting.py:execute_script` (around L1066-L1230):

```python
def execute_script(source: str, doc_api: DocAPI | _DocAPI, ...) -> ScriptResult:
    """Execute a user-provided Python script."""
    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    _logger.info(
        "script_invoked",
        source_sha256=source_hash,
        source_len=len(source),
        has_write_access=isinstance(doc_api, _DocAPI),
    )
    ...
    try:
        exec(compiled, namespace)  # noqa: S102  # nosec B102 — documented sandboxed-script execution
    except BaseException as exc:
        _logger.exception(
            "script_execution_failed",
            source_sha256=source_hash,
            error_type=type(exc).__name__,
        )
        error_message = ...  # existing capture
        # do NOT re-raise
    ...
    _logger.info(
        "script_completed",
        source_sha256=source_hash,
        stdout_len=len(stdout_capture.getvalue()),
        stderr_len=len(stderr_capture.getvalue()),
        output_files=len(output_files),
        had_error=error_message is not None,
    )
    return ScriptResult(...)
```

## Sites to fix in `src/intellicrack/ui/panels/hex_editor/_scripting.py`

### HIGH — execute_script (L1066-L1230)

| Severity | Lines | Fix |
|----------|-------|-----|
| HIGH | 1193-1205 | Add invocation log at entry; `.exception("script_execution_failed", ...)` inside `except BaseException`; completion log before `return ScriptResult(...)` |

### HIGH — LookupError re-raises

| Severity | Lines | Fix |
|----------|-------|-----|
| HIGH | 606-610 | `except LookupError as exc:` re-raises new LookupError without log | Add `_logger.warning("script_search_text_unknown_encoding", encoding=resolved)` before raise |
| HIGH | 827-830 | Same pattern | `_logger.warning("script_replace_text_unknown_encoding", encoding=resolved)` before raise |

### MEDIUM — file write & temp dir creation

| Severity | Lines | Fix |
|----------|-------|-----|
| MEDIUM | 1062 | `resolved.open("w", encoding="utf-8")` inside `_safe_print` | `_logger.info("file_written", path=str(resolved), kind="script_print_output", mode="w")` before opening |
| MEDIUM | 1112 | `tempfile.mkdtemp(prefix=_SCRIPT_TEMPDIR_PREFIX)` | `_logger.debug("script_sandbox_tempdir_created", path=str(sandbox_dir))` |
| MEDIUM | 1340 | `worker.start()` in `_on_run_script` | `_logger.info("script_worker_started", has_write_access=isinstance(doc_api, _DocAPI))` |
| MEDIUM | 1397-1412 | `_on_load_script` reads script file via Qt dialog | `_logger.info("script_loaded", path=script_path, size=len(content))` after `setPlainText` |
| MEDIUM | 1432-1438 | `Path(save_path).write_text(...)` save handler — `_logger.info("file_written", ...)` happens BEFORE write (acceptable ordering) but `_logger.exception("script_save_failed")` at L1438 missing `path=save_path` kwarg | Add `path=save_path` to the exception log |

## Acceptance criteria

- [ ] `execute_script` has 3 distinct log emissions (invoke / exception / complete)
- [ ] Source hash (first 12 chars of SHA-256) used as the cross-cutting correlation key
- [ ] LookupError re-raises log before raise
- [ ] Temp file/dir creation and worker dispatch logged
- [ ] `# noqa: S102 # nosec B102` retained on the `exec(...)` call (security suppression, not logging suppression)
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
