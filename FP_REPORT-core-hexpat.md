# Semgrep Logging False Positives — `core/hexpat/` (Unit 6)

The findings below cannot be resolved without breaking functionality
or by introducing a misleading audit signal. They are documented here
in lieu of a code change.

## FP: intellicrack-logging-g5-dynamic-log-level at src/intellicrack/core/hexpat/stdlib.py:806

**Semgrep message:** `_logger.log(level_variable, ...)` makes the severity unpredictable from static inspection - readers and log filters cannot tell whether the call is informational or a failure. Call the named method directly (`_logger.info(...)` / `_logger.error(...)`); if you genuinely need conditional severity, branch on the condition and call the explicit method in each arm.

**Current code:**

```python
return PatternValue(value=math.log(val))
```

**Why FP:** The rule pattern `$L.log($LVL, ...)` matches `math.log(val)` because `$L` matches the `math` module identifier and `.log()` is the natural-logarithm function from the standard `math` module — not a logger method. There is no logger involvement here.

**Proposed resolution:** adjust rule pattern-not (e.g. `pattern-not: math.log(...)` and the equivalent for `math.log2`/`math.log10`) — a manual re-review confirmed the call is `math.log(...)` arithmetic, not a structlog `_logger.log(level, ...)` call.

## FP: intellicrack-logging-g5-dynamic-log-level at src/intellicrack/core/hexpat/stdlib.py:1771

**Semgrep message:** `_logger.log(level_variable, ...)` makes the severity unpredictable from static inspection - readers and log filters cannot tell whether the call is informational or a failure. Call the named method directly (`_logger.info(...)` / `_logger.error(...)`); if you genuinely need conditional severity, branch on the condition and call the explicit method in each arm.

**Current code:**

```python
return PatternValue(value=param1 - param2 * math.log(-math.log(max(u, 1e-300))))
```

**Why FP:** Same root cause as the line 806 finding. The two calls to `math.log(...)` here are natural-logarithm computations used to produce a Gumbel-distributed random number for `std::random`. The rule's `$L.log($LVL, ...)` pattern incorrectly classifies these arithmetic uses as logger calls.

**Proposed resolution:** adjust rule pattern-not (carve out `math.log`, `math.log2`, `math.log10` so the dynamic-log-level rule no longer flags arithmetic).

## FP: intellicrack-logging-g5-dynamic-log-level at src/intellicrack/core/hexpat/stdlib.py:1795

**Semgrep message:** `_logger.log(level_variable, ...)` makes the severity unpredictable from static inspection - readers and log filters cannot tell whether the call is informational or a failure. Call the named method directly (`_logger.info(...)` / `_logger.error(...)`); if you genuinely need conditional severity, branch on the condition and call the explicit method in each arm.

**Current code:**

```python
value=math.floor(math.log(max(u, 1e-300)) / math.log(1.0 - param1)),
```

**Why FP:** Same root cause as the lines 806 and 1771 findings. These two `math.log(...)` calls compute the geometric distribution sampling formula. They are arithmetic computations on floats, not logger calls.

**Proposed resolution:** adjust rule pattern-not (carve out the `math` module's logarithmic helpers).

## FP: intellicrack-logging-d9-destructive-op-without-log at src/intellicrack/core/hexpat/stdlib.py:1676

**Semgrep message:** Destructive filesystem operation (`os.remove`, `os.unlink`, `shutil.rmtree`, `pathlib.Path.unlink`, `pathlib.Path.rmdir`). Destructive ops MUST leave an audit trail - confirm a log with the target path is emitted before/after the op.

**Current code:**

```python
if file_name:
    _logger.info(
        "hexpat_file_remove",
        handle=handle,
        file_path=file_name,
    )
    try:
        Path(file_name).unlink(missing_ok=True)
    except OSError as exc:
        _logger.exception(
            "hexpat_file_remove_failed",
            handle=handle,
            file_path=file_name,
        )
        msg = f"std::file::remove failed: {exc}"
        raise HexPatRuntimeError(msg) from exc
```

**Why FP:** The audit-trail requirement is satisfied: an `_logger.info("hexpat_file_remove", handle=..., file_path=...)` call is emitted immediately before the `Path(...).unlink(...)` invocation, and an `_logger.exception("hexpat_file_remove_failed", ...)` covers the failure path. The d9 rule has no `pattern-not` clause that recognizes adjacent log statements; it fires on every textual occurrence of `$P.unlink(...)`/`$P.rmdir(...)` regardless of surrounding context. The rule documents this expectation as a manual checklist (`confirm a log ... is emitted before/after the op`).

**Proposed resolution:** manual re-review (the rule deliberately requires a human to inspect — the fix is to acknowledge the surrounding log statements satisfy the audit-trail contract).
