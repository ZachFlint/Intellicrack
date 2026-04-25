# False Positive Report

Scope: Unit 4 — semgrep-logging cleanup of `src/intellicrack/bridges/` (process,
frida_bridge, ghidra, installer, named_pipe_client, sandbox_bridge).

Base commit: `680494d1`. Each FP listed below was already firing on the base
commit and is preserved in this PR (i.e. zero NEW findings introduced).

---

## FP-1: `intellicrack-logging-d8-binary-write-without-log`

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Line:** `1411` — `script_path.write_text(script_content)`
- **Status (base):** Already firing on `680494d1`.
- **Status (current):** Still firing.

### Why this is a false positive

The rule's own message acknowledges that adjacent logging makes the finding a
"reviewable non-issue":

> Confirm an adjacent `_logger.info("file_written", path=str(path),
> size=len(data))` call exists - if so this finding is a reviewable non-issue.

The current code already has logs on **both sides** of the write:

```python
_logger.info(
    "ghidra_bridge_script_writing",
    script_path=str(script_path),
    content_size=len(script_content),
)
script_path.write_text(script_content)
_logger.info(
    "file_written",
    path=str(script_path),
    data_size=len(script_content),
)
```

The rule has no `pattern-not-inside` or metavariable-pattern correlation that
recognizes adjacent `_logger.info(...)` calls, so it fires on every
`write_text(...)` regardless of context. This finding is a manual-review prompt
by design.

---

## FP-2: `intellicrack-logging-c5-exception-call-outside-except`

- **File:** `src/intellicrack/bridges/ghidra.py`
- **Line:** `4608` — `_logger.exception("get_calling_conventions_failed")`
- **Status (base):** Already firing on `680494d1`.
- **Status (current):** Still firing.

### Why this is a false positive

The `_logger.exception(...)` call is unambiguously inside an `except Exception:`
handler:

```python
try:
    result = await self._execute_remote("""...""")
except Exception:
    _logger.exception("get_calling_conventions_failed")
    return []
else:
    if isinstance(result, list):
        return [str(c) for c in cast("list[object]", result)]
    return []
```

The semgrep rule (`03-structured-fields.yml`, id c5) has
`pattern-not-inside: try: ... except $E: ...` clauses that should suppress this,
but they fail to match in the presence of an `else:` clause on the same
`try` block. This is a structural blind spot in the rule's pattern library.

Substituting `_logger.error(..., error=str(e), error_type=type(e).__name__)`
clears the c5 finding but introduces ruff `BLE001` (blind `except Exception`)
and `TRY400` (use `logging.exception` instead of `logging.error` in an except
block) — both of which are already correctly satisfied by the original
`_logger.exception(...)` form. The current form is the canonically correct
shape for an `except Exception:` block; the rule simply mis-classifies it due
to the trailing `else:`.

---

## FP-3: `intellicrack-logging-c5-exception-call-outside-except`

- **File:** `src/intellicrack/bridges/installer.py`
- **Line:** `669` — `_logger.exception("download_failed", url=url)`
- **Status (base):** Already firing on `680494d1`.
- **Status (current):** Still firing.

### Why this is a false positive

Identical structural shape to FP-2: the `_logger.exception(...)` call is
inside an `except (httpx.HTTPError, OSError, ValueError):` handler that has a
sibling `else:` clause on the same `try` block:

```python
try:
    ...
    _logger.info("download_completed", file_name=filename, data_size=downloaded)
except (httpx.HTTPError, OSError, ValueError):
    _logger.exception(
        "download_failed",
        url=url,
    )
    return None
else:
    return temp_path
```

The c5 rule's `pattern-not-inside` set does not match the `try/except/else`
shape, so the rule fires even though the call is genuinely inside an `except`
handler with a live exception. Rewriting to `_logger.error(...)` to satisfy
this rule trips `TRY400` in ruff (and is also semantically inferior because it
discards the traceback). The current form is canonically correct.
