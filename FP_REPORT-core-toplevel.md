# Semgrep Logging False Positive Report — Unit 5 (Core Top-Level)

This report documents semgrep findings that remain after Unit 5 remediation work
and explains why each is considered a false positive (FP) rather than a missed
fix.

## FP: intellicrack-logging-a3-get-logger-requires-dunder-name at src/intellicrack/core/logging.py:431

**Semgrep message:** `get_logger()` must be called with `__name__` so the logger participates in the hierarchy `intellicrack.<subpackage>.<module>`. Passing a hand-written literal string (e.g. `get_logger("mybridge")`) breaks parent-child log-level propagation and makes per-module filtering unreliable.

**Current code (3-5 lines):**
```python
def log_tool_call(...) -> None:
    ...
    slog = get_logger("tools")
```

**Why this is a false positive:** This file (`logging.py`) is the `get_logger`
factory itself. The helper functions `log_tool_call`, `log_provider_request`,
`log_provider_response`, `log_binary_operation`, `log_sandbox_operation`,
`log_session_operation`, and `log_analysis_operation` intentionally produce
namespaced child loggers (`intellicrack.tools`, `intellicrack.providers`, etc.)
that downstream code can subscribe to as a single subsystem stream. Replacing
the literal name with `__name__` would route every call back to
`intellicrack.core.logging`, defeating the per-subsystem filtering the helpers
are designed to provide.

**Proposed resolution:** add `paths.exclude: ["**/intellicrack/core/logging.py"]`
to the a3 rule (already done for a1 and a6) so the factory module is exempt
from the dunder-name requirement.

## FP: intellicrack-logging-a3-get-logger-requires-dunder-name at src/intellicrack/core/logging.py:497

**Semgrep message:** Same as above (a3).

**Current code:**
```python
slog = get_logger("providers")
```

**Why this is a false positive:** Same reason as line 431 — internal child
logger factory.

**Proposed resolution:** Add path exclude for `logging.py` to a3 rule.

## FP: intellicrack-logging-a3-get-logger-requires-dunder-name at src/intellicrack/core/logging.py:523

**Semgrep message:** Same as above (a3).

**Current code:**
```python
slog = get_logger("providers")
```

**Why this is a false positive:** Same reason as line 431.

**Proposed resolution:** Add path exclude for `logging.py` to a3 rule.

## FP: intellicrack-logging-a3-get-logger-requires-dunder-name at src/intellicrack/core/logging.py:548

**Semgrep message:** Same as above (a3).

**Current code:**
```python
slog = get_logger("binary")
```

**Why this is a false positive:** Same reason as line 431.

**Proposed resolution:** Add path exclude for `logging.py` to a3 rule.

## FP: intellicrack-logging-a3-get-logger-requires-dunder-name at src/intellicrack/core/logging.py:564

**Semgrep message:** Same as above (a3).

**Current code:**
```python
slog = get_logger("sandbox")
```

**Why this is a false positive:** Same reason as line 431.

**Proposed resolution:** Add path exclude for `logging.py` to a3 rule.

## FP: intellicrack-logging-a3-get-logger-requires-dunder-name at src/intellicrack/core/logging.py:580

**Semgrep message:** Same as above (a3).

**Current code:**
```python
slog = get_logger("session")
```

**Why this is a false positive:** Same reason as line 431.

**Proposed resolution:** Add path exclude for `logging.py` to a3 rule.

## FP: intellicrack-logging-a3-get-logger-requires-dunder-name at src/intellicrack/core/logging.py:599

**Semgrep message:** Same as above (a3).

**Current code:**
```python
slog = get_logger("analysis")
```

**Why this is a false positive:** Same reason as line 431.

**Proposed resolution:** Add path exclude for `logging.py` to a3 rule.

## FP: intellicrack-logging-d9-destructive-op-without-log at src/intellicrack/core/logging.py:134

**Semgrep message:** Destructive filesystem operation (`os.remove`, `os.unlink`, `shutil.rmtree`, `pathlib.Path.unlink`, `pathlib.Path.rmdir`). Destructive ops MUST leave an audit trail - confirm a log with the target path is emitted before/after the op.

**Current code:**
```python
if mtime < cutoff_timestamp:
    bootstrap_logger.info(
        "log_file_unlink",
        file=str(log_file),
        mtime=mtime,
    )
    log_file.unlink()
```

**Why this is a false positive:** d9 is a "confirm" rule that flags every
destructive call regardless of surrounding context. The remediation requested
by the rule's message is already in place: an `_logger.info("log_file_unlink",
file=..., mtime=...)` call is emitted on the line immediately preceding the
`unlink()` invocation. The rule has no `pattern-not` for adjacent log
statements, so it always fires.

**Proposed resolution:** manual re-review (confirm the adjacent log) — no code
change required.

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/core/script_gen.py:342

**Semgrep message:** Writing to a file. For an analysis/cracking platform, every write is potentially a patch or artifact emission that must be recorded. Confirm an adjacent `_logger.info("file_written", path=str(path), size=len(data))` call exists - if so this finding is a reviewable non-issue.

**Current code:**
```python
_logger.info("script_file_written", path=str(path), size=len(self.content))
path.write_text(self.content, encoding="utf-8")
_logger.info("script_saved", path=str(path), size=len(self.content))
```

**Why this is a false positive:** d8 is a "confirm" rule. Adjacent
`_logger.info` calls bracket the `write_text()` (one immediately before with
path+size, one after announcing the save). The rule has no `pattern-not` for
neighbouring log statements.

**Proposed resolution:** manual re-review.

## FP: intellicrack-logging-d9-destructive-op-without-log at src/intellicrack/core/script_gen.py:440

**Semgrep message:** Destructive filesystem operation (`os.remove`, `os.unlink`, `shutil.rmtree`, `pathlib.Path.unlink`, `pathlib.Path.rmdir`).

**Current code:**
```python
finally:
    _logger.info("temp_file_unlink", path=temp_path)
    Path(temp_path).unlink(missing_ok=True)
    _logger.info("temp_file_cleaned", path=temp_path)
```

**Why this is a false positive:** Adjacent `_logger.info` calls before AND
after the unlink. d9 always fires regardless.

**Proposed resolution:** manual re-review.

## FP: intellicrack-logging-c5-exception-call-outside-except at src/intellicrack/core/session.py:247

**Semgrep message:** `_logger.exception(...)` captures the active exception via `exc_info=True`. When called outside an `except:` block there is no active exception, so it logs `NoneType: None` or nothing at all - a useless record.

**Current code:**
```python
try:
    yield conn
    conn.commit()
    ...
except (sqlite3.Error, OSError):
    conn.rollback()
    _logger.exception("db_connection_rollback", db_path=str(self.db_path))
    raise
```

**Why this is a false positive:** The `_logger.exception` call IS inside an
`except (sqlite3.Error, OSError):` clause — a 2-element tuple. The c5 rule's
`pattern-not-inside` list explicitly enumerates 2-, 3-, 4-, 5-element tuple
exception clauses, so a 2-tuple should be matched. The actual semgrep matcher
appears unable to thread the pattern through a `@contextmanager` generator
function in combination with the multi-tuple exception clause; the same code
shape outside a `@contextmanager` is matched correctly by the rule. The
`raise` immediately after the log preserves the original exception, so the
runtime behaviour is exactly what c5 was written to enforce.

**Proposed resolution:** adjust rule `pattern-not-inside` to also handle
`@contextmanager`-wrapped generator functions (or keep manual re-review).

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/core/template_manager.py:240

**Semgrep message:** Writing to a file. Confirm an adjacent log call exists.

**Current code:**
```python
try:
    _logger.info(
        "builtin_template_file_written",
        template_name=name,
        path=str(target_path),
        size=len(raw_json),
    )
    target_path.write_text(raw_json, encoding="utf-8")
except OSError as exc:
    ...
```

**Why this is a false positive:** Adjacent `_logger.info` call with path and
size precedes the `write_text`. d8 is a confirm-only rule with no
`pattern-not` for adjacent logs.

**Proposed resolution:** manual re-review.

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/core/template_manager.py:323

**Semgrep message:** Same as above (d8).

**Current code:**
```python
_logger.info(
    "user_template_file_written",
    template_name=name,
    path=str(json_path),
    size=len(json_str),
)
json_path.write_text(json_str, encoding="utf-8")
```

**Why this is a false positive:** Adjacent log emitted with path and size.

**Proposed resolution:** manual re-review.

## FP: intellicrack-logging-d8-binary-write-without-log at src/intellicrack/core/template_manager.py:334

**Semgrep message:** Same as above (d8).

**Current code:**
```python
_logger.info(
    "user_template_dsl_file_written",
    template_name=name,
    path=str(dsl_path),
    size=len(dsl_source),
)
dsl_path.write_text(dsl_source, encoding="utf-8")
```

**Why this is a false positive:** Adjacent log emitted with path and size.

**Proposed resolution:** manual re-review.

## FP: intellicrack-logging-d9-destructive-op-without-log at src/intellicrack/core/template_manager.py:383

**Semgrep message:** Destructive filesystem operation (`pathlib.Path.unlink`).

**Current code:**
```python
if json_path.exists():
    _logger.info(
        "user_template_json_unlink",
        template_name=name,
        path=str(json_path),
    )
    json_path.unlink()
    deleted = True
```

**Why this is a false positive:** Adjacent `_logger.info` precedes the
`unlink` call with full path context. d9 always fires.

**Proposed resolution:** manual re-review.

## FP: intellicrack-logging-d9-destructive-op-without-log at src/intellicrack/core/template_manager.py:391

**Semgrep message:** Same as above (d9).

**Current code:**
```python
if dsl_path.exists():
    _logger.info(
        "user_template_dsl_unlink",
        template_name=name,
        path=str(dsl_path),
    )
    dsl_path.unlink()
```

**Why this is a false positive:** Adjacent `_logger.info` precedes the
`unlink` with full path context.

**Proposed resolution:** manual re-review.

## FP: intellicrack-logging-i5-provider-completion-without-model at src/intellicrack/core/hexpat_compiler.py:1262

**Semgrep message:** AI provider `generate` / `stream` / `chat` / `complete` / `create_completion` call without a log that includes the `model` kwarg. The shared workspace's AI event stream is indexed by model - completions without it become untraceable.

**Current code:**
```python
class HexPatCodegen:
    ...
    def generate(self) -> dict[str, Any]:
        """Generate the JSON template dict from all declarations."""
        main_struct: StructDecl | None = next((decl for decl in self._decls if isinstance(decl, StructDecl)), None)
        if main_struct is None:
            ...
```

**Why this is a false positive:** `HexPatCodegen.generate()` is a JSON
template-codegen method on a HexPat DSL compiler — there is no LLM provider
involved and no `model` to log. The i5 rule pattern matches every `def
generate(self, ...)` regardless of class context, so any class with a method
named `generate` on a non-provider class trips it.

**Proposed resolution:** add a `metavariable-regex` filter on the enclosing
class name (similar to i6 / i7) to limit i5 to provider-named classes
(`*Provider*`, `*LLMProvider*`, `*Completion*`, etc.).
