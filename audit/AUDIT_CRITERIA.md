# Intellicrack Logging Audit Criteria (STRICT mode)

You are auditing a shard of `D:\Intellicrack\src\intellicrack\` for **logging coverage** and **logging correctness**. This file defines the EXACT rules to enforce. Read this carefully before beginning.

REPORT ONLY. **Do not edit any source files.** Use `Read`, `Grep`, `Glob` freely. Be precise with file paths and line numbers.

---

## 1. Canonical Logger Pattern

Intellicrack uses **structlog** wrapped by `intellicrack.core.logging.get_logger`. The canonical pattern is:

```python
from intellicrack.core.logging import get_logger

_logger = get_logger(__name__)
```

This module-level `_logger` (note the leading underscore and the exact name `_logger`) is the **only acceptable logger** for normal modules.

### Documented exception: LLMProviderBase subclasses

Classes in `src/intellicrack/providers/` that subclass `LLMProviderBase` (defined in `providers/base.py`) are permitted to use an **instance-level** `self._logger`. This is the documented exception per project memory. Look for the subclass relationship; do not flag this pattern in those classes.

### Logger call style — STRUCTURED KWARGS

Log calls must use `structlog`-style structured kwargs:

```python
_logger.info("operation_started", target=path, mode=mode)
_logger.error("ghidra_run_failed", error=str(e), exit_code=rc)
_logger.exception("subprocess_crash", binary=path)  # inside except: block
```

**NOT acceptable** (these are violations):

```python
_logger.info(f"Started operation on {path}")          # f-string — flag as MEDIUM
_logger.info("Started operation on %s" % path)        # % formatting — flag as MEDIUM
_logger.info("Started operation on {}".format(path))  # .format — flag as MEDIUM
```

The first positional arg should be a short stable **event name** (snake_case ok, or a brief human phrase), with values passed as kwargs.

---

## 2. Coverage Requirements (STRICT — "every operation logged")

Flag any of the following as **missing coverage**:

### 2.1 Entry/exit logging for public methods that do real work

A public method (no leading underscore) that performs non-trivial work (more than just attribute return or simple delegation) must log at entry (debug or info with context) AND at exit (debug or info with result summary). Exception: simple `@property` getters/setters and `__repr__`/`__str__`/`__eq__`/`__hash__`/`__bool__`-style dunder methods.

### 2.2 Every error / exception path

Every `except` block must have a log call (typically `_logger.exception(...)` or `_logger.error(...)`):

```python
try:
    do_something()
except SomeError as e:
    _logger.exception("operation_failed", context=...)  # required
    raise
```

A bare `except:` or `except Exception:` (or any except clause) without a log statement is a **HIGH** violation, even if the exception is re-raised.

`contextlib.suppress` is forbidden per memory — flag any use of it as HIGH.

### 2.3 Every external call must be logged

These operations must have log statements before AND after (or around them in a way that records both intent and outcome):

- **Subprocess**: `subprocess.run`, `subprocess.Popen`, `subprocess.call`, `subprocess.check_output`, `subprocess.check_call`, `os.system`, `os.popen`
- **Network**: `requests.*`, `urllib.request.*`, `urllib.urlopen`, `httpx.*`, `aiohttp.*`, `socket.socket`/`.connect`/`.send`/`.recv`, `http.client.*`, `ftplib.*`, `smtplib.*`, `ssl.*` wrappers around sockets, `websockets.*`
- **File I/O**: `open(...)` for writes (`'w'`, `'a'`, `'wb'`, `'ab'`, `'x'`), `Path.write_text`, `Path.write_bytes`, `Path.unlink`, `Path.rmdir`, `Path.mkdir`, `Path.rename`, `Path.replace`, `Path.touch`, `Path.chmod`, `shutil.copy*`, `shutil.move`, `shutil.rmtree`, `os.remove`, `os.rename`, `os.replace`, `os.unlink`, `os.makedirs`, `os.rmdir`
- **Registry / Win32**: `winreg.*`, `ctypes.windll.*` direct calls, `ctypes.WinDLL(...)` followed by API call, `win32api.*`, `win32com.*`, `pywintypes.*`
- **Process attachment / debugging**: `frida.attach`, `frida.spawn`, x64dbg debugger commands, ptrace, anything that attaches to or controls another process
- **Bridge invocations**: when one bridge in `src/intellicrack/bridges/` calls another bridge or invokes an external tool through its bridge layer
- **AI provider calls**: HTTP requests to LLM endpoints (anthropic, openai, ollama, etc.)

Read-only file operations (`open` for read, `Path.read_*`) should be logged when they involve user-provided targets, configuration loads, or anything beyond trivial helpers. Use judgment — log a finding only when the read is operationally significant.

### 2.4 Significant state mutations

Any of these must be logged: session updates, config persistence, credential read/write, cache invalidation, registration of tools/providers, lifecycle transitions (start/stop/connect/disconnect), GUI workflow milestones (target loaded, analysis queued, etc.).

---

## 3. Violations to Flag

### HIGH severity

1. **Stdlib logging directly**: `import logging; logger = logging.getLogger(__name__)` or any direct `logging.info/.warning/.error/.debug/.critical/.exception` call. Exception: a module may set up stdlib `logging` infrastructure *inside* `core/logging.py` itself — do NOT flag `core/logging.py` for using stdlib `logging`; it is the wrapper. Everywhere else, stdlib logging is forbidden.
2. **`except` clause with no log call** (silent failure). Always HIGH.
3. **`contextlib.suppress(...)` used to swallow exceptions** — forbidden per project memory.
4. **`print(...)` for runtime output** — forbidden. Exception: legitimate CLI output to stdout (e.g., `main.py` writing to stdout intentionally for the user). Use judgment but flag everything else.
5. **Missing module-level `_logger`** when the module has any operations that should be logged.
6. **Catching exception but using `.error()` / `.warning()` instead of `.exception()`** so the traceback is lost. (Ruff TRY400 may flag the inverse — using `.error` when `.warning` is correct because of re-raise — see project memory; use judgment.)
7. **Using `# noqa`, `# type: ignore`, `# pyright: ignore`** for logging-related suppressions — forbidden per project memory.

### MEDIUM severity

8. **Missing entry/exit logging** in public methods that perform real work (per §2.1).
9. **Unlogged subprocess / network / file-write / registry / win32 / bridge / AI-provider call** (per §2.3).
10. **String formatting inside log message** (`f"..."`, `%`, `.format`) instead of structured kwargs (per §1).
11. **Wrong log level**: errors logged at `info`, debug-level data at `warning`, business events at `debug`.
12. **Inconsistent logger name**: anything other than `_logger` at module level, or anything other than `self._logger` for the LLMProvider exception. `logger` (no underscore), `LOG`, `log`, etc. are violations.

### LOW severity

13. **Missing context kwargs** — log call with only a message and no structured context where context was clearly available (variables in scope).
14. **Logger initialized inside a function** instead of at module level (unless there's a justified lazy-init reason — note your judgment).
15. **Duplicate / redundant log lines** (e.g., log of the same event from caller and callee with same level and no additional context).

---

## 4. Exempt (do NOT flag)

- LLMProviderBase subclasses' `self._logger` (§1).
- `__init__.py` files containing only re-exports (`from X import Y`) with no executable code.
- Pure data / constant files (e.g., `_tld_data.py`, `_metadata.py`) where there are no operations.
- Type definitions, dataclasses with no methods or only trivial dunder methods.
- `core/logging.py` itself using stdlib `logging` — it IS the wrapper.
- Code under `if TYPE_CHECKING:` blocks.

---

## 5. Output Format

Write your report to the path the orchestrator specifies (something like `D:\Intellicrack\audit\shard-NN-<name>.md`).

Use this exact structure:

```markdown
# Shard NN — <descriptive shard name>

- **Files audited**: N
- **Total LOC**: NNNNN
- **Generated**: <ISO timestamp>

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | N     |
| MEDIUM   | N     |
| LOW      | N     |

- Files missing module-level `_logger`: N
- Files using stdlib `logging`: N
- Files containing `print(` runtime output: N
- Files with `contextlib.suppress`: N
- Files with bare `except` (no log): N

## Findings by file

### src/intellicrack/<relative path>.py — LOC NNN

**Logger status**: `module-level _logger` | `instance-level self._logger (LLMProvider exception)` | `missing` | `wrong-name (logger)` | `stdlib logging`

**Imports `from intellicrack.core.logging import get_logger`**: yes | no

**Findings**:

- [HIGH] L42 — `except Exception:` block at `do_thing()` does not log. Fix: add `_logger.exception("do_thing_failed", target=path)` before re-raise.
- [HIGH] L101 — `print(f"Error: {e}")` used for runtime output. Fix: `_logger.error("operation_failed", error=str(e))`.
- [MEDIUM] L88-92 — `subprocess.run([...])` call has no surrounding log statements.
- [MEDIUM] L120 — public method `process_pe_header()` performs significant work (PE parsing, file I/O) with no entry/exit logging.
- [MEDIUM] L200 — log call uses f-string: `_logger.info(f"loaded {path}")` should be `_logger.info("module_loaded", path=path)`.
- [LOW] L301 — log call missing context kwargs; `target` and `mode` are in scope.

(continue per file — include EVERY file in your shard, even if 0 findings; in that case say "Findings: none" and explain why)

## Aggregate notes

- Any patterns observed across multiple files in the shard
- Cross-file recommendations
- Files where the audit was difficult (e.g., generated code, very large files)
```

---

## 6. Audit Workflow

1. **Read this criteria file completely** before starting.
2. For each file in your shard:
   - Use `Grep` first to spot quick wins: `print\(`, `logging\.getLogger`, `import logging`, `contextlib\.suppress`, `except`, `subprocess\.`, `requests\.`, `urllib\.`, `winreg\.`, `_logger`, `self\._logger`, `\.format\(`, `f"`, `Path\(.*\)\.write`, `open\(.*['"][wax]`, etc.
   - Use `Read` to inspect specific regions / understand context. For files >2000 lines, read in chunks using `offset`/`limit`.
   - Cross-check the canonical pattern: does the module import `get_logger`? Is `_logger` defined?
   - Walk every `except` clause and verify it logs.
   - Walk every external-call site (subprocess, network, file write, win32, bridge call) and verify surrounding log statements.
   - For public methods, judge whether they perform real work and need entry/exit logs.
3. Write your report file to the designated path with the exact structure above. Make sure findings include precise line numbers (or line ranges for multi-line items).
4. Be thorough but accurate — false positives waste reviewer time. When uncertain, mark severity LOW and explain the uncertainty.

You are one of 20 parallel agents. Stay within your assigned shard.
