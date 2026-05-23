# Shard 10 — hexpat evaluator + core infra

- **Files audited**: 11
- **Total LOC**: 8086
- **Generated**: 2026-05-22T16:54:51-06:00

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 12    |
| MEDIUM   | 6     |
| LOW      | 6     |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 1 (exempt: `core/logging.py` itself)
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 12 (counted as individual findings)

## Findings by file

### src/intellicrack/core/__init__.py — LOC 153

**Logger status**: imports `get_logger` for re-export only; no module-level `_logger` needed.

**Imports `from intellicrack.core.logging import get_logger`**: yes (re-export only).

**Findings**: none. The file is exclusively re-exports from sibling modules (§4 exemption); it has no executable runtime code or operations to log.

---

### src/intellicrack/core/_subprocess.py — LOC 82

**Logger status**: `module-level _logger`.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L19).

**Findings**: none.

The module is a thin re-export wrapper around stdlib `subprocess`. It already initialises a module-level `_logger` and emits a debug log inside the `_StartupInfoFallback.__init__` (L43). The constants and class assignments at module level are pure rebindings to the stdlib API — no subprocess invocations happen here; downstream callers are the ones who must surround `run()` / `Popen()` invocations with logging. Not flagging the `importlib.import_module("sub" + "process")` call at L24 because it's a static-analysis evasion technique for bandit, not a runtime operation needing logging.

---

### src/intellicrack/core/_xml_gen.py — LOC 34

**Logger status**: not applicable.

**Imports `from intellicrack.core.logging import get_logger`**: no.

**Findings**: none. §4 exemption — the file re-exports stdlib `xml.etree.ElementTree` symbols with no runtime operations. Adding a logger would be noise.

---

### src/intellicrack/core/logging.py — LOC 760

**Logger status**: `module-level _logger` not present (this IS the structlog wrapper). §4 exempts stdlib `logging` usage in this file. The bootstrap helper `cleanup_old_logs` correctly obtains its logger via `get_logger(__name__)` (L183).

**Imports `from intellicrack.core.logging import get_logger`**: yes (self-import inside `cleanup_old_logs`).

**Findings**:

- [HIGH] L80 — `except ImportError:` inside `_resolve_log_dir_from_config()` silently `return None`. No log call. Fix: add `bootstrap_logger.debug("config_module_import_failed")` (using `get_logger` lazily, to avoid bootstrap re-entrancy) before returning.
- [HIGH] L90 — `except (OSError, RuntimeError):` silently `return None`. No log call. Fix: log at debug level with the suppressed exception details before returning.
- [HIGH] L99 — `except (OSError, ValueError, KeyError):` silently `return None` when `Config.load(config_path)` fails. No log call. This swallows config-load failures during logger bootstrap. Fix: log at warning level (`config_load_failed_during_bootstrap`, path=str(config_path), error=str(exc)).
- [LOW] L747-753 — `OperationTimer.__exit__` uses `self._logger.error("operation_failed", ...)` when an exception propagates through the `with` block. Because the exception is *not* caught, traceback context is lost. The contract is debatable here (the exception will still surface to the caller), but the canonical pattern is `_logger.exception(...)` inside the actual `except`. Fix (optional): use `_logger.exception("operation_failed", ...)` so the traceback is recorded for the timer's log even though the exception continues to propagate.

The stdlib `logging` import at L15 and the `logging.getLogger()` calls at L272/L276 are exempt per §4.

---

### src/intellicrack/core/config.py — LOC 677

**Logger status**: `module-level _logger`.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L19).

**Findings**: none of HIGH/MEDIUM severity.

All `except` clauses (L332, L343, L373, L401, L428, L535) log at the appropriate level (`warning`) with structured kwargs. The two file-I/O operations (`path.open("rb")` at L302 and `path.open("wb")` at L541) are bracketed by debug-entry / info-completion log calls (L301/L306 for load, L532/L543 for save). `ensure_directories()` logs each `mkdir` at info (L628-631).

- [LOW] L626-631 — `ensure_directories()` runs three `mkdir` calls and logs each at info; the `mkdir(exist_ok=True)` for already-existing directories produces info noise on every startup. Consider conditional logging only when the directory is actually created. (Judgment call — keeping as LOW.)

---

### src/intellicrack/core/tools.py — LOC 635

**Logger status**: `module-level _logger`.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L26).

**Findings**: none of HIGH/MEDIUM severity.

Every `except` clause logs (L167-168, L178-179, L222-223, L241-242, L437-442, L453-454, L486-487, L532-533, L592-595). Bridge initialization, status retrieval, shutdown, and tool-call dispatch all have debug/info logging around them. Public `execute_tool_call` (L506) has entry/exit log via `log_tool_call` in the `finally` clause (L596-604). `initialize_tool`, `shutdown`, `register_bridge` are all well-logged.

- [LOW] L201 — `_logger.error("unknown_tool", tool_name=name)` is logged at `error` level for what is arguably a normal validation failure path (caller passed an unregistered tool); the function returns False rather than raising. `warning` might match the documented TRY400 convention better since no traceback is available. Judgment — keeping as LOW.

---

### src/intellicrack/core/template_manager.py — LOC 546

**Logger status**: `module-level _logger`.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L17).

**Findings**:

- [LOW] L289 — `_logger.error("template_name_sanitization_empty", template_name=name)` followed immediately by `raise ValueError(msg)`. The call is outside an `except` block, so `.exception` is not applicable, but per project memory `warning` is the conventional level when re-raising for callers to handle (TRY400 convention). Consider `_logger.warning(...)` here.
- [LOW] L323, L382, L400 — Same pattern as L289 — `_logger.error(...)` immediately followed by `raise ValueError(...)` / `raise FileNotFoundError(...)`. `warning` may be more consistent.

All `except` blocks (L37, L220, L233, L330, L350, L461) log appropriately at debug/warning/exception. File-writes at L232, L329, L349 are paired with info-level success logs and warning-level failure logs. `unlink` calls at L412/L420 are pre-logged at info (L407, L415). `mkdir` calls in `ensure_directories` log at debug (L125). Good overall.

---

### src/intellicrack/core/transform_pipeline.py — LOC 873

**Logger status**: `module-level _logger`.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L22).

**Findings**:

- [HIGH] L410-412 — `except re.error as exc:` in `RegexReplaceNode.process()` raises `TransformParamError` without logging. Fix: add `_logger.warning("regex_compile_failed", pattern=raw_pattern, error=str(exc))` before re-raise.
- [HIGH] L487-489 — `except SyntaxError as exc:` in `CustomExpressionNode.process()` raises `TransformParamError` without logging. Fix: add `_logger.warning("expression_parse_failed", expression=expression, error=str(exc))` before re-raise.
- [HIGH] L550-552 — `except (TypeError, ValueError) as exc:` in `RepeatNode.process()` raises `TransformParamError` without logging.
- [HIGH] L615-617 — `except (TypeError, ValueError) as exc:` in `TruncateNode.process()` raises `TransformParamError` without logging.
- [HIGH] L686-688 — `except (TypeError, ValueError) as exc:` in `PadNode.process()` raises `TransformParamError` without logging.
- [HIGH] L697-699 — `except (TypeError, ValueError) as exc:` in `PadNode.process()` (second `except` for `byte` param) raises `TransformParamError` without logging.
- [MEDIUM] L796-811 — `TransformPipeline.execute()` is a public method that runs every step in the pipeline, mutating data through arbitrary transforms (including Rust-side native calls). No entry/exit log. Fix: add `_logger.debug("pipeline_execute_started", step_count=len(self._steps), input_size=len(data))` at the start and `_logger.debug("pipeline_execute_complete", output_size=len(result))` at the end.
- [MEDIUM] L813-828 — `TransformPipeline.preview()` — same as `execute()`, no entry/exit log.
- [MEDIUM] L298-340 — `RustTransformNode.process()` invokes the Rust `_hexcore_mod.HexDocument.open_bytes` and `doc.transform_data` — these are cross-language external calls (per §2.3, equivalent to native API calls). No surrounding log. Fix: log debug `rust_transform_started` (transform=self._name, input_size=len(data)) and `rust_transform_complete` (output_size=len(result)).
- [LOW] L135-138 — `_logger.error("ast_node_unsupported_constant", type_name=...)` is followed by `raise UnsupportedConstantTypeError(...)`. Same TRY400 consideration — `warning` would be more consistent.

---

### src/intellicrack/core/hexpat/data_reader.py — LOC 429

**Logger status**: `module-level _logger`.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L12).

**Findings**: none of HIGH/MEDIUM severity.

The 14 `read_*` primitive methods (L158-401) are leaf operations that may be invoked millions of times during pattern evaluation — explicit logging on each would be inappropriate. `read()` at L133 logs at error on out-of-bounds (L148-153). No `except` blocks present. No external system calls.

- [LOW] L148 — `_logger.error("hexpat_data_reader_read_out_of_bounds", ...)` followed by `raise HexPatRuntimeError(...)`. Consider `warning` per TRY400 convention (no traceback available; user-visible error).

---

### src/intellicrack/core/hexpat/preprocessor.py — LOC 824

**Logger status**: `module-level _logger`.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L23).

**Findings**:

- [MEDIUM] L98-208 — `HexPatPreprocessor.process()` is the public entry point and does significant work (full preprocessing, include resolution, macro expansion, pragma extraction). It logs initialisation at the constructor (L93), but `process()` itself has no entry/exit log. Fix: add `_logger.debug("hexpat_preprocess_started", file=str(file_path) if file_path else "<inline>", source_size=len(source))` at L113 and `_logger.debug("hexpat_preprocess_complete", endian=endian, mime=mime, magic_count=len(magic_list), output_size=len(output_lines))` before `return`.
- [MEDIUM] L391 — `candidate.read_text(encoding="utf-8", errors="replace")` reads an `#include` file from disk (a user-driven path under `_include_paths`). Only the FAILURE case is logged (L402-408); the SUCCESS case has no log. This is operationally significant — every included pattern file should be auditable. Fix: add `_logger.debug("hexpat_include_resolved", include_path=include_path, resolved_path=resolved_str, depth=depth)` before reading (or after successful read).
- [LOW] L725 — `extract_pragmas_fast()` is a public function but performs lightweight regex matching only; missing entry/exit log is low-priority.

---

### src/intellicrack/core/hexpat/evaluator.py — LOC 3073

**Logger status**: `module-level _logger`.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L72).

**Findings**:

- [HIGH] L966-968 — `_eval_try()`: `except (HexPatRuntimeError, HexPatTypeError):` block runs the catch body but does not log. This implements the HexPat language's user-level `try/catch` semantics, so suppression is by design from the language's perspective. However, per §2.2 every `except` must log. Fix: add `_logger.debug("hexpat_try_caught", line=node.line, column=node.column)` so failures inside user `try` blocks are auditable even when the language semantically swallows them.
- [HIGH] L2589-2590 — `_sizeof_conditional_field()`: `except (HexPatRuntimeError, HexPatTypeError):` returns `0` on any evaluation failure. This silently masks the error. Fix: add `_logger.debug("hexpat_sizeof_conditional_eval_failed", ...)` before returning 0 so silent zero-sizing is auditable.
- [HIGH] L2736-2738 — Inside the cast-to-integer block: `except (OverflowError, ValueError) as exc:` raises `HexPatRuntimeError(msg, line, column) from exc` without logging. Fix: add `_logger.warning("hexpat_float_to_int_conversion_failed", target_type=target_prim.name, error=str(exc))` before re-raise.
- [MEDIUM] L643-663 — `HexPatEvaluator.evaluate()` is THE main public entry point for pattern evaluation against binary data. It iterates the entire program, dispatching to every declaration / statement evaluator, accumulating parsed-field dictionaries. The constructor logs `hexpat_evaluator_initialized` (L361), but `evaluate()` itself has no entry/exit log. Fix: add `_logger.debug("hexpat_evaluate_started", program_node_count=len(program), data_size=self._data.size)` at L655 and `_logger.debug("hexpat_evaluate_complete", result_count=len(self._results), pattern_count=self._pattern_count)` before `return self._results`.
- [LOW] L2225-2226 — `except _ReturnSignalError as sig:` in `_call_user_function` does not log; analogous `_BreakSignalError`/`_ContinueSignalError` `except` blocks in `_eval_while` (L901-906) and `_eval_for` (L928-933) DO log at debug. Inconsistency — either remove the debug logs from while/for or add one here. Recommend adding `_logger.debug("hexpat_function_returned", function_name=decl.name)` for symmetry.
- [LOW] L980, L1276, L1353, L2076, L2087, L2120, L2954 — several call sites use `_logger.error(...)` immediately followed by `raise HexPatRuntimeError(...)`. Per project memory's TRY400 convention, `warning` would be the consistent level since no traceback is available (these are outside `except` blocks). Many `error` calls here; consider standardising on `warning` for raise-after-log.

The remaining `_logger.debug` calls inside `_eval_while`/`_eval_for` for break/continue exceptions are appropriate. No use of f-strings or `%` formatting inside log calls (all messages are stable event names with structured kwargs). No external (subprocess/network/winreg/socket) calls in this module — every byte read goes through the bounded `DataReader` interface, so primitive-read leaf operations are appropriately silent.

---

## Aggregate notes

### Shard-wide observations

1. **Logger convention is excellent across the shard.** Every non-exempt file initialises `_logger = get_logger(__name__)` correctly, and no file uses stdlib `logging` outside the documented exception (`core/logging.py` itself). No f-string / `%` / `.format` formatting was found inside any log call. No `contextlib.suppress`, no `print()`, no inline noqa/type-ignore suppressions for logging.

2. **The biggest cluster of HIGH findings is in `transform_pipeline.py`** — six `except` blocks across the five Python transform-node `process()` methods raise `TransformParamError` without logging the precipitating parse error. The fix pattern is uniform: add a single `_logger.warning(event_name, param=..., error=str(exc))` line before each `raise`.

3. **`logging.py` bootstrap helpers silently absorb three exception types** when discovering the configured log directory (`_resolve_log_dir_from_config`). Because this runs before logging is fully set up, careful debug-level logging (using a lazily obtained `get_logger`) is the safe fix; suppression here is intentional, but the criteria require at least a log line.

4. **The hexpat evaluator's main entry point `evaluate()` has no entry/exit log**, even though it dispatches across the entire AST and produces the document's parsed-field output. The constructor log captures init-time context; an evaluate-time bracket would close the loop. Similarly, `TransformPipeline.execute()` and `HexPatPreprocessor.process()` are missing entry/exit logs at their primary public surface.

5. **Language-level `try`/`catch` semantics intersect with the audit rules.** The evaluator's `_eval_try` (L966) implements the user-visible HexPat `try/catch` construct and must semantically suppress runtime errors. Per the strict criteria these are still HIGH violations; however, a debug-level log of the caught exception preserves the language semantics while making the suppression auditable.

6. **`error` vs `warning` log-level choice when re-raising.** Many sites in the evaluator and transform pipeline use `_logger.error(...)` right before `raise SomeError(...)`. Per project memory's TRY400 note, `warning` is conventionally the right level when the function is re-raising for the caller to handle. There are roughly a dozen of these across the shard — I've grouped them as LOW findings rather than enumerating every line.

### Difficult-to-audit files

- `evaluator.py` (3073 LOC) was read in chunks; the bulk of its bodies are private `_eval_*` and `_reflect_*` helpers that operate on AST nodes. Public surface is small (`evaluate`, `scope`, `current_array_index`, `set_default_endian`, `reflection_provider`). I focused logging-coverage judgement on the public entry point and on every `except` clause; mid-evaluator helpers that raise unconditionally (no `except`) were not flagged because the criteria scope `except`-clause logging, not raise-site logging.
- `data_reader.py` reads dispatch through `struct.unpack` on slices returned by the wrapped `_read_fn`. There is no IO that should be logged at this layer — the underlying `HexDocument` reads are handled by the Rust side, and explicit Python-level logging would generate enormous noise during pattern evaluation.

### Cross-file recommendations

- Adopt a uniform pattern at every `except` site that raises a typed translated exception: `_logger.warning(event_name, error=str(exc), context_kwargs...); raise NewError(...) from exc`. This would clean up all six HIGH findings in `transform_pipeline.py` and several in `evaluator.py` with minimal noise.
- Consider a small helper / decorator to bracket public entry points (`evaluate`, `process`, `execute`) in the hexpat + transform pipeline with debug-level start/complete logs. The `OperationTimer` context manager already in `logging.py` could serve this purpose if invoked at these three call sites.
