# F14 — Silent `except` in `core/` modules (transform_pipeline, logging, process_manager, hexpat)

## Fix description

12 HIGH silent-except findings in core infrastructure. All need a one-line `_logger.debug/warning/exception` before the silent return / continue / re-raise.

## Sites to fix

### `src/intellicrack/core/transform_pipeline.py`

All six transform-node `process()` methods catch and re-raise `TransformParamError` without logging the underlying parse error.

| Severity | Lines | Node | Suggested event |
|----------|-------|------|-----------------|
| HIGH | 410-412 | `RegexReplaceNode.process` `except re.error` | `regex_compile_failed`, `pattern=raw_pattern, error=str(exc)` |
| HIGH | 487-489 | `CustomExpressionNode.process` `except SyntaxError` | `expression_parse_failed`, `expression=expression, error=str(exc)` |
| HIGH | 550-552 | `RepeatNode.process` `except (TypeError, ValueError)` | `repeat_param_failed`, `count_raw=count_raw, error=str(exc)` |
| HIGH | 615-617 | `TruncateNode.process` `except (TypeError, ValueError)` | `truncate_param_failed`, `length_raw=length_raw, error=str(exc)` |
| HIGH | 686-688 | `PadNode.process` `except (TypeError, ValueError)` | `pad_length_param_failed`, `error=str(exc)` |
| HIGH | 697-699 | `PadNode.process` byte-param except | `pad_byte_param_failed`, `error=str(exc)` |

Fix template:

```python
except re.error as exc:
    _logger.warning("regex_compile_failed", pattern=raw_pattern, error=str(exc))
    raise TransformParamError(...) from exc
```

### `src/intellicrack/core/logging.py`

Bootstrap-helper silent excepts (must use a **lazy** logger to avoid bootstrap re-entrancy).

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 80 | `_resolve_log_dir_from_config()` `except ImportError` |
| HIGH | 90 | Same function, `except (OSError, RuntimeError)` |
| HIGH | 99 | Same function, `except (OSError, ValueError, KeyError)` when `Config.load` fails |

Fix template (use a lazy bootstrap logger; do NOT use module-level `_logger` because this IS the bootstrap):

```python
except ImportError as exc:
    # Use a bootstrap logger acquired lazily to avoid re-entrancy
    structlog.get_logger("intellicrack.core.logging").debug("config_module_import_failed", error=str(exc))
    return None
```

(Note: `core/logging.py` is exempt from "no stdlib logging" rule per §4 — it IS the wrapper. But also exempt from the "no inline `structlog.get_logger`" rule for this specific bootstrap case. Document the exception in code comments.)

### `src/intellicrack/core/process_manager.py`

`_pid_exists_posix` (POSIX existence probe via `os.kill(pid, 0)`):

| Severity | Line | Branch |
|----------|-----:|--------|
| HIGH | 141 | `except ProcessLookupError: return False` |
| HIGH | 143 | `except PermissionError: return True` |
| HIGH | 145 | `except OSError: return False` |

Fix:

```python
except ProcessLookupError:
    _logger.debug("pid_probe_no_such_process", pid=pid)
    return False
except PermissionError:
    _logger.debug("pid_probe_permission_denied", pid=pid)
    return True
except OSError as exc:
    _logger.debug("pid_probe_oserror", pid=pid, error=str(exc))
    return False
```

### `src/intellicrack/core/hexpat/parser.py`

Pratt-parser backtracking points where `except HexPatParseError:` is swallowed:

| Severity | Lines | Context | Suggested event |
|----------|-------|---------|-----------------|
| HIGH | 229-234 | `parse()` recovery loop — `except HexPatParseError as err: self._errors.append(err); continue` | `_logger.debug("hexpat_parse_recover", error=err.message, line=err.line, column=err.column, file_path=self.file_path)` |
| HIGH | 237 | `raise HexPatAggregateParseError(...)` aggregate without count log | `_logger.warning("hexpat_parse_failed", error_count=len(self._errors), file_path=self.file_path)` before raise |
| HIGH | 774 | sizeof/expression disambiguation backtrack | `_logger.debug("hexpat_parser_backtrack", context="sizeof", line=..., column=...)` |
| HIGH | 989 | placement vs expression statement | `_logger.debug("hexpat_parser_backtrack", context="placement_vs_expr")` |
| HIGH | 1034 | top-level placement vs expression statement | `_logger.debug("hexpat_parser_backtrack", context="top_level_placement")` |
| HIGH | 1055 | typed vs untyped const decl | `_logger.debug("hexpat_parser_backtrack", context="typed_const")` |

(Mirror the existing pattern at L840 `_logger.warning("hexpat_parser_cast_backtrack", ...)` — but at debug level since these are expected control-flow paths.)

### `src/intellicrack/core/hexpat/evaluator.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 966-968 | `_eval_try` user-level try/catch — `except (HexPatRuntimeError, HexPatTypeError):` no log | `_logger.debug("hexpat_try_caught", line=node.line, column=node.column)` |
| HIGH | 2589-2590 | `_sizeof_conditional_field` returns 0 on eval failure | `_logger.debug("hexpat_sizeof_conditional_eval_failed", line=node.line)` |
| HIGH | 2736-2738 | float-to-int cast raises HexPatRuntimeError w/o log | `_logger.warning("hexpat_float_to_int_conversion_failed", target_type=target_prim.name, error=str(exc))` before re-raise |

### `src/intellicrack/core/hexpat/stdlib.py`

Already covered by F02 (`_safe_int_from_str` helper for time/format builtins). Additional non-F02 sites:

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| MEDIUM | 1101-1105 | `_string_parse_int` — wrap to `HexPatRuntimeError` w/o log | `_logger.exception("hexpat_string_parse_int_failed", input=s, base=base)` before raise |
| MEDIUM | 1124-1128 | `_string_parse_float` — same pattern | `_logger.exception("hexpat_string_parse_float_failed", input=s)` before raise |

### `src/intellicrack/core/hexpat_compiler.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 803-806 | `compile_to_dict` `except HexPatError as exc:` re-wrap silently | `_logger.exception("hexpat_compile_preprocess_failed", file=exc.file, line=exc.line)` before re-raise |
| HIGH | 811-814 | `compile_to_dict` `except HexPatParseError as exc:` re-wrap silently | `_logger.exception("hexpat_compile_parse_failed", file=exc.file, line=exc.line)` before re-raise |

## Acceptance criteria

- [ ] All 6 `transform_pipeline.py` transform-node excepts log before re-raise
- [ ] All 3 `core/logging.py` bootstrap excepts log via lazy bootstrap logger
- [ ] All 3 `_pid_exists_posix` branches log at debug
- [ ] All 6 hexpat parser backtrack/aggregate sites log
- [ ] All 3 evaluator silent excepts log
- [ ] 2 stdlib parse_int/float sites log via `.exception(...)` before re-raise
- [ ] 2 hexpat_compiler wrap-and-reraise sites log via `.exception(...)`
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
