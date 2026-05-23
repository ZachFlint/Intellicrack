# F10 — Convert `.warning(..., error=str(exc))` to `.exception(...)` inside non-re-raising except blocks

## Fix description

Per project memory: `_logger.warning(...)` is the correct level when re-raising (TRY400 conflict). When the except block **swallows the exception** (returns a default, sets a local variable, continues, etc.) without re-raising, `_logger.exception(...)` should be used so the traceback is preserved.

## Fix template

Before:

```python
except (OSError, RuntimeError) as exc:
    _logger.warning("operation_failed", error=str(exc))
    return []  # swallowed
```

After:

```python
except (OSError, RuntimeError):
    _logger.exception("operation_failed")
    return []
```

(`_logger.exception` automatically captures the current exception's traceback via `exc_info=True`; no need to pass `error=str(exc)` since the traceback contains it. Keep call-site context kwargs.)

## Sites to fix

### `src/intellicrack/bridges/hex_editor.py`

| Severity | Lines | Context |
|----------|-------|---------|
| LOW | 5856, 5976, 6038 | Native PE/Mach-O/ELF parse failures → return `[]` |
| LOW | 3945, 3995, 4007, 4057, 4081 | Similar parse fallbacks → return |
| LOW | 6382, 6482, 6610 | Rollback paths → return `[]` |

### `src/intellicrack/bridges/installer.py`

| Severity | Line | Context |
|----------|-----:|---------|
| LOW | 1807 | `_cmake_timeout` — `except ValueError` (does not capture `as exc`); add capture and use `.exception` |

### `src/intellicrack/bridges/frida_bridge.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 6748 | `compile_typescript` — `.warning` loses traceback for wrapped error |
| LOW | 1565-1572 | `spawn()` inner kill-leaked-process — currently `.warning`, consider `.exception` |

### `src/intellicrack/credentials/oauth.py`

| Severity | Lines | Context |
|----------|-------|---------|
| LOW | 997, 1002 | `token_refresh_*` — caught and return None (not re-raise) → `.exception` |

### `src/intellicrack/providers/discovery.py`

| Severity | Lines | Context |
|----------|-------|---------|
| LOW | 309, 405, 428 | I/O failures in `save_to_disk` / `load_from_disk` — `.warning` loses traceback |
| LOW | 641, 759 | `discover_one`, `discover_provider` — non-timeout transport failure |

### `src/intellicrack/core/logging.py`

| Severity | Line | Context |
|----------|-----:|---------|
| LOW | 747-753 | `OperationTimer.__exit__` — uses `.error` when exception is propagating; use `.exception` |

### `src/intellicrack/core/transform_pipeline.py`

| Severity | Lines | Context |
|----------|-------|---------|
| LOW | 135-138 | `_logger.error(...)` then raise — use `.warning` per TRY400 (no traceback available outside except) |

### `src/intellicrack/sandbox/windows.py`

| Severity | Lines | Context |
|----------|-------|---------|
| LOW | 1428, 1437 | `SandboxTimeoutError` / `SandboxError` caught, assigned to local result fields without re-raise → `.exception` |

### `src/intellicrack/ui/panels/hex_editor/panel.py`

| Severity | Line | Context |
|----------|-----:|---------|
| MEDIUM | 640 | `load_file` `.warning` → `.exception` (catches OSError, sets `result = None`, no re-raise) |

### `src/intellicrack/ui/panels/hex_editor/_transforms.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 923 | `_on_apply_arithmetic` — `.warning("arithmetic_bridge_failed", error=str(exc))` inside except that doesn't re-raise; convert to `.exception` |

### `src/intellicrack/ui/panels/hex_editor/_data_inspector.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 370 | `_on_encode_text` — `.warning("encode_text_bridge_failed", ...)` loses traceback; convert to `.exception` and include `error=str(exc)` |

### `src/intellicrack/ui/resources/font_manager.py`

| Severity | Line | Context |
|----------|-----:|---------|
| LOW | 119 | `font_loading_error` — caught (FileNotFoundError, PermissionError), no re-raise → `.exception` |

### `src/intellicrack/ui/xpu_status.py`

| Severity | Lines | Context |
|----------|-------|---------|
| LOW | 235, 263, 291, 317, 358, 374 | Uses `.debug(..., exc_info=True)` — acceptable but inconsistent; standardize to `.exception(...)` |

## Decision guidance

When deciding `.exception` vs `.warning`:

| Situation | Level |
|-----------|-------|
| Inside `except`, will re-raise the same exception | `.warning(event, error=str(exc))` (TRY400 — traceback will be logged at outer handler) |
| Inside `except`, swallows the exception (return / continue / set local) | `.exception(event)` |
| Inside `except`, raises a NEW exception via `raise NewError(...) from exc` | `.exception(event)` (the wrap loses the original traceback otherwise) |
| Outside `except`, validation error then `raise` | `.warning(event)` (no traceback to preserve) |
| Qt signal-delivered exception (no active traceback) | `.warning(event, error=str(exc), error_type=type(exc).__name__)` |

## Acceptance criteria

- [ ] All ~25 sites above audited and updated per the decision guidance
- [ ] Existing TRY400-correct usage (re-raise patterns) preserved
- [ ] `ruff check` clean (TRY400 warnings should go away after the fix)
- [ ] `basedpyright` clean
