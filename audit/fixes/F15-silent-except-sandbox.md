# F15 — Silent `except` in `sandbox/qemu.py` and `sandbox/windows.py`

## Fix description

6 silent-except sites across the two sandbox backends. Mostly polling helpers (intentional pattern) and yara ImportError re-raises (both backends share the pattern).

## Sites to fix

### `src/intellicrack/sandbox/qemu.py`

| Severity | Lines | Context | Suggested fix |
|----------|-------|---------|---------------|
| HIGH | 2900-2901 | `_stat_size` helper of `_wait_for_logs_stable` — `except FileNotFoundError: return 0` | `_logger.debug("logs_stable_stat_missing", path=str(path))` before return 0 |
| HIGH | 3168-3170 | `_wait_for_ppm_stable` — `except FileNotFoundError: await asyncio.sleep(...); continue` | `_logger.debug("ppm_stat_missing", ppm_path=str(ppm_path))` before sleep |
| HIGH | 3601-3604 | `yara_scan` `except ImportError as exc: raise SandboxError(_ERR_YARA_NOT_AVAILABLE) from exc` | `_logger.warning("yara_python_not_installed", error=str(exc))` before re-raise |

### `src/intellicrack/sandbox/windows.py`

| Severity | Lines | Context | Suggested fix |
|----------|-------|---------|---------------|
| HIGH | 1501-1502 | `_wait_for_monitor_quiescence` — `except OSError: break` | `_logger.warning("monitor_quiescence_stat_failed")` (or `.debug` if poll race expected) |
| HIGH | 2193-2196 | `yara_scan` `except ImportError as exc:` re-raise SandboxError | `_logger.warning("yara_python_not_installed", error=str(exc))` before re-raise |
| HIGH | 2478-2479 | `_win_handle_from_file` — `except (OSError, ValueError, AttributeError): return None` | `_logger.warning("win_handle_from_file_failed", exc_info=True)` before return None |

## Pattern recommendation: consolidate yara ImportError

Both `qemu.py:3601` and `windows.py:2193` use the same `except ImportError as exc: raise SandboxError(...) from exc` pattern. Consider consolidating to a single helper like `core/_optional_imports.py`:

```python
def require_yara() -> ModuleType:
    """Import yara-python or raise SandboxError with structured logging."""
    try:
        import yara  # type: ignore[import-untyped]
    except ImportError as exc:
        _logger.warning("yara_python_not_installed", error=str(exc))
        raise SandboxError(_ERR_YARA_NOT_AVAILABLE) from exc
    return yara
```

## Acceptance criteria

- [ ] 3 qemu.py silent excepts log before swallow/re-raise
- [ ] 3 windows.py silent excepts log before swallow/re-raise
- [ ] (Optional) Consolidate yara ImportError into a shared helper
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
