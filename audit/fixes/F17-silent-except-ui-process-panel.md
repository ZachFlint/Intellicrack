# F17 — Silent `except` in `ui/panels/process_panel/`

## Fix description

6 HIGH sites in process_panel tabs where `except ToolError: return None` or `_on_error` UI handlers fail silently (QMessageBox without log).

The commit `6bab435e` established the right pattern (QMessageBox + logger) for the memory tab; modules tab and threads tab need the same uplift.

## Sites to fix

### `src/intellicrack/ui/panels/process_panel/_base.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 256-260 | `_refresh_arch_label._detect` — `except ToolError: return None` silent | `_logger.warning("arch_detection_failed", pid=pid, error=str(...))` before return None |
| HIGH | 276-280 | `_refresh_privilege_label._fetch_privs` — same silent ToolError swallow | `_logger.warning("privilege_fetch_failed", pid=pid, error=str(...))` |

### `src/intellicrack/ui/panels/process_panel/_modules_tab.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 405-406 | `_refresh_handles._on_error(exc)` — QMessageBox only | `_logger.warning("handles_enumerate_failed", pid=self._attached_pid, error=str(exc))` before the QMessageBox |
| HIGH | 431-432 | `_refresh_heaps._on_error(exc)` — same | `_logger.warning("heaps_enumerate_failed", pid=..., error=str(exc))` |
| HIGH | 455-456 | `_refresh_com._on_error(exc)` — same | `_logger.warning("com_enumerate_failed", pid=..., error=str(exc))` |
| HIGH | 479-480 | `_refresh_dotnet._on_error(exc)` — same | `_logger.warning("dotnet_detect_failed", pid=..., error=str(exc))` |

Plus MEDIUM `%`-formatting violation:

| Severity | Line | Context | Fix |
|----------|-----:|---------|-----|
| MEDIUM | 329 | `_logger.warning("Module enumeration failed: %s", exc)` | Change to `_logger.warning("module_enumeration_failed", error=str(exc))` |

### `src/intellicrack/ui/panels/process_panel/_threads_tab.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 482-485 | `_on_reg_cell_changed` — `except ValueError: return` silent | `_logger.debug("register_cell_parse_failed", raw=raw, row=row, col=col)` |

Plus a coverage issue addressed in F27 (run_bridge_coroutine_async None error callbacks).

### `src/intellicrack/ui/panels/process_panel/_system_tab.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| LOW | 905-907 | `_on_raw_query._on_success` — `except ValueError: setPlainText(result); return` silent | `_logger.debug("raw_query_hex_parse_failed", length=len(result))` |

## Acceptance criteria

- [ ] All 6 HIGH sites log before silent return / QMessageBox
- [ ] L329 `%` formatting converted to structured kwargs
- [ ] LOW system_tab hex parse swallow logged at debug
- [ ] Pattern is consistent across all tabs (matches `6bab435e` memory tab pattern)
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
