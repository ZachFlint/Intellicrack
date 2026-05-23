# F27 — Fix `run_bridge_coroutine_async(..., None, None, ...)` anti-pattern

## Fix description

The pattern `run_bridge_coroutine_async(self._bridge.X(...), None, None, self)` passes `None` for the error callback. Bridge failures fall back to the generic `async_bridge_worker_failed` log in `async_bridge.py` which lacks operation context (PID/TID/bridge-op-name).

Either (a) supply a contextful `_on_error` per call site, or (b) extend `run_bridge_coroutine_async` to accept an `operation_name` string that the generic fallback can include in its log.

## Recommended approach

Adopt the F03 `run_bridge_coroutine_logged` wrapper — it requires a structured `event=` and emits `<event>_started`/`<event>_failed` logs with operation context, eliminating the `None` callback anti-pattern.

Alternatively, extend the existing helper signature:

```python
def run_bridge_coroutine_async(
    coro: Coroutine[Any, Any, T],
    on_success: Callable[[T], None] | None,
    on_error: Callable[[BaseException], None] | None,
    parent: QObject,
    *,
    operation: str | None = None,  # NEW: operation name for context-light fallback log
) -> None:
    ...
    if on_error is None and operation is not None:
        def _default_error(exc: BaseException) -> None:
            _logger.warning(
                "async_bridge_worker_failed",
                operation=operation,
                error=str(exc),
                error_type=type(exc).__name__,
            )
        on_error = _default_error
    ...
```

## Sites to fix

`src/intellicrack/ui/panels/process_panel/_threads_tab.py`:

| Severity | Lines | Bridge call | Suggested operation_name |
|----------|-------|-------------|--------------------------|
| HIGH | 405-409 | `self._bridge.get_threads(self._attached_pid)` | `"threads_refresh"` (or full `_on_error`) |
| MEDIUM | 428-432 | `self._bridge.suspend(self._attached_pid)` | `"suspend_process"` — also add success log (significant mutation) |
| MEDIUM | 434-438 | `self._bridge.resume(self._attached_pid)` | `"resume_process"` |
| MEDIUM | 440-461 | `self._bridge.get_thread_context(tid)` | `"get_thread_context"` |
| MEDIUM | 504-540 | `self._bridge.set_thread_context(tid, regs)` | `"set_thread_context"` (significant mutation) |
| MEDIUM | 542-573 | `self._bridge.stack_walk(tid)` | `"stack_walk"` |
| MEDIUM | 575-603 | `self._bridge.get_seh_chain(tid)` | `"seh_enumerate"` |
| MEDIUM | 605-625 | `self._bridge.get_fiber_data(tid)` | `"fiber_query"` |
| MEDIUM | 627-653 | `self._bridge.get_tls_values(tid)` | `"tls_values"` |

## Recommended migration

For consistency, migrate all 9 `_threads_tab.py` call sites to `run_bridge_coroutine_logged` (F03) — that closes the None-callback anti-pattern AND the missing entry-log gap in one change.

## Acceptance criteria

- [ ] All 9 `_threads_tab.py` call sites use either F03 wrapper or supply a contextful `_on_error`
- [ ] `rg "run_bridge_coroutine_async\(.*None, None" src/intellicrack/` returns zero matches
- [ ] Significant mutations (suspend_thread, resume_thread, set_thread_context) log at info on success
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
