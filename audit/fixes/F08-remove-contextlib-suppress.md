# F08 — Remove `contextlib.suppress` (forbidden)

## Fix description

`contextlib.suppress` is forbidden by project memory (`feedback_no_silencing_warnings.md` and the general "no silent failures" rule). It must be replaced with an explicit try/except that logs at debug.

## Sites to fix

### `src/intellicrack/bridges/x64dbg.py:L2564`

Current:

```python
with contextlib.suppress(ValueError):
    self._step_waiters.remove(waiter)
```

(In `_cancel_step_waiter()`)

Fix:

```python
try:
    self._step_waiters.remove(waiter)
except ValueError as exc:
    _logger.debug("step_waiter_already_removed", waiter=id(waiter), error=str(exc))
```

## Verification

This regex should return zero matches across `src/intellicrack/`:

```
rg "contextlib\.suppress" src/intellicrack/
```

Note: `contextlib.contextmanager` (decorator) and `contextlib.closing` (mmap close) are NOT `contextlib.suppress` and are NOT forbidden. They appear legitimately in:

- `src/intellicrack/providers/base.py:L14` — `@contextlib.contextmanager` decorator (legitimate)
- `src/intellicrack/ui/panels/hex_editor/_base.py` — `contextlib.closing` on mmap (legitimate)
- `src/intellicrack/bridges/hex_editor.py:L7879` — `@contextlib.contextmanager` (legitimate)

## Acceptance criteria

- [ ] `bridges/x64dbg.py:L2564` rewritten as explicit try/except with debug log
- [ ] `rg "contextlib\.suppress" src/intellicrack/` returns zero matches
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
