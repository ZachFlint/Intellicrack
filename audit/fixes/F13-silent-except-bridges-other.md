# F13 — Silent `except` in other bridge files (installer / named_pipe / frida / x64dbg / hex_editor)

## Fix description

Mixed silent-except findings across the remaining bridge files. Most have one-off failure modes that need a single `_logger.debug/warning/exception` line before the swallow / re-raise.

## Sites to fix

### `src/intellicrack/bridges/installer.py`

| Severity | Lines | Function | Suggested fix |
|----------|-------|----------|---------------|
| HIGH | 422-425 | `_is_user_admin` | `except OSError as exc: _logger.debug("is_user_admin_check_failed", error=str(exc)); return False` |
| HIGH | 512-513 | `_read_pe_version_info` per-entry | `except (AttributeError, UnicodeError) as exc: _logger.debug("pe_version_decode_failed", exe=str(exe_path), key=key_name, error=str(exc)); continue` |
| HIGH | 1778-1779 | `_detect_vs_generator` cmake probe | `except (OSError, TimeoutExpired) as exc: _logger.warning("cmake_help_failed", cmake_path=str(cmake_path), error=str(exc)); return None` |
| HIGH | 2180-2181 | `_path_requires_admin` resolve | `except OSError as exc: _logger.debug("path_requires_admin_resolve_failed", target=str(target), error=str(exc)); return False` |
| HIGH | 2190-2192 | `_path_requires_admin` prefix-loop | `except (OSError, ValueError) as exc: _logger.debug("path_requires_admin_prefix_check_failed", prefix=prefix, error=str(exc)); continue` |

Plus LOW:

| LOW | 2207 | `logger = _logger` dead alias | Remove the alias (no callers use it) |

### `src/intellicrack/bridges/named_pipe_client.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 227-229 | `except Exception:` in `connect()` re-raise w/o log | `_logger.exception("pipe_connect_unexpected_error", pipe_name=pipe_name)` before `raise` |
| HIGH | 316-317 | `except (asyncio.CancelledError, ToolError, OSError): pass` in `close()` | Split into per-class except blocks; CancelledError debug-log; ToolError/OSError warning-log |
| HIGH | 441-442 | `except asyncio.CancelledError: raise` in `_reader_loop` | `_logger.debug("pipe_reader_cancelled")` before `raise` |
| MEDIUM | 295-332 | `close()` early-return when `self._handle is None` is silent | `_logger.debug("pipe_close_noop_already_disconnected")` before early return |

### `src/intellicrack/bridges/frida_bridge.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 4828-4829 | `set_exception_handler()` `except Exception as e:` raises `ToolError` w/o log | `_logger.warning("frida_exception_handler_create_failed", error=str(e), error_type=type(e).__name__)` before raise |
| HIGH | 5075-5076 | `stalker_add_call_probe()` same pattern | `_logger.warning("stalker_call_probe_create_failed", address=hex(validated_address), error=str(e), error_type=type(e).__name__)` |

(Note: `compile_typescript` L6748 is in F10 — `.warning` → `.exception`.)

### `src/intellicrack/bridges/x64dbg.py`

Already covered by F01 (typed-exception passthroughs) and F02 (`_safe_int_from_str`). Additional sites:

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 2208-2209 | `_cancel_all_step_waiters()` `except RuntimeError: continue` | `_logger.debug("step_waiter_loop_unavailable_on_cancel", waiter=id(waiter))` before continue |
| HIGH | 2526-2527 | `_resolve_step_waiters()` same pattern | `_logger.debug("step_waiter_loop_unavailable_on_resolve", waiter=id(waiter))` |
| HIGH | 2999-3005 | `except TimeoutError as exc:` in `_await_step_complete` raises new ToolError w/o log | `_logger.warning("x64dbg_step_timeout", command=command, timeout_s=self.STEP_TIMEOUT_SECONDS, error=str(exc))` before raise |
| HIGH | 3006-3008 | `except BaseException:` (bare-style) in `_await_step_complete` re-raise | `_logger.debug("x64dbg_step_cancelled", command=command, exc_info=True)` before raise |

### `src/intellicrack/bridges/hex_editor.py`

Already exemplary; the LOW findings about `.warning` → `.exception` are in F10.

## Acceptance criteria

- [ ] All listed silent-except sites emit a log before the swallow / re-raise
- [ ] `installer.py` `logger = _logger` alias removed
- [ ] `named_pipe_client.py:L316` split into per-exception handlers
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
