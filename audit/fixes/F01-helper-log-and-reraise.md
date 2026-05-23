# F01 — Typed-exception passthrough: `_log_and_reraise` helper

## Fix description

The pattern `except (TypedException1, TypedException2): raise` re-raises an already-translated exception without logging. Per §2.2 every except clause must log even when re-raising. This affects providers, bridges, and some sandbox code.

Closes ~35 HIGH findings in one helper rollout.

## Helper template

Add to `src/intellicrack/providers/base.py` (or a shared util module):

```python
def _log_and_reraise(
    logger: structlog.stdlib.BoundLogger,
    event: str,
    exc: BaseException,
    **context: Any,
) -> NoReturn:
    """Log a passthrough re-raise event then re-raise the exception unchanged.

    Args:
        logger: Logger to emit on.
        event: Stable snake_case event name (e.g. "ollama_list_tags_passthrough").
        exc: Exception being re-raised.
        **context: Additional structured kwargs (provider, model, etc.).

    Raises:
        BaseException: The original exception, unchanged.
    """
    logger.warning(event, error=str(exc), error_type=type(exc).__name__, **context)
    raise exc
```

Then the pattern at every site becomes:

```python
except (AuthenticationError, ProviderError, RateLimitError) as exc:
    _log_and_reraise(self._logger, "<provider>_<op>_passthrough", exc, model=model)
```

## Sites to fix

### `src/intellicrack/providers/base.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 508 | `except AuthenticationError: raise` in `_retry_with_backoff` |

### `src/intellicrack/providers/anthropic.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 471 | `except anthropic.APIStatusError as e:` fall-through `raise` (non-5xx, non-rate-limit branch) |
| HIGH | 572 | `except RateLimitError: raise` in `chat()` |

### `src/intellicrack/providers/google.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 375 | `except (AuthenticationError, ProviderError, RateLimitError): raise` in `chat()` |
| HIGH | 511 | Same pattern in `chat_stream()` |
| HIGH | 673 | `_call_generate_content` `except APIError as exc:` fall-through `raise` |

### `src/intellicrack/providers/openrouter.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 749 | `except (AuthenticationError, RateLimitError, ProviderError): raise` in `chat_stream()` |

### `src/intellicrack/providers/ollama.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 416 | `except ProviderError: raise` in `list_tags` |
| HIGH | 418 | `except (ConnectionError, ...) as exc:` raises `ProviderError` w/o log |
| HIGH | 447 | `except ProviderError: raise` in `list_running_models` |
| HIGH | 449 | Same `except (ConnectionError, ...)` pattern |
| HIGH | 480 | `except ProviderError: raise` in `show_model` |
| HIGH | 482 | Same `except (ConnectionError, ...)` pattern |
| HIGH | 1328 | `except (AuthenticationError, RateLimitError, ProviderError): raise` in `_stream_native` |
| HIGH | 1483 | Same pattern in `_stream_openai_compatible` |
| HIGH | 1653 | Same pattern in `pull_model` |

### `src/intellicrack/providers/local_transformers.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 527 | `chat()` raises `ProviderError(_MSG_NOT_CONNECTED)` with no prior log |
| HIGH | 530 | `chat()` raises `ProviderError(_ERR_EMPTY_MODEL)` with no prior log |
| HIGH | 545 | `chat()` raises `ProviderError(_MSG_NO_MODEL_LOADED)` with no prior log |
| HIGH | 630 | `chat_stream()` same `_MSG_NOT_CONNECTED` |
| HIGH | 633 | `chat_stream()` same `_ERR_EMPTY_MODEL` |
| HIGH | 648 | `chat_stream()` same `_MSG_NO_MODEL_LOADED` |
| HIGH | 870 | `except (RuntimeError, ImportError, ValueError, OSError):` outer raise without log |

### `src/intellicrack/bridges/x64dbg.py` — `_x64dbg_error_code(exc) != UNKNOWN_COMMAND` arm

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 3219 | `_verify_breakpoint_applied()` |
| HIGH | 5026 | `_wait_for_instruction_pointer()` |
| HIGH | 5070 | `_lookup_annotation_text()` |
| HIGH | 5140 | `_query_bp_list()` |
| HIGH | 5230 | `_query_thread_details()` |
| HIGH | 5331 | `_wait_for_running_state()` |
| HIGH | 5375 | `_query_script_error()` |
| HIGH | 5406 | `_query_plugin_present()` (first arm) |
| HIGH | 5420 | `_query_plugin_present()` (second arm) |

### `src/intellicrack/bridges/frida_bridge.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 4828 | `set_exception_handler()` `except Exception as e:` re-raise w/o log |
| HIGH | 5075 | `stalker_add_call_probe()` `except Exception as e:` re-raise w/o log |

### `src/intellicrack/bridges/named_pipe_client.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 227 | `except Exception:` in `connect()` re-raise w/o log (use `.exception` here) |
| HIGH | 441 | `except asyncio.CancelledError: raise` in `_reader_loop()` |

### `src/intellicrack/core/yara_scanner.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 132 | `compile_rules` `except (ValueError, OSError, RuntimeError) as exc: raise ValueError(msg) from exc` (no log) |
| HIGH | 160 | `compile_source` same pattern |

### `src/intellicrack/core/hexpat_compiler.py`

| Severity | Line | Context |
|----------|-----:|---------|
| HIGH | 803 | `compile_to_dict` `except HexPatError as exc:` re-wrap w/o log |
| HIGH | 811 | `compile_to_dict` `except HexPatParseError as exc:` re-wrap w/o log |

## Acceptance criteria

- [ ] `_log_and_reraise` helper added (with type hints, docstring)
- [ ] All ~35 sites above updated to use the helper (or equivalent inline `logger.warning(...) + raise` if helper unsuitable)
- [ ] Each call passes meaningful structured kwargs (provider, model, op, etc.)
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
- [ ] `pydoclint` + `pydocstyle` clean on the new helper

## Why

Before fix: silent passthrough re-raises lose the local context (which provider, which model, what op) — downstream loggers see only the wrapped exception type.
After fix: every re-raise emits a structured `<provider>_<op>_passthrough` event with `error`, `error_type`, plus call-site context kwargs.
