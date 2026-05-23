# F16 — Silent `except` in provider files (not covered by F01)

## Fix description

Provider sites with silent excepts that don't fit the `_log_and_reraise` helper rollout (F01) — mostly static methods, ollama usage parsers, response decoders.

## Sites to fix

### `src/intellicrack/providers/ollama.py`

These are silent transport / parse failures that swallow context (not typed re-raises — those are in F01):

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 356-357 | `except (httpx.HTTPError, RuntimeError, UnicodeDecodeError):` returning `""` | `self._logger.debug("ollama_response_text_unreadable")` before return |
| HIGH | 1059-1060 | `_record_usage_from_openai_payload` — `except (TypeError, ValueError): return` | `self._logger.debug("openai_usage_parse_failed", error=str(...))` |
| HIGH | 1160-1161 | `_record_usage_from_chunk` — `prompt_tokens = 0` silently | Add `self._logger.debug("usage_prompt_tokens_parse_failed", error=str(exc))` |
| HIGH | 1163-1165 | `_record_usage_from_chunk` — `completion_tokens = 0` silently | Add `self._logger.debug("usage_completion_tokens_parse_failed", error=str(exc))` |

### `src/intellicrack/providers/huggingface.py`

Depends on F06 (module-level `_logger` added first):

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 287-288 | `@staticmethod _extract_503_message` — `except (json.JSONDecodeError, ValueError, UnicodeDecodeError, TypeError, httpx.DecodingError):` silently returns fallback string | Capture `as exc`, add `_logger.warning("hf_503_body_decode_failed", error_type=type(exc).__name__)` before return |

### `src/intellicrack/providers/openrouter.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 573-574 | `@staticmethod _build_usage_from_data` — `except (TypeError, ValueError): return None` | Requires module-level `_logger` (add via F06 if needed); capture `as exc`, add `_logger.warning("openrouter_usage_parse_failed", error_type=type(exc).__name__)` |

### `src/intellicrack/providers/local_transformers.py`

| Severity | Lines | Context | Fix |
|----------|-------|---------|-----|
| HIGH | 870-877 | CUDA `from_pretrained` failure path — outer raise without logging the original failure (only cleanup attempt logged) | Add `self._logger.warning("cuda_from_pretrained_failed", model_id=config.model_id, error=str(exc))` before the cleanup block |

## Acceptance criteria

- [ ] All 7 sites log before silent return / re-raise
- [ ] Module-level `_logger` added to huggingface.py and openrouter.py (per F06)
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
