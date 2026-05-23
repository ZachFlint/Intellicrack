# Shard 11 — AI providers (cloud) + remaining core analysis

- **Files audited**: 11
- **Total LOC**: 7844
- **Generated**: 2026-05-22T00:00:00Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 9     |
| MEDIUM   | 1     |
| LOW      | 4     |

- Files missing module-level `_logger`: 4 (anthropic.py, grok.py, huggingface.py, openai.py, openrouter.py — all permitted by LLMProviderBase exception; however huggingface.py has *module-level* helper functions that cannot access `self._logger`, which is an issue)
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0 (note: `contextlib.contextmanager` is used in `base.py` line 948 — not the same as `suppress`; legitimate)
- Files with bare `except` (no log): 5 — base.py, anthropic.py, google.py, huggingface.py, openrouter.py

## Findings by file

### src/intellicrack/providers/**init**.py — LOC 100

**Logger status**: `missing` (file is pure re-exports — exempt per §4)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none — file contains only re-exports and `__all__` declaration, exempt per §4.

---

### src/intellicrack/providers/base.py — LOC 1270

**Logger status**: `module-level _logger` (line 50) — additionally, `LLMProviderBase` sets `self._logger = get_logger(__name__)` in `__init__` (line 286), establishing the documented LLMProviderBase exception for subclasses.

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L508-509 — `except AuthenticationError: raise` inside `_retry_with_backoff` re-raises with **no log call**. Fix: add `self._logger.warning("provider_retry_auth_failed", attempt=attempt + 1)` before `raise` (or `self._logger.exception(...)`).
- [LOW] L513-522 — Retry backoff warning is logged on retryable exceptions, which is correct, but a corresponding event when the retry budget is exhausted (the `if attempt >= max_retries: raise` branch on L511-512) is silently re-raised. Fix: add `self._logger.error("provider_retry_exhausted", attempts=attempt, error=str(exc))` before the `raise` to surface failure mode visibly.

Remaining `except` blocks (L996, L999, L1002, L1005, L1044, L181) all log appropriately. The `@contextlib.contextmanager` import at L14 is for the legitimate decorator, not `contextlib.suppress`.

---

### src/intellicrack/providers/anthropic.py — LOC 822

**Logger status**: `instance-level self._logger (LLMProvider exception)` — `AnthropicProvider(LLMProviderBase)` rebinds `self._logger = get_logger(__name__).bind(provider="anthropic")` at line 76. Permitted.

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L462-471 — `except anthropic.APIStatusError as e:` logs only the `status_code >= 500` path. The fall-through `raise` at L471 (re-raising the original APIStatusError for non-5xx, non-rate-limit failures such as 400/401/404) executes with **no log call**. Fix: add `self._logger.warning("anthropic_api_status_error_passthrough", status_code=status_code, error=str(e))` before the bare `raise`.
- [HIGH] L572-573 — `except RateLimitError: raise` in `chat()` re-raises without logging. Fix: add `self._logger.warning("anthropic_chat_rate_limited_passthrough", model=model)` before `raise` (or upgrade to `self._logger.exception(...)`).

Remaining except blocks (L107, L110, L128, L149, L459, L574, L671, L674, L690) all log appropriately. No f-string/`%`/`.format()` formatting in any logger call. HTTP POST/SDK calls are surrounded by `log_provider_request`/`log_provider_response` plus `_logger.info`/`debug` entries.

---

### src/intellicrack/providers/google.py — LOC 1010

**Logger status**: dual — module-level `_logger` (L71) AND `self._logger` (L85) inside the LLMProviderBase subclass. The module-level logger is used only inside `@staticmethod _check_safety_block` (L607, L622, L625), which cannot access `self`. Permitted as a controlled fallback for static methods.

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L375-376 — `except (AuthenticationError, ProviderError, RateLimitError): raise` re-raises without logging in `chat()`. Fix: add `self._logger.warning("google_chat_typed_exception_passthrough", model=model)` (or `.exception(...)`) before `raise`.
- [HIGH] L511-512 — Same pattern in `chat_stream()`: `except (AuthenticationError, ProviderError, RateLimitError): raise` — no log. Fix: add `self._logger.warning("google_chat_stream_typed_exception_passthrough", model=model, chunks_received=chunk_count)` before `raise`.
- [HIGH] L663-673 — `_call_generate_content` `except APIError as exc:` logs only the rate-limit/5xx branch. The fall-through `raise` at L673 (for 4xx codes that aren't rate-limited) executes with **no log call**. Fix: add `self._logger.warning("google_api_error_passthrough", model=model, code=code, error=str(exc))` before the bare `raise`.

Remaining except blocks all log. The f-strings at L606, L621, L624 are inside *exception message construction* (`msg = f"..."` then `raise ProviderError(msg)`), which is legitimate per §1 — only logger calls themselves must avoid f-strings.

---

### src/intellicrack/providers/grok.py — LOC 940

**Logger status**: `instance-level self._logger (LLMProvider exception)` — `GrokProvider(LLMProviderBase)` rebinds `self._logger = get_logger(__name__).bind(provider="grok")` at line 115. Permitted.

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**: none.

All `except` blocks (L148, L153, L161, L178, L283, L884, L887, L890, L893) log structured warnings before re-raising as typed errors. `chat()` relies on `_translate_openai_errors` (defined in base.py) for SDK exception logging, which logs appropriately. All HTTP API calls (`client.models.list`, `chat.completions.create`) are surrounded by `_logger.info("grok_provider_initialized")`, `log_provider_request`, and structured response logs.

---

### src/intellicrack/providers/huggingface.py — LOC 937

**Logger status**: `instance-level self._logger (LLMProvider exception)` — `HuggingFaceProvider(LLMProviderBase)` rebinds at line 184. Permitted for instance methods. **However**, this file also contains module-level helper functions and a `@staticmethod` that cannot access `self._logger`, and there is no module-level `_logger`. This is a coverage gap.

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L287-288 — In `@staticmethod _extract_503_message`, `except (json.JSONDecodeError, ValueError, UnicodeDecodeError, TypeError, httpx.DecodingError): return "Model is loading and not yet ready"` swallows the exception silently with **no log call**. Fix: add a module-level `_logger = get_logger(__name__)` at module scope, then `_logger.warning("hf_503_body_decode_failed", error_type=type(exc).__name__)` inside the except (will require capturing `as exc`).
- [MEDIUM] Module-scope — Missing module-level `_logger`. Helper functions `_convert_tool_choice` (L853), `_parse_message_tool_calls` (L878), `_extract_stream_delta` (L902), and the static `_extract_503_message` (L262) have no path to logging. Fix: add `_logger = get_logger(__name__)` at module scope (e.g. after L130).
- [LOW] L901-931 — `_extract_stream_delta` walks the streamed chunk and parses every tool-call delta with no log statements. Since this is hot-path stream processing, a debug log on first tool-call delta seen per chunk would aid debugging. Mark LOW because perf considerations apply.

Remaining except blocks (L232, L243, L305, L362, L371, L552, L555, L558, L568, L575, L688, L691, L694, L704, L711, L756, L763, L770, L780, L794) all log appropriately. Streaming `chat_completion` calls have surrounding `log_provider_request` (L532), `self._logger.info("huggingface_stream_started", ...)` (L667), and completion logs (L600, L750).

---

### src/intellicrack/providers/openai.py — LOC 932

**Logger status**: `instance-level self._logger (LLMProvider exception)` — `OpenAIProvider(LLMProviderBase)` rebinds at L121. Permitted.

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**: none.

Every except block (L154, L162, L187, L291, L876, L879, L882, L885) logs structured warnings before re-raising. `_make_openai_api_call` (L622-776) wraps every SDK invocation in `_translate_openai_errors` (base.py L948), which centralises SDK exception logging. Stream path L840-892 has surrounding `_logger.info("openai_stream_started", ...)` semantics via `log_provider_request` (L361) and the comprehensive `_logger.debug("openai_api_call_starting", ...)` (L664) at API call site. No f-strings, no `%`, no `.format()` in any logger call.

---

### src/intellicrack/providers/openrouter.py — LOC 850

**Logger status**: `instance-level self._logger (LLMProvider exception)` — `OpenRouterProvider(LLMProviderBase)` rebinds at L85. Permitted.

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L573-574 — `_build_usage_from_data` `except (TypeError, ValueError): return None` swallows parse failure silently with **no log call**. Because this is a `@staticmethod` it cannot use `self._logger`. Fix: add a module-level `_logger = get_logger(__name__)` and `_logger.warning("openrouter_usage_parse_failed", error_type=type(exc).__name__)` (capture `as exc`).
- [HIGH] L749-750 — `except (AuthenticationError, RateLimitError, ProviderError): raise` in `chat_stream()` re-raises without logging. Fix: add `self._logger.warning("openrouter_chat_stream_typed_exception_passthrough", model=model, chunks_yielded=chunks_yielded)` before `raise`.

Remaining except blocks (L118, L138, L150, L175, L209, L215, L247, L425, L434, L751, L842) all log. HTTP calls — `client.get` (L136, L192, L832), `client.post` (L421), `client.stream` (L692) — all have surrounding `_logger.info`/`warning` events. `_logger.info("openrouter_chat_started", ...)` (L308) and `_logger.info("openrouter_chat_completed", ...)` (L380) bracket the chat path.

---

### src/intellicrack/core/disassembler.py — LOC 426

**Logger status**: `module-level _logger` (L25)

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**: none.

All except blocks log: L32-33 (`except ImportError: _logger.warning(...)`), L404 (`except (ValueError, OSError, AttributeError): _logger.debug(..., exc_info=True)`). Every public method (`disassemble`, `disassemble_to_lines`, `auto_detect_arch`, `get_supported_architectures`) emits `_logger.debug` at entry with full context kwargs and (where applicable) at completion. Capstone library load is logged at L33 and L137. No f-strings, no print, no stdlib logging, no suppress.

---

### src/intellicrack/core/yara_scanner.py — LOC 301

**Logger status**: `module-level _logger` (L24)

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [HIGH] L132-134 — `compile_rules` `except (ValueError, OSError, RuntimeError) as exc: msg = f"YARA compilation failed: {exc}"; raise ValueError(msg) from exc` — re-raises as `ValueError` with **no log call**. Fix: `_logger.exception("yara_compile_failed", file_count=len(filepaths))` before constructing `msg` and raising.
- [HIGH] L160-162 — `compile_source` has the same pattern: `except (ValueError, OSError, RuntimeError) as exc: msg = ...; raise ValueError(msg) from exc` — no log. Fix: `_logger.exception("yara_compile_source_failed", namespace=namespace)` before raising.
- [LOW] L185 (`scan_data`) and L208 (`scan_file`) — public scan methods log debug entry but do not log completion (match count). Fix: add `_logger.debug("yara_data_scan_complete", matches=len(raw_matches))` after the `rules.match(...)` call. Minor — entry log is present.

The yara module import at L31-37 logs `yara_module_import_failed` at debug — consistent with the optional-dependency pattern used elsewhere. `_convert_matches` (L242) is pure data conversion with no I/O so no logging needed.

---

### src/intellicrack/core/analysis_aggregator.py — LOC 256

**Logger status**: `module-level _logger` (L31)

**Imports `from intellicrack.core.logging import get_logger`**: yes

**Findings**:

- [LOW] L210 (`_deduplicate_imports`) and L235 (`_deduplicate_exports`) — Module-private helpers with no logging. They process potentially large lists of imports/exports from bridges; a single debug log noting input/output counts would help diagnose mis-aggregation. Optional — these functions are deterministic and well-tested by their consumer.

All `try`/`except` blocks (L150-154, L158-168, L170-180, L182-192, L194-204) log appropriately with structured kwargs. Public `aggregate()` method logs `aggregation_starting` (L71) and `aggregation_completed` (L107) with full context. Bridge call wiring (L80-97) per §2.3 (bridge invocations) is logged.

---

## Aggregate notes

### Patterns observed across multiple files

1. **`raise` (bare re-raise) after partial-match log** — Found in `base.py` L508-509, `anthropic.py` L471, L572-573, `google.py` L375-376, L511-512, L673, `openrouter.py` L749-750. The pattern is `except (TypedException1, TypedException2): raise` to let already-translated exceptions propagate. Per §2.2, every except clause must log, even when re-raising. Suggested fix: add a brief `self._logger.warning("..._passthrough", ...)` (or `.debug` if noise is a concern) before the bare `raise` to record the propagation.

2. **Silent exception swallowing in static methods that lack `self._logger`** — `huggingface.py` `_extract_503_message` (L287) and `openrouter.py` `_build_usage_from_data` (L573) swallow exceptions and return fallback values without logging because they are `@staticmethod` inside an LLMProviderBase subclass and the surrounding file has no module-level `_logger`. The fix is uniform: add `_logger = get_logger(__name__)` at module scope (this does **not** conflict with the LLMProviderBase `self._logger` exception — the two coexist), then log inside those except blocks.

3. **`ValueError(msg)` chained from caught exception without log** — `yara_scanner.py` L132-134 and L160-162. The pattern preserves the original via `from exc` but no log line is emitted, making failure invisible to operators. Add `_logger.exception("yara_compile_failed", ...)` before raising.

### Cross-file recommendations

- **Add module-level `_logger`** to `huggingface.py` and `openrouter.py`. Both files need it for static methods and module-level helpers. This is additive and does not affect the LLMProviderBase `self._logger` exception.
- **Standardise passthrough logging** for `except TypedException: raise` patterns. A consistent helper or convention (e.g., always `self._logger.warning("<provider>_<op>_typed_exception_passthrough", ...)`) would reduce ambiguity and make grep-based audits simpler.
- **Provider classes' coverage** is otherwise excellent. Streaming paths, retry logic, cancellation, rate-limiting, and SDK-error translation are all well-instrumented with structured kwargs. The exception logging gaps are confined to the few "no-op passthrough" except clauses identified above.

### Files where the audit was difficult

- `grok.py` and `openai.py` — Each has very long mechanical `if/elif` ladders in `_dispatch_grok_create` / `_open_grok_stream` / `_open_openai_stream` / `_make_openai_api_call` that select between `max_tokens` vs `max_completion_tokens` overloads. These are wrapped by `_translate_openai_errors` (base.py L948) which provides centralised SDK exception logging, so individual `client.chat.completions.create(...)` calls do not need surrounding log statements at the call site. Auditor verified this delegation is consistent throughout.
- `huggingface.py` `_extract_stream_delta` — Hot-path streaming function with no logging. Marked LOW since perf considerations apply to per-chunk log statements.
