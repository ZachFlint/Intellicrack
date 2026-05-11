> # Workgroup Directive — Execution Order 18/23: `providers-cloud`
>
> Spawn a multi-agent workgroup to drive **every F-#### finding below** to
> production release-ready. The workgroup must run this pipeline for every
> finding in this file:
>
> 1. **`developer`** agents (in parallel where findings touch disjoint
>    files) — implement the full fix per the finding's `Suggested
>    remediation summary`. No placeholders, mocks, stubs, hardcoded
>    returns, or fake-success paths. Re-verify each finding against the
>    cited source/lines before fixing; if already resolved, annotate
>    `[obsolete]` with the resolving commit hash and move on.
> 2. **`code-reviewer`** — verify each fix actually addresses the failure
>    mode described in `Why this is non-functional` and audit every caller
>    listed under `Callers / blast radius` for regressions.
> 3. **`test-writer`** — author production-grade tests that fail without
>    the fix and pass with it. Tests must execute against real binaries,
>    real bridges, and real protocols. No mocks of the unit under test.
> 4. **`test-reviewer`** — confirm tests genuinely validate the fix and
>    meet Intellicrack's no-mock standard.
> 5. **`linter`** — run `ruff check`, `basedpyright`, `pydoclint`, and
>    `pydocstyle`; resolve every finding without suppression directives.
>
> Hard constraints (non-negotiable):
>
> - Production-ready and immediately deployable; zero placeholders, mocks,
>   stubs, simulated implementations, or fake-success returns.
> - `ruff check` clean, fully `basedpyright` compliant, `pydoclint` and
>   `pydocstyle` clean — no inline suppression directives of any kind.
> - Windows-first compatibility, preserve existing functionality, never
>   delete a method binding — implement the missing function instead.
> - When this file is fully processed, every F-#### below must be either
>   fixed-and-tested or annotated `[obsolete]` with the resolving commit.
> - **All work for this file ships as one single PR (one PR per prompt /
>   per file).** Every F-#### in this file must be batched into the same
>   PR — do not split findings across multiple PRs, and do not merge any
>   subset until the whole file is fixed-and-tested or annotated
>   `[obsolete]`.
>
> ---
>
# Findings: providers-cloud

## Files audited (6)

- src/intellicrack/providers/base.py
- src/intellicrack/providers/anthropic.py
- src/intellicrack/providers/openai.py
- src/intellicrack/providers/google.py
- src/intellicrack/providers/grok.py
- src/intellicrack/providers/openrouter.py

## Critical-path verification

All provider `chat()` / `chat_stream()` paths invoke real SDK calls:

- Anthropic: `self._client.messages.create(...)` and `self._client.messages.stream(...)`
- OpenAI: `self.client.chat.completions.create(...)` non-stream and stream
- Google: `client.aio.models.generate_content(...)` and `generate_content_stream(...)`
- Grok: `self.client.chat.completions.create(...)` via openai SDK at `https://api.x.ai/v1`
- OpenRouter: `self.client.post(...)` and `self.client.stream("POST", ...)` httpx to `https://openrouter.ai/api/v1`

Streaming verified incremental (yields per chunk inside `async for`) in all 5 providers. Tool-use round-trip implemented bidirectionally. Usage tokens extracted from real response/chunk objects. Errors translated into typed exceptions.

## Findings

### Category 12 - Configuration / Silently Dropped Parameters

#### F-0001 - `enable_cache` accepted but silently discarded in OpenAI/Grok/OpenRouter/Google

- **Files:** `openai.py:326-327, 466-467`, `grok.py:332-333, 492-493`, `openrouter.py:327-328, 516-517`, `google.py:292-293`
- **Pattern:** Cat 12, Cat 17
- **Excerpt:**

  ```python
  if enable_cache:
      self._logger.debug("openai_cache_ignored")
  ```

- **Why this is non-functional:** `enable_cache=True` is part of the public API contract on `LLMProviderBase`. Anthropic implements it; OpenAI/OpenRouter/Grok/Google accept it, log debug, throw away. None wire it into the SDK call.

#### F-0002 - `thinking` config silently discarded in OpenAI/Grok/OpenRouter/Google

- **Files:** `openai.py:324-325, 464-465`, `grok.py:330-331, 490-491`, `openrouter.py:325-326, 514-515`, `google.py:290-291, 415`
- **Pattern:** Cat 12, Cat 17
- **Excerpt:**

  ```python
  if thinking is not None and thinking.enabled:
      self._logger.debug("google_thinking_ignored")
  ```

- **Why this is non-functional:** Gemini 2.5, OpenAI o-series, and Grok-4 all support reasoning/thinking budgets. Only Anthropic wires `ThinkingConfig` correctly.

### Category 7 - Cancellation That Doesn't Cancel

#### F-0003 - `cancel_request()` is a no-op for non-streaming `chat()` in 4 of 5 providers

- **Files:** `anthropic.py:591-598`, `openai.py:553-561`, `grok.py:614-623`, `openrouter.py:617-620`
- **Pattern:** Cat 7, Cat 17
- **Excerpt:**

  ```python
  async def cancel_request(self) -> None:
      """Cancel any in-flight request."""
      self._cancel_requested = True
      had_task = False
      if self._current_task is not None and not self._current_task.done():
          self._current_task.cancel()
          had_task = True
      self._logger.info("anthropic_request_cancelled", had_active_task=had_task)
  ```

- **Why this is non-functional:** `_current_task` is never assigned during `chat()` or `chat_stream()` for these providers. Cancel only flips a boolean checked inside streaming `async for` loops. Non-streaming `chat()` calls cannot be cancelled.

### Category 24 - Inconsistent Retry Handling

#### F-0004 - `_retry_with_backoff` only used by Anthropic and OpenAI; Grok/Google/OpenRouter never retry on rate limits

- **Files:** `grok.py:342-350`, `google.py:320-329`, `openrouter.py:330-334`
- **Pattern:** Cat 24
- **Why this is non-functional:** `LLMProviderBase._retry_with_backoff` is the standard transient-failure handler. Three providers call SDK directly with no retry wrapper.

### Category 4 - Partial Implementation

#### F-0005 - Anthropic `enable_cache` only caches the system prompt, never tools or messages

- **File:** `src/intellicrack/providers/anthropic.py`
- **Lines:** 268-275
- **Pattern:** Cat 4
- **Why this is non-functional:** Anthropic supports cache_control on system prompts, tool definitions, AND messages. Implementation only handles system prompt - missing largest savings opportunity.

### Category 5 - Silently Swallowed Errors During Cancel

#### F-0006 - OpenAI `chat_stream` swallows transport errors when `_cancel_requested` is set

- **File:** `src/intellicrack/providers/openai.py`
- **Lines:** 548-551
- **Pattern:** Cat 5
- **Excerpt:**

  ```python
  except (ConnectionError, TimeoutError, OSError, ValueError) as e:
      if not self._cancel_requested:
          self._logger.warning("openai_stream_failed", model=model, error=str(e))
          raise ProviderError(_ERR_STREAM_FAILED % e) from e
  ```

- **Why this is non-functional:** Same swallow-on-cancel pattern in anthropic, grok, openrouter, google. Genuine errors coinciding with cancel are silently dropped.

### Category 19 - Invalid Input Fall-Through

#### F-0007 - `_convert_tool_choice_to_openai_format` produces empty function name when SPECIFIC mode lacks `function_name`

- **File:** `src/intellicrack/providers/base.py`
- **Lines:** 685-688
- **Pattern:** Cat 19, Cat 5
- **Excerpt:**

  ```python
  return {
      "type": "function",
      "function": {"name": tool_choice.function_name or ""},
  }
  ```

- **Why this is non-functional:** Sends invalid request to API rather than validating with typed `ProviderError("function_name required")`.

### Category 20 - Unused Workflow Surface

#### F-0008 - `get_pending_usage()` / `get_pending_thinking()` populated by every provider but never consumed

- **File:** `src/intellicrack/providers/base.py`
- **Lines:** 390-422
- **Pattern:** Cat 20
- **Why this is non-functional:** Every provider sets `_pending_usage` after every chat/stream. `rg "get_pending_usage|get_pending_thinking" src/intellicrack/` finds zero non-test consumers. Token usage and thinking transcripts captured but discarded.

### Category 4 - DRY Violation

#### F-0009 - Three identical `_convert_tools_to_provider_format` implementations across openai/grok/openrouter

- **Files:** `openai.py:591-595`, `grok.py:653-657`, `openrouter.py:654-658`
- **Pattern:** Cat 4

### Category 4 - Inefficiency

#### F-0010 - Anthropic `connect()` probe uses `limit=1` but pagination loop omits limit

- **File:** `src/intellicrack/providers/anthropic.py`
- **Lines:** 102-106
- **Pattern:** Cat 4
