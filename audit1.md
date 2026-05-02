> # Audit List 1/6
>
> Drive **every F-#### finding below** to production release-ready. For
> each finding: re-verify against the cited source/lines, implement the
> full fix per the `Suggested remediation summary`, and write
> production-grade tests that fail without the fix and pass with it. If a
> finding is already resolved on `main`, annotate it in this file by
> appending `[obsolete: <commit-hash>]` to the F-#### heading line (e.g.
> `#### F-0042 [obsolete: c0bfbdf9] - <original title>`) and move on.
>
> ## Orchestrator Responsibility (Claude)
>
> **Claude bears final, non-delegable responsibility for verifying that
> every fix is a real, root-cause solution — never a workaround,
> monkeypatch, or band-aid that masks the underlying defect.** Reject any
> change that:
>
> - Suppresses, hides, or routes around the failure mode instead of fixing
>   the cause described in `Why this is non-functional`.
> - Adds opt-in flags or "preserve old behavior" toggles that leave the
>   broken code path reachable.
> - Catches and swallows the symptom (logging-only, fake `success: True`,
>   silent fallback, bare `except`) instead of correcting the logic.
> - Replaces one fake-success path with a different fake-success path.
> - Disables, weakens, skips, or `xfail`s tests / assertions to silence a
>   failure.
> - Adds shim layers, polyfills, or compatibility wrappers when the
>   upstream call site or data structure should be corrected directly.
> - Inserts `type: ignore`, `pyright: ignore`, `noqa`, or other
>   suppression directives instead of fixing the actual defect.
> - Hardcodes a value, sentinel, or "known-good" response in place of the
>   real computation.
> - Monkeypatches at runtime or vendors a private copy of upstream code to
>   avoid touching the real broken site.
>
> Do not mark a finding resolved until the underlying defect is
> **actually** gone and the new tests would have caught the original bug.
>
> Hard constraints:
>
> - Production-ready and immediately deployable; zero placeholders, mocks,
>   stubs, simulated implementations, or fake-success returns.
> - `ruff check` clean, fully `basedpyright` compliant, `pydoclint` and
>   `pydocstyle` clean — no inline suppression directives of any kind.
> - Windows-first compatibility, preserve existing functionality, never
>   delete a method binding — implement the missing function instead.
> - Every F-#### below must end fixed-and-tested or annotated
>   `[obsolete: <commit-hash>]` inline on its heading line in this file.
>
> ---

# Findings: bridges-hex

## Files audited (2)

- src/intellicrack/bridges/hex_editor.py
- src/intellicrack/bridges/hex_state.py

## Summary

60 findings across 24 categories. Major themes: a fundamentally broken Python "sandbox" in `run_python_script` (real RCE), naive ClamAV/DIE signature scanners that misimplement the formats, missing Mach-O support contradicting advertised capabilities, full-document memory loads that defeat the memory-mapped Rust backend, BPS encoder degenerate to suboptimal output, broken UTF-16 string scanner, and pervasive "fake success" returns when backend methods are missing.

## Findings

### Category 14 - Security / Crypto Failures

#### F-0001 - `run_python_script` "sandbox" is escapable; permits subprocess.Popen and os.system via **subclasses**

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5667-5872 (esp. 5802-5825)
- **Pattern:** Cat 14, Cat 3
- **Why this is non-functional:** Excludes only six builtins. `object`, `type`, `getattr`, `globals`, `__build_class__`, `vars`, `setattr` all remain. A user/LLM script can trivially escape via `().__class__.__base__.__subclasses__()` to obtain `subprocess.Popen` or `os.system`. This is a Windows RCE vector exposed to LLM tool calls.

### Category 2 - Hardcoded Return Values & Fake Success

#### F-0002 - set_va_base claims success when backend lacks add_va_mapping

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4631-4668
- **Pattern:** Cat 2

#### F-0003 - set_chunk_size and set_memory_budget return True regardless of effect

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5874-5919
- **Pattern:** Cat 2

### Category 20 - Dead Code

#### F-0004 - `_alignment_grid_size` is written and never read

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5451-5464, 345
- **Pattern:** Cat 20, Cat 18

### Category 7 - Concurrency

#### F-0005 - `_state_lock` only acquired in shutdown; meaningless elsewhere

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 347, 1569
- **Pattern:** Cat 7

### Category 9 - Bridge Integration

#### F-0006 - `apply_transform` and `apply_pipeline` return transformed bytes but never write back

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3318-3368, 3370-3418
- **Pattern:** Cat 9

### Category 19 - Data Parsing

#### F-0007 - `_build_ips_from_patches` overflow handling broken

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3621-3682, 3799-3830
- **Pattern:** Cat 19

#### F-0008 - `_apply_ips_patches` premature break + project-invented EOF marker

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3832-3893
- **Pattern:** Cat 19, Cat 5

### Category 14 - Security

#### F-0009 - MD5 of full file in memory defeats memory-mapped backend

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6080
- **Pattern:** Cat 14

### Category 4 - Naive Implementations

#### F-0010 - ClamAV NDB scanner strips wildcards, defeating signatures

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6044-6172
- **Pattern:** Cat 4

#### F-0011 - DIE scanner is a fundamental loss of capability

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5945-6042
- **Pattern:** Cat 4

### Category 15 - Platform

#### F-0012 - list_process_regions docstring says Windows-only, no actual platform check

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4133-4184
- **Pattern:** Cat 15

### Category 16 - Binary Analysis

#### F-0013 - get_pe_imports/get_pe_exports load full document into memory

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3203-3248, 3250-3316
- **Pattern:** Cat 16

#### F-0014 - yara_scan loads entire document into memory

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3023-3110
- **Pattern:** Cat 16

#### F-0015 - PE checksum offset hardcoded inline despite available constants

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5485-5516
- **Pattern:** Cat 19

### Category 5 - Error Handling

#### F-0016 - Pattern registry unavailable returns empty list, indistinguishable from no matches

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2235-2256, 2258-2291
- **Pattern:** Cat 5

### Category 13 - Logging Theater

#### F-0017 - apply_template doesn't notify state holder

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2002-2025
- **Pattern:** Cat 13, Cat 18

### Category 5 - Error Handling

#### F-0018 - _apply_arithmetic_fallback silently returns input unchanged for xor/and/or without key

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4515-4520
- **Pattern:** Cat 5

### Category 16 - Binary Analysis

#### F-0019 - entropy/digram_matrix etc. require exact Rust attribute names with no fallback

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2831-2929
- **Pattern:** Cat 16

### Category 4 - Naive

#### F-0020 - read_bytes registered as LLM tool with no length cap

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1633-1653
- **Pattern:** Cat 4

### Category 13 - Logging Theater

#### F-0021 - Wholesale "everything from 0 to length changed" event after every modification

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1882-1907
- **Pattern:** Cat 13

#### F-0022 - State holder notified that entire document changed even when script didn't write

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5868-5871
- **Pattern:** Cat 13

### Category 16 - Binary Analysis

#### F-0023 - Mach-O missing despite supported_formats=["pe","elf","macho","raw"]

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5076-5099, 5164
- **Pattern:** Cat 16

### Category 23 - Build/Release Metadata

#### F-0024 - Capabilities advertise macho/scripting that aren't real

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 348-354
- **Pattern:** Cat 23

### Category 16 - Binary Analysis

#### F-0025 - Mach-O magics return [] silently in auto_detect_va_mappings

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4710-4734
- **Pattern:** Cat 16

### Category 5 - Error Handling

#### F-0026 - PE structure bookmarks left half-applied on failure

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5113-5132
- **Pattern:** Cat 5

### Category 12 - Configuration

#### F-0027 - set_display_mode/set_color_mode don't validate against documented enum

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4108-4131, 5921-5934
- **Pattern:** Cat 12

### Category 4 - Naive

#### F-0028 - snap_to_alignment only floors despite "snap to nearest" docstring

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5433-5449
- **Pattern:** Cat 4

### Category 19 - Data Parsing

#### F-0029 - UTF-16LE scanner only checks even starting offsets

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5050-5071
- **Pattern:** Cat 19

### Category 4 - Naive

#### F-0030 - BPS encoder degenerate; only emits SourceRead and TargetRead

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6428-6492
- **Pattern:** Cat 4

### Category 21 - Documentation Drift

#### F-0031 - toggle_bit Rust path doesn't emit log; fallback path does

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4593-4629
- **Pattern:** Cat 21

### Category 6 - Resource Lifecycle

#### F-0032 - open_file doesn't close previous document; leaks mmap

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1577-1612
- **Pattern:** Cat 6

#### F-0033 - save_to_sandbox leaks created sandbox instance on copy_to failure

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2677-2754
- **Pattern:** Cat 6

### Category 17 - AI Provider

#### F-0034 - get_context_for_ai returns unbounded bookmark list

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2625-2675
- **Pattern:** Cat 17

### Category 5 - Error Handling

#### F-0035 - export_ips_patches falls back silently for ips32 path mismatch

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3669-3679
- **Pattern:** Cat 5

### Category 7 - Concurrency

#### F-0036 - hex_state_notify guard silently drops downstream events

- **File:** `src/intellicrack/bridges/hex_state.py`
- **Lines:** 560-599
- **Pattern:** Cat 7

#### F-0037 - hex_state set_document reads length outside the lock

- **File:** `src/intellicrack/bridges/hex_state.py`
- **Lines:** 191-227
- **Pattern:** Cat 7

#### F-0038 - hex_state asymmetric locking on display_mode getter/setter

- **File:** `src/intellicrack/bridges/hex_state.py`
- **Lines:** 337-355
- **Pattern:** Cat 7

#### F-0039 - hex_state property getters read shared state without lock

- **File:** `src/intellicrack/bridges/hex_state.py`
- **Lines:** 110-126
- **Pattern:** Cat 7

### Category 16 - Binary Analysis

#### F-0040 - UTF-16 scanner accepts code units like 0x2070 as printable

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5050-5071
- **Pattern:** Cat 16

### Category 5 - Error Handling

#### F-0041 - search_text_encoded falls through silently if Rust path raises

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1853-1856
- **Pattern:** Cat 5

### Category 6 - Resource Lifecycle

#### F-0042 - BPS/UPS export loads original + current docs simultaneously

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6248-6370
- **Pattern:** Cat 6

### Category 5 - Error Handling

#### F-0043 - ClamAV DB load raises uncaught AttributeError on dict-shaped DB

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5962-5963
- **Pattern:** Cat 5

#### F-0044 - ClamAV dispatch by suffix only; .cdb/.mdb/.fp etc. mishandled

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6063-6068
- **Pattern:** Cat 5

### Category 22 - Test/Debug Code

#### F-0045 - run_python_script forbidden_builtins set looks like a hand-rolled prototype

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5802
- **Pattern:** Cat 22

### Category 18 - GUI/UX

#### F-0046 - copy_as silently copies one byte at cursor when no selection

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2401-2407
- **Pattern:** Cat 18

### Category 5 - Error Handling

#### F-0047 - base_convert raises uncaught ValueError on bad input

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5594-5625
- **Pattern:** Cat 5

### Category 6 - Resource Lifecycle

#### F-0048 - initialize replaces local cache, dropping bridge-side rules

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1531-1546
- **Pattern:** Cat 6

#### F-0049 - save_as doesn't update target_path

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2526-2570
- **Pattern:** Cat 6

### Category 14 - Security

#### F-0050 - export_annotated_html only escapes 3 chars; bookmark color XSS

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5283-5295
- **Pattern:** Cat 14

### Category 17 - AI Provider

#### F-0051 - get_digram_matrix returns 65536 integers (~400 KB JSON) per call

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 2913-2929
- **Pattern:** Cat 17

### Category 4 - Naive

#### F-0052 - CRC fallback bit-by-bit Python; no zlib/binascii fallback

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3606-3616
- **Pattern:** Cat 4

### Category 9 - Bridge Integration

#### F-0053 - fpdf module lazy-import without runtime availability check

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 6756-6760
- **Pattern:** Cat 9

### Category 21 - Documentation Drift

#### F-0054 - search_numeric accepts unknown value_type, silently treats as uint

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3895-3949
- **Pattern:** Cat 21

### Category 24 - Recovery Theater

#### F-0055 - open_process_memory doesn't close any previously open document

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 4173-4184
- **Pattern:** Cat 24

### Category 5 - Error Handling

#### F-0056 - get_pe_imports DIRECTORY_ENTRY default 1/0 magic fallback

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 3219-3220, 3291-3292
- **Pattern:** Cat 5

### Category 11 - State

#### F-0057 - target_path constructed twice; can drift from Rust file_path()

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 1600-1606
- **Pattern:** Cat 11

#### F-0058 - hex_state clear_all clears highlights but only emits DOCUMENT_CLOSED

- **File:** `src/intellicrack/bridges/hex_state.py`
- **Lines:** 280-301
- **Pattern:** Cat 11

### Category 5 - Error Handling

#### F-0059 - run_python_script catches MemoryError; SystemExit uncaught; OverflowError missing

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5834-5855
- **Pattern:** Cat 5

### Category 21 - Documentation Drift

#### F-0060 - safe_print ignores file= kwarg; no size cap on capture

- **File:** `src/intellicrack/bridges/hex_editor.py`
- **Lines:** 5805-5819
- **Pattern:** Cat 21

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

# Findings: bridges-core

## Files audited (5)

- src/intellicrack/bridges/**init**.py
- src/intellicrack/bridges/base.py
- src/intellicrack/bridges/_pe_format.py
- src/intellicrack/bridges/_win32_types.py
- src/intellicrack/bridges/schemas.py

## Findings

### Category 4 - Ineffective / Naive Implementations

#### F-0001 - normalize_type silently downgrades all unknown types to "string"

- **File:** `src/intellicrack/bridges/schemas.py`
- **Lines:** 181-197
- **Pattern:** Cat 4, "silently masks errors / loses information"
- **Excerpt:**

  ```python
  def normalize_type(param_type: str) -> str:
      """Normalize a parameter type to JSON Schema type.
      ...
      """
      param_type_lower = param_type.lower().strip()
      if param_type_lower in PYTHON_TO_JSON_TYPES:
          return PYTHON_TO_JSON_TYPES[param_type_lower]
      if param_type_lower in VALID_JSON_SCHEMA_TYPES:
          return param_type_lower
      return "string"
  ```

- **Why this is non-functional:** Any unrecognised type string (`"list[int]"`, `"Foo"`, `"bytes"`, `"Optional[int]"`, `"int|None"`) is silently coerced to `"string"`. Tool parameters that should be integers, lists, or objects will be advertised to every LLM provider as plain strings, causing the model to emit string arguments which then fail to coerce when the bridge function tries to use them as ints/lists. There is no log warning at the conversion point; the only safety net (`validate_tool_parameter`) is itself defeated by this fallback (see F-0002).
- **Callers / blast radius:** `src/intellicrack/bridges/schemas.py:214` (`build_schema_property`), `src/intellicrack/bridges/schemas.py:274` (`_build_google_schema_parameters`), `src/intellicrack/bridges/schemas.py:347` (`validate_tool_parameter`). Schemas built here flow into `to_anthropic_schema` / `to_openai_schema` / `to_google_schema` and ultimately `get_schema_for_provider` consumed by `core/orchestrator.py:1260` `_validate_tool_schemas`.
- **Suggested remediation summary:** Either raise / log a warning for unknown types and propagate it, or return a `(type, was_fallback)` tuple so the validator can flag it.

### Category 5 - Error Handling Anti-Patterns

#### F-0002 - validate_tool_parameter type check is permanently dead because normalize_type cannot return an invalid value

- **File:** `src/intellicrack/bridges/schemas.py`
- **Lines:** 347-355
- **Pattern:** Cat 5, "validation that cannot fire"; cross-reference Cat 20 (dead code)
- **Excerpt:**

  ```python
      normalized_type = normalize_type(param.type)
      if normalized_type not in VALID_JSON_SCHEMA_TYPES:
          errors.append(
              ValidationError(
                  f"Invalid type '{param.type}' (normalized to '{normalized_type}')",
                  location,
                  "warning",
              ),
          )
  ```

- **Why this is non-functional:** `normalize_type` (lines 181-197) is *guaranteed* to return one of the seven members of `VALID_JSON_SCHEMA_TYPES` (it falls back to `"string"` for unknown input). Therefore the `if normalized_type not in VALID_JSON_SCHEMA_TYPES` branch can never be true, the `errors.append(...)` body is unreachable, and no caller will ever see a "warning" diagnostic for a malformed type string. The validator pretends to detect bad type names but in fact accepts everything.
- **Callers / blast radius:** Called from `validate_tool_function` at `src/intellicrack/bridges/schemas.py:440`, which is called from `validate_tool_definition` at `src/intellicrack/bridges/schemas.py:483`, surfaced through `validate_and_convert` (`src/intellicrack/bridges/schemas.py:661`) used by `core/orchestrator.py:1260` `_validate_tool_schemas`. Production warning logging is suppressed because this branch never runs.
- **Suggested remediation summary:** Validate `param.type` *before* normalisation (compare against `PYTHON_TO_JSON_TYPES` keys plus `VALID_JSON_SCHEMA_TYPES`) so the warning fires when the developer wrote an unsupported type string.

### Category 13 - Logging / Observability Theater

#### F-0003 - validate_and_convert / get_schema_for_provider results are computed only to log a count

- **File:** `src/intellicrack/bridges/schemas.py`
- **Lines:** 645-679
- **Pattern:** Cat 13, "work performed solely to feed a log line"
- **Excerpt:**

  ```python
  def validate_and_convert(
      tool: ToolDefinition,
      provider: ProviderName,
  ) -> tuple[list[dict[str, Any]], list[ValidationError]]:
      ...
      schemas = get_schema_for_provider(tool, provider)
      _logger.debug(
          "schema_converted",
          tool=str(tool.tool_name),
          provider=str(provider),
          schema_count=len(schemas),
      )
      return schemas, errors
  ```

- **Why this is non-functional:** Together with `core/orchestrator.py:1260` (`_schemas, errors = validate_and_convert(tool, provider_name)`) and `core/orchestrator.py:1279` (`all_schemas = get_all_schemas_for_provider(tools, provider_name)`), the converted provider schemas are never sent to the LLM - the orchestrator passes raw `tool_definitions` to `_call_llm` and lets each provider re-convert. The full schema-build pipeline is therefore executed twice per agent loop iteration purely so the orchestrator can log `schema_count=...`. If `get_schema_for_provider` ever drifts from what the providers actually emit, no behavior changes; the log just becomes a lie.
- **Callers / blast radius:** `core/orchestrator.py:1260` (discards `_schemas`), `core/orchestrator.py:1279` (uses `all_schemas` only for `len()`). No production caller consumes the converted schema list returned from these functions.
- **Suggested remediation summary:** Either route the converted schemas to the provider call (so providers stop re-converting) or replace the conversion calls with a pure-validation pass that does not allocate the dict trees.

### Category 20 - Dead Code & Unreachable Paths

#### F-0004 - bridges/**init**.py public re-exports are unused by production code

- **File:** `src/intellicrack/bridges/__init__.py`
- **Lines:** 13-58
- **Pattern:** Cat 20, "exported symbol with no production importers"
- **Excerpt:**

  ```python
  from intellicrack.bridges.base import (
      BinaryOperationsBridge,
      BridgeCapabilities,
      ...
  )
  from intellicrack.bridges.cutter import CutterBridge
  from intellicrack.bridges.frida_bridge import FridaBridge
  from intellicrack.bridges.ghidra import GhidraBridge
  ...
  __all__: list[str] = [
      "BinaryOperationsBridge",
      ...
  ```

- **Why this is non-functional:** Every production importer of any bridge symbol uses the fully-qualified submodule path (`from intellicrack.bridges.base import ToolBridgeBase`, `from intellicrack.bridges.ghidra import GhidraBridge`, etc.). A repo-wide search for `from intellicrack\.bridges import \w+` returns only `tests/test_bridges/test_win32_types.py:15`. The package-level re-export block at the top of `__init__.py` therefore has no production consumers and forces every heavy bridge module (Frida 242 KB, Ghidra 259 KB, hex_editor 284 KB, x64dbg 227 KB, process 187 KB) to be eagerly imported the first time anything touches `intellicrack.bridges`, even when the caller only needed `intellicrack.bridges.base`.
- **Callers / blast radius:** No production callers. Only `tests/test_bridges/test_win32_types.py:15` relies on the package-level surface. Eager imports trigger the heavy bridges (frida_bridge, ghidra, x64dbg, hex_editor, process) the moment any code does `import intellicrack.bridges.<anything>`.
- **Suggested remediation summary:** Convert to lazy `__getattr__` re-exports or delete the `__all__` surface and rely on submodule imports.

### Category 21 - Documentation / Signature Drift

#### F-0005 - protection_to_string promised "rwx" / "r--" return shape is contradicted by its implementation

- **File:** `src/intellicrack/bridges/_win32_types.py`
- **Lines:** 949-972
- **Pattern:** Cat 21, "docstring lies about return shape / contract"
- **Excerpt:**

  ```python
  def protection_to_string(prot: int) -> str:
      """Convert a Win32 memory protection constant to a human-readable string.
      ...
      Returns:
          str: Protection string like 'rwx', 'r--', etc.
      """
      prot_map: dict[int, str] = {
          PAGE_NOACCESS: "---",
          PAGE_READONLY: "r--",
          PAGE_READWRITE: "rw-",
          PAGE_WRITECOPY: "rw-c",
          ...
          PAGE_EXECUTE_WRITECOPY: "rwxc",
      }
      base_prot = prot & 0xFF
      result = prot_map.get(base_prot, "???")
      if prot & PAGE_GUARD:
          result += "+G"
      return result
  ```

- **Why this is non-functional:** The docstring says the function returns a fixed-length protection triplet "like 'rwx', 'r--'", but the actual returned strings are 3 characters for the simple cases, 4 characters for the WRITECOPY variants ("rw-c", "rwxc"), three question marks ("???") for the unknown case, and an additional "+G" suffix when the guard bit is set. Callers that try to parse the result by character index (e.g. `result[0] == 'r'`) will break on WRITECOPY pages and on guard-protected pages.
- **Callers / blast radius:** Imported by `src/intellicrack/bridges/process.py` (line 127) and used inside ProcessBridge memory region enumeration. Any GUI or LLM consumer that treats the field as a fixed-shape `rwx` triplet will misclassify writecopy / guard pages.
- **Suggested remediation summary:** Either tighten the docstring to enumerate every possible suffix, or redesign the return as a typed dict with separate `read`, `write`, `execute`, `copy_on_write`, `guard` flags.

#### F-0006 - state_to_string and mem_type_to_string silently bucket all unknown values to "unknown"

- **File:** `src/intellicrack/bridges/_win32_types.py`
- **Lines:** 975-1006
- **Pattern:** Cat 21, "doc/contract drift"; cross-reference Cat 4 (naive)
- **Excerpt:**

  ```python
  def state_to_string(state: int) -> str:
      ...
      state_map: dict[int, str] = {
          MEM_COMMIT: "committed",
          MEM_RESERVE: "reserved",
          MEM_FREE: "free",
      }
      return state_map.get(state, "unknown")


  def mem_type_to_string(mem_type: int) -> str:
      ...
      type_map: dict[int, str] = {
          MEM_PRIVATE: "private",
          MEM_MAPPED: "mapped",
          MEM_IMAGE: "image",
      }
      return type_map.get(mem_type, "unknown")
  ```

- **Why this is non-functional:** The docstrings advertise the return as one of the listed states / types, but every other Win32 `MEM_*` value (MEM_DECOMMIT 0x4000, composite states) collapses to the literal `"unknown"`. There is no log line and no exception, so a downstream caller that records a process memory map will silently lose the distinction between "we never enumerated this kind of region before" and "we misread the field". The `"unknown"` bucket also collides with the `"???"` produced by `protection_to_string`, so the human reader cannot tell whether the failure is on the protection or the state side.
- **Callers / blast radius:** Both helpers are imported and called by `src/intellicrack/bridges/process.py` for memory region enumeration. Returned strings flow into ProcessBridge `get_memory_regions` and then into LLM context.
- **Suggested remediation summary:** Log unknown values at debug level with the raw int, return `f"unknown(0x{state:x})"`, and document the contract honestly.

### Category 24 - Recovery / Robustness Theater

#### F-0007 - ToolBridgeBase.shutdown does no real cleanup

- **File:** `src/intellicrack/bridges/base.py`
- **Lines:** 409-412
- **Pattern:** Cat 24, "cleanup helper that does not clean anything up"
- **Excerpt:**

  ```python
      async def shutdown(self) -> None:
          """Shutdown the tool and cleanup resources."""
          self._logger.info("bridge_shutdown", bridge_class=self.__class__.__name__)
          self._state = BridgeState()
  ```

- **Why this is non-functional:** The base implementation is non-abstract (so subclasses are not forced to override it) and only resets the in-memory `BridgeState` dataclass. The docstring says "cleanup resources" but there is no handle close, no subprocess kill, no socket teardown, no tempfile unlink. Every shipped subclass (`cutter.py:894`, `x64dbg.py:1860`, `process.py:915`, `frida_bridge.py:1291`, `ghidra.py:1183`, `hex_editor.py:1575`) calls `await super().shutdown()` first, but a future bridge author who relies on the default contract will leak file descriptors / child processes and the type system will not catch it. Compare with `initialize` and `is_available`, which *are* abstract for exactly this reason.
- **Callers / blast radius:** `src/intellicrack/main.py:914` (`orchestrator.shutdown()`) which fans out via `core/orchestrator.py:1827` (`await self._tools.shutdown()`) and `core/tools.py:199` (`await bridge.shutdown()`); `src/intellicrack/ui/panels/cutter_panel.py:174` and `src/intellicrack/ui/panels/ghidra_panel.py:206` / `:1303` invoke per-bridge shutdown directly. If anyone adds a new bridge that inherits ToolBridgeBase without overriding `shutdown`, those call sites will silently leak the bridge's resources.
- **Suggested remediation summary:** Either mark `shutdown` `@abstractmethod` (forcing every bridge to write its real cleanup) or have the base log a warning when used without override.

# Findings: providers-local

## Files audited (5)

- src/intellicrack/providers/ollama.py
- src/intellicrack/providers/huggingface.py
- src/intellicrack/providers/local_transformers.py
- src/intellicrack/providers/model_loader.py
- src/intellicrack/providers/xpu_utils.py

## Critical-path verification

- **Ollama**: confirmed real HTTP calls to `http://localhost:11434/api/generate`, `/api/chat`, `/api/tags`, `/api/show`, `/api/embeddings`, `/api/ps`, `/api/pull` via `httpx.AsyncClient`. Cloud routed to `https://ollama.com/v1/chat/completions`. Streaming uses real NDJSON / SSE parsing. No canned responses.
- **HuggingFace**: confirmed real `AsyncInferenceClient.chat_completion(...)` calls with `provider="hf-inference"`. `HfApi.list_models` and `HfApi.whoami` exercised on real network.
- **local_transformers**: confirmed real `AutoTokenizer.from_pretrained`, `AutoModelForCausalLM.from_pretrained`, `model.generate(...)` and per-token forward passes. No canned responses.

## Findings

### Category 20 - Dead Code

#### F-0001 - Dead constants `_B580_DEVICE_IDS` and `_INTEL_VENDOR_ID`

- **File:** `src/intellicrack/providers/xpu_utils.py`
- **Lines:** 41, 44
- **Pattern:** Cat 20
- **Excerpt:**

  ```python
  _B580_DEVICE_IDS: frozenset[str] = frozenset({"0xe20b", "e20b", "E20B", "0xE20B"})
  _ARC_DEVICE_PATTERNS: tuple[str, ...] = ("Arc", "A770", "A750", "A380", "A310", "B580")

  _INTEL_VENDOR_ID: str = "8086"
  ```

- **Why this is non-functional:** `_B580_DEVICE_IDS` and `_INTEL_VENDOR_ID` are never read. The B580 device-ID match is performed inline in `_is_b580_device` against the literal set `{"e20b", "0xe20b"}` (line 330) instead of using `_B580_DEVICE_IDS`. The Intel vendor ID is never referenced in PNP parsing.
- **Suggested remediation summary:** Either wire constants in or delete them.

### Category 19 - Lossy Data Path

#### F-0002 - Cloud-stream tool-call dict arguments are silently dropped

- **File:** `src/intellicrack/providers/ollama.py`
- **Lines:** 1493-1523, 1525-1552
- **Pattern:** Cat 19, Cat 17
- **Excerpt:**

  ```python
  for delta in deltas:
      ...
      args_val = func_delta.get("arguments")
      if isinstance(args_val, str) and args_val:
          entry_func["arguments"] = cast("str", entry_func["arguments"]) + args_val
  ```

- **Why this is non-functional:** The streaming counterpart `_accumulate_openai_tool_call_deltas` only handles `isinstance(args_val, str)` and silently discards any dict-typed delta. `_finalize_openai_tool_calls` then defaults to `"{}"`, producing a tool call with empty arguments. The non-stream parsers handle both string and dict.
- **Suggested remediation summary:** Mirror the dict-vs-string handling already implemented in `_accumulate_native_tool_call_deltas`.

### Category 4 - Surprising Default Behavior

#### F-0003 - Default model silently substituted on empty input

- **File:** `src/intellicrack/providers/local_transformers.py`
- **Lines:** 540, 640
- **Pattern:** Cat 4, Cat 17
- **Excerpt:**

  ```python
  model_id = model or _DEFAULT_MODEL
  await self._ensure_model_loaded(model_id)
  ```

- **Why this is non-functional:** Both `chat` and `chat_stream` silently substitute `microsoft/Phi-3-mini-4k-instruct` when caller passes empty string. No warning, no error. Other providers raise `ProviderError`.

### Category 13 - Logging Consistency

#### F-0004 - `_logger` instance attribute reassignment loses provider binding

- **File:** `src/intellicrack/providers/local_transformers.py`
- **Lines:** 199
- **Pattern:** Cat 13
- **Excerpt:**

  ```python
  self._logger = _logger
  self._logger.info("local_transformers_provider_initialized", prefer_xpu=prefer_xpu)
  ```

- **Why this is non-functional:** `OllamaProvider` and `HuggingFaceProvider` both bind a `provider=` field via `get_logger(__name__).bind(provider="<name>")`. `LocalTransformersProvider.__init__` instead overwrites the inherited `self._logger` with the unbound module-level `_logger`, losing the provider field on every log entry.

### Category 19 - Brittle Text Parsing

#### F-0005 - `_extract_text_before_tool_call` regex misses whitespace-formatted tool calls

- **File:** `src/intellicrack/providers/local_transformers.py`
- **Lines:** 1288, 1353
- **Pattern:** Cat 19, Cat 17
- **Excerpt:**

  ```python
  start_idx = response.find('{"tool_call":')
  ...
  if match := re.search(r'\{"tool_call":', response):
      return response[: match.start()].strip()
  ```

- **Why this is non-functional:** Both helpers only locate tool calls when the model emits the exact compact form `{"tool_call":` with no whitespace. Instruction-tuned models routinely pretty-print JSON. When that happens, `_parse_tool_calls` returns `None` and the user-visible response leaks the raw JSON instead of dispatching the tool.

### Category 5 - Unhandled Exception Path

#### F-0006 - `chat_template` attribute access can raise `AttributeError` for non-chat tokenizers

- **File:** `src/intellicrack/providers/local_transformers.py`
- **Lines:** 1183-1195
- **Pattern:** Cat 5
- **Excerpt:**

  ```python
  if hasattr(tokenizer, "apply_chat_template") and tokenizer.chat_template is not None:
      try:
          result: str | list[int] = tokenizer.apply_chat_template(...)
  ```

- **Why this is non-functional:** Older HF tokenizers do not define a `chat_template` attribute at all and access raises `AttributeError` outside the `try` block, escaping `_format_prompt` entirely and propagating up as `_ERR_INFERENCE_FAILED`.

### Category 5 - Defensive Parsing

#### F-0007 - `_check_rebar_status` parses PowerShell numeric output unsafely

- **File:** `src/intellicrack/providers/xpu_utils.py`
- **Lines:** 569-576
- **Pattern:** Cat 5, Cat 15
- **Excerpt:**

  ```python
  if result.returncode == 0:
      count = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ""
      if count and int(count) > 0:
          _logger.debug("xpu_rebar_enabled", count=count)
          return (True, "")
  ```

- **Why this is non-functional:** `int(count)` is called without exception protection. The exception propagates out of `_check_rebar_status` → `check_windows_requirements` → `LocalTransformersProvider.connect`, breaking provider connection on systems where the ReBAR check returns unexpected output.

# Findings: hexcore-rust

## Files audited (22)

- src/intellicrack-hexcore/Cargo.toml
- src/intellicrack-hexcore/intellicrack_hexcore.pyi
- src/intellicrack-hexcore/src/lib.rs
- src/intellicrack-hexcore/src/bps_ups.rs
- src/intellicrack-hexcore/src/data_inspector.rs
- src/intellicrack-hexcore/src/data_source.rs
- src/intellicrack-hexcore/src/diff.rs
- src/intellicrack-hexcore/src/encodings.rs
- src/intellicrack-hexcore/src/entropy.rs
- src/intellicrack-hexcore/src/hash.rs
- src/intellicrack-hexcore/src/mmap_io.rs
- src/intellicrack-hexcore/src/patch_export.rs
- src/intellicrack-hexcore/src/piece_table.rs
- src/intellicrack-hexcore/src/search.rs
- src/intellicrack-hexcore/src/strings.rs
- src/intellicrack-hexcore/src/transforms.rs
- src/intellicrack-hexcore/src/undo.rs
- src/intellicrack-hexcore/src/templates/mod.rs
- src/intellicrack-hexcore/src/templates/common.rs
- src/intellicrack-hexcore/src/templates/elf.rs
- src/intellicrack-hexcore/src/templates/eval.rs
- src/intellicrack-hexcore/src/templates/json_schema.rs
- src/intellicrack-hexcore/src/templates/macho.rs
- src/intellicrack-hexcore/src/templates/pe.rs
- src/intellicrack-hexcore/src/templates/zip.rs

## Findings

### Category 6 - Resource & Lifecycle Issues

#### F-0001 - `move_block` clears source without recording undo for the source clear

- **File:** `src/intellicrack-hexcore/src/lib.rs`
- **Lines:** 843-861
- **Pattern:** Cat 6, "Asymmetric / partial state mutation that breaks undo"
- **Excerpt:**

  ```rust
  fn move_block(&mut self, src_offset: usize, length: usize, dst_offset: usize) -> PyResult<()> {
      let doc_len = self.inner.document_size();
      if src_offset + length > doc_len || dst_offset + length > doc_len {
          return Err(pyo3::exceptions::PyValueError::new_err(
              "block exceeds document size",
          ));
      }
      let data = self.inner.read(src_offset, length);
      let old_dst = self.inner.read(dst_offset, length);
      let zeros = vec![0u8; length];
      self.inner.overwrite(src_offset, &zeros);
      self.inner.overwrite(dst_offset, &data);
      self.undo_mgr.record(undo::Operation::Overwrite {
          offset: dst_offset,
          old_data: old_dst,
          new_data: data,
      });
      Ok(())
  }
  ```

- **Why this is non-functional:** Two byte-region mutations are performed (src zeroed, dst overwritten) but only one `Operation::Overwrite` is recorded - the destination one. There is no undo record for the source-clear write. Calling `undo()` after `move_block` will only restore the destination region; the source bytes will remain zeroed. This leaves the document in an inconsistent state that cannot be returned to the original via `undo()`. It also breaks `is_modified()` accounting symmetry.
- **Callers / blast radius:** `src/intellicrack/bridges/hex_editor.py:4315`, `src/intellicrack/ui/panels/hex_editor/_transforms.py:774`.
- **Suggested remediation summary:** Record both `Operation::Overwrite` events as a single composite, or add a `MoveBlock` undo variant that captures both regions.

### Category 14 - Silent Data Corruption

#### F-0002 - `swap_blocks` silently zero-pads when blocks have different lengths

- **File:** `src/intellicrack-hexcore/src/lib.rs`
- **Lines:** 879-886
- **Pattern:** Cat 6, Cat 14
- **Excerpt:**

  ```rust
  let data_a = self.inner.read(offset_a, len_a);
  let data_b = self.inner.read(offset_b, len_b);
  let mut write_a: Vec<u8> = data_b.clone();
  write_a.resize(len_a, 0);
  let mut write_b: Vec<u8> = data_a.clone();
  write_b.resize(len_b, 0);
  self.inner.overwrite(offset_a, &write_a);
  self.inner.overwrite(offset_b, &write_b);
  ```

- **Why this is non-functional:** When `len_a != len_b`, `write_a.resize(len_a, 0)` truncates or zero-pads `data_b` to fit slot A. This destroys the trailing bytes of the longer block instead of performing a true swap. There is no length-equality check.
- **Callers / blast radius:** `src/intellicrack/bridges/hex_editor.py:4364`, `src/intellicrack/ui/panels/hex_editor/_transforms.py:790`.
- **Suggested remediation summary:** Reject unequal lengths with an error, or perform real insert/delete swap via piece table.

### Category 22 - Dead Code

#### F-0003 - `diff_data_block` block-level fallback is dead code

- **File:** `src/intellicrack-hexcore/src/diff.rs`
- **Lines:** 338-431 (specifically the post-anchored fallback at 348-430)
- **Pattern:** Cat 22, Cat 20
- **Excerpt:**

  ```rust
  fn diff_data_block(data_a: &[u8], data_b: &[u8]) -> DiffResult {
      if data_a == data_b {
          return identical_result(data_a.len());
      }

      let anchored = diff_data_anchored(data_a, data_b);
      if !anchored.regions.is_empty() {
          return anchored;
      }

      let blocks_a: Vec<&[u8]> = data_a.chunks(BLOCK_SIZE).collect();
      let blocks_b: Vec<&[u8]> = data_b.chunks(BLOCK_SIZE).collect();
      let ops = capture_diff_slices(Algorithm::Myers, &blocks_a, &blocks_b);
  ```

- **Why this is non-functional:** `diff_data_anchored` always pushes at least one region for non-identical inputs. The only path where `anchored.regions` could be empty is `data_a == data_b`, which is short-circuited above. Therefore the entire 64-byte block-level Myers fallback is unreachable.
- **Callers / blast radius:** `src/intellicrack-hexcore/src/lib.rs:1097`.
- **Suggested remediation summary:** Either delete the fallback or change the condition that gates entering it.

### Category 7 - Silent Errors

#### F-0004 - `eval_pointer` swallows recursive-evaluation errors

- **File:** `src/intellicrack-hexcore/src/templates/eval.rs`
- **Lines:** 367-387
- **Pattern:** Cat 7, Cat 5
- **Excerpt:**

  ```rust
  let children = if ptr_value < self.data.len() && self.depth < MAX_DEPTH {
      if let Some(template) = self.registry.get(target_template) {
          ...
          let result = self.evaluate_fields(&template.fields);
          ...
          result.unwrap_or_default()
      } else {
          Vec::new()
      }
  } else {
      Vec::new()
  };
  ```

- **Why this is non-functional:** When dereferencing a `Pointer` field, the recursive `evaluate_fields` call's `Result` is collapsed via `result.unwrap_or_default()`. Any `TemplateError` raised by the pointed-at template is silently dropped. Compare to `eval_struct_ref` which uses `?` to propagate template errors.
- **Suggested remediation summary:** Use `?` to propagate template errors; or attach an error indicator to the parsed field.

### Category 14 - Silent Zero Result

#### F-0005 - `sizeof()` silently returns 0 for unknown type names

- **File:** `src/intellicrack-hexcore/src/templates/eval.rs`
- **Lines:** 905-912
- **Pattern:** Cat 14, Cat 5
- **Excerpt:**

  ```rust
  let size = match type_name.as_str() {
      "u8" | "uint8" | "int8" | "s8" | "bool" | "char" => 1,
      "u16" | "uint16" | "int16" | "s16" => 2,
      "u32" | "uint32" | "int32" | "s32" | "float" | "float32" => 4,
      "u64" | "uint64" | "int64" | "s64" | "double" | "float64" => 8,
      _ => 0,
  };
  return Ok(size);
  ```

- **Why this is non-functional:** Inside template `Computed` expressions, `sizeof(unknown_or_typo)` returns 0 with no error. A user-authored JSON template using `sizeof(uint128)` or `sizeof(SomeStruct)` silently substitutes 0 into the surrounding arithmetic, producing zero-element dynamic arrays without flagging the typo.
- **Suggested remediation summary:** Error on unknown type names, or look them up against registered structs.

## Notes on inspected items that are NOT findings

- All `unreachable!()` calls (transforms.rs, hash.rs, bps_ups.rs) sit after exhaustive matches whose dispatch is statically verified.
- `let _ =` occurrences in `mmap_io.rs:267-268` are test-only cleanup; in `hash.rs:115` and `patch_export.rs:177` they discard `fmt::Write` results that are infallible for `String`.
- Non-Windows arms of `from_process_memory` / `list_process_memory_regions` (`lib.rs:733-739, 757-763`) intentionally return a `PyRuntimeError` rather than canned data - this is correct platform-gating.
- The `iso10126` padding using zero filler with the length byte is documented as deterministic by design; decryption only relies on the trailing length byte.
- Search/diff/template parsers all do real work; PE-checksum, BPS/UPS, IPS/IPS32/COD all parse and produce real bytes, validated by extensive `#[cfg(test)] mod tests` blocks.
