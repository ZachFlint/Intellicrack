> # Workgroup Directive — Execution Order 15/23: `providers-local`
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
