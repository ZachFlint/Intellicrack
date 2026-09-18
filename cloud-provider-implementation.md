# Cloud implementation brief — arbitrary AI provider support (Intellicrack)

You are implementing an approved plan in the Intellicrack repository
(`ZachFlint/Intellicrack`), on the branch `feat/arbitrary-providers`.

**Your role is code only.** A separate local session owns every test, every
quality gate, and all environment-bound verification. Write the implementation;
do not write tests and do not claim anything is verified.

---

## 0. Environment constraints — read before doing anything

Your VM is Linux. The project is Windows-first. Several things you would
normally reach for **do not work here**:

- **`pixi` will not work.** `pyproject.toml` sets `workspace.platforms = ["win-64"]`
  and `pixi.lock` contains only win-64 entries. `pixi install` / `pixi run`
  fail on Linux. Do not try to fix this, and **do not edit
  `workspace.platforms` or `pixi.lock`.**
- **`ruff` is your one usable gate.** Install it standalone
  (`pip install ruff`) — it needs no project dependencies. Every file you touch
  must end `ruff check` clean, using the repo's own config.
- **`basedpyright` will be noisy here** because third-party dependencies and
  the `typings/` stubs resolve out of the win-64 environment you do not have.
  Run it if you like for obvious self-inflicted errors, but **do not chase its
  missing-import findings and do not restructure code to silence them.** The
  local session runs it authoritatively.
- **`pytest` cannot run at all.** A repo hook blocks host pytest, and the test
  sandbox is a **Windows Server container** (`docker/Dockerfile.windows`,
  `mcr.microsoft.com/windows/servercore`) whose runner calls
  `_ensure_windows_engine()` and aborts unless Docker is on its Windows engine.
  Never report a test as passing.
- **Never modify** the `[tool.basedpyright]` section of `pyproject.toml`,
  `pyrightconfig.json`, the pydoclint/pydocstyle configuration, `pixi.lock`, or
  `requirements.txt` (generated). These are locked.

Line numbers cited below were verified 2026-09-15/16. They drift as you edit —
treat them as starting points and re-locate symbols by name.

---

## 1. Ground rules (non-negotiable)

- **No placeholders, stubs, mocks, simulated behaviour, hardcoded responses, or
  TODO markers.** Every function performs its real operation. If something
  cannot be completed, leave the existing working code in place and say so in
  your summary rather than shipping a stub.
- **Full type annotations everywhere**, written to be basedpyright-correct.
- **Never use any suppression**: no `# type: ignore`, no `# pyright: ignore`,
  no `# noqa`, no inline disables of any kind. Fix the actual error.
- **Google-style docstrings** on every module, class, function and method, and
  they must match the signature exactly — parameters, types, returns, raises,
  yields. `pydoclint` and `pydocstyle` run locally with zero tolerance, so a
  docstring whose `Returns:` type disagrees with the annotation is a defect.
- **No comments** unless the code genuinely cannot be understood without one.
  **No emojis** anywhere.
- **Never delete a method binding.** If something is missing, create a real,
  functional implementation.
- **Windows compatibility is the priority platform** even though you are on
  Linux. Use `pathlib`, avoid POSIX-only assumptions, and keep platform checks
  explicit.
- **SOLID, DRY, KISS.** Maintain existing functionality over "cleaner" code.
- Line length limit is **140**.

---

## 2. Repository state you are starting from

Branch `feat/arbitrary-providers` already contains work from the local session.
**Do not revert or rewrite it:**

- `src/intellicrack/credentials/store.py` — Win32 credential-error typing fix.
  `pywintypes.error` derives only from `Exception`, so all seven keyring
  `except` tuples previously missed it and a `CredWrite` failure escaped
  untyped, bypassing the `.env` fallback. Fixed with a static typed import plus
  a sentinel fallback (`_Win32CredentialError` / `_Win32CredentialFallbackError`),
  mirroring the existing `_KeyringFallbackError` idiom.
- `typings/win32ctypes/` — new stubs required by that import, because
  `pyrightconfig.json` sets `useLibraryCodeForTypes: false` and
  `reportMissingTypeStubs: "error"`.
- `.gitignore` — added `!tests/providers/credentials/`; a bare `credentials/`
  rule had been silently excluding tests in that directory.
- Spike S3 (Windows keyring) is complete. Relevant finding for Phase 4.3:
  **Windows Credential Manager caps a secret at 1280 characters / 2560 bytes**
  (`CRED_MAX_CREDENTIAL_BLOB_SIZE`). Per-instance keyring payloads must stay
  under it, and an over-cap write must surface as a typed error.

---

## 3. Context — why this work exists

Intellicrack can talk to exactly eight AI providers, and that number is baked
into the type system. `ProviderName` (`src/intellicrack/core/types.py:258-268`)
is a closed 8-member enum, and 26 source files plus 89 test files key off it —
including `bridges/schemas.py:686-702`, whose dispatch ends in `_assert_never`,
so a ninth provider is a *type error*, not a config change. A user with a
corporate gateway, a LiteLLM proxy, vLLM, Together, Groq, Cerebras, DeepSeek or
a second OpenAI account cannot connect it at all; `ui/app.py:331-332` silently
drops any provider id that is not an enum member.

Four further defects compound it:

- **No API-dialect abstraction.** `providers/openai.py` is Chat-Completions-only
  and decides what a model supports by string prefix
  (`_REASONING_MODEL_PREFIXES` at `:73`, `startswith(("o1","o3","o4"))` at `:244`
  and `:262`), so GPT-5.x/6.x models get `max_tokens` instead of
  `max_completion_tokens`, a temperature other than 1, and no Responses API —
  the combination OpenAI requires for tool calling on current models.
- **Capabilities are guessed.** Context window falls back to `128000`
  (`openai.py:250`), `supports_tools` is hardcoded `True` (`openai.py:318`), and
  `_get_model_context_window` (`core/orchestrator.py:1876`) needs an exact
  model-id match or the agent loop refuses to run, with `context_window_override`
  (`:226`) exposed in no UI.
- **Externally-sourced tools cannot cross the wire.** `ToolParameter`
  (`types.py:1485`) cannot express raw JSON Schema; `ToolResult.result` and
  `Message.content` are text-only; and `core/tools.py:821` resolves a tool call
  through `ToolName(tool_name.lower())`, so a tool outside the closed bridge
  enum cannot even be dispatched.
- **Reasoning state is lossy.** `Message.thinking_content` is a plain `str`
  (`types.py:393`) and `providers/anthropic.py:432` captures only `block.thinking`
  — it **drops `block.signature`**. Anthropic requires signed thinking blocks
  echoed back on tool-use turns, so extended thinking plus multi-turn tool
  calling is already silently degraded today.

The outcome: any OpenAI-compatible or Anthropic-compatible endpoint can be added
as a named provider instance from the GUI, with its own dialect, credentials,
headers and per-model capabilities; and any tool — Intellicrack's own bridges or
one handed in from outside — renders, replays and executes correctly on every
dialect.

---

## 4. Standards to implement against

These are the reference implementations the design follows. Consult the URLs
when a wire detail is ambiguous.

| Source | What we adopt | URL |
| --- | --- | --- |
| VS Code "Custom Endpoint" BYOK | `apiType` per provider **and** per model (`chat-completions`/`responses`/`messages`); url-driven discovery **or** explicit `models` array; per-model `toolCalling`, `vision`, `thinking`, `supportsReasoningEffort`, `reasoningEffortFormat`, `maxInputTokens`/`maxOutputTokens`/`contextWindow`, `streaming`, `modelOptions`, `requestHeaders` with `${apiKey}`; token-limit field per family (`max_completion_tokens` only for Chat-Completions thinking models, Responses keeps `max_output_tokens`, Messages keeps `max_tokens`); `stream_options.include_usage` only on streaming Chat Completions; **a user-supplied auth header suppresses the inferred one** | <https://code.visualstudio.com/docs/agent-customization/language-models> |
| Zed | `Add Provider` UI + `openai_compatible`/`anthropic_compatible`; per-model `capabilities` (`tools`, `images`, `parallel_tool_calls`, `prompt_cache_key`, `chat_completions:false` forces Responses, `interleaved_reasoning`, `max_tokens_parameter`); `reasoning_effort` `none`..`max`; `custom_headers`; keys in OS keychain, never settings; env var derived as `<PROVIDER_ID>_API_KEY` upper-snake | <https://zed.dev/docs/ai/use-api-access> |
| LibreChat | Unlimited custom endpoints: `baseURL`, `apiKey` from env or user, `models.default` + `models.fetch`, `headers`, `addParams`/`dropParams`, native Anthropic via `provider: anthropic`, `customParams.reasoningFormat`/`reasoningKey`/`includeReasoningContent`/`includeReasoningHistory`, `tokenConfig` (context + pricing) | <https://www.librechat.ai/docs/configuration/librechat_yaml/object_structure/custom_endpoint> · <https://www.librechat.ai/docs/configuration/librechat_yaml/object_structure/custom_params> |
| Cherry Studio | Registry-driven presets merged as **preset → provider override → user overlay**; provider instance `id` distinct from `presetProviderId`; `endpointConfigs` map endpoint type → base URL + `adapterFamily`; per-model capability/price editing; "Check" key button; model-list fetchers as an ordered strategy registry with an always-match OpenAI-compatible fallback last | <https://deepwiki.com/CherryHQ/cherry-studio/11.2-adding-a-new-provider> · <https://deepwiki.com/CherryHQ/cherry-studio/9.3-provider-configuration> |
| OpenAI API status | Chat Completions remains supported, Responses recommended for new projects; **from GPT-5.4, Chat Completions does not support tool calling with `reasoning_effort` other than `none`**; Responses function defs are internally tagged/flat, `strict` defaults on, calls correlate by `call_id`; reasoning items must be replayed on function-call turns; `store:false` + `include:["reasoning.encrypted_content"]` keeps reasoning without server retention | <https://developers.openai.com/api/docs/guides/migrate-to-responses> · <https://developers.openai.com/api/docs/guides/reasoning> |
| Anthropic tool search (GA) | `tool_search_tool_regex_20251119`/`_bm25_20251119` in `tools`; `defer_loading: true` per tool; at least one tool must stay non-deferred; **every definition is still sent on every request**; max 10,000 deferred; search returns 5 by default; server call has `srvtoolu_` id and must never get a `tool_result`; prompt-cache prefix preserved | <https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool> |
| OpenAI tool search | `{"type":"tool_search"}`, `gpt-5.4`+ only; `defer_loading: true` per function; **`namespace` tool type** groups functions (`defer_loading` applies to the functions, not the namespace); hosted (`execution:"server"`) or client (`execution:"client"` → `tool_search_call`/`tool_search_output`); loaded tools appended at end of context to preserve cache; aim < 20 functions callable at turn start, < 10 per namespace | <https://developers.openai.com/api/docs/guides/tools-tool-search> · <https://developers.openai.com/api/docs/guides/function-calling.md> |

---

## 5. Architecture — the chosen design

These decisions are settled. Implement them; do not substitute alternatives.

### A. Identity: string instance ids, exhaustiveness moves to dialect

Delete `ProviderName`. A provider is identified by a `str` instance id validated
by `normalize_provider_id()` against `^[a-z0-9][a-z0-9_-]{0,63}$`. Built-in ids
keep their exact current string values, so `providers.json`, the sessions SQLite
column, `.env` variable names and the discovery cache all round-trip
byte-identically with **no data migration**.

A new `providers/ids.py` exposes `Final[str]` constants — `ANTHROPIC: Final = "anthropic"`,
`OPENAI: Final = "openai"`, … — so `ProviderName.OPENAI` becomes
`provider_ids.OPENAI`: readable, greppable, mechanical.

The critical move: **basedpyright exhaustiveness migrates from provider identity
(now open) to API dialect (closed)**. `ApiDialect` is a closed enum and
`_assert_never` is retained on *it*. No type safety is lost and no suppression is
introduced, which the locked basedpyright config requires.

`core/session.py:514,578,619,1007` currently does `ProviderName(row["provider"])`
and raises on an unknown value; with `str` it is strictly more permissive, so old
sessions keep loading and sessions from user instances become storable.

### B. Dialects: one adapter per wire format — and one provider that has none

New package `providers/dialects/`:

| Module | Class | Phase 1 | Phase 5 |
| --- | --- | --- | --- |
| `dialects/base.py` | `DialectAdapter` (ABC), `DialectRequest`, `DialectResponse`, `StreamDelta`, shared text-fallback renderer | full | — |
| `dialects/chat_completions.py` | `ChatCompletionsAdapter` | full | — |
| `dialects/responses.py` | `ResponsesAdapter` | full | + tool search, namespaces |
| `dialects/messages.py` | `MessagesAdapter` | behaviour-preserving lift-and-shift of today's `anthropic.py` wire code | full rewrite + tool search, deferred loading |
| `dialects/gemini.py` | `GeminiAdapter` | behaviour-preserving lift-and-shift of today's `google.py` wire code | full rewrite |

This resolves the phasing tension directly: **Phase 1 migrates all eight
providers onto the dialect *interface*** (Messages and Gemini as verbatim
shells, so there is provably no behavioural regression), and **Phase 5
*implements* Messages and Gemini properly**. Nothing is half-wired in between.

`DialectAdapter` surface: `build_tool_schemas`, `build_request`,
`parse_response`, `parse_stream_event`, `render_tool_result`,
`render_reasoning`, `auth_headers`, `endpoint_path`, `token_limit_field`.

**`local_transformers` is explicitly carved out.** It is not an HTTP provider at
all — it runs `AutoModelForCausalLM.from_pretrained` and `model.generate()`
in-process (`local_transformers.py:1007,1097`); its only httpx use is a
reachability probe at `:176`. It keeps implementing `LLMProviderBase` directly
and is outside `ApiDialect`. Any code that assumes "provider ⇒ dialect" must
tolerate `None`.

`providers/configurable.py::ConfigurableProvider` is the single HTTP provider
class, driven entirely by a `ProviderInstance` record. The seven HTTP built-in
classes are retained (no method binding is deleted) as thin preset-bound
subclasses; `LocalTransformersProvider` is untouched structurally.

**Consolidation:** two OpenAI schema builders currently disagree —
`base.py:1523 create_openai_tool_schema` applies `to_wire_name`,
`schemas.py:591 to_openai_schema` does **not**. The adapter becomes the one path
and always applies the wire mapping.

### C. Streaming

Each dialect owns its event model; `StreamDelta` is the normalized output
(`text`, `reasoning`, `tool_call_fragment`, `usage`, `finish`).

| Dialect | Events |
| --- | --- |
| Chat Completions | `choices[0].delta.content`, `delta.tool_calls[].function.arguments` fragments keyed by array index; `stream_options.include_usage` only here |
| Responses | semantic events: `response.created`, `response.output_text.delta`, `response.function_call_arguments.delta`/`.done`, `response.completed`, `error` |
| Messages | `content_block_start`/`content_block_delta`/`content_block_stop`, `message_delta`; thinking arrives as its own block type and carries the signature on `stop` |
| Gemini | streamed `candidates[].content.parts` |

`providers/base.py:1313 ToolCallBufferManager` is OpenAI-index-shaped; it is
generalized to key fragments by an opaque per-dialect correlation token (array
index for Chat Completions, `call_id` for Responses, block index for Messages).
`cancel_request` (`base.py:570`) must abort the underlying stream on every
dialect.

### D. Capabilities: three-layer merge, no heuristics

New `providers/capabilities.py::ModelCapabilities` covering tools, vision,
reasoning (supported + effort levels + wire format), context window, max output
tokens, `max_tokens` vs `max_completion_tokens`, parallel tool calls, prompt
caching, streaming, structured outputs, **tokenizer hint**, and pricing.
`ModelInfo` (`types.py:1439`) gains `capabilities`; existing scalar fields are
retained and derived from it so no binding breaks.

Resolution order, following Cherry Studio: **dialect/preset default → metadata
ingested from the endpoint's own `/models` payload → per-model user override
(always wins)**. `providers/openrouter.py:317 _build_model_info` already parses
`context_length`, `pricing`, `modality` and `supported_parameters`; it becomes
the generic ingester behind an ordered fetcher registry whose last entry is an
always-match OpenAI-compatible fallback.

The tokenizer belongs here, **not** on the dialect: an Anthropic-compatible
gateway serving Llama is not cl100k. `core/orchestrator.py:76
_PROVIDER_TOKEN_ENCODINGS` is replaced by a capability field defaulting to
o200k. `:89 _STREAMING_TOOL_CALL_PROVIDERS` *is* genuinely a dialect property
and re-keys to `ApiDialect`.

### E. Wire contract for externally-sourced tools

1. **Raw JSON Schema.** `ToolFunction` gains
   `input_schema: Mapping[str, object] | None`. When set it is authoritative and
   `parameters` is ignored; bridge tools keep using `parameters` unchanged. Per
   dialect: Messages and Chat Completions pass 2020-12 through; Responses inlines
   `$ref`/`$defs` and enforces strict-mode rules (all properties required,
   `additionalProperties:false`) or sets `strict:false`; Gemini reduces to its
   supported subset with uppercase types.
2. **`ToolDefinition.tool_name` becomes `str`** (11 construction sites, 8 using
   `tool_name=ToolName.X` — bridges pass `.value`). `ToolName` is retained as the
   canonical enum of *bridge* namespaces and stays the key of
   `core/tools.py::_bridges`. Bridge namespaces are reserved: an external tool
   may not claim `ghidra`, `frida`, `x64dbg`, `cutter`, `process`, `sandbox`,
   `hex_editor` or `tools`.
3. **Multi-part results.** `ToolResult` gains
   `content: list[ToolResultPart] | None` (text / image / audio / resource link /
   embedded resource / structured) and `is_error: bool`, keeping `result: object`
   for bridges.

   | Dialect | Native | Fallback |
   | --- | --- | --- |
   | Messages | `tool_result` blocks with text+image, `is_error` | resource link → text |
   | Chat Completions | text only | images re-emitted as a following `user` message with `image_url` when the model reports vision; else deterministic text |
   | Responses | `function_call_output` text, correlated by `call_id` | images as a following `input_image` item |
   | Gemini | `functionResponse.response` takes structured JSON natively | images as `inlineData` in a following user content |

   The text fallback is defined once in `dialects/base.py` so every dialect
   degrades identically.

4. **Reasoning replay.** `Message.thinking_content: str` is replaced by
   `reasoning: list[ReasoningItem] | None`, where `ReasoningItem` carries display
   text plus a provider-opaque payload that must be echoed back verbatim:
   Anthropic `signature` (and `redacted_thinking`), OpenAI Responses reasoning
   item `id` + `encrypted_content`, and OpenAI-compatible `reasoning_content`
   (LibreChat's `reasoningKey`/`includeReasoningContent`). `thinking_content` is
   retained as a derived read-only property so no binding breaks. Each adapter
   implements `render_reasoning` for the replay direction. This fixes the
   existing `anthropic.py:432` signature-drop defect.
5. **Dispatch boundary.** `core/tools.py:796 execute_tool_call` currently does
   `ToolName(tool_name.lower())` at `:821` and rejects anything else. It is
   generalized to resolve a namespace against the bridge registry **first**
   (unchanged behaviour, unchanged `_bridges` keying) and otherwise against a new
   external-executor registry. This plan ships the registry and the routing; a
   later MCP plan registers executors into it.
6. **`providers/tool_names.py` — what it must additionally guarantee.**
   The `.`↔`__` mapping and the deterministic blake2b fallback already handle
   three of the four external-tool cases and need **no change**:
   - *Already contains `__`*: `to_wire_name` self-checks the round-trip
     (`wire.replace("__",".") == canonical`), which fails, routing it to the
     registered hash fallback. Correct today.
   - *Exceeds 64 chars*: the fallback truncates to the **last** 64 chars, which
     always retains the full 16-hex digest, so collision resistance survives.
     Correct today.
   - *Not dotted* (the common MCP case, e.g. `read_file`): passes through
     unchanged, and `from_wire_name` is idempotent on it. Correct today.

   Two genuinely new guarantees are required:
   - **Registry rehydration.** Fallback reversal depends on the process-local
     `_wire_to_canonical` dict that `to_wire_name` populates. A tool present in
     *replayed history* but absent from the active set — exactly what tool search
     and deferred loading cause — would reverse through the primary `__`→`.`
     path and yield the wrong canonical name. The wire layer must call
     `to_wire_name` over the union of *(active tools ∪ every tool referenced in
     replayed history)* before any `from_wire_name`. No new persistence.
   - **Namespace-aware pair form.** Under OpenAI namespaces the wire identity is
     the pair `(namespace, name)`: `ghidra.decompile` is sent as namespace
     `ghidra` + function `decompile`. Add `to_wire_pair`/`from_wire_pair` sharing
     the same fallback registry. Intellicrack's dotted bridge names map onto
     namespaces exactly.

### F. Configuration, secrets and security

`.env` stays authoritative for built-ins. `ProviderSettingsStore` grows an
`instances` section at `SETTINGS_SCHEMA_VERSION = 3`. **Built-in providers are
presets that materialize as ordinary editable instances** — one mechanism, so a
user can duplicate OpenAI for a second account or pin it at a proxy. Deleting a
built-in instance restores it from its preset rather than orphaning it.

*Downgrade rule:* `_uses_current_schema` tests `version >= SETTINGS_SCHEMA_VERSION`,
so an older build reading a v3 file already treats it as legacy and applies its
own defaults rather than crashing. v3 therefore keeps every v2 key in place and
only *adds* the `instances` section — a v3 file stays readable by a v2 build,
losing only the custom instances it could not use anyway.

Secrets for all instances go to the **existing** `credentials/store.py::CredentialStore`
(already OS-keyring backed with `KeyringUnavailableError` and an env fallback),
keyed by instance id, with `<INSTANCE_ID>_API_KEY` upper-snake in `.env` as an
override. Prefix key validation (`env_loader.py:428-454`) is replaced by
per-instance validation that never rejects a valid third-party key. Keep each
stored payload under the 1280-character Windows Credential Manager cap and
surface an over-cap write as a typed `CredentialStoreError`.

Security posture (all four adopted):

- **`store: false` by default on Responses**, with `include:["reasoning.encrypted_content"]`
  so multi-turn reasoning still works without OpenAI retaining binary-analysis
  context. Per-instance opt-in toggle.
- **Transport.** `https://` anywhere is fine. `http://` to loopback or a
  private range is allowed silently — the Ollama/LM Studio/vLLM case must have
  no friction. `http://` to a public host requires one explicit, persisted
  per-instance acknowledgement before the API key is attached. Warn, never
  hard-block, or a legitimate internal gateway becomes unusable.
- **Headers.** Follow VS Code, not Zed: the user *may* override auth headers
  (`Authorization`, `api-key`, `x-api-key`), because gateways and APIM require
  it, and when they do the inferred auth header is suppressed so the endpoint
  never receives two conflicting credentials. Hard-deny only protocol-breaking
  headers (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`). Before
  save, the UI names every header that will receive the interpolated `${apiKey}`.
- **Import/export.** Exports never contain secrets. On import, an instance whose
  base-URL host matches no known preset shows host and headers and requires
  confirmation before it goes live.

---

## 6. The work

Implement the phases in order. Each phase depends on the ones before it.

### Phase 1 — Identity and dialects

| Item | Files / symbols |
| --- | --- |
| 1.1 Introduce ids | **new** `providers/ids.py` (`Final[str]` per built-in, `normalize_provider_id`, `BUILTIN_PROVIDER_IDS`) |
| 1.2 Delete the enum | `core/types.py:258-268` remove `ProviderName`; retype `ModelInfo.provider` (`:1457`) to `str` |
| 1.3 Re-key every holder | `providers/registry.py` (`_providers`, `_provider_classes`, `_active_provider`, register/get/get_or_raise/unregister/list_registered); `credentials/env_loader.py` (`PROVIDER_MAPPINGS`, `get_credentials`, `get_connect_credentials`, `_validate_key_format`); `credentials/store.py` (`StoredCredential.provider`, keyring key builders); `credentials/provider_settings.py` (`ProviderConnectPolicy.timeouts`, `is_enabled`, `timeout_for`, `apply_timeout`); `core/config.py:337,451,454,485,524`; `core/session.py:77,115,146,514,578,619,1007,1208`; `providers/discovery.py` (`DiscoveryCache` get/set/invalidate/`_parse_cache_entries`/`get_all_cached`/`get_provider_model_count`); `providers/display_names.py` (`NO_API_KEY_PROVIDERS`); `credentials/oauth.py:102`; `ui/preferences.py:120,200`; `ui/app.py:245,295-305,331-332,505-580,1022,1593-1650`; `main.py:764-789`; `providers/base.py` (`name` → `str`) and all 8 subclasses. **Includes `core/orchestrator.py:1002` (`ProviderName(provider.lower())` — case normalization now explicit) and `:1007` (`provider.value` → the id itself).** |
| 1.4 Dialect abstraction | **new** `providers/dialects/{__init__,base,chat_completions,responses,messages,gemini}.py`; Messages/Gemini are behaviour-preserving shells in this phase |
| 1.5 Retarget schema dispatch | `bridges/schemas.py`: `get_schema_for_provider`→`get_schema_for_dialect` (`:670-702`, `_assert_never` now over `ApiDialect`), `get_all_schemas_for_provider` (`:705`), `validate_tool_for_provider` (`:725`, drops the `provider not in set(ProviderName)` check at `:743`); `core/orchestrator.py:89 _STREAMING_TOOL_CALL_PROVIDERS` re-keys to `ApiDialect` |
| 1.6 Migrate 7 HTTP providers | `providers/{anthropic,openai,google,ollama,openrouter,huggingface,grok}.py` delegate to their adapter. **`local_transformers.py` is explicitly excluded** (in-process, no dialect) |
| 1.7 OpenAI onto Responses | `providers/openai.py`: delete `_REASONING_MODEL_PREFIXES` (`:73`), `_supports_reasoning_effort` (`:78`), `_supports_max_completion_tokens` (`:471`), the `startswith` branches at `:244`/`:262`; route per-model via capabilities; `reasoning_effort` top-level (Chat Completions) vs nested `reasoning.effort` (Responses); `max_completion_tokens` vs `max_output_tokens`; temperature omitted where the family rejects non-1; `store:false` + encrypted reasoning |
| 1.8 Streaming | Generalize `providers/base.py:1313 ToolCallBufferManager` to an opaque correlation token; per-dialect `parse_stream_event`; `cancel_request` (`:570`) aborts on every dialect |
| 1.9 Consolidate schema builders | `base.py:1523 create_openai_tool_schema` folded into `ChatCompletionsAdapter`; `to_wire_name` applied on the one path |

**Behavioural contract** (the local session gates these; you cannot):

- An instance with id `"my-gateway"` registers, connects, lists models and
  completes a tool-calling chat. Today `ui/app.py:331` drops it.
- `grep -rn "ProviderName" src/` returns zero hits.
- Deleting one branch of `adapter_for()` must produce a basedpyright
  `_assert_never` error — exhaustiveness moved rather than evaporated.
- A GPT-5.x-class model's request body has `max_completion_tokens`, no
  `temperature`, `store:false`, and posts to `/responses`; a GPT-4-class model
  has `max_tokens` and posts to `/chat/completions`.
- Anthropic and Google produce **byte-identical** request bodies before and
  after 1.6 (the lift-and-shift guarantee).
- Cancelling mid-stream on each dialect disconnects server-side.
- A pre-change session row still loads; `providers.json` and `.env`
  byte-unchanged.

### Phase 2 — Wire contract for externally-sourced tools

| Item | Files / symbols |
| --- | --- |
| 2.1 Raw JSON Schema | `core/types.py:1516 ToolFunction` + `input_schema`; `bridges/schemas.py` `build_schema_parameters`/`_build_json_schema_parameters`/`_build_google_schema_parameters`/`build_schema_property` gain a raw-schema path; **new** `bridges/json_schema.py` (`inline_refs`, `to_strict_subset`, `to_gemini_subset`) |
| 2.2 Container name | `core/types.py:1543 ToolDefinition.tool_name` → `str`; `providers/base.py:745,779,786`; `bridges/schemas.py:525`; the 8 `tool_name=ToolName.X` sites; reserved-namespace check |
| 2.3 Multi-part results | `core/types.py:358 ToolResult` + `content`/`is_error`; **new** `ToolResultPart` union; `providers/base.py:202 serialize_tool_result` becomes the shared fallback in `dialects/base.py`; per-dialect `render_tool_result` |
| 2.4 Wire-name guarantees | `providers/tool_names.py` + `to_wire_pair`/`from_wire_pair` + `rehydrate_wire_names`; called from `dialects/base.py` over active ∪ history |
| 2.5 Reasoning replay | **new** `core/types.py::ReasoningItem`; `Message.thinking_content` → `reasoning` list with `thinking_content` retained as a derived property; `providers/anthropic.py:416-446` captures `signature` and `redacted_thinking`; `ResponsesAdapter` replays reasoning items incl. `encrypted_content`; `ChatCompletionsAdapter` replays `reasoning_content`; per-adapter `render_reasoning`; `base.py:553 get_pending_thinking` retained |
| 2.6 Dispatch boundary | `core/tools.py:796 execute_tool_call`, `:821 ToolName(tool_name.lower())` → bridge registry first, then **new** external-executor registry; `_bridges` keying unchanged |

**Behavioural contract:**

- A tool declared with a raw 2020-12 schema using `$ref`/`$defs`/`anyOf` is
  accepted; refs intact for Messages, inlined for Responses strict mode,
  reduced for Gemini.
- A multi-part result (text + PNG + structured + `is_error`) renders natively on
  Messages and as the defined fallback on Chat Completions.
- Every existing bridge tool produces a **byte-identical** schema to the
  pre-change output.
- A two-turn Anthropic exchange with thinking enabled and a tool call replays
  the thinking block *with its signature*. Same shape for Responses reasoning
  items.
- An external tool with namespace `mcp_files` executes through the external
  registry; one claiming `ghidra` is rejected.
- A history referencing a tool no longer in the active set still resolves to its
  canonical name.
- Round-trip holds for names containing `__`, > 64 chars, non-dotted, and
  containing `/`.

### Phase 3 — Capabilities

| Item | Files / symbols |
| --- | --- |
| 3.0 Store schema v3 | `credentials/provider_settings.py`: `SETTINGS_SCHEMA_VERSION` 2→3 + `instances` section, **moved ahead of the UI** so per-model overrides have somewhere to live |
| 3.1 Capability record | **new** `providers/capabilities.py` (`ModelCapabilities`, `ReasoningSupport`, `TokenLimitField`, tokenizer hint, `merge_capabilities`); `core/types.py:1439 ModelInfo` + `capabilities` |
| 3.2 Generic ingestion | **new** `providers/model_metadata.py` generalizing `providers/openrouter.py:317`; ordered fetcher registry, OpenAI-compatible fallback last |
| 3.3 Delete heuristics | `providers/openai.py:244-262`, `:318` |
| 3.4 Context-window resolution | `core/orchestrator.py:1876` — exact → capability record → normalized/suffix-stripped id → per-model override → `context_window_override`; `:1927` message updated; `:76 _PROVIDER_TOKEN_ENCODINGS` replaced by the capability tokenizer hint |
| 3.5 Discovery isolation | `providers/discovery.py` — per-instance timeout and failure isolation so one slow custom endpoint cannot stall the sweep; cache schema version bumped (legacy entries = cold cache, no data loss) |
| 3.6 UI surfacing | `ui/provider_config.py` per-model context-window override; remove truncation at `:1274` (`[:20]`), `:1388` (`[:50]`), `:1456` (`[:30]`); model combo `setEditable(True)` (`:3384`) |

**Behavioural contract:**

- A `/models` payload advertising `context_length`, `max_completion_tokens`,
  function calling, vision and pricing resolves to `ModelCapabilities` matching
  it field-for-field.
- User override beats ingested metadata beats dialect default.
- A suffixed id (`my-model:free`, `my-model@2026-01`) resolves a context window;
  today it raises `ToolError`.
- An endpoint returning 137 models shows all 137; a hand-typed id is accepted.
- One endpoint hanging for 30 s does not delay discovery of the others.
- `grep -n 'startswith(("o1"' providers/openai.py` → no hits.

### Phase 4 — Configuration, secrets and UI

| Item | Files / symbols |
| --- | --- |
| 4.1 Instance model | **new** `providers/instances.py::ProviderInstance`; **new** `providers/configurable.py::ConfigurableProvider`; built-in presets materialize as editable instances; the 7 HTTP built-in classes become preset-bound subclasses |
| 4.2 Headers / body params | `ProviderInstance.headers` (`${apiKey}` interpolation, VS Code auth-suppression rule, protocol-header hard-deny), `extra_body`, `drop_params`; applied in `dialects/base.py` |
| 4.3 Secrets | `credentials/store.py` keyed by instance id; `<INSTANCE_ID>_API_KEY` derivation; replace `_validate_key_format` (`:428-454`) with non-rejecting validation |
| 4.4 Provider UI | `ui/provider_config.py`: add/edit/duplicate/delete, dialect picker, per-model capability editor, header/param editors, import/export with host confirmation; collapse the if-chains at `:690-705` (tests) and `:1071-1086` (fetches) into dialect-driven probes; replace API-base gating at `:2517-2527` with an always-present base-URL field plus the transport policy; `_provider_default_api_base` (`:244`) reads presets |
| 4.5 Presets | **new** `providers/presets.py` for the 8 built-ins plus common OpenAI-/Anthropic-compatible endpoints |
| 4.6 Startup | `main.py:764-789` builds from presets + saved instances instead of the hardcoded 8-tuple |

**Behavioural contract:**

- Two instances of the same dialect with different base URLs and keys connect
  concurrently with separate credentials.
- The built-in OpenAI entry can be duplicated and the copy pointed at a proxy,
  with both usable simultaneously.
- Instances, headers, params, overrides and model lists survive restart; keys
  never appear in `providers.json`.
- A key not matching any known prefix (`Bearer abc123`) is accepted — today
  `env_loader.py:441` rejects it.
- A user-supplied `Authorization` header suppresses the inferred one — exactly
  one credential on the wire.
- `http://` to loopback saves silently; `http://` to a public host refuses to
  attach the key until acknowledged.
- Export → delete → import reproduces the instance minus secrets, with host
  confirmation demanded for an unknown host.

### Phase 5 — Remaining dialects and large toolsets

| Item | Files / symbols |
| --- | --- |
| 5.1 Messages dialect | `providers/dialects/messages.py` full implementation replacing the Phase 1 shell; `providers/anthropic.py` reduced to preset + capabilities |
| 5.2 Gemini dialect | `providers/dialects/gemini.py` full implementation; `providers/google.py` likewise; preserves `ToolCall.thought_signature` (`types.py:335`) echo-back |
| 5.3 Anthropic deferred loading | `MessagesAdapter`: emit `tool_search_tool_regex_20251119`/`_bm25_20251119`, `defer_loading: true` on all but the non-deferred head, handle `server_tool_use`/`srvtoolu_` (never return a `tool_result` for it) |
| 5.4 OpenAI tool search | `ResponsesAdapter`: `{"type":"tool_search"}` + `namespace` entries built via `to_wire_pair`; `defer_loading` on member functions; parse `tool_search_call`/`tool_search_output` |
| 5.5 Capability-aware cap | `providers/base.py:712 _enforce_tool_count_cap`, `:352 TOOL_COUNT_CAP` become capability-derived: with Anthropic defer_loading the budget is 10,000 deferred (all ~715 functions ship); with OpenAI namespaces the 128 cap applies only to functions callable at turn start |
| 5.6 Report back | **new** `SentToolReport` (sent / deferred / truncated / dropped) + `get_last_sent_tools()`, mirroring `get_pending_tool_calls`/`get_pending_usage`/`get_pending_thinking` (`base.py:521-553`) |

**Behavioural contract:**

- All ~715 tool functions are sent to a Messages endpoint with exactly one
  non-deferred head; a request deferring *every* tool is rejected before it
  leaves the process (Anthropic 400s on that).
- Tools reach a Responses endpoint grouped as `namespace` entries; a
  `tool_search_output` naming a deferred tool makes it callable, and the call
  reverses through `from_wire_pair` to its canonical dotted name.
- `get_last_sent_tools()` reconciles exactly with the request body.
- Input order equals wire order — the layer never reorders the priority list it
  is handed.

---

## 7. Risk mitigations that shape the code

- **R1 — Responses migration must not regress the working OpenAI provider.**
  Routing is capability-gated: a model whose record says `chat_completions`
  stays on Chat Completions. Both paths ship behind the same adapter interface.
- **R2 — Third-party endpoints may reject `__` wire names, or rewrite them when
  proxying upstream.** Provide a per-instance `tool_name_style` escape selecting
  pass-through-dotted; `from_wire_name` is already idempotent on canonical names.
- **R5 — The discovery cache is persisted and keyed by the enum.** Bump the cache
  schema version; legacy entries are treated as a cold cache. It is a TTL cache,
  so there is no data loss.
- **R6 — Reasoning-item replay is provider-opaque and easy to corrupt silently.**
  Opaque payloads are stored and echoed **verbatim**, never re-serialized,
  re-ordered or normalized.

---

## 8. Non-goals — do not build these

- MCP client, MCP server configuration, MCP tool discovery. This work ships the
  wire contract **and** the external-executor registry; a later MCP plan
  registers executors into it.
- Tool-selection policy and ranking. This layer receives a final,
  priority-ordered list and never reorders it.
- Embeddings, image-generation, audio and rerank endpoints; chat/tool-calling only.
- Provider-hosted built-in tools (web search, file search, code interpreter,
  computer use) and OpenAI stateful `previous_response_id` / Conversations —
  `store:false` is the default posture.
- Routing, failover, load-balancing or cost-optimisation across instances.
- Replacing `.env` as the authority for built-in providers.
- Changing the local `tools.search` meta-tool (`core/tool_search.py`); native
  large-toolset support is added alongside it.
- Giving `local_transformers` a dialect; it stays in-process by design.

---

## 9. Explicitly out of scope for you — the local session owns these

Do not attempt any of the following, and do not write code whose only purpose
is to satisfy them:

- **Writing tests of any kind.** No new test files, no edits to existing tests
  *except* the mechanical `ProviderName` → provider-id rename required by 1.3 in
  the 89 test files that reference it. Those edits are mechanical renames only —
  do not change what any test asserts.
- **Test infrastructure**, including any extension of
  `tests/_helpers/provider_endpoint_server.py`.
- **Running or reporting any gate** other than `ruff`.
- **Live-endpoint spikes** (Responses parity, wire names through a real
  gateway), GUI verification, and Windows keyring verification.

If you believe something needs a test to be trustworthy, note it in your final
summary instead of writing one.

---

## 10. Delivery

- Work on `feat/arbitrary-providers`. Commit per phase, or per coherent slice
  within a phase for Phase 1.3 — that item alone touches 26 source files and 89
  test files, so split it by subsystem (registry, credentials, config/session,
  discovery, ui, main, providers) into reviewable commits.
- Every file you touch ends `ruff check` clean.
- Open a pull request when done. In the PR description, list:
  1. Which phases and items are complete, and which are not.
  2. Every behavioural-contract bullet you believe your code satisfies but that
     has **not** been verified, so the local session knows what to gate.
  3. Anything you had to leave working-as-before because completing it properly
     needed an environment you did not have.
- Do not claim any test passed. Do not claim basedpyright is clean.
