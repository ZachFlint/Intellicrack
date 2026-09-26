# Fix every defect in the MCP client and AI provider layers

Fix every item below in `src/intellicrack/`. The items were found by a review of merges `c977291b` (arbitrary providers) and `4d9cf274` (MCP client). File:line references are from `main` at `ff6859ae`, and may have drifted.

## Rules

- **Every item must be fixed for real.**
  - Nothing gets skipped, deferred, stubbed, or worked around by deleting the feature, disabling the code path, or narrowing what's accepted.
  - If an item is marked **(verify)**, confirm it against the code first. If it turns out not to be a defect, say so in the final report along with the evidence.
- **Fix the root cause, not the symptom.**
  - Don't add a `default=str` to `json.dumps` to hide the result-type bug.
  - Don't broaden `except Exception` to hide the error-type bug.
- **Check behaviour against the installed SDKs and the real wire protocols.** Don't trust memory for any of it.
  - Installed SDKs: `mcp` 2.2.0 (spec 2026-07-28), `openai` 3.16.2, `anthropic` 1.7.0, `google-genai` 2.24.0.
  - Inspect the installed package source and signatures.
  - Where a vendor API detail matters, use current vendor docs.
- **Follow `CLAUDE.md` in full**:
  - full type hints;
  - zero `basedpyright` findings;
  - zero `ruff`, `pydoclint` and `pydocstyle` findings;
  - no suppression comments of any kind;
  - no edits to linter or type-checker config;
  - Google docstrings;
  - no explanatory comments;
  - Windows-first behaviour;
  - never delete method bindings.
- **Every fix needs a real, falsifiable test** under the matching `tests/` subdirectory.
  - The test must fail when the fix is reverted. Prove this for each fix by reverting it and watching the test go red.
  - Use real inputs: a real MCP server (the SDK's `MCPServer` over stdio, SSE and streamable HTTP), the real provider SDKs against a loopback HTTP server, and real SSE byte streams.
  - Don't assert on mocks.
  - Windows-only behaviour (job objects, Credential Manager, `.cmd` shims) must be tested on Windows. A platform `skipif` is allowed only for those tests, and each one must name the Windows behaviour it covers.
- **Order of work:** do the Blockers first. MCP blockers 1–3 are coupled: MCP tool calls won't work until all three are fixed.
- **Final report:** list every item as fixed or not-a-defect, with the test that covers it and the evidence of the revert-to-red check. Also list any item you could not verify in this environment.

## Blockers

1. **MCP tool results can't be serialized.**
   - `McpToolSource.call` (`mcp/tool_source.py:633`) returns `list[ToolResultPart]`, which the orchestrator stores in `ToolResult.result` (`core/orchestrator.py:2983`).
   - Every dialect then runs `serialize_tool_result` → `json.dumps` on it (`providers/dialects/base.py:251`; also `providers/base.py:1260` and `dialects/gemini.py:440`), which raises `TypeError`.
   - `ToolResult.content` and `ToolResult.is_error` are never populated in production.
   - Fix: route multi-part results into `content` and `is_error`, so the dialects' native text, image and structured paths are used.
2. **Session save crashes when MCP results are in history.**
   - `core/session.py:245` writes the raw result, and `:695` calls `json.dumps` on it.
   - The `TypeError` escapes inside `BEGIN IMMEDIATE` without a rollback, because the `except` only catches `sqlite3.Error` and `OSError`.
   - Fix: serialize multi-part content properly, round-trip it on load, and make any failure inside the transaction roll back.
3. **MCP errors abort the whole turn.**
   - `McpError` derives from `IntellicrackError` and is not caught by `core/tools.py:543` (`_execute_external`) or `orchestrator.py:3012`.
   - `log_tool_call` records these calls as success.
   - `tool_source.py:629-632` raises on `isError`, which contradicts its own docstring.
   - Fix: return tool errors to the model as `is_error` results carrying their full content (not cut to 512 characters, with images and structured detail kept). Turn connection, timeout, invalid-params (-32602), disabled-tool and outputSchema failures into failed `ToolResult`s.
4. **A custom provider instance's API key is never saved.**
   - `_persist_api_key_to_env` (`ui/provider_config.py:4391-4394`) returns early because `get_api_key_env_var_mapping()` (`credentials/env_loader.py:1061`) covers only built-ins. The key is lost on restart.
   - Fix: persist custom-instance keys through the instance's derived credential mapping, and load them at startup.
5. **OpenAI Responses streaming crashes.**
   - `_iter_responses_stream` (`providers/openai.py:1239-1254`) runs `async for` over a `Response` object.
   - `AsyncStream[object]` yields dicts, which `_event_mapping` (`:103-108`) turns into `{}`.
   - This affects every `gpt-5*`, `gpt-6*` and o-series streamed turn.
6. **Custom Gemini streaming yields nothing.**
   - `dialects/gemini.py:498` requests `:streamGenerateContent` without `?alt=sse`.
   - `configurable.py:616-627` parses the response line by line, which can't handle the JSON array the server returns without that flag.

## MCP: connection and transport

7. **Dead servers stay READY.** The heartbeat relies on `send_ping`, which spec 2026-07-28 removed (`connection.py:735-788`, `387`). The first `METHOD_NOT_FOUND` disables heartbeats permanently, even across reconnects. A clean server exit, or `call_tool` returning "Connection closed", never triggers a reconnect.
8. **`type: "sse"` servers are driven with `streamable_http_client`** (`transport.py:317`, `connection.py:519-521`). Use the SDK's SSE client and the legacy client mode.
9. **Sandboxed launch can't identify the server process.**
   - It diffs child PIDs and requires one image whose stem matches (`connection.py:654-689`, `1095-1108`).
   - This fails for `.cmd` and `.bat` shims such as `npx` (`cmd.exe`) and for venv `python.exe` (two processes).
   - For chained launchers (uvx → uv → python) the launcher is adopted instead of the real server (verify).
   - Adoption happens after the handshake, so server startup and its early children run unconfined.
   - Fix: the process tree must be inside the job from creation.
10. **The sandbox doesn't provide the confinement its config and docstrings promise** (`mcp/sandbox_launch.py`, `config.py:304-318`, `connection.py:556-567`).
    - Implement the restricted token and write confinement (`allow_write`).
    - Enforce `allowed_domains`, or make the config and UI say plainly that it isn't enforced. It must not claim protection it doesn't give.
    - Make the environment a true allowlist instead of a merge over `get_default_environment()`.
    - Use or remove the dead `SandboxedLaunch.command`, `.args`, `.creation_flags` and `.limits` fields.
11. **`CONNECT_TIMEOUT_S=45` (`connection.py:94`, `878`) wraps the launch-consent prompt and the interactive OAuth flow.** It cancels them while the dialog or browser is still open (the UI allows 900 s, OAuth 300 s). Operator wait time must not count against the connect timeout.
12. **The `listen` subscription runs once** (`connection.py:1028-1070`, `1352`) and is never restarted after a reconnect. On older servers, `notifications/tools/list_changed` arriving via `message_handler` → `_on_incoming` (`717-733`) is ignored.
13. **The reconnect attempt counter is never reset** after a successful READY period (`connection.py:803-846`). A healthy server becomes permanently FAILED after 8 drops over a session.
14. **A change notification inside the server's `ttlMs` window returns the cached catalog** (`connection.py:969-971`, `catalog.py:142-157`). A notification must force a real refresh.
15. **`tiktoken.get_encoding` downloads with no timeout and no negative caching** (`mcp/policy.py:62-69`). It runs on the Qt thread (`ui/mcp_config.py:587`), and the orchestrator uses the same pattern.
16. **`open_web_url` (`transport.py:92-93`) re-parses the URL unguarded** and raises `ValueError` on input like `http://[::1`.

## MCP: auth, config, secrets

17. **OAuth tokens over about 1.2 KB fail to store on Windows** because of the Credential Manager 2560-byte blob limit (`auth.py:249-257`, `credentials/store.py:372,389`). `McpSecretResolver.set_input` has the same problem, and its error message wrongly says "install keyring".
18. **The configured OAuth client id is never used.** `resolve_client_identity` (`auth.py:316-372`) has no callers, and `build_oauth_provider` (`:425-460`) ignores `spec.oauth_client_id`.
19. **The stored client registration is discarded on every restart** when the authorization server is on a different host from the MCP server. Storage is keyed to the MCP server's origin, but the SDK stamps `client_info.issuer` with the authorization server (`auth.py:88-105`, `278`, `296`). `issuer_for` also keeps default ports, while the SDK drops them.
20. **Refresh tokens are unused after a restart.** No absolute expiry is stored, so an expired access token is sent and the 401 triggers a full re-authorization (`auth.py:231-257`).
21. **All OAuth flows share the fixed port 8724.** `OAuthCallbackServer.start` sets `socketserver.TCPServer.allow_reuse_address = True` globally, so two flows can bind the same port on Windows.
22. **The callback server handles exactly one request of any path** (`credentials/oauth.py`, and `auth.py:412` builds it without `expected_state`). A stray favicon or probe request ends the flow.
23. **`DEFAULT_SCOPE` (`auth.py:61`) has no effect**, because the SDK overwrites the scope. Fix the behaviour or the documented claim.
24. **Keyring read failures are silently reported as "not stored"** (`store.py:339-344`). The promised `McpAuthError` never fires, and the user is told to re-enter the secret.
25. **Config import rejects valid input and accepts invalid input** (`mcp/config.py`):
    - `SERVER_ID_PATTERN` (39) rejects keys such as `GitHub` and `my_server` (normalise them instead), and `parse_document` (1077) rejects the whole document over one bad key.
    - `_parse_transport_kind` (755-783) rejects `streamable-http` and `streamableHttp`.
    - The literal-secret heuristics (123-242) flag URLs, file paths and UUIDs.
    - `args` get no secret check.
    - `${input:x}` in `args` passes parsing but is never resolved, so launch then refuses it (`transport.py:214-219`).

## MCP: tool routing, consent, validation

26. **`_inline_node` (`bridges/json_schema.py:127-157`) takes exponential time on recursive `$ref` schemas with two self-references.** It's reached from `mcp/validation.py:570` and from the Responses and Gemini `build_tool_schemas`.
27. **The ReDoS guard (`mcp/validation.py:53-125`) misses these patterns:**
    - `(a+){2,40}`
    - `(.*a){12}`
    - `a*a*a*a*a*b`
    - `(a{1,1000})+`
    Server-controlled patterns must not be able to block the loop.
28. **Untrusted server text is never fenced** despite the docstring and `catalog_lines()` saying it is. Raw descriptions go into the system prompt (`orchestrator.py:2089-2101`, `1993`), `tools.search` (`2790`) and provider tool definitions. Results aren't fenced or stripped of control characters (`tool_source.py:147`, `map_result`).
29. **`from_canonical_name` raises `McpConfigError` (`config.py:505`), but callers catch only `McpProtocolError`**: `tool_source.py:523/544/567`, and `orchestrator.py:745` catches neither. The wire name `mcp-files__` crashes classification, or leaves the GUI confirmation future unresolved (`ui/app.py:1632`).
30. **Consent and trust can't be revoked** (`consent.py`, `ui/mcp_bridge.py:137-138`).
    - `TrustStore.reset` and any `set_state` other than TRUSTED have no callers, and there's no UI to use them.
    - A changed launch command approved without the trust box keeps the old TRUSTED state.
    - Trust is keyed by server id alone.
    - A single "No", or a timeout (`CONSENT_TIMEOUT_S=900`, `consent.py:681-684`), sets DENIED forever, while the error text points to a non-existent reset control.
31. **Persisted "Always" approvals (`ui/confirmation_dialog.py`, `consent.py:518-592`) are offered for built-in bridge tools** (generation `""`, so never invalidated). No UI lists or revokes them.
32. **`json_schema.py:157` removes properties named `definitions` or `$defs`** while leaving them in `required`.
33. **MCP tools are rendered to the model as taking no arguments**, because `ToolFunction.signature` (`core/types.py:1734`) and `_render_tool_function` read `parameters`, not `input_schema`.
34. **Trimming can orphan a tool result** (`trim_messages_to_context_window`). It can drop the assistant `tool_calls` message and keep its tool result.
35. **Token counting and bounding of multi-part content** (`orchestrator.py:2288-2289`):
    - `_message_tokens` counts base64 image data as text.
    - `_bound_message_for_llm` doesn't bound `content`.
36. **Output-schema validation rejects `nullable: true`**, and `const`/`enum` treat `1 == True`.
37. **`register_all()` runs on the GUI thread (`ui/mcp_service.py:303`)** and mutates `ExternalToolRegistry` while the loop thread iterates it.

## MCP: UI

38. **The elicitation form (`ui/mcp_elicitation_dialog.py:241-338`) doesn't follow the requested schema:**
    - It ignores `minimum`, `maximum`, `minLength` and `pattern`.
    - Optional numbers default to 0 and are always sent, and an optional enum sends its first option.
    - Titled `oneOf`/`const` enums and multi-select arrays fall back to a text field, and arrays are returned as strings.
    - URL-mode Send returns `content={}` (`372-383`).
    - Missing required fields are signalled only in the window title.
39. **Prompts whose future times out or is cancelled stay open, and their late answer is discarded** (`ui/mcp_bridge.py:186-220`). A late consent approval still sets TRUSTED. Elicitation is effectively capped by the 60 s `call_tool` timeout (`connection.py:1014-1017`), not by `ELICITATION_TIMEOUT_S`.
40. **The Sign-out button is permanently disabled.** `refresh_auth_state` (`ui/mcp_config.py:1395-1414`) runs only once, before any selection.
41. **The MCP Settings editor loses edits and reports false changes** (`ui/mcp_config.py:1040-1063`, `466-492`):
    - Switching servers discards unsaved edits.
    - Just selecting a server marks the dialog dirty.
    - Save applies only the current server.
42. **A server added in the dialog is created with `enabled=False` but shows "running, N tools" while advertising nothing** (`ui/mcp_config.py:1160-1177`, `1292-1314`, `mcp/policy.py:143`).
43. **Renaming a running server orphans its process until exit** (`ui/mcp_config.py:1154-1156`).
44. **Shutdown doesn't cancel the in-flight `service.start()`** (`ui/app.py:1475-1489`, `connection.py:1274-1278`). Servers can start after MCP stops (verify). `manager.start` is sequential, so one pending OAuth sign-in stalls every later server, and the GUI never says a browser was opened.
45. **GUI-thread state is mutated from the loop thread without synchronisation**: `ToolConfirmationDialog._remembered_decisions` and `session.mcp_servers` (`ui/mcp_service.py:173-206`).
46. **Wire up or remove the dead code:**
    - `McpService.record_session_state` (a new or restored session gets no MCP state)
    - `mcp_bridge.elicitation_factory`
    - `resolve_elicitation` and `build_declined_result`
    - `McpServerConsentDialog.for_config`
    - the listener-less signals `answered` and `decision_made`
    - `McpToolSource.costs`, `.definitions` and `.execute`
    - `resources.list_prompts` and `get_prompt`
    - `consent.deny_all_launches`
    - `_resolve_loaded_external_name` (`orchestrator.py:2861`)
47. **The `ImportError` fallback in `app._start_mcp_service` can't fire**, because `ui/__init__.py` and `chat.py` import `mcp` at module level. A missing SDK must disable MCP, not break the UI.
48. **Every opening of MCP Settings leaks a dialog** (`ui/mcp_service.py:297-303`).

## Providers: dialects and ConfigurableProvider

49. **Streaming HTTP errors surface as `httpx.StreamClosed`.** The stream is closed before `_read_error_body` reads it (`configurable.py:575-577`).
50. **The Responses branch of `chat_stream` bypasses error translation** (`openai.py:954-968`).
51. **Gemini `thought_signature` is replayed as `bytes` over raw HTTP** (`gemini.py:239-241`, sent via `configurable.py:451`). It must be the base64 string. Also: `_post_json` doesn't wrap `TypeError`.
52. **Responses reasoning replay omits the required `summary` field** (`responses.py:561-566`), and `reasoning_param` never requests summaries.
53. **`_strictify` claims `strict: true` for non-compliant schemas** (`responses.py:247-255`, `json_schema.py:254-269`): free-form objects and map-style `additionalProperties`.
54. **Responses tool-search `namespace` is ignored when parsing and on replay** (`responses.py:680-699`, `736-767`, `309-316`).
55. **Mid-stream errors are dropped** (`configurable.py:530-545`, `messages.py:512-516`, `responses.py:487-493`):
    - `finish="error"` is never checked.
    - `response.failed` and `response.incomplete` aren't handled.
    - Chat Completions `{"error":…}` chunks are ignored.
56. **Anthropic thinking always sends `{"type":"enabled","budget_tokens":N}`** (`anthropic.py:292-305`, `messages.py:340-343`, `presets.py:155-159`). Current models (Opus 4.7+, Sonnet 5, Fable) need `{"type":"adaptive"}` plus `output_config.effort`. Resolve this per model.
57. **`merge_auth_headers` drops `anthropic-version` when a custom auth header is set** (`dialects/base.py:486-493`).
58. **Image tool results insert `user` messages between `tool` messages** (`chat_completions.py:205-207`, `495-506`).
59. **Gemini `models/` is doubled in URLs** for listed model ids (`gemini.py:499`).
60. **Gemini streamed function calls are mishandled** (`gemini.py:374-388`):
    - They get synthetic ids and can merge.
    - The real `functionCall.id` is ignored.
    - `thoughtSignature` is never captured.
    - `call_id` falls back to the function name (`:583`).
61. **Error `detail` is discarded for status codes other than 401, 403 and 429** (`configurable.py:461`, `584`, `274`).
62. **429 handling** (`configurable.py:413`):
    - It ignores `Retry-After`.
    - It retries permanent quota errors (`is_permanent_quota_error` is unused).
    - Streaming is never retried.
63. **Messages streaming ignores `message_start` usage**, which carries input and cache tokens (`messages.py:501-517`).
64. **One `MessagesAdapter` is shared across concurrent streams** (`configurable.py:119`), and `reset_stream_state()` is never called (verify).
65. **Anthropic tool search drops `server_tool_use` and `tool_search_tool_result` blocks from replay**, and doesn't handle `pause_turn` (`messages.py:476-477`, `531-535`) (verify).
66. **Model listing isn't paginated for Anthropic and Gemini** (`configurable.py:74-79`).
67. **Chat Completions parsing hard-codes `reasoning_content`** (`chat_completions.py:449`, `656`) instead of `capabilities.reasoning.reasoning_key`.
68. **Gemini `OBJECT` schemas with empty or missing `properties`** (`json_schema.py:359-362`) (verify against the current Gemini API).

## Providers: built-in classes and core

69. **Google model listing** (`google.py:293-305`):
    - It reads `supported_generation_methods`, which is absent in google-genai 2.x (use `supported_actions`), so every model is reported as having no tools, streaming or vision.
    - `input_token_limit` can be `None`, which breaks `context_window > 0`.
70. **`google.py:193` ignores `credentials.api_base`**, and `:1198`/`:1266` use `capabilities_for("")`, so per-model overrides never apply.
71. **OpenRouter ignores per-model `supports_tools` and capability overrides**, and always sends tools and temperature (`openrouter.py:454-471`, `1007`).
72. **OpenAI model heuristics are wrong** (`openai.py:246-275`, `presets.py:189-219`):
    - `gpt-4.1*` is set to 128k context (it's about 1M).
    - `gpt-4-*-preview` is set to 8k (it's 128k).
    - `gpt-5-chat-latest` is treated as a reasoning model.
    - `_is_chat_model` lists realtime, audio, transcribe and computer-use models as chat models.
73. **Anthropic context windows are hard-coded to 200k** (`anthropic.py:238-248`, `presets.py:52`); use `/v1/models` `max_input_tokens`. Also: `_finalize_anthropic_stream` builds tool names by hand instead of using `parse_tool_call`.
74. **Grok bypasses the capability layer** (`grok.py:219-253`, `430-446`). `reasoning_effort` is only sent for `multi-agent` ids.
75. **The HuggingFace preset uses the deprecated `api-inference.huggingface.co`** (`presets.py:289`), which gets written to `.env` on save (verify).
76. **Provider error text isn't redacted** (`base.py:1460-1477`, `openai.py:993-1012`).
77. **Env var names derived from instance ids** (`ids.py:135-161`, `env_loader.derived_credential_mapping`):
    - `my-gw` and `my_gw` collide.
    - `xai`, `gemini` and `google_cloud` collide with built-in variables.
    - `1gw` produces an unparseable name.
    Instance ids must map to unique, valid names, or be rejected at creation.

## Providers: settings UI, credentials, startup

78. **The toolbar provider combo is filled once** (`ui/app.py:1037-1038`). Adding, deleting or Set Active never updates it. Delete (`provider_config.py:2363-2371`) also leaves the provider registered and connected.
79. **Edits to a registered custom instance are ignored until restart**, because `registry.get(pname)` returns the stale `ConfigurableProvider` (`app.py:2830`). The transport-risk check uses `self.instance.api_base` but connects to `credentials.api_base` (`configurable.py:171-182`, `220`). A key can therefore be sent over plain HTTP to a public host without acknowledgement.
80. **Test Connection and Refresh Models skip `may_send_api_key`** (`provider_config.py:874`, `1288`). The auto-refresh at `:3996-3997` sends the key when the page opens.
81. **A disabled custom instance still auto-connects**: `connect_policy` covers only built-ins, and `instance.enabled` is never read (`provider_settings.py:448`).
82. **Keyless presets (vLLM, LM Studio, LiteLLM) are blocked** at startup (`main.py:752-757`), on OK (`app.py:2832-2837`), and by Test/Refresh (`provider_config.py:4106`, `4208`, `4086-4090`).
83. **`ModelRefreshWorker` doesn't catch `ProviderError`** (`provider_config.py:1224-1250`). The model picker and Refresh button stay disabled (`app.py:2968-2969`), and the dialect fallback is skipped.
84. **Duplicating OpenAI, Anthropic or Google creates instances with no base URL.** Ollama and HuggingFace duplicates get wrong paths (`instances.from_preset`, `provider_config.py:1894`).
85. **`_reload_provider_list` discards unsaved edits on other pages** (`provider_config.py:2271-2285`).
86. **Import silently overwrites existing ids and accepts built-in ids** (`provider_config.py:2419-2434`).
87. **Delete leaves `<ID>_API_BASE` in `.env`**, which then overrides a re-added instance (verify).
88. **Set Active on a new instance raises an uncaught `ProviderError`** (`provider_config.py:2594-2601`).
89. **Instance display names are overwritten by `provider_display_name(id)`** (`provider_config.py:2615`, toolbar), and can't be edited.
90. **Dead or built-in-only code:**
    - `ProviderPreset.api_key_env_var`/`api_key_aliases` and `ProviderInstance.api_key_env_var` are never read, so a `deepseek` instance named `ds` reads `DS_API_KEY`.
    - `CredentialSourceDetector.ENV_VAR_MAPPING`, `list_configured_providers`, `store.list_providers` and `migrate_from_env` ignore custom instances.
91. **The `.env` writer doesn't escape U+2028 and other `str.splitlines` separators**, so values are truncated on reload.
