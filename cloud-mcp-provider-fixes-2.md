# Round 2: finish the MCP client and AI provider layers

This round fixes every item below in `src/intellicrack/` and `tests/`. PR #429 (merge `3bce8a59`) was audited on Windows against live MCP servers, the real provider SDKs and the real Windows Credential Manager. Everything listed here is what that audit found still broken, partly fixed, newly introduced, untested, or missing. File:line references are from `main` at `24f73cda`; they may have drifted.

## Rules

- Fix every item for real. Don't skip, defer or stub anything. Don't remove or disable a feature to make its problem go away, and don't narrow what the code accepts as a shortcut.
- Items marked **(verify)** were reasoned about but not reproduced. Confirm them first. If one turns out not to be a defect, say so in the report with the evidence.
- Fix root causes, not symptoms. No blanket `except Exception`, no `default=str`, and no longer timeouts used to hide a design problem.
- Check behaviour against the installed SDKs and the real wire protocols, not from memory. Inspect the installed package source and signatures, and use current vendor docs or the MCP spec where they matter. Installed SDKs:
  - `mcp` 2.2.0, spec 2026-07-28, which also negotiates legacy 2025-11-25
  - `openai` 3.16.2
  - `anthropic` 1.7.0
  - `google-genai` 2.24.0
- Follow `CLAUDE.md` in full:
  - full type hints
  - zero basedpyright, ruff, pydoclint and pydocstyle findings
  - no suppression comments of any kind
  - no edits to linter or type-checker config
  - Google docstrings
  - no explanatory comments
  - Windows-first behaviour
  - never delete method bindings
- Every fix and every feature needs real, falsifiable tests under the matching `tests/` subdirectory. For each one, revert the change and show that its tests go red. Use real inputs: the SDK's `MCPServer` over stdio, SSE and streamable HTTP; the real provider SDKs against a loopback HTTP server (reuse `tests/_helpers`); real SSE byte streams. Don't assert on mocks.
- Tests must not touch the developer's real Windows Credential Manager, `.env` or user config.
- Windows-only behaviour must be tested on Windows. A platform `skipif` is allowed only on those tests, and it must name the Windows behaviour it covers.
- Don't pass `--timeout` to pytest on Windows. pytest-timeout's thread trips the conftest non-daemon-thread guard.
- Order of work: section A first (security), then B, C, D, E and F.
- Final report: list every item as fixed or not-a-defect, and every feature as implemented. For each, give the tests that cover it and the evidence from the revert-to-red check. Also list anything you could not verify in your environment.

## A. Security (do first)

1. **The fence around untrusted MCP text can be bypassed**. Descriptions and text parts are fenced; everything below is not.
   - (a) `StructuredResultPart` is never fenced or sanitised (`mcp/tool_source.py:323-327`; rendered with `json.dumps` in `providers/dialects/base.py:295`). Python SDK `MCPServer` tools repeat their text in `structuredContent`, so a server can close the fence with `<<<END_UNTRUSTED_MCP_SERVER_TEXT>>>` and inject instructions. On Gemini the structured object merges natively into `functionResponse.response` (`dialects/gemini.py:465-476`), so ESC, BEL, U+202E, ZWSP and BOM reach the endpoint unchanged.
   - (b) Provider tool definitions pass `input_schema` through verbatim: server-supplied property descriptions, enum and const values, and titles go out raw on every dialect.
   - (c) `render_schema_parameters` (`core/types.py`) writes property names, `$ref` leaf names and const/enum values raw into the system prompt and the `tools.search` signature.
   - (d) The fence defang only replaces the exact-case marker. Lower-case, spaced (`>>> `) and full-width look-alikes survive. U+2028/U+2029 are kept.
   - Fix: every piece of server-originated text that reaches a model is sanitised, stripping control and bidi characters, and fenced or structurally isolated. This covers structured content, schema text, prompt and resource content, and sampling and elicitation text.
2. **Image parts are never validated.** MIME type and base64 are unchecked (verify). A bad image is stored in history and breaks every later request to that provider; for example, Anthropic accepts only jpeg, png, gif and webp. Fix:
   - allow-list MIME types per dialect and validate the base64;
   - cap the image count and the total image bytes per result (right now 100 images of 2000x2000 pixels are all kept);
   - degrade an image the endpoint can't take to a described text part.
3. **Trust and approvals ignore changes that widen what a server can do.** `consent.launch_digest` and `server_identity` (`mcp/consent.py`) leave out `config.sandbox` (`enabled`, `allow_write`), env values and HTTP headers. So disabling the sandbox, widening `allowWrite` to `C:\`, changing `PATH` (which changes which `npx` runs) or changing headers keeps the server TRUSTED with no prompt.
   - Include these in the identity and digest.
   - Show the sandbox state in the consent dialog.
4. **"Always" approvals aren't tied to server identity.** `ApprovalStore` keys only on namespace, function and generation. If a server id is repointed at a different program or URL, its old "always approve" answers still apply. Bind approvals to server identity, and invalidate them when the identity changes. That includes HTTP servers, which never pass through `ensure_launch_consent`.
5. **The trust and approval files lose data under concurrent writes** (`mcp/consent.py:357-372`, `411-423`).
   - Every write is an unlocked read-modify-write through one fixed temp file.
   - On Windows this causes `WinError 5` on replace (the write is silently dropped), permission errors on read, and corrupt JSON. A corrupt read is treated as `{}`, so the next write wipes every record.
   - The GUI thread and the loop thread both write these files.
   - Fix: serialise writes, use unique temp files, and never overwrite the file after a failed read.
6. **The sandbox's allow-write folders stay writable to every low-integrity process** (`label_directory_low_integrity`). It recursively applies a Low `(I)(NW)` label to every file already in the tree and never reverts it, so any Low-integrity process on the machine can write there afterwards.
   - Scope the grant to the server's lifetime and revert it on disconnect.
   - Don't relabel pre-existing content beyond what's needed.
   - Move the work off the event loop; a large tree blocks it today.
7. **The UI never says that `allowedDomains` is not enforced.** It appears only in docstrings and a log warning (`sandbox_launch.py:719`), and `ui/mcp_config.py` has no sandbox editor.
   - Enforce network egress per sandboxed server, or state plainly in the UI that it isn't enforced.
   - Add a sandbox editor for `enabled`, `allowWrite`, `allowedDomains` and the env allowlist.

## B. MCP correctness

8. **The SDK's per-request timeouts still apply during operator waits.** `OperatorWaitClock` pauses only Intellicrack's own deadline.
   - During OAuth sign-in:
     - `server/discover` has a hard 10 s cap (`DISCOVER_TIMEOUT_SECONDS`), so a sign-in over 10 s silently downgrades a modern server to legacy 2025-11-25 and loses `subscriptions/listen`;
     - `initialize` uses `read_timeout_seconds=request_timeout_s` (`connection.py:724`), so a sign-in over about 10 s + `request_timeout_s` fails outright, even though the UI allows 300 s.
   - On legacy servers, elicitation inside `tools/call` is capped by `read_timeout_seconds`, so a slow answer fails with "tools/call timed out". Modern servers are fine.
   - Fix: complete OAuth before the handshake's timed requests start, and exclude operator time from the SDK per-request timeouts on every protocol version.
   - Then fix `test_slow_oauth_sign_in_does_not_time_out`: it currently passes only through the downgrade. It must assert the negotiated protocol version and cover a sign-in longer than 60 s.
9. **Connection lifecycle** (`mcp/connection.py`):
   - Cancelling `connect()` or `manager.start()` leaves the supervisor task running, so the server can still reach READY afterwards (`1166-1168`).
   - `_supervise` returns on stop without setting `_settled`, so an in-flight `connect()` waits the whole 45 s and then reports a misleading timeout (`1096-1098`).
   - `manager.stop()` disconnects servers one at a time, with a 10 s wait each (`1678-1687`). Make it concurrent, and make stop end open OAuth waits.
   - `start_server` has no "stopped" guard. `deny_all_launches` blocks only stdio consent, so a queued HTTP or SSE start after stop still connects (verify).
   - A legacy `list_changed` that arrives while `fetch_catalog` is running is lost, because `_start_follower` replaces `_change_notice` (`1375`) (verify).
10. **Sandboxed launches** (`mcp/sandbox_launch.py`):
    - `render_command_line` (`:518`) wraps `.cmd` arguments in quotes without MSVC backslash doubling. An argument ending in `\`, such as `npx … C:\proj\`, swallows every argument after it.
    - `uv`/`uvx` fail with "Failed to initialize cache … Access is denied".
    - `npx` writes its cache to a literal `<cwd>\${LOCALAPPDATA}\npm-cache` because `LOCALAPPDATA` isn't on the allowlist.
    - Make common launchers (npx, uvx, uv run, pipx, python, node, docker) work sandboxed with a correct per-server cache and temp location, and tell the operator what to change when a launcher needs more access.
    - Close the handle-inheritance window between `SetHandleInformation(INHERIT)` and closing the handles (`:1386`).
    - Raise an error if `ResumeThread` fails and last-error reads 0 (verify).
    - Remove or wire the dead `SandboxedJob.adopt` and `assign_process_to_job` (`:941`, `:1559`).
11. **Credential Manager chunking** (`credentials/store.py`):
    - A write that fails partway leaks the chunks it has already written, and they can't be deleted afterwards (`525-529`).
    - Concurrent writers orphan each other's chunks.
    - A reader can get a transient `KeyringReadError` while a writer deletes old chunks.
    - Make writes transactional and cleaned up, serialise writers across `CredentialStore` instances, and report quota exhaustion clearly to the user.
12. **MCP config handling** (`mcp/config.py`, `ui/mcp_config.py`):
    - Importing keys that collide after normalisation (`GitHub` and `github`, or keys that match in their first 32 characters) loses one of them when saved (`serialize_document`, `1419-1420`).
    - Renaming a server to an id that already exists silently replaces that server's config (`_apply_editor`, `1696-1700`). If the replaced server was running, its process keeps running on a config that no longer matches.
    - The literal-secret heuristics still flag harmless values and miss real secrets.
      - Flagged wrongly: 40-hex git SHAs in args, 32-hex Notion ids, Google Drive ids, `AUTH_MODE=oauth`, `PRIVATE_REPO=true`, `SIGNATURE_ALGO=rs256`.
      - Missed: `DB_CONN=Server=db;Password=Hunter2!`, `--password hunter2`, `-p Sup3rS3cret!`.
    - Pressing Escape or Close (`reject()`) skips the unsaved-changes warning (`closeEvent` only, `2014-2023`).
    - One added server with an empty command blocks Save for every other edit.
13. **Consent and elicitation prompts are nested modal `exec()` calls** (`ui/mcp_bridge.py:345-357`). Answers are delivered only after `exec()` returns, so with two prompts open, the first answer waits for the second dialog to close and can be discarded as late. Concurrent server starts make this common at startup. Answers must be delivered as soon as they are given, whatever the stacking.
14. **Elicitation form** (`ui/mcp_elicitation_dialog.py`):
    - An optional boolean with no default is always sent as `false` (`636-637`).
    - Number fields accept `nan` and `inf` (`_parse_number`).
    - Format checks are lax: date `20260131`, date-time `2026-01-31` and `2026-01-31 10:00`, and uri `a:b` are all accepted.
    - Validate to the spec's formats.
15. **Legacy built-in providers turn images into text and drop `is_error`.** The built-in OpenAI chat path, Grok, OpenRouter and Ollama (`providers/base.py:1290-1297`, `_convert_messages_to_openai_format`) send `[image image/png, …]` text and carry no error marker.
    - Route them through the dialect rendering, or give them native image and error handling equal to the dialects.
    - Add end-to-end MCP tests for the Responses and Gemini dialects and for these providers.
16. **The Gemini tool-result renderer overwrites structured fields named `content` and `error`** (`dialects/gemini.py:465-476`).
17. **Structured results double the context cost.** When `structuredContent` duplicates the text, both are sent. Send one representation, chosen per dialect, without losing information.
18. **Validation** (`mcp/validation.py`, `bridges/json_schema.py`):
    - **Regression:** a pattern with 249 or more nested groups raises `RecursionError` out of `validate_against_schema` (`_PatternParser`, `116-304`). The elicitation dialog calls it on the GUI thread with no guard (`:660`).
    - `uniqueItems` is O(n²) through Python `_json_equal` (`839-856`). 10,000 items take 15.7 s on the loop, and this path has no time budget.
    - `$ref` inside `dependencies` isn't inlined, and `$dynamicRef` is left as is.
    - A non-`$ref` schema nested about 2,000 levels deep raises `RecursionError` during inlining, strict reduction and validation.
    - Gemini `parameters` can contain untyped `{}` nodes where recursion was collapsed, and `_gemini_has_open_object` doesn't route them to `parametersJsonSchema` (verify).
    - The ECMA-262 dialect differs from Python's: `^abc$` accepts `"abc\n"`, `\d` matches non-ASCII digits, `.` matches U+2028, `^\s$` rejects U+FEFF, and `[^]`, `\cJ` and `\u{…}` are silently treated as uncompilable. Match ECMA-262 semantics.
    - The docstring claim that `regex` releases the GIL is wrong without `concurrent=True`.
19. **Tool accounting and dead code:**
    - `McpToolSource.costs` has no callers, and `ui/mcp_config.py:696` duplicates the calculation. Make the UI use `estimate_entry_costs` through `costs`.
    - `ToolConfirmationDialog.decision_made` (`ui/confirmation_dialog.py:90`) has no production listener.
    - `schema_parameters` renders `allOf` and nested objects as `any` or `object` (verify).
    - `stop()` calls `ToolConfirmationDialog.set_approval_store(None)` on the loop thread (`ui/mcp_service.py:501`).
    - `_execute_tool_calls` raising `CancelledError` after the assistant message is appended leaves a call with no result (`orchestrator.py:1547`, `2988-2989`) (verify).
    - A history that already starts with an orphaned tool message keeps it.
20. **Token encoding** (`core/token_encoding` / `mcp/policy.py`):
    - The `.tmp` staging file isn't removed if `replace` fails.
    - DNS resolution isn't covered by the connect timeout.
    - `TIKTOKEN_CACHE_DIR=""` falls through to an unbounded `tiktoken.get_encoding`.
21. **`open_web_url` hands the raw string to `webbrowser`.** `urlsplit` strips leading C0 and space characters, so `'\x00http://a'`, `' http://x'` and `'http://\\\\evil\\share'` are accepted. Launch only the parsed and re-serialised URL.
22. **OAuth leftovers:**
    - A stored dynamic registration beats a newly configured `oauthClientId`.
    - After the SDK drops an issuer-mismatched registration (`oauth2.py:690`), the code falls back to dynamic registration, not the configured id.
    - `OAuthManager.run_authorization_flow` (`credentials/oauth.py:1516`) now accepts only `/callback`, so a provider `redirect_uri` with another path never completes.
    - Tokens stored under an old `:443` key are orphaned without a migration.

## C. Providers

23. **Thinking fails for unverified OpenAI organizations.** `dialects/responses.py:414` always sends `reasoning.summary: "auto"` when thinking is on. OpenAI returns 400 `invalid_request_error` with `param: reasoning.summary` ("organization must be verified"), so every thinking-enabled gpt-5.x or o-series turn fails for those orgs. This affects both the built-in `OpenAIProvider` and Responses instances.
    - On that error, retry without `summary` and remember the result per instance.
    - Add a setting for it.
24. **Forced `tool_choice` is rejected by newer Claude models.** `any` and `tool` return 400 on Fable 5.1 and Opus 5.5, and on any Claude model with thinking on (`dialects/messages.py:390-395`). Resolve per model and per thinking state.
25. **Gemini 3 is sent `thinkingBudget` instead of `thinkingLevel`.** Send the native field per model family.
26. **The built-in OpenAI Responses stream has two gaps** (`providers/openai.py`):
    - It drops `tool_search_*` items from replay (`_responses_stream_deltas`); the dialect path keeps them.
    - It doesn't close the SDK stream when a cancel breaks the loop (`1363-1366`).
27. **HuggingFace settings:**
    - Saved `HUGGINGFACE_API_BASE=https://api-inference.huggingface.co` values are never migrated to the router host.
    - `HUGGINGFACE` has no `default_api_base` in the credential mapping, so saving writes the default URL into `.env`.
    - The docstring at `instances.py:61-73` is stale.
28. **Anthropic pause_turn rebuild loses ordering.** The partial turn is rebuilt as reasoning and server blocks followed by text, which loses the model's own interleaving. Preserve block order.
29. **`prompt_cache_key` is the model id** (`responses.py:389`, `chat_completions.py:305`). Use a per-conversation key.
30. **Round-1 item 73's `parse_tool_call` refactor has no test that goes red when it is reverted.** Add one.

## D. Missing MCP features (full end-to-end implementations)

Each feature must be implemented from the protocol layer through the orchestrator and GUI, and be persisted where relevant. Each must be tested against real `MCPServer` instances on both the 2026-07-28 and legacy 2025-11-25 paths.

31. **Sampling (`sampling/createMessage`).** Wire `sampling_callback` on the SDK `Client`, so servers can request completions through the user's configured AI providers.
    - Map `modelPreferences` (hints, cost, speed and intelligence priorities) to a configured provider and model, with a per-server override.
    - Honour `systemPrompt`, `maxTokens`, `temperature` where the provider accepts it, `stopSequences`, and `includeContext`.
    - Support tool use in sampling where the spec version allows it.
    - Pass multi-part content (text, image, audio) through the dialect adapters.
    - Require operator approval with the request shown, and an option to edit the request before sending and to review the response before returning it.
    - Keep per-server policy (always ask, allow within budgets, deny), per-server token and cost budgets, and rate limits.
    - Fence all server text and never expose provider credentials.
    - Advertise the capability only when at least one provider is connected.
    - Record sampling exchanges in the transcript with server attribution.
32. **Roots (`roots/list`, `notifications/roots/list_changed`).** Wire `list_roots_callback`.
    - Roots come from the active project and session: the target binary's directory, project folders, and operator-added folders, as `file://` URIs with Windows paths encoded correctly.
    - Allow per-server root restrictions, and keep sandbox `allowWrite` consistent with roots.
    - Send `list_changed` when the project, target or root set changes.
    - Add a UI for viewing and editing roots per server.
33. **Logging (`logging/setLevel`, `notifications/message`).** Wire `logging_callback`.
    - Route server log messages into the app's structlog pipeline and the log viewer, with server attribution, level mapping and rate limiting.
    - Add a per-server log view and level selector in MCP Settings that sends `logging/setLevel`.
    - Keep stderr capture from stdio servers alongside it.
34. **Progress and cancellation.**
    - Send a `progressToken` on `call_tool` (`progress_callback`), and show live progress and messages for long tool calls in the chat and tool UI.
    - Let the operator cancel a running call, sending `notifications/cancelled` and producing a failed tool result.
    - Honour server-side progress on resource reads and prompts too.
    - Progress must not reset or starve the request timeout incorrectly. Define and test how progress extends deadlines.
35. **Model access to resources and prompts.** Today they can only be attached by hand from the settings dialog.
    - Expose meta-tools the model can call:
      - list resources and resource templates, paginated
      - read a resource, including binary blobs as parts
      - list prompts
      - get a prompt with arguments
    - All of these go through consent, fencing, size budgets and the tool-search surface.
    - Implement `resources/subscribe` and `notifications/resources/updated`, with the conversation or UI notified of changes to attached or subscribed resources.
    - Implement `notifications/resources/list_changed` and `notifications/prompts/list_changed` following.
    - Implement `completion/complete` for prompt and resource-template arguments, in both the UI and the meta-tools.
    - Add resource and prompt browsing and insertion to the chat UI, not only the settings dialog.
36. **Capability negotiation and status.** Advertise exactly the client capabilities that are actually implemented, per negotiated protocol version. Show each server's negotiated protocol version and server capabilities in MCP Settings.

## E. Tests: gates that don't gate

37. **Sandbox job confinement (round-1 item 9)** stays green with the sandbox removed:
    - `_is_in_job` uses `IsProcessInJob(h, NULL)`, which is true for any job, and the host is usually already in one.
    - The SDK's own kill-on-close job makes the `_gone` checks indistinguishable.
    - `test_venv_launcher_server_is_confined` never asserts job membership.
    - Assert membership of the specific sandbox job from process creation, including grandchildren.
    - Also add tests for:
      - the integrity level and privileges;
      - an argument with a trailing backslash;
      - the sandboxed launchers from item 10.
38. **Server-death detection (round-1 item 7).** The gates go red only when both detectors are reverted. Gate each one alone, including an idle server killed from outside.
39. **`log_tool_call` success reporting** (`core/tools.py:556`) is not gated.
40. **The fence-marker defang** is not gated.
41. **`test_chat_completions_turn_carries_every_part` accepts the text fallback.** It checks only `"image/png" in json.dumps(body)`. Assert the native `image_url` part.
42. **`test_descriptions_are_fenced_everywhere…`** has a near-tautological assertion at line ~683. Rewrite it.
43. **The outputSchema `lie` case** passes because the SDK rejects the content first. Exercise Intellicrack's own `validate_structured_content`.
44. **Elicitation tests:** the format checks and legacy `enumNames` handling aren't gated; mutants survive. Add tests for booleans, NaN and inf, and date/uri strictness. Most current tests fail on the old code only because of object names; make them assert behaviour.
45. **Prompt bridge tests:** there's no test answering after a timeout, and none with two prompts open at once.
46. **Credential Manager tests:** add tests that chunks are gone after delete, for cleanup after a partial failure, and for concurrent writers.
47. **Consent tests:** add tests for items 3, 4 and 5 (privilege-widening changes, identity-bound approvals, concurrent trust writes).
48. **The round-1 item 75 test** checks only the new HuggingFace host, not migration of an already-saved value.
49. **`test_slow_oauth_sign_in_does_not_time_out` writes to the real Windows Credential Manager.** Isolate it. Existing Intellicrack MCP OAuth entries on the developer machine likely came from this test.

## F. Test environment

50. **`keyrings.alt` is required but not declared.** `tests/_helpers/private_keyring.py:30,46` loads `keyrings.alt.file.PlaintextKeyring`, but it isn't declared in `pyproject.toml` or `pixi.lock` and isn't installed. As a result, 16 auth and credential gates can't run in the project environment:
    - `test_fix_keyring_chunking` (1 failure, 10 errors)
    - `test_fix_oauth_restart` (5 errors)
    - `test_fix_config_import` (1 error)
    Declare it as a test dependency in the pixi environment (updating the lock), or replace it with an in-repo keyring backend. Fix the helper's docstring either way.
51. **`tests/_helpers/child_python.py:30,57` gives child processes a minimal environment without `CONDA_PREFIX`.** Capstone's `__init__` joins `os.getenv('CONDA_PREFIX')` and raises `TypeError`, so `tests/ui/test_fix_mcp_tool_cost_nonblocking.py` has never passed on native Windows. Give children the environment the pixi runtime needs.
52. **`regex` is imported but not declared.** It's imported by `mcp/validation.py:35` without a fallback, and arrives only through tiktoken. Declare it in `pyproject.toml` and the pixi environment.
53. **Test ordering is randomized, so `-x` stops at a different first failure each run.** Make every new test order-independent, and confirm by running the new files with at least two seeds.
