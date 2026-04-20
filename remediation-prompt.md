# Intellicrack Production-Readiness Remediation — 34 Outstanding Items

## ROLE

You are the orchestrator for the final remediation pass on Intellicrack. An audit
of `D:\Intellicrack\needed-fixes.md` confirmed 250/284 findings already resolved.
This prompt addresses the remaining **34 items** (18 unresolved, 15 partial,
1 scope-drift) to bring the project to production release readiness.

## CRITICAL STANDARDS (from `D:\Intellicrack\CLAUDE.md`)

- Production code only. NO placeholders, mocks, stubs, simulated functionality,
  hardcoded data, or simple ineffective implementations.
- Every fix must perform the real operation against real binaries / real
  systems / real protocols.
- Windows compatibility is PRIORITY.
- ALL code must pass `pixi run ruff check` with 0 findings on touched files.
- ALL code must be fully `basedpyright` compliant. ZERO findings acceptable.
- NEVER use type-suppression comments (no `type: ignore`, `pyright: ignore`,
  `noqa` for type issues). Fix the real type error.
- NEVER edit `[tool.basedpyright]`, `[tool.pydoclint]`, or `[tool.pydocstyle]`
  in `pyproject.toml`. Configs are locked.
- ALL code must pass `pydoclint` and `pydocstyle` with 0 findings.
- Google-style docstrings exactly matching signatures (params/types/returns/raises).
- NO comments / emojis / TODO markers unless I explicitly request.
- **NEVER delete method bindings — create FUNCTIONAL missing functions instead.
  MAINTAIN functionality over "cleaner" code.** When given a wire-or-delete
  decision, ALWAYS WIRE.
- For Rust: `cargo clippy --all-targets --no-deps -- -D warnings` and
  `cargo fmt --check` and `cargo test` must all pass.

## NON-NEGOTIABLE BEHAVIOR

- DO NOT open pull requests.
- DO NOT push to remote.
- Make commits per logical cluster (one commit per file or tight group).
- After every change: re-read the diff to verify the fix matches the intent.
- For each finding: read ≥30 lines of surrounding context BEFORE editing.
- If a validator fails, FIX THE ROOT CAUSE. Never suppress.
- Use `pwsh` (PowerShell 7), never `powershell.exe`.
- Use `rg` (not `grep`), `fd` (not `find`).
- Pixi env at `D:\Intellicrack\.pixi\envs\default`. Run via `pixi run <cmd>`.

## ORCHESTRATION

You may dispatch focused subagents per file or per cluster, BUT after any
subagent returns you MUST re-read the diff and re-run validators yourself.
Never trust "completed" claims without verification.

For independent work, parallelize: e.g. Group C provider fixes can run
concurrently per file.

---

## TIER 1 — DATA-INTEGRITY / CORRECTNESS (do FIRST)

### A14 — `src/intellicrack/bridges/x64dbg.py:3407`
Inside `_get_modules`, populate `ModuleInfo.entry_point` for every module by
calling the existing PE-header reader (same code path used by the public
`get_entry_point()` method). Currently the dataclass field is hardcoded to 0,
silently misreporting for every consumer. Read `AddressOfEntryPoint` at PE
header offset+24+16 from `module.base_address`. Add `base_address` if missing.

### A1 — `src/intellicrack/bridges/ghidra.py:1481`
Move `self.state.binary_loaded = True` to AFTER the `_extract_binary_metadata`
try-block at line ~1493. On metadata extraction failure, leave
`binary_loaded=False`, clear `connected`/`tool_running`, and re-raise ToolError.
The flag must reflect actual successful load.

### A5 — `src/intellicrack/bridges/ghidra.py:3625, 3762`
Extract a `_apply_decompiler_options(iface)` helper that reads the persisted
`_decompiler_simplification` and `_decompiler_max_instructions` instance attrs
and calls `iface.setSimplificationStyle(...)` / `iface.setOptions(...)` on the
DecompInterface. Invoke this helper inside `get_pcode` and `compute_slice` Jython
script generation. Currently options are only applied in `decompile()`.

### A13 — `src/intellicrack/bridges/x64dbg.py:2884`
Replace the BaseAddress range-scan for `MemoryRegion.module_name` with direct
`mbi.AllocationBase` dictionary lookup against `get_modules()` results.
AllocationBase is already captured in the MEMORY_BASIC_INFORMATION struct;
build `{module.base_address: module.name}` once and look up by AllocationBase.

### D5 — `src/intellicrack/sandbox/windows.py:988, 1002`
In the inline PowerShell network monitor, replace `$sent = 0; $recv = 0` with
real per-PID byte accounting. Use `Get-NetTCPConnection | ... |
Get-NetAdapterStatistics` aggregation, OR shell out to `netstat -b -o -n` and
parse the per-PID byte counts. Emit real `bytes_sent` / `bytes_received`.

### D10 — `src/intellicrack/sandbox/qemu.py:1556, 1568`
Same change as D5 inside `_windows_agent_script_content` — the agent.ps1
generated for QEMU guests must compute and emit real network byte counts, not
literal `0|0`. Mirror the netstat or Get-NetAdapterStatistics approach.

### D19 — `src/intellicrack/sandbox/scripts/{resource,service,clipboard}_monitor.ps1`
Add `param([string]$LogDir = 'C:\sandbox_shared\logs')` block at the top of all
three scripts. Replace the hardcoded `$logDir = 'C:\sandbox_shared\logs'` line
with reference to the `$LogDir` param. Without this, `start_monitors.cmd`'s
`-LogDir <path>` argument is silently ignored and telemetry never reaches the
host shared folder. Validate with PSScriptAnalyzer.

---

## TIER 2 — PROVIDERS + CREDENTIALS (largest cluster)

### C4 — `src/intellicrack/providers/google.py:458-475`
Replace the `asyncio.to_thread(_start_stream)` + per-chunk `asyncio.to_thread(next, ...)`
loop with native async iteration:
```python
response_stream = await self._client.aio.models.generate_content_stream(
    model=model, contents=contents, config=config
)
async for chunk in response_stream:
    ...
```
Use `client.aio.models.generate_content_stream` (returns AsyncIterator).

### C5 — `src/intellicrack/providers/google.py:83, 156`
On entry to `chat()` and `chat_stream()`, set
`self._current_task = asyncio.current_task()`. In `finally` clause clear it.
This makes `cancel_request` and `disconnect` actually work.

### C6 — `src/intellicrack/providers/google.py:196-202`
Replace `model_data.supported_generation_methods` with
`getattr(model_data, "supported_actions", [])` (modern google-genai SDK field).
For models matching `gemini-(1\.5|2\.0|2\.5)` name prefixes, default
`supports_tools=True, supports_streaming=True`; derive `supports_vision` from
name match against `vision|pro|flash`.

### C7 — `src/intellicrack/providers/google.py:712`
Wrap `response.text` access in try/except ValueError (raised when no text
parts present, e.g. function-call-only response). On ValueError, iterate
`candidates[0].content.parts` directly, accumulating text and function_call
parts separately. Return empty string for text accumulator if no text parts.

### C8 — `src/intellicrack/providers/google.py:826-833`
In `_build_tool_declarations`, for each parameter dict:
1. `param_dict.pop("default", None)` BEFORE constructing Schema (Schema doesn't
   accept "default").
2. Map `param_dict["type"]` (string) to `types.Type[param_dict["type"].upper()]`
   enum value before passing to Schema.
3. Construct Schema field-by-field rather than splatting unknown keys.

### C10 — `src/intellicrack/providers/grok.py:188-192, 362-385`
Two changes:
1. Add grok-4 arm to `_infer_context_window`: when `model.startswith("grok-4")`
   return `256000`; when `model.startswith("grok-3-mini")` return `131072`.
2. In chat call body construction, when
   `model.startswith(("grok-4","grok-3-mini"))`:
   - Substitute `request_body["max_completion_tokens"] = max_tokens`
     (NOT `max_tokens`).
   - When `thinking.budget_tokens` is provided, map
     `>=10000 → reasoning_effort="high"`, else `"low"`. Add to request_body.

### C11 — `src/intellicrack/providers/grok.py:604-608`
Add `self._logger.info("grok_request_cancelled",
had_active_task=self._current_task is not None)` to match sibling providers.

### C12 — `src/intellicrack/providers/openrouter.py:102-111`
At top of `connect()`:
```python
if self.client is not None:
    await self.client.aclose()
```
Replace `headers["HTTP-Referer"] = api_base or "http://localhost"` with a
constant app identity. Use `from intellicrack._metadata import __url__` and
set `headers["HTTP-Referer"] = __url__`. Keep `api_base` only for `base_url=`.

### C13 — `src/intellicrack/providers/openrouter.py:502-507, 292-320`
Inside `async with client.stream(...) as response:`, BEFORE `raise_for_status`,
call `body = await response.aread()`. Then branch on `response.status_code`:
- 429 → `RateLimitError(body.decode())`
- 401 → `AuthenticationError(body.decode())`
- else if not ok → parse JSON error body if present and raise `ProviderError`.

Apply the same fix symmetrically to the non-streaming `chat()` method.

### C14 — `src/intellicrack/providers/ollama.py:247, 663, 1067`
Add a helper `_endpoint_for(path: str) -> str` on the provider that returns
the OpenAI-compat path when `self._is_cloud` is True (host endswith `.ollama.com`
or env override): `/api/tags → /v1/models`, `/api/chat → /v1/chat/completions`.
For local hosts, keep `/api/*` unchanged. Document support for env override
`INTELLICRACK_OLLAMA_CLOUD_URL` if wired through credentials.

### C15 — `src/intellicrack/providers/ollama.py:1036-1048`
Delete the blocking-fallback shortcut (`if tools: return await self.chat(...)`)
in `chat_stream`. Always stream. Accumulate `last_chunk_data` from the streamed
NDJSON. Parse tool calls from the final chunk where `done:true`. Yield text
deltas as they arrive.

### C16 — `src/intellicrack/providers/ollama.py:829-830, 1029-1030`
Replace the "ignored" log lines with actual forwarding. Add
`request_body["tool_choice"] = self._convert_tool_choice_to_openai_format(tool_choice)`
when tools are present. The helper exists in the OpenAI provider — extract
to a shared location (`providers/_tool_choice.py` or `providers/base.py`)
to satisfy DRY, then import from both providers.

### C29 — `src/intellicrack/credentials/store.py:129-156`
Replace the destructive set/get/delete keyring probe with non-destructive
class inspection:
```python
import keyring
import keyring.backends.Windows
import keyring.backends.macOS
import keyring.backends.SecretService

backend = keyring.get_keyring()
keyring_kind = (
    "windows_credential_manager" if isinstance(backend, keyring.backends.Windows.WinVaultKeyring)
    else "macos_keychain" if isinstance(backend, keyring.backends.macOS.Keyring)
    else "secret_service" if isinstance(backend, keyring.backends.SecretService.Keyring)
    else "fallback"
)
```
Cache result in module-level `_KEYRING_STATUS = None` set on first call.
Handle ImportError gracefully on platforms where a backend module isn't
available.

### C30 — `src/intellicrack/credentials/oauth.py:84-92, 275-289`
Extend `OAuthProvider` enum:
```python
class OAuthProvider(StrEnum):
    GOOGLE = "google"
    ANTHROPIC = "anthropic"
    HUGGINGFACE = "huggingface"
    OPENAI = "openai"
```
Add real `OAUTH_CONFIGS` entries for each:
- ANTHROPIC: `https://console.anthropic.com/oauth/authorize`,
  `https://console.anthropic.com/oauth/token`, scopes `["api.read","api.write"]`,
  revoke_url `https://console.anthropic.com/oauth/revoke`
- HUGGINGFACE: `https://huggingface.co/oauth/authorize`,
  `https://huggingface.co/oauth/token`, scopes `["read-repos","write-repos","inference-api"]`
- OPENAI: `https://platform.openai.com/oauth/authorize`,
  `https://platform.openai.com/oauth/token`, scopes `["api.read","api.write"]`
Read `client_id`/`client_secret` from
`os.environ.get(f"OAUTH_CLIENT_ID_{provider.value.upper()}")` and
`OAUTH_CLIENT_SECRET_{...}`. Document env convention in module docstring.

### C31 — `src/intellicrack/credentials/oauth.py:172-182, 919`
In `get_token()`, change refresh trigger from `is_expired` to `needs_refresh`:
```python
if token.needs_refresh and auto_refresh and token.refresh_token:
    token = await self._refresh_token(provider, token)
if token.is_expired:
    return None
```
Keep `is_expired` as final return-None gate. The 10-minute `needs_refresh`
buffer must trigger proactive refresh before expiry.

### C32 — `src/intellicrack/credentials/oauth.py:323-378`
Convert `OAuthCallbackHandler` ClassVar state to per-instance via factory:
```python
def _make_handler(flow_state: _OAuthFlowState) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.server.flow_state = flow_state  # type-safe via subclass
            ...
    return _Handler
```
Server subclass holds `flow_state: _OAuthFlowState`. Eliminates global state
collision between concurrent OAuth flows.

### C33 — `src/intellicrack/credentials/oauth.py:1017-1066`
Track `revoke_ok` and `delete_ok` separately:
```python
revoke_ok = False
delete_ok = False
try:
    response = await client.post(revoke_url, ...)
    response.raise_for_status()
    revoke_ok = True
except (httpx.HTTPError, httpx.HTTPStatusError) as exc:
    self._logger.warning("oauth_revoke_failed", error=str(exc))
try:
    await self._delete_credentials(provider)
    delete_ok = True
except (CredentialStoreError, _KeyringError) as exc:
    self._logger.warning("oauth_credentials_delete_failed", error=str(exc))
return revoke_ok and delete_ok
```

### C18 — `src/intellicrack/providers/huggingface.py:277-352`
Align `list_models` filter and downstream pipeline_tag accept-list. Change
filter to `text-generation` (drop `text-generation-inference` deprecated value).
Drop `conversational` from accept-list since it's deprecated; rely on
`text-generation` as primary. Update docstrings to reflect the change.

### C19 — `src/intellicrack/providers/huggingface.py:122, 484-496`
The new `AsyncInferenceClient` path raises `HfHubHTTPError`. WIRE proper
503 handling instead of removing the unused constant: add a try/except around
the AsyncInferenceClient call that catches `HfHubHTTPError` with
`status_code == HTTP_SERVICE_UNAVAILABLE`, then raises a friendly
`ProviderError("Model is loading; retry in 30 seconds")`. Use the existing
`HTTP_SERVICE_UNAVAILABLE` constant (don't remove it).

---

## TIER 3 — REMAINING BRIDGE / CORE / RUST GAPS

### A18 — `src/intellicrack/bridges/x64dbg.py:2756`
Add restype/argtypes to `OpenProcess` call inside `free_memory`:
```python
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
```
Or use the existing module-level `_configure_kernel32` helper if one exists.

### A21 — `src/intellicrack/bridges/x64dbg.py:3094-3099`
Replace warning-only short-pattern path with hard error:
```python
if len(pattern) < _MIN_SCAN_PATTERN_LEN:
    raise ToolError(
        f"{_ERR_PATTERN_TOO_SHORT}: pattern length {len(pattern)} "
        f"below threshold {_MIN_SCAN_PATTERN_LEN}"
    )
```
Define `_ERR_PATTERN_TOO_SHORT` and `_MIN_SCAN_PATTERN_LEN` constants near
other error/threshold constants if not already present.

### A25 — `src/intellicrack/bridges/x64dbg.py:5355, 4527`
Drop `*,` keyword-only marker:
- `adjust_privilege(self, name, *, enable=True)` →
  `adjust_privilege(self, name, enable=True)`
- `set_logging_breakpoint(..., *, non_stopping=True)` →
  `set_logging_breakpoint(..., non_stopping=True)`
Verify tool_definition entries match.

### A31 — `src/intellicrack/bridges/frida_bridge.py:3131`
In `_resolve_target_js`, wrap `module` and `func` interpolations with
`_escape_js_string(...)`. Currently only `replacement_code/on_enter/on_leave`
are protected. Module names with apostrophes (rare but possible on macOS
framework paths) currently break the JS template AND enable injection.

### A54 — `src/intellicrack/bridges/hex_editor.py:1971, 2246`
Remove `TypeError` from the `(RuntimeError, OSError, TypeError)` catch tuple
around `_hexcore_mod.HexDocument()`. Let TypeError propagate — it indicates
a real programming bug (constructor signature mismatch), not a runtime
condition. Update docstring `Raises:` section.

### F13 — `src/intellicrack-hexcore/src/templates/elf.rs`
Endianness propagation for non-Ehdr ELF templates. Cleanest approach: add a
`parent_default_endian: Option<Endianness>` field on `TemplateEvaluator` (in
`src/templates/eval.rs`). When evaluating a struct that doesn't carry its own
EndiannessSwitch, use the parent's resolved endian. Then the evaluator chain
(Ehdr → Phdr → Shdr → Sym/Rel/Rela/Dyn) naturally inherits the correct
endianness.

Alternative if propagation is hard: keep the `Endianness::Little` defaults but
add a public `with_default_endianness(self, e: Endianness) -> Self` builder
on `TemplateEvaluator` so Python callers can construct BE-aware evaluators
when the caller knows the target.

After change: add `cargo test` cases for BE Phdr/Shdr/Sym/Rel/Rela/Dyn parsing
of a real PowerPC or s390 ELF binary.

### B24 — `src/intellicrack/core/hexpat_compiler.py:1430-1469`
Add a `BitAndZero` codegen primitive that emits a single comparison
`(field & mask) == 0` to the Rust hexcore. For inverted BitAnd conditions in
`Conditional.false_fields` codegen, emit `BitAndZero(field, mask)` instead of
the incorrect `Eq(field, 0)` substitution. Currently the file raises
HexPatError as a guard-rail but loses the functionality. Once BitAndZero
is wired, remove the guard-rail and fully restore inverted-condition support.

### B18 — `src/intellicrack/core/logging.py:404-416`
**LEAVE AS-IS (documented deprecated alias).** Verified that
`get_structlog_logger` is literally `return get_logger(name)` with identical
return type (`structlog.stdlib.BoundLogger`). Wiring it into call sites would
create artificial redundancy with zero functional benefit (the audit's
"delete" recommendation conflicts with the CLAUDE.md "NEVER delete method
bindings" rule). The function is already a valid public API — a deprecated
alias preserved for backward compatibility. ACTION: ensure the docstring
clearly identifies it as a stable backward-compat alias for `get_logger`.
Strengthen wording from `.. deprecated::` to a clear `.. note::` block
explaining: "This function is preserved as a stable alias for callers that
explicitly want the structlog return type signature; new code should prefer
:func:`get_logger`." Do NOT add fake call sites to make it "load-bearing".

### B21 — `src/intellicrack/core/template_manager.py`
**WIRE for the responsibilities it uniquely owns; do NOT replace existing
working flows.** Verified that the bridge's lazy `_get_pattern_registry()`
(`bridges/hex_editor.py:2062-2082`) and the hexcore-backed
`doc.list_templates()` / `doc.list_templates_detailed()` /
`doc.export_template_json()` methods already cover pattern lookup and template
introspection from the UI side. TemplateManager adds value ONLY in areas
those flows DO NOT cover:

1. **Filesystem persistence of built-in templates as JSON sidecars** — give
   users editable copies under `config_dir/templates/builtin/<category>/`.
2. **User template directory bootstrap** — create `config_dir/templates/user/`
   with the standard category subdirectories so users have a place to drop
   their own JSON template files.
3. **Startup-time bootstrap error surfacing** via `TemplateBootstrapError`.

Wire it as follows:

1. In `src/intellicrack/main.py` startup (after Config load, before GUI init),
   instantiate `TemplateManager(config.config_dir)`. Acquire a hex document
   reference (use the bridge's headless `HexDocument` factory) and call
   `template_manager.ensure_directories()` then
   `template_manager.bootstrap_builtins(document)`. Persist the manager on
   the app context (`app.template_manager: TemplateManager`).
2. Wrap the `bootstrap_builtins()` call in try/except `TemplateBootstrapError`;
   on failure, log structured warning AND, if GUI is initializing, surface
   via `QMessageBox.warning` listing the `failed_templates` paths. Do not
   abort startup.
3. **UI template-picker integration**: in the hex editor template panel
   (`ui/panels/hex_editor/_pattern_editor.py` or appropriate), add a
   "User Templates" source that scans `app.template_manager._user_dir` for
   `*.json` files, alongside the existing built-in registry path. This
   exposes the user-editable templates the bootstrap creates. Do NOT
   replace the bridge's existing `list_templates()` flow — augment it.
4. **DO NOT** replace `_get_pattern_registry()` or route hex editor pattern
   lookups through TemplateManager. Those flows work and changing them is
   out of scope.

After wiring, verify:
- Fresh-config startup creates `<config_dir>/templates/builtin/{pe,elf,macho,zip,common}/`
  populated with JSON files.
- Fresh-config startup creates empty `<config_dir>/templates/user/`.
- A deliberately-broken template entry causes a logged warning and (in GUI mode)
  a user-visible message but does not crash startup.
- The hex editor template picker shows both built-in and user templates.

---

## VALIDATION GATES (per file, before commit)

```
pixi run ruff check <file>          # → 0
pixi run ruff format <file>         # formatted
pixi run basedpyright <file>        # → 0
pixi run pydoclint <file>           # → 0
pixi run pydocstyle <file>          # → 0
```

For Rust (F13):
```
cd src/intellicrack-hexcore
cargo build
cargo clippy --all-targets --no-deps -- -D warnings
cargo fmt --check
cargo test
```

For PowerShell (D19):
```
pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path <script.ps1>"
```

## FINAL GATE (entire project, before reporting done)

1. `pixi run ruff check src/intellicrack/` → 0
2. basedpyright on entire `src/intellicrack/` → 0
3. pydoclint / pydocstyle → 0
4. `cargo clippy/fmt/test` inside hexcore → all clean
5. PSScriptAnalyzer on all sandbox `.ps1` → 0 warnings
6. Re-audit each of the 34 items above by reading the cited file — confirm
   the implemented change matches the directive exactly (not a reword).
7. Smoke-launch the GUI locally to confirm no regressions
   (`pixi run python -m intellicrack`).

## REPORTING

When all 34 are complete, give me:
- Per-item status table: `Item | File:Line | Status | Diff Summary`
- Total commits made (per-cluster)
- Any items where the directive needed adjustment (with reason)
- Confirmation of all validation gates passing

Do NOT open a PR. Do NOT push. Stay on the current branch.

## START

Begin with TIER 1 (data-integrity fixes). Work through TIER 2 in parallel by
file (Google provider is one cluster, Ollama another, OAuth another). End with
TIER 3. Re-validate after each tier.
