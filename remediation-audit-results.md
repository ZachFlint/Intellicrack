# Remediation Audit Failures — Intellicrack

This document lists the remaining failures and behavioral drift identified during the production-readiness audit of the `needed-fixes.md` remediation plan.

---

### **Group B — Core + Hexpat**

* **B12 — `src/intellicrack/core/logging.py` + `src/intellicrack/main.py`**: `setup_logging` accepts a `log_dir` parameter but `main.py` never passes `config.logs_directory`, so the user's configured log directory is ignored and the default `cwd/logs` path is used instead.
* **B18 — `src/intellicrack/core/logging.py`**: Delete the unused `get_structlog_logger` method.
* **B24 — `src/intellicrack/core/hexpat_compiler.py`**: Implement `BitAndZero` primitive or `If/Else` paired logic for bit-mask inversion in `else` branches (currently just raises an error).
* **B21, B22, B25 — `src/intellicrack/main.py`**: Wire `TemplateManager.bootstrap_builtins` and `ScriptGenerator` into the application startup flow.

### **Group A — Bridges**

* **A1 — `src/intellicrack/bridges/ghidra.py`**: Move `state.connected` and `state.binary_loaded` updates to *after* successful metadata extraction to prevent corrupted state on failure.
* **A9 — `src/intellicrack/bridges/ghidra.py`**: Rename `manage_thunks` to `get_thunk_info` and `manage_external_references` to `get_external_references`.
* **A14 — `src/intellicrack/bridges/x64dbg.py`**: Replace the hardcoded `0` in `ModuleInfo.entry_point` with real logic reading `AddressOfEntryPoint` from the PE header.
* **A18 — `src/intellicrack/bridges/x64dbg.py`**: Add `restype`/`argtypes` declarations to all Win32 API calls to prevent HANDLE truncation on 64-bit. `OpenProcess` only declared at 3 of 7 sites (still missing at lines 274, 2149, 2756, 2815). `ReadProcessMemory`, `WriteProcessMemory`, `VirtualQueryEx`, `VirtualFreeEx`, `CloseHandle`, `Thread32First/Next`, `Module32FirstW/NextW`, `Process32FirstW/NextW`, `IsWow64Process`, `GetCurrentProcess`, and `OpenProcessToken` have no declarations anywhere. Replace `INVALID_HANDLE_VALUE = -1` with `wintypes.HANDLE(-1).value`.
* **A21 — `src/intellicrack/bridges/x64dbg.py`**: `scan_memory` warns on short pattern but still proceeds. Either raise `ToolError("pattern too short for reliable scan")` or drop the check; current code does neither.
* **A26 — `src/intellicrack/bridges/x64dbg.py`**: One bare `except ToolError: pass` still remains at line 3952 in `_get_export_names`. Replace with last-error tracking and re-raise of non-pipe/non-file errors.
* **A32 — `src/intellicrack/bridges/frida_bridge.py`**: `enumerate_exports`/`enumerate_imports` module-not-found path uses a `moduleFound: false` flag on the success payload instead of emitting an `{error: "module_not_found"}` payload as the fix spec required. Resolve by having the JS emit a dedicated error payload.
* **A33 — `src/intellicrack/bridges/frida_bridge.py`**: `create_cancellable` stores `frida.Cancellable` tokens in `self._cancellables` and `_resolve_cancellable` retrieves them, but the cancellable is never passed to `attach`, `spawn`, `create_script`, or `compiler.build`. Wire the token through the real Frida API calls.
* **A35 — `src/intellicrack/bridges/frida_bridge.py`**: `write_code` two-phase probe implemented but still uses hardcoded `_PATCH_CODE_PROBE_SIZE` for the probe buffer. Add a configurable `max_size` parameter.
* **A41 — `src/intellicrack/bridges/frida_bridge.py`**: `protect_memory` / `kernel_protect` / `kernel_enumerate_ranges` / `get_memory_regions` / `socket_listen` / `socket_connect` escape JS params but there is no explicit `_VALID_PROTECTION_FLAGS` set validating protection strings upfront. Add the explicit validation set.
* **A44 — `src/intellicrack/bridges/frida_bridge.py`**: `enumerate_threads` hardcodes `priority: 0` in the JS response and passes it back as `ThreadInfo.priority`. The JS never calls `GetThreadPriority`. Either wire up a real NativeFunction call to `GetThreadPriority` or separate `start_address` from `current_pc` and drop the fake priority.
* **A45 — `src/intellicrack/bridges/hex_editor.py`**: `import_patches` tool_definition does not advertise a `format` parameter or enum, so it cannot be split into format-specific entries as the fix spec required. Either split tool_definition into format-specific entries or broaden `import_patches` to accept `original_path` and dispatch on magic header.
* **A46 — `src/intellicrack/bridges/hex_editor.py`**: `export_patches` tool_definition advertises enum `["ips", "ips32", "bps", "ups"]` but the method raises `ToolError` for bps/ups telling callers to use separate methods. Either tighten the enum to `ips/ips32` or route bps/ups to `export_patches_bps/ups` with `original_path` source.
* **A48 — `src/intellicrack/bridges/hex_editor.py`**: `shutdown()` calls `self.clear_all()` instead of `self.state_holder.set_document(None, None, source="bridge")` before nulling `self.document`. Mirror the `close_file` pattern so the state holder is notified.
* **A52 — `src/intellicrack/bridges/hex_editor.py`**: `search_numeric` Python fallback advance formula (`pos += chunk_len - (size - 1)`) looks correct but alignment reset between chunks is implicit, not explicit. Explicitly reset `idx = (-pos) % alignment` per chunk, or remove the Python fallback entirely since the native hexcore path already exists.

### **Group C — Providers + Credentials**

* **C4 — `src/intellicrack/providers/google.py`**: Use native `AsyncIterator` for `chat_stream` instead of wrapping a sync iterator in `asyncio.to_thread`.
* **C5 — `src/intellicrack/providers/google.py`**: Ensure `_current_task` is assigned during `chat` and `chat_stream` execution so requests can actually be cancelled.
* **C10 — `src/intellicrack/providers/grok.py`**: Add support for Grok-4 context windows (256K) and `max_completion_tokens`.
* **C11 — `src/intellicrack/providers/grok.py`**: Add missing info logging in `cancel_request`.
* **C12 — `src/intellicrack/providers/openrouter.py`**: Properly close existing `httpx` clients in `connect()` before creating new ones.
* **C13 — `src/intellicrack/providers/openrouter.py`**: Read the full error body before raising for status in streams so the user sees real error messages.
* **C14 — `src/intellicrack/providers/ollama.py`**: Route cloud requests through OpenAI-compatible `/v1/` endpoints instead of local `/api/` paths.
* **C15 — `src/intellicrack/providers/ollama.py`**: Implement real streaming for tool calls; remove the blocking `chat()` fallback.
* **C16 — `src/intellicrack/providers/ollama.py`**: Wire up the `tool_choice` parameter in the request body.
* **C17 — `src/intellicrack/providers/huggingface.py`**: `BASE_URL` still targets the deprecated `api-inference.huggingface.co`; `DEFAULT_PROVIDER = "auto"` routes through generic auto-provider selection rather than the router endpoint. Switch to `https://router.huggingface.co/hf-inference/v1/chat/completions` or use `huggingface_hub.InferenceClient` with an explicit provider.
* **C19 — `src/intellicrack/providers/huggingface.py`**: 503 branch calls `response.json()` unguarded; HTML service-unavailable bodies raise `DecodingError` uncaught. Wrap the `json()` call in `try/except (json.JSONDecodeError, ValueError)` with a "Model is loading" fallback.
* **C29 — `src/intellicrack/credentials/store.py`**: Replace the destructive "test_key" write/delete probe with passive class inspection of the keyring backend.
* **C30 — `src/intellicrack/credentials/oauth.py`**: Extend `OAuthProvider` enum and configs to support Anthropic, HuggingFace, and OpenAI.
* **C31 — `src/intellicrack/credentials/oauth.py`**: Use the 10-minute `needs_refresh` buffer in `get_token` logic.
* **C32 — `src/intellicrack/credentials/oauth.py`**: Move callback data from class-level attributes to the server instance to prevent concurrent flow collisions.
* **C33 — `src/intellicrack/credentials/oauth.py`**: Check HTTP status in `revoke_token` and return a combined success status for both the API call and keyring deletion.
