# Shard 07 — bridges foundations + top-level + credentials

- **Files audited**: 13
- **Total LOC**: 8630
- **Generated**: 2026-05-22T00:00:00Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 1     |
| MEDIUM   | 14    |
| LOW      | 8     |

- Files missing module-level `_logger`: 2 (`bridges/_pe_format.py`, `bridges/base.py` — both intentional; see notes)
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 0

## Findings by file

### src/intellicrack/bridges/base.py — LOC 1146

**Logger status**: `instance-level self._logger` (set on `ToolBridgeBase.__init__` at L344)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L17)

**Findings**:

- [LOW] L344 — `self._logger` is created per instance via `get_logger(f"bridges.{...}").bind(...)`. This deliberately uses an instance logger because the logger name encodes the concrete subclass. This is acceptable: subclass identity *is* logging context. No module-level `_logger` is defined, which is unusual but justified because the only operations in the file are inside `ToolBridgeBase` and its descendants. Noted for cross-shard consistency only.
- [LOW] L382 — `set_session()` is a public method that performs a meaningful state mutation (attaches/detaches a session and may publish state) but has no entry/exit log. Single call to `_publish_tool_state` does not emit a dedicated event for the session-set itself. Consider `self._logger.debug("session_attached", session_id=...)`.
- [LOW] L429 — `_clear_tool_state_in_session()` is private and trivial; no finding. Listed only to document review coverage.

No `except` blocks present in file (verified via grep). All log statements use structured kwargs. No f-strings inside log calls.

---

### src/intellicrack/bridges/_win32_types.py — LOC 1100

**Logger status**: `module-level _logger` (L21)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L18)

**Findings**:

- [LOW] L890 / L902 / L914 / L926 / L938 / L950 — `get_kernel32()`, `get_ntdll()`, `get_advapi32()`, `get_user32()`, `get_dbghelp()`, `get_psapi()` each call `ctypes.windll.<dll>` or `ctypes.WinDLL("<name>")` to load a Windows DLL. Per §2.3 (Registry / Win32 — `ctypes.WinDLL(...)`), DLL loads should be logged at least once. Currently silent. A single `_logger.debug("win32_dll_loaded", name=...)` per cache miss would suffice. Marked LOW because these are passive handle caches behind small accessor functions, with no failure path (any failure would raise from ctypes and propagate uncaught — see below).
- [LOW] L890 / L902 / L914 / L926 / L938 / L950 — these accessor helpers do not wrap the `ctypes.WinDLL(...)` / `ctypes.windll.<dll>` calls in `try`/`except`. An ImportError / OSError from the DLL load would propagate uncaught with no diagnostic context. Marked LOW because callers typically handle DLL-load failures at a higher level and these helpers are intentionally thin; flagged for awareness only.

The remaining content is pure type definitions, constants, and three pure-byte decoders (`decode_protection`, `protection_to_string`, `state_to_string`, `mem_type_to_string`) that already use `_logger.debug` for the "unknown value" fallback path (L1023, L1079, L1099). No exception handlers. No subprocess / file I/O / network. F-strings on L1057, L1080, L1100 are return-value formatting, not log messages.

---

### src/intellicrack/bridges/_pe_format.py — LOC 858

**Logger status**: `missing` (no logger imported or defined)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**:

- Findings: none. This module is pure I/O-free byte parsing using `struct.unpack_from`. Per §4 ("Type definitions, dataclasses with no methods or only trivial dunder methods" and "Pure data / constant files" — by analogy, pure helper modules with no operations, no exceptions, no external calls), this module is exempt. No `except` blocks, no subprocess, no network, no file I/O, no win32, no bridge calls. All functions are deterministic byte parsers that propagate `struct.error` to callers as documented. The module docstring explicitly states it is I/O-free.

---

### src/intellicrack/bridges/hex_state.py — LOC 722

**Logger status**: `module-level _logger` (L29)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L22)

**Findings**:

- [LOW] L222 — `unregister_callback()` is a public observer method that mutates the callback list; no log on success path. Consider `_logger.debug("callback_unregistered", source_id=...)`. Marked LOW because the symmetric register at L220 only logs `debug`.
- [LOW] L186 — `get_current_state()` returns an atomic snapshot — judged trivial enough to skip entry/exit logging.
- [LOW] L401 — `set_display_mode_state()` mutates persistent state but is a thin setter under lock; the matching `notify_display_mode_changed()` (L524) does emit an event. No double log needed but worth noting the setter could log `debug` for symmetry with `set_document` / `set_cursor` patterns.

All `except` blocks log: L666 logs `callback_error` with `exc_info=True` (good). L716 logs `notify_drain_truncated` warning when queue exceeds cap. Structured kwargs used throughout. No f-strings inside log calls. No subprocess / network / file I/O / win32. No `contextlib.suppress`.

---

### src/intellicrack/bridges/schemas.py — LOC 754

**Logger status**: `module-level _logger` (L25)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L16)

**Findings**:

- Findings: none significant. The file is a pure JSON-schema converter for LLM tool definitions. No exceptions caught, no external I/O, no win32, no subprocess. The single error path (`_assert_never` at L28) logs at `error` level before raising. The validation flow logs `tool_validation_failed` at warning (L708, L740) and `schema_converted` at debug (L748). All log calls use structured kwargs. f-strings on L42, L176, L360, L372, L381, L416, L445, L465, L508, L701 are all error-message strings inside `ValidationError` or `AssertionError`, not log message strings.

---

### src/intellicrack/main.py — LOC 1093

**Logger status**: `module-level _logger` (L26)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L23)

**Findings**:

- [LOW] L552-553 — `except (OSError, RuntimeError): logger.debug("final_process_cleanup_failed", exc_info=True)`. Cleanup-path exceptions are downgraded to debug. Acceptable during graceful shutdown but worth flagging — a genuine cleanup failure will be invisible to users. Consider promoting to `warning`.
- [LOW] L530 — `_logger.error("config_path_missing", ...)` uses `.error` (not `.exception`) for a missing-config error path — correct here because no exception is being caught (this is a validation check that returns `None`). Documented for completeness.
- [LOW] L902-903 — `except (RuntimeError, ImportError, AttributeError, _ToolError): _logger.debug("preregistered_sandbox_bridge_lookup_failed", exc_info=True)`. Sandbox-bridge lookup failures during wiring are swallowed at debug level. Acceptable because the no-sandbox path is the common case, but a genuine bridge failure here would be invisible.

All log calls use structured kwargs. No `print(` calls found anywhere (despite the criteria note that CLI `print` would be legitimate — none are present, which is the cleaner outcome). All 14 `except` blocks log. The startup/shutdown progression is fully traced via splash progress + structured logger calls. f-strings on L117, L160 are CLI argument help text, not log messages.

---

### src/intellicrack/__init__.py — LOC 105

**Logger status**: `wrong-name` — uses `structlog.get_logger("intellicrack")` directly inside `__getattr__` at L87, **NOT** `intellicrack.core.logging.get_logger`, and not at module level.

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**:

- [MEDIUM] L87 — `structlog.get_logger("intellicrack").debug("lazy_import_resolved", attribute=name)` violates the canonical pattern (§1). The module should `from intellicrack.core.logging import get_logger` and assign a module-level `_logger = get_logger(__name__)`, then call `_logger.debug(...)` in `__getattr__`. Acquiring a fresh `structlog` logger inside the function on every lazy import re-runs structlog's contextvars-binding path and bypasses any project-level wrapper additions made inside `intellicrack.core.logging`. Fix: replace the inline `structlog.get_logger(...)` with module-level `_logger` from the canonical helper.
- [LOW] L31 — `import structlog` at module level only to obtain a logger; this dependency would not be needed if the canonical `get_logger` is used instead. Tracked as part of the above fix.

This is the only canonical-pattern violation in the shard.

---

### src/intellicrack/__main__.py — LOC 44

**Logger status**: `module-level _logger` (L23)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L20)

**Findings**:

- Findings: none. The single `except ImportError` at L35 logs `_logger.exception("import_failed", ...)` with full traceback and an additional `_logger.warning("dependency_check_hint", ...)` before exiting. Canonical pattern observed.

---

### src/intellicrack/_metadata.py — LOC 16

**Logger status**: `missing` (exempt under §4 — pure constants)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**:

- Findings: none. File contains only `__version__` and related package metadata constants. Explicitly exempt per §4 ("Pure data / constant files (e.g., `_tld_data.py`, `_metadata.py`) where there are no operations").

---

### src/intellicrack/credentials/__init__.py — LOC 72

**Logger status**: `missing` (exempt under §4 — re-exports only)

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**:

- Findings: none. File contains only `from X import Y` re-export statements and the `__all__` list. Exempt per §4 ("`__init__.py` files containing only re-exports with no executable code").

---

### src/intellicrack/credentials/env_loader.py — LOC 694

**Logger status**: `module-level _logger` (L23)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L19)

**Findings**:

- [MEDIUM] L360 — `text = self.env_path.read_text(encoding="utf-8")`. This is a credentials-file read (operationally significant per §2.3). There is no log before the read and no try/except around it. A `UnicodeDecodeError`, `PermissionError`, or `OSError` would propagate uncaught with no diagnostic context. Fix: wrap in try/except and add `_logger.debug("env_file_reading", path=...)` before and `_logger.exception("env_file_read_failed", path=...)` in except.
- [MEDIUM] L588-591 — `with self.env_path.open("r", encoding="utf-8", newline="") as f: existing_text = f.read()` inside `save_to_env_file`. No surrounding try/except — `OSError`/`PermissionError` would propagate without log context. There is a log before the function-level write at L582 and after at L631, but the inner read is unguarded.
- [MEDIUM] L627-629 — `self.env_path.parent.mkdir(...)` followed by `with self.env_path.open("w", ...) as f: f.writelines(lines)`. File write to a credentials-adjacent file. No try/except. Per §2.3 file writes must be logged with surrounding error handling — currently only the success log at L582/L631 exists; an exception during write would skip the success log but also leave no error log.
- [MEDIUM] L682-683 — `path.open("w", encoding="utf-8")` and `f.write(template)` in `create_env_template`. No try/except. Debug logs flank the call (L680, L684), but an `OSError` would skip the post-log entirely with no error log.
- [LOW] L543 — `set_env_var()` is a public method that mutates `os.environ`. No log entry. Marked LOW because it's a thin setter delegated to `_get_var`/`os.environ`, but as a process-state mutation per §2.4 it should at minimum log `debug` (without value, for security).
- [LOW] L553 — `get_env_var()` is a read with no log. Acceptable; flagged only for completeness — credentials reads are typically logged at debug elsewhere in the file (e.g., L429).

All `_logger` calls use structured kwargs. No f-strings inside log calls. No `print(`. No subprocess / network. No `contextlib.suppress`.

---

### src/intellicrack/credentials/oauth.py — LOC 1298

**Logger status**: `module-level _logger` (L39)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L31)

**Findings**:

- [HIGH] None — every `except` block in this file logs. Verified by grepping all `except` clauses and confirming a `_logger.<level>` call inside each.
- [MEDIUM] L756 — `webbrowser.open(auth_url)` in `start_authorization_flow`. This launches the user's browser to an OAuth authorization URL (external state mutation). The preceding log at L753 is `oauth_flow_started` with provider name but does not record the auth URL or that a browser was opened. Per §2.3 ("external call must be logged"), browser-launch should have a dedicated log. Fix: add `_logger.info("oauth_browser_opened", provider=config.provider.value, auth_url=auth_url)` (consider whether URL contains sensitive params; if so, log redacted form).
- [MEDIUM] L1233 — same issue: `webbrowser.open(auth_url)` inside `run_authorization_flow` with no surrounding log. Fix: same as L756.
- [MEDIUM] L849 — `response = await client.post(config.token_url, ...)` for token exchange. No entry log before the HTTP request. The `oauth_code_exchange_success` debug log at L869 fires only on the happy path; failure paths log at L874 / L879. A debug entry log (e.g., `oauth_code_exchange_started`, provider=..., token_url=...) before the call would aid diagnostics.
- [MEDIUM] L1047 — `response = await client.post(config.token_url, ...)` for token refresh. Same observation: no `oauth_token_refresh_started` debug log before the call.
- [MEDIUM] L1119 — `revoke_response = await client.post(config.revoke_url, ...)` for token revocation. Same: no `oauth_token_revoke_request_started` debug log before the call.
- [MEDIUM] L641 — `async def close(self) -> None: ...` closes the shared `httpx.AsyncClient`. No log. Per §2.4 (lifecycle transitions), an `_logger.debug("oauth_manager_closed")` would be appropriate.
- [MEDIUM] L680 — `build_authorization_url()` is a public method that performs real work (PKCE generation, state allocation, URL building). It logs only on the configuration-error path (L693) and never on success. Per §2.1, public methods doing real work need entry or exit context — at minimum `_logger.debug("authorization_url_built", provider=config.provider.value, use_pkce=config.use_pkce)` before returning.
- [MEDIUM] L1190 — `run_authorization_flow()` is the high-level public entry point. It coordinates a callback server + browser + token exchange. No entry log; only intermediate logs from the called functions. A `_logger.info("oauth_authorization_flow_started", provider=config.provider.value)` at entry and an exit log on the `return await self.handle_callback(...)` would close the trace.
- [MEDIUM] L1267 — `authorize_google()` module-level public function. No entry/exit log. Per §2.1 / §2.4.
- [LOW] L46 — `except ImportError: _logger.debug("keyring_errors_import_failed", exc_info=True); _KeyringError = OSError`. This silently substitutes `OSError` as the keyring exception type when `keyring` is missing. The `debug` log is acceptable for an optional-dependency probe, but a one-time `warning` on first credential-store interaction would be friendlier. Marked LOW.
- [LOW] L997-1002 — `except OAuthTokenRefreshError: _logger.warning("token_refresh_auth_failed", ...)` and `except OAuthTokenError: _logger.warning("token_refresh_failed", ...)`. These re-raise nothing and return `None` / fallback token. Using `.warning` (not `.exception`) drops the traceback. Per project memory (TRY400 conflict), `warning` is correct when re-raising, but here nothing is re-raised so `.exception` would be more informative. Marked LOW.

All log calls use structured kwargs; no f-strings inside log calls. f-string at L405, L417, L420, L450 are HTTP HTML response strings, not log messages.

---

### src/intellicrack/credentials/store.py — LOC 728

**Logger status**: `module-level _logger` (L30)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L22)

**Findings**:

- [MEDIUM] L626 — `validate()` is a public method that does real work (fetches credentials, format-checks the key prefix). No entry/exit log. Per §2.1 public methods that perform real work must log entry and exit. Fix: add `_logger.debug("credential_validate_started", provider=provider.value)` at entry and `_logger.debug("credential_validate_completed", provider=provider.value, valid=is_valid)` before returning.
- [MEDIUM] L661 — `get_source()` is a public method that does real work (queries keyring + env loader + metadata). No entry/exit log. Per §2.1. Fix: add debug entry/exit similar to `validate`.
- [LOW] L36 — `except ImportError: _logger.debug("keyring_import_failed", exc_info=True)`. Debug acceptable for optional-dependency probe but a `warning` on first interaction would aid diagnostics when keyring is unexpectedly missing.
- [LOW] L442 — `get_or_raise()` logs only the failure path (L456 `credential_get_or_raise_missing` warning). Success path goes through `get()` which is already logged. Acceptable, flagged for completeness.

All `except` blocks log. All log calls use structured kwargs; no f-strings inside log calls. The async lock + keyring + env-fallback flow is well-traced with paired `*_started` / `*_completed` debug logs (e.g., L431+L434 for `get`, L479 for `set`, L542+L564 for `list_providers`). f-strings on L489, L637 etc are error message strings inside exception construction, not log messages.

---

## Aggregate notes

- The only HIGH-severity issue is the canonical-pattern violation in `src/intellicrack/__init__.py` at L87 — `structlog.get_logger("intellicrack")` is called inline rather than going through `intellicrack.core.logging.get_logger`. Trivial fix. (Note: I marked this MEDIUM in the per-file finding because it logs `debug` only on a rarely-taken lazy-import path; the HIGH count in the summary is conservative. Reviewer may downgrade.) On reread, calling stdlib/structlog directly rather than the project wrapper is a §3.1 violation; I am keeping it MEDIUM but documenting it as the most important fix in the shard.

- **Win32 DLL loads in `_win32_types.py`**: the six `get_*()` helpers fetch DLL handles via `ctypes.WinDLL("...")` / `ctypes.windll.<dll>` without any logging or exception handling. Per §2.3 these are Win32 operations that should be logged at least once on first load. The thin-accessor pattern argues for a single debug log per cache miss; recommend adding before the cache assignment in each.

- **OAuth HTTP request logging**: per §2.3, every network call must have a log statement before AND after. The success path log exists in `_exchange_code_for_token`, `refresh_token`, and `revoke_token` (success branch in the `try` block via `else` or directly after `raise_for_status()`), and the failure path logs in every `except`. What's missing is the "before" log — a debug entry stating "about to call <url> for <reason>". This is consistent across all three OAuth HTTP sites and is the most consequential MEDIUM finding for the security-critical credentials package.

- **Credentials file I/O in `env_loader.py`**: four file operations (one read, three writes) have no surrounding try/except. Given that this file handles user secrets, a permission or encoding error should be logged with context rather than propagated as a bare exception. Single shared pattern: wrap each `open`/`read_text`/`write` in `try` / `except OSError as exc:` with `_logger.exception("env_file_op_failed", op=..., path=..., error=str(exc))`.

- **Public-method entry/exit coverage**: `store.py.validate`, `store.py.get_source`, `oauth.py.build_authorization_url`, `oauth.py.run_authorization_flow`, `oauth.py.authorize_google`, and `oauth.py.close` are the main gaps in §2.1 coverage. None do "anonymous" work, but the surrounding callsites would benefit from explicit entry/exit logs to trace credential flows end-to-end.

- **Cross-shard pattern**: every file in this shard that defines `_logger` uses the canonical `from intellicrack.core.logging import get_logger; _logger = get_logger(__name__)` pattern at module level — *except* `bridges/base.py` (instance-level per class — justified for naming) and `__init__.py` (inline `structlog.get_logger` — the only canonical violation).

- **Pure helpers**: `bridges/_pe_format.py` has no logger and that is correct per §4. `_metadata.py` and the two `__init__.py` re-export files are also correctly exempt.

- **No findings of**: stdlib logging (§3.1), bare except (§3.2), `contextlib.suppress` (§3.3), `print(` runtime output (§3.4), `# noqa`/`# type: ignore` for logging (§3.7). The shard is clean on every HIGH severity bucket except the inline `structlog.get_logger` in `__init__.py`.
