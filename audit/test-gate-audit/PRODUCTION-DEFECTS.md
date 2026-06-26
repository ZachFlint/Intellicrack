# Production Defects Surfaced by Test-Gate Remediation

Defects found while writing correct falsifiable gates. The gates were written
first and kept RED while `src/` was untouched (remediation rule 1). All seven
have since been **resolved in source and verified GREEN** in the Windows Docker
sandbox (`custom` run, 2026-06-26: 16 passed / 0 failed / 0 skipped).

## PD-001: resource_exists — RESOLVED (green)
- **Source:** `src/intellicrack/ui/resources/resource_helper.py`:175 (`resource_exists`)
- **Test file:** `tests/test_ui/test_resource_helper.py`
- **Expected:** resource_exists("") returns False — an empty path is not an existing resource
- **Actual (defect):** resource_exists("") returned True because get_resource_path("") normalizes the empty string to "" and `assets_dir / ""` evaluates to the assets directory itself (which exists), so path.exists() was True
- **Fix:** guard a falsy `resource_path` at the top of `resource_exists` and return False before resolving
- **Red gate:** `tests/test_ui/test_resource_helper.py::TestResourceExists::test_returns_false_for_empty_path`
- **Sandbox status:** PASSED (green)

## PD-002: ProcessBridge.time_thread_wait — RESOLVED (green)
- **Source:** `src/intellicrack/bridges/process.py` (`time_thread_wait`)
- **Test file:** `tests/test_bridges/test_process_win32.py`
- **Expected:** OpenThread called with THREAD_QUERY_INFORMATION | SYNCHRONIZE (0x00100040) so WaitForSingleObject has the required SYNCHRONIZE access right and can return WAIT_OBJECT_0 or WAIT_TIMEOUT
- **Actual (defect):** OpenThread was called with only THREAD_QUERY_INFORMATION (0x0040), which lacks SYNCHRONIZE; WaitForSingleObject always returned WAIT_FAILED
- **Fix:** added `SYNCHRONIZE` (0x00100000) to `win32_types`; `time_thread_wait` now opens the thread with `THREAD_QUERY_INFORMATION | SYNCHRONIZE` and configures `OpenThread.restype = wintypes.HANDLE` / argtypes to prevent 64-bit handle truncation
- **Red gate:** `test_time_thread_wait_exited_thread_signals`
- **Sandbox status:** PASSED (green)

## PD-003: ProcessBridge._time_wait_on_handle — RESOLVED (green)
- **Source:** `src/intellicrack/bridges/process.py` (`_time_wait_on_handle`)
- **Test file:** `tests/test_bridges/test_process_win32.py`
- **Expected:** WaitForSingleObject returns the unsigned DWORD result so `wait_result == WAIT_FAILED` (0xFFFFFFFF) matches on failure and WAIT_OBJECT_0 / WAIT_TIMEOUT classify correctly
- **Actual (defect):** WaitForSingleObject had the default `c_int` restype, so 0xFFFFFFFF was read as signed -1; `-1 == 0xFFFFFFFF` is False and the method returned `other_-1` instead of `failed`
- **Fix:** set `WaitForSingleObject.restype = wintypes.DWORD` and argtypes `[HANDLE, DWORD]` before the call
- **Red gate:** `test_time_thread_wait_running_thread_times_out`
- **Sandbox status:** PASSED (green)

## PD-004: _get_pattern_registry — RESOLVED (green)
- **Source:** `src/intellicrack/bridges/hex_editor.py`:1774 (`_get_pattern_registry`)
- **Test file:** `tests/test_hexcore_e2e/test_bridge_pattern_engine.py`
- **Expected:** project_root = Path(__file__).resolve().parents[3]  # repository root
- **Actual (defect):** project_root = Path(__file__).resolve().parents[2]  # resolves to <repo>/src, one level too shallow, so `<repo>/vendor/community-patterns/patterns` was never scanned and the catalog stayed empty
- **Fix:** `parents[2]` -> `parents[3]`
- **Red gate:** `test_list_hexpat_patterns_items_have_required_keys` / `test_auto_detect_with_pe_file_returns_list`
- **Sandbox status:** PASSED (green)

## PD-005: ProcessBridge.enumerate_services — RESOLVED (green)
- **Source:** `src/intellicrack/bridges/process.py` (`enumerate_services` / `_enumerate_services_by_state`)
- **Test file:** `tests/test_bridges/test_process_win32.py`
- **Expected:** enumerate_services configures `OpenSCManagerW.restype = wintypes.SC_HANDLE` (plus the EnumServicesStatusExW / CloseServiceHandle prototypes) itself so the 64-bit SCM handle is not truncated; EnumServicesStatusExW succeeds and the method returns the real service list
- **Actual (defect):** enumerate_services never configured the ctypes prototypes; the default `c_int` restype truncated the 64-bit SC_HANDLE so EnumServicesStatusExW failed with ERROR_INVALID_HANDLE (6) and the method returned []. It only worked by accident if list_services had configured the shared advapi32 prototype earlier in the same process (order-dependent)
- **Fix:** extracted a shared `_configure_scm_prototypes()` helper (DRY) that sets the OpenSCManagerW / EnumServicesStatusExW / CloseServiceHandle restype/argtypes; both `list_services` and `enumerate_services` now call it, and `_enumerate_services_by_state` receives the configured `enum_svc` callable explicitly
- **Red gate:** `test_enumerate_services_returns_list` / `test_enumerate_services_active_filter`
- **Sandbox status:** PASSED (green)

## PD-006: AnthropicProvider._build_usage_from_message — RESOLVED (green)
- **Source:** `src/intellicrack/providers/anthropic.py`:379 (`_build_usage_from_message`) / `src/intellicrack/providers/base.py`:56 (`UsageInfo`)
- **Test file:** `tests/test_providers/test_anthropic_provider.py`
- **Expected:** `UsageInfo` carries `cache_read_tokens` / `cache_creation_tokens` fields, and `_build_usage_from_message` populates them from the response's `cache_read_input_tokens` / `cache_creation_input_tokens`, so prompt-cache hits are observable
- **Actual (defect):** `UsageInfo` was a 3-field slots dataclass (prompt/completion/total); `_build_usage_from_message` read only input_tokens/output_tokens, so cache token counts were silently dropped
- **Fix:** added `cache_read_tokens` / `cache_creation_tokens` (default 0) to `UsageInfo`; `_build_usage_from_message` now reads `cache_read_input_tokens` / `cache_creation_input_tokens` and populates them. Added the missing falsifiable pure-logic gate `test_cache_token_fields_surface_exactly` (constructs a `Usage` with cache counts, asserts they surface exactly)
- **Red gate:** `tests/test_providers/test_anthropic_provider.py::TestBuildUsageFromMessage::test_cache_token_fields_surface_exactly`
- **Sandbox status:** PASSED (green)

## PD-007: ProcessBridge._resolve_symbol (SYMBOL_INFO.SizeOfStruct) — RESOLVED (green)
- **Source:** `src/intellicrack/bridges/process.py` (`_resolve_symbol`)
- **Test file:** `tests/test_bridges/test_process_bridge.py`
- **Expected:** `SizeOfStruct` = 88 (offsetof(Name)=84 + the 1-byte Name, rounded up to the struct's 8-byte alignment) so SymFromAddr accepts the struct and resolves the address; the resolved name is read from offsetof(Name)=84
- **Actual (defect):** the formula `sizeof(SYMBOL_INFO) - sizeof(c_char*1024) + sizeof(c_char)` yielded 1112 - 1024 + 1 = 89 (the ctypes trailing `Name` array adds 8-byte alignment padding the real C struct's `Name[1]` lacks); SymFromAddr returned ERROR_INVALID_PARAMETER (87) so `_resolve_symbol` returned ("",0) for every address. The name slice also used the SizeOfStruct value as the read offset, which would have skipped the first 4 bytes of every name had resolution ever succeeded
- **Fix:** compute `sym_header_size` as `ceil((SYMBOL_INFO.Name.offset + sizeof(CHAR)) / alignof(SYMBOL_INFO)) * alignof(SYMBOL_INFO)` = 88 (correct-by-construction, no magic number); read the resolved name from `SYMBOL_INFO.Name.offset` (84), not from `sym_header_size`
- **Red gate:** `TestF0024SymbolInfoSizeOfStruct` (incl. `test_resolve_symbol_returns_nonempty_name`) / `TestF0042SymbolBufferAllocation` (incl. `test_resolve_symbol_no_truncation_on_long_name`)
- **Sandbox status:** PASSED (green) — the live SymFromAddr resolution tests now resolve real kernel32 symbols instead of skipping
