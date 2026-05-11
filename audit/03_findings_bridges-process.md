> # Workgroup Directive — Execution Order 03/23: `bridges-process`
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
# Findings: bridges-process

## Files audited (1)

- src/intellicrack/bridges/process.py

## Findings

### Category 4 - Ineffective Implementations

#### F-0001 - `_elevate_debug_privilege` ignores `AdjustTokenPrivileges` BOOL return; `ctypes.get_last_error()` unreliable

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 884-905
- **Pattern:** Cat 4, Cat 13

#### F-0002 - `CreateToolhelp32Snapshot` invalid-handle check uses `== -1` without `restype` declaration

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 1014-1016, 1067-1068, 1962-1967, 2021-2022, 3157-3158
- **Pattern:** Cat 4, Cat 5

### Category 5 - Error Handling

#### F-0003 - `Process32First` failure silently returns empty list

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 1022-1043
- **Pattern:** Cat 5

### Category 11 - State

#### F-0004 - `terminate` always tears down the bridge handle on the failure branch

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 1466-1477
- **Pattern:** Cat 11

#### F-0005 - `suspend` / `resume` swallow OpenThread/SuspendThread failures and unconditionally claim success

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 1500-1507, 1530-1537
- **Pattern:** Cat 5, Cat 7

### Category 4 - Naive Implementations

#### F-0006 - `get_memory_map` hardcodes `{0x40000, 0x1000000}` instead of using constants

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 1744-1755
- **Pattern:** Cat 4, Cat 16

#### F-0007 - `_scan_region_pattern` aborts entire region after a single chunk read failure

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 1864-1888
- **Pattern:** Cat 5, Cat 16

### Category 16 - Binary Analysis

#### F-0008 - `get_seh_chain` is x86-only but exposed for arbitrary TIDs

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3677-3731
- **Pattern:** Cat 16, Cat 21

#### F-0009 - `get_thread_context` and `set_thread_context` pick CONTEXT64/32 by host pointer size, ignoring WOW64

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3217-3286, 3321-3385
- **Pattern:** Cat 4, Cat 16

#### F-0010 - `inject_dll` discards `WaitForSingleObject` return; no `GetExitCodeThread`; uses ANSI API for UTF-8 path

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 2208-2227
- **Pattern:** Cat 5, Cat 6

#### F-0011 - `read_peb` and `read_teb` use a fixed 0x100-byte buffer

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 2809-2818, 3063-3072
- **Pattern:** Cat 4

### Category 19 - Data Format

#### F-0012 - `_extract_env_pointer` uses bogus offsets and wrong field width

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3917-3941
- **Pattern:** Cat 19

### Category 1 - Stub Implementation

#### F-0013 - `_acquire_queryable_job_handle` is a documented stub; `OpenJobObjectW(_, _, NULL)` always fails

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4458-4490
- **Pattern:** Cat 1, Cat 2

### Category 4 - Naive

#### F-0014 - `enumerate_com_servers` walks all of HKCR\CLSID synchronously on the asyncio thread

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4054-4133
- **Pattern:** Cat 4, Cat 7

#### F-0015 - `detect_dotnet` "version" is a hardcoded string keyed off DLL basename

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4201-4255
- **Pattern:** Cat 4, Cat 16

### Category 5 - Error Handling

#### F-0016 - `pipe_close` and `device_close` always return True even when `CloseHandle` fails

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4036-4048, 4347-4359
- **Pattern:** Cat 5, Cat 6

### Category 4 - Type Truncation

#### F-0017 - `pipe_connect` and `device_open` invoke `CreateFileW` without setting `restype = wintypes.HANDLE`

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3965-3982, 4278-4293
- **Pattern:** Cat 4, Cat 14

#### F-0018 - `device_ioctl` accepts `bytes` but tool def says hex-string; no shim

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4295-4345
- **Pattern:** Cat 4, Cat 9

### Category 16 - Binary Analysis

#### F-0019 - `get_handles` returns raw `ObjectTypeIndex` integers without resolving via `NtQueryObject`

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 2528-2538
- **Pattern:** Cat 4, Cat 16

#### F-0020 - `_query_thread_state` Suspend-then-Resume-to-probe pattern can leave the thread suspended

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 2112-2166
- **Pattern:** Cat 5, Cat 16

#### F-0021 - `get_tls_values` reads from TLS *expansion* slot pointer (NULL for nearly every thread)

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4936-4977
- **Pattern:** Cat 4, Cat 21

#### F-0022 - `_parse_teb_fields` mislabels TEB+0x58 as `tls_pointer`

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3085-3129
- **Pattern:** Cat 4, Cat 16

### Category 19 - Data Format

#### F-0023 - `_parse_service_entries` stores raw `c_wchar_p` pointers (not Python strings)

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 2712-2731
- **Pattern:** Cat 19, Cat 6

#### F-0024 - `_resolve_symbol` uses magic expression for `SizeOfStruct`

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3636-3648
- **Pattern:** Cat 4

#### F-0025 - `_resolve_module` uses an undersized 584-byte raw buffer

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3650-3671
- **Pattern:** Cat 4, Cat 5

### Category 21 - Documentation

#### F-0026 - tool defs say "Success status" but impls always return True regardless of partial failure

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 276-291, 564-569, 606-612, 1479-1537, 4036-4048, 4347-4359
- **Pattern:** Cat 21

#### F-0027 - `get_mitigation_policies` reports `enabled = bool(flags & 1)` for every policy

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3788-3800
- **Pattern:** Cat 4

### Category 6 - Lifecycle

#### F-0028 - `read_teb` reads from `self._process_handle` regardless of TID owner

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3010-3083
- **Pattern:** Cat 6

### Category 13 - Logging Theater

#### F-0029 - Nearly every public method emits `_started` info-level events

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** Many
- **Pattern:** Cat 13

### Category 5 - Error Handling

#### F-0030 - `_parse_registry_path` only recognises three roots

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4667-4697
- **Pattern:** Cat 5

#### F-0031 - `reg_read_value` uses fixed 4096-byte buffer; treats ERROR_MORE_DATA as failure

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4724-4753
- **Pattern:** Cat 5

### Category 19 - Data Parsing

#### F-0032 - `_check_inproc_server` only walks `CLSID\…\InprocServer32`

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4135-4195
- **Pattern:** Cat 19

#### F-0033 - `get_environment` caps the env-block read at 64 KiB

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3895-3915
- **Pattern:** Cat 4

### Category 6 - Resource Lifecycle

#### F-0034 - `_target_is_64bit` falls back to host pointer size when both `IsWow64Process2` and `IsWow64Process` unavailable

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 2835-2875
- **Pattern:** Cat 6

### Category 7 - Concurrency

#### F-0035 - `async def` methods that loop tens of thousands of times block the event loop

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4109-4133, 2515-2538, 3590-3621
- **Pattern:** Cat 7

### Category 5 - Error Handling

#### F-0036 - `enumerate_com_servers` returns `[]` when `advapi32` is unavailable instead of raising

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4054-4081
- **Pattern:** Cat 5

### Category 21 - Documentation Drift

#### F-0037 - tool defs claim "Hex string" but impls return raw `bytes`

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 292-300, 545-553, 595-605, 691-698; impls 1543-1573, 3984-4009, 4295-4345, 5005-5046
- **Pattern:** Cat 21

### Category 5 - Security

#### F-0038 - `create_section` does not detect `ERROR_ALREADY_EXISTS`

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4863-4895
- **Pattern:** Cat 5, Cat 14

### Category 6 - Resource Leak

#### F-0039 - `map_section` has no matching `unmap_section`

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 4897-4930
- **Pattern:** Cat 6

#### F-0040 - `get_handles` walks entries by index without verifying buffer size

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 2515-2538
- **Pattern:** Cat 4

#### F-0041 - `stack_walk` discards SuspendThread/SymInitialize BOOL returns

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3431-3446
- **Pattern:** Cat 6, Cat 7

#### F-0042 - `_resolve_symbol` allocates only a bare `SYMBOL_INFO` instance; DbgHelp writes past allocation

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3623-3648
- **Pattern:** Cat 6

### Category 5 - Error Handling

#### F-0043 - `query_system_info` only retries on `STATUS_INFO_LENGTH_MISMATCH`

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 5005-5046
- **Pattern:** Cat 5

### Category 6 - Lifecycle

#### F-0044 - `shutdown` releases DLL refs but does not unmap sections, close pipe handles, or close device handles

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 906-916
- **Pattern:** Cat 6, Cat 11

### Category 13 - Logging Theater

#### F-0045 - dispatch shims `list`/`list_detailed`/`open` emit duplicate `_started` log events

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 937-994
- **Pattern:** Cat 13, Cat 21

### Category 19 - Data Parsing

#### F-0046 - `_extract_env_pointer` reads `<H` (16-bit) for `EnvironmentSize`

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 3917-3941
- **Pattern:** Cat 19

### Category 4 - Hardcoded Returns

#### F-0047 - `get_modules` hardcodes `entry_point=0` for every module

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 1976-1994
- **Pattern:** Cat 4

#### F-0048 - `get_threads` hardcodes `current_pc=0` for every thread

- **File:** `src/intellicrack/bridges/process.py`
- **Lines:** 2032-2053
- **Pattern:** Cat 4
