> # Audit List 2/6
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

# Findings: providers-meta

## Files audited (3)

- src/intellicrack/providers/registry.py
- src/intellicrack/providers/discovery.py
- src/intellicrack/providers/**init**.py

## Findings

### Category 5 - Error Handling Anti-Patterns

#### F-0001 - Registry `connect_provider()` swallows wrong exception set; provider-raised `ProviderError`/`AuthenticationError` will bypass the handler

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 165-172
- **Pattern:** Cat 5
- **Why this is non-functional:** Provider implementations routinely raise `ProviderError` and `AuthenticationError` from `connect()`. `ProviderError` derives from `IntellicrackError(Exception)`, NOT a subclass of any of `ConnectionError`/`TimeoutError`/`OSError`/`RuntimeError`/`ValueError`. The handler never catches the most common failure class.

### Category 24 - Recovery / Robustness Theater

#### F-0002 - Registry `connect_provider()` documents `bool` return but never returns `False`

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 137-172
- **Pattern:** Cat 24

### Category 20 - Dead Code

#### F-0003 - `ProviderRegistry._credential_loader` parameter is wired but never reached

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 36-52, 158-163, 244-259
- **Pattern:** Cat 20, Cat 12
- **Why this is non-functional:** `get_provider_registry()` (the only construction site) calls `ProviderRegistry()` with no arguments, so `self._credential_loader` is permanently `None`.

### Category 18 - Public API Plumbing

#### F-0004 - `get_provider_registry` is not exported from `providers/__init__.py`

- **File:** `src/intellicrack/providers/__init__.py`
- **Lines:** 48, 63-109
- **Pattern:** Cat 18

### Category 9 - Bridge / Tool Integration Failures

#### F-0005 - `ProviderRegistry` is not a true factory: it cannot map a `ProviderName` to a class

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 30-122
- **Pattern:** Cat 9

### Category 7 - Concurrency / Async Issues

#### F-0006 - `ModelDiscovery._lock` is allocated but never used

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 314-324
- **Pattern:** Cat 7, Cat 20

#### F-0007 - `DiscoveryCache.get/set/invalidate` advertise thread safety via `_lock` but never acquire it for the hot path

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 88-157
- **Pattern:** Cat 7

### Category 4 - Ineffective Implementations

#### F-0008 - `ModelDiscovery.get_recommended_model` is `async` but never awaits anything

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 689-751
- **Pattern:** Cat 4

#### F-0009 - `get_recommended_model` silently returns an arbitrary first model on any unknown `task_type`

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 700-751
- **Pattern:** Cat 4

#### F-0010 - `DiscoveryFilter` regex matching uses `pattern.match` (start-anchored)

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 596-628
- **Pattern:** Cat 19

### Category 11 - Persistence / State Issues

#### F-0011 - `DiscoveryCache` stores empty model lists which are then returned as valid cached data

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 106-123, 503-541
- **Pattern:** Cat 11

#### F-0012 - `discover_all(use_cache=False, force_refresh=False)` leaks stale cache to other readers

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 335-470
- **Pattern:** Cat 11

### Category 5 - Error Handling Anti-Patterns (continued)

#### F-0013 - `disconnect_all` aborts the loop on the first provider that raises during disconnect

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 174-188
- **Pattern:** Cat 5, Cat 24

#### F-0014 - `ProviderError` raised inside the registry never carries `provider_name`

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 24-27, 109-114, 161-163, 199-202
- **Pattern:** Cat 5

### Category 7 - Concurrency / Async Issues (continued)

#### F-0015 - Singleton pattern offers no reset/teardown API and no DI of credential_loader

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 235-259
- **Pattern:** Cat 7, Cat 22

### Category 11 - Persistence / State Issues (continued)

#### F-0016 - `disconnect_provider` does not clear `_active_provider` when the active provider is disconnected

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 174-215
- **Pattern:** Cat 11

#### F-0017 - `discover_one` returns `[]` for unconnected providers but does not invalidate cache

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 392-405
- **Pattern:** Cat 11

### Category 4 - DRY Violations

#### F-0018 - `discover_one` and `discover_provider` duplicate the cache-set / new-removed-diff logic verbatim

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 414-435 and 537-552
- **Pattern:** Cat 4

#### F-0019 - `DiscoveryCache.save_to_disk` calls `time.time()` per iteration instead of snapshotting once

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 198-225
- **Pattern:** Cat 4

### Category 11 - Persistence (continued)

#### F-0020 - `DiscoveryCache.load_from_disk` partially overwrites in-memory cache and offers no atomicity

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 244-292
- **Pattern:** Cat 11

#### F-0021 - `discover_all` records error events but never invalidates the now-known-stale cache entry

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 437-467
- **Pattern:** Cat 11

### Category 7 - Concurrency

#### F-0022 - `ProviderRegistry.register/unregister/set_active` mutate shared state without internal locking

- **File:** `src/intellicrack/providers/registry.py`
- **Lines:** 54-85
- **Pattern:** Cat 7

### Category 18 - Public API Bloat

#### F-0023 - `__init__.py` re-exports private TypedDict helpers that have no external consumers

- **File:** `src/intellicrack/providers/__init__.py`
- **Lines:** 14-27, 63-109
- **Pattern:** Cat 18

### Category 5 - Validation Theater

#### F-0024 - `DiscoveryFilter` invalid regex silently degrades to "no regex applied" instead of failing closed

- **File:** `src/intellicrack/providers/discovery.py`
- **Lines:** 596-628
- **Pattern:** Cat 5

# Findings: bridges-sandbox

## Files audited (1)

- src/intellicrack/bridges/sandbox_bridge.py

## Findings

### Category 5 - Error Handling Anti-Patterns

#### F-0001 - `cont()` only catches `SandboxError`; `QMPClient.cont()` can raise other exceptions

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1235-1247
- **Pattern:** Cat 5, Cat 24
- **Why this is non-functional:** `QMPClient.cont()` is an async TCP/JSON-RPC call that can realistically raise `ConnectionError`, `OSError`, `asyncio.TimeoutError`, `json.JSONDecodeError`, or `RuntimeError`. The docstring promises `Raises: ToolError`, but only `SandboxError` is wrapped.

#### F-0002 - Analysis bridge wrappers swallow only `(ValueError, KeyError, TypeError)`; other exceptions escape raw

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1614-1620, 1658-1664, 1711-1717, 1750-1756, 1804-1810
- **Pattern:** Cat 5, Cat 21

#### F-0003 - `detect_behaviors` silently discards bad rules files instead of erroring

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1702-1709
- **Pattern:** Cat 5, Cat 4
- **Why this is non-functional:** Three silent failure modes - missing path, wrong JSON shape, JSONDecodeError uncaught. Also the parameter description says "YAML file", but the loader uses `json.loads`.

### Category 19 - Data Parsing / Format Issues

#### F-0004 - `yara_scan` advertises `enum=["files","memory"]` but performs zero validation

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1548-1581 (vs. tool definition lines 550-557)
- **Pattern:** Cat 19, Cat 8

### Category 9 - Bridge / Tool Integration Failures

#### F-0005 - Bridge reaches into private QEMU sandbox attributes (`_qmp`, `_agent`)

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1236, 1290
- **Pattern:** Cat 9, Cat 24

### Category 13 - Logging / Observability Theater

#### F-0006 - `is_available`, `status`, `list` log `_logger.info("…_started")` on every call

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 701, 1012, 1022
- **Pattern:** Cat 13

### Category 4 - Ineffective / Naive Implementations

#### F-0007 - `get_vnc_port` accesses `instance.sandbox.vnc_port` for any sandbox type without checking VNC support

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1818-1846
- **Pattern:** Cat 4, Cat 21

#### F-0008 - `pcap_start`/`screenshot`/`memory_dump`/`extract_dropped_files`/`anti_evasion` accept any sandbox type without QEMU gating

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1313-1344, 1389-1427, 1429-1466, 1468-1506, 1508-1546
- **Pattern:** Cat 9, Cat 21

### Category 6 - Resource & Lifecycle Issues

#### F-0009 - `_ensure_manager()` silently re-creates the SandboxManager singleton, losing in-flight instance state

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 708-716
- **Pattern:** Cat 6, Cat 11

### Category 11 - Persistence / State Issues

#### F-0010 - `BridgeState` is wired once and never updated; `binary_loaded`/`target_path`/`target_pid`/`last_error` stay frozen

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 674-684, 692
- **Pattern:** Cat 11, Cat 18

### Category 21 - Documentation / Signature Drift

#### F-0011 - Tool-definition `default` values for `time_limit`, `output_path`, `args`, `categories` are absent

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 200-205, 215-219, 247-251, 444-453, 466-472, 506-511, 525-530, 583-589
- **Pattern:** Cat 21

### Category 4 - Ineffective / Naive Implementations (continued)

#### F-0012 - `extract_iocs`/`timeline`/`detect_behaviors`/`detect_c2`/`diff` re-import `intellicrack.sandbox.analysis` on every call

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 44-50, 1601, 1645, 1689, 1737, 1781
- **Pattern:** Cat 4, Cat 6

### Category 5 - Error Handling Anti-Patterns (continued)

#### F-0013 - `cont` returns `success=False` from QMP without raising; "vm_resumed" is logged unconditionally

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1241-1253
- **Pattern:** Cat 5, Cat 2

#### F-0014 - `get_pending_messages` builds `{"type": msg.msg_type, "data": msg.data}` outside the `try` block; AttributeErrors leak past the wrapper

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1295-1311
- **Pattern:** Cat 19, Cat 8

### Category 19 - Data Parsing / Format Issues (continued)

#### F-0015 - `_report_to_dict` emits `list(report.file_changes)` etc. — typed dataclasses, not JSON-serialisable dicts

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 1862-1880
- **Pattern:** Cat 19, Cat 17
- **Why this is non-functional:** When the orchestrator passes the bridge return value through `json.dumps()` to send to an LLM provider, it raises `TypeError: Object of type FileChange is not JSON serializable`.

#### F-0016 - Timestamps in `list()` and `create()` emitted as `isoformat()` without timezone labelling in the schema

- **File:** `src/intellicrack/bridges/sandbox_bridge.py`
- **Lines:** 769-774, 1025-1035
- **Pattern:** Cat 21, Cat 19
