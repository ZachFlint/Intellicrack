# Shard 03 — bridges/process.py (Windows process bridge)

- **Files audited**: 1
- **Total LOC**: 7823
- **Generated**: 2026-05-22T00:00:00Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 10    |
| MEDIUM   | 52    |
| LOW      | 6     |

- Files missing module-level `_logger`: 0
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 1 (10 occurrences within the single file)

## Findings by file

### src/intellicrack/bridges/process.py — LOC 7823

**Logger status**: `module-level _logger` (correct canonical pattern: `_logger = get_logger(__name__)` at L176)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L162)

**Class**: `ProcessBridge(ToolBridgeBase)` — large Windows-native process-management bridge using ctypes/Win32. No subprocess/network/registry-via-winreg/file-write/AI calls. Heavy ctypes.windll/WinDLL usage (kernel32, ntdll, psapi, advapi32, user32, dbghelp).

**Findings**:

#### HIGH severity — silent `except` clauses (no log call)

- **[HIGH] L2813-2814** — `except (OSError, ctypes.ArgumentError): pass` inside `_query_thread_state`. Swallows kernel/ctypes errors from `NtQueryInformationThread` / `SuspendThread` / `GetThreadContext`. Fix: `_logger.debug("thread_state_probe_failed", tid=tid, error=str(exc), error_type=type(exc).__name__)` before `pass`.
- **[HIGH] L2888-2889** — `except (OSError, ctypes.ArgumentError): pass` inside `_query_thread_pc_and_state`. Same pattern as above; loses diagnostic context for the combined PC+state probe. Fix: add `_logger.debug("thread_pc_and_state_probe_failed", tid=tid, error=str(exc))` before `pass`.
- **[HIGH] L3519-3520** — `except (ValueError, OSError, ctypes.ArgumentError): return ""` inside `_parse_type_info_buffer`-region string decoder. No log on parse failure. Fix: `_logger.debug("object_type_name_decode_failed", offset=str_offset, error=str(exc))` before `return ""`.
- **[HIGH] L5115-5116** — `except (OSError, ctypes.ArgumentError): policies[name] = {"enabled": False, "error": "not supported"}` inside `get_mitigation_policies` loop. Silent fallback into result dict — no diagnostic trail. Fix: `_logger.debug("mitigation_policy_query_unsupported", policy=name, error=str(exc))` before the dict assignment.
- **[HIGH] L5770-5771** — `except (OSError, ctypes.ArgumentError): sehop_mask = 0` inside `get_mitigation_policy`. No log on SEHOP options-mask query failure. Fix: `_logger.debug("sehop_mask_query_failed", pid=target_pid, error=str(exc))` before assignment.
- **[HIGH] L5830-5831** — `except (OSError, ctypes.ArgumentError): disabled = False` inside `get_extension_policy`. Silent fallback. Fix: `_logger.debug("extension_policy_query_failed", pid=target_pid, error=str(exc))`.
- **[HIGH] L6461-6462** — `except struct.error: return None` inside `_parse_pe_com_descriptor`. No log on COM-descriptor parse failure. Fix: `_logger.debug("cor20_pe_descriptor_parse_failed")`.
- **[HIGH] L6516-6517** — `except struct.error: return None` inside `_read_cor20_version`. No log on CLR meta-RVA parse failure. Fix: `_logger.debug("cor20_meta_rva_parse_failed", base_address=hex(base_address))`.
- **[HIGH] L6576-6577** — `except struct.error: return None` inside `_read_metadata_version`. No log on .NET metadata header parse failure. Fix: `_logger.debug("dotnet_metadata_header_parse_failed", meta_va=hex(meta_va))`.
- **[HIGH] L6906-6907** — `except ToolError: return None` inside `_duplicate_job_handle_from_target`. Silently swallows a `ToolError` raised by `_query_extended_handles_buffer()` (a bridge-internal call). Fix: `_logger.debug("job_handle_dup_buffer_query_failed", target_pid=target_pid)` before `return None`.

#### MEDIUM severity — missing entry/exit logging for public async methods

The bridge consistently emits an **entry** debug log on most public methods (`_logger.debug("<method>_started", ...)`) but rarely emits an explicit **exit** log on the success path. Per §2.1, public methods that perform real work must log both entry AND exit with a result summary. The following methods perform non-trivial work (Win32 calls, PE/PEB/TEB parsing, registry walks, etc.) and are missing exit-side logging:

- **[MEDIUM] L1538-1592** — `list_processes` — entry log only at L1553; no exit log with count.
- **[MEDIUM] L1594-1646** — `list_processes_detailed` — entry log at L1611; no exit log with `len(results)`.
- **[MEDIUM] L1648-1682** — `get_process_memory_mb` — entry log at L1657; no exit log on success or returned MB value.
- **[MEDIUM] L1684-1725** — `detect_architecture` — entry log at L1703; no exit log with detected arch string.
- **[MEDIUM] L1921-1969** — `open_process` — no entry log at all (`_logger.info("process_opened", ...)` only at exit L1968 happens AFTER attaching the process; method does real work but lacks pre-call log).
- **[MEDIUM] L1971-1989** — `close` — no entry log; `process_handle_closed` info log only when handle present.
- **[MEDIUM] L1991-2030** — `terminate` — no entry log; only success/failure log.
- **[MEDIUM] L2032-2071** — `suspend` — no entry log.
- **[MEDIUM] L2073-2112** — `resume` — no entry log.
- **[MEDIUM] L2118-2142** — `read_memory` — entry log at L2141; no exit log with bytes-read count or success indication.
- **[MEDIUM] L2144-2175** — `write_memory` — no entry log; exit log only on success.
- **[MEDIUM] L2177-2211** — `allocate` — no entry log; exit log only.
- **[MEDIUM] L2213-2241** — `free` — no entry log; exit log only.
- **[MEDIUM] L2243-2290** — `protect` — no entry log; exit log only.
- **[MEDIUM] L2292-2353** — `get_memory_map` — entry log at L2304; no exit log with region count.
- **[MEDIUM] L2355-2425** — `search_pattern` — entry log at L2379; no exit log with match count.
- **[MEDIUM] L2571-2640** — `get_modules` — entry log at L2583; no exit log with module count.
- **[MEDIUM] L2642-2701** — `get_threads` — entry log at L2658; no exit log with thread count.
- **[MEDIUM] L3082-3104** — `get_process_info` — entry log at L3091; no exit log with success/not-found.
- **[MEDIUM] L3138-3183** — `get_token_privileges` — entry log at L3150; no exit log with privilege count.
- **[MEDIUM] L3268-3349** — `adjust_token_privilege` — no entry log; exit log only.
- **[MEDIUM] L3404-3433** — `get_handles` — entry log at L3424; no exit log with handle count.
- **[MEDIUM] L3611-3638** — `enum_handles` — entry log at L3632; no exit log.
- **[MEDIUM] L3697-3765** — `get_windows` — entry log at L3709; no exit log with window count.
- **[MEDIUM] L3771-…** — `list_services` — entry log at L3783; no exit log.
- **[MEDIUM] L3921-3978** — `read_peb` — entry log at L3946; no exit log with PEB summary.
- **[MEDIUM] L4217-4302** — `read_teb` — entry log at L4239; no exit log with TEB summary.
- **[MEDIUM] L4357-4403** — `get_heaps` — entry log at L4369; no exit log with heap count.
- **[MEDIUM] L4409-4519** — `get_thread_context` — entry log at L4421; no exit log on success.
- **[MEDIUM] L4521-4622** — `set_thread_context` — no entry log; exit log at L4617 only.
- **[MEDIUM] L4628-4688** — `stack_walk` — entry log at L4650; no exit log with frame count.
- **[MEDIUM] L4990-5050** — `get_seh_chain` — no entry log seen; no exit log with chain depth.
- **[MEDIUM] L5056-5121** — `get_mitigation_policies` — entry log at L5068; no exit log with policy summary.
- **[MEDIUM] L5182-5224** — `enumerate_system_processes` — entry log at L5192; no exit log with count.
- **[MEDIUM] L5226-5270** — `enumerate_handles` — entry log at L5243; no exit log with count.
- **[MEDIUM] L5272-5339** — `enumerate_heaps` — entry log at L5289; no exit log with count.
- **[MEDIUM] L5341-5403** — `enumerate_services` — entry log at L5354; no exit log with count.
- **[MEDIUM] L5405-5451** — `time_thread_wait` — entry log at L5424; no exit log with result/elapsed.
- **[MEDIUM] L5453-5514** — `duplicate_token` — entry log at L5471; no exit log with duplicated handle.
- **[MEDIUM] L5516-5577** — `remove_privilege` — entry log at L5532; no exit log with outcome.
- **[MEDIUM] L5579-5621** — `decommit_memory` — entry log at L5597; success log only via warning on failure (L5617); no info-level success log.
- **[MEDIUM] L5623-5671** — `read_registry` — entry log at L5646; no exit log with value type/size. (Registry read is an external-resource call per §2.3.)
- **[MEDIUM] L5673-5716** — `detect_kernel_debugger` — entry log at L5688; no exit log with result.
- **[MEDIUM] L5718-5783** — `get_mitigation_policy` — entry log at L5734; no exit log.
- **[MEDIUM] L5785-5835** — `get_extension_policy` — entry log at L5797; no exit log.
- **[MEDIUM] L5841-5890** — `get_environment` — entry log at L5853; no exit log with var count.
- **[MEDIUM] L6114-6134** — `enumerate_com_servers` — entry log at L6128; no exit log with COM-server count. (Registry walk is external-resource per §2.3.)
- **[MEDIUM] L6307-…** — `detect_dotnet` — no exit log with managed/version result. (Performs PE memory parsing + module enumeration.)
- **[MEDIUM] L6710-6768** — `get_job_info` — entry log at L6735; no exit log with in_job result.
- **[MEDIUM] L7130-7176** — `get_gui_resources` — entry log at L7142; no exit log with object counts.
- **[MEDIUM] L7218-7255** — `reg_read_value` — entry log at L7231; no exit log with type/data. (Registry read is external-resource per §2.3.)
- **[MEDIUM] L7257-7306** — `reg_enum_keys` — entry log at L7269; no exit log with key count. (Registry walk.)
- **[MEDIUM] L7308-7357** — `reg_enum_values` — entry log at L7320; no exit log with value count. (Registry walk.)
- **[MEDIUM] L7572-7618** — `get_tls_values` — entry log at L7588; no exit log with slot count.
- **[MEDIUM] L7662-7678** — `get_fiber_data` — entry log at L7671; no exit log.
- **[MEDIUM] L7684-7735** — `query_system_info` — entry log at L7698; no exit log with return-length / status.

(Note: `pipe_connect`, `pipe_read`, `pipe_write`, `pipe_close`, `device_open`, `device_ioctl`, `device_close`, `create_section`, `map_section`, `unmap_section`, `inject_dll`, `read_memory` (info level), `write_memory`, `allocate`, `free`, `protect` DO emit success info-level logs and are not flagged for missing exit logging — the entry-only methods above are the gap.)

#### LOW severity

- **[LOW] L1407-1408** — `except ToolError: raise` in `_elevate_debug_privilege` re-raises without any log. The pattern is intentional (passthrough of an already-known ToolError raised in the inner block), but per §2.2 every `except` clause must log. Marked LOW because the inner `raise ToolError(msg)` at L1401 is the original logical event; consider adding `_logger.debug("se_debug_privilege_known_failure")` for consistency, or restructure to remove the bare passthrough.
- **[LOW] L1483-1500** — `list` dispatch shim delegates to `list_processes` with no log; acceptable per §2.1 (simple delegation) but flagged LOW because the shim is the public LLM-tool surface (`process.list`) and an entry breadcrumb at the shim layer would improve traceability of LLM invocations.
- **[LOW] L1502-1517** — `list_detailed` dispatch shim — same as `list` above.
- **[LOW] L1519-1536** — `open` dispatch shim — same as above.
- **[LOW] L3110-3117** — `add_privileges_changed_callback` — public method, no log on registration (a state mutation per §2.4: "registration of tools/providers"). Consider `_logger.debug("privileges_callback_registered", callback=callback.__qualname__)`.
- **[LOW] L3119-3128** — `remove_privileges_changed_callback` — same as above; only logs on the "not registered" debug path.

## Aggregate notes

- **Logger pattern is canonical and consistent.** Module imports `get_logger` (L162) and defines `_logger = get_logger(__name__)` (L176). 177 logger call-sites across the file. No stdlib `logging` usage. No `print()` runtime output. No `contextlib.suppress`. No `# noqa` / `# type: ignore` suppressions. No f-string / `%` / `.format()` formatting inside log messages — every observed log call uses structured kwargs. This file is a strong reference for the canonical pattern.
- **Primary gap is exit logging.** The file establishes a consistent `_logger.debug("<method>_started", ...)` entry pattern (~50+ public methods) but rarely follows with an explicit success-exit log carrying the result summary. Methods that have side effects (open, close, terminate, suspend, resume, allocate, free, protect, inject_dll, pipe_*, device_*, create_section, unmap_section, write_memory) DO emit `_logger.info("<event>", ...)` on success — those are fine. The gap is in read/query methods that return aggregates (lists, dicts) without a follow-up log of the cardinality of the result.
- **Secondary gap is silent error paths in low-level helpers.** Ten `except` blocks swallow OSError / ctypes.ArgumentError / struct.error / ToolError without logging (see HIGH section). All sit in private helpers where the operation is best-effort and the caller has a sentinel return (0, None, "", or a fallback dict), but per §2.2 every exception path must still emit at least a debug-level breadcrumb. The fix in each case is a one-line `_logger.debug(...)` before the swallow.
- **External-resource calls (registry, COM, kernel handle table) consistently lack exit logging.** `reg_read_value`, `reg_enum_keys`, `reg_enum_values`, `read_registry`, `enumerate_com_servers`, `enum_handles`, `enumerate_handles`, `enumerate_services` all read external state but do not log the resulting cardinality. Per §2.3 these calls should have entry AND exit logs.
- **No subprocess / network / HTTP / file-write / `print` / `contextlib.suppress` / stdlib-logging hits.** Most of the §2.3 "external call" categories are not exercised by this bridge — it operates entirely through ctypes/Win32 and the registry. The Win32/ctypes call sites are largely well-instrumented around success/failure of the kernel call (consistent `_logger.error` + `raise ToolError` pattern on `GetLastError`).
- **`f"..."` use in `ToolError(msg)` construction is acceptable** — those build the exception message string itself, they are not the first arg to a logger call. Several appear (e.g., L1570, L2067, L2108, L3070, L3399, L3683, L3681, L5209, L5432, L5447, L5698, L5712, L7253, L7803) and are NOT logging-formatting violations.
- **File size:** 7823 LOC, one class. The audit required reading in chunks of ~300 lines; recommend a future split (e.g., separate modules for token/privilege, registry, mitigation, COM/.NET, section/TLS) to keep the public surface manageable. Not a logging concern per se.
