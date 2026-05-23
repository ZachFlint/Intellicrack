# F12 — Silent `except` in `bridges/process.py` (Win32 probes)

## Fix description

10 silent `except` clauses in private helpers swallow `OSError`/`ctypes.ArgumentError`/`struct.error`/`ToolError` without logging. All sit in best-effort probe helpers where the caller has a sentinel return (0, None, "", or a fallback dict), but per §2.2 every exception path must still emit at least a debug breadcrumb.

(Some of these are also covered by F02 `_safe_int_from_str` helper — for `struct.error` PE/CLR parsers. Apply F02 first; for OSError/ctypes paths, use this file.)

## Fix template

Before:

```python
try:
    sehop_mask = _query_token_info(handle, ...)
except (OSError, ctypes.ArgumentError):
    sehop_mask = 0
```

After:

```python
try:
    sehop_mask = _query_token_info(handle, ...)
except (OSError, ctypes.ArgumentError) as exc:
    _logger.debug("sehop_mask_query_failed", pid=target_pid, error=str(exc))
    sehop_mask = 0
```

## Sites to fix

`src/intellicrack/bridges/process.py`:

| Severity | Lines | Function | Suggested event |
|----------|-------|----------|-----------------|
| HIGH | 2813-2814 | `_query_thread_state` | `thread_state_probe_failed`, `tid=tid, error=str(exc), error_type=type(exc).__name__` |
| HIGH | 2888-2889 | `_query_thread_pc_and_state` | `thread_pc_and_state_probe_failed`, `tid=tid, error=str(exc)` |
| HIGH | 3519-3520 | `_parse_type_info_buffer`-region string decoder | `object_type_name_decode_failed`, `offset=str_offset, error=str(exc)` |
| HIGH | 5115-5116 | `get_mitigation_policies` per-policy | `mitigation_policy_query_unsupported`, `policy=name, error=str(exc)` |
| HIGH | 5770-5771 | `get_mitigation_policy` SEHOP options | `sehop_mask_query_failed`, `pid=target_pid, error=str(exc)` |
| HIGH | 5830-5831 | `get_extension_policy` | `extension_policy_query_failed`, `pid=target_pid, error=str(exc)` |
| HIGH | 6461-6462 | `_parse_pe_com_descriptor` | `cor20_pe_descriptor_parse_failed` |
| HIGH | 6516-6517 | `_read_cor20_version` | `cor20_meta_rva_parse_failed`, `base_address=hex(base_address)` |
| HIGH | 6576-6577 | `_read_metadata_version` | `dotnet_metadata_header_parse_failed`, `meta_va=hex(meta_va)` |
| HIGH | 6906-6907 | `_duplicate_job_handle_from_target` | `job_handle_dup_buffer_query_failed`, `target_pid=target_pid` |

Plus LOW finding:

| Severity | Lines | Function | Fix |
|----------|-------|----------|-----|
| LOW | 1407-1408 | `_elevate_debug_privilege` `except ToolError: raise` | Either add `_logger.debug("se_debug_privilege_known_failure")` or restructure to remove the passthrough |

## Acceptance criteria

- [ ] All 10 HIGH silent excepts emit a `_logger.debug(...)` with structured kwargs before the sentinel return
- [ ] Each `as exc` captured where applicable
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
