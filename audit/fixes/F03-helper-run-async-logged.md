# F03 — Bridge invocation entry/exit logging: `_run_async_logged` wrapper

## Fix description

Across UI panels, the pattern is:

```python
self._run_async(self._bridge.some_op(args), on_success=..., on_error=...)
```

Post-call success/failure are usually logged via the callbacks. The **pre-call intent** is almost never logged. Per §2.3, bridge invocations must be logged before AND after.

Closes ~150 MEDIUM findings in one structural change.

## Wrapper template

Add to `src/intellicrack/ui/panels/async_bridge.py` (next to existing `run_bridge_coroutine_async`):

```python
def run_bridge_coroutine_logged(
    coro: Coroutine[Any, Any, T],
    on_success: Callable[[T], None] | None,
    on_error: Callable[[BaseException], None] | None,
    parent: QObject,
    *,
    event: str,
    logger: structlog.stdlib.BoundLogger,
    **context: Any,
) -> None:
    """Run a bridge coroutine with structured entry / success / failure logs.

    Emits ``<event>_started`` before dispatch, ``<event>_succeeded`` after success
    (in addition to invoking on_success), and ``<event>_failed`` on failure (in
    addition to invoking on_error). When the caller-supplied ``on_error`` is None,
    the failure log replaces it.

    Args:
        coro: Bridge coroutine to execute.
        on_success: Optional caller success callback.
        on_error: Optional caller error callback; if None, only the failure log fires.
        parent: Qt parent for the worker thread lifetime.
        event: Snake_case base event name (e.g. "ghidra_rename_function").
        logger: Module-level _logger to emit on.
        **context: Structured kwargs included in every emitted log.
    """
    logger.info(f"{event}_started", **context)

    def _logged_success(result: T) -> None:
        logger.info(f"{event}_succeeded", **context)
        if on_success is not None:
            on_success(result)

    def _logged_error(exc: BaseException) -> None:
        logger.warning(
            f"{event}_failed",
            error=str(exc),
            error_type=type(exc).__name__,
            **context,
        )
        if on_error is not None:
            on_error(exc)

    run_bridge_coroutine_async(coro, _logged_success, _logged_error, parent)
```

Then every call site becomes:

```python
run_bridge_coroutine_logged(
    self._bridge.rename_function(addr, name),
    on_success=self._on_rename_success,
    on_error=self._on_rename_error,
    parent=self,
    event="ghidra_rename_function",
    logger=_logger,
    address=hex(addr),
    new_name=name,
)
```

## Affected files (with approximate site counts)

| File | Sites |
|------|------:|
| `src/intellicrack/ui/panels/process_panel/_memory_tab.py` | ~7 |
| `src/intellicrack/ui/panels/process_panel/_modules_tab.py` | ~7 |
| `src/intellicrack/ui/panels/process_panel/_threads_tab.py` | ~9 |
| `src/intellicrack/ui/panels/process_panel/_process_tab.py` | ~9 |
| `src/intellicrack/ui/panels/process_panel/_system_tab.py` | ~14 |
| `src/intellicrack/ui/panels/frida_panel.py` | ~25 |
| `src/intellicrack/ui/panels/ghidra_panel.py` | ~50 |
| `src/intellicrack/ui/panels/x64dbg_panel.py` | ~40 |
| `src/intellicrack/ui/panels/sandbox_panel.py` | ~25 |
| `src/intellicrack/ui/panels/cutter_panel.py` | ~10 |
| `src/intellicrack/ui/panels/cutter_tabs.py` | ~10 |
| `src/intellicrack/ui/panels/hex_editor/_highlighting.py` | already symmetric — pattern reference |
| `src/intellicrack/ui/panels/hex_editor/_yara.py` | 2 |
| `src/intellicrack/ui/panels/hex_editor/_search.py` | 2 |
| `src/intellicrack/ui/panels/hex_editor/_signatures.py` | 1 |
| `src/intellicrack/ui/panels/hex_editor/_data_inspector.py` | 2 |
| `src/intellicrack/ui/panels/hex_editor/_sections.py` | 1 |
| `src/intellicrack/ui/panels/hex_editor/_disassembly.py` | 1 |
| **Total** | **~150** |

Specific line numbers for each panel are enumerated in the per-shard reports (`shard-16-*`, `shard-17-*`, `shard-18-*`, `shard-19-*`, `shard-20-*`). The wrapper is uniform, so the rollout is mostly mechanical replacement of `run_bridge_coroutine_async(...)` with `run_bridge_coroutine_logged(...)`.

## Specific high-value sites worth manual review

Sites where the bridge call is a **state mutation** (§2.4) deserve `_logger.info` level (not debug):

- `frida_panel.py`: write_memory L1687, allocate_memory L1697, protect_memory L1806, call_function L2142, spawn L1176, replace_function L1274, intercept_return L1248, enable/disable_child_gating L2152/L2162, enable_crash_reporting L2223
- `ghidra_panel.py`: rename_function L1918, add_comment L1930, set_function_variable_type L1944, delete_function L2011, set_color L1998, edit_function_signature L2038, define_structure L2380, apply_structure_at L2427, create_memory_block L2567, set_program_metadata L2668, set_label L2258, create_bookmark L2318, set_data_type L1048, create_function L1844, set_decompiler_options L3133, configure_analysis L3163, add_external_function L3055, create_overlay_space L1576, create_namespace L2934, create_equate L2983, import_debug_info L1511, execute_script L3074, execute_script_with_params L3096
- `x64dbg_panel.py`: run/pause/stop/step (L1120/L1148/L1177/L1205/L1217/L1229), set_register L1564, set_ip L2013, run_to L1962, execute_til_return L1972, skip_instruction L1982, save_database L2032, load_database L2042, set_watchpoint L2068, remove_watchpoint L2099, dump_memory_to_file L2285/L2389, allocate_memory L2304, free_memory L2322, set_breakpoint_on_api L2362, write_memory L2409, patch_instruction L2428, nop_range L2452, suspend_thread L2473, resume_thread L2494, switch_thread L2515, set_exception_config L2547, set_label L2210, set_comment L2229, spawn L1928, detach L1906
- `sandbox_panel.py`: snapshot_create L978, snapshot_restore L1040, snapshot_delete L1561, screenshot L1082, pcap_start/stop L1115, memory_dump L1185, extract_files L1218, yara_scan L1251, extract_iocs L1293, timeline L1340, detect_behaviors L1386, copy_to L1434, copy_from L1483, cont L1532, execute L1604, get_vnc_port L1741

## Acceptance criteria

- [ ] Wrapper added to `async_bridge.py` with full type hints + docstring
- [ ] Rolled out across all panel files (use `rg "run_bridge_coroutine_async\("` to find call sites)
- [ ] State-mutation sites use `info` level; refresh/query sites use `debug` level
- [ ] Existing `_on_*_success` / `_on_*_error` handlers retained (called from inside the wrapper's logged callbacks)
- [ ] `_threads_tab.py` `None, None` callbacks replaced with the wrapper (see F27)
- [ ] `ruff check` clean
- [ ] `basedpyright` clean
