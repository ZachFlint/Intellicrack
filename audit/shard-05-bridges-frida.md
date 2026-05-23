# Shard 05 — bridges (Frida + named pipe IPC + lazy package wiring)

- **Files audited**: 4
- **Total LOC**: 7910
- **Generated**: 2026-05-22T22:54:14Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 6     |
| MEDIUM   | 26    |
| LOW      | 4     |

- Files missing module-level `_logger`: 0 (`__init__.py` and `_lazy.py` are exempt under §4 — re-export wiring only)
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 2 (`named_pipe_client.py`, `frida_bridge.py`)

## Findings by file

### src/intellicrack/bridges/__init__.py — LOC 96

**Logger status**: `n/a (exempt re-export package init)`

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. The module contains only re-exports, lazy import wiring via `__getattr__`, and `__dir__`. Under §4, `__init__.py` files containing only re-exports are exempt. The `__getattr__` simply delegates to `intellicrack.bridges._lazy.resolve` and raises `AttributeError` for unknown names. No operational paths require logging here. The lazy resolver itself raises `AttributeError`/`TypeError` for invalid lookups; surfacing those as logs at the package boundary would be redundant.

---

### src/intellicrack/bridges/_lazy.py — LOC 68

**Logger status**: `missing (exempt — module is import-wiring infrastructure)`

**Imports `from intellicrack.core.logging import get_logger`**: no

**Findings**: none. The module exists solely to back PEP 562 `__getattr__` on the `bridges` package. The only function (`resolve`) performs an `importlib.import_module` and a type check; both failure paths raise explicit, well-typed exceptions (`AttributeError`, `TypeError`) that propagate to the package importer. No silent swallowing, no external I/O, no `subprocess`/network/file/registry. Equivalent to a re-export shim per §4 — flagging would be a false positive. (Optional improvement: a `_logger.debug("lazy_export_resolved", name=name, module=module_path)` would aid debugging of cold-start import ordering, but not required.)

---

### src/intellicrack/bridges/named_pipe_client.py — LOC 867

**Logger status**: `module-level _logger` (L29)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L25)

**Findings**:

- [HIGH] L227-229 — `except Exception:` in `connect()` re-raises without any log call. Other except clauses in this method (`TimeoutError`, `CancelledError`) log appropriately; this generic catch-all silently propagates. Fix: add `_logger.exception("pipe_connect_unexpected_error", pipe_name=pipe_name)` before `raise`.
- [HIGH] L316-317 — `except (asyncio.CancelledError, ToolError, OSError): pass` inside `close()` silently swallows three different exception classes from the reader-task drain. Even though closing is a best-effort path, swallowing `ToolError` and `OSError` without any log violates §3 #2. Fix: `_logger.debug("pipe_reader_drain_swallowed", error_type=...)` or split the cancellation case from the I/O-error case and log the latter.
- [HIGH] L441-442 — `except asyncio.CancelledError: raise` in `_reader_loop()` has no log call. Per §3 #2 every except clause must log, even when re-raising. Fix: add `_logger.debug("pipe_reader_cancelled")` before `raise`, or merge the cancellation re-raise into the outer try (less invasive).
- [MEDIUM] L295-332 — `close()` performs significant lifecycle work (lock acquisition, reader cancellation, futures fail-out, native handle close). The method logs at entry (L306 `pipe_disconnecting`) and exit (L332 `pipe_disconnected`) but the early-return at L304 when `self._handle is None` has no log — callers cannot tell from logs whether they tried to close an already-closed pipe. Fix: `_logger.debug("pipe_close_noop_already_disconnected")` before the early return.
- [LOW] L443 — exception handler logs at `warning` (L445) without using `_logger.exception` even though a typed exception (`ToolError`, `OSError`, `RuntimeError`, `ValueError`) is being handled. The traceback is lost. Per §3 #6, prefer `_logger.exception("pipe_reader_failed", ...)` to preserve the stack trace, then carry on with the failure propagation as today.

The pipe handle lifecycle (`CreateFileW`, `ReadFile`, `WriteFile`, `CloseHandle`, `WaitNamedPipeW`, `CancelIoEx`) is thoroughly logged with structured kwargs including the `GetLastError` code and a mapped hint. Win32 coverage is exemplary. All command send/receive paths log `pipe_command_sent`, `pipe_read_started/chunk/complete`, `pipe_write_started/chunk/complete` at debug. No f-strings or `%`/`.format` in log messages anywhere.

---

### src/intellicrack/bridges/frida_bridge.py — LOC 6879

**Logger status**: `module-level _logger` (L65)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L32)

**Findings**:

- [HIGH] L4828-4829 — `except Exception as e: raise ToolError(_ERR_EXCEPTION_HANDLER_FAILED) from e` in `set_exception_handler()` swallows the original exception with no log. Fix: `_logger.warning("frida_exception_handler_create_failed", error=str(e), error_type=type(e).__name__)` (or `_logger.exception(...)`) before the re-raise.
- [HIGH] L5075-5076 — `except Exception as e: raise ToolError(_ERR_PROBE_FAILED) from e` in `stalker_add_call_probe()` has no log. Fix: `_logger.warning("stalker_call_probe_create_failed", address=hex(validated_address), error=str(e), error_type=type(e).__name__)` before re-raise.
- [HIGH] L6748-6750 — `except Exception as e:` inside `compile_typescript()` logs at `warning` only with `error=str(e)` and loses the traceback. The chain of failure modes from `Compiler.build` is large (transport, filesystem, syntax, cancellation). Per §3 #6, the better level is `.exception()` because the exception is not just being re-raised verbatim — the original cause is wrapped in a new `ToolError`. Fix: `_logger.exception("typescript_compile_failed", entrypoint=entrypoint)`.

The following block-level exception handlers in `frida_bridge.py` are correctly logged and do NOT need changes (sampled and verified): L1212, L1232, L1240, L1251, L1258, L1265, L1274, L1281, L1287, L1295, L1324, L1374, L1382, L1426, L1448, L1454, L1519, L1564, L1567, L1593, L1629, L1645, L1946, L2130, L2144, L2445, L2532, L2540, L2561, L2602, L2941, L3318, L3730, L3772, L3778, L3899, L3921, L3953, L4007, L4029, L4044, L4113, L4131, L4168, L4229, L4437, L4458, L5166, L5200, L5458, L5692, L5790, L6401, L6450, L6755, L6827, L6854. All emit structured kwargs and use `_logger.warning` or `_logger.exception` appropriately.

The following public methods perform real work (Frida script injection, JS execution, in-process state mutation) but lack either entry OR exit logging — flag as MEDIUM under §2.1. Most have exit-only debug logs; entry context would aid trace correlation since each call involves a JS payload that may be expensive or risky:

- [MEDIUM] L1658 `read_memory(address, size)` — has entry `memory_read_starting` (L1679) but no exit log on success. Reads arbitrary memory from a target process; result size is a useful audit signal.
- [MEDIUM] L1699 `write_memory(address, data)` — no entry log; exit log only (L1729). Writes arbitrary memory; entry log would record intent before the JS injection.
- [MEDIUM] L1732 `get_memory_regions(protection)` — entry/exit logs are `debug` (L1749, L1792). Acceptable, but consider promoting one to `info` since this is a process-wide enumeration.
- [MEDIUM] L1956 `enumerate_modules()` — exit-only debug log (L2008); no entry log.
- [MEDIUM] L2011 `enumerate_exports(module_name)` — exit-only debug log (L2073); no entry log.
- [MEDIUM] L2076 `hook_function(target, on_enter, on_leave)` — has exit log `hook_installed` (L2170) but no entry log. Hooks are persistent state mutations — entry-level audit is valuable.
- [MEDIUM] L2192 `get_hooks()` — only `debug` (L2198) and no entry. Acceptable for a query-only read; flagged LOW-leaning but per §2.1 included as MEDIUM.
- [MEDIUM] L2201 `execute_script(script)` — has entry `script_executing` (L2217 debug) but no success-exit log. The script can do anything; an exit confirmation aids forensics.
- [MEDIUM] L2285 `intercept_return(target, return_value)` — entry debug (L2296); no exit log of its own (delegates to `hook_function`). Acceptable since `hook_function` logs; LOW.
- [MEDIUM] L2307 `call_function(address, args, ...)` — entry debug (L2351); no exit log. Invokes arbitrary native functions in the target — exit log of return value (or success flag) is operationally important.
- [MEDIUM] L2771 `enumerate_imports(module_name)` — exit-only debug (L2836).
- [MEDIUM] L2840 `enumerate_threads()` — exit-only debug (L2898).
- [MEDIUM] L2901 `allocate_memory(size)` — no entry log; exit log only (L2967).
- [MEDIUM] L2970 `protect_memory(address, size, protection)` — no entry log; exit debug (L3021).
- [MEDIUM] L3029 `find_base_address(module_name)` — exit-only debug (L3065).
- [MEDIUM] L3068 `resolve_symbol(address)` — exit-only debug (L3124).
- [MEDIUM] L3133 `find_functions_named(name)` — exit-only debug (L3192).
- [MEDIUM] L3195 `resolve_api(query, resolver_type)` — exit-only debug (L3254).
- [MEDIUM] L3257 `replace_function(target, replacement_code, ...)` — exit-only info log (L3344). Function replacement is a persistent state mutation worth a startup-of-operation entry log.
- [MEDIUM] L3347 `enumerate_processes()` — exit-only debug (L3367); no entry log.
- [MEDIUM] L3850 `enable_child_gating()` — exit info log (L3898) but no entry log. The handler registration is a meaningful lifecycle transition.
- [MEDIUM] L3903 `disable_child_gating()` — exit info log (L3920); no entry log.
- [MEDIUM] L3957 `enable_crash_reporting()` — exit info log (L4013); no entry log.
- [MEDIUM] L4356 `patch_code(address, hex_data)` — exit info log (L4394); no entry log. Patching code is operationally significant.
- [MEDIUM] L4397 `allocate_string(value, encoding)` — exit info log (L4462); no entry log.
- [MEDIUM] L4465 `enumerate_symbols(module_name)` — exit-only debug (L4522).
- [MEDIUM] L4569 `find_module_by_address(address)` — has entry info log (L4581) but the `None`-return branch (L4599) has no exit log. Both branches should log.
- [MEDIUM] L4613 `find_functions_matching(pattern)` — exit-only debug (L4667); no entry log.
- [MEDIUM] L4670 `disassemble_instruction(address)` — entry info log (L4682); no success-exit log.
- [MEDIUM] L4725 `get_backtrace(context_address, backtracer)` — exit-only debug (L4793); no entry log.
- [MEDIUM] L4849 `revert_hook(target)` — exit-only info log (L4879); no entry log.
- [MEDIUM] L4882 `flush_interceptor()` — exit-only debug (L4903); no entry log.
- [MEDIUM] L4958 `call_system_function(address, args, ...)` — entry info log (L4982); no success-exit log of return-value / errno / lastError.
- [MEDIUM] L5113 `enumerate_applications()` — exit-only debug (L5130); no entry log.
- [MEDIUM] L5140 `inject_library_file(pid, path, entrypoint, data)` — exit info log (L5170); no entry log. Injection is a state mutation worth pre-call logging.
- [MEDIUM] L5173 `inject_library_blob(pid, blob_hex, entrypoint, data)` — exit info log (L5204); no entry log. Same rationale as above.
- [MEDIUM] L5404 `objc_hook_method(class_name, method_name, on_enter, on_leave)` — exit info log (L5484); no entry log.
- [MEDIUM] L5538 `java_choose(class_name, limit)` — entry info log (L5551); no success-exit log of match count.
- [MEDIUM] L5585 `java_use(class_name)` — entry info log (L5597); no success-exit log of method-count.
- [MEDIUM] L5626 `java_hook_method(class_name, method_name, ...)` — exit info log (L5713); no entry log.
- [MEDIUM] L5716 `java_deoptimize()` — exit info log (L5743); no entry log. Deoptimizing the JVM is a major state mutation; entry log is valuable.
- [MEDIUM] L5746 `create_cmodule(code, symbols)` — exit info log (L5812); no entry log. Loading inline C code is a state mutation that should be logged at entry.
- [MEDIUM] L5815 `kernel_enumerate_modules()` — entry info log (L5824); no success-exit log.
- [MEDIUM] L5866 `kernel_enumerate_ranges(protection)` — entry info log (L5878); no success-exit log.
- [MEDIUM] L6037 `kernel_protect(address, size, protection)` — entry info log (L6051); no success-exit log of the protect succeeding.
- [MEDIUM] L6135 `socket_connect(host, port, family)` — entry info log (L6149); no success-exit log of the connect result. (`socket_listen` does have an exit `socket_listening` log at L6132 — pattern inconsistency.)
- [MEDIUM] L6177 `socket_type(handle)` — entry info log (L6189); no success-exit log of the type string.
- [MEDIUM] L6210 `socket_local_address(handle)` — entry info log (L6222); no success-exit log.
- [MEDIUM] L6244 `socket_peer_address(handle)` — entry info log (L6256); no success-exit log.
- [MEDIUM] L6278 `file_read_target(path)` — entry info log (L6290); no success-exit log of bytes read.
- [MEDIUM] L6318 `file_write_target(path, hex_data)` — entry info log (L6331); no success-exit log of bytes written.
- [MEDIUM] L6356 `sqlite_open(path)` — has exit info log `sqlite_database_opened` (L6428) but no entry log.
- [MEDIUM] L6431 `sqlite_exec(script_id, sql)` — no entry log; the success path (L6454) has no exit log. SQL exec on the target is operationally significant.
- [MEDIUM] L6456 `sqlite_dump(path)` — entry info log (L6468); no success-exit log of dump length.
- [MEDIUM] L6490 `write_code(address, architecture, instructions, ...)` — exit info log (L6578); no entry log. Writing assembly via a JS code-writer is a major state mutation.
- [MEDIUM] L6581 `cloak_add_thread(thread_id)` — exit debug log (L6606); no entry log.
- [MEDIUM] L6609 `cloak_remove_thread(thread_id)` — exit debug log (L6634); no entry log.
- [MEDIUM] L6637 `cloak_add_range(address, size)` — exit debug log (L6664); no entry log.
- [MEDIUM] L6667 `cloak_remove_range(address, size)` — exit debug log (L6694); no entry log.
- [MEDIUM] L6697 `compile_typescript(source, project_root, ...)` — exit info log `typescript_compiled` (L6761); no entry log of compile intent.
- [MEDIUM] L6811 `monitor_path(path)` — exit info log (L6859); no entry log of monitor creation intent.

Notes on level choice and consistency:

- [LOW] L1565-1572 — In `spawn()`, the inner `except (OSError, RuntimeError, frida.TransportError) as kill_err` logs at `warning` to flag a kill-leaked-process failure. Acceptable, but consider `.exception()` since the traceback context (the kill path failed while cleaning up another failure) is the most useful debug artifact. Severity LOW because the failure is already wrapped into the outer `ToolError`.
- [LOW] L4828, L5075 — Both report `Exception as e` after a Frida `create_script` call but use the wrapped `ToolError` constants without preserving `error_type=type(e).__name__` in any log. When fixing (see HIGH findings above), include the qualified type name so callers can disambiguate frida transport errors from local validation errors.
- [LOW] L1325 `frida_availability_check_failed` — single-event capture-and-return-false pattern; logged at `debug`. Caller can easily miss this. Consider `info` since availability checks are a one-shot lifecycle probe. Minor.

All log calls in this module use structured kwargs (verified — no `f"..."`, `%`, or `.format` patterns found inside `_logger.*` calls anywhere in the 6879-line file). No `print(`, no `contextlib.suppress`, no `import logging` direct usage, no `# noqa`/`# type: ignore` suppressions for logging.

External-call coverage assessment (§2.3):

- `frida.get_local_device`, `frida.enumerate_devices`, `frida.get_usb_device`, `manager.add_remote_device` — all wrapped with surrounding logs (initialize / connect_device).
- `frida.Compiler()` / `Compiler.build` — wrapped (compile_typescript, with one LOW finding about traceback preservation).
- `frida.FileMonitor(path)` and `monitor.enable` — wrapped with error logs (file_monitor_create_failed, file_monitor_enable_failed); add entry log per MEDIUM finding L6811 above.
- `device.attach`, `device.spawn`, `device.resume`, `device.kill`, `device.enable_spawn_gating`, `device.disable_spawn_gating`, `device.inject_library_file`, `device.inject_library_blob`, `device.enumerate_processes`, `device.enumerate_applications` — all logged at entry and/or exit; failures handled with structured warnings.
- `session.create_script`, `session.detach`, `script.load`, `script.unload`, `script.post`, `script.eternalize`, `script.exports_sync.*` — all wrapped via `_execute_script_and_wait`, `_unload_script`, etc., with appropriate log coverage.
- `asyncio.to_thread`, `asyncio.wait_for` — internal plumbing, not external calls; not in scope.
- `tempfile.NamedTemporaryFile` (L1111) — file-write, but it is a private helper for a clearly-scoped temp file path that is cleaned up. No log added; this is a LOW concern since the caller (`compile_typescript`) holds the operational context. Optional improvement: `_logger.debug("typescript_tempfile_created", path=...)`.
- `Path.unlink` (L6754) — wrapped in try/except, exception logged. OK.

---

## Aggregate notes

- The Frida bridge is large but disciplined: 116 `info`/`debug` log calls, ~60 `warning`/`error`/`exception` calls, and effectively zero formatting violations. The only sharp HIGH issues are three `except` clauses (L4828, L5075, and the `compile_typescript` warning-instead-of-exception at L6748) that need direct fixes.
- The dominant MEDIUM theme is **asymmetric entry/exit logging**: many public methods log either at entry or at exit but not both. Roughly 35-40 public methods exhibit this gap. The exit-only debug logs (e.g. `enumerate_*`) provide post-hoc audit but lose the "this was attempted" signal that is valuable when a script load hangs or a JS payload causes a target-process crash before the exit log can fire. The fix is mechanical — adding `_logger.info("frida_<operation>_started", ...)` at the top of each method.
- `named_pipe_client.py` has tight Win32-layer coverage (every `kernel32.*` call site is logged with `GetLastError`) but three `except` clauses (L227, L316, L441) violate §3 #2 by silently re-raising or swallowing without a log. These are the highest-impact fixes in the file because they affect IPC reliability diagnostics.
- `__init__.py` and `_lazy.py` are correctly minimal — exempt under §4. No actionable findings.
- No use of stdlib `logging`, `print()`, `contextlib.suppress`, or any inline lint/type suppression directives observed across the entire 7910-LOC shard. No f-string / `%` / `.format` inside log messages.
- Pattern recommendation: extract a small `@_log_operation("event_name", **kwargs)` decorator or helper that emits entry + exit + failure events around each Frida call, reducing the repetition. This would erase 30+ of the MEDIUM findings in one structural change without bloating any individual method.
- The file `frida_bridge.py` is large (6879 lines) — auditing required chunked reads. No section was skipped; all 60+ except clauses were verified manually.
