# Group 04 Verification Report — FridaBridge Subsystem

**Scope:** `audit/test-coverage-audit/section-03-debugger-bridges.md` — FridaBridge
subsystem only: "Operation Inventory — FridaBridge" table (lines ~145–259) and
Frida-specific Worst-Offenders (O-06 resume\_child/enumerate\_exports error path,
O-07 stalker\_follow/unfollow, O-08 shutdown).

Note: O-09 (x64dbg `script_load`) referenced in the task prompt is an X64DbgBridge
finding and falls under Group 03 scope; it is excluded here.

---

## Enumeration Methodology

Every row in the FridaBridge inventory table whose Verdict was NOT plain `REAL GATE`
(covering `WEAK`, `NO COVERAGE`, and `PARTIAL` verdicts) was extracted as a finding.
Three Worst-Offender subsections (O-06, O-07, O-08) were added as additional findings
where they raised concerns beyond the table rows. Total: **71 findings**.

---

## Finding Table

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation caught) |
|---|------------------------|-----------------|-----|--------------------------------------------------|
| 1 | `is_available()` frida_bridge.py:1342 | NO COVERAGE | NOT_RESOLVED | No test found in any frida test file. Missing: assert `bridge.is_available() is True` when frida installed, `False`/ToolError when not. |
| 2 | `attach_by_name(name, cancellable_id)` frida_bridge.py:1444 | NO COVERAGE | RESOLVED | test_frida_wave2c_core.py:550-580 · oracle=_ATTACH_PID constant · mutation: pick wrong pid from process list |
| 3 | `spawn(path, args, ...)` frida_bridge.py:1523 | NO COVERAGE | RESOLVED | test_frida_wave2c_core.py:413-447 · oracle=_SPAWN_PID constant, known argv list · mutation: swap argv ordering or pass wrong program |
| 4 | `resume()` frida_bridge.py:1650 | NO COVERAGE | RESOLVED | test_frida_wave2c_core.py:483-498 · oracle=_ATTACH_PID constant · mutation: pass 0 to device.resume() |
| 5 | `detach(kill_spawned)` frida_bridge.py:1674 | WEAK | NOT_RESOLVED | Still only fixture teardown swallowing ToolError (test_frida_bridge.py:169-183). No positive test asserts session.detach_calls==1 or bridge._session is None. Missing: assert session.detach_calls==1 after detach(). |
| 6 | `get_hooks()` frida_bridge.py:2290 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: install a hook, call get_hooks(), assert hook list contains id/target. |
| 7 | `execute_script(script)` frida_bridge.py:2301 | NO COVERAGE | NOT_RESOLVED | Public `execute_script` has no test. audit5 test_f0021 covers internal `_execute_script_and_wait` only. Missing: call execute_script() via offline session, assert result dict matches canned payload. |
| 8 | `unload_all_scripts()` frida_bridge.py:2716 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: load two scripts, call unload_all_scripts(), assert _scripts is empty. |
| 9 | `set_message_handler(handler)` frida_bridge.py:2722 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: install handler, deliver a message, assert handler was called with correct payload. |
| 10 | `intercept_return(target, return_value)` frida_bridge.py:2387 | NO COVERAGE | RESOLVED | test_frida_wave2c_core.py:758-806 · oracle=decimal(0x12345678)="305419896" · mutation: use hex in ptr() |
| 11 | `resume_child(pid)` frida_bridge.py:4229 | WEAK (O-06) | NOT_RESOLVED | test_realcov_03a_frida_modules.py:245 still uses bare `pytest.raises(ToolError)` with no `match=`. Any ToolError from any cause satisfies the gate. Missing: `match=r"not found|resume|unknown child"`. |
| 12 | `shutdown()` frida_bridge.py:5673 | WEAK (O-08) | RESOLVED | test_frida_bridge_audit5.py:922-953 · oracle=bridge.state.connected==False (documented contract) · mutation: move super().shutdown() out of finally block |
| 13 | `post_message(script_id, message)` frida_bridge.py:4428 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: install persistent script capturing posted messages, post a known payload, assert it appears in bridge-side delivery log. |
| 14 | `eternalize_script(script_id)` frida_bridge.py:4455 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: register script, call eternalize_script(id), assert script.eternalize() invoked exactly once. |
| 15 | `rpc_call(script_id, method_name, args)` frida_bridge.py:4480 | NO COVERAGE | RESOLVED | test_frida_wave2c_core.py:599-637 · oracle=_RPC_RETURN_VALUE=0xABCD_1234 and received_args==(42,) · mutation: pass wrong method name or ignore args |
| 16 | `create_cancellable()` frida_bridge.py:4516 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: create token, assert returned id is non-empty str and registered in bridge's cancellables dict. |
| 17 | `cancel(cancellable_id)` frida_bridge.py:4528 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: create token then cancel it, assert ToolError("unknown cancellable token") for unknown id per documented constant. |
| 18 | `patch_code(address, hex_data)` frida_bridge.py:4544 | NO COVERAGE | RESOLVED | test_frida_wave2c_core.py:690-755 · oracle=address decimal, known byte literals, size=3 in JS · mutation: use wrong byte sequence or skip patchCode call |
| 19 | `allocate_string(value, encoding)` frida_bridge.py:4586 | NO COVERAGE | RESOLVED | test_frida_wave2c_core.py:914-1109 · oracle=_ALLOC_STR_ADDR=0x55550000, alloc fn name per encoding · mutation: use wrong allocFn for encoding |
| 20 | `enumerate_symbols(module_name)` frida_bridge.py:4655 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: deliver canned symbol list, assert count/name/address parsed correctly. |
| 21 | `load_module(path)` frida_bridge.py:4716 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: assert Module.load() in JS, path embedded, result dict parsed. |
| 22 | `find_module_by_address(address)` frida_bridge.py:4760 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: deliver canned module info, assert address decimal embedded in JS, name/base returned. |
| 23 | `find_functions_matching(pattern)` frida_bridge.py:4807 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: deliver canned function list, assert pattern embedded in JS, addresses parsed. |
| 24 | `disassemble_instruction(address)` frida_bridge.py:4865 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: deliver canned instruction dict, assert address in JS, mnemonic/operands returned exactly. |
| 25 | `get_backtrace(context_address, backtracer)` frida_bridge.py:4922 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: deliver canned frame list, assert backtracer type embedded in JS, frames parsed. |
| 26 | `set_exception_handler()` frida_bridge.py:4994 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: install handler, assert Process.setExceptionHandler in JS, handler invoked on synthetic exception message. |
| 27 | `revert_hook(target)` frida_bridge.py:5054 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: hook a function, revert it, assert Interceptor.revert in JS and hook removed from _scripts. |
| 28 | `flush_interceptor()` frida_bridge.py:5088 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: assert Interceptor.flush() in JS. |
| 29 | `call_system_function(address, ...)` frida_bridge.py:5113 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: deliver canned result, assert NativeFunction in JS, address decimal embedded. |
| 30 | `stalker_add_call_probe(address, callback_code)` frida_bridge.py:5208 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: assert Stalker.addCallProbe in JS, address decimal embedded, probe_id returned. |
| 31 | `stalker_remove_call_probe(probe_id)` frida_bridge.py:5267 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: add probe, remove it, assert Stalker.removeCallProbe(probe_id) in JS. |
| 32 | `enumerate_applications()` frida_bridge.py:5284 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: deliver canned app list, assert identifier/name fields parsed correctly. |
| 33 | `inject_library_file(pid, path, ...)` frida_bridge.py:5313 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: deliver canned result, assert device.inject_library_file called with correct pid/path. |
| 34 | `inject_library_blob(pid, blob_hex, ...)` frida_bridge.py:5347 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: assert bytes decoded from blob_hex passed to inject_library_blob. |
| 35 | `objc_enumerate_classes()` frida_bridge.py:5382 | NO COVERAGE | RESOLVED | test_frida_wave2c_objc_java.py:302-328 · oracle=["NSObject","NSString","NSURL"] and ObjC.classes in JS · mutation: use ObjC.protocols instead |
| 36 | `objc_enumerate_protocols()` frida_bridge.py:5411 | NO COVERAGE | RESOLVED | test_frida_wave2c_objc_java.py:356-380 · oracle=["NSCopying","NSMutableCopying"] and ObjC.protocols in JS · mutation: use ObjC.classes |
| 37 | `objc_enumerate_loaded_classes(pattern)` frida_bridge.py:5440 | NO COVERAGE | RESOLVED | test_frida_wave2c_objc_java.py:395-443 · oracle=canned class list, ObjC.enumerateLoadedClasses in JS, pattern/no-pattern framing · mutation: omit pattern from JS |
| 38 | `objc_choose(class_name, limit)` frida_bridge.py:5491 | NO COVERAGE | RESOLVED | test_frida_wave2c_objc_java.py:458-498 · oracle=hex addresses parse to [0x1000,0x2000,0x3000], class/limit in JS · mutation: use decimal parser on hex string |
| 39 | `objc_get_class_methods(class_name)` frida_bridge.py:5541 | NO COVERAGE | RESOLVED | test_frida_wave2c_objc_java.py:513-552 · oracle=["- init","- dealloc","+ new"], class name and $ownMethods in JS · mutation: use $allMethods instead |
| 40 | `objc_hook_method(...)` frida_bridge.py:5579 | NO COVERAGE | RED_BY_DESIGN | test_frida_wave2c_objc_java.py:555-653 (4 tests) — all RED because PD-004: `_logger.info(..., method_name=method_name)` at frida_bridge.py:5600 raises TypeError before any guard runs. Tests are correct gates; defect is in production code. |
| 41 | `java_enumerate_loaded_classes(pattern)` frida_bridge.py:5685 | NO COVERAGE | RESOLVED | test_frida_wave2c_objc_java.py:668-735 · oracle=canned class list, Java.enumerateLoadedClasses in JS · mutation: use wrong Java API |
| 42 | `java_choose(class_name, limit)` frida_bridge.py:5736 | NO COVERAGE | RESOLVED | test_frida_wave2c_objc_java.py:750-793 · oracle=canned instance list, class name and limit in JS · mutation: wrong class name in script |
| 43 | `java_use(class_name)` frida_bridge.py:5785 | NO COVERAGE | RESOLVED | test_frida_wave2c_objc_java.py:807-852 · oracle=className=="com.example.App", methods==["onCreate","checkLicense"], Java.use in JS · mutation: use wrong Java API |
| 44 | `java_hook_method(...)` frida_bridge.py:5830 | NO COVERAGE | RED_BY_DESIGN | test_frida_wave2c_objc_java.py:854-970 (4 tests) — all RED because PD-004: `_logger.info(..., method_name=method_name)` at frida_bridge.py:5853 raises TypeError before any guard runs. Tests are correct gates; defect is in production code. |
| 45 | `java_deoptimize()` frida_bridge.py:5926 | NO COVERAGE | RESOLVED | test_frida_wave2c_objc_java.py:985-1022 · oracle=True return, Java.deoptimizeEverything and Java.perform in JS · mutation: call wrong deopt API |
| 46 | `create_cmodule(code, symbols)` frida_bridge.py:5957 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: assert CModule construction in JS, symbols embedded, handle returned. |
| 47 | `kernel_enumerate_modules()` frida_bridge.py:6031 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:313-376 · oracle=_KERNEL_MODULE_BASE=0xFFFFF80012340000, name, Kernel.enumerateModules() in JS · mutation: use Process.enumerateModules() |
| 48 | `kernel_enumerate_ranges(protection)` frida_bridge.py:6083 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:394-444 · oracle=_KERNEL_RANGE_BASE, "r-x" embedded in JS, region fields · mutation: embed wrong protection |
| 49 | `kernel_read(address, size)` frida_bridge.py:6142 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:447-487 · oracle=_KERNEL_READ_BYTES.hex()="deadbeefcafe", address/size decimal in JS · mutation: read wrong result field |
| 50 | `kernel_write(address, hex_data)` frida_bridge.py:6183 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:490-525 · oracle=expanded hex byte array, Kernel.writeByteArray in JS · mutation: expand wrong byte sequence |
| 51 | `kernel_alloc(size)` frida_bridge.py:6220 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:528-566 · oracle=_KERNEL_ALLOC_ADDR=0xFFFFF80030000000 parsed from hex · mutation: use int() instead of int(x,16) |
| 52 | `kernel_protect(address, size, protection)` frida_bridge.py:6255 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:569-618 · oracle=address/size/protection all in JS, True returned · mutation: embed wrong protection |
| 53 | `socket_listen(port, family)` frida_bridge.py:6300 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:626-664 · oracle=port 8080 and "ipv4" in JS, script_id in _scripts · mutation: embed wrong port |
| 54 | `socket_connect(host, port, family)` frida_bridge.py:6354 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:681-722 · oracle=host/port/family in JS, response dict host/port fields · mutation: embed wrong host |
| 55 | `socket_type(handle)` frida_bridge.py:6398 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:724-757 · oracle="tcp" from value field, handle in JS · mutation: read wrong response field |
| 56 | `socket_local_address(handle)` frida_bridge.py:6433 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:760-777 · oracle=addr_data dict exact match, Socket.localAddress in JS · mutation: return envelope instead of data field |
| 57 | `socket_peer_address(handle)` frida_bridge.py:6469 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:780-797 · oracle=peer_data dict exact match, Socket.peerAddress in JS · mutation: return wrong field |
| 58 | `file_read_target(path)` frida_bridge.py:6505 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:805-862 · oracle=_FILE_READ_BYTES.hex(), path/'rb' in JS · mutation: read data instead of __binary field |
| 59 | `file_write_target(path, hex_data)` frida_bridge.py:6549 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:865-899 · oracle=expanded hex array in JS, path/'wb' in JS · mutation: use wrong byte sequence |
| 60 | `sqlite_open(path)` frida_bridge.py:6588 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:907-976 · oracle=path in JS, rpc.exports in JS, script_id in _scripts · mutation: omit rpc.exports |
| 61 | `sqlite_exec(script_id, sql)` frida_bridge.py:6664 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:979-1018 · oracle=_SQLITE_ROWS exact match, exec_calls[0]==_SQLITE_SQL · mutation: call wrong exports method |
| 62 | `sqlite_dump(path)` frida_bridge.py:6691 | NO COVERAGE | RESOLVED | test_frida_wave2c_kernel_io.py:1021-1058 · oracle=_SQLITE_DUMP_TEXT exact match, path in JS · mutation: read wrong result field |
| 63 | `write_code(address, code, architecture)` frida_bridge.py:6727 | NO COVERAGE | RESOLVED | test_frida_wave2c_core.py:824-894 · oracle=arch→writer class map (X86Writer, Arm64Writer, etc.), size from result · mutation: hardcode single writer class |
| 64 | `cloak_add_thread(thread_id)` frida_bridge.py:6819 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: assert Stalker.addToIncludeList in JS, thread_id embedded. |
| 65 | `cloak_remove_thread(thread_id)` frida_bridge.py:6848 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: assert Stalker.removeFromIncludeList in JS. |
| 66 | `cloak_add_range(address, size)` frida_bridge.py:6877 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: assert Cloak.addRange in JS, address/size decimal embedded. |
| 67 | `cloak_remove_range(address, size)` frida_bridge.py:6908 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: assert Cloak.removeRange in JS. |
| 68 | `monitor_path(path)` frida_bridge.py:7077 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: assert PathMonitor construction in JS, path embedded, monitor_id returned and registered. |
| 69 | `stop_monitor(monitor_id)` frida_bridge.py:7129 | NO COVERAGE | NOT_RESOLVED | No test found. Missing: open monitor, stop it, assert monitor script unloaded and id removed from registry. |
| 70 | O-06: `enumerate_exports` module-not-found error path test_realcov_03a_frida_modules.py:169-177 | WEAK GATE | NOT_RESOLVED | Still bare `pytest.raises(ToolError)` with no `match=`. If bridge raises ToolError("timeout") instead of "not found", test still passes. Missing: `match=r"not found|not loaded"`. |
| 71 | O-07: `stalker_follow`/`stalker_unfollow` test_frida_bridge.py:567-618, 1274-1303 | NON-DETERMINISTIC | NOT_RESOLVED | Both tests still use `time.sleep(1.0)` (lines 598, 1297) with no explicit synchronization. On a loaded CI host the worker thread (10×Sleep(100)ms) may not have generated events within the window, producing flaky failures. Missing: replace `time.sleep` with a polling loop `while event_count == 0 and elapsed < 5.0: time.sleep(0.1)`. |

---

## STILL OPEN

| # | Operation | Why not real | Missing assertion |
|---|-----------|-------------|-------------------|
| 1 | `is_available()` frida_bridge.py:1342 | Zero tests | `assert bridge.is_available() is True` when frida importable; `False` when not |
| 5 | `detach(kill_spawned)` frida_bridge.py:1674 | Only fixture teardown with swallowed ToolError | `assert session.detach_calls == 1` after detach(); `assert bridge._session is None` |
| 6 | `get_hooks()` frida_bridge.py:2290 | Zero tests | Install hook, then `assert len(bridge.get_hooks()) == 1` with id/target fields |
| 7 | `execute_script(script)` frida_bridge.py:2301 | Zero tests for public method | Call via offline session, assert result dict==canned payload |
| 8 | `unload_all_scripts()` frida_bridge.py:2716 | Zero tests | Load 2 scripts, call unload_all_scripts(), assert `bridge._scripts == {}` |
| 9 | `set_message_handler(handler)` frida_bridge.py:2722 | Zero tests | Install handler, deliver message, assert handler called with exact payload |
| 11 | `resume_child(pid)` frida_bridge.py:4229 | `pytest.raises(ToolError)` no match= | Add `match=r"not found|resume|unknown"` |
| 13 | `post_message(script_id, message)` frida_bridge.py:4428 | Zero tests | `assert fake_script.posts == [expected_payload]` |
| 14 | `eternalize_script(script_id)` frida_bridge.py:4455 | Zero tests | `assert fake_script.eternalize called once` |
| 16 | `create_cancellable()` frida_bridge.py:4516 | Zero tests | `assert token_id in bridge._cancellables` |
| 17 | `cancel(cancellable_id)` frida_bridge.py:4528 | Zero tests | Known id: assert no raise; unknown id: `pytest.raises(ToolError, match=r"unknown cancellable")` |
| 20 | `enumerate_symbols()` frida_bridge.py:4655 | Zero tests | Deliver canned symbol list; assert name/address/type fields on result |
| 21 | `load_module()` frida_bridge.py:4716 | Zero tests | `assert "Module.load" in captured_js` and path embedded |
| 22 | `find_module_by_address()` frida_bridge.py:4760 | Zero tests | `assert result.name == known_name and result.base_address == known_base` |
| 23 | `find_functions_matching()` frida_bridge.py:4807 | Zero tests | Deliver canned list; assert addresses parsed to exact ints |
| 24 | `disassemble_instruction()` frida_bridge.py:4865 | Zero tests | Deliver canned dict; assert mnemonic/operands/address fields |
| 25 | `get_backtrace()` frida_bridge.py:4922 | Zero tests | Deliver canned frame list; assert `result[0].address == known_addr` |
| 26 | `set_exception_handler()` frida_bridge.py:4994 | Zero tests | `assert "Process.setExceptionHandler" in captured_js` |
| 27 | `revert_hook(target)` frida_bridge.py:5054 | Zero tests | `assert "Interceptor.revert" in captured_js` and hook removed from `_scripts` |
| 28 | `flush_interceptor()` frida_bridge.py:5088 | Zero tests | `assert "Interceptor.flush()" in captured_js` |
| 29 | `call_system_function()` frida_bridge.py:5113 | Zero tests | Deliver canned result; assert NativeFunction in JS, address decimal embedded |
| 30 | `stalker_add_call_probe()` frida_bridge.py:5208 | Zero tests | `assert "Stalker.addCallProbe" in captured_js` and probe_id returned |
| 31 | `stalker_remove_call_probe()` frida_bridge.py:5267 | Zero tests | `assert "Stalker.removeCallProbe" in captured_js` with known probe_id |
| 32 | `enumerate_applications()` frida_bridge.py:5284 | Zero tests | Deliver canned list; assert identifier/name fields |
| 33 | `inject_library_file()` frida_bridge.py:5313 | Zero tests | `assert device.inject_library_file_calls[0] == (pid, path, ...)` |
| 34 | `inject_library_blob()` frida_bridge.py:5347 | Zero tests | Assert bytes decoded from blob_hex passed to device |
| 46 | `create_cmodule()` frida_bridge.py:5957 | Zero tests | `assert "new CModule" in captured_js`, symbols embedded, handle returned |
| 64 | `cloak_add_thread()` frida_bridge.py:6819 | Zero tests | `assert "Stalker.addToIncludeList" in captured_js` with thread_id decimal |
| 65 | `cloak_remove_thread()` frida_bridge.py:6848 | Zero tests | `assert "Stalker.removeFromIncludeList" in captured_js` |
| 66 | `cloak_add_range()` frida_bridge.py:6877 | Zero tests | `assert "Cloak.addRange" in captured_js` with address/size decimal |
| 67 | `cloak_remove_range()` frida_bridge.py:6908 | Zero tests | `assert "Cloak.removeRange" in captured_js` |
| 68 | `monitor_path()` frida_bridge.py:7077 | Zero tests | `assert path embedded in JS, monitor_id in bridge._monitors` |
| 69 | `stop_monitor()` frida_bridge.py:7129 | Zero tests | Load monitor, stop it, assert script unloaded and id removed |
| 70 | `enumerate_exports` not-found error path (test_realcov_03a:169-177) | `pytest.raises(ToolError)` no match= | Add `match=r"not found|not loaded"` |
| 71 | `stalker_follow`/`stalker_unfollow` (test_frida_bridge.py:598, 1297) | Bare `time.sleep(1.0)` without synchronization | Replace with polling loop: `while ... : time.sleep(0.1)` |

---

## Notes on RED_BY_DESIGN Findings

**PD-004** (`objc_hook_method` and `java_hook_method`):
Both methods open with `_logger.info(..., method_name=method_name)` which triggers
`TypeError: _proxy_to_logger() got multiple values for argument 'method_name'` from
structlog's `BoundLoggerBase`. This exception is raised before the `if self._session is None`
guard, before any script construction, and before any message processing — meaning
**every** call path (not-attached, happy-path, error-payload) fails identically.

The 8 tests in `test_frida_wave2c_objc_java.py` (4 for each method) are correct gates:
they would pass if PD-004 were fixed. Currently all 8 are RED because the production
code raises `TypeError` instead of the expected `ToolError` or `HookInfo`. Classified
RED_BY_DESIGN per the protocol; the defect is tracked in `audit/PRODUCTION-DEFECTS.md`.

**Note on `shutdown()` (finding #12 / O-08):** `test_f0024_shutdown_calls_super_in_finally`
(audit5:922-953) is a real gate: it asserts `bridge.state.connected is False` after
shutdown completes even when cleanup raises. The mutation "remove super().shutdown()
from the finally block" would leave `state.connected == True`, failing the assertion.
However, the happy-path cleanup sequence (session.detach(), _scripts cleared, _session
set to None) remains without a direct gate. This gap is noted but not blocking given
the gate that does exist.
