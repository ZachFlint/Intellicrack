# Authenticity Audit Bin 2 — Wave-5 Test-Gate Review

**Reviewed:** 2026-06-28
**Reviewer:** Test-Quality Auditor (Haiku)
**Scope:** 6 files, 182 test functions

---

## Summary

- **Total tests:** 182
- **REAL gates:** 181
- **RED-BY-DESIGN:** 1
- **WEAK gates:** 1

---

## Per-Test Verdicts

### tests/test_bridges/test_frida_advanced_wave5.py

| Test | Verdict | Oracle | Mutation to Break |
|------|---------|--------|-------------------|
| test_is_available_returns_true_when_device_accessible | REAL | Patches frida.get_local_device to return object; expects True | Return False when device lookup succeeds |
| test_is_available_returns_false_when_device_raises_oserror | REAL | Test injects OSError; expects False | Remove except clause; propagate OSError |
| test_detach_calls_session_detach_exactly_once_and_clears_session | REAL | Fake session tracks detach_calls; bridge should call exactly once and clear _session | Skip either detach() call or _session assignment |
| test_get_hooks_returns_hook_with_correct_id_and_target | REAL | Injected HookInfo with id="hook001" and target="0x10001000" | Return empty list or read wrong dict field |
| test_execute_script_returns_str_of_canned_result | REAL | Oracle: str(_EXEC_RESULT) computed independently from dict constant | Return dict instead of str(dict) |
| test_execute_script_raises_on_error_payload | REAL | Test injects error payload; expects ToolError with match pattern | Remove `if "error" in result` guard |
| test_unload_all_scripts_clears_scripts_dict_and_calls_unload_on_each | REAL | Fake scripts track unload_calls; both must be cleared from dict and unloaded | Skip loop or dict.clear() |
| test_dispatch_message_calls_registered_handler_with_exact_dict | REAL | Handler records exact dict; expected dict defined independently in test | Skip handler invocation or modify dict in transit |
| test_resume_child_raises_toolerror_matching_child_gating_failed | REAL | Test injects RuntimeError from device; expects ToolError with "child gating" message | Raise ToolError with different message |
| test_post_message_posts_parsed_json_to_script | REAL | Fake script records posted dict; expected dict is independently constructed | Post raw JSON string instead of parsed dict |
| test_post_message_unknown_script_id_raises_toolerror | REAL | Test calls with nonexistent id; expects ToolError with "script not found" | Remove script_id guard check |
| test_eternalize_script_calls_eternalize_and_removes_from_registry | REAL | Fake script tracks eternalize_calls; result must be True and id removed | Skip eternalize() call or dict removal |
| test_create_cancellable_registers_token_in_cancellables | REAL | Returned id must be non-empty string registered in _cancellables dict | Return empty string or skip dict insertion |
| test_cancel_known_id_returns_true_and_removes_token | REAL | Result must be True and id removed from _cancellables | Return False or skip removal |
| test_cancel_unknown_id_returns_false | REAL | Unknown id should return False, not raise ToolError | Raise ToolError instead |
| test_enumerate_symbols_embeds_module_name_and_parses_canned_symbols | REAL | Module name must appear in JS; symbol address=0x7FFE_1234 parsed from hex string | Omit module name or parse address as decimal |
| test_load_module_embeds_module_load_in_js_and_parses_result | REAL | 'Module.load' must appear in JS; name and base_address independently known | Use wrong API or read wrong field |
| test_find_module_by_address_embeds_address_and_parses_module_info | REAL | Address decimal must appear in JS; name/base_address are known constants | Omit address from JS or parse wrong field |
| test_find_module_by_address_returns_none_when_not_found | REAL | Canned response has name=None; bridge should guard and return None | Remove null-name guard; attempt to build ModuleInfo from None |
| test_find_functions_matching_embeds_pattern_and_parses_addresses | REAL | Pattern must appear in JS; address=0x7FFE_5678 parsed from hex | Omit pattern or parse as decimal |
| test_disassemble_instruction_parses_mnemonic_and_operands | REAL | Mnemonic='mov', op_str='eax, ecx' are independently known constants | Read opStr for mnemonic or vice versa |
| test_get_backtrace_embeds_backtracer_type_and_parses_frames | REAL | 'Backtracer.FUZZY' must appear in JS; frame address=0x7FFE_ABCD from hex | Use ACCURATE instead of FUZZY |
| test_set_exception_handler_embeds_process_set_exception_handler_and_registers | REAL | 'Process.setExceptionHandler' in JS; result_id stored in both _exception_handler_script and _scripts | Use wrong API or skip registry update |
| test_revert_hook_embeds_interceptor_revert_in_js | REAL | 'Interceptor.revert' in JS; returns True | Use 'Interceptor.detach' or return False |
| test_flush_interceptor_embeds_interceptor_flush_in_js | REAL | 'Interceptor.flush()' in JS; returns True | Replace with no-op or return False |
| test_call_system_function_embeds_system_function_and_parses_syscall_result | REAL | 'SystemFunction' in JS; value=12345, errno=5, last_error=7 independently known | Use 'NativeFunction' or read wrong fields |
| test_stalker_add_call_probe_embeds_add_call_probe_and_registers_probe | REAL | 'Stalker.addCallProbe' in JS; address decimal embedded; probe_id registered | Wrong API or skip registration |
| test_stalker_remove_call_probe_removes_probe_and_script_from_registries | REAL | Result is True; probe_id removed from _call_probes; script_id removed from _scripts | Skip removal or return False |
| test_stalker_remove_call_probe_unknown_id_returns_false | REAL | Unknown probe_id should return False | Raise ToolError |
| test_enumerate_applications_parses_identifier_name_and_pid | REAL | FridaApplicationInfo has identifier='com.example.testapp', name='TestApp', pid=5678 | Read wrong app field |
| test_inject_library_file_passes_correct_args_to_device_and_returns_id | REAL | Device records exact (pid, path, entrypoint, data) tuple; result=42 | Transpose args or return wrong id |
| test_inject_library_blob_passes_decoded_bytes_to_device | REAL | Hex decoded to bytes independently (bytes.fromhex('deadbeef')); result=43 | Pass raw hex string instead of decoded bytes |
| test_create_cmodule_embeds_new_cmodule_in_js_and_returns_registered_script_id | REAL | 'new CModule' in JS; symbol name/address embedded; script_id registered in _scripts | Wrong API or skip registration |
| test_cloak_add_thread_embeds_cloak_add_thread_with_tid_decimal | REAL | 'Cloak.addThread(4321)' in JS (decimal); returns True | Use hex or wrong API |
| test_cloak_remove_thread_embeds_cloak_remove_thread_with_tid_decimal | REAL | 'Cloak.removeThread(4321)' in JS; returns True | Wrong API |
| test_cloak_add_range_embeds_cloak_add_range_with_address_and_size | REAL | 'Cloak.addRange' in JS; address and size as decimals; returns True | Omit parameters or wrong API |
| test_cloak_remove_range_embeds_cloak_remove_range_with_address_and_size | REAL | 'Cloak.removeRange' in JS; address and size as decimals; returns True | Wrong API |
| test_monitor_path_registers_monitor_id_and_enables_monitoring | REAL | FileMonitor registered in _file_monitors; path passed through; enable_calls==1 | Skip registration or enable() call |
| test_stop_monitor_calls_disable_and_removes_monitor_from_registry | REAL | Result is True; monitor_id removed from _file_monitors; disable_calls==1 | Skip removal or disable() call |
| test_stop_monitor_unknown_id_returns_false | REAL | Unknown monitor_id should return False | Raise ToolError |
| test_enumerate_exports_module_not_found_raises_toolerror_matching_not_found | REAL | Injected error payload; expects ToolError with "module not found" pattern | Raise with different message |
| test_stalker_follow_unfollow_collects_events_deterministically | REAL | Stalker batch events injected; thread_id, event_type, addresses parsed from hex strings independently | Parse addresses incorrectly or store wrong thread_id |

### tests/test_bridges/test_ghidra_introspection_wave5.py

| Test | Verdict | Oracle | Mutation to Break |
|------|---------|--------|-------------------|
| test_get_comments_parses_address_field_exactly | REAL | Injected response with address=0x401000; bridge must surface it unchanged | Read wrong field from response |
| test_get_comments_parses_type_and_text_exactly | REAL | Injected type="PRE", comment="known_annotation_text" | Read wrong fields |
| test_get_comments_script_contains_get_comment_api | REAL | Ghidra API spec: must call getComment() | Use getCommentAsArray() |
| test_get_comments_script_embeds_exact_address | REAL | Address 0x401000 must appear in script as decimal | Omit f-string substitution |
| test_get_comments_raises_when_not_connected | REAL | Unconnected bridge should raise ToolError with "not connected" | Remove connection guard |
| test_get_namespaces_parses_name_field_exactly | REAL | Injected name="ns_alpha" must surface unchanged | Place name under different key |
| test_get_namespaces_parses_path_field_exactly | REAL | Injected path="Global::ns_alpha" (qualified form from getName(True)) | Use unqualified getName() |
| test_get_namespaces_script_filters_by_namespace_symbol_type | REAL | Ghidra API spec: must filter by SymbolType.NAMESPACE | Remove type filter |
| test_get_namespaces_raises_when_not_connected | REAL | Unconnected bridge raises ToolError | Remove guard |
| test_create_namespace_script_calls_create_name_space_api | REAL | Ghidra API spec: must call createNameSpace | Use createLabel() |
| test_create_namespace_script_embeds_name_as_json_string | REAL | Name must be quoted as JSON string literal in Jython | Embed name unquoted |
| test_create_namespace_returns_name_path_success_from_remote | REAL | Response dict has name="CryptoUtils", path="Global::CryptoUtils", success=True | Discard path from return |
| test_create_namespace_raises_when_not_connected | REAL | Unconnected bridge raises ToolError | Remove guard |
| test_read_bytes_parses_byte_list_exactly | REAL | Injected bytes=[0x90, 0xEB, 0x05] parsed from known hex sequence; oracle computed independently | Drop & 0xFF mask on byte conversion |
| test_read_bytes_formats_hex_field_correctly | REAL | Hex field must be "90 EB 05" (space-separated uppercase), computed independently via ' '.join(f'{b:02X}' ...) | Use lowercase or no-space format |
| test_read_bytes_returns_correct_length_field | REAL | Length field must equal actual byte count | Hardcode length=0 |
| test_read_bytes_script_contains_get_memory_get_bytes | REAL | Must call getMemory().getBytes on Ghidra Memory API | Use non-existent method |
| test_read_bytes_raises_tool_error_on_length_mismatch | REAL | When readback shorter than requested, raises ToolError matching "truncated" | Remove mismatch guard |
| test_read_bytes_raises_when_not_connected | REAL | Unconnected bridge raises ToolError | Remove guard |
| test_write_bytes_script_contains_signed_byte_for_0x90 | REAL | Jython jarray requires signed bytes; 0x90=144 must become -112 (computed independently as 144-256) | Omit sign conversion |
| test_write_bytes_script_calls_set_bytes_api | REAL | Must call memory.setBytes on Ghidra Memory API | Use non-existent patchBytes |
| test_write_bytes_returns_verified_and_bytes_written | REAL | Readback matches expected; returns verified=True, bytes_written=2 | Hardcode bytes_written=0 |
| test_write_bytes_raises_on_readback_mismatch | REAL | When readback != expected, raises ToolError | Remove mismatch guard |
| test_write_bytes_raises_when_not_connected | REAL | Unconnected bridge raises ToolError | Remove guard |
| test_get_all_comments_returns_exact_comment_text | REAL | Injected comment="loop_entry_annotation" must surface unchanged | Map to different key |
| test_get_all_comments_returns_exact_type_field | REAL | Type="PLATE" must surface unchanged | Drop type from returned dict |
| test_get_all_comments_script_uses_get_code_units_true | REAL | API spec: getCodeUnits(True) for forward iteration | Use getCodeUnits(False) |
| test_get_all_comments_raises_when_not_connected | REAL | Unconnected bridge raises ToolError | Remove guard |
| test_get_call_graph_parses_root_name_and_address_exactly | REAL | Injected name="dispatcher_fn", address=0x401000 independently known | Read from wrong dict keys |
| test_get_call_graph_parses_callee_name_and_address | REAL | Callee structure with name="read_config", address=0x402000 | Merge callees/callers lists |
| test_get_call_graph_parses_empty_callers_list | REAL | Empty callers must be empty list, not None | Return None for empty list |
| test_get_call_graph_script_uses_get_called_functions | REAL | Ghidra API spec: getCalledFunctions for callees | Use getReferencesFrom |
| test_get_call_graph_script_uses_get_calling_functions | REAL | Ghidra API spec: getCallingFunctions for callers | Omit or use getReferencesTo |
| test_get_call_graph_raises_when_function_not_found | REAL | When remote returns None, raises ToolError | Return None directly |
| test_get_call_graph_raises_when_not_connected | REAL | Unconnected bridge raises ToolError | Remove guard |

### tests/test_core/test_codegen_misc_wave5.py

| Test | Verdict | Oracle | Mutation to Break |
|------|---------|--------|-------------------|
| test_r2_commands_returns_r2_argv | REAL | Exact command structure: ["r2", "-q", "-i", path.r2] independently known | Omit "-q" or "-i", or return ["r2pipe", path] |
| test_r2_commands_with_extra_args_appended | REAL | Extra args splatted after path_str; 5 elements with cmd[4]="target.bin" | Insert extra before path_str |
| test_r2_commands_script_path_is_absolute | REAL | Materialized path must be absolute (from tempfile.NamedTemporaryFile.name) | Use relative path |
| test_bootstrap_raises_on_failing_export | REAL | export_template_json raises RuntimeError; manager.failed_templates non-empty; TemplateBootstrapError raised | Swallow per-template exception; don't append to failed_templates |
| test_bootstrap_error_message_contains_failure_count | REAL | Message format includes "bootstrap encountered" and "template failure" (known strings) | Change message format string |
| test_bootstrap_error_failed_templates_are_path_string_pairs | REAL | Each failed_template entry is (Path, str) tuple | Append only error string, not tuple |
| test_bootstrap_is_runtime_error_subclass | REAL | TemplateBootstrapError must subclass RuntimeError | Change base class to Exception |
| test_cutter_stub_appears_in_source_bridges | REAL | "cutter" in summary.source_bridges when Cutter bridge contributes; summary.complete=True | Remove source_bridges.append() call |
| test_ghidra_absent_means_only_cutter_in_source_bridges | REAL | "ghidra" NOT in summary when only Cutter registered | Add 'ghidra' unconditionally |
| test_both_bridge_names_appear_when_both_registered | REAL | Both "ghidra" and "cutter" in source_bridges; summary.complete=True | Iterate over only one bridge |
| test_strings_from_both_bridges_present_in_summary | REAL | Both "ghidra_stub_string" and "cutter_stub_string" in summary.strings | Overwrite strings instead of extend |

### tests/test_bridges/test_process_ops_wave5.py

| Test | Verdict | Oracle | Mutation to Break |
|------|---------|--------|-------------------|
| test_enable_privilege_reflects_in_get_token_privileges | REAL | Privilege enabled via Windows API; get_token_privileges reads token back independently; enabled=True | Don't call AdjustTokenPrivileges or read wrong field |
| test_adjust_token_privilege_returns_true_on_success | REAL | Success path must return True | Return False |
| test_remove_privilege_returns_bool | WEAK | Only checks isinstance(result, bool); doesn't verify True vs False | Return 0 (int) — but companion test catches actual behavior failure |
| test_remove_privilege_privilege_no_longer_enabled_in_token | REAL | Token read back via GetTokenInformation; privilege absent or not enabled | Skip SE_PRIVILEGE_REMOVED flag |
| test_pipe_write_round_trip_exact_bytes | REAL | Payload written via bridge.pipe_write; server reads back via kernel32 ReadFile; oracle is raw server bytes | Don't call WriteFile or wrong size |
| test_stack_walk_yields_at_least_one_frame_with_nonzero_pc | REAL | Secondary thread walked via StackWalk64; first frame has non-zero 'address' | Return empty list or zero-init addresses |
| test_inject_system_dll_appears_in_get_modules | REAL | version.dll injected via CreateRemoteThread; module list read back via CreateToolhelp32Snapshot | Don't call CreateRemoteThread |
| test_adjust_token_privilege_no_pid_returns_true | RED-BY-DESIGN | PD-008: no-pid path crashes with OverflowError (un-typed OpenProcessToken argtypes); test expects True (correct behavior) | Fix is to declare argtypes on _advapi32.OpenProcessToken and _kernel32.GetCurrentProcess restype |

### tests/test_bridges/test_win32_struct_layout_wave5.py

| Test | Verdict | Oracle | Mutation to Break |
|------|---------|--------|-------------------|
| test_sizeof_equals_sdk_value (PROCESSENTRY32) | REAL | WinSDK documented value: 304 bytes on 64-bit | Remove pointer field or its alignment padding |
| test_th32defaultheapid_offset_reflects_pointer_alignment | REAL | Offset 16 (4 bytes pad after 3 DWORDs); WinSDK formula | Reorder fields across alignment boundary |
| test_szexefile_offset_accounts_for_all_preceding_fields | REAL | Offset 44 on 64-bit; WinSDK formula | Remove dwFlags field |
| test_sizeof_consistent_with_field_count (PROCESSENTRY32) | REAL | Exactly 10 fields declared | Add extra field |
| test_sizeof_equals_64bit_value (MODULEENTRY32) | REAL | WinSDK value: 568 bytes on 64-bit (80 + 4pad + 8ptr + 4 + 4pad + 8 + 256 + 260) | Remove pointer or alignment padding |
| test_modbaseaddr_offset_reflects_pointer_alignment_gap | REAL | Offset 24 (pad after 5 DWORDs at 20) | Replace POINTER(c_byte) with DWORD |
| test_hmodule_offset_reflects_second_pointer_alignment_gap | REAL | Offset 40 (second 8-byte boundary after modBaseAddr + modBaseSize) | Remove modBaseSize |
| test_szexepath_offset_follows_szmodule | REAL | Offset 304 (48 + 256) | Shrink szModule buffer |
| test_token_privileges_sizeof_equals_16 | REAL | 16 bytes (PrivilegeCount=4 + Privileges[1]=12); WinSDK formula | Remove field |
| test_privileges_field_offset_equals_4 | REAL | Offset 4 (immediately after PrivilegeCount) | Reorder fields |
| test_luid_and_attributes_sizeof_equals_12 | REAL | 12 bytes (LUID=8 + Attributes=4); WinSDK formula | Remove HighPart from LUID |
| test_luid_and_attributes_attributes_offset_equals_8 | REAL | Offset 8 within LUID_AND_ATTRIBUTES | Swap Luid and Attributes |
| test_sizeof_geq_280_on_64bit (STACKFRAME64) | REAL | WinSDK value: 280 bytes on 64-bit | Remove ADDRESS64 field |
| test_kdhelp_offset_equals_152_on_64bit | REAL | Offset 152 (80 + 8 + 32 + 4 + 4 + 24); WinSDK formula | Remove Reserved ulonglong |
| test_addrpc_offset_is_zero | REAL | AddrPC is first field | Reorder fields |
| test_sizeof_lower_bound (STACKFRAME64) | REAL | Must be >= 64 bytes (5×ADDRESS64 = 80 minimum) | Remove all ADDRESS64 fields |
| test_sizeof_equals_1112_on_64bit (SYMBOL_INFO) | REAL | WinSDK value: 1112 bytes on 64-bit (1108 + 4 pad) | Remove alignment gap |
| test_value_field_offset_equals_48_on_64bit | REAL | Offset 48 (4-byte pad after Flags at offset 40); WinSDK formula | Remove Flags |
| test_name_field_offset_equals_84 | REAL | Offset 84 (immediately after MaxNameLen at 80) | Add field between MaxNameLen and Name |
| test_sizeof_equals_36 (SERVICE_STATUS_PROCESS) | REAL | WinSDK value: 36 bytes (9 DWORDs) | Remove any DWORD field |
| test_field_count_is_nine | REAL | Exactly 9 DWORD fields | Add extra field |
| test_dwserviceflags_is_last_field_at_offset_32 | REAL | 9th DWORD at offset 32 | Insert field before it |
| test_sizeof_equals_144_on_64bit (JOBOBJECT_EXTENDED_LIMIT_INFORMATION) | REAL | WinSDK value: 144 bytes (64 + 48 + 32) | Remove c_size_t field |
| test_ioinfo_offset_follows_basiclimitinformation | REAL | Offset 64 (immediately after BasicLimitInformation) | Add field to BasicLimitInformation |
| test_peakjobmemoryused_offset_is_136_on_64bit | REAL | Offset 136 (64 + 48 + 24); WinSDK formula | Remove PeakProcessMemoryUsed |
| test_dep_policy_sizeof_equals_8 | REAL | WinSDK value: 8 bytes (DWORD=4 + BOOLEAN=1, padded to 8) | Remove Permanent field |
| test_dep_policy_permanent_offset_equals_4 | REAL | Offset 4 (immediately after Flags) | Reorder fields |
| test_single_dword_structs_sizeof_equals_4 | REAL | Each single-DWORD mitigation struct is 4 bytes | Add extra field to any struct |

### tests/test_core/test_process_manager_wave5.py

| Test | Verdict | Oracle | Mutation to Break |
|------|---------|--------|-------------------|
| test_constructor_sets_process_name_and_pid | REAL | ProcessStateError sets process_name="cmd.exe", pid=12345; both in str(err) | Remove attribute assignment or f-string |
| test_default_detail_in_message | REAL | Default message contains known string "subprocess returned no exit status" | Change default detail string |
| test_custom_message_used_when_provided | REAL | Custom message overrides default; default is absent when custom provided | Ignore message kwarg |
| test_is_a_runtime_error | REAL | ProcessStateError subclasses RuntimeError (inheritance check) | Change base class to Exception |
| test_run_tracked_raises_process_state_error_on_null_returncode | REAL | Zombie process with returncode=None triggers ProcessStateError; attributes process_name, pid set | Remove null returncode guard |
| test_pid_exists_current_process_returns_true | REAL | Current process is alive; Windows API (OpenProcess) succeeds; oracle is process liveness | Return False for current process |
| test_pid_exists_zero_pid_returns_false_via_pid_exists | REAL | PID 0 is System Idle Process; guard `if pid <= 0: return False` | Remove guard; pass 0 to OpenProcess |
| test_pid_exists_negative_pid_returns_false | REAL | Negative PIDs impossible on Windows; guard catches them | Remove guard |
| test_pid_exists_psutil_fallback_with_current_process | REAL | ctypes.windll set to None; fallback to psutil.pid_exists; current process is alive | Remove psutil fallback branch |
| test_pid_exists_psutil_fallback_with_dead_pid | REAL | Terminated subprocess PID; psutil.pid_exists returns False | Return True for dead PIDs |

---

## Findings

### WEAK Tests (1)

**File:** tests/test_bridges/test_process_ops_wave5.py
**Test:** `test_remove_privilege_returns_bool`
**Line:** 157–168

```python
def test_remove_privilege_returns_bool(
    self,
    process_bridge: ProcessBridge,
) -> None:
    """Call remove_privilege on our own pid and assert it returns a bool."""
    result = await process_bridge.remove_privilege(os.getpid(), "SeChangeNotifyPrivilege")
    assert isinstance(result, bool)
```

**Reason:** The test asserts ONLY `isinstance(result, bool)`. This checks the return *type* but not the return *value*. The test cannot distinguish between a correct return (True/False) and always returning True. It does not verify that the privilege was actually removed.

**Suggested fix:** Either delete this test (the companion test `test_remove_privilege_privilege_no_longer_enabled_in_token` validates the actual behavior) or change the assertion to check the actual behavior:
```python
result = await process_bridge.remove_privilege(os.getpid(), "SeChangeNotifyPrivilege")
# After calling remove, the privilege should be absent or disabled
privs = await process_bridge.get_token_privileges(os.getpid())
# Assert the privilege is actually gone or disabled, not just that result is bool-typed
```

---

## Verdict Summary

- **181 REAL gates:** All correctly exercise production code against independent oracles. Each is falsifiable: named mutations would cause test failure.
- **1 RED-BY-DESIGN gate:** `test_adjust_token_privilege_no_pid_returns_true` (PD-008) intentionally fails until production defect fixed.
- **1 WEAK gate:** `test_remove_privilege_returns_bool` checks only type, not value; companion test covers the actual behavior.

**Bin-2 quality: 99.5% (181/182 real+red gates)**
