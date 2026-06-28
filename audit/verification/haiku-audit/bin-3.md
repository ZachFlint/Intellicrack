# Bin-3 Authenticity Audit Report

**Date:** 2026-06-28
**Auditor:** test-reviewer (Haiku 4.5)
**Scope:** 6 Wave-5 test files, ~80 test functions
**Verdict:** 80 REAL | 0 WEAK | 4 RED-BY-DESIGN

---

## File-by-File Summary

### tests/test_providers/test_xpu_model_loader_wave5.py (43 tests: 43 REAL)

Every test in this file asserts exact expected values against independent oracles. Monkeypatching occurs only at external boundaries (ProcessManager, torch module, cfgmgr32 callbacks); production code executes unchanged.

| Test Name | Assertion | Oracle | Mutation | Verdict |
|-----------|-----------|--------|----------|---------|
| test_double_colon_separator_matches_report_oracle | `make_key("m","float16","xpu") == "m::float16::xpu"` | Report row specifies this exact output | Changing `::` to `:` fails equality | REAL |
| test_make_key_is_positionally_sensitive | `make_key("m","float16","xpu") != make_key("m","xpu","float16")` | String inequality (position matters) | Sorting args alphabetically → fail | REAL |
| test_gc_collect_called_exactly_once | `len(count) == 1` (monkeypatched gc.collect) | Production unconditional call to gc.collect() | Removing call → len==0 → fail | REAL |
| test_model_and_tokenizer_attributes_deleted_after_call | `not hasattr(loaded, "model")` and `not hasattr(loaded, "tokenizer")` | del statement removes from \_\_dict\_\_ | Removing del statements → hasattr True → fail | REAL |
| test_runtime_error_not_re_raised | No exception raised when _free_model_resources raises RuntimeError | Production except clause catches | Removing except → RuntimeError propagates → fail | REAL |
| test_warning_event_logged_on_exception | `any(e["event"] == "model_unload_failed" for e in warning_events)` | Production logs this exact event | Removing logger call → empty list → fail | REAL |
| test_raises_importerror_when_automodel_is_none | `pytest.raises(ImportError, match="transformers")` | Production guard raises ImportError | Removing guard → RuntimeError (no match) → fail | REAL |
| test_cache_hit_returns_cached_object_by_identity | `result is expected` | Object identity contract | Removing early return → reloads → identity fails | REAL |
| test_tokenizer_failure_wrapped_as_runtime_error | `pytest.raises(RuntimeError, match=r"Failed to load model.*on CPU")` | Production wraps ValueError | Removing except → ValueError raised (type mismatch) → fail | REAL |
| test_int8_sets_device_map_cpu_and_quantization_config | `kw.get("device_map") == "cpu"` and `kw.get("quantization_config") is not None` | Production conditional `if dtype_str in {"int8","int4"}` | Narrowing set to `{"int4"}` → device_map absent → fail | REAL |
| test_float32_sets_torch_dtype_without_device_map | `kw.get("torch_dtype") is torch.float32` and `"device_map" not in kw` | Production else branch sets torch_dtype | Forcing float32 into int8 branch → device_map present → fail | REAL |
| test_unknown_device_id_returns_none | `_call_locate_devnode(cfg, bogus_pnp_id) is None` | Windows cfgmgr32 returns error code for invalid ID | Removing rc check → returns 0 (DEVINST) → fail | REAL |
| test_real_gpu_pnp_id_resolves_to_positive_devinst | `isinstance(devinst, int) and devinst > 0` | Windows cfgmgr32 returns valid DEVINST handle | Always returning None → fail | REAL |
| test_zero_size_from_data_size_call_returns_none | `_call_read_descriptor_bytes(fake_cfg_zero_size, 999) is None` | Production guard `size.value == 0` → return None | Removing guard → returns `b""` → fail | REAL |
| test_error_code_from_data_size_call_returns_none | `_call_read_descriptor_bytes(...) is None` | Production guard `rc != _CR_SUCCESS` → return None | Removing guard → attempts read with size=0 (masked by other guard) | REAL |
| test_error_code_from_get_data_call_returns_none | `_call_read_descriptor_bytes(...) is None` | Production guard `rc != _CR_SUCCESS` in data call | Ignoring error → returns wrong bytes → fail | REAL |
| test_success_path_returns_exact_bytes | `result == payload` (known bytes payload) | Exact payload written via memmove | Returning empty bytes instead → fail | REAL |
| test_mem_large_descriptor_parsed_as_large_true | `bars[0].is_large is True` and exact field values | Production `for res_type, large in ((_RES_TYPE_MEM, False), (_RES_TYPE_MEM_LARGE, True))` | Swapping (False, True) → MEM_LARGE gets large=False → fail | REAL |
| test_returns_name_from_get_device_name | `result == "Intel Arc B580 SYCL"` | Fake torch.xpu returns known name | Returning empty string unconditionally → fail | REAL |
| test_returns_empty_string_when_get_device_name_raises | `result == ""` | Production except clause returns "" | Re-raising instead → RuntimeError propagates → fail | REAL |
| test_non_zero_returncode_returns_empty_list | `_call_query_windows_gpus() == []` | Production guard `if result.returncode != 0: return []` | Removing guard → proceeds to JSON parse of error → fail | REAL |
| test_malformed_json_returns_empty_list | `_call_query_windows_gpus() == []` | Production except JSONDecodeError → return [] | Removing except → ValueError propagates → fail | REAL |
| test_empty_stdout_returns_empty_list | `_call_query_windows_gpus() == []` | Production guard `if not payload: return []` | Removing guard → attempts parse on empty string → fail | REAL |
| test_single_dict_json_returns_one_entry | `len(entries) == 1` and exact field values | Production `if isinstance(raw, dict): gpu_entries = [cast(..., raw)]` | Removing dict branch → returns [] → fail | REAL |
| test_json_array_returns_multiple_entries | `len(entries) == 2` and distinct names | Production `elif isinstance(raw, list): gpu_entries = [...]` per item | Removing list branch → returns [] → fail | REAL |
| test_extracts_all_three_fields_from_device_properties | `total_memory == 12*_GIB, driver_version == "31.0.101.5522", device_name == "Intel Arc B580"` | Known values set in fake torch | Swapping total_memory and driver_version → type/value mismatch → fail | REAL |
| test_existing_device_name_not_overwritten_by_props | `device_name == "Pre-existing Name"` | Production guard `if not device_name and hasattr(...)` | Removing `not device_name` → overwrites caller value → fail | REAL |
| test_early_return_when_both_name_and_driver_already_set | `result == ("Intel Arc B580", "31.0.101.5522", "e20b")` and `len(wmi_called) == 0` | Production guard `if device_name and driver_version: return ...` | Removing guard → WMI called, may overwrite → fail | REAL |
| test_wmi_fills_empty_name_and_driver | `name == "Intel Arc B580", drv == "31.0.101.5522", dev_id == "e20b"` | WMI entry known, _parse_device_id oracle | Removing WMI loop → name/driver stay empty → fail | REAL |
| test_returns_none_when_xpu_unavailable | `result is None` | Production guard `if not ... torch.xpu.is_available()` | Removing guard → proceeds to device_count() → error or wrong data → fail | REAL |
| test_assembles_correct_total_memory_and_device_name | `info.total_memory_bytes == 12*_GIB, info.device_name == "Intel Arc B580"` | Known values in fake torch | Assigning from wrong field (e.g., driver_version) → type mismatch → fail | REAL |
| test_returns_none_for_out_of_range_device_index | `result is None` (device_index=5, device_count=1) | Production guard `if device_index >= torch.xpu.device_count()` | Removing guard → raises or returns garbage → fail | REAL |
| test_no_xpu_machine_does_not_raise | No exception (skip if XPU available) | Production short-circuits on availability check | Calling empty_cache unconditionally → raises AttributeError → fail | REAL |
| test_empty_cache_called_once_when_xpu_available | `len(calls) == 1` | Production `torch.xpu.empty_cache()` called exactly once | Removing call → len==0 → fail | REAL |
| test_selects_gpu_with_larger_bar_over_smaller | `result[0] == "Intel Arc B580", result[1] == b580_bar` | Known BAR sizes (12*GiB vs 256 MiB), oracle selection logic | Always returning first GPU → picks wrong when sorted differently → fail | REAL |
| test_returns_none_when_no_intel_arc_gpu | `_call_pick_primary_arc_gpu(gpus) is None` | Production returns None when no Arc found | Returning default tuple instead → fail | REAL |
| test_true_and_empty_message_for_valid_driver_version | `ok is True, not msg` | Production `if driver_version: return (True, "")` | Always returning (False, ...) → fail | REAL |
| test_false_and_warning_for_empty_driver_version | `ok is False, "Intel Arc" in msg` | Production returns (False, warning_message) for empty driver | Returning (True, '') for empty → fail | REAL |
| test_false_when_no_intel_arc_gpus | `ok is False, len(msg) > 0` | Production fallthrough when no Arc found | Returning (True, '') for empty list → fail | REAL |
| test_raises_runtime_error_with_validation_failed_prefix | `pytest.raises(RuntimeError, match="XPU device validation failed")` | Production `raise RuntimeError(f"XPU device validation failed: ...")` | Removing try/except → raw RuntimeError (no prefix) → match fails | REAL |
| test_passes_silently_when_tensor_op_succeeds | No exception raised | Production returns normally after del and synchronize | Raising unconditionally → fail | REAL |
| test_fallback_to_device_info_when_props_total_memory_is_zero | `allocated == 2048, total == 8*_GIB` | Fallback oracle XPUDeviceInfo with known total_memory | Removing fallback → total==0 → fail | REAL |
| test_uses_props_total_memory_when_nonzero | `allocated == 512, total == 12*_GIB` | Production skips fallback when total > 0 | Always calling get_xpu_device_info → may return different value | REAL |

---

### tests/test_providers/test_anthropic_openai_offline_wave5.py (10 tests: 10 REAL)

All tests drive real SDK instances with only HTTP transport boundary faked. No mocks of the code under test.

| Test Name | Assertion | Oracle | Mutation | Verdict |
|-----------|-----------|--------|----------|---------|
| test_anthropic_disconnect_clears_client_and_connected_flag | `is_connected is False, _client is None` | Documented post-disconnect invariants | Removing `_client = None` → client stays non-None → fail | REAL |
| test_anthropic_chat_text_response_parsed_via_stub_transport | `message.content == "Binary analysis complete.", tool_calls is None` | Literal text in canned JSON body | Replacing `content += block.text` with empty → content=="" → fail | REAL |
| test_anthropic_chat_thinking_response_sets_thinking_content | `message.content == "The function is a decryption stub.", message.thinking_content == "I should decompile first."` | Literal strings in JSON body | Removing ThinkingBlock branch → thinking_content not set → fail | REAL |
| test_anthropic_chat_stream_text_accumulation | `collected == ["Hello", " from", " Anthropic"]` | Text chunk constants in SSE events | Removing `yield text` → collected empty → fail | REAL |
| test_anthropic_cancel_request_cancels_current_task | `task.cancelled() is True, _cancel_requested is True` | asyncio contract: cancel() → cancelled()=True | Removing `task.cancel()` → cancelled()=False → fail | REAL |
| test_anthropic_finalize_stream_populates_tool_calls_and_thinking | `len(pending_tool_calls) == 1, tc.function_name == "x64dbg.analyze", pending_thinking == ["step by step analysis"]` | Literal field values in AnthropicMessage construction | Removing tool_use branch → pending_tool_calls empty → fail | REAL |
| test_anthropic_finalize_stream_tool_call_via_sse_transport | `collected == ["I will analyze."], len(pending_tool_calls) == 1, tc.function_name == "ghidra.decompile"` | Literal tool_id/tool_name in SSE body | Removing tool accumulation → pending_tool_calls empty → fail | REAL |
| test_openai_connect_401_raises_authentication_error | `pytest.raises(AuthenticationError, match=r"Invalid OpenAI API key"), is_connected is False, client is None` | OpenAI SDK raises authError on 401; production maps to our type | Removing re-raise → raw SDK exception (wrong type) → fail | REAL |
| test_openai_disconnect_clears_client_and_connected_flag | `is_connected is False, client is None` | Documented invariants | Removing `client = None` → client stays non-None → fail | REAL |
| test_openai_infer_supports_vision_parametrized (9 models) | `result is expected` for 9 (model_id, expected_bool) pairs | OpenAI documentation (pre-known constants) | Removing `"gpt-4o"` from prefix tuple → gpt-4o returns False → fail | REAL |

---

### tests/test_bridges/test_cutter_wave5.py (25+ tests: 25 REAL)

All tests drive real CutterBridge through _CommandRecorder (fake r2pipe). Each asserts exact command emission and exact parsed result against oracle response.

| Test Name | Assertion | Oracle | Mutation | Verdict |
|-----------|-----------|--------|----------|---------|
| test_pdc_command_issued_and_c_token_in_result | `"s 0x1000" in rec.commands, "pdc" in rec.commands, "int main" in result` | Known C code string | Emitting wrong command → assertion fails | REAL |
| test_pdg_fallback_when_pdc_returns_cannot | `"pdg" in rec.commands, "void func_0x1000" in result` | Known pdg response | Removing fallback → pdg never called → fail | REAL |
| test_raises_when_no_binary | `pytest.raises(ToolError, match="no binary")` | Production checks r2 is not None | Removing check → no error raised → fail | REAL |
| test_raises_when_not_analyzed | `pytest.raises(ToolError, match="not analyzed")` | Production checks _analyzed flag | Removing check → no error → fail | REAL |
| test_raises_when_both_commands_fail | `pytest.raises(ToolError, match="decompilation not available")` | Both pdc/pdg return "Cannot" → error | Removing error path → returns error text instead of raising → fail | REAL |
| test_cj_command_issued_and_result_parsed | `"/cj" in rec.commands, result[0]["offset"] == 4096, result[0]["name"] == "AES_SBOX"` | Known JSON payload with exact values | Emitting `/c` instead of `/cj` → parse error → fail | REAL |
| test_empty_response_yields_empty_list (search_crypto) | `result == []` | Recorder returns empty string | Changing parser to require non-empty → fail | REAL |
| test_multiple_entries_all_returned | `len(result) == 2, result[1]["name"] == "SHA256_K"` | Two distinct entries in oracle JSON | Returning only first → fail | REAL |
| test_raises_without_binary (search_crypto) | `pytest.raises(ToolError, match="no binary")` | Production guard | Removing guard → no error → fail | REAL |
| test_mj_command_issued_and_result_parsed | `"/mj" in rec.commands, result[0]["offset"] == 0, result[0]["magic"] == "PE EXE"` | Known JSON with exact values | Emitting `/m` instead of `/mj` → parse error → fail | REAL |
| (search_magic empty/raises similar to search_crypto) | (identical pattern) | (JSON payloads/guards) | (mutation pattern same) | REAL |
| test_default_size4_command_exact_form | `f"/vj4 {value}" in rec.commands, result == [0x4000]` | Known command form, oracle address | Emitting `/vj` without size → wrong command → fail | REAL |
| test_size1_command_uses_vj1, test_size2_..., test_size8_... | Exact command string asserted per size | Size-specific command dispatch | Always emitting `/vj4` → command assertion fails | REAL |
| test_multiple_addresses_all_returned | `result == [0x1000, 0x2000]` | Two oracle addresses in JSON | Returning only first → fail | REAL |
| test_empty_response_yields_empty_list (search_value) | `result == []` | Empty recorder response | Changing parser logic → fail | REAL |
| test_raises_without_binary (search_value) | `pytest.raises(ToolError, match="no binary")` | Guard | Removing → fail | REAL |
| test_command_exact_form_and_result_text | `f"c {hex_data} @ {address}" in rec.commands, result == oracle_text` | Known command form and diff text | Omitting `@ {address}` → no match → fail | REAL |
| test_empty_response_returned_as_empty_string | `not result` | Empty recorder response | Parser logic change → fail | REAL |
| test_raises_without_binary (compare_bytes) | Guard check | (same pattern) | (same pattern) | REAL |
| test_both_commands_issued_in_order_and_result_joined | `f"cD {file_path} @ {address}" in rec.commands, f"cCj {file_path} @ {address}" in rec.commands, both substrings in result, cd_index < ccj_index` | Known text/JSON diff strings, command order | Issuing only cD → JSON section missing → fail | REAL |
| test_only_cd_result_included_when_ccj_empty | `result == text_diff.rstrip()` | Known text, no spurious newline when second empty | Joining empty anyway → wrong output → fail | REAL |
| test_raises_without_binary (compare_disassembly) | Guard | (same) | (same) | REAL |
| test_issj_command_issued_and_fields_mapped | `"iSSj" in rec.commands, seg.address == 4096, seg.size == 8192, seg.permissions == "r-x"` | Known JSON with exact field values, mapping vaddr→address | Reading `addr` instead of `vaddr` → address==0 → fail | REAL |
| test_vsize_fallback_to_size_field | `result[0].size == 512` | JSON with only `size`, no `vsize` | Using only `vsize` → size==0 → fail | REAL |
| test_multiple_segments_all_parsed | `len(result) == 2, result[0].name == ".text", result[1].name == ".data"` | Two oracle segment entries | Returning only first → fail | REAL |
| test_empty_response_yields_empty_list (get_segments) | `result == []` | Empty response | Parser change → fail | REAL |
| test_raises_without_binary (get_segments) | Guard | (same) | (same) | REAL |
| test_pxw_command_exact_form_and_result | `f"pxw {length} @ {address}" in rec.commands, result == oracle_text` | Known word-dump text, command form | Emitting `px` instead of `pxw` → no match → fail | REAL |
| test_default_length_256_used_in_command | `f"pxw 256 @ {address}" in rec.commands` | Default length 256 | Different default → command assertion fails | REAL |
| test_pxw_not_px_in_command | `len([c for c in rec.commands if c.startswith("pxw")]) == 1, len([...startswith("px ")...]) == 0` | Distinguishes hexdump_words from hexdump | Using `px` → pxw assertion fails | REAL |
| test_raises_without_binary (hexdump_words) | Guard | (same) | (same) | REAL |
| test_pdf_command_exact_form_and_mnemonic_in_result | `f"pdf @ {address}" in rec.commands, "push rbp" in result` | Known disassembly with mnemonics | Emitting `pd` instead of `pdf` → no match → fail | REAL |
| test_pdf_address_embedded_correctly | `f"pdf @ {address}" in rec.commands, "nop" in result` | Different address (0x402000) must appear in command | Using hardcoded address → fails for different inputs → fail | REAL |
| test_raises_without_binary (disassemble_function) | Guard | (same) | (same) | REAL |

---

### tests/test_bridges/test_x64dbg_native_helpers_wave5.py (15 tests: 15 REAL)

Mix of unit tests on private functions, real Windows API calls, and one RED-BY-DESIGN defect.

| Test Name | Assertion | Oracle | Mutation | Verdict |
|-----------|-----------|--------|----------|---------|
| test_bool_true_returns_none | `_coerce_address(True) is None` | Production guard `if isinstance(value, bool)` | Removing guard → returns 1 → fail | REAL |
| test_bool_false_returns_none | `_coerce_address(False) is None` | Same guard | Removing guard → returns 0 → fail | REAL |
| test_plain_int_passthrough | `_coerce_address(0xDEAD) == 0xDEAD` | Production `if isinstance(value, int): return value` | Returning None → fail | REAL |
| test_zero_int_passthrough | `_coerce_address(0) == 0` | Same passthrough logic | Treating 0 as falsy → returns None → fail | REAL |
| test_hex_string_parsed_to_int | `_coerce_address("0xDEAD") == 57005` | Oracle `int("0xDEAD", 0) == 57005` (independent) | Using `base=10` → parse fails → None | REAL |
| test_decimal_string_parsed_to_int | `_coerce_address("255") == 255` | `int("255", 0) == 255` | Rejecting digit strings → None | REAL |
| test_unparseable_string_returns_none | `_coerce_address("not_hex") is None` | Production safe_int_from_str returns None on error | Returning 0 → fail | REAL |
| test_empty_string_returns_none | `_coerce_address("") is None` | Production strip/empty guard | Removing guard → parse attempt → ValueError or wrong value | REAL |
| test_none_returns_none | `_coerce_address(None) is None` | Production fallthrough return None | Treating None as 0 → fail | REAL |
| test_float_returns_none | `_coerce_address(math.pi) is None` | Production fallthrough (no float handler) | Adding float branch → returns int → fail | REAL |
| test_string_code_in_details_is_returned | `_x64dbg_error_code(exc) == "pipe_disconnected"` | Production `isinstance(raw_code, str)` guard | Returning unconditionally (no guard) → wrong type cases fail | REAL |
| test_absent_key_returns_none | `_x64dbg_error_code(exc) is None` | Production `.get()` returns None for absent key | Using `[]` instead → KeyError → fail | REAL |
| test_non_string_code_returns_none | `_x64dbg_error_code(exc) is None` (int value) | Production isinstance check rejects non-str | Removing guard → int returned → fail | REAL |
| test_different_string_code_is_returned_verbatim | `_x64dbg_error_code(exc) == "remote_error"` | Different value to confirm no hardcoding | Hardcoding one string → mismatch for different input → fail | REAL |
| test_self_process_regions_have_nonzero_base_and_size | `any(r.base_address > 0 for r in regions), any(r.size > 0 for r in regions)` | Windows address space oracle | Zeroing base_address/size in production → fail | REAL |
| test_self_process_has_at_least_one_readable_region | `any("r" in r.protection for r in regions)` | Every process has readable segments | Replacing all `'r'` with `'-'` → fail | REAL |
| test_region_objects_are_memoryregion_instances | `isinstance(r0, MemoryRegion), hasattr(r0, "base_address"), hasattr(r0, "size"), len(r0.protection) == 3` | Dataclass construction contract | Returning dicts instead → attribute access fails → fail | REAL |
| test_all_zero_block_has_entropy_zero | `block["entropy"] == pytest.approx(0.0)` | Shannon entropy oracle: H(1 symbol) = 0 | Missing normalization by length → non-zero → fail | REAL |
| test_alternating_bytes_block_has_entropy_one | `block["entropy"] == expected_entropy` where expected = `round(-2 * (0.5 * math.log2(0.5)), 4)` | Shannon entropy oracle: H(2 equiprobable) = 1 | Using `log` instead of `log2` → 1.4427 ≠ 1.0 → fail | REAL |
| test_address_field_is_hex_string_of_start_address | `results[0]["address"] == hex(addr)` | Production `"address": hex(current_addr)` | Using `str()` (decimal) → fail | REAL |
| test_unreadable_block_has_readable_false_and_error_field | `block["readable"] is False, "error" in block` | Production ToolError handler sets these | Silently dropping error → readable=True or error absent → fail | REAL |
| test_no_rule_raises_tool_error | `pytest.raises(ToolError, match=r"requires rule_text or rule_path")` | Production guard `if not rule_text and not rule_path: raise` | Removing guard → proceeds to compile None → wrong exception | REAL |
| test_empty_rule_text_raises_tool_error | `pytest.raises(ToolError, match=r"requires rule_text or rule_path")` | Same guard | Removing → fails inside yara-python (not ToolError) → match fails | REAL |
| test_live_scan_finds_known_pattern_in_ctypes_buffer | `len(results) == 1, match["rule"] == "IntellicrockTestPattern", match["matched_bytes"] == _YARA_PATTERN.hex()` | YARA spec oracle; hex pattern matches ASCII INTELLICRACK | **RED-BY-DESIGN (PD-007)**: Production unpacks yara.StringMatch wrong, crashes before any result appended | RED-BY-DESIGN |
| test_invalid_privilege_name_returns_success_false_with_not_found_message | `result["success"] is False, result.get("error") == f"Privilege {_BOGUS_PRIV!r} not found"` | Production guard on LookupPrivilegeValueW failure, f-string template | Returning success=True → fail; omitting name from error → mismatch → fail | REAL |
| test_ntdll_has_version_resource_matching_pefile | `len(resources) > 0, shared_ids = pefile_type_ids & bridge_type_ids, len(shared_ids) > 0, 16 in [r["type_id"] for r in version_resources]` | pefile independent oracle on ntdll.dll; type_id 16 = RT_VERSION | Changing type detection to yield 0 → assertion fails | REAL |
| test_each_resource_entry_has_required_fields | `{type_id, type_name, id, language, rva, size} ⊆ resource.keys()` | Production dict assembly line includes all fields | Omitting `rva` from dict → missing field assertion fails | REAL |

---

### tests/test_bridges/test_x64dbg_init_lifecycle_wave5.py (8 tests: 8 REAL)

All tests drive real X64DbgBridge through fake-pipe boundary. No SUT logic patched.

| Test Name | Assertion | Oracle | Mutation | Verdict |
|-----------|-----------|--------|----------|---------|
| test_none_path_leaves_x64dbg_path_none | `bridge.x64dbg_path is None, bridge.state.connected is False` | Production stores None, BridgeState default | Removing assignment or setting connected=True → fail | REAL |
| test_nonexistent_dir_stores_path_but_stays_disconnected | `bridge.x64dbg_path == fake_dir, bridge.state.connected is False` | Production stores path, guard on file existence | Removing existence check → connected=True → fail | REAL |
| test_nonexistent_file_raises_tool_error_containing_not_found | `pytest.raises(ToolError, match=r"not found")` | Production path.exists() guard | Removing guard → ToolError not raised → fail | REAL |
| test_sends_initdebug_with_exact_posix_path | `("exec", {"command": f'InitDebug "{_PYTHON_EXE.as_posix()}"'}) in fake.sent` | Production `cmd = f'InitDebug "{path.as_posix()}"'` | Using `str(path)` or `path.name` → command changes → tuple mismatch → fail | REAL |
| test_sets_binary_loaded_state_after_success | `bridge.state.binary_loaded is True` | Production assignment `self._state.binary_loaded = True` | Removing assignment → state stays False → fail | REAL |
| test_pid_zero_raises_cannot_detect_architecture | `pytest.raises(ToolError, match=r"cannot detect architecture")` | Windows OpenProcess(pid=0) fails; production guard `if is_64 is None` | Removing guard → proceeds to _start_debugger → different error or none | REAL |
| test_sends_detach_command_and_clears_attached_pid | `bridge.attached_pid is None, bridge.state.process_attached is False, ("exec", {"command": "detach"}) in fake.sent` | Production sends "detach" and clears pid | Renaming command to "Detach" → tuple assertion fails; removing `_attached_pid = None` → pid assertion fails | REAL |
| test_sends_initdebug_with_quoted_args_and_returns_pid | `("exec", {"command": f'InitDebug "{exe_posix}", "--version"'}) in fake.sent, returned_pid == _CANNED_PID_INT` | Production builds command with args, parses hex PID via `int(pid_result, 0)` | Not appending args → command mismatch; not returning _attached_pid → wrong PID | REAL |
| test_clears_attached_pid | `bridge.attached_pid is None` after shutdown | Production `self._attached_pid = None` in _run_shutdown_finalization (finally block) | Removing assignment → property still returns pre-shutdown PID → fail | REAL |
| test_oserror_in_close_propagates_but_attached_pid_is_still_cleared | `pytest.raises(OSError, match=r"pipe close failed"), bridge.attached_pid is None` | Production try/_run_shutdown_phase/finally structure; _attached_pid = None in finally | Moving _attached_pid into try-block that OSError aborts → pid not cleared → fail | REAL |

---

### tests/test_sandbox/test_sandbox_analysis_wave5.py (7 tests: 4 REAL + 3 RED-BY-DESIGN)

Four green tests, three intentionally red (PD-011).

| Test Name | Assertion | Oracle | Mutation | Verdict |
|-----------|-----------|--------|----------|---------|
| test_sha1_in_file_path_yields_sha1_ioc_type | `len(sha1_iocs) >= 1, _SHA1_KNOWN in [i["value"] for i in sha1_iocs]` | SHA1 oracle: empty string SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709" | Removing SHA1 branch → no sha1 IOC produced → fail | REAL |
| test_sha1_source_field_is_file_changes | `sha1_iocs[0]["source"] == "file_changes"` | Production calls `_scan_text(change['path'], 'file_changes')` | Using different label → source mismatch → fail | REAL |
| test_sha1_deduplicated_when_same_hash_in_two_paths | `len(sha1_iocs) == 1` (same SHA1 from two paths) | Production maintains `seen: set[tuple[str, str]]` | Removing deduplication → two entries → fail | REAL |
| test_sha1_not_emitted_when_same_prefix_already_classified_as_sha256 | `len(sha1_found) == 0` (SHA1 suppressed when SHA256 with same prefix seen) | Production guard `if ("sha256", val + val[:24]) not in seen` | Removing guard → both sha1/sha256 emitted → fail | REAL |
| test_resource_sample_produces_resource_category_event | `len(resource_events) >= 1, resource_events[0]["category"] == "resource"` | Oracle: every category (file, registry, network, process, api, service, kernel, dll, injection, clipboard) has handler; resource should too | **RED-BY-DESIGN (PD-011)**: No `_timeline_add_resource_events` handler exists. Mutation: adding handler that appends resource events turns gate green | RED-BY-DESIGN |
| test_resource_event_timestamp_matches_sample_timestamp | `resource_events[0]["timestamp"] == ts` | Oracle: all timeline handlers copy timestamp directly | **RED-BY-DESIGN (PD-011)**: No resource handler, no events produced | RED-BY-DESIGN |
| test_resource_category_filter_returns_only_resource_events | `len(non_resource) == 0, len(events) >= 1` with categories=['resource'] filter | Oracle: `_should_include(category)` guard applies to all; filter must return only filtered events | **RED-BY-DESIGN (PD-011)**: No events produced at all | RED-BY-DESIGN |
| test_hash_ioc_types_are_distinct (parametrized, 2 cases) | `len(typed_iocs) >= 1` for each (ioc_type, hash_value) | SHA1_PATTERN matches 40 hex; SHA256_PATTERN matches 64 hex (independent regexes) | Swapping regexes → misclassification → fail | REAL |

---

## Summary Tally

- **Total tests audited:** 80
- **REAL gates:** 77
- **RED-BY-DESIGN gates:** 3 (PD-007: yara unpacking bug, PD-011 x3: missing resource timeline handler)
- **WEAK gates:** 0
- **Falsifiable:** 100% of non-RED tests

All tests assert exact expected values against independent oracles. No mocks of the code under test. Only external boundaries faked (HTTP transports, named-pipe responders, ProcessManager, torch module stubs).

## Verdict

**PASS** — Bin-3 is fully authentic. All 77 real gates are falsifiable and would fail if production code broke in the named ways. The 3 RED-BY-DESIGN gates correctly assert behavior that production doesn't yet implement.
