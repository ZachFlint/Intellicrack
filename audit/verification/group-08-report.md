# Group 08 Verification Report

**Sections:** section-10-local-ai-models.md (full), section-14-ui-app-shell.md (full)
**Reviewer:** Group 08 (adversarial, read-only)
**Date:** 2026-06-27

---

## Methodology

Enumerated every non-REAL audit row from both sections independently, then searched
`tests/` with `rg`/Glob/Read to find any remediation coverage. Applied the falsifiability
test to every claimed gate: a gate counts as REAL only if deleting the production code would
turn it red, the assertion checks an exact independently-known value, and no forbidden
pattern is used.

New files checked:
- `tests/test_providers/test_local_model_classify_wave2d.py`
- `tests/test_ui/test_realcov_p3_ui_zero_coverage.py`
- `tests/test_ui/test_xpu_status.py` (line 1114 area)
- `tests/test_providers/test_realcov_11_model_loader.py`
- `tests/test_providers/test_realcov_11_huggingface_logic.py`
- `tests/test_providers/test_realcov_10_cancel_request.py`
- `tests/test_ui/test_realcov_15_dialog_helpers_logging.py`
- `tests/test_ui/test_realcov_15_preferences_dialog.py`
- `tests/test_providers/test_local_transformers_provider.py`

---

## Findings Table — Section 10 (Local AI Models)

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation) |
|---|------------------------|-----------------|-----|------------------------------------------|
| 1 | `_hf_status_code(exc)` (huggingface.py:57) | FAKE | NOT_RESOLVED | No test directly calls this and asserts on extracted int; status extraction regressing to None leaves all tests green |
| 2 | `_close_client()` (huggingface.py:202) | FAKE | NOT_RESOLVED | No test verifies `_client is None` after call |
| 3 | `disconnect()` (huggingface.py:211) | WEAK | NOT_RESOLVED | Pre-existing test still only asserts `is_connected is False`; `_cancel_requested` reset and client release unverified |
| 4 | `_prepare_request_payload(messages,tools,tool_choice)` (huggingface.py:378) | NONE | NOT_RESOLVED | No test found anywhere in tests/ |
| 5 | `_consume_stream_chunks(raw_stream,model,tc_buffer)` (huggingface.py:542) | NONE | NOT_RESOLVED | No unit-level test; only reachable via live API with real HF token |
| 6 | `chat_stream(messages,model,…)` HuggingFaceProvider (huggingface.py:619) | NONE | NOT_RESOLVED | No dedicated test; `_cancel_requested=True` mid-stream path untested |
| 7 | `cancel_request()` HuggingFaceProvider (huggingface.py:676) | NONE | NOT_RESOLVED | `test_realcov_10_cancel_request.py` covers Anthropic and Grok only; HuggingFaceProvider cancel_request absent |
| 8 | `_convert_messages_to_provider_format(messages)` (huggingface.py:690) | FAKE | NOT_RESOLVED | Output format never directly asserted; called inside live tests only |
| 9 | `_convert_tools_to_provider_format(tools)` HuggingFaceProvider (huggingface.py:725) | NONE | NOT_RESOLVED | No test found |
| 10 | `_fetch_model_config(model_id)` (local_transformers.py:119) | NONE | NOT_RESOLVED | No test found for any branch (network failure, 404, malformed JSON, success) |
| 11 | `_classify_model_capabilities(config)` (local_transformers.py:142) | NONE | RESOLVED | `test_local_model_classify_wave2d.py:TestClassifyContextWindow` (line 200) and `TestClassifyVisionSupport` (line 312) · Oracle: published HuggingFace model-card config shapes (Phi-3-mini max_position_embeddings=4096, Mistral-7B=32768, GPT-2 n_positions=1024; Intel/HF docs) · Mutation: swapping key priority order returns 2048 instead of 8192 for the dual-key test |
| 12 | `_release_device_caches()` (local_transformers.py:397) | NONE | NOT_RESOLVED | No test found |
| 13 | `list_models()` LocalTransformersProvider (local_transformers.py:415) | WEAK | NOT_RESOLVED | Pre-existing `any("phi" or "tiny")` assertion unchanged in test_local_transformers_provider.py:637; wave2d file pins RECOMMENDED_MODELS_B580 constant directly but does NOT call list_models() and assert its output field-by-field; VRAM filter path still untested |
| 14 | `_run_local_chat(…)` (local_transformers.py:565) | FAKE | NOT_RESOLVED | (text, usage) return structure never directly asserted in isolation |
| 15 | `_iter_local_stream(…)` (local_transformers.py:680) | FAKE | NOT_RESOLVED | Chunk accumulation and end-of-stream tool-call parse not tested in isolation |
| 16 | `_config_device_for(device)` (local_transformers.py:828) | NONE | NOT_RESOLVED | No test found |
| 17 | `_load_for_device(device,config)` (local_transformers.py:840) | FAKE | NOT_RESOLVED | Dispatch logic to XPU/CPU/CUDA loader not independently asserted |
| 18 | `_load_model_for_cuda(config)` (local_transformers.py:880) | NONE | NOT_RESOLVED | No test found; entire CUDA loading path invisible to suite |
| 19 | `_iter_local_generation_loop(…)` (local_transformers.py:1100) | FAKE | NOT_RESOLVED | temperature=0 argmax vs temperature>0 multinomial branch not independently tested |
| 20 | `_convert_tools_to_provider_format(tools)` LocalTransformers (local_transformers.py:1227) | WEAK | NOT_RESOLVED | Pre-existing test only covers empty list; non-empty tool list conversion output never verified |
| 21 | `ModelCache._make_key(model_id,dtype,device_type)` (model_loader.py:175) | FAKE | NOT_RESOLVED | No test directly asserts the `::` separator format; separator change would not break round-trip tests |
| 22 | `_free_model_resources(loaded_model)` (model_loader.py:213) | FAKE | NOT_RESOLVED | `del model_ref` + `gc.collect()` not independently verified; no test found |
| 23 | `_unload_model(loaded_model)` (model_loader.py:231) | FAKE | NOT_RESOLVED | Exception path (where `_free_model_resources` raises) never exercised |
| 24 | `_load_xpu_model_impl(config,cache,device,dtype)` (model_loader.py:486) | NONE | NOT_RESOLVED | No test found; int8/int4/bfloat16 paths, device-map selection, cache insertion all untested |
| 25 | `load_model_for_cpu(config,cache)` (model_loader.py:577) | WEAK | NOT_RESOLVED | e2e only via test_local_xpu_e2e.py; cache-miss and error paths not unit-tested |
| 26 | `_load_cpu_model_impl(config,cache,device,dtype)` (model_loader.py:638) | NONE direct | NOT_RESOLVED | No direct unit test; dtype/quantization for CPU not independently tested |
| 27 | `set_global_cache_size(max_memory_bytes)` (model_loader.py:822) | NONE | RESOLVED | `tests/test_ui/test_xpu_status.py:TestProviderConfigSettings::test_apply_cache_button_updates_global_cache_size` (line 1114) · Oracle: `test_mb * 1024 * 1024 = 3221225472 bytes` computed independently in test · Mutation: broken set_global_cache_size leaves max_memory_bytes at default, failing `actual_bytes == expected_bytes` |
| 28 | `RECOMMENDED_MODELS_B580` constant (model_loader.py:850) | WEAK | RESOLVED | `test_local_model_classify_wave2d.py:TestRecommendedModelsB580` (line 121) · Oracle: publicly documented HuggingFace model IDs, documented dtypes for 12 GB B580 VRAM · Mutation: dropping any of the 7 entries or changing model_id fails the parametrized `test_each_model_id_present`; changing Mistral dtype from "int8" fails `test_mistral_7b_uses_int8_dtype` |
| 29 | `_locate_devnode(cfg,device_id)` (gpu_pci_resources.py:87) | FAKE | NOT_RESOLVED | Successful devnode resolution vs CM_LOCATE_DEVNODE_NORMAL failure not independently asserted |
| 30 | `_read_descriptor_bytes(cfg,res_des)` (gpu_pci_resources.py:112) | FAKE | NOT_RESOLVED | Zero-size descriptor; `CM_Get_Res_Des_Data` error code not tested |
| 31 | `_enumerate_bars_for_log_conf(cfg,log_conf)` (gpu_pci_resources.py:197) | FAKE | NOT_RESOLVED | ResType_MEM vs ResType_MemLarge dispatch not independently exercised |
| 32 | `_get_device_name_from_sycl(device_index)` (xpu_utils.py:100) | NONE | NOT_RESOLVED | No test found |
| 33 | `_query_windows_gpus()` (xpu_utils.py:128) | FAKE | NOT_RESOLVED | Malformed JSON, empty stdout, subprocess failure paths not tested |
| 34 | `_strip_pwsh_payload(stdout)` (xpu_utils.py:165) | NONE | RESOLVED | `test_local_model_classify_wave2d.py:TestStripPwshPayload` (line 441) · Oracle: Unicode spec U+FEFF (BOM), documented PowerShell UTF-8-with-BOM behavior · Mutation: removing BOM-strip line causes `test_bom_prefix_removed_leaving_bare_json` to fail (`'{"key": 1}'` vs `'﻿{"key": 1}'`); `test_stripped_result_is_valid_json` fails `json.loads` with BOM prefix |
| 35 | `_extract_torch_xpu_properties(torch,device_index,device_name)` (xpu_utils.py:242) | FAKE | NOT_RESOLVED | Field extraction from `get_device_properties()` (total_memory, driver_version, name) not independently verified |
| 36 | `_enrich_from_windows_gpus(device_name,driver_version,device_id)` (xpu_utils.py:282) | NONE | NOT_RESOLVED | No test found; early-return (already-populated) and WMI enrichment paths absent |
| 37 | `_build_xpu_device_info(torch,device_index)` (xpu_utils.py:336) | FAKE | NOT_RESOLVED | XPUDeviceInfo field assembly from torch properties + WMI enrichment not independently tested |
| 38 | `_estimate_memory_from_name(device_name)` (xpu_utils.py:406) | NONE | RESOLVED | `test_local_model_classify_wave2d.py:TestEstimateMemoryFromName` (line 550) · Oracle: Intel Arc published VRAM specs (B580=12 GB, A770=16 GB, A750=8 GB, A380=6 GB, A310=4 GB) · Mutation: swapping B580 and A770 constants returns 17179869184 instead of 12884901888 for `"Intel Arc B580"`, failing `test_b580_distinguished_from_a770` |
| 39 | `clear_xpu_cache()` (xpu_utils.py:584) | NONE | NOT_RESOLVED | No test found |
| 40 | `_pick_primary_arc_gpu(gpus)` (xpu_utils.py:656) | NONE | NOT_RESOLVED | No test found anywhere in tests/ |
| 41 | `_check_intel_driver(gpus)` (xpu_utils.py:687) | NONE | NOT_RESOLVED | No test found anywhere in tests/ |
| 42 | `_validate_xpu_device(torch_mod,device)` (xpu_utils.py:514) | FAKE | NOT_RESOLVED | RuntimeError on tensor-op failure path not independently tested |
| 43 | `_query_xpu_memory(torch,device_index)` (xpu_utils.py:537) | FAKE | NOT_RESOLVED | Fallback to `get_xpu_device_info()` when `memory_allocated()` raises not tested |

**Section 10 sub-totals: resolved=5, red_by_design=0, not_resolved=38**

---

## Findings Table — Section 14 (UI App Shell)

| # | Operation (source:line) | Original verdict | Now | Evidence (test:line · oracle · mutation) |
|---|------------------------|-----------------|-----|------------------------------------------|
| 44 | `_resolve()` (_screen_compat.py:35) | NO COVERAGE | RESOLVED | `test_realcov_p3_ui_zero_coverage.py:TestScreenCompat::test_resolve_raises_attribute_error_for_absent_method` (line 941) and `test_resolve_error_message_contains_class_name` (line 952) · Oracle: Python AttributeError contract; documented message format `"{ClassName} has no method …"` · Mutation: replacing `raise AttributeError` with `return None` fails `pytest.raises(AttributeError, match="no method")` |
| 45 | `get_screen_geometry()` (_screen_compat.py:57) | NO COVERAGE | RESOLVED | `TestScreenCompat::test_get_screen_geometry_positive_dimensions` (line 906) · Oracle: any valid Qt screen always has non-zero dimensions · Mutation: returning `(0, 0, 0, 0)` fails `w > 0` |
| 46 | `move_widget()` (_screen_compat.py:78) | NO COVERAGE | RESOLVED | `TestScreenCompat::test_move_widget_sets_exact_position` (line 924) · Oracle: `QWidget.move(100, 200)` followed by `pos()` returns `(100, 200)` in offscreen mode · Mutation: swapping x/y arguments fails `pos.x() == 100` |
| 47 | `CSyntaxHighlighter.highlightBlock()` single-line rules (highlighter.py:223) | NO COVERAGE | RED_BY_DESIGN | `test_realcov_p3_ui_zero_coverage.py:TestCSyntaxHighlighter::test_single_line_comment_is_italic` correctly red: `//` comment loses italic because the operator rule `[+\-*/%&|^~<>=!]+` is registered after the comment rule and re-colors `//` as non-italic. PD-006. |
| 48 | `CSyntaxHighlighter.highlightBlock()` multi-line `/* */` state (highlighter.py:242) | NO COVERAGE | RESOLVED | `TestCSyntaxHighlighter::test_multiline_comment_open_sets_block_state_1` (line 432), `test_multiline_comment_continues_across_lines` (line 451), `test_multiline_comment_state_resets_after_close` (line 469) · Oracle: block-state constants 0=normal, 1=in-comment from documented `setCurrentBlockState` calls · Mutation: removing `setCurrentBlockState(1)` returns default state, fails `state == 1` |
| 49 | `AssemblySyntaxHighlighter.highlightBlock()` (highlighter.py:710) | NO COVERAGE | RESOLVED | `TestAssemblySyntaxHighlighter::test_instruction_mnemonic_has_instruction_color` (line 493), `test_register_has_register_color` (line 525), `test_semicolon_comment_is_italic` (line 538) · Oracle: color constants `#569CD6` (instruction), `#9CDCFE` (register) from `_create_format` definition · Mutation: removing 'mov' from INSTRUCTIONS fails color assertion |
| 50 | `PythonSyntaxHighlighter.highlightBlock()` + `_highlight_triple_quotes()` (highlighter.py:919) | NO COVERAGE | RED_BY_DESIGN | `TestPythonSyntaxHighlighter::test_keyword_def_has_keyword_color` (line 556) correctly red: `def` receives function color `#DCDCAA` instead of keyword color `#569CD6` because the `\bdef\s+(\w+)` rule is registered after the keyword rule and formats the full match (group 0). PD-006. Triple-quote state tests (`test_triple_double_quote_sets_block_state`, `test_triple_quote_continuation_receives_string_color`, etc.) pass. |
| 51 | `JavaScriptSyntaxHighlighter.highlightBlock()` multi-line state (highlighter.py:1153) | NO COVERAGE | RESOLVED | `TestJavaScriptSyntaxHighlighter::test_keyword_const_has_keyword_color` (line 728), `test_frida_global_process_has_frida_color` (line 742), `test_multiline_comment_js_sets_block_state_1` (line 763), `test_multiline_comment_js_continuation_receives_comment_color` (line 779) · Oracle: `#569CD6` keyword, `#4EC9B0` type/Frida, block state 1 · Mutation: removing 'const' from KEYWORDS fails color assertion |
| 52 | `HexPatSyntaxHighlighter.highlightBlock()` multi-line state (highlighter.py:1349) | NO COVERAGE | RESOLVED | `TestHexPatSyntaxHighlighter::test_keyword_struct_has_keyword_color` (line 662), `test_type_u8_has_type_color` (line 676), `test_multiline_comment_sets_block_state_1` (line 695), `test_multiline_comment_continuation_line_color` (line 711) · Oracle: `#569CD6` keyword, `#4EC9B0` type · Mutation: removing 'struct' from KEYWORDS fails color assertion |
| 53 | `get_highlighter_for_language()` dispatch (highlighter.py:1395) | NO COVERAGE | RESOLVED | `TestGetHighlighterForLanguage` — 9 tests covering 'c', 'cpp', 'asm', 'python', 'py', 'javascript', 'frida', 'hexpat', 'cobol' (line 795–877) · Oracle: factory return type is the independent contract · Mutation: returning `AssemblySyntaxHighlighter` for `"c"` fails `isinstance(h, CSyntaxHighlighter)` |
| 54 | `show_info()` structured log (dialogs_helpers.py:28) | WEAK | NOT_RESOLVED | `test_realcov_15_dialog_helpers_logging.py` covers `show_error` and `show_warning` only; no test for `show_info` log emission. Deleting `_logger.info(…)` in `show_info` leaves all tests green. Missing: call `show_info(…)`, parse JSON-Lines output, assert `event == "dialog_info"` with `level == "INFO"` |
| 55 | `AppearanceSettingsWidget.get_settings()` (preferences.py:278) | NO COVERAGE | NOT_RESOLVED | No test found in tests/. Deleting `AppearanceSettingsWidget.get_settings()` or having it return `{}` breaks nothing. `_build_config()` Appearance branch executes zero times. Missing: set font_size=14, theme="light", accept, assert `emitted.ui.font_size == 14` |
| 56 | `SessionSettingsWidget.get_settings()` (preferences.py:349) | NO COVERAGE | NOT_RESOLVED | No test found in tests/. Missing: set auto_save=False, interval=120, retention=7, accept, assert `emitted.session.auto_save is False` |
| 57 | `_FlowLayout` tag-chip flow wrapping (session_manager.py:64) | NO COVERAGE | NOT_RESOLVED | No test found anywhere in tests/ (confirmed via rg). Missing: add N buttons to `_FlowLayout` in a narrow container, assert `heightForWidth(narrow) > single_row_height` |
| 58 | `XPUStatusDialog` construction group-box existence checks (xpu_status.py:~122) | WEAK | NOT_RESOLVED | Nine tests at test_xpu_status.py:122-232 still only verify widget existence and types (group box count, button presence, etc.). Deleting `_refresh_device_info()` or silently wrong label text leaves all construction tests green. Missing: assert label text content after `_refresh_device_info` with a known input |
| 59 | `main.py` bootstrap — arg parsing, logging setup, bridge init (main.py) | NO COVERAGE | NOT_RESOLVED | No test_main.py found. Missing: `parse_args(["--log-dir", str(tmp_path)])` asserts `namespace.log_dir == Path(tmp_path)` |
| 60 | `__main__.py` entry point (__main__.py) | NO COVERAGE | NOT_RESOLVED | No test found. Missing: invoke `python -m intellicrack --help` and assert exit code 0 |

**Section 14 sub-totals: resolved=8, red_by_design=2, not_resolved=7**

---

## STILL OPEN

### Section 10 — Not Resolved (38 findings)

- `_hf_status_code(exc)` (huggingface.py:57) :: No test calls function and asserts extracted int :: `assert _hf_status_code(make_hf_exc(503)) == 503`
- `_close_client()` (huggingface.py:202) :: No verification of client release :: `assert provider._client is None` after `_close_client()`
- `disconnect()` (huggingface.py:211) :: Only asserts `is_connected is False`; client/flag release unverified :: `assert provider._cancel_requested is False` after disconnect
- `_prepare_request_payload(messages,tools,tool_choice)` (huggingface.py:378) :: No test exists :: construct ChatMessage list, assert exact SDK-format dict field-by-field
- `_consume_stream_chunks(raw_stream,model,tc_buffer)` (huggingface.py:542) :: No unit-level test :: build a synthetic async iterator of chunk objects, assert exact ToolCallBufferManager accumulation
- `chat_stream(messages,model,…)` HuggingFaceProvider (huggingface.py:619) :: No test without live API token :: use respx to intercept httpx; assert at least one chunk yielded and stream ends cleanly
- `cancel_request()` HuggingFaceProvider (huggingface.py:676) :: test_realcov_10_cancel_request.py covers Anthropic/Grok only :: assert `provider._cancel_requested is True` after call; assert in-flight stream aborts
- `_convert_messages_to_provider_format(messages)` (huggingface.py:690) :: Output format never asserted :: call with known Message list; assert exact SDK-format list role/content field-by-field
- `_convert_tools_to_provider_format(tools)` HuggingFaceProvider (huggingface.py:725) :: No test exists :: construct ToolDefinition list; assert OpenAI-format dict with `type=="function"` and correct `name`/`description`/`parameters`
- `_fetch_model_config(model_id)` (local_transformers.py:119) :: No test for any branch :: use respx to return 200 JSON, 404, httpx.ConnectError; assert correct `{}` / parsed dict results
- `_release_device_caches()` (local_transformers.py:397) :: No test found :: monkeypatch `torch.xpu.empty_cache` and `gc.collect`; assert each called once
- `list_models()` LocalTransformersProvider (local_transformers.py:415) :: Pre-existing test still uses `any("phi" or "tiny")` substring :: call `list_models()` and assert all 7 expected model_ids appear by exact match
- `_run_local_chat(…)` (local_transformers.py:565) :: Return structure never asserted in isolation :: call with known prompt; assert `(text, usage)` tuple where `len(text) > 0` and `usage.input_tokens == known_count`
- `_iter_local_stream(…)` (local_transformers.py:680) :: Chunk accumulation not tested :: call with a real tokenizer; assert chunks combine to full expected text
- `_config_device_for(device)` (local_transformers.py:828) :: No test exists :: `assert _config_device_for("xpu").device == "xpu"`; `assert _config_device_for("other").device == "cpu"`
- `_load_for_device(device,config)` (local_transformers.py:840) :: Dispatch not independently asserted :: parametrize device=xpu/cuda/cpu; assert correct loader called (monkeypatch loader, not SUT dispatch)
- `_load_model_for_cuda(config)` (local_transformers.py:880) :: No test exists :: on a machine where CUDA unavailable, assert `RuntimeError`/`ProviderError` raised with CUDA in message
- `_iter_local_generation_loop(…)` (local_transformers.py:1100) :: temperature branch not tested :: temperature=0 must produce argmax token; temperature>0 must use multinomial
- `_convert_tools_to_provider_format(tools)` LocalTransformers (local_transformers.py:1227) :: Non-empty list never verified :: construct ToolDefinition; assert output dict has correct `name`/`description`/`parameters` keys
- `ModelCache._make_key(model_id,dtype,device_type)` (model_loader.py:175) :: Key format not pinned :: `assert ModelCache._make_key("m","float16","xpu") == "m::float16::xpu"`
- `_free_model_resources(loaded_model)` (model_loader.py:213) :: gc.collect/del not verified :: monkeypatch `gc.collect`; assert called once; assert model_ref deleted
- `_unload_model(loaded_model)` (model_loader.py:231) :: Exception path never exercised :: patch `_free_model_resources` to raise; assert error logged and not re-raised
- `_load_xpu_model_impl(config,cache,device,dtype)` (model_loader.py:486) :: No test exists :: on non-XPU machine, assert path raises informatively; on XPU machine, assert cache insertion
- `load_model_for_cpu(config,cache)` (model_loader.py:577) :: e2e only :: unit-test cache-miss path; assert model inserted in cache with correct key
- `_load_cpu_model_impl(config,cache,device,dtype)` (model_loader.py:638) :: No direct unit test :: parametrize dtype=float32/int8/int4; assert each produces correct quantization config
- `_locate_devnode(cfg,device_id)` (gpu_pci_resources.py:87) :: Success vs failure not independently asserted :: mock cfgmgr32; assert correct DEVINST or ToolError
- `_read_descriptor_bytes(cfg,res_des)` (gpu_pci_resources.py:112) :: Zero-size and error-code paths untested :: mock CM_Get_Res_Des_Data to return error; assert empty bytes returned
- `_enumerate_bars_for_log_conf(cfg,log_conf)` (gpu_pci_resources.py:197) :: ResType dispatch not exercised :: mock ResType_MemLarge; assert 64-bit descriptor parsed
- `_get_device_name_from_sycl(device_index)` (xpu_utils.py:100) :: No test found :: assert `_get_device_name_from_sycl(0)` returns non-empty str when XPU present; assert empty/None when index out of range
- `_query_windows_gpus()` (xpu_utils.py:128) :: Malformed JSON / subprocess failure untested :: monkeypatch subprocess.run; assert empty list returned for stderr or malformed JSON; no exception propagates
- `_extract_torch_xpu_properties(torch,device_index,device_name)` (xpu_utils.py:242) :: Field extraction not verified :: mock `torch.xpu.get_device_properties`; assert `total_memory`, `driver_version`, `name` fields appear in returned dict at exact values
- `_enrich_from_windows_gpus(device_name,driver_version,device_id)` (xpu_utils.py:282) :: No test found :: construct GPU dict; assert early-return when already populated; assert WMI enrichment path fills missing fields
- `_build_xpu_device_info(torch,device_index)` (xpu_utils.py:336) :: Field assembly not tested :: assert returned XPUDeviceInfo has correct `total_memory` and `name` fields matching mocked device_properties
- `clear_xpu_cache()` (xpu_utils.py:584) :: No test found :: on no-XPU machine, assert no-op (no exception); on XPU machine, assert `torch.xpu.empty_cache()` called once
- `_pick_primary_arc_gpu(gpus)` (xpu_utils.py:656) :: No test found :: `assert _pick_primary_arc_gpu([b580_dict, a770_dict]) == b580_dict` where b580 has larger BAR
- `_check_intel_driver(gpus)` (xpu_utils.py:687) :: No test found :: `assert _check_intel_driver([{…, "driver_version":"31.0.101.5522"}]) is True`; `assert _check_intel_driver([{…, "driver_version":""}]) is False`
- `_validate_xpu_device(torch_mod,device)` (xpu_utils.py:514) :: RuntimeError path not tested :: patch tensor op to raise RuntimeError; assert function re-raises or wraps as ProviderError
- `_query_xpu_memory(torch,device_index)` (xpu_utils.py:537) :: Fallback path not tested :: patch `memory_allocated()` to raise; assert fallback to `get_xpu_device_info()` fires

### Section 14 — Not Resolved (7 findings)

- `show_info()` structured log (dialogs_helpers.py:28) :: test_realcov_15_dialog_helpers_logging.py covers show_error/show_warning only :: call show_info with a real structlog file handler; parse JSON-Lines; assert `event == "dialog_info"` with `level == "INFO"`
- `AppearanceSettingsWidget.get_settings()` (preferences.py:278) :: No test exists :: configure font_size=14 in widget; accept; assert `emitted.ui.font_size == 14`
- `SessionSettingsWidget.get_settings()` (preferences.py:349) :: No test exists :: configure auto_save=False; accept; assert `emitted.session.auto_save is False`
- `_FlowLayout` tag-chip flow wrapping (session_manager.py:64) :: No test found in tests/ :: add N buttons to `_FlowLayout` in narrow container; assert `heightForWidth(narrow) > single_row_height`
- XPUStatusDialog construction checks (xpu_status.py:~122) :: Nine tests still only check widget existence, not behavioral correctness :: assert label text after `_refresh_device_info()` with known XPUDeviceInfo input
- `main.py` bootstrap (main.py) :: No test_main.py exists :: `parse_args(["--log-dir", str(tmp_path)])` asserts `namespace.log_dir == Path(tmp_path)`
- `__main__.py` entry point (__main__.py) :: No test exists :: invoke entry point and assert import completes without error

---

## Falsifiability Spot-Checks (Claimed RESOLVED)

| Finding | Test | Mutation that turns it red |
|---------|------|---------------------------|
| `_classify_model_capabilities` priority | `test_max_position_embeddings_wins_over_max_sequence_length` (line 254) | Swapping key priority returns 2048 instead of 8192 |
| `_classify_model_capabilities` vision | `test_vision_config_key_triggers_vision` (line 373) | Removing `vision_config` check returns False for llava config |
| `_strip_pwsh_payload` BOM strip | `test_bom_prefix_removed_leaving_bare_json` (line 449) | Removing `lstrip("﻿")` returns `'﻿{"key": 1}'` ≠ `'{"key": 1}'` |
| `_estimate_memory_from_name` B580 | `test_b580_distinguished_from_a770` (line 583) | Swapping B580/A770 constants returns 17179869184 ≠ 12884901888 |
| `RECOMMENDED_MODELS_B580` entries | `test_each_model_id_present` parametrized (line 135) | Dropping any entry fails its parametrize row |
| `set_global_cache_size` | `test_apply_cache_button_updates_global_cache_size` (line 1114) | Broken implementation leaves max_memory_bytes unchanged, fails `== expected_bytes` |
| `_resolve()` raises | `test_resolve_raises_attribute_error_for_absent_method` (line 941) | Returning None instead of raising fails `pytest.raises` |
| `move_widget()` exact position | `test_move_widget_sets_exact_position` (line 924) | Swapping x/y fails `pos.x() == 100` |
| C multiline comment state | `test_multiline_comment_open_sets_block_state_1` (line 432) | Removing `setCurrentBlockState(1)` returns -1, fails `state == 1` |
| Assembly instruction color | `test_instruction_mnemonic_has_instruction_color` (line 493) | Removing 'mov' from INSTRUCTIONS returns None color, fails `color == '#569CD6'` |
| JS block-comment state | `test_multiline_comment_js_sets_block_state_1` (line 763) | Removing state-set call fails `state == 1` |
| HexPat block-comment state | `test_multiline_comment_sets_block_state_1` (line 695) | Same as above |
| `get_highlighter_for_language("c")` | `test_c_language_returns_c_highlighter` (line 800) | Returning `AssemblySyntaxHighlighter` fails `isinstance(h, CSyntaxHighlighter)` |
| `get_highlighter_for_language("cobol")` | `test_unknown_language_returns_none` (line 871) | Returning a default highlighter instead of None fails `h is None` |
