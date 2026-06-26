# Section 10 — Local AI Models & GPU/Accel: Test Coverage Audit

**Audited files**

| Source file | LOC |
|---|---|
| `src/intellicrack/providers/huggingface.py` | 984 |
| `src/intellicrack/providers/local_transformers.py` | 1621 |
| `src/intellicrack/providers/model_loader.py` | 900 |
| `src/intellicrack/providers/gpu_pci_resources.py` | 265 |
| `src/intellicrack/providers/xpu_utils.py` | 813 |

**Test files consulted**

- `tests/test_providers/test_huggingface_provider.py`
- `tests/test_providers/test_local_transformers_provider.py`
- `tests/test_providers/test_providers_local_audit1.py`
- `tests/test_providers/test_realcov_11_gpu_pci.py`
- `tests/test_providers/test_realcov_11_huggingface_logic.py`
- `tests/test_providers/test_realcov_11_local_transformers_logic.py`
- `tests/test_providers/test_realcov_11_model_loader.py`
- `tests/test_providers/test_realcov_11_xpu_utils.py`
- `tests/test_providers/test_local_xpu_e2e.py`
- `tests/test_providers/test_local_transformers_live.py`

---

## Operation Inventory

Verdicts: **REAL** = falsifiable gate; **WEAK** = exists but assertions are too broad to catch real breakage; **FAKE** = test present but cannot fail when production code is broken; **NONE** = no coverage at all.

### huggingface.py

| Operation | Source file approx. line | Test file:approx. line | Verdict | Missing edges |
|---|---|---|---|---|
| `_hf_status_code(exc)` | huggingface.py:57 | None — only an indirect callsite inside `connect()` that catches results | FAKE | No assertion on the extracted int vs a known HTTP code; status extraction regressing to `None` would not fail any test |
| `_extract_503_message(exc)` | huggingface.py:70 | test_realcov_11_huggingface_logic.py:TestExtract503Message | REAL | Missing: exception whose response has a JSON body with an unexpected schema key |
| `HuggingFaceProvider.__init__` | huggingface.py:113 | test_huggingface_provider.py:TestHuggingFaceConnection | REAL | Trivial; adequately covered |
| `connect(credentials)` | huggingface.py:147 | test_huggingface_provider.py:TestHuggingFaceConnection | REAL | Invalid non-empty key (401 response) not tested at unit level; connection timeout not tested; 503 during whoami probe not tested |
| `_close_client()` | huggingface.py:202 | Indirectly via `disconnect()`; no assertion on client cleanup | FAKE | Whether the underlying `AsyncInferenceClient` is actually released is never verified |
| `disconnect()` | huggingface.py:211 | test_huggingface_provider.py:TestHuggingFaceConnection | WEAK | Only asserts `is_connected is False`; client reference release and `_cancel_requested` reset not verified |
| `list_models()` | huggingface.py:222 | test_huggingface_provider.py:TestHuggingFaceModelListing | REAL (live) | Warm-model filter and VRAM filter logic not unit-tested in isolation; gated behind live HF API token |
| `_build_model_info_list(raw_models)` | huggingface.py:291 | test_realcov_11_huggingface_logic.py:TestBuildModelInfoList | REAL | Missing: model with zero tags; model with an unsupported-combination tag; dedup when IDs differ only in case |
| `_prepare_request_payload(messages, tools, tool_choice)` | huggingface.py:378 | None | NONE | Full conversion chain (message roles, tool schemas, tool_choice wiring into SDK) has no unit test |
| `chat(messages, model, ...)` | huggingface.py:476 | test_realcov_11_huggingface_logic.py:TestHuggingFaceLiveChat | REAL (live) | Error paths: 429 rate-limit, 401 with bad key, request timeout — none tested at unit level |
| `_consume_stream_chunks(raw_stream, model, tc_buffer)` | huggingface.py:542 | None | NONE | ToolCallBufferManager accumulation across multiple deltas has no unit-level test; only reachable via live API |
| `chat_stream(messages, model, ...)` | huggingface.py:619 | None | NONE | No dedicated test; `_cancel_requested=True` mid-stream path untested |
| `cancel_request()` | huggingface.py:676 | Not confirmed present in any enumerated test file | NONE (unconfirmed) | Flag mutation and its effect on in-flight generation not tested |
| `_convert_messages_to_provider_format(messages)` | huggingface.py:690 | None that directly asserts output format | FAKE | Called inside `chat()` live tests but output format never directly asserted |
| `_convert_tools_to_provider_format(tools)` | huggingface.py:725 | None | NONE | OpenAI-schema output for HuggingFace SDK never verified independently |
| `_convert_tool_choice(tool_choice)` | huggingface.py:764 | test_realcov_11_huggingface_logic.py:TestConvertToolChoice | REAL | All four modes covered (AUTO, NONE, REQUIRED, SPECIFIC) |
| `_parse_message_tool_calls(response_message)` | huggingface.py:800 | test_realcov_11_huggingface_logic.py:TestParseMessageToolCalls | REAL | Missing: malformed arguments JSON in tool call; partial tool call with missing `id` |
| `_extract_stream_delta(chunk)` | huggingface.py:841 | test_realcov_11_huggingface_logic.py:TestExtractStreamDelta | REAL | Missing: chunk carrying multiple tool-call updates; finish_reason propagation |
| `name` property | huggingface.py:111 | test_huggingface_provider.py:TestHuggingFaceConnection | REAL | Trivial |

**huggingface.py score: 10 REAL / 19 operations = 53 %**

---

### local_transformers.py

| Operation | Source file approx. line | Test file:approx. line | Verdict | Missing edges |
|---|---|---|---|---|
| `_fetch_model_config(model_id)` | local_transformers.py:119 | None | NONE | Network failure returns `{}`; 404 returns `{}`; malformed JSON returns `{}`; success returns parsed dict — none of these four branches tested |
| `_classify_model_capabilities(config)` | local_transformers.py:142 | None | NONE | Priority order of `max_position_embeddings` > `max_sequence_length` > `n_positions` not tested; vision detection via `architectures`, `vision_config`, `image_size` keys not tested; empty config → default 4096 not tested |
| `LocalTransformersProvider.__init__` | local_transformers.py:182 | test_local_transformers_provider.py:TestProviderInit | REAL | - |
| `name` property | local_transformers.py:240 | test_local_transformers_provider.py:TestProviderInit | REAL | trivial |
| `connect(credentials)` | local_transformers.py:249 | test_local_transformers_provider.py:TestProviderConnection | REAL | - |
| `_select_device()` | local_transformers.py:302 | test_realcov_11_local_transformers_logic.py | REAL | - |
| `_probe_cuda()` | local_transformers.py:335 | test_realcov_11_local_transformers_logic.py | REAL | - |
| `_cuda_device_count()` | local_transformers.py:354 | test_realcov_11_local_transformers_logic.py | REAL | - |
| `disconnect()` | local_transformers.py:367 | test_local_transformers_provider.py:TestProviderConnection | REAL | `_release_device_caches` side-effects not verified |
| `_release_device_caches()` | local_transformers.py:397 | None | NONE | XPU `empty_cache`, CUDA `empty_cache`, and `gc.collect` calls not verified independently |
| `list_models()` | local_transformers.py:415 | test_local_transformers_provider.py:TestModelListing | WEAK | Model ID match `any("phi" or "tiny")` is the only discriminating check; VRAM filter path not tested; `_classify_model_capabilities` output not verified; none of the 7 `RECOMMENDED_MODELS_B580` entries confirmed present by ID |
| `chat(messages, model, ...)` | local_transformers.py:504 | test_local_xpu_e2e.py; test_local_transformers_live.py | REAL (e2e) | OOM during model load not tested; fallback-chain execution not observed |
| `_run_local_chat(...)` | local_transformers.py:565 | Indirectly via `chat()` e2e | FAKE | (text, usage) return structure never directly asserted in isolation |
| `chat_stream(messages, model, ...)` | local_transformers.py:620 | test_local_xpu_e2e.py | REAL (e2e) | - |
| `_iter_local_stream(...)` | local_transformers.py:680 | Indirectly via `chat_stream()` e2e | FAKE | Chunk accumulation and end-of-stream tool call parse not tested in isolation |
| `_ensure_model_loaded(model_id)` | local_transformers.py:740 | test_local_xpu_e2e.py | REAL (e2e, happy path) | Device fallback chain (CUDA→CPU, XPU→CPU) when primary device raises is never exercised by any test |
| `_config_device_for(device)` | local_transformers.py:828 | None | NONE | `"xpu"` → `ModelConfig.device="xpu"`; other → `"cpu"` mapping not tested |
| `_load_for_device(device, config)` | local_transformers.py:840 | Indirectly via `_ensure_model_loaded` | FAKE | Dispatch logic to XPU/CPU/CUDA loader not independently asserted |
| `_fallback_chain_for(current)` | local_transformers.py:870 | test_realcov_11_local_transformers_logic.py | REAL | - |
| `_load_model_for_cuda(config)` | local_transformers.py:880 | None | NONE | Entire CUDA model-loading path untested; BitsAndBytesConfig for CUDA quantization not tested |
| `_generate_sync(prompt, temperature, max_tokens)` | local_transformers.py:957 | test_local_xpu_e2e.py; test_local_transformers_live.py | REAL (e2e) | `_loaded_model is None` branch; `_torch is None` branch; context-length truncation not verified |
| `_stream_generate(prompt, temperature, max_tokens)` | local_transformers.py:1032 | test_local_xpu_e2e.py | REAL (e2e) | `_cancel_requested=True` mid-generation path not tested |
| `_iter_local_generation_loop(...)` | local_transformers.py:1100 | Indirectly via streaming e2e | FAKE | temperature=0 → argmax vs temperature>0 → softmax+multinomial branch not independently tested |
| `_convert_messages_to_provider_format(messages)` | local_transformers.py:1170 | test_local_transformers_provider.py:TestMessageConversion | REAL | - |
| `_convert_tools_to_provider_format(tools)` | local_transformers.py:1227 | test_local_transformers_provider.py (empty list only) | WEAK | Non-empty tool list conversion output never verified |
| `_format_prompt(messages, tools)` | local_transformers.py:1243 | test_local_transformers_provider.py:TestPromptFormatting | REAL | - |
| `_build_chat_messages(messages, tools)` | local_transformers.py:1275 | test_realcov_11_local_transformers_logic.py | REAL | - |
| `_format_prompt_chatml_fallback(chat_messages)` | local_transformers.py:1355 | test_realcov_11_local_transformers_logic.py | REAL | - |
| `_find_tool_call_start(response)` | local_transformers.py:1389 | test_realcov_11_local_transformers_logic.py | REAL | - |
| `_parse_tool_calls(response)` | local_transformers.py:1415 | test_realcov_11_local_transformers_logic.py | REAL | - |
| `_build_tool_call_from_json(json_str)` | local_transformers.py:1479 | test_realcov_11_local_transformers_logic.py | REAL | - |
| `_extract_text_before_tool_call(response)` | local_transformers.py:1521 | test_realcov_11_local_transformers_logic.py | REAL | - |
| `get_device_info()` | local_transformers.py:1539 | test_realcov_11_local_transformers_logic.py + test_local_transformers_provider.py | REAL | XPU info path not exercised on non-XPU hardware in unit tests |
| `unload_model()` | local_transformers.py:1582 | test_local_transformers_provider.py:TestModelLifecycle | REAL | - |
| `clear_cache()` | local_transformers.py:1602 | test_local_transformers_provider.py:TestCacheManagement | REAL | - |

**local_transformers.py score: 24 REAL / 35 operations = 69 %**

---

### model_loader.py

| Operation | Source file approx. line | Test file:approx. line | Verdict | Missing edges |
|---|---|---|---|---|
| `ModelCache.__init__` | model_loader.py:68 | test_realcov_11_model_loader.py | REAL | - |
| `ModelCache.get(model_id, dtype, device_type)` | model_loader.py:84 | test_realcov_11_model_loader.py | REAL | - |
| `ModelCache.put(loaded_model)` | model_loader.py:105 | test_realcov_11_model_loader.py | REAL | - |
| `ModelCache.remove(model_id, dtype, device_type)` | model_loader.py:129 | test_realcov_11_model_loader.py | REAL | - |
| `ModelCache.clear()` | model_loader.py:150 | test_realcov_11_model_loader.py | REAL | - |
| `ModelCache.get_memory_usage()` | model_loader.py:165 | test_realcov_11_model_loader.py | REAL | - |
| `ModelCache._make_key(model_id, dtype, device_type)` | model_loader.py:175 | Indirectly via `get`/`put` | FAKE | Key format (double-colon separator) not directly asserted; a separator change would not break the round-trip tests |
| `ModelCache._evict_to_fit(required_bytes)` | model_loader.py:187 | test_realcov_11_model_loader.py | REAL | LRU ordering under concurrent access not tested (RLock is acquired but concurrency itself is not exercised) |
| `_free_model_resources(loaded_model)` | model_loader.py:213 | Indirectly via `ModelCache.clear()` | FAKE | `del model_ref` + `gc.collect()` not independently verified; error-handling path in `_unload_model` not tested |
| `_unload_model(loaded_model)` | model_loader.py:231 | Indirectly via `ModelCache` | FAKE | Exception path inside `_unload_model` (where `_free_model_resources` raises) is never exercised |
| `estimate_model_memory(model_id, dtype, include_activations)` | model_loader.py:248 | test_realcov_11_model_loader.py | REAL | - |
| `_estimate_parameter_count(model_id)` | model_loader.py:292 | test_realcov_11_model_loader.py | REAL | - |
| `select_dtype_for_memory(model_id, available_memory_bytes, preferred_dtype)` | model_loader.py:362 | test_realcov_11_model_loader.py | REAL | - |
| `load_model_for_xpu(config, cache)` | model_loader.py:422 | test_realcov_11_model_loader.py (error path only) | REAL (partial) | Happy path unreachable without XPU hardware; `BitsAndBytesConfig` import failure not tested |
| `_load_xpu_model_impl(config, cache, device, dtype)` | model_loader.py:486 | None | NONE | int8 and int4 quantization path on XPU; model-to-device transfer; cache insertion — all completely untested |
| `load_model_for_cpu(config, cache)` | model_loader.py:577 | test_local_xpu_e2e.py | WEAK | e2e only; cache-miss path and error path not unit-tested |
| `_load_cpu_model_impl(config, cache, device, dtype)` | model_loader.py:638 | Indirectly via e2e only | NONE direct | dtype selection inside CPU loader; float32 vs int8/int4 for CPU not independently tested |
| `_get_torch_dtype(dtype_str)` | model_loader.py:737 | test_realcov_11_model_loader.py | REAL | - |
| `_get_quantization_config(dtype_str)` | model_loader.py:766 | test_realcov_11_model_loader.py | REAL | - |
| `get_global_model_cache()` | model_loader.py:804 | Indirectly via `clear_cache()` in test_local_transformers_provider.py | REAL | Singleton identity (same object returned on repeated calls) not verified |
| `set_global_cache_size(max_memory_bytes)` | model_loader.py:822 | None | NONE | Completely untested; the global cache `max_memory_bytes` mutation and its effect on eviction not verified |
| `clear_global_cache()` | model_loader.py:838 | test_local_transformers_provider.py:TestCacheManagement (via `clear_cache()`) | REAL | - |
| `RECOMMENDED_MODELS_B580` constant | model_loader.py:850 | test_local_transformers_provider.py (only presence of "phi" or "tiny") | WEAK | Seven specific entries with `model_id`, `description`, `recommended_dtype`, `estimated_memory_gb` fields not individually verified |

**model_loader.py score: 16 REAL / 23 operations = 70 %**

---

### gpu_pci_resources.py

| Operation | Source file approx. line | Test file:approx. line | Verdict | Missing edges |
|---|---|---|---|---|
| `_load_cfgmgr()` | gpu_pci_resources.py:40 | test_realcov_11_gpu_pci.py:TestLoadCfgmgr | REAL | OSError path (cfgmgr32 fails to load on Windows) not tested |
| `_locate_devnode(cfg, device_id)` | gpu_pci_resources.py:87 | Indirectly via `enumerate_pci_memory_bars()` | FAKE | Successful devnode resolution vs CM_LOCATE_DEVNODE_NORMAL failure not independently asserted |
| `_read_descriptor_bytes(cfg, res_des)` | gpu_pci_resources.py:112 | Indirectly via `enumerate_pci_memory_bars()` | FAKE | Zero-size descriptor; `CM_Get_Res_Des_Data` returning an error code not tested |
| `_parse_mem_descriptor(data, large)` | gpu_pci_resources.py:140 | test_realcov_11_gpu_pci.py:TestParseMemDescriptor | REAL | Both large (uint64) and small (uint32) encodings tested at exact field offsets |
| `_enumerate_bars_for_log_conf(cfg, log_conf)` | gpu_pci_resources.py:197 | Indirectly via `enumerate_pci_memory_bars()` | FAKE | ResType_MEM vs ResType_MemLarge dispatch not independently exercised |
| `enumerate_pci_memory_bars(device_id)` | gpu_pci_resources.py:232 | test_realcov_11_gpu_pci.py:TestEnumeratePciMemoryBars | REAL | Real hardware + nonexistent device + off-Windows paths all covered |
| `max_memory_bar_bytes(device_id)` | gpu_pci_resources.py:254 | test_realcov_11_gpu_pci.py:TestEnumeratePciMemoryBars | REAL | Verified against `max(b.size_bytes for b in bars)`; empty-list → 0 checked |

**gpu_pci_resources.py score: 4 REAL / 7 operations = 57 %**

---

### xpu_utils.py

| Operation | Source file approx. line | Test file:approx. line | Verdict | Missing edges |
|---|---|---|---|---|
| `is_xpu_available()` | xpu_utils.py:68 | test_realcov_11_xpu_utils.py:TestXpuDetection | REAL | - |
| `get_xpu_device_count()` | xpu_utils.py:84 | test_realcov_11_xpu_utils.py:TestXpuDetection | REAL | - |
| `_get_device_name_from_sycl(device_index)` | xpu_utils.py:100 | None | NONE | SYCL name extraction from `torch.xpu.get_device_name()` not tested; index out-of-range behavior not tested |
| `_query_windows_gpus()` | xpu_utils.py:128 | Indirectly via `_get_windows_gpu_info()` | FAKE | Malformed JSON from PowerShell not tested; empty stdout not tested; subprocess failure not tested |
| `_strip_pwsh_payload(stdout)` | xpu_utils.py:165 | None | NONE | BOM (`﻿`) stripping not tested; whitespace-only input not tested; non-BOM input passthrough not tested |
| `_get_windows_gpu_info()` | xpu_utils.py:180 | test_realcov_11_xpu_utils.py:TestWindowsGpuEnumeration | REAL | Error path when subprocess fails not tested |
| `_parse_device_id_from_pnp(pnp_id)` | xpu_utils.py:212 | test_realcov_11_gpu_pci.py:TestParseDeviceIdFromPnp + test_providers_local_audit1.py:F-0001 | REAL | - |
| `_extract_torch_xpu_properties(torch, device_index, device_name)` | xpu_utils.py:242 | Indirectly via `get_xpu_device_info(0)` | FAKE | `total_memory`, `driver_version`, `name` field extraction from `get_device_properties()` not independently verified |
| `_enrich_from_windows_gpus(device_name, driver_version, device_id)` | xpu_utils.py:282 | None | NONE | Early-return (name + driver already present) path not tested; WMI enrichment for missing fields not tested |
| `_build_xpu_device_info(torch, device_index)` | xpu_utils.py:336 | Indirectly via `get_xpu_device_info()` | FAKE | Assembly of `XPUDeviceInfo` fields from torch properties + WMI enrichment not independently tested |
| `get_xpu_device_info(device_index)` | xpu_utils.py:386 | test_realcov_11_xpu_utils.py:TestXpuDeviceInfo | REAL | - |
| `_estimate_memory_from_name(device_name)` | xpu_utils.py:406 | None | NONE | b580→12 GB, a770→16 GB, a750→8 GB, a380→6 GB, a310→4 GB, unknown→8 GB — none of the six branches tested |
| `_is_b580_device(device_name, device_id)` | xpu_utils.py:436 | test_providers_local_audit1.py:F-0001 | REAL | Boundary case E20C ≠ B580; name-only path; ID-only path |
| `is_arc_b580()` | xpu_utils.py:464 | test_realcov_11_xpu_utils.py:TestXpuDetection | REAL | - |
| `initialize_xpu(device_index)` | xpu_utils.py:493 | test_realcov_11_xpu_utils.py:TestInitializeXpu | REAL | - |
| `_validate_xpu_device(torch_mod, device)` | xpu_utils.py:514 | Indirectly via `initialize_xpu()` | FAKE | RuntimeError on tensor-op failure path not independently tested |
| `_query_xpu_memory(torch, device_index)` | xpu_utils.py:537 | Indirectly via `get_xpu_memory_info()` | FAKE | Fallback to `get_xpu_device_info()` when `memory_allocated()` raises not tested |
| `get_xpu_memory_info(device_index)` | xpu_utils.py:562 | test_realcov_11_xpu_utils.py:TestXpuMemoryInfo | REAL | - |
| `clear_xpu_cache()` | xpu_utils.py:584 | None | NONE | `torch.xpu.empty_cache()` invocation not verified; no-XPU guard path not tested |
| `check_windows_requirements()` | xpu_utils.py:598 | test_realcov_11_xpu_utils.py:TestWindowsRequirements | REAL | Internal breakdown: Windows version check, driver check, ReBAR check not individually verified; warning string content not asserted |
| `_pick_primary_arc_gpu(gpus)` | xpu_utils.py:656 | None | NONE | Multi-GPU disambiguation by largest BAR not tested; single-GPU list not tested; empty list not tested |
| `_check_intel_driver(gpus)` | xpu_utils.py:687 | None | NONE | Driver-present, driver-absent, and driver-empty-string paths not tested |
| `_check_rebar_status(gpus)` | xpu_utils.py:714 | test_providers_local_audit1.py:F-0007 | REAL | 12 GB BAR → enabled; 256 MB BAR → disabled; zero data → indeterminate warning; no Intel Arc → (False, "") |
| `get_optimal_dtype_for_xpu()` | xpu_utils.py:753 | test_realcov_11_xpu_utils.py:TestOptimalDtype | REAL | - |

**xpu_utils.py score: 14 REAL / 24 operations = 58 %**

---

## Section Scores

| File | REAL gates | Total operations | Gate coverage |
|---|---|---|---|
| `huggingface.py` | 10 | 19 | **53 %** |
| `local_transformers.py` | 24 | 35 | **69 %** |
| `model_loader.py` | 16 | 23 | **70 %** |
| `gpu_pci_resources.py` | 4 | 7 | **57 %** |
| `xpu_utils.py` | 14 | 24 | **58 %** |
| **Section 10 total** | **68** | **108** | **63 %** |

**Edge-case coverage score: ~48 %**. Approximate denominator is the set of operations that are tested at all and that have identifiable edge cases worth exercising. The operations that do have unit tests are generally well-exercised (five cases for `_extract_503_message`, both MEM and MEM_LARGE layouts for `_parse_mem_descriptor`, five eviction scenarios for `ModelCache`). The score is depressed by the large number of operations (primarily the internal dispatch helpers and the Windows enrichment pipeline) that are entirely untested, leaving every edge case of those operations at zero.

**85 % gate target: NOT MET** (section 10 reaches 63 % gate coverage).

---

## Worst Offenders

### 1. `_fetch_model_config` + `_classify_model_capabilities` — local_transformers.py:119 and 142

Neither function has any test. `_classify_model_capabilities` is the sole source of context-window and vision-capability data surfaced in every `ModelInfo` returned by `list_models()`. The priority ordering of config keys (`max_position_embeddings` > `max_sequence_length` > `n_positions`), the vision-detection heuristics, and the default fallback to 4096 are all invisible to the test suite. A regression that returned `0` for every context window would pass all tests because `test_list_models_model_info_complete` only asserts `context_window > 0` — a check that would still pass as long as the fallback returns 4096, not that the actual config key was used.

`_fetch_model_config` has no test for its most important contract: network failure must return `{}` without propagating an exception. There is no test that confirms this graceful degradation.

**Falsifiability: FAILS.** Deleting or corrupting either function leaves the test suite green.

### 2. `_load_model_for_cuda` — local_transformers.py:880

This is an entire model-loading code path for CUDA users. It is referenced from `_load_for_device` and is the primary path activated when `_select_device()` returns `"cuda"`. There are zero tests for this code. The dtype handling, quantization config selection, model-to-device transfer, and cache insertion inside this method are completely invisible to the suite.

**Falsifiability: FAILS.** The CUDA loading path could be dropped entirely; no test would fail.

### 3. `_load_xpu_model_impl` — model_loader.py:486

Counterpart to the CUDA loader on the XPU side. `load_model_for_xpu` is tested only for the error path (`RuntimeError("XPU is not available")`). The actual implementation — dtype selection, int4/int8 quantization via `BitsAndBytesConfig`, device transfer, and cache insertion — has no test at any level.

**Falsifiability: FAILS.** The int4 quantization branch could silently be replaced with int8; no test would detect it.

### 4. `_estimate_memory_from_name` — xpu_utils.py:406

Six device-name-to-VRAM mappings are encoded here (B580→12 GB, A770→16 GB, A750→8 GB, A380→6 GB, A310→4 GB, unknown→8 GB). This function is the VRAM fallback when WMI enrichment cannot supply a memory figure. No test covers any of the six cases. The B580 mapping being incorrect would cause `list_models()` to offer oversized models that exhaust VRAM, but the test suite would not detect this.

**Falsifiability: FAILS.** Swapping the B580 and A770 constants would not fail any test.

### 5. `_strip_pwsh_payload` — xpu_utils.py:165

BOM removal is the entire purpose of this function. The `﻿` byte-order mark is injected by PowerShell's default UTF-8-with-BOM encoding and will cause `json.loads()` to fail if not stripped. No test exercises the BOM-stripping path. On a machine where PowerShell outputs BOM (the default on Windows), GPU enumeration would silently fail with a JSON parse error if this function were broken.

**Falsifiability: FAILS.** Removing the BOM-strip line would not fail any test.

### 6. `_check_intel_driver` + `_pick_primary_arc_gpu` — xpu_utils.py:687 and 656

These are internal components of `check_windows_requirements()`. The test for `check_windows_requirements` only verifies the return type `(bool, list[str])`, not the specific warning content or the decision logic. `_check_intel_driver` is never tested for driver-present, driver-absent, or empty-version-string inputs. `_pick_primary_arc_gpu` is never tested for multi-GPU disambiguation. If either function returned incorrect results, `check_windows_requirements` would still return a typed tuple that passed `isinstance` checks.

**Falsifiability: FAILS.** A logic inversion in driver detection (always returning `True`) would not fail any test.

### 7. `_consume_stream_chunks` + `chat_stream` — huggingface.py:542 and 619

Streaming with tool-call accumulation has no unit-level test. The `ToolCallBufferManager` delta-accumulation logic (partial `id`, partial `name`, partial `arguments` deltas across multiple stream chunks) is exercised only by the live API tests gated behind a real HuggingFace token. On a machine without a token, this entire code path is invisible to the suite. The `_cancel_requested` mid-stream abort is never tested at any level.

**Falsifiability: FAILS** without an HF API token.

### 8. Vacuous assertions in test_local_xpu_e2e.py

Three tests in `test_local_xpu_e2e.py` have assertions that cannot fail when inference works:

- `test_two_turn_conversation` (line ~890): both turns assert only `len(response.content) > 0`. A model producing a single space character would pass.
- `test_three_turn_with_system_prompt` (line ~940): same vacuous check on all three turns.
- `test_max_tokens_100_longer_output` (line ~980): asserts only `len(response.content) > 0`. The test name claims it verifies output is longer than the 10-token case but never checks length against the 10-token result.

These are not falsifiable gates. They would pass if `chat()` returned a `ChatResponse` with `.content = " "`.

### 9. `test_list_models_has_recommended_models` — test_local_transformers_provider.py

Assertion: `any("phi" in m.lower() or "tiny" in m.lower() for m in model_ids)`. This only verifies that at least one model whose name contains "phi" or "tiny" appears somewhere in the list. It does not verify that all seven `RECOMMENDED_MODELS_B580` entries are present, that their `model_id` values are correct, or that any specific model appears. A version of `list_models()` returning a single model named "phi-placeholder" would pass.

### 10. `_hf_status_code` — huggingface.py:57

No test directly verifies that `_hf_status_code` extracts the HTTP integer from `HfHubHTTPError.response.status_code`. The function is only reachable via `connect()` error paths in the live test suite. If the `response` attribute lookup were silently broken and the function returned `None` for every exception, the only observable effect would be wrong error routing — something not directly asserted in any test.

---

## Gap List

The following behaviors are completely absent from the test suite:

1. `_fetch_model_config(model_id)` — network failure returns `{}`; 404 returns `{}`; malformed JSON returns `{}`; valid JSON parsed correctly
2. `_classify_model_capabilities(config)` — key priority ordering; vision key detection; empty config default
3. `_release_device_caches()` — XPU `empty_cache`, CUDA `empty_cache`, `gc.collect` invocations
4. `_config_device_for(device)` — `"xpu"` → `"xpu"`, anything else → `"cpu"` dispatch
5. `_load_model_for_cuda(config)` — CUDA model loading, quantization selection on CUDA
6. `_iter_local_generation_loop(...)` — temperature=0 argmax vs temperature>0 multinomial sampling branch
7. `_load_xpu_model_impl(...)` — int8/int4/bfloat16 XPU loading; device-map selection; cache insertion
8. `_load_cpu_model_impl(...)` — dtype and quantization for CPU independently of e2e
9. `set_global_cache_size(max_memory_bytes)` — global cache size mutation and eviction effect
10. `_get_device_name_from_sycl(device_index)` — SYCL name extraction; out-of-range on XPU
11. `_strip_pwsh_payload(stdout)` — BOM strip; whitespace-only; non-BOM passthrough
12. `_enrich_from_windows_gpus(...)` — WMI enrichment; early-return when already populated
13. `_estimate_memory_from_name(device_name)` — six device-to-VRAM mappings (b580, a770, a750, a380, a310, unknown)
14. `_pick_primary_arc_gpu(gpus)` — largest-BAR selection; single-GPU list; empty list
15. `_check_intel_driver(gpus)` — driver present; driver absent; empty driver string
16. `clear_xpu_cache()` — `torch.xpu.empty_cache()` call; no-XPU guard
17. `cancel_request()` in `HuggingFaceProvider` — flag set; effect on in-flight streaming
18. `_prepare_request_payload(messages, tools, tool_choice)` in `HuggingFaceProvider` — full message/tool conversion to SDK format
19. `_convert_tools_to_provider_format(tools)` in `HuggingFaceProvider` — OpenAI schema for HF SDK
20. `_consume_stream_chunks(raw_stream, model, tc_buffer)` — tool-call delta accumulation across chunks
21. `chat_stream(messages, model, ...)` in `HuggingFaceProvider` — end-to-end streaming without live API
22. `connect()` with invalid non-empty key (401) and connection timeout
23. `_ensure_model_loaded` fallback chain (CUDA→CPU, XPU→CPU when primary device fails)
24. `_validate_xpu_device` — tensor-op failure path → RuntimeError
25. `_query_windows_gpus()` — malformed JSON; empty output; subprocess failure
26. `ModelCache._make_key(...)` — key format verification (colon-separated structure)
27. `_unload_model(loaded_model)` error path when `_free_model_resources` raises

---

## Remediation Recommendations

Each recommendation identifies an independent ground truth oracle to use as the expected value, so the test cannot be tautological.

### R-1: Unit-test `_classify_model_capabilities` against known HuggingFace config shapes

For each config key pattern, construct a minimal real-shaped dict (matching the actual HuggingFace `config.json` schema for a known model) and assert the exact `(context_window, supports_vision)` tuple returned.

```python
# Independent oracle: Phi-3-mini publishes max_position_embeddings=4096 in its config.json
phi3_config = {"max_position_embeddings": 4096, "architectures": ["Phi3ForCausalLM"]}
ctx, vision = _classify_model_capabilities(phi3_config)
assert ctx == 4096
assert vision is False

# LLaVA has vision_config present
llava_config = {"max_sequence_length": 2048, "vision_config": {"image_size": 336}}
ctx, vision = _classify_model_capabilities(llava_config)
assert ctx == 2048
assert vision is True
```

The expected values are known from the published model cards, not derived by running the production function.

### R-2: Unit-test `_fetch_model_config` using real httpx response stubs (no mocks)

Construct a real `httpx.Response` object with a controlled body and pass it through a patched `httpx.AsyncClient.get` using `respx` (a real httpx routing library, not a mock). Assert the returned dict matches the JSON exactly. Assert that a `404` response returns `{}`. Assert that an `httpx.ConnectError` returns `{}`.

Do NOT use `unittest.mock`. `respx` intercepts at the transport level and exercises the real httpx client code path.

### R-3: Unit-test `_estimate_memory_from_name` against the Intel Arc product line

```python
# Independent oracle: Intel's published VRAM specifications
# Arc B580 = 12 GB (B580 product page)
# Arc A770 = 16 GB (A770 product page)
assert _estimate_memory_from_name("Intel Arc B580") == 12 * 1024**3
assert _estimate_memory_from_name("Intel Arc A770") == 16 * 1024**3
assert _estimate_memory_from_name("Intel Arc A380") == 6 * 1024**3
assert _estimate_memory_from_name("Some Unknown GPU XYZ") == 8 * 1024**3
```

### R-4: Unit-test `_strip_pwsh_payload` with BOM and without

```python
# BOM is Unicode U+FEFF, UTF-8 encoded as b'\xef\xbb\xbf'
bom_input = "﻿  {\"key\": 1}\n  "
assert _strip_pwsh_payload(bom_input) == '{"key": 1}'

clean_input = '  {"key": 2}  '
assert _strip_pwsh_payload(clean_input) == '{"key": 2}'

# Empty after BOM strip
assert _strip_pwsh_payload("﻿\n") == ""
```

The expected value is the string with BOM U+FEFF and surrounding whitespace removed, which is independently verifiable by inspection.

### R-5: Unit-test `_check_intel_driver` and `_pick_primary_arc_gpu` with constructed WMI entries

Construct real GPU info dicts (matching the `{"name", "pnp_device_id", "driver_version"}` schema) and assert exact `(bool, str)` / selected-dict results.

```python
# _check_intel_driver: driver present → True; absent → False
with_driver = [{"name": "Intel Arc B580", "pnp_device_id": "PCI\\VEN_8086&DEV_E20B\\0", "driver_version": "31.0.101.5522"}]
no_driver = [{"name": "Intel Arc B580", "pnp_device_id": "PCI\\VEN_8086&DEV_E20B\\0", "driver_version": ""}]
assert _check_intel_driver(with_driver) is True
assert _check_intel_driver(no_driver) is False

# _pick_primary_arc_gpu: largest real BAR wins (12 GB B580 beats 8 GB A380)
```

The expected Boolean is derived from the input structure itself, not from running the function in a prior run.

### R-6: Add a unit test for `_load_model_for_cuda` error paths

Even without CUDA hardware, the `cuda is not available` path can be tested by constructing a `ModelConfig` with `device="cuda"` and calling `_load_model_for_cuda` on a machine where `torch.cuda.is_available()` returns `False`. The test should assert that a `RuntimeError` or `ProviderError` is raised with a message that identifies CUDA as the missing component.

### R-7: Replace vacuous `len > 0` assertions in multi-turn conversation tests

For `test_two_turn_conversation`, `test_three_turn_with_system_prompt`, and `test_max_tokens_100_longer_output`, apply the same coherence oracle used in `test_single_turn_coherent_response`: check word count, distinct tokens, alphabetic character ratio, and common English word presence. The arithmetic prompt ("what is 2 + 2?") should produce a response that contains "4"; this is an independently verifiable oracle.

### R-8: Unit-test `_prepare_request_payload` in `HuggingFaceProvider`

Construct a fixed list of `ChatMessage` objects and a fixed list of `ToolDefinition` objects, call `_prepare_request_payload`, and assert the SDK-format dict produced matches the independently expected structure field by field. The expected structure is defined by the HuggingFace Inference SDK's documented input format, which serves as the independent oracle.

### R-9: Unit-test `set_global_cache_size`

After calling `set_global_cache_size(new_limit)`, assert that `get_global_model_cache().max_memory_bytes == new_limit`. Add a second assertion that inserting a model exceeding the new limit triggers eviction.

### R-10: Unit-test `ModelCache._make_key` directly

Assert the exact string format of the cache key for known inputs:

```python
key = ModelCache._make_key("my-model", "float16", "xpu")
assert key == "my-model::float16::xpu"
```

This pins the separator contract so that any change to the format (e.g., switching from `::` to `/`) fails immediately.

### R-11: Unit-test `_classify_model_capabilities` for multi-key priority

Provide a config with both `max_position_embeddings` and `max_sequence_length` present and assert that `max_position_embeddings` takes precedence:

```python
config = {"max_position_embeddings": 8192, "max_sequence_length": 2048}
ctx, _ = _classify_model_capabilities(config)
assert ctx == 8192  # not 2048
```

### R-12: Unit-test `_ensure_model_loaded` fallback chain without real hardware

Construct a `LocalTransformersProvider` with a patched `_load_for_device` that raises `RuntimeError` for the primary device and succeeds for the CPU fallback. Assert that after the load fails on the primary device, `device_type` is `"cpu"`. Do not mock the `_ensure_model_loaded` function itself; mock only `_load_for_device` to control which device path fails.

---

## Summary

Section 10 reaches 63 % gate coverage against a mandatory 85 % floor. The primary coverage deficit falls in three categories:

1. **Internal dispatch helpers with zero tests**: `_fetch_model_config`, `_classify_model_capabilities`, `_load_model_for_cuda`, `_load_xpu_model_impl`, `_estimate_memory_from_name`, `_strip_pwsh_payload`, `_enrich_from_windows_gpus`, `_pick_primary_arc_gpu`, `_check_intel_driver`. These are not trivial — they contain real logic and real branching that affects visible behavior.

2. **Live-only paths**: `chat_stream`, `_consume_stream_chunks` in `HuggingFaceProvider` require a real API token and real network to exercise. Unit-level tests against constructed real SDK objects (as already done for `_extract_stream_delta`) would close this gap without network dependency.

3. **Vacuous multi-turn and long-output assertions**: Three tests in `test_local_xpu_e2e.py` reduce to existence checks and do not verify that the LLM produced coherent, topically correct output. These are not falsifiable gates.

The areas that are well covered are the parsing and conversion utilities (`_parse_tool_calls`, `_build_chat_messages`, `_format_prompt_chatml_fallback`, `_extract_503_message`, `_convert_tool_choice`, `_parse_message_tool_calls`, `_extract_stream_delta`), the `ModelCache` LRU implementation, the memory estimation math (`estimate_model_memory`, `_estimate_parameter_count`, `select_dtype_for_memory`), the PCI BAR descriptor parsing (`_parse_mem_descriptor`), and the B580 device identification pipeline (`_is_b580_device`, `_parse_device_id_from_pnp`, `_check_rebar_status`).
