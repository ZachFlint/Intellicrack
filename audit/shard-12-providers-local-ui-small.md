# Shard 12 — AI providers (local/HW) + small UI files

- **Files audited**: 11
- **Total LOC**: 8282
- **Generated**: 2026-05-22T22:57:40Z

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 17    |
| MEDIUM   | 18    |
| LOW      | 8     |

- Files missing module-level `_logger`: 2 (`discovery.py`, `registry.py` — both also use `self._logger` in non-LLMProviderBase classes)
- Files using stdlib `logging`: 0
- Files containing `print(` runtime output: 0
- Files with `contextlib.suppress`: 0
- Files with bare `except` (no log): 17 instances of `except X: raise` re-raise patterns that omit a log call (counted as HIGH per criteria §2.2)

## Findings by file

### src/intellicrack/providers/ollama.py — LOC 1657

**Logger status**: `instance-level self._logger (LLMProvider exception)` — `OllamaProvider` subclasses `LLMProviderBase` (confirmed at L128). Module-level `_logger` also present at L44.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L23)

**Findings**:

- [HIGH] L416 — `except ProviderError: raise` re-raises without a log call (`list_tags`). Fix: `self._logger.warning("ollama_list_tags_failed", source=source, error=str(...))` before `raise`.
- [HIGH] L418-419 — `except (ConnectionError, ...) as exc:` raises `ProviderError(...) from exc` with no log of the original transport exception. Fix: `self._logger.warning("ollama_list_tags_transport_error", error=str(exc))` before raise.
- [HIGH] L447 — `except ProviderError: raise` in `list_running_models` — no log. Same fix pattern.
- [HIGH] L449-450 — `except (ConnectionError, ...) as exc:` raises without logging the transport error. Same fix.
- [HIGH] L480 — `except ProviderError: raise` in `show_model` — no log.
- [HIGH] L482-483 — `except (ConnectionError, ...) as exc:` raises without log.
- [HIGH] L356-357 — `except (httpx.HTTPError, RuntimeError, UnicodeDecodeError):` returns `""` silently with no log. Fix: at least `self._logger.debug("ollama_response_text_unreadable")`.
- [HIGH] L1059-1060 — `except (TypeError, ValueError): return` silently swallows usage-parse failures with no log (`_record_usage_from_openai_payload`). Fix: add `self._logger.debug("openai_usage_parse_failed", error=str(...))`.
- [HIGH] L1160-1161 — `except (TypeError, ValueError): prompt_tokens = 0` in `_record_usage_from_chunk` — no log. Same recommendation.
- [HIGH] L1163-1165 — `except (TypeError, ValueError): completion_tokens = 0` — no log.
- [HIGH] L1328-1329 — `except (AuthenticationError, RateLimitError, ProviderError): raise` (in `_stream_native`) — no log.
- [HIGH] L1483-1484 — `except (AuthenticationError, RateLimitError, ProviderError): raise` (in `_stream_openai_compatible`) — no log.
- [HIGH] L1653-1654 — `except (AuthenticationError, RateLimitError, ProviderError): raise` (in `pull_model`) — no log.
- [MEDIUM] L183-217 — `connect()` (public) has no entry log; only emits granular events from `_connect_local`/`_connect_cloud`. Add `self._logger.info("ollama_connect_started", ...)` at entry. L213-214 raises `ProviderError(_ERR_CONNECT_BOTH_FAILED)` with no log of the aggregated failure; add `self._logger.error("ollama_connect_both_failed")` before `raise`.
- [MEDIUM] L485-552 — `generate()` performs an unwrapped `await client.post(...)` (L541) with no surrounding try/except and no warning log before/after the external call; transport errors propagate unlogged. The "ollama_generate_starting" entry log exists (L525) but no exit log.
- [MEDIUM] L554-584 — `embeddings()` (public): no entry log between connect check and `client.post`; no try/except around the network call. Add entry+exit logs and a wrapping try/except that logs transport errors.
- [MEDIUM] L363-389 — `list_models()` lacks an exit summary log (model count, sources hit); only an entry debug log at L378.
- [MEDIUM] L391-419, L421-450, L452-483 — `list_tags`, `list_running_models`, `show_model` perform real HTTP work but emit no entry/exit log around the request — only error path is partially logged (and that omits the log per HIGH above).
- [MEDIUM] L1614-1657 — `pull_model()` (public, network-heavy): no entry log before the streaming request begins; only error-path log on L1656. Add `self._logger.info("ollama_pull_starting", model=actual_model)` before `client.stream(...)`.
- [LOW] L1648-1649 — `except json.JSONDecodeError: self._logger.warning("pull_status_json_decode_failed")` — context (the offending line content / model name) is in scope but not passed as kwargs. Add `error=..., model=actual_model`.

### src/intellicrack/providers/local_transformers.py — LOC 1440

**Logger status**: `instance-level self._logger (LLMProvider exception)` — `LocalTransformersProvider` subclasses `LLMProviderBase` (L171). Module-level `_logger` also present at L90.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L25)

**Findings**:

- [HIGH] L527-528 — `chat()` raises `ProviderError(_MSG_NOT_CONNECTED)` with no log. Fix: `self._logger.error("local_chat_not_connected", model=model)` before raise.
- [HIGH] L530-531 — `chat()` raises `ProviderError(_ERR_EMPTY_MODEL)` with no log. Fix: `self._logger.error("local_chat_empty_model")` before raise.
- [HIGH] L545-546 — `chat()` raises `ProviderError(_MSG_NO_MODEL_LOADED)` with no log. Fix: `self._logger.error("local_chat_no_model_loaded", model=model_id)` before raise.
- [HIGH] L630-631 — `chat_stream()` raises `ProviderError(_MSG_NOT_CONNECTED)` with no log.
- [HIGH] L633-634 — `chat_stream()` raises `ProviderError(_ERR_EMPTY_MODEL)` with no log.
- [HIGH] L648-649 — `chat_stream()` raises `ProviderError(_MSG_NO_MODEL_LOADED)` with no log.
- [HIGH] L870-877 — `except (RuntimeError, ImportError, ValueError, OSError):` (CUDA model load fallback) — outer `raise` at L877 with no log for the original `from_pretrained` / `model.to` failure (only `_logger.warning("cuda_cache_clear_after_failure", ...)` for the cleanup attempt). Add `self._logger.warning("cuda_from_pretrained_failed", model_id=config.model_id)` before the cleanup block.
- [MEDIUM] L424-495 — `list_models()` lacks entry/exit logging. Real work: queries XPU memory, fetches HuggingFace configs via network. Add `self._logger.info("local_list_models_started", device=self._device_type)` at entry and `self._logger.info("local_list_models_complete", count=len(models))` at exit.
- [MEDIUM] L118-136 — `_fetch_model_config()` performs an HTTP GET to HuggingFace (L130) but only logs on failure (L135). Add `_logger.debug("hf_config_fetch_started", url=url)` before the request.
- [MEDIUM] L1420-1435 — `unload_model()` is public and does real work (cache mutation, XPU/CUDA cache clear, GC). It logs exit (L1435) but no entry — add `self._logger.info("model_unload_started", model_id=model_id)`.
- [MEDIUM] L256-324 — `connect()` is well-logged for branching but has no single "entry" event. Granular events suffice in practice; flag as LOW only.
- [LOW] L256-324 — see above; consider adding a single `local_transformers_connect_starting` event at entry.

### src/intellicrack/providers/discovery.py — LOC 1026

**Logger status**: `instance-level self._logger` in `DiscoveryCache` (L107) and `ModelDiscovery` (L463). **Neither class is a `LLMProviderBase` subclass**, so this violates the canonical pattern §1.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L21)

**Findings**:

- [MEDIUM] L107, L463 — Both classes hold `self._logger` instances despite not subclassing `LLMProviderBase`. The §1 documented exception applies only to LLMProvider subclasses. Module also has no module-level `_logger`. Recommend either (a) replace with module-level `_logger = get_logger(__name__)` and drop the instance attrs, or (b) keep the `.bind(...)` pattern but document the exception in the criteria. Same finding applies in `registry.py`. Flagged once per file.
- [HIGH] L402-403 — `except json.JSONDecodeError:` calls `self._logger.exception("cache_parse_failed", cache_path=str(path))` — this is **correct**. Not a finding. (Mentioned to show I checked.)
- [LOW] L309-310 — `except (OSError, ValueError, TypeError) as exc:` uses `.warning` instead of `.exception` after catching an I/O failure in `save_to_disk`. The function returns normally so `.warning(..., error=str(exc))` is acceptable; flagged LOW because traceback information is lost.
- [LOW] L405-407 — Same pattern as above in `load_from_disk`.
- [LOW] L428-433 — `cache_load_aborted_existing_preserved` uses `.warning` — acceptable since the exception is suppressed and explicitly documented.
- [LOW] L641-661, L759-762 — `discover_one` and `discover_provider` use `.warning(...)` after catching `(ConnectionError, OSError, RuntimeError, ValueError)` even though the exception details (other than `str(exc)`) are lost. Acceptable per project memory on TRY400, but consider `.exception()` for the non-timeout transport failure path since it's a genuine error not just a recoverable timeout.

### src/intellicrack/providers/model_loader.py — LOC 821

**Logger status**: `module-level _logger` (L50)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L20)

**Findings**:

- [MEDIUM] L468-565 — `load_model_for_xpu()` is a public function performing heavy work (tokenizer download via HF, model download/load, device transfer). Entry log at L497 ("model_loading_xpu") exists. Exit log at L553 ("model_loaded_xpu") exists. **However**, the call to `AutoTokenizer.from_pretrained(...)` (L505) is the actual network/file-I/O call — it can download multi-GB tokenizer files — and is not separately logged before the catch site. Consider a debug log between L502 and L505 confirming the tokenizer download is starting. Marginal.
- [MEDIUM] L568-667 — same pattern for `load_model_for_cpu()`. Marginal.
- [MEDIUM] L265-282 — `_unload_model()` (private helper but does real work — deleting tensors, GC, XPU cache clear). It logs only on failure paths. Add an entry log for traceability when models are evicted.
- [LOW] L317-326 — `estimate_model_memory()` debug log is fine.
- No other findings — exception handling consistently logs.

### src/intellicrack/providers/registry.py — LOC 442

**Logger status**: `instance-level self._logger` in `ProviderRegistry` (L75). **NOT a `LLMProviderBase` subclass**, so violates §1 like `discovery.py`. No module-level `_logger`.

**Imports `from intellicrack.core.logging import get_logger`**: yes (L15)

**Findings**:

- [MEDIUM] L75 — `self._logger = get_logger(__name__)` on a non-LLMProviderBase class; §1 exception does not apply here. Module also lacks a module-level `_logger`. Recommend module-level `_logger` and remove instance attr.
- All `except` blocks correctly log (L237-243, L244-250, L280-287, L329-335).
- [LOW] L168-170 — `get_or_raise()` logs at error level then raises immediately — appropriate; no finding.
- [LOW] L353-354 — `set_active` logs at error level then raises — appropriate.
- No HIGH/MEDIUM coverage gaps observed for the rest of the file. All state mutations (register, unregister, connect, disconnect, set_active) are logged.

### src/intellicrack/providers/xpu_utils.py — LOC 638

**Logger status**: `module-level _logger` (L39)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L20)

**Findings**:

- [MEDIUM] L156-198 — `_get_windows_gpu_info()` performs a subprocess call via `ProcessManager.get_instance().run_tracked(...)` (L167-176) but has no log before the subprocess invocation. Add `_logger.debug("windows_gpu_info_starting")` before `run_tracked(...)`. Failure path at L195 is logged.
- [MEDIUM] L529-555 — `_check_intel_driver()` runs a PowerShell subprocess (L537-546) — entry debug at L535 exists. Exit log on success (L552 "xpu_driver_detected") and failure (L554) exists. Acceptable; no finding.
- [MEDIUM] L558-592 — `_check_rebar_status()` runs a PowerShell subprocess (L566-575) — entry debug at L564, exit at L587-591. Acceptable.
- [LOW] L585-586 — `except ValueError: _logger.debug("xpu_rebar_count_unparseable", raw_count=count)` — fine.
- [LOW] L619-620 / L631-632 — `except (RuntimeError, OSError) as exc:` in `get_optimal_dtype_for_xpu()` logs at debug level which is appropriate since these are probe failures.
- No HIGH findings — every `except` clause logs.

### src/intellicrack/providers/gpu_pci_resources.py — LOC 276

**Logger status**: `module-level _logger` (L34)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L31)

**Findings**:

- [MEDIUM] L93-106 — `_Cfgmgr32.__init__` calls `ctypes.WinDLL("cfgmgr32.dll")` (L95) and resolves multiple function pointers. Per §2.3 win32 / ctypes calls must be logged. There is no log statement here — only the *failure* path is logged from the caller `_load_cfgmgr` (L121). Add `_logger.debug("cfgmgr32_loaded")` after successful DLL load.
- [MEDIUM] L228-260 — `enumerate_pci_memory_bars()` (public function) walks Windows PnP resource descriptors via cfgmgr32. No entry/exit log around the main work; only the failure path at L254 emits a debug log. Add an entry log `_logger.debug("pci_bar_enumeration_started", device_id=device_id)` and a debug exit summary with bar count.
- [LOW] L120-122 — `except OSError as exc:` uses `.debug` level which is appropriate since DLL load is expected to fail on non-Windows.
- No HIGH findings.

### src/intellicrack/ui/xpu_status.py — LOC 401

**Logger status**: `module-level _logger` (L38)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L28)

**Findings**:

- [LOW] L235-237, L263-265, L291-293, L317-321, L358-361, L374-377 — All `except (RuntimeError, OSError):` blocks use `_logger.debug(..., exc_info=True)`. This captures traceback (so traceback is preserved). The criteria §3 #6 prefers `.exception(...)` over `.error(...)`/`.warning(...)`. `debug(..., exc_info=True)` is an unusual but acceptable pattern that preserves traceback at debug level. No fix required — but consistency suggests `.exception(...)` is preferred. Flagged LOW.
- No entry/exit logs at all for `_refresh_*` methods. These are private UI handlers — most are timer-driven repaints, so frequent info logs would be noisy. Acceptable per §2.1 (private methods).
- [MEDIUM] L100-105 — `__init__` starts a periodic timer (`refresh_timer.start(_LIVE_REFRESH_MS)`) and runs an initial full refresh, but no info log of dialog open. Per §2.4, "GUI workflow milestones (target loaded, analysis queued, etc.)" should be logged. Add `_logger.info("xpu_status_dialog_opened")` in `__init__`.

### src/intellicrack/ui/chat.py — LOC 509

**Logger status**: `module-level _logger` (L35)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L27)

**Findings**:

- No exception blocks in this file. No HIGH findings.
- [LOW] L407-419 — `add_message()` (public) logs at debug level — fine for chat-bubble add.
- [LOW] L429-457 — `add_streaming_message()` (public) logs at debug — appropriate. The `append_chunk` inner function does not log per chunk (correct — that would be too noisy).
- [LOW] L459-470 — `clear_messages()` logs at info — appropriate workflow milestone.
- [LOW] L498-509 — `insert_context_text()` (public, GUI workflow milestone per §2.4 since "context insertion from other parts of the workspace" feeds into the chat) — no log. Add `_logger.debug("chat_context_inserted", length=len(text))`.

### src/intellicrack/ui/preferences.py — LOC 691

**Logger status**: `module-level _logger` (L47)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L42)

**Findings**:

- [MEDIUM] L646-655 — `_on_accept()` and `_on_apply()` are key state-mutation entry points (config save → emits `settings_changed`). `_on_apply` logs only on the file-save path (L660 info, L662 exception). The signal emit at L655 (`self.settings_changed.emit(new_config)`) is a significant state mutation per §2.4 and should be logged: add `_logger.info("preferences_apply_clicked", has_config_path=self._config_path is not None)` before `_build_config()`.
- [MEDIUM] L159-167 — `_browse_tools()` / `_browse_logs()` invoke `QFileDialog.getExistingDirectory` and mutate path-bound widgets. No log when the user picks a new directory. Add `_logger.debug("preferences_path_selected", key="tools_directory", path=path)` after each non-empty selection.
- [LOW] L457-451 (`LoggingSettingsWidget.get_settings`), L295-294 (`AppearanceSettingsWidget.get_settings`), L357-360 (`SessionSettingsWidget.get_settings`), L188-202 (`GeneralSettingsWidget.get_settings`) — simple data assembly, no log needed.
- No HIGH findings — the one `except OSError:` at L661-662 correctly uses `_logger.exception(...)`.

### src/intellicrack/ui/confirmation_dialog.py — LOC 381

**Logger status**: `module-level _logger` (L34)

**Imports `from intellicrack.core.logging import get_logger`**: yes (L28)

**Findings**:

- [LOW] L195-197 — `except (TypeError, ValueError): _logger.debug("tool_call_args_format_failed")` — context (`call.tool_name`, `call.function_name`) is in scope but not passed as kwargs. Add `tool=self._call.tool_name, function=self._call.function_name`.
- All state mutations (open dialog L71-75, remembered-replay L312-317, approve L347-352, deny L354-359) are properly logged. No coverage gaps.
- No HIGH/MEDIUM findings.

## Aggregate notes

**Cross-file patterns observed**:

1. **`except ProviderError: raise` with no log** — appears repeatedly in `ollama.py` (L416, L447, L480, L1328, L1483, L1653) and one variant in `local_transformers.py` (L870). Per criteria §2.2, even re-raises must log. The original transport exception is being silently discarded; downstream loggers only see the wrapped `ProviderError`. Recommend a single helper `_log_and_reraise(self, event, exc)` to standardize.

2. **Unlogged `ProviderError(_MSG_NOT_CONNECTED)` raises** — `local_transformers.py` `chat()` and `chat_stream()` (L528, L531, L546, L631, L634, L649) all raise `ProviderError` without an `_logger.error` first. `ollama.py` consistently does log these (e.g. L375, L522, L577); `local_transformers.py` is inconsistent with that pattern.

3. **`self._logger` outside LLMProviderBase** — `discovery.py` (`DiscoveryCache`, `ModelDiscovery`) and `registry.py` (`ProviderRegistry`) all use `self._logger = get_logger(__name__)`. Per §1 the exception is specifically for `LLMProviderBase` subclasses. These classes also do not have a module-level `_logger`. Recommend pattern unification across the providers package.

4. **Silent usage-parse failures in `ollama.py`** — three `except (TypeError, ValueError): return` blocks (L1059, L1160, L1163) discard usage information without any debug log. Token-accounting bugs become unobservable.

5. **External calls (HF, ctypes, PowerShell subprocess) often lack explicit entry logs** — `_fetch_model_config` (HF download), `_Cfgmgr32.__init__` (WinDLL load), and `_get_windows_gpu_info` (Get-WmiObject subprocess) all begin the external operation with no log. Only failure paths are logged.

6. **`debug(..., exc_info=True)` pattern in `ui/xpu_status.py`** — preserves traceback but at debug level, so traceback is only visible when debug logging is enabled. Acceptable but inconsistent with the project's typical `.exception(...)` usage.

7. **No `print(...)`, no stdlib `logging`, no `contextlib.suppress`, no f-string log messages** detected in the shard. The structlog-kwargs convention is followed throughout.

**Files with cleanest logging hygiene**: `model_loader.py`, `xpu_utils.py`, `confirmation_dialog.py`, `chat.py`.

**Files needing the most remediation**: `ollama.py` (re-raise patterns), `local_transformers.py` (unlogged `ProviderError` raises).

**Audit confidence**: HIGH. All files fully read at relevant regions; every `except`/raise/external call site cross-checked. No partial reads on undersized files. The `ollama.py` 1657-LOC file was the largest but reviewable in regions.
