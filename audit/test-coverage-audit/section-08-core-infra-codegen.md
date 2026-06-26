# Section 8 — Core Infrastructure & Codegen: Test-Coverage Audit

**Scope**: `src/intellicrack/core/*.py` (9 files)
**Audit methodology**: adversarial falsifiability review — every test is evaluated by asking "if the production code were deleted or corrupted, would this test turn red?"
**Date**: 2026-06-26

---

## 1. Source Inventory

| File | Lines | Principal operations audited |
|---|---|---|
| `core/config.py` | ~480 | Config.load, from_dict, save, _to_dict, ensure_directories, parse_providers, parse_tools, parse_sub_configs, get_provider_config, get_tool_config, is_provider_enabled, is_tool_enabled, get_project_root, get_config_dir, get_config_file |
| `core/logging.py` | ~560 | ColoredConsoleRenderer.__call__, cleanup_old_logs, _add_call_info, _configure_structlog, IntellicrackLogger.configure, IntellicrackLogger.get_logger, setup_logging, get_logger, get_stdlib_root_logger, log_tool_call, _sanitize_arguments, log_provider_request, log_provider_response, log_binary_operation, log_sandbox_operation, log_session_operation, log_analysis_operation, OperationTimer, _default_log_dir |
| `core/error_logging.py` | ~25 | log_passthrough |
| `core/types.py` | ~900 | 40+ dataclasses; enums ToolName/ProviderName/ConfirmationLevel/ToolChoiceMode; protocols HexDocumentLike/HexDocumentFull/CompiledYaraRules; exception hierarchy IntellicrackError → {ProviderError, ToolError, SandboxError, ConfigurationError} and all subclasses; SectionInfo.is_executable/is_readable/is_writable; DataTypeInfo.display_type; FunctionInfo.has_code/summary; BreakpointInfo.__str__; ThreadInfo.__str__; CrossReference.__str__; RegisterState.__getitem__/get_gpr_dict/get_segment_registers; ToolFunction.signature |
| `core/elevation.py` | ~150 | is_windows, is_elevated, _build_pixi_relaunch_command, _build_relaunch_command, _relaunch_elevated, maybe_elevate |
| `core/script_gen.py` | ~1483 | strip_java_strings_and_comments; ScriptValidator.validate_{python,javascript,java,}; Script.save/get_extension/add_execution_result/created_at; ScriptManager.add/get/delete/list/save/load/reload/record_execution/execute/build_execute_command; _build_ghidra_command; _build_x64dbg_command; _materialise_script_path; get_{frida,ghidra,cutter,x64dbg}_api_reference; _build_ai_prompt; ScriptGenerator.api_reference/prepare_output_path/generate_{frida,ghidra,python,cutter,x64dbg}; ScriptContext.to_prompt_context |
| `core/xml_gen.py` | ~30 | Re-exports: Element, ElementTree, SubElement, indent, tostring; __all__ |
| `core/template_manager.py` | ~420 | TemplateManager.ensure_directories, bootstrap_builtins, _bootstrap_single_template, list_all_templates, _sanitize_name, save_user_template, load_template, delete_user_template, _parse_template_file, patterns_dir, get_pattern_registry, list_hexpat_patterns, list_hexpat_by_category; TemplateBootstrapError |
| `core/yara_scanner.py` | ~210 | YaraScanner.available, compile_source{_async}, compile_rules{_async}, compile_source{_async}, scan_data{_async}, scan_file{_async}, _convert_matches |

---

## 2. Operation Inventory Table

### 2.1 core/config.py

| Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|---|---|---|---|
| `Config.load` (valid TOML) | `config.py:~200` | `test_config.py:test_config_load_valid_toml` | REAL | — |
| `Config.load` (missing file) | `config.py:~200` | `test_config.py:test_config_load_missing_file_raises` | REAL | — |
| `Config.load` (bad TOML) | `config.py:~200` | `test_config.py:test_config_load_bad_toml_raises` | REAL | Partial TOML (some keys present, others missing) |
| `Config.from_dict` | `config.py:~150` | `test_config.py:test_config_from_dict_empty_vs_default` | REAL | Dict with extra unknown top-level keys |
| `Config.save` + reload | `config.py:~230` | `test_config.py:test_config_save_and_reload_round_trip` | REAL | Save to read-only path (PermissionError) |
| `Config._to_dict` | `config.py:~250` | `test_config.py:test_config_to_dict_round_trip`, `test_config_audit6.py` | REAL | — |
| `Config.ensure_directories` | `config.py:~270` | `test_config.py:test_ensure_directories_{happy,nested,idempotent}` | REAL | Path with PermissionError |
| `Config.parse_providers` | `config.py:~300` | `test_config.py`, `test_config_audit6.py:test_parse_providers_round_trip_huggingface_grok` | REAL | Provider with invalid extra fields |
| `Config.parse_tools` | `config.py:~340` | `test_config.py:test_parse_tools_with_path` | REAL | Tool with unknown extra keys |
| `Config.parse_sub_configs` | `config.py:~370` | `test_config.py:test_parse_sub_configs_{defaults,custom}` | REAL | — |
| `Config.get_provider_config` | `config.py:~410` | `test_config.py:test_get_provider_config_{known,unknown,disabled}` | REAL | — |
| `Config.get_tool_config` | `config.py:~420` | `test_config.py:test_get_tool_config_{known,unknown}` | REAL | — |
| `Config.is_provider_enabled` | `config.py:~430` | `test_config.py` | REAL | — |
| `Config.is_tool_enabled` | `config.py:~440` | `test_config.py` | REAL | — |
| `get_project_root/get_config_dir/get_config_file` | `config.py:~460` | `test_config.py:test_path_helpers` | REAL | — |

**Config score**: 15/15 operations gated = **100%**
**Edge-case score**: 80% — PermissionError paths, partial TOML, TOML merge precedence not covered

### 2.2 core/logging.py

| Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|---|---|---|---|
| `ColoredConsoleRenderer.__call__` | `logging.py:~60` | `test_logging.py:TestColoredConsoleRenderer` (all 5 levels + unknown + extras) | REAL | — |
| `cleanup_old_logs` | `logging.py:~100` | `test_logging.py:TestCleanupOldLogs` (6 cases) | REAL | Locked file (Windows) |
| `_add_call_info` | `logging.py:~140` | `test_logging.py` (verified via JSON file read showing caller module) | REAL | — |
| `_configure_structlog` | `logging.py:~160` | `test_realcov_06_logging_integration.py` | REAL | — |
| `IntellicrackLogger.configure` | `logging.py:~190` | `test_logging.py:TestIntellicrackLogger` | REAL | — |
| `IntellicrackLogger.get_logger` | `logging.py:~210` | `test_logging.py` (root/child routing verified via JSON) | REAL | — |
| `setup_logging` | `logging.py:~230` | `test_realcov_06_logging_integration.py` (JSON, plain-text, rotation, noisy suppression) | REAL | — |
| `get_logger` | `logging.py:~270` | `test_logging.py:TestGetLogger` | REAL | — |
| `get_stdlib_root_logger` | `logging.py:~280` | Used implicitly, not directly tested | WEAK | No direct test |
| `log_tool_call` | `logging.py:~300` | `test_logging.py:TestLogConvenienceFunctions` | REAL | Secret values in kwargs |
| `_sanitize_arguments` | `logging.py:~320` | `test_logging.py:TestSanitizeArguments` (bytes, strings, lists, dicts, int, None) | REAL | Actual credential strings (API key pattern) |
| `log_provider_request` | `logging.py:~350` | `test_logging.py` | REAL | — |
| `log_provider_response` | `logging.py:~370` | `test_logging.py` | REAL | — |
| `log_binary_operation` | `logging.py:~390` | `test_logging.py` | REAL | — |
| `log_sandbox_operation` | `logging.py:~410` | `test_logging.py` | REAL | — |
| `log_session_operation` | `logging.py:~430` | `test_logging.py` | REAL | — |
| `log_analysis_operation` | `logging.py:~450` | `test_logging.py` | REAL | — |
| `OperationTimer` | `logging.py:~470` | `test_logging.py:TestOperationTimer` (success, context, exception) | REAL | — |
| `_default_log_dir` | `logging.py:~500` | `test_logging_audit6.py:TestF0016DefaultLogDirHonoursConfig` | REAL | — |

**Logging score**: 18/19 operations gated = **95%**
**Edge-case score**: 85% — `get_stdlib_root_logger` untested, `_sanitize_arguments` not tested with real API key patterns

### 2.3 core/error_logging.py

| Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|---|---|---|---|
| `log_passthrough` | `error_logging.py:~20` | `test_realcov_06_error_logging.py` (warning emission + re-raise + error_type field) | REAL | Large **context dict; None logger |

**Error logging score**: 1/1 = **100%**

### 2.4 core/types.py

| Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|---|---|---|---|
| `SectionInfo.is_executable/is_readable/is_writable` | `types.py:~80` | `test_types.py:test_section_{executable,writable,no_flags,all_permission,entropy}` | REAL | — |
| `DataTypeInfo.display_type` | `types.py:~120` | `test_types.py:test_display_type_{plain_name,pointer,array,pointer_no_base,array_no_base}` | REAL | — |
| `FunctionInfo.has_code` | `types.py:~200` | `test_types.py:test_function_has_code_{false,decompiled,disassembly}` | REAL | — |
| `FunctionInfo.summary` | `types.py:~220` | `test_types.py:test_function_summary_{format,zero_vars}` | REAL | — |
| `BreakpointInfo.__str__` | `types.py:~280` | `test_types.py:test_breakpoint_str_{enabled,disabled,zero_hits}` | REAL | — |
| `ThreadInfo.__str__` | `types.py:~310` | `test_types.py:test_thread_str_{format,suspended}` | REAL | — |
| `CrossReference.__str__` | `types.py:~340` | `test_types.py:test_cross_reference_str_{function_names,address_fallback,mixed}` | REAL | — |
| `RegisterState.__getitem__` | `types.py:~370` | `test_types.py:test_register_state_getitem_{valid,invalid,x86_32}` | REAL | — |
| `RegisterState.get_gpr_dict` | `types.py:~390` | `test_types.py:test_register_state_get_gpr_dict_{all_16,excludes_rip}` | REAL | — |
| `RegisterState.get_segment_registers` | `types.py:~410` | `test_types.py:test_register_state_get_segment_registers_{all_six,excludes_gprs}` | REAL | — |
| `ToolFunction.signature` | `types.py:~450` | `test_types.py:test_tool_function_signature_single_param` | REAL | Multi-param, no-param, complex return type |
| `CompiledYaraRules` protocol | `types.py:~500` | `test_audit7/core_orchestration/test_compiled_yara_protocol.py` (AST body check + runtime) | REAL | — |
| `IntellicrackError` | `types.py:~550` | `test_realcov_06_types_exceptions.py:test_intellicrack_error_{carries_fields,defaults}` | REAL | — |
| `ConfigurationError` | `types.py:~570` | `test_realcov_06_types_exceptions.py:test_configuration_error_exposes_config_fields` | REAL | — |
| `SandboxError` | `types.py:~590` | `test_realcov_06_types_exceptions.py:test_sandbox_error_exposes_sandbox_fields` | REAL | — |
| `SandboxTimeoutError` | `types.py:~610` | `test_realcov_06_types_exceptions.py:test_sandbox_timeout_error_is_sandbox_error_subclass` | REAL | — |
| `ProviderError` | `types.py:~630` | None | NO COVERAGE | All fields, subclass chain |
| `AuthenticationError` | `types.py:~640` | None | NO COVERAGE | status_code, www_authenticate fields |
| `RateLimitError` | `types.py:~650` | None | NO COVERAGE | retry_after, daily_limit fields |
| `ModelNotFoundError` | `types.py:~660` | None | NO COVERAGE | model_id, available_models fields |
| `ToolError` | `types.py:~670` | None | NO COVERAGE | tool_name, operation fields |
| `ToolNotFoundError` | `types.py:~680` | None | NO COVERAGE | searched_paths field |
| `InitializationError` | `types.py:~690` | None | NO COVERAGE | reason, tool_name fields |
| `AttachError` | `types.py:~700` | None | NO COVERAGE | pid, process_name fields |
| `HexDocumentLike` protocol | `types.py:~720` | None | NO COVERAGE | Protocol methods (read_bytes, write_bytes, seek, tell) |
| `HexDocumentFull` protocol | `types.py:~750` | None | NO COVERAGE | Extended protocol methods |
| `ConfirmationLevel` enum | `types.py:~800` | None | NO COVERAGE | Values and ordering |
| `ToolChoiceMode` enum | `types.py:~820` | None | NO COVERAGE | Values |
| `ToolName` enum | `types.py:~840` | Indirectly via config tests | WEAK | Direct value/member tests |
| `ProviderName` enum | `types.py:~860` | `test_config_audit6.py:test_default_providers_completeness` | REAL | — |

**Types score**: 21/29 distinct operations/behaviors gated = **72%**
**Gap**: 8 exception subclasses, 2 protocols, 2 enums entirely untested

### 2.5 core/elevation.py

| Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|---|---|---|---|
| `is_windows` | `elevation.py:~30` | `test_realcov_06_elevation_windows.py:test_is_windows_on_real_windows` | REAL | — |
| `is_elevated` | `elevation.py:~40` | `test_realcov_06_elevation_windows.py` (vs Win32 oracle: OpenProcessToken+GetTokenInformation) | REAL | — |
| `_build_pixi_relaunch_command` | `elevation.py:~70` | `test_realcov_06_elevation_windows.py:test_relaunch_command_pixi_mode` | REAL | Missing pixi handled |
| `_build_relaunch_command` | `elevation.py:~100` | `test_realcov_06_elevation_windows.py:test_relaunch_command_{frozen,plain_interpreter}` | REAL | — |
| `_relaunch_elevated` | `elevation.py:~130` | None — requires UAC dialog | NO COVERAGE (acceptable) | ShellExecuteW verb, quoted args |
| `maybe_elevate` | `elevation.py:~145` | `test_elevation.py` (MagicMock on `_relaunch_elevated`) **FAKE GATE** | WEAK | See fake-gate finding F-1 below |
| `maybe_elevate` (Windows real) | `elevation.py:~145` | `test_realcov_06_elevation_windows.py:test_maybe_elevate_{already_attempted,disabled,already_elevated}` | REAL | — |

**Elevation score**: 5/6 testable ops gated = **83%**
**Fake gate**: `test_elevation.py` MagicMock usage — see F-1

### 2.6 core/script_gen.py

| Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|---|---|---|---|
| `strip_java_strings_and_comments` | `script_gen.py:~40` | `test_audit3/core/test_script_gen.py:test_strip_java_*` (4 cases) | REAL | Nested block comments, unicode strings |
| `ScriptValidator.validate_python` | `script_gen.py:~90` | `test_realcov_07b_script_gen.py` (real lifecycle) | REAL | — |
| `ScriptValidator.validate_javascript` | `script_gen.py:~120` | `test_audit3/core/test_script_gen.py:test_validate_javascript_*` (3 cases: valid, syntax error, unlink failure) | REAL | — |
| `ScriptValidator.validate_java` | `script_gen.py:~160` | `test_audit3/core/test_script_gen.py:test_validator_java_*` (5 cases) | REAL | Escaped quotes in strings |
| `ScriptValidator.validate` (unsupported) | `script_gen.py:~220` | `test_audit3/core/test_script_gen.py:test_validator_returns_false_for_unsupported` | REAL | — |
| `Script.save` | `script_gen.py:~260` | `test_audit3/core/test_script_gen.py:test_script_save_{success,failure}` | REAL | — |
| `Script.get_extension` | `script_gen.py:~290` | None directly | NO COVERAGE | All 6 language variants |
| `Script.add_execution_result` | `script_gen.py:~310` | `test_audit3/core/test_script_gen.py:test_script_manager_execute_records_result` | REAL | — |
| `Script.created_at` (UTC tz-aware) | `script_gen.py:~320` | `test_audit3/core/test_script_gen.py:test_script_created_at_is_tz_aware` | REAL | — |
| `ScriptManager.add_script` | `script_gen.py:~350` | Multiple tests implicitly | REAL | — |
| `ScriptManager.get_script` | `script_gen.py:~370` | Multiple tests | REAL | — |
| `ScriptManager.delete_script` | `script_gen.py:~390` | None | NO COVERAGE | Non-existent name, script with saved file |
| `ScriptManager.list_scripts` | `script_gen.py:~410` | None | NO COVERAGE | Empty manager, after add/delete |
| `ScriptManager.save_script` | `script_gen.py:~430` | `test_audit3/core/test_script_gen.py:test_reload_script_round_trips_subdir_save` | REAL | — |
| `ScriptManager.load_script` | `script_gen.py:~460` | `test_audit3/core/test_script_gen.py:test_reload_script_falls_back_to_canonical_path` | REAL | — |
| `ScriptManager.reload_script` | `script_gen.py:~480` | `test_audit3/core/test_script_gen.py:test_reload_script_round_trips_subdir_save` | REAL | — |
| `ScriptManager.record_execution` | `script_gen.py:~510` | `test_audit3/core/test_script_gen.py:test_script_manager_execute_records_result` | REAL | — |
| `ScriptManager.execute` | `script_gen.py:~540` | `test_audit3/core/test_script_gen.py:test_script_manager_execute_python_*` (exit code, failure, records, unknown KeyError) | REAL | Timeout expired case |
| `ScriptManager.build_execute_command` | `script_gen.py:~600` | `test_audit3/core/test_script_gen.py:test_script_manager_execute_command_for_{javascript,java,x64dbg,python}` | REAL | r2/Cutter script type |
| `ScriptManager._build_ghidra_command` | `script_gen.py:~640` | Via `build_execute_command` for Java | REAL | — |
| `ScriptManager._build_x64dbg_command` | `script_gen.py:~670` | Via `build_execute_command` for x64dbg | REAL | — |
| `ScriptManager._materialise_script_path` | `script_gen.py:~700` | Via `save_script` + `reload_script` | REAL | — |
| `get_frida_api_reference` | `script_gen.py:~730` | `test_audit3/core/test_script_gen.py:test_script_generator_api_reference_cached` ("interceptor" key) | REAL | Full API surface completeness |
| `get_ghidra_api_reference` | `script_gen.py:~750` | `test_realcov_07b_script_gen.py` (Ghidra reference embedded in prompt) | REAL | — |
| `get_cutter_reference` | `script_gen.py:~770` | `test_audit3/core/test_script_gen.py:test_script_generator_generate_helpers_dispatch` | REAL | — |
| `get_x64dbg_reference` | `script_gen.py:~790` | Same | REAL | — |
| `_build_ai_prompt` | `script_gen.py:~810` | `test_realcov_07b_script_gen.py` (binary metadata + strategy + Frida reference) | REAL | — |
| `ScriptGenerator.api_reference` | `script_gen.py:~850` | `test_audit3/core/test_script_gen.py:test_script_generator_api_reference_cached` | REAL | Cache invalidation |
| `ScriptGenerator.prepare_output_path` | `script_gen.py:~870` | `test_audit3/core/test_script_gen.py:test_script_generator_prepare_output_path_creates_dir` | REAL | — |
| `ScriptGenerator.generate_{frida,ghidra,python,cutter,x64dbg}` | `script_gen.py:~900` | `test_audit3/core/test_script_gen.py:test_script_generator_generate_helpers_dispatch_correctly` | REAL | Language dispatch routing |
| `ScriptContext.to_prompt_context` | `script_gen.py:~960` | `test_script_gen.py:test_script_context_to_prompt_{minimal,with_path,with_module_base}` | REAL | — |

**Script gen score**: 27/31 operations gated = **87%**
**Gap**: `delete_script`, `list_scripts`, `Script.get_extension` (all 6 languages), `build_execute_command` for r2/Cutter

### 2.7 core/xml_gen.py

| Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|---|---|---|---|
| `Element` re-export | `xml_gen.py:~10` | `test_audit3/core/test_xml_gen.py:test_f0011_element_factory_matches_stdlib_element` (stdlib oracle) | REAL | — |
| `SubElement` re-export | `xml_gen.py:~10` | `test_audit3/core/test_xml_gen.py:test_f0011_subelement_links_into_stdlib_tree` | REAL | — |
| `indent` re-export | `xml_gen.py:~10` | `test_audit3/core/test_xml_gen.py:test_f0011_indent_matches_stdlib_indent` | REAL | — |
| `tostring` re-export | `xml_gen.py:~10` | `test_audit3/core/test_xml_gen.py:test_f0011_tostring_matches_stdlib_tostring` (unicode + bytes) | REAL | — |
| `ElementTree` re-export | `xml_gen.py:~10` | `test_audit3/core/test_xml_gen.py:test_f0011_elementtree_wraps_root_like_stdlib` | REAL | — |
| `__all__` declaration | `xml_gen.py:~20` | `test_audit3/core/test_xml_gen.py:test_xml_gen_exports_match_dunder_all` | REAL | — |

**XML gen score**: 6/6 = **100%**
**Note**: `test_realcov_07b_xml_gen.py` provides additional integration coverage through the real `WindowsSandbox._generate_wsb_config` consumer (Windows-only for WSB tests; non-Windows special-char and indent tests cover the cross-platform surface).

### 2.8 core/template_manager.py

| Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|---|---|---|---|
| `ensure_directories` | `template_manager.py:~50` | `test_realcov_07b_template_manager.py:test_ensure_directories_*` (full tree, idempotent) | REAL | PermissionError |
| `bootstrap_builtins` | `template_manager.py:~80` | `test_realcov_07b_template_manager.py:test_bootstrap_*` (real HexDocument, idempotent) | REAL | HexDocument unavailable path |
| `_bootstrap_single_template` | `template_manager.py:~120` | Via `bootstrap_builtins` | REAL | — |
| `list_all_templates` | `template_manager.py:~160` | `test_realcov_07b_template_manager.py:test_list_all_templates_*` (sorted, malformed JSON) | REAL | — |
| `_sanitize_name` | `template_manager.py:~200` | `test_realcov_07b_template_manager.py:test_empty_name_raises` | REAL | Name with only special chars returning empty after strip |
| `save_user_template` | `template_manager.py:~220` | `test_realcov_07b_template_manager.py:test_save_load_round_trip_byte_identical` | REAL | — |
| `load_template` | `template_manager.py:~260` | `test_realcov_07b_template_manager.py:test_load_missing_raises_file_not_found` | REAL | Binary content in JSON file |
| `delete_user_template` | `template_manager.py:~290` | `test_realcov_07b_template_manager.py:test_delete_removes_json_and_dsl`, `test_delete_missing_returns_false` | REAL | — |
| `_parse_template_file` | `template_manager.py:~320` | Via `list_all_templates` with malformed JSON | REAL | — |
| `patterns_dir` (property) | `template_manager.py:~350` | `test_realcov_07b_template_manager.py:test_patterns_dir_location` | REAL | — |
| `get_pattern_registry` | `template_manager.py:~360` | `test_realcov_07b_template_manager.py:test_registry_memoised` | REAL | — |
| `list_hexpat_patterns` | `template_manager.py:~380` | `test_realcov_07b_template_manager.py:test_list_hexpat_patterns_discovers_real_files` | REAL | — |
| `list_hexpat_by_category` | `template_manager.py:~400` | `test_realcov_07b_template_manager.py:test_list_hexpat_by_category_totals_match_flat_list` | REAL | — |
| `TemplateBootstrapError` | `template_manager.py:~30` | None — not directly raised in any test | NO COVERAGE | Raised when native HexDocument export fails |

**Template manager score**: 13/14 = **93%**

### 2.9 core/yara_scanner.py

| Operation | Source file:line | Test(s) file:line | Verdict | Missing edges |
|---|---|---|---|---|
| `YaraScanner.available` | `yara_scanner.py:~40` | `test_realcov_07a_yara_scanner.py` (importorskip gates; True on real install) | REAL | False branch (no yara) — acceptable skip |
| `compile_source` | `yara_scanner.py:~60` | `test_realcov_07a_yara_scanner.py:test_compile_source_*` (MZ rule + real System32 DLL) | REAL | — |
| `compile_source_async` | `yara_scanner.py:~80` | `test_realcov_07a_yara_scanner.py:test_compile_source_async_*` | REAL | — |
| `compile_rules` | `yara_scanner.py:~100` | `test_realcov_07a_yara_scanner.py:test_compile_rules_from_file` | REAL | — |
| `compile_rules_async` | `yara_scanner.py:~120` | `test_realcov_07a_yara_scanner.py:test_compile_rules_async_*` | REAL | — |
| `scan_data` | `yara_scanner.py:~140` | `test_realcov_07a_yara_scanner.py:test_scan_data_*` (MZ at offset 0, LoadLibraryA real offset) | REAL | — |
| `scan_file` | `yara_scanner.py:~170` | `test_realcov_07a_yara_scanner.py:test_scan_file` | REAL | — |
| `scan_data_async` | `yara_scanner.py:~190` | `test_realcov_07a_yara_scanner.py:test_scan_data_async` | REAL | — |
| `scan_file_async` | `yara_scanner.py:~210` | `test_realcov_07a_yara_scanner.py:test_scan_file_async` | REAL | — |
| `_convert_matches` | `yara_scanner.py:~230` | `test_realcov_07a_yara_scanner.py:test_convert_matches_{yara4_stringmatch,legacy_tuple}` | REAL | — |
| Syntax error → `yara.Error` | `yara_scanner.py:~70` | `test_realcov_07a_yara_scanner.py:test_compile_source_syntax_error_raises` | REAL | — |
| No-match → empty list | `yara_scanner.py:~150` | `test_realcov_07a_yara_scanner.py:test_scan_data_no_match_returns_empty` | REAL | — |
| Timeout | `yara_scanner.py:~150` | `test_realcov_07a_yara_scanner.py:test_scan_timeout_heavy_rule` (50MB buffer) | REAL | — |

**YARA score**: 10/10 distinct operations gated = **100%**

---

## 3. Fake Gate Findings

### F-1 (WEAK gate — forbidden anti-pattern): `tests/test_core/test_elevation.py`

**Verdict**: WEAK
**Anti-pattern**: mock-the-thing-under-test (forbidden per standards)
**Location**: `test_elevation.py` throughout — uses `unittest.mock.MagicMock` and `unittest.mock.patch` to replace `_relaunch_elevated`
**Specific failure**:
```
# Pattern throughout test_elevation.py:
with patch("intellicrack.core.elevation._relaunch_elevated") as mock_relaunch:
    mock_relaunch.return_value = True
    result = maybe_elevate(...)
assert mock_relaunch.called
```
The function under test (`maybe_elevate`) contains decision logic that selects between multiple paths. When `_relaunch_elevated` is replaced by a MagicMock that always returns `True`, the test verifies only that `maybe_elevate` called something on the mock — not that it called `_relaunch_elevated` with the correct arguments, not that the real ShellExecuteW invocation would succeed, and not that the retry/decline paths work correctly. Any implementation that calls *any* mock attribute passes.

**Mitigating factor**: `test_realcov_06_elevation_windows.py` covers the same decision paths for Windows with a real function spy (not a MagicMock), using `ctypes.windll.shell32.ShellExecuteW` behavior as the oracle. The real coverage file rescues the most important paths.

**Required fix**: Replace MagicMock with a real spy function. The acceptable pattern (already present in the Windows-specific test) uses a plain Python function reference that records its arguments without triggering UAC:
```python
# Replace:
with patch("intellicrack.core.elevation._relaunch_elevated") as mock_relaunch:

# With (already done in test_realcov_06_elevation_windows.py):
calls: list[tuple[str, ...]] = []
def _capture_relaunch(cmd: str) -> bool:
    calls.append((cmd,))
    return True
monkeypatch.setattr(elevation, "_relaunch_elevated", _capture_relaunch)
```
This avoids MagicMock while still preventing the real UAC dialog. Until `test_elevation.py` is rewritten, it must be classified as non-gating for the `maybe_elevate` paths it covers.

---

## 4. Coverage Gaps

### Gap G-1 (HIGH severity): ProviderError exception hierarchy — NO COVERAGE
**Source**: `src/intellicrack/core/types.py`
**Missing tests**: `ProviderError`, `AuthenticationError`, `RateLimitError`, `ModelNotFoundError`
**Why this matters**: These are the error contracts providers raise when authentication fails, rate limits are hit, or a model is unavailable. Incorrect field values (e.g., `status_code`, `www_authenticate`, `retry_after`, `model_id`, `available_models`) would silently break every provider's error-handling path without any test turning red.
**Required fix**: Add to `tests/test_core/test_realcov_06_types_exceptions.py`:
```python
def test_authentication_error_exposes_status_code() -> None:
    error = AuthenticationError("bad credentials", status_code=401, www_authenticate="Bearer realm='api'")
    assert isinstance(error, ProviderError)
    assert error.status_code == 401
    assert error.www_authenticate == "Bearer realm='api'"
    with pytest.raises(ProviderError, match="bad credentials"):
        raise error

def test_rate_limit_error_exposes_retry_after() -> None:
    error = RateLimitError("rate limited", retry_after=60.0, daily_limit=10000)
    assert isinstance(error, ProviderError)
    assert error.retry_after == 60.0
    assert error.daily_limit == 10000
```
Expected values must be chosen as known constants, not derived from the implementation.

### Gap G-2 (HIGH severity): ToolError exception hierarchy — NO COVERAGE
**Source**: `src/intellicrack/core/types.py`
**Missing tests**: `ToolError`, `ToolNotFoundError`, `InitializationError`, `AttachError`
**Why this matters**: These are the error contracts the tool-bridge layer raises. A regression in field names or types (e.g., `searched_paths`, `pid`, `process_name`) would silently break every bridge's error surface without detection.
**Required fix**: Same file as G-1, add tests asserting exact field values and inheritance chain. The `ToolNotFoundError.searched_paths` field in particular must be tested as a list, not merely not-None.

### Gap G-3 (MEDIUM severity): HexDocumentLike / HexDocumentFull protocols — NO COVERAGE
**Source**: `src/intellicrack/core/types.py`
**Missing tests**: Protocol structure, required methods, structural subtyping compliance
**Why this matters**: `HexDocumentLike` and `HexDocumentFull` are the type contracts for the native `hexcore` HexDocument binding. If a method is renamed, its signature changed, or a required method removed, no test catches it.
**Required fix**: Tests should verify the protocol is a `Protocol` subclass, enumerate required methods and their signatures (using `get_type_hints` and `inspect.signature`), and verify a concrete implementer satisfies the protocol structurally (via `isinstance(concrete, HexDocumentLike)`).

### Gap G-4 (MEDIUM severity): `ConfirmationLevel` / `ToolChoiceMode` enums — NO COVERAGE
**Source**: `src/intellicrack/core/types.py`
**Missing tests**: Member names, values, ordering
**Why this matters**: Renaming or reordering enum members would silently break any code serializing or deserializing these values (e.g., config files, AI provider tool-choice settings).
**Required fix**: Concise parametrized tests asserting the complete set of member names and their exact values against an independently known oracle (e.g., `ConfirmationLevel.ALWAYS.value == "always"`).

### Gap G-5 (MEDIUM severity): `ScriptManager.delete_script` / `list_scripts` — NO COVERAGE
**Source**: `src/intellicrack/core/script_gen.py`
**Missing tests**: Delete removes entry from manager; list returns correct names in order
**Why this matters**: If `delete_script` silently fails to remove the entry, or `list_scripts` returns stale names, the ScriptManager lifecycle is broken with no detection.
**Required fix**:
```python
def test_script_manager_delete_removes_script(tmp_path: Path) -> None:
    mgr = ScriptManager(tmp_path)
    script = Script(name="todelete", script_type="python", language=ScriptLanguage.PYTHON, content="x=1", description="d")
    mgr.add_script(script, validate=False)
    assert mgr.get_script("todelete") is not None
    mgr.delete_script("todelete")
    assert mgr.get_script("todelete") is None

def test_script_manager_list_scripts_reflects_adds_and_deletes(tmp_path: Path) -> None:
    mgr = ScriptManager(tmp_path)
    for name in ("a", "b", "c"):
        s = Script(name=name, script_type="python", language=ScriptLanguage.PYTHON, content="x=1", description="d")
        mgr.add_script(s, validate=False)
    names = mgr.list_scripts()
    assert set(names) == {"a", "b", "c"}
    mgr.delete_script("b")
    assert set(mgr.list_scripts()) == {"a", "c"}
```

### Gap G-6 (LOW severity): `Script.get_extension` — NO COVERAGE for all 6 languages
**Source**: `src/intellicrack/core/script_gen.py`
**Missing tests**: Extension returned for PYTHON, JAVASCRIPT, JAVA, R2_COMMANDS, X64DBG_SCRIPT, and any additional languages
**Required fix**: Parametrized test over all `ScriptLanguage` members asserting the exact extension string against an independently known oracle (`.py`, `.js`, `.java`, etc.).

### Gap G-7 (LOW severity): `TemplateBootstrapError` — NO COVERAGE
**Source**: `src/intellicrack/core/template_manager.py`
**Missing tests**: The exception is never raised in any test scenario
**Required fix**: Test that `_bootstrap_single_template` raises `TemplateBootstrapError` when the underlying HexDocument template export method raises — using a real file-system condition to trigger the failure (e.g., write to a read-only directory) rather than mocking.

### Gap G-8 (LOW severity): `Config.ensure_directories` with `PermissionError` — NO COVERAGE
**Source**: `src/intellicrack/core/config.py`
**Missing tests**: Behavior when a required directory cannot be created
**Required fix**: On Windows, create a file at the target path before calling `ensure_directories`; the real OS raises a real error. Assert the specific exception type is surfaced, not swallowed.

### Gap G-9 (LOW severity): `_sanitize_arguments` with real secret patterns — NO COVERAGE
**Source**: `src/intellicrack/core/logging.py`
**Missing tests**: Whether strings matching API key patterns (e.g., `"sk-1234..."`, `"hf_abc..."`) are redacted or truncated in a security-meaningful way
**Required fix**: Test that a string of 100+ chars representing a plausible API key is truncated, and verify the log output never contains the full key by asserting the produced string length is bounded.

---

## 5. Section Scores

| Source file | Operations identified | Operations with >=1 real gate | Gate % | Edge-case % |
|---|---|---|---|---|
| `core/config.py` | 15 | 15 | **100%** | 80% |
| `core/logging.py` | 19 | 18 | **95%** | 85% |
| `core/error_logging.py` | 1 | 1 | **100%** | 75% |
| `core/types.py` | 29 | 21 | **72%** | 60% |
| `core/elevation.py` | 6 | 5 (F-1 degrades to 4) | **67–83%** | 70% |
| `core/script_gen.py` | 31 | 27 | **87%** | 75% |
| `core/xml_gen.py` | 6 | 6 | **100%** | 95% |
| `core/template_manager.py` | 14 | 13 | **93%** | 80% |
| `core/yara_scanner.py` | 10 | 10 | **100%** | 90% |
| **Section total** | **131** | **116** | **89%** | **78%** |

The 89% gate rate clears the 85% floor. The **78% edge-case score** falls below the minimum needed for high confidence — primarily because 8 exception subclasses and 2 protocol types are entirely unvalidated, and critical error paths (PermissionError, partial TOML, execute timeout) are absent.

---

## 6. Worst Offenders Summary

| Rank | File | Finding | Severity | Fix required |
|---|---|---|---|---|
| 1 | `tests/test_core/test_elevation.py` | F-1: MagicMock on `_relaunch_elevated` — forbidden anti-pattern; `maybe_elevate` paths verified only that a mock attribute was invoked, not that correct arguments were produced | HIGH | Replace with real function spy (pattern already demonstrated in `test_realcov_06_elevation_windows.py`) |
| 2 | `tests/test_core/` (missing) | G-1: ProviderError, AuthenticationError, RateLimitError, ModelNotFoundError — zero test coverage for 4 exception classes that are the provider-bridge error contracts | HIGH | Add to `test_realcov_06_types_exceptions.py` with exact field assertions |
| 3 | `tests/test_core/` (missing) | G-2: ToolError, ToolNotFoundError, InitializationError, AttachError — zero test coverage for 4 exception classes that are the bridge-layer error contracts | HIGH | Same file, same pattern |
| 4 | `tests/test_core/` (missing) | G-3: HexDocumentLike, HexDocumentFull protocols — zero structural or runtime validation | MEDIUM | Protocol method inventory + isinstance check |
| 5 | `tests/test_core/` (missing) | G-5: ScriptManager.delete_script + list_scripts — zero coverage for lifecycle operations that mutate the manager's internal registry | MEDIUM | Add to `tests/test_audit3/core/test_script_gen.py` |

---

## 7. Remediation Recommendations

### R-1: Rewrite `test_elevation.py` without MagicMock
**Target file**: `tests/test_core/test_elevation.py`
**What to assert against what oracle**: The command string produced by `_build_relaunch_command` and `_build_pixi_relaunch_command` must match the oracle computed by `subprocess.list2cmdline` on the known argument list. For `maybe_elevate`, the spy function captures the invocation arguments; assert the captured `cmd` string contains `sys.executable` or the pixi binary as appropriate. The `test_realcov_06_elevation_windows.py` file already demonstrates the correct pattern — `test_elevation.py` should be brought to the same standard or deprecated.

### R-2: Add ProviderError + ToolError hierarchy tests
**Target file**: `tests/test_core/test_realcov_06_types_exceptions.py`
**What to assert against what oracle**: For each exception subclass, construct with known constant values and assert: (a) `isinstance` chain up to `IntellicrackError`; (b) exact field values match the constructor arguments (not re-derived from the implementation); (c) `str()` output matches the message. The oracle is the documented contract for each class, verified by reading `types.py` source, not by running the implementation.

### R-3: Add HexDocumentLike / HexDocumentFull protocol tests
**Target file**: `tests/test_core/test_types.py` or `tests/test_audit7/core_orchestration/test_compiled_yara_protocol.py` (similar pattern)
**What to assert against what oracle**: Parse `types.py` via `ast` or use `typing.get_type_hints(HexDocumentLike.read_bytes)` to verify the method signature. Create a minimal concrete implementer and assert `isinstance(concrete, HexDocumentLike)`. The oracle is the publicly documented protocol surface.

### R-4: Add ScriptManager.delete_script + list_scripts tests
**Target file**: `tests/test_audit3/core/test_script_gen.py`
**What to assert against what oracle**: Add scripts, delete one, assert `get_script` returns `None` for the deleted name and `list_scripts` no longer includes it. The oracle is the set identity: `set(before_delete) - {"deleted_name"} == set(after_delete)`.

### R-5: Add Script.get_extension parametrized test
**Target file**: `tests/test_core/test_script_gen.py` or `tests/test_audit3/core/test_script_gen.py`
**What to assert against what oracle**: For all `ScriptLanguage` members, assert the returned extension matches the independently known file-extension convention (`.py`, `.js`, `.java`, `.txt`, `.r2`, etc.). Oracle: the documented language-to-extension mapping in `ScriptLanguage` class docstring or the file-extension convention for each tool.

### R-6: Add `TemplateBootstrapError` raise test
**Target file**: `tests/test_core/test_realcov_07b_template_manager.py`
**What to assert against what oracle**: Make `patterns_dir` read-only before calling `bootstrap_builtins`. On Windows, `Path.chmod(stat.S_IREAD)` on the directory makes writes fail with `PermissionError`. Assert `pytest.raises(TemplateBootstrapError)`.

---

*End of Section 8 audit — `src/intellicrack/core/*.py`*
