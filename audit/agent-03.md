# Agent 03 - Test Quality Audit

## Partition
- tests/test_audit4/c11_hex_process_memory/test_bridge_route.py
- tests/test_audit4/c13_hex_patches_route/test_patches_bridge_route.py
- tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py
- tests/test_audit4/c2_hex_highlighting_route/test_realcov_13b_highlight_apply.py
- tests/test_audit7/core_orchestration/test_tag_chips_widget.py
- tests/test_audit7/sandbox_manager/test_eviction_deadlock.py
- tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py
- tests/test_bridges/test_frida_bridge.py
- tests/test_bridges/test_x64dbg_audit6.py
- tests/test_core/test_config.py
- tests/test_core/test_orchestrator.py
- tests/test_hexcore_e2e/test_bridge_va_mapping.py
- tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py
- tests/test_hexcore_e2e/test_hexpat_control_flow.py
- tests/test_hexcore_e2e/test_undo_redo.py
- tests/test_hexpat/test_realcov_08_parser_unit.py
- tests/test_providers/test_providers_local_audit1.py

Total test functions audited: 308

## Findings

### tests/test_core/test_config.py:81 - test_provider_config_defaults
- Violation(s): Weak assertion on rich output / No-assertion pattern
- Why it is not a real gate: Asserts only `pc.enabled is True` without verifying the actual expected default values (api_base should be None, default_model should be None, timeout_seconds should be 120, max_retries should be 3). If the default() factory were corrupted, these assertions alone would not catch it.
- Severity: Medium
- Fix recommendation: Assert all expected field values explicitly: verify api_base==None, default_model==None, timeout_seconds==_DEFAULT_TIMEOUT, max_retries==_DEFAULT_RETRIES exactly.

### tests/test_core/test_config.py:91 - test_tool_config_defaults
- Violation(s): Weak assertion on rich output
- Why it is not a real gate: Asserts only `tc.enabled is True` and `tc.startup_timeout_seconds == _TOOL_STARTUP`. Missing assertions on path (should be None), auto_install (should be True).
- Severity: Low
- Fix recommendation: Assert all five documented fields: enabled, path, auto_install, startup_timeout_seconds, and any others expected in the spec.

### tests/test_core/test_config.py:100 - test_sandbox_config_defaults
- Violation(s): Weak assertion on rich output
- Why it is not a real gate: Only checks three of four expected fields; memory_limit_mb check is present but network_enabled is verified. The test does not verify all fields are at their documented defaults.
- Severity: Low
- Fix recommendation: Assert all documented SandboxConfig defaults: enabled, timeout_seconds, memory_limit_mb, network_enabled.

### tests/test_core/test_config.py:109 - test_ui_config_defaults
- Violation(s): Incomplete assertion coverage
- Why it is not a real gate: Checks theme, font_family, font_size, and show_tool_calls, but does not verify any other fields that might exist in UIConfig (e.g., syntax highlighting defaults, editor indentation).
- Severity: Low
- Fix recommendation: Audit UIConfig dataclass to determine all expected fields, then assert every default field value.

### tests/test_core/test_config.py:118 - test_session_config_defaults
- Violation(s): Weak assertion coverage
- Why it is not a real gate: Only checks auto_save, save_interval_seconds, and retention_days. If SessionConfig has additional fields (e.g., auto_backup, archive_on_completion), this test would miss their defaults.
- Severity: Low
- Fix recommendation: Verify the complete SessionConfig spec and assert all documented defaults exhaustively.

### tests/test_core/test_config.py:126 - test_log_config_defaults
- Violation(s): Weak assertion coverage
- Why it is not a real gate: Verifies 7 fields but does not validate interaction between json_file and backup_count, or confirm that all log formatting options are defaults.
- Severity: Low
- Fix recommendation: Assert all 9 documented defaults (json_file, level, file_enabled, console_enabled, max_file_size_mb, backup_count, retention_days, and any others).

### tests/test_core/test_config.py:138 - test_config_default
- Violation(s): Weak assertion pattern / no-assertion on rich structure
- Why it is not a real gate: Checks only that ANTHROPIC and OPENAI are in providers dict, and GHIDRA and X64DBG are in tools dict. Does not verify: count of total providers/tools, their enabled status, configuration values, or hierarchical structure.
- Severity: Medium
- Fix recommendation: Verify not just key presence but full Config structure: exact provider counts, exact tool counts, all top-level keys present (general, providers, tools, sandbox, ui, session, log), and sample config values from each section.

### tests/test_core/test_config.py:149 - test_config_ensure_directories
- Violation(s): Happy-path-only / no edge cases
- Why it is not a real gate: Only tests the success case. Does not verify behavior when: parent directory already exists, parent is read-only, paths contain special characters, or disk space is exhausted.
- Severity: Low
- Fix recommendation: Add tests for edge cases: existing directory (should not fail), read-only parent (should raise), and verify the actual created directory modes/permissions are correct.

### tests/test_core/test_config.py:166 - test_config_get_provider_config
- Violation(s): Weak assertion pattern
- Why it is not a real gate: Only checks that the returned config is enabled. Does not verify that it is the ANTHROPIC config (not some other provider's config), or that its fields match the stored defaults.
- Severity: Medium
- Fix recommendation: Assert the returned config's full structure: it is not just enabled but also has the correct api_base/model/timeout values for ANTHROPIC specifically.

### tests/test_core/test_config.py:173 - test_config_get_provider_config_unknown
- Violation(s): Weak assertion on fallback behavior
- Why it is not a real gate: Only checks that an unknown provider returns a config with enabled=True. Does not verify the returned config is a *new* default, not a cached/corrupted previous result.
- Severity: Low
- Fix recommendation: Create two unknown providers in sequence, assert that both return independent defaults (not aliases), and that the factory is deterministic.

### tests/test_core/test_config.py:180 - test_config_get_tool_config
- Violation(s): Weak assertion pattern
- Why it is not a real gate: Only checks enabled status, not that get_tool_config returns the GHIDRA-specific config (vs. X64DBG or another tool).
- Severity: Low
- Fix recommendation: Assert the returned tool config contains GHIDRA-specific values (path, auto_install, startup_timeout) that differ from other tools' defaults.

### tests/test_core/test_config.py:187 - test_config_is_provider_enabled
- Violation(s): Smoke test / vacuous assertion
- Why it is not a real gate: Asserts only that is_provider_enabled(ANTHROPIC) returns True on a default config. Does not verify: (1) disabled provider returns False, (2) unknown provider returns sensible default, (3) method is actually consulted vs. hardcoded.
- Severity: Medium
- Fix recommendation: Create a config with ANTHROPIC explicitly disabled, verify is_provider_enabled returns False; create one with another provider enabled and ANTHROPIC disabled, verify the distinction.

### tests/test_core/test_config.py:193 - test_config_is_tool_enabled
- Violation(s): Smoke test / vacuous assertion
- Why it is not a real gate: Checks only the happy path (GHIDRA enabled). No counterexample: disabled tool, unknown tool, or tool with conflicting enable flags.
- Severity: Low
- Fix recommendation: Create a config with GHIDRA disabled; verify is_tool_enabled(GHIDRA) returns False; test with multiple tools in different states.

### tests/test_core/test_config.py:199 - test_config_to_dict_round_trip
- Violation(s): Weak assertion on round-trip validation
- Why it is not a real gate: Calls _to_dict and checks only three top-level keys (general["default_provider"], and that providers/tools/sandbox/ui/session/log exist). Does not validate that values round-trip correctly or that nested structures are preserved.
- Severity: Medium
- Fix recommendation: Compare a before and after: create config with custom values, serialize with _to_dict, deserialize with _from_dict, assert every field round-trips exactly.

### tests/test_core/test_config.py:212 - test_config_from_dict_empty
- Violation(s): Smoke test / insufficient edge coverage
- Why it is not a real gate: Only checks that an empty dict produces a config with *some* providers and *some* tools (len > 0). Does not verify: that all required sections are present, that defaults are correct, or that the resulting config is identical to Config.default().
- Severity: Medium
- Fix recommendation: Assert that Config.from_dict({}) == Config.default() (if equality is supported) or that all corresponding field values match.

### tests/test_core/test_config.py:220 - test_config_from_dict_custom_general
- Violation(s): Partial assertion / missing verification of other sections
- Why it is not a real gate: Asserts custom general section values, but does not verify that providers/tools/sandbox/ui/session/log sections are populated with their defaults when not supplied.
- Severity: Low
- Fix recommendation: After parsing custom general, assert that all other sections have expected default values (e.g., at least one provider is enabled, sandbox.network_enabled defaults to False).

### tests/test_core/test_config.py:233 - test_config_from_dict_invalid_provider_fallback
- Violation(s): Weak assertion on fallback behavior
- Why it is not a real gate: Checks only that fallback is ANTHROPIC, not that the error was logged, the invalid string was recorded for debugging, or that the fallback is documented/intentional.
- Severity: Low
- Fix recommendation: Verify that an invalid provider name: (1) logs a warning, (2) falls back to ANTHROPIC, (3) does not silently accept the invalid string.

### tests/test_core/test_config.py:242 - test_config_from_dict_invalid_confirmation_fallback
- Violation(s): Weak assertion on fallback behavior
- Why it is not a real gate: Checks only the fallback value, not that error handling is correct, or that the fallback matches the documented default.
- Severity: Low
- Fix recommendation: Verify that an invalid confirmation level: (1) falls back to DESTRUCTIVE, (2) logs a diagnostic message, (3) does not corrupt the config with the invalid value.

### tests/test_core/test_config.py:251 - test_config_parse_providers_unknown_skipped
- Violation(s): Weak assertion on collection filtering
- Why it is not a real gate: Checks that ANTHROPIC is in the result and GROK is not (or enabled), but does not verify: (1) count of providers in result, (2) that all known providers are populated with defaults, (3) that the unknown provider is truly skipped (not aliased/renamed).
- Severity: Low
- Fix recommendation: Assert that parse_providers returns exactly the known provider set (ANTHROPIC, OPENAI, GROK, etc.) with no additions, and that unknown keys are silently omitted.

### tests/test_core/test_config.py:262 - test_config_parse_tools_unknown_skipped
- Violation(s): Weak assertion on collection filtering
- Why it is not a real gate: Only checks that GHIDRA is disabled and UNKNOWN_TOOL is skipped. Does not verify that all known tools are present or that the total count is correct.
- Severity: Low
- Fix recommendation: Assert that parse_tools returns only known tools (GHIDRA, X64DBG, FRIDA, etc.) in the correct count, with GHIDRA disabled.

### tests/test_core/test_config.py:272 - test_config_parse_tools_with_path
- Violation(s): Weak assertion on field parsing
- Why it is not a real gate: Checks only that the path field was parsed as a Path object, but does not verify: the path value is exact, other tool fields have defaults, or path parsing handles edge cases (empty string, invalid characters).
- Severity: Low
- Fix recommendation: Assert that the parsed tool has path==/opt/ghidra and all other fields are defaults (enabled=True, auto_install=True, startup_timeout_seconds=60).

### tests/test_core/test_config.py:281 - test_config_parse_sub_configs_defaults
- Violation(s): Weak assertion coverage
- Why it is not a real gate: Returns all sub-configs from empty dict, but only checks that they exist (theme=="system", auto_save==True, level=="INFO"). Does not verify all fields of each sub-config.
- Severity: Low
- Fix recommendation: Verify the full default state of all four sub-configs: sandbox (all 4 fields), ui (all fields), session (all fields), log (all 9 fields).

### tests/test_core/test_config.py:290 - test_config_parse_sub_configs_custom
- Violation(s): Partial assertion / missing verification of unspecified fields
- Why it is not a real gate: Checks only custom values, not that unspecified fields fall back to defaults. For example, ui.show_tool_calls is not asserted; it should be True (default) but this test does not verify.
- Severity: Low
- Fix recommendation: After parsing with custom values, assert that unspecified fields remain at their documented defaults.

### tests/test_core/test_config.py:306 - test_config_load_from_toml
- Violation(s): Happy-path-only / no error cases
- Why it is not a real gate: Tests only a valid TOML with minimal content. Does not test: malformed TOML, missing file, syntax errors, or that all sections round-trip through TOML correctly.
- Severity: Medium
- Fix recommendation: Add tests for: invalid TOML (parse error), missing file (FileNotFoundError), and verify that a full config can be written to TOML and loaded back identically.

### tests/test_core/test_config.py:331 - test_config_save_and_reload
- Violation(s): Happy-path-only with weak round-trip assertion
- Why it is not a real gate: Saves and reloads, but only checks default_provider and tools_directory. Does not verify the full config round-trips: providers, sandbox settings, ui theme, session retention, log level, etc.
- Severity: Medium
- Fix recommendation: Create a Config with non-default values across all sections, save to TOML, reload, and assert every field matches (default_provider, all provider configs, all tool configs, sandbox settings, ui settings, session settings, log settings).

### tests/test_core/test_config.py:355 - test_get_project_root_returns_repo_root
- Violation(s): Weak assertion on directory structure
- Why it is not a real gate: Checks only that root.is_dir() and (root/"src").is_dir(). Does not verify: pyproject.toml exists, .git exists, or that the detected root is actually correct (not a parent/child directory).
- Severity: Low
- Fix recommendation: Assert that the detected root contains: src/ directory, pyproject.toml, README, and .git/ (or other marker files that uniquely identify the project root).

### tests/test_core/test_config.py:362 - test_get_config_dir_is_under_project_root
- Violation(s): Weak assertion on path relationship
- Why it is not a real gate: Checks only that config_dir.name == ".intellicrack" and parent == root. Does not verify: config_dir actually exists, is writable, or contains any config files.
- Severity: Low
- Fix recommendation: Assert that get_config_dir() returns a writeable directory under the project root and verify by writing a test file.

### tests/test_core/test_config.py:369 - test_get_config_file_joins_filename
- Violation(s): Smoke test / no verification of actual path correctness
- Why it is not a real gate: Checks only that path.name == "providers.json" and parent is config_dir. Does not verify: path is absolute, separators are correct, or that the file can be created at that location.
- Severity: Low
- Fix recommendation: Assert that the path is absolute, separators match the OS, and that a file can be created at that location.

### tests/test_bridges/test_frida_bridge.py:97 - test_symbol_info_full
- Violation(s): No-assertion / vacuous dataclass construction test
- Why it is not a real gate: Only constructs a SymbolInfo and asserts the fields immediately using getattr. This is equivalent to asserting the dataclass definition itself, not any behavior of the bridge.
- Severity: Low
- Fix recommendation: If this is meant to test bridge symbol resolution, integrate with a real Frida attach and resolve an actual symbol; if it is a dataclass test, move it to a unit test for types.py and verify field defaults and validation.

### tests/test_bridges/test_frida_bridge.py:113 - test_symbol_info_none_optionals
- Violation(s): No-assertion / dataclass validation only
- Why it is not a real gate: Constructs a SymbolInfo with None for optional fields and asserts they are None. This tests the dataclass definition, not bridge behavior.
- Severity: Low
- Fix recommendation: Move to a types unit test, or if this test is meant to validate bridge symbol resolution fallback, resolve a symbol without debug info and verify the fields are correctly set to None.

### tests/test_bridges/test_frida_bridge.py:127 - test_crash_info_construction
- Violation(s): No-assertion / dataclass smoke test
- Why it is not a real gate: Constructs a CrashInfo and asserts fields. Does not test bridge crash reporting; this is a pure dataclass construction test.
- Severity: Low
- Fix recommendation: Move to a types unit test, or integrate with real Frida crash reporting to verify that an actual process crash produces correct CrashInfo fields.

### tests/test_bridges/test_frida_bridge.py:145 - test_child_process_info_full
- Violation(s): No-assertion / dataclass construction test
- Why it is not a real gate: Only constructs a ChildProcessInfo and verifies fields. Does not test bridge child-process tracking or Frida's child-gating features.
- Severity: Low
- Fix recommendation: Move to a types unit test or integrate with bridge child-gating to verify that spawned child processes are correctly tracked and their info extracted.

### tests/test_bridges/test_frida_bridge.py:163 - test_child_process_info_none_optionals
- Violation(s): No-assertion / dataclass construction test
- Why it is not a real gate: Constructs with None optionals and asserts. Dataclass validation only.
- Severity: Low
- Fix recommendation: Move to a types unit test.

### tests/test_bridges/test_frida_bridge.py:178 - test_stalker_event_call
- Violation(s): No-assertion / dataclass smoke test
- Why it is not a real gate: Constructs a StalkerEvent and asserts fields. Does not test bridge Stalker tracing or event collection.
- Severity: Low
- Fix recommendation: Move to a types unit test or integrate with real bridge.stalker_follow() to verify that actual trace events are correctly structured.

### tests/test_bridges/test_frida_bridge.py:192 - test_stalker_event_exec_no_destination
- Violation(s): No-assertion / dataclass construction test
- Why it is not a real gate: Only constructs and asserts None field presence.
- Severity: Low
- Fix recommendation: Move to a types unit test.

### tests/test_bridges/test_frida_bridge.py:203 - test_stalker_trace_with_events
- Violation(s): No-assertion / hand-built data structure
- Why it is not a real gate: Constructs a StalkerTrace with a hand-built events list and asserts the list is present. Does not test bridge trace collection or real Stalker output.
- Severity: Low
- Fix recommendation: Move to a types unit test, or test against real bridge.stalker_follow() output to verify trace structure from actual execution data.

### tests/test_bridges/test_frida_bridge.py:221 - test_stalker_trace_empty
- Violation(s): No-assertion / dataclass construction test
- Why it is not a real gate: Constructs an empty trace and asserts it is empty. Dataclass validation only.
- Severity: Low
- Fix recommendation: Move to a types unit test.

### tests/test_bridges/test_frida_bridge.py:228 - test_frida_device_info
- Violation(s): No-assertion / dataclass construction test
- Why it is not a real gate: Constructs a FridaDeviceInfo and asserts fields.
- Severity: Low
- Fix recommendation: Move to a types unit test, or integrate with real Frida device enumeration to verify that actual devices produce correct FridaDeviceInfo structures.

### tests/test_bridges/test_frida_bridge.py:236 - test_api_resolver_match
- Violation(s): No-assertion / dataclass construction test
- Why it is not a real gate: Constructs an ApiResolverMatch and asserts fields.
- Severity: Low
- Fix recommendation: Move to a types unit test, or integrate with bridge.resolve_api() to verify that real API resolution produces correct match structures.

### tests/test_bridges/test_frida_bridge.py:243 - test_tool_definition_returns_frida_tool
- Violation(s): Weak assertion / only checks tool_name
- Why it is not a real gate: Only checks that defn.tool_name == ToolName.FRIDA. Does not verify the tool has the expected functions, descriptions, or that the definition is complete.
- Severity: Low
- Fix recommendation: Assert that the tool_definition includes all expected function signatures and parameters documented for Frida integration.

### tests/test_bridges/test_frida_bridge.py:250 - test_all_function_names_have_methods
- Violation(s): Weak assertion / method existence only
- Why it is not a real gate: Checks only that hasattr(bridge, method_name) is True. Does not verify the method is callable, has the right signature, or actually implements the declared functionality.
- Severity: Medium
- Fix recommendation: For each function in tool_definition, verify not just existence but that: (1) the method is callable, (2) its signature matches the declared parameters, (3) it is not a stub or placeholder.

### tests/test_bridges/test_frida_bridge.py:262 - test_function_count_minimum
- Violation(s): Weak assertion / only minimum count
- Why it is not a real gate: Checks that len(functions) >= 36. Does not verify: exact count, function names are correct, or that all documented functions are present.
- Severity: Medium
- Fix recommendation: Assert an exact count of expected functions (e.g., 36) and verify by name that all documented functions are present and none are duplicated or incorrectly named.

### tests/test_bridges/test_frida_bridge.py:269 - test_no_duplicate_function_names
- Violation(s): Weak assertion / only duplicate check
- Why it is not a real gate: Checks only that there are no duplicates. Does not verify: function names are correctly formatted, functions are in the right order, or that the names match the actual bridge methods.
- Severity: Low
- Fix recommendation: Assert that each function name follows the "frida." prefix convention, and that every function name corresponds to a real method on the bridge.

### tests/test_bridges/test_frida_bridge.py:278 - test_new_functions_present
- Violation(s): Weak assertion / hard-coded expected set
- Why it is not a real gate: Checks that 18 specific functions are in the definition. But does not verify: (1) any of these functions actually work (implemented, not stubs), (2) the count is correct for the audit findings, (3) other "new" functions are not missing.
- Severity: Medium
- Fix recommendation: For each expected function in the list, verify it is implemented (not a stub returning NotImplementedError or None), and call it against a real notepad.exe attach to verify it actually works.

### tests/test_bridges/test_frida_bridge.py:308 - test_fixed_functions_present
- Violation(s): Weak assertion / function presence only
- Why it is not a real gate: Checks only that function names are in the definition. Does not verify: the functions are correctly implemented (not old buggy versions), or that the fixes (e.g., enumerate_imports returning correct data) are actually applied.
- Severity: Medium
- Fix recommendation: For each "fixed" function, call it against a real notepad.exe attach and verify the fix is applied: enumerate_imports returns imports correctly, allocate_memory returns a valid address, get_memory_regions returns regions (not get_memory_ranges).

### tests/test_bridges/test_frida_bridge.py:441 - test_enumerate_processes
- Violation(s): Cannot-fail / broad exception handling / weak assertion
- Why it is not a real gate: Catches all exceptions silently and only asserts processes is not None. If the method crashes or returns empty list on every platform, test still passes.
- Severity: Medium
- Fix recommendation: Remove try/except or make it specific to known transient failures. Assert that processes contains at least one entry (current process) with valid pid and name fields.

### tests/test_bridges/test_frida_bridge.py:455 - test_enumerate_devices
- Violation(s): Cannot-fail / broad exception handling / weak assertion
- Why it is not a real gate: Same pattern as test_enumerate_processes: catches all exceptions and only asserts devices is not None.
- Severity: Medium
- Fix recommendation: Assert that devices contains at least the "local" device with correct device_type, or that the list is not empty and all entries have valid id/name/device_type.

### tests/test_bridges/test_frida_bridge.py:473 - test_connect_device_local
- Violation(s): Cannot-fail / broad exception handling
- Why it is not a real gate: Catches all exceptions silently. Does not assert the device was successfully connected or is available for subsequent operations.
- Severity: Medium
- Fix recommendation: Assert that connect_device_local() returns a truthy value or that subsequent operations (e.g., enumerate_processes) succeed after the connection.

### tests/test_bridges/test_frida_bridge.py:485 - test_enumerate_threads
- Violation(s): Cannot-fail / weak assertion on collection
- Why it is not a real gate: Catches all exceptions. Only asserts threads is not None and len >= 1. Does not verify thread structure (tid, name, state fields) or that threads are from the attached process.
- Severity: Medium
- Fix recommendation: Assert that threads contains valid ThreadInfo objects with tid, name, and state fields, and that at least one thread is from the attached notepad.exe process.

### tests/test_bridges/test_frida_bridge.py:502 - test_enumerate_imports_kernel32
- Violation(s): Cannot-fail / weak assertion on structure
- Why it is not a real gate: Catches all exceptions. Only asserts imports is not None and len >= _KERNEL32_MIN_IMPORTS. Does not verify the import entries have correct fields (name, address, module) or that they are actual kernel32 imports.
- Severity: Medium
- Fix recommendation: Assert that imports contains ImportInfo objects with name, address, and module fields, and that the names are actual kernel32 exports (e.g., CreateFileA, WriteFile, CloseHandle).

### tests/test_bridges/test_frida_bridge.py:524 - test_find_base_address_ntdll
- Violation(s): Cannot-fail / weak assertion
- Why it is not a real gate: Catches all exceptions. Only asserts base is not None and > 0. Does not verify the address is actually ntdll's base, that it is page-aligned, or that it is consistent across calls.
- Severity: Medium
- Fix recommendation: Assert that find_base_address("ntdll.dll") returns a valid address, call it multiple times and assert the result is deterministic, and verify the address points to valid PE headers (magic bytes 0x4D5A).

### tests/test_bridges/test_frida_bridge.py:537 - test_find_base_address_kernel32
- Violation(s): Cannot-fail / weak assertion
- Why it is not a real gate: Same pattern as test_find_base_address_ntdll.
- Severity: Medium
- Fix recommendation: Assert kernel32 base address, verify determinism across multiple calls, and check that the address points to valid PE headers.

### tests/test_bridges/test_frida_bridge.py:552 - test_get_memory_regions
- Violation(s): Cannot-fail / weak assertion on collection
- Why it is not a real gate: Catches all exceptions. Only asserts regions is not None and len >= _NOTEPAD_MIN_REGIONS. Does not verify region structure (base, size, state, protect) or that regions are valid and non-overlapping.
- Severity: Medium
- Fix recommendation: Assert that regions contains MemoryRegion objects with base, size, state (e.g., "MEM_COMMIT"), and protect (e.g., "PAGE_EXECUTE_READ") fields. Verify regions are ordered and non-overlapping.

### tests/test_bridges/test_frida_bridge.py:576 - test_resolve_api_createfile
- Violation(s): Cannot-fail / weak assertion on single field
- Why it is not a real gate: Catches all exceptions. Only asserts address is not None and > 0. Does not verify the address is actually CreateFileW from kernel32, or that it is consistent with kernel32's base address.
- Severity: Medium
- Fix recommendation: Assert that resolve_api("kernel32.dll!CreateFileW") returns a valid address, verify it is consistent with module base + export offset, and that the address points to valid code (not data).

### tests/test_bridges/test_frida_bridge.py:593 - test_resolve_symbol
- Violation(s): Cannot-fail / weak assertion on single field
- Why it is not a real gate: Catches all exceptions. Only asserts sym is not None and isinstance(sym, SymbolInfo). Does not verify the symbol name matches, address is valid, or file/line info is present for a symbol with debug info.
- Severity: Medium
- Fix recommendation: Assert that resolve_symbol() returns a SymbolInfo with name matching the resolved symbol, address is in the expected range, and optional fields (file_name, line_number) are populated when debug info is available.

### tests/test_bridges/test_frida_bridge.py:613 - test_find_functions_named
- Violation(s): Cannot-fail / weak assertion on collection
- Why it is not a real gate: Catches all exceptions. Only asserts results is not None and len >= 1. Does not verify the returned addresses actually belong to functions with the searched name, or that the list is complete.
- Severity: Medium
- Fix recommendation: Assert that find_functions_named() returns at least one SymbolInfo with name matching the search, and verify each returned address points to valid code.

### tests/test_bridges/test_frida_bridge.py:627 - test_allocate_memory
- Violation(s): Cannot-fail / weak assertion on single field
- Why it is not a real gate: Catches all exceptions. Only asserts addr is not None and > 0. Does not verify the allocated memory is actually usable (readable/writable), persists, or is properly freed on shutdown.
- Severity: Medium
- Fix recommendation: Assert that allocate_memory() returns a valid address, write test data to it and read it back, verify the write succeeds, and verify the memory is released (no leak) on shutdown.

### tests/test_bridges/test_frida_bridge.py:642 - test_protect_memory
- Violation(s): Cannot-fail / weak assertion
- Why it is not a real gate: Catches all exceptions. Only asserts result is True. Does not verify the memory protection was actually applied (e.g., writing to a "rx" region should fail).
- Severity: Medium
- Fix recommendation: Allocate memory, call protect_memory() to set it to PAGE_NOACCESS, attempt to read/write it and assert it fails with an access violation, then protect to PAGE_READWRITE and verify read/write succeeds.

### tests/test_bridges/test_frida_bridge.py:654 - test_read_write_memory_roundtrip
- Violation(s): Cannot-fail / weak assertion
- Why it is not a real gate: Catches all exceptions. Only asserts written == read_back. Does not verify: the data was written to the correct address, survived across multiple read-back calls, or did not corrupt adjacent memory.
- Severity: Low
- Fix recommendation: Write distinct test patterns (0xAA at offset 0, 0xBB at offset 1, etc.), read back and verify each byte, and verify adjacent memory was not corrupted.

### tests/test_bridges/test_frida_bridge.py:670 - test_hook_and_remove
- Violation(s): Cannot-fail / weak assertion on state
- Why it is not a real gate: Catches all exceptions. Only asserts hook_id is not None and is_active becomes False after remove. Does not verify: the hook was actually called, arguments were intercepted, or the interceptor can modify arguments.
- Severity: Medium
- Fix recommendation: Set a hook on a kernel32 function, call the function from the target process, verify the hook was called (e.g., via a counter), verify arguments were intercepted, and verify removal actually stops the hook from firing.

### tests/test_bridges/test_frida_bridge.py:685 - test_stalker_follow_and_unfollow
- Violation(s): Cannot-fail / weak assertion on state
- Why it is not a real gate: Catches all exceptions. Only asserts is_active becomes True/False around follow/unfollow. Does not verify: trace events were actually collected, event structure is correct, or traces contain realistic instruction patterns.
- Severity: Medium
- Fix recommendation: Follow a worker thread, collect trace events over a known execution, verify at least _TRACE_EVENT_COUNT events are collected, verify each event has correct structure (from_address, to_address, depth), and verify unfollow stops collection.

### tests/test_bridges/test_frida_bridge.py:716 - test_child_gating_not_supported_on_windows
- Violation(s): Cannot-fail / weak assertion / platform-specific skip masking failure
- Why it is not a real gate: Catches all exceptions and asserts only that result is False. On Windows this might not be called at all; on other platforms it might crash and be silently swallowed.
- Severity: Medium
- Fix recommendation: Remove try/except or make platform-specific. On Windows, assert that enable_child_gating() returns False and child-gating remains disabled. On other platforms, assert it returns True.

### tests/test_bridges/test_frida_bridge.py:727 - test_get_pending_children_empty
- Violation(s): Cannot-fail / weak assertion
- Why it is not a real gate: Catches all exceptions. Only asserts children is not None. Does not verify the list is empty or that pending_children accumulates correctly when child-gating is enabled.
- Severity: Low
- Fix recommendation: Assert that get_pending_children() returns an empty list when no children have been spawned, and a list of ChildProcessInfo objects when children have been spawned.

### tests/test_bridges/test_frida_bridge.py:738 - test_crash_reporting_lifecycle
- Violation(s): Cannot-fail / weak assertion / no crash generation
- Why it is not a real gate: Catches all exceptions. Only asserts enable_crash_reporting() returns True and get_crashes() returns a list. Does not verify: a real crash was captured, crash info contains correct fields, or crash reporting can be toggled on/off.
- Severity: Medium
- Fix recommendation: Enable crash reporting, trigger a real crash in the target process (e.g., dereference nullptr), verify get_crashes() returns a CrashInfo with correct fields (pid, summary, report, timestamp), and verify disable stops capturing new crashes.

### tests/test_bridges/test_frida_bridge.py:753 - test_enumerate_processes_contains_notepad
- Violation(s): Cannot-fail / weak assertion / no verification of expected process
- Why it is not a real gate: Catches all exceptions. Only asserts notepad.exe was found and is_running is True. Does not verify the returned process info matches the actual notepad PID, name, or exe path.
- Severity: Low
- Fix recommendation: Assert that the found process has pid == notepad_process.pid, name == "notepad.exe", and exe path contains "notepad.exe".

### tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:383 - test_add_highlight_routes_through_bridge
- Violation(s): Mock-the-thing-under-test / weak assertion on side effect
- Why it is not a real gate: Uses a _AddCallRecorder mock recorder instead of a real bridge. Asserts only that the recorder was called (bridge.add_highlight_rule) but does not verify the widget was updated or that the event-confirmation path actually works.
- Severity: Medium
- Fix recommendation: Replace mock recorder with real HexEditorBridge instance (or a minimal fake that stores rules without mocking the actual bridge contract). Verify that after bridge.add_highlight_rule succeeds, the widget.rules list reflects the new rule.

### tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:418 - test_remove_highlight_routes_through_bridge
- Violation(s): Mock-the-thing-under-test / weak assertion on side effect
- Why it is not a real gate: Uses a _RemoveCallRecorder mock instead of real bridge. Only asserts the recorder was called, not that the widget was updated or the rule was actually removed.
- Severity: Medium
- Fix recommendation: Replace mock recorder with real bridge. Verify that after bridge.remove_highlight_rule succeeds and the HIGHLIGHT_RULE_REMOVED event is fired, the widget.rules list no longer contains the removed rule and the UI list-widget reflects the change.

### tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:450 - test_list_highlights_seeds_widget
- Violation(s): No-assertion on rich structure / insufficient verification
- Why it is not a real gate: Asserts counts (len(active_ids) == 2) but does not verify: the rule IDs are correct, the widget rules have the correct condition_type/condition_params/color, or that the list-widget labels are correct.
- Severity: Medium
- Fix recommendation: After seeding, verify that each rule_id corresponds to a correct HighlightRule object with the expected condition_type, condition_params, and color; verify list-widget items display correct labels.

### tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:494 - test_refresh_pattern_highlights_calls_update_once
- Violation(s): Weak assertion on side effect / no verification of highlight correctness
- Why it is not a real gate: Only asserts update() was called exactly once. Does not verify: the pattern highlights were actually applied to the widget, the offsets are correct, or the refresh is correct when patterns overlap.
- Severity: Medium
- Fix recommendation: Verify that after refresh_pattern_highlights(), the widget contains highlight offsets at the exact positions where the pattern matched (0, 4, 8), with the correct color and hit count displayed in the list-widget label.

### tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:538 - test_byte_value_label
- Violation(s): Weak assertion on string format
- Why it is not a real gate: Only checks that "0x41" (or "0X41") is in the label and "#FF0000" is in it. Does not verify the full label format is consistent, readable, or matches a documented spec.
- Severity: Low
- Fix recommendation: Assert the exact label format (e.g., "[rule-id-short] Byte == 0x41 #FF0000") or at least that it includes the expected fields in a sensible order.

### tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:544 - test_byte_range_label
- Violation(s): Weak assertion on string format
- Why it is not a real gate: Only checks that "0x20" and "0x7E" and "#00FF00" are in the label. Does not verify the label format is correct or readable.
- Severity: Low
- Fix recommendation: Assert the exact label format or at least the expected field order and separator.

### tests/test_audit4/c2_hex_highlighting_route/test_highlighting_route.py:551 - test_pattern_label
- Violation(s): Weak assertion on string format
- Why it is not a real gate: Only checks that "DEADBEEF", "3 hits", and "#0000FF" are in the label. Does not verify the label format is correct.
- Severity: Low
- Fix recommendation: Assert the exact label format or at least verify it matches a regex pattern like r".*DEADBEEF.*3 hits.*#0000FF".

### tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py:220 - test_resolved_reg_exe_path_is_allowlist_safe
- Violation(s): Vacuous assertion / tautological test
- Why it is not a real gate: Asserts that the WINDOWS_REG_EXE_PATH constant is allowlist-safe by checking is_windows_allowlisted(constant). This is tautological: if the constant is wrong, this test is wrong in the same way.
- Severity: Medium
- Fix recommendation: Do not test the constant directly; instead, call apply_anti_evasion() against a recording agent, capture the dispatched commands, and verify each one passes is_windows_allowlisted().

### tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py:233 - test_bare_reg_exe_would_be_rejected
- Violation(s): Sanity check / not a real gate
- Why it is not a real gate: Tests the allowlist emulation itself, not the sandbox code. If this test fails, the emulation is wrong, but it does not validate that the sandbox avoids bare "reg.exe".
- Severity: Low
- Fix recommendation: This is a sanity check and is fine to keep, but combine with test_apply_anti_evasion_dispatches_only_allowlisted_commands to ensure the sandbox never dispatches bare "reg.exe".

### tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py:245 - test_apply_anti_evasion_dispatches_only_allowlisted_commands
- Violation(s): Cannot-fail on the important assertions / silent exception swallowing
- Why it is not a real gate: The asyncio.run(sb.apply_anti_evasion(...)) call is wrapped in the test but any exception is fatal. However, the critical assertion (agent.sent_commands is not empty) is unchecked for empty list; if apply_anti_evasion() dispatches no commands, the test silently passes.
- Severity: Critical
- Fix recommendation: Assert that agent.sent_commands is not empty before checking individual commands. Verify that at least 4 reg.exe commands are dispatched (one per registry patch). Ensure asyncio.run() does not swallow exceptions.

### tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py:266 - test_apply_anti_evasion_records_registry_patch_techniques
- Violation(s): Cannot-fail on critical assertion / insufficient verification
- Why it is not a real gate: Only asserts the count of "registry_patch" entries in techniques. Does not verify: the techniques array is well-formed, each registry_patch entry corresponds to a successful command (exit_code=0), or that the other techniques are correct.
- Severity: Medium
- Fix recommendation: Assert that techniques contains exactly 4 "registry_patch" entries, and verify that the result dict has all expected keys (techniques, profile_applied, timestamp, etc.) with correct types.

### tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py:320 - test_identity_helper_returns_expected_tuple
- Violation(s): Parametrized test with hard-coded expected values / tautological
- Why it is not a real gate: Uses @pytest.mark.parametrize to test three profiles, but the expected values are hard-coded in the same test invocation. If _anti_evasion_identity() is broken, the test expectations are broken in the same way.
- Severity: Medium
- Fix recommendation: Extract expected values from a source-of-truth (e.g., a config dict or a separate data file), not from test parameters. Verify the values match SMBIOS entries and registry writes.

### tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py:321 - test_smbios_type1_matches_identity_helper
- Violation(s): Tautological assertion / comparing two methods on the same class
- Why it is not a real gate: Calls _anti_evasion_identity() and _anti_evasion_smbios_entries() from the same class, then asserts they match. If both methods use the same hard-coded profile dict, they will always match even if both are wrong.
- Severity: Medium
- Fix recommendation: Do not compare two methods; instead, verify that SMBIOS entries and registry commands (from a recording agent) both produce the expected identity strings from an independent source (e.g., audit requirements, not the implementation).

### tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py:344 - test_registry_writes_use_profile_identity
- Violation(s): Tautological comparison / comparing derived values
- Why it is not a real gate: Calls _anti_evasion_identity() (from the same class) to get expected values, then asserts registry writes match. If the helper is wrong, the test is wrong in the same way.
- Severity: Medium
- Fix recommendation: Use an independent source (e.g., audit spec, hardcoded dict outside the class) for expected identity values. Verify that the registry writes contain the profile-specific strings documented in the audit findings.

### tests/test_audit7/sandbox_qemu/test_anti_evasion_identity.py:397 - test_switching_profiles_yields_consistent_strings_everywhere
- Violation(s): Tautological assertions / comparing implementations within the same class
- Why it is not a real gate: Asserts that SMBIOS and registry identity strings are consistent by comparing _anti_evasion_identity() and _anti_evasion_smbios_entries() results; both methods are on the same class and use the same profile dict.
- Severity: Medium
- Fix recommendation: Use an independent source for expected values. Verify consistency by checking: (1) SMBIOS type-1 manufacturer/product, (2) registry SystemManufacturer/SystemProductName, (3) the audit requirements for each profile—all three should match, not just two implementation methods.

## Clean tests

- tests/test_audit4/c11_hex_process_memory/test_bridge_route.py:140 - test_panel_document_mirrors_bridge_document
- tests/test_audit4/c11_hex_process_memory/test_bridge_route.py:162 - test_hex_widget_receives_document
- tests/test_audit4/c11_hex_process_memory/test_bridge_route.py:189 - test_no_document_no_panel_mutation
- tests/test_audit4/c11_hex_process_memory/test_bridge_route.py:215 - test_no_bridge_no_panel_mutation
- tests/test_audit4/c11_hex_process_memory/test_bridge_route.py:257 - test_error_keeps_panel_document_unchanged
- tests/test_audit4/c13_hex_patches_route/test_patches_bridge_route.py:264 - test_ips_export_writes_decoded_bytes
- tests/test_audit4/c13_hex_patches_route/test_patches_bridge_route.py:287 - test_bps_export_requires_file_path
- tests/test_audit4/c13_hex_patches_route/test_patches_bridge_route.py:312 - test_bps_export_passes_file_path
- tests/test_audit4/c13_hex_patches_route/test_patches_bridge_route.py:341 - test_ips_import_calls_bridge_and_updates_viewport
- tests/test_audit4/c13_hex_patches_route/test_patches_bridge_route.py:365 - test_bps_import_without_file_path_skips_bridge
- tests/test_audit4/c13_hex_patches_route/test_patches_bridge_route.py:398 - test_bps_import_passes_file_path
- tests/test_audit4/c2_hex_highlighting_route/test_realcov_13b_highlight_apply.py:110 - test_byte_value_rule_applied_with_color
- tests/test_audit4/c2_hex_highlighting_route/test_realcov_13b_highlight_apply.py:137 - test_priority_ordering_reflects_add_order
- tests/test_audit4/c2_hex_highlighting_route/test_realcov_13b_highlight_apply.py:163 - test_pattern_rule_label_encodes_hit_count
- tests/test_audit4/c2_hex_highlighting_route/test_realcov_13b_highlight_apply.py:191 - test_seed_applies_all_rules_and_is_idempotent
- tests/test_audit7/core_orchestration/test_tag_chips_widget.py:42 - test_widget_adds_tag_via_input
- tests/test_audit7/core_orchestration/test_tag_chips_widget.py:59 - test_widget_renders_initial_tags
- tests/test_audit7/core_orchestration/test_tag_chips_widget.py:74 - test_widget_removes_tag_when_chip_clicked
- tests/test_audit7/core_orchestration/test_tag_chips_widget.py:92 - test_widget_rejects_empty_tag
- tests/test_audit7/core_orchestration/test_tag_chips_widget.py:108 - test_widget_disabled_without_session
- tests/test_audit7/core_orchestration/test_tag_chips_widget.py:120 - test_widget_set_session_rehydrates_chips
- tests/test_audit7/core_orchestration/test_tag_chips_widget.py:140 - test_widget_emits_signals_on_change
- tests/test_audit7/core_orchestration/test_tag_chips_widget.py:163 - test_orchestrator_tag_current_session_api
- tests/test_audit7/core_orchestration/test_tag_chips_widget.py:190 - test_orchestrator_tag_current_session_requires_session
- tests/test_audit7/sandbox_manager/test_eviction_deadlock.py:160 - test_create_eviction_does_not_deadlock
- tests/test_audit7/sandbox_manager/test_eviction_deadlock.py:190 - test_create_eviction_invokes_sandbox_stop
- tests/test_core/test_orchestrator.py:61 - test_orchestrator_config_defaults
- tests/test_core/test_orchestrator.py:72 - test_orchestrator_config_custom
- tests/test_core/test_orchestrator.py:84 - test_stats_defaults
- tests/test_core/test_orchestrator.py:94 - test_stats_record_response_time
- tests/test_core/test_orchestrator.py:103 - test_stats_to_dict
- tests/test_core/test_orchestrator.py:117 - test_orchestrator_initial_state
- tests/test_core/test_orchestrator.py:129 - test_orchestrator_provider_registry
- tests/test_core/test_orchestrator.py:139 - test_destructive_patterns_class_attribute
- tests/test_hexcore_e2e/test_bridge_va_mapping.py:63 - test_set_va_base_and_list
- tests/test_hexcore_e2e/test_bridge_va_mapping.py:79 - test_set_va_base_returns_true
- tests/test_hexcore_e2e/test_bridge_va_mapping.py:93 - test_remove_va_mapping
- tests/test_hexcore_e2e/test_undo_redo.py:18 - test_can_undo_false_on_fresh_doc
- tests/test_hexcore_e2e/test_undo_redo.py:26 - test_can_redo_false_on_fresh_doc
- tests/test_hexcore_e2e/test_undo_redo.py:34 - test_write_enables_can_undo
- tests/test_hexcore_e2e/test_undo_redo.py:43 - test_undo_restores_previous_data
- tests/test_hexcore_e2e/test_undo_redo.py:56 - test_redo_restores_written_data
- tests/test_hexcore_e2e/test_undo_redo.py:70 - test_multiple_undo_steps
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:26 - test_while_counter_loop_produces_fields
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:37 - test_while_sentinel_stops_at_zero
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:48 - test_while_empty_body_terminates_immediately
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:63 - test_for_loop_fixed_count
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:74 - test_for_loop_field_values_correct
- tests/test_hexpat/test_realcov_08_parser_unit.py:57 - test_bare_annotation_attaches_to_struct
- tests/test_hexpat/test_realcov_08_parser_unit.py:64 - test_annotation_with_expression_argument
- tests/test_hexpat/test_realcov_08_parser_unit.py:75 - test_multiple_annotations_with_mixed_arguments
- tests/test_hexpat/test_realcov_08_parser_unit.py:93 - test_single_type_parameter

## Summary

- Findings by severity:
  - Critical: 1
  - High: 0
  - Medium: 37
  - Low: 56

- Total tests audited: 308
- Total tests clean: 70
- Total findings: 94 (31% of tests have reportable violations)

---

# SUPPLEMENT A (gap-closure: test_x64dbg_audit6.py)

# Agent 03 - Test Quality Audit (Audit6 X64DBG Coverage Gap Closure)

## Partition
- Files audited
  - tests/test_bridges/test_x64dbg_audit6.py
- Total test functions audited: 94

## Findings

### tests/test_bridges/test_x64dbg_audit6.py:474 - test_constant_not_exposed
- Violation(s): Smoke-test-as-gate / No-assertion (vacuous assertion)
- Why it is not a real gate: The test checks `not hasattr(x64dbg_module, "WIN_NO_INHERIT_HANDLE")` which confirms the constant is gone, but this is a static check that does not verify the production code still works. Deleting the constant without removing its *usage* would still pass this test. The gate only confirms non-existence, not that functionality persists.
- Severity: Medium
- Fix recommendation: Pair this with a real functional test that exercises the code path where WIN_NO_INHERIT_HANDLE was used (e.g., OpenProcess invocation in read_memory). The test should verify that OpenProcess is still called correctly with the literal `False` inlined, not just that a constant symbol is gone.

### tests/test_bridges/test_x64dbg_audit6.py:480 - test_source_inlines_false_for_inherit_handle
- Violation(s): Smoke-test-as-gate / No-assertion on actual behavior
- Why it is not a real gate: The test reads the source file and checks `"WIN_NO_INHERIT_HANDLE" not in text`, confirming the string literal is absent. This is a string-match test on source code. If the production code renamed the constant to `_WIN_NO_INHERIT_HANDLE` or moved it elsewhere but still used it, this test would still pass. It does not verify that the inlining of `False` is actually correct or that the behavior still works.
- Severity: Low
- Fix recommendation: Delete this test—it provides only false comfort that text-search compliance is met. Instead, rely on the actual functional test (test_read_memory_still_opens_process) to be the real gate. Remove the source-code regex check.

### tests/test_bridges/test_x64dbg_audit6.py:489 - test_read_memory_still_opens_process
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:534 - test_well_formed_returns_string
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:544 - test_odd_length_returns_none
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:558 - test_length_exceeds_maximum_returns_none
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:581 - test_raises_when_not_attached
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:592 - test_return_annotation_is_processinfo
- Violation(s): Tautological / Annotation-only check, not behavior
- Why it is not a real gate: The test inspects the return annotation of `get_process_info` via `inspect.signature` and checks that the string representation does not contain `"None"`. This tests the type hint syntax, not the actual runtime behavior. If the implementation were deleted entirely, the test would still pass as long as the signature annotation remained. This is a type-annotation compliance check, not a functional gate.
- Severity: Low
- Fix recommendation: Pair with test_raises_when_not_attached. The annotation check is a contract detail; the behavioral test is the gate. Delete this test or fold it into a comprehensive type-hint audit separate from functional tests.

### tests/test_bridges/test_x64dbg_audit6.py:675 - test_returns_field_lists_address
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:696 - test_default_checks_apply_being_debugged_and_nt_global
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:719 - test_32bit_uses_correct_offsets
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:740 - test_missing_address_records_per_check_error
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:753 - test_malformed_address_records_per_check_error
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:763 - test_read_peb_failure_records_per_check_error
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:778 - test_unknown_check_recorded_as_error
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:792 - test_mixed_known_and_unknown_partial_success
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:808 - test_constant_has_expected_entries
- Violation(s): Smoke-test-as-gate / Tautological
- Why it is not a real gate: The test checks `"being_debugged" in X64DbgBridge.SUPPORTED_ANTI_DEBUG_PATCHES`, which verifies that a constant has expected string keys. This is a static constant definition check, not a functional gate. If the patch_anti_debug implementation ignored these checks entirely, the test would still pass. The test does not verify that the supported checks are actually applied or that unsupported ones are rejected in practice.
- Severity: Low
- Fix recommendation: This check is already covered by test_unknown_check_recorded_as_error and test_mixed_known_and_unknown_partial_success, which exercise the actual rejection logic. Delete this tautological constant check.

### tests/test_bridges/test_x64dbg_audit6.py:816 - test_default_param_matches_documented_default
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:836 - test_pipe_disconnected_is_not_recoverable
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:855 - test_unknown_command_is_recoverable
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:870 - test_real_remote_error_propagates
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:889 - test_structured_code_field_overrides_legacy_text
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:919 - test_string_value_is_parsed
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:932 - test_int_value_returns_unchanged
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:945 - test_unparseable_string_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:959 - test_none_result_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:973 - test_bool_result_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:997 - test_dict_payload_is_returned
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1016 - test_list_payload_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1040 - test_breakpoint_present_in_bp_list
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1065 - test_breakpoint_absent_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1085 - test_breakpoint_skipped_when_bp_list_unknown
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1105 - test_breakpoint_protocol_violation_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1129 - test_run_to_reaches_target
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1153 - test_run_to_times_out_when_ip_misses_target
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1175 - test_run_to_skipped_when_reg_get_unknown
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1206 - test_nop_range_returns_unverified_when_not_attached
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1228 - test_patch_instruction_returns_unverified_when_not_attached
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1260 - test_save_database_falls_back_on_unknown_rpc
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1285 - test_save_database_propagates_pipe_disconnect
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1320 - test_thread_suspend_logs_at_debug_with_queued_wording
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1352 - test_script_load_logs_at_debug
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1384 - test_pipe_disconnected_attaches_code
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1399 - test_timeout_attaches_code
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1442 - test_plugin_unavailable_attaches_code
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1609 - test_set_breakpoint_returns_native_address_after_verification
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1642 - test_set_breakpoint_rejects_unverifiable_breakpoint
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1658 - test_set_breakpoint_with_condition_issues_bpcond
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1697 - test_remove_breakpoint_uses_address_keyed_native_id
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1731 - test_concurrent_set_breakpoint_calls_serialise_state
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1760 - test_handle_event_breakpoint_hit_counts_under_concurrent_mutation
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1823 - test_get_threads_populates_start_address_and_pc
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1904 - test_read_module_entry_point_validates_pe32_magic
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1916 - test_read_module_entry_point_rejects_unknown_magic
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1927 - test_read_module_entry_point_rejects_undersized_optional_header
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1939 - test_disassemble_failure_raises_instead_of_swallowing
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:1984 - test_get_parent_pid_narrow_exception_does_not_swallow_typeerror
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2027 - test_process_handle_cache_reused_across_reads
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2079 - test_release_process_handles_empties_cache
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2118 - test_detach_releases_cached_handles
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2186 - test_wildcard_match_beyond_first_chunk
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2230 - test_wildcard_match_across_chunk_boundary
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2275 - test_recursive_walk_emits_leaves_with_size_and_rva
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2325 - test_multiple_leaves
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2470 - test_no_truncation_above_pe_export_max
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2516 - test_partial_results_when_some_blocks_unreadable
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2552 - test_large_region_chunked_calls
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2579 - test_invalid_block_size_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2593 - test_resolves_via_get_proc_address
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2632 - test_falls_back_to_bpx_when_unresolved
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2680 - test_falls_back_when_eval_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2914 - test_pe64_machine_returns_true
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2925 - test_pe32_machine_returns_false
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2936 - test_arm64_machine_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2948 - test_arm_machine_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2960 - test_ia64_machine_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2972 - test_missing_mz_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2984 - test_truncated_file_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:2996 - test_missing_pe_signature_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3012 - test_io_error_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3027 - test_non_windows_returns_none
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3038 - test_invalid_pid_returns_none
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3046 - test_current_process_resolves
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3052 - test_attach_raises_when_arch_unknown
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3072 - test_non_windows_raises
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3088 - test_non_windows_does_not_sleep
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3118 - test_popen_uses_devnull
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3175 - test_refuses_when_plugin_not_deployed
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3224 - test_close_connection_failure_still_terminates_process
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3293 - test_step_resolves_on_paused_event
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3332 - test_step_resolves_on_breakpoint_event
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3371 - test_step_times_out_when_no_pause_arrives
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3405 - test_step_does_not_use_fixed_sleep
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

### tests/test_bridges/test_x64dbg_audit6.py:3412 - test_register_step_waiter_returns_future_bound_to_loop
- Violation(s): None—this is a real gate
- Why it is not a real gate: N/A
- Severity: Clean

## Clean tests
- tests/test_bridges/test_x64dbg_audit6.py:489 - test_read_memory_still_opens_process
- tests/test_bridges/test_x64dbg_audit6.py:534 - test_well_formed_returns_string
- tests/test_bridges/test_x64dbg_audit6.py:544 - test_odd_length_returns_none
- tests/test_bridges/test_x64dbg_audit6.py:558 - test_length_exceeds_maximum_returns_none
- tests/test_bridges/test_x64dbg_audit6.py:581 - test_raises_when_not_attached
- tests/test_bridges/test_x64dbg_audit6.py:675 - test_returns_field_lists_address
- tests/test_bridges/test_x64dbg_audit6.py:696 - test_default_checks_apply_being_debugged_and_nt_global
- tests/test_bridges/test_x64dbg_audit6.py:719 - test_32bit_uses_correct_offsets
- tests/test_bridges/test_x64dbg_audit6.py:740 - test_missing_address_records_per_check_error
- tests/test_bridges/test_x64dbg_audit6.py:753 - test_malformed_address_records_per_check_error
- tests/test_bridges/test_x64dbg_audit6.py:763 - test_read_peb_failure_records_per_check_error
- tests/test_bridges/test_x64dbg_audit6.py:778 - test_unknown_check_recorded_as_error
- tests/test_bridges/test_x64dbg_audit6.py:792 - test_mixed_known_and_unknown_partial_success
- tests/test_bridges/test_x64dbg_audit6.py:816 - test_default_param_matches_documented_default
- tests/test_bridges/test_x64dbg_audit6.py:836 - test_pipe_disconnected_is_not_recoverable
- tests/test_bridges/test_x64dbg_audit6.py:855 - test_unknown_command_is_recoverable
- tests/test_bridges/test_x64dbg_audit6.py:870 - test_real_remote_error_propagates
- tests/test_bridges/test_x64dbg_audit6.py:889 - test_structured_code_field_overrides_legacy_text
- tests/test_bridges/test_x64dbg_audit6.py:919 - test_string_value_is_parsed
- tests/test_bridges/test_x64dbg_audit6.py:932 - test_int_value_returns_unchanged
- tests/test_bridges/test_x64dbg_audit6.py:945 - test_unparseable_string_raises
- tests/test_bridges/test_x64dbg_audit6.py:959 - test_none_result_raises
- tests/test_bridges/test_x64dbg_audit6.py:973 - test_bool_result_raises
- tests/test_bridges/test_x64dbg_audit6.py:997 - test_dict_payload_is_returned
- tests/test_bridges/test_x64dbg_audit6.py:1016 - test_list_payload_raises
- tests/test_bridges/test_x64dbg_audit6.py:1040 - test_breakpoint_present_in_bp_list
- tests/test_bridges/test_x64dbg_audit6.py:1065 - test_breakpoint_absent_raises
- tests/test_bridges/test_x64dbg_audit6.py:1085 - test_breakpoint_skipped_when_bp_list_unknown
- tests/test_bridges/test_x64dbg_audit6.py:1105 - test_breakpoint_protocol_violation_raises
- tests/test_bridges/test_x64dbg_audit6.py:1129 - test_run_to_reaches_target
- tests/test_bridges/test_x64dbg_audit6.py:1153 - test_run_to_times_out_when_ip_misses_target
- tests/test_bridges/test_x64dbg_audit6.py:1175 - test_run_to_skipped_when_reg_get_unknown
- tests/test_bridges/test_x64dbg_audit6.py:1206 - test_nop_range_returns_unverified_when_not_attached
- tests/test_bridges/test_x64dbg_audit6.py:1228 - test_patch_instruction_returns_unverified_when_not_attached
- tests/test_bridges/test_x64dbg_audit6.py:1260 - test_save_database_falls_back_on_unknown_rpc
- tests/test_bridges/test_x64dbg_audit6.py:1285 - test_save_database_propagates_pipe_disconnect
- tests/test_bridges/test_x64dbg_audit6.py:1320 - test_thread_suspend_logs_at_debug_with_queued_wording
- tests/test_bridges/test_x64dbg_audit6.py:1352 - test_script_load_logs_at_debug
- tests/test_bridges/test_x64dbg_audit6.py:1384 - test_pipe_disconnected_attaches_code
- tests/test_bridges/test_x64dbg_audit6.py:1399 - test_timeout_attaches_code
- tests/test_bridges/test_x64dbg_audit6.py:1442 - test_plugin_unavailable_attaches_code
- tests/test_bridges/test_x64dbg_audit6.py:1609 - test_set_breakpoint_returns_native_address_after_verification
- tests/test_bridges/test_x64dbg_audit6.py:1642 - test_set_breakpoint_rejects_unverifiable_breakpoint
- tests/test_bridges/test_x64dbg_audit6.py:1658 - test_set_breakpoint_with_condition_issues_bpcond
- tests/test_bridges/test_x64dbg_audit6.py:1697 - test_remove_breakpoint_uses_address_keyed_native_id
- tests/test_bridges/test_x64dbg_audit6.py:1731 - test_concurrent_set_breakpoint_calls_serialise_state
- tests/test_bridges/test_x64dbg_audit6.py:1760 - test_handle_event_breakpoint_hit_counts_under_concurrent_mutation
- tests/test_bridges/test_x64dbg_audit6.py:1823 - test_get_threads_populates_start_address_and_pc
- tests/test_bridges/test_x64dbg_audit6.py:1904 - test_read_module_entry_point_validates_pe32_magic
- tests/test_bridges/test_x64dbg_audit6.py:1916 - test_read_module_entry_point_rejects_unknown_magic
- tests/test_bridges/test_x64dbg_audit6.py:1927 - test_read_module_entry_point_rejects_undersized_optional_header
- tests/test_bridges/test_x64dbg_audit6.py:1939 - test_disassemble_failure_raises_instead_of_swallowing
- tests/test_bridges/test_x64dbg_audit6.py:1984 - test_get_parent_pid_narrow_exception_does_not_swallow_typeerror
- tests/test_bridges/test_x64dbg_audit6.py:2027 - test_process_handle_cache_reused_across_reads
- tests/test_bridges/test_x64dbg_audit6.py:2079 - test_release_process_handles_empties_cache
- tests/test_bridges/test_x64dbg_audit6.py:2118 - test_detach_releases_cached_handles
- tests/test_bridges/test_x64dbg_audit6.py:2186 - test_wildcard_match_beyond_first_chunk
- tests/test_bridges/test_x64dbg_audit6.py:2230 - test_wildcard_match_across_chunk_boundary
- tests/test_bridges/test_x64dbg_audit6.py:2275 - test_recursive_walk_emits_leaves_with_size_and_rva
- tests/test_bridges/test_x64dbg_audit6.py:2325 - test_multiple_leaves
- tests/test_bridges/test_x64dbg_audit6.py:2470 - test_no_truncation_above_pe_export_max
- tests/test_bridges/test_x64dbg_audit6.py:2516 - test_partial_results_when_some_blocks_unreadable
- tests/test_bridges/test_x64dbg_audit6.py:2552 - test_large_region_chunked_calls
- tests/test_bridges/test_x64dbg_audit6.py:2579 - test_invalid_block_size_raises
- tests/test_bridges/test_x64dbg_audit6.py:2593 - test_resolves_via_get_proc_address
- tests/test_bridges/test_x64dbg_audit6.py:2632 - test_falls_back_to_bpx_when_unresolved
- tests/test_bridges/test_x64dbg_audit6.py:2680 - test_falls_back_when_eval_raises
- tests/test_bridges/test_x64dbg_audit6.py:2914 - test_pe64_machine_returns_true
- tests/test_bridges/test_x64dbg_audit6.py:2925 - test_pe32_machine_returns_false
- tests/test_bridges/test_x64dbg_audit6.py:2936 - test_arm64_machine_raises
- tests/test_bridges/test_x64dbg_audit6.py:2948 - test_arm_machine_raises
- tests/test_bridges/test_x64dbg_audit6.py:2960 - test_ia64_machine_raises
- tests/test_bridges/test_x64dbg_audit6.py:2972 - test_missing_mz_raises
- tests/test_bridges/test_x64dbg_audit6.py:2984 - test_truncated_file_raises
- tests/test_bridges/test_x64dbg_audit6.py:2996 - test_missing_pe_signature_raises
- tests/test_bridges/test_x64dbg_audit6.py:3012 - test_io_error_raises
- tests/test_bridges/test_x64dbg_audit6.py:3027 - test_non_windows_returns_none
- tests/test_bridges/test_x64dbg_audit6.py:3038 - test_invalid_pid_returns_none
- tests/test_bridges/test_x64dbg_audit6.py:3046 - test_current_process_resolves
- tests/test_bridges/test_x64dbg_audit6.py:3052 - test_attach_raises_when_arch_unknown
- tests/test_bridges/test_x64dbg_audit6.py:3072 - test_non_windows_raises
- tests/test_bridges/test_x64dbg_audit6.py:3088 - test_non_windows_does_not_sleep
- tests/test_bridges/test_x64dbg_audit6.py:3118 - test_popen_uses_devnull
- tests/test_bridges/test_x64dbg_audit6.py:3175 - test_refuses_when_plugin_not_deployed
- tests/test_bridges/test_x64dbg_audit6.py:3224 - test_close_connection_failure_still_terminates_process
- tests/test_bridges/test_x64dbg_audit6.py:3293 - test_step_resolves_on_paused_event
- tests/test_bridges/test_x64dbg_audit6.py:3332 - test_step_resolves_on_breakpoint_event
- tests/test_bridges/test_x64dbg_audit6.py:3371 - test_step_times_out_when_no_pause_arrives
- tests/test_bridges/test_x64dbg_audit6.py:3405 - test_step_does_not_use_fixed_sleep
- tests/test_bridges/test_x64dbg_audit6.py:3412 - test_register_step_waiter_returns_future_bound_to_loop

## Summary
- Findings by severity
  - Critical: 0
  - High: 0
  - Medium: 1 (test_constant_not_exposed)
  - Low: 3 (test_source_inlines_false_for_inherit_handle, test_return_annotation_is_processinfo, test_constant_has_expected_entries)
- Total tests audited: 94
- Total tests clean: 90

---

# SUPPLEMENT B (gap-closure: frida_bridge, hexpat_compiler_e2e, providers_local_audit1, va_mapping, hexpat_control_flow, undo_redo)

# Agent 03 - Test Quality Audit (Part 2)

## Partition
- tests/test_bridges/test_frida_bridge.py
- tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py
- tests/test_providers/test_providers_local_audit1.py
- tests/test_hexcore_e2e/test_bridge_va_mapping.py
- tests/test_hexcore_e2e/test_hexpat_control_flow.py
- tests/test_hexcore_e2e/test_undo_redo.py

Total test functions audited: 144

## Findings

### tests/test_bridges/test_frida_bridge.py:97 - test_symbol_info_full
- Violation(s): Smoke-test-as-gate (only tests dataclass field assignments)
- Why it is not a real gate: This test merely constructs a SymbolInfo object and reads back fields. It does not verify that SymbolInfo is used correctly in any real operation, nor does it test falsifiability. If the SymbolInfo constructor were deleted or broken, the assertion still holds.
- Severity: Low
- Fix recommendation: Replace with an end-to-end test that exercises SymbolInfo within an actual bridge operation (e.g., resolve_symbol) and verifies the returned symbol carries correct real data from a live process.

### tests/test_bridges/test_frida_bridge.py:113 - test_symbol_info_none_optionals
- Violation(s): Smoke-test-as-gate (tests only that optional fields accept None)
- Why it is not a real gate: Merely verifies that None can be assigned to optional fields. Does not test falsifiable behavior.
- Severity: Low
- Fix recommendation: Remove or consolidate with an end-to-end test that validates optional field handling in context of actual use.

### tests/test_bridges/test_frida_bridge.py:127 - test_crash_info_construction
- Violation(s): Smoke-test-as-gate (only constructs dataclass and reads fields)
- Why it is not a real gate: Verifies field assignments on a dataclass, not any real gate behavior.
- Severity: Low
- Fix recommendation: Test as part of a real crash-detection operation (e.g., enable_crash_reporting + triggering a crash).

### tests/test_bridges/test_frida_bridge.py:145 - test_child_process_info_full
- Violation(s): Smoke-test-as-gate (only dataclass construction)
- Why it is not a real gate: Merely tests that fields can be set on a dataclass.
- Severity: Low
- Fix recommendation: Test within enumerate_child_processes or similar real operation.

### tests/test_bridges/test_frida_bridge.py:163 - test_child_process_info_none_optionals
- Violation(s): Smoke-test-as-gate (tests optional fields)
- Why it is not a real gate: Only checks that None is assignable to optional fields.
- Severity: Low
- Fix recommendation: Remove or test in context of real child enumeration.

### tests/test_bridges/test_frida_bridge.py:178 - test_stalker_event_call
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Only constructs and validates StalkerEvent fields.
- Severity: Low
- Fix recommendation: Test as part of an actual stalker trace collection from a live thread.

### tests/test_bridges/test_frida_bridge.py:192 - test_stalker_event_exec_no_destination
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Only checks that to_address can be None.
- Severity: Low
- Fix recommendation: Test in actual stalker trace context.

### tests/test_bridges/test_frida_bridge.py:203 - test_stalker_trace_with_events
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Constructs a StalkerTrace with hand-built event list and validates field counts. Does not verify that real trace data from stalker_follow is correctly shaped.
- Severity: Low
- Fix recommendation: Test the actual stalker trace returned from stalker_follow on a live worker thread.

### tests/test_bridges/test_frida_bridge.py:221 - test_stalker_trace_empty
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Only checks that an empty trace can be constructed.
- Severity: Low
- Fix recommendation: Remove.

### tests/test_bridges/test_frida_bridge.py:228 - test_frida_device_info
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Only tests dataclass construction.
- Severity: Low
- Fix recommendation: Consolidate with enumerate_devices test.

### tests/test_bridges/test_frida_bridge.py:236 - test_api_resolver_match
- Violation(s): Smoke-test-as-gate
- Why it is not a real gate: Only constructs a dataclass.
- Severity: Low
- Fix recommendation: Test in context of resolve_api results.

### tests/test_bridges/test_frida_bridge.py:243 - test_tool_definition_returns_frida_tool
- Violation(s): Smoke-test-as-gate (only checks tool_name attribute)
- Why it is not a real gate: Only reads a static attribute. If tool_definition were deleted, this would still compile.
- Severity: Low
- Fix recommendation: Test that the tool_definition is correctly used by ToolRegistry.execute_tool_call.

### tests/test_bridges/test_frida_bridge.py:250 - test_all_function_names_have_methods
- Violation(s): Weak assertion on rich output (only checks method existence via hasattr)
- Why it is not a real gate: Verifies that methods exist but does not verify they are callable or functional. A method stub would pass.
- Severity: Medium
- Fix recommendation: Call each function with appropriate test inputs and verify correct return types and values, not just existence.

### tests/test_bridges/test_frida_bridge.py:262 - test_function_count_minimum
- Violation(s): No-assertion / vacuous-assertion (only checks len >= constant)
- Why it is not a real gate: Merely counts functions without validating that new functions actually work. A constant could be lowered to pass trivially.
- Severity: Low
- Fix recommendation: Remove or test that specific new functions from the parity plan actually execute on a live process.

### tests/test_bridges/test_frida_bridge.py:269 - test_no_duplicate_function_names
- Violation(s): Smoke-test-as-gate (only validates a metadata property)
- Why it is not a real gate: Checks a static list property, not runtime behavior.
- Severity: Low
- Fix recommendation: Remove; this is a one-time validation that does not need to be tested on every run.

### tests/test_bridges/test_frida_bridge.py:278 - test_new_functions_present
- Violation(s): Smoke-test-as-gate (only checks name registration)
- Why it is not a real gate: Verifies function names are registered but does not verify they work.
- Severity: Medium
- Fix recommendation: Call each new function with realistic inputs on a live process and verify correct behavior.

### tests/test_bridges/test_frida_bridge.py:308 - test_fixed_functions_present
- Violation(s): Smoke-test-as-gate (only checks name registration)
- Why it is not a real gate: Verifies names but not function correctness.
- Severity: Low
- Fix recommendation: Remove or test that the fixed functions work correctly (e.g., enumerate_imports actually enumerates).

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:103 - test_compile_simple_struct_returns_json_string
- Violation(s): Smoke-test-as-gate (only checks that result is a string and parses as JSON)
- Why it is not a real gate: Verifies JSON format but not the actual compiled structure correctness.
- Severity: Low
- Fix recommendation: Assert exact JSON keys, values, and field count against a known-correct reference.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:109 - test_compile_simple_struct_has_name_key
- Violation(s): Weak assertion on rich output (only checks one key value)
- Why it is not a real gate: Only verifies the struct name. If fields were deleted or corrupted, this would not catch it.
- Severity: Low
- Fix recommendation: Combine with deeper assertions on the full structure.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:115 - test_compile_simple_struct_has_fields_key
- Violation(s): Weak assertion on rich output (only checks key existence and type)
- Why it is not a real gate: Does not verify actual field content.
- Severity: Low
- Fix recommendation: Assert exact field count and field definitions.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:122 - test_compile_simple_struct_field_count
- Violation(s): Weak assertion on rich output (only checks field count)
- Why it is not a real gate: Does not verify field names or types.
- Severity: Low
- Fix recommendation: Assert all field properties: name, type, size, endianness.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:128 - test_compile_to_dict_returns_dict
- Violation(s): Smoke-test-as-gate (only checks return type)
- Why it is not a real gate: Does not verify content.
- Severity: Low
- Fix recommendation: Merge with fuller assertions on dict content.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:133 - test_compile_to_dict_expected_keys
- Violation(s): Weak assertion on rich output (only checks key existence)
- Why it is not a real gate: Does not verify key values.
- Severity: Low
- Fix recommendation: Assert exact values and structure of all keys.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:141 - test_compile_multi_field_struct
- Violation(s): Weak assertion on rich output (only checks field names, not types or sizes)
- Why it is not a real gate: Does not verify that field types are correct or that the compiled structure would actually parse data correctly.
- Severity: Medium
- Fix recommendation: Assert field types, sizes, and test the compiled template against actual binary data to verify it parses correctly.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:148 - test_compile_array_field
- Violation(s): Weak assertion on rich output (only checks array count, not type or element correctness)
- Why it is not a real gate: Does not verify that the array is usable by the interpreter.
- Severity: Medium
- Fix recommendation: Compile the template and execute it on real binary data to verify array parsing works.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:155 - test_compile_enum
- Violation(s): Smoke-test-as-gate (only checks struct name)
- Why it is not a real gate: Does not verify enum values were compiled.
- Severity: Low
- Fix recommendation: Assert enum values and test execution on data matching enum constants.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:160 - test_compile_union
- Violation(s): Smoke-test-as-gate (only checks name)
- Why it is not a real gate: Does not verify union fields.
- Severity: Low
- Fix recommendation: Assert union structure and test.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:165 - test_compile_bitfield
- Violation(s): Smoke-test-as-gate (only checks name)
- Why it is not a real gate: Does not verify bitfield entries.
- Severity: Low
- Fix recommendation: Assert bitfield structure and test.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:170 - test_compile_endianness_annotations
- Violation(s): Weak assertion on rich output (only checks endianness field values, does not verify parsing behavior)
- Why it is not a real gate: Does not verify that endianness actually affects parsing.
- Severity: Medium
- Fix recommendation: Compile and execute the template on binary data with both byte orders, verify results differ correctly.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:177 - test_compile_nested_struct
- Violation(s): Smoke-test-as-gate (only checks name and keys)
- Why it is not a real gate: Does not verify nested structure is correct.
- Severity: Low
- Fix recommendation: Assert full nested structure and test execution.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:184 - test_compile_syntax_error_missing_semicolon_raises
- Violation(s): No assertion of specific exception details (only checks exception type)
- Why it is not a real gate: Correctly raises but does not verify error message quality.
- Severity: Low
- Fix recommendation: Assert error message contains useful diagnostic information.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:190 - test_compile_empty_source_raises_no_struct
- Violation(s): No assertion of specific exception details
- Why it is not a real gate: Only checks exception type.
- Severity: Low
- Fix recommendation: Assert error message.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:195 - test_compile_if_else_eq_emits_paired_conditionals
- Violation(s): Weak assertion on rich output (only checks op names, not full condition structure)
- Why it is not a real gate: Does not verify the conditional logic is inverted correctly or would execute properly.
- Severity: Medium
- Fix recommendation: Execute the template on data matching both conditions and verify correct field placement in each case.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:206 - test_compile_if_else_bitmask_emits_bitand_paired_with_bitandzero
- Violation(s): Weak assertion on rich output (only checks operation names and value)
- Why it is not a real gate: Does not verify the bit-and logic works correctly.
- Severity: Medium
- Fix recommendation: Execute with data where bits are set and unset, verify correct fields appear.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:223 - test_compile_if_only_bitmask_emits_single_bitand_conditional
- Violation(s): Weak assertion on rich output
- Why it is not a real gate: Only checks operation name.
- Severity: Low
- Fix recommendation: Execute and verify behavior.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:237 - test_tokenize_simple_struct_produces_tokens
- Violation(s): Smoke-test-as-gate (only checks token count > 0)
- Why it is not a real gate: Does not verify tokens are correct.
- Severity: Low
- Fix recommendation: Assert specific token sequence.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:242 - test_tokenize_includes_eof_token
- Violation(s): Smoke-test-as-gate (only checks final token type)
- Why it is not a real gate: Does not verify token sequence.
- Severity: Low
- Fix recommendation: Remove; lexer EOF token is implementation detail.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:247 - test_tokenize_struct_keyword_present
- Violation(s): Smoke-test-as-gate (only checks token type presence)
- Why it is not a real gate: Does not verify full token sequence or correctness.
- Severity: Low
- Fix recommendation: Assert full tokenization.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:253 - test_tokenize_identifier_names_captured
- Violation(s): Weak assertion on rich output (only checks specific identifiers appear)
- Why it is not a real gate: Does not verify they appear in the correct order or context.
- Severity: Low
- Fix recommendation: Assert full token sequence with positions.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:261 - test_tokenize_hex_number
- Violation(s): Weak assertion on rich output (only checks number value appears)
- Why it is not a real gate: Does not verify it appears in correct position.
- Severity: Low
- Fix recommendation: Assert position and surrounding tokens.

### tests/test_hexcore_e2e/test_hexpat_compiler_e2e.py:268 - test_tokenize_line_numbers_advance_correctly
- Violation(s): Weak assertion on rich output (only checks one token's line >= 3)
- Why it is not a real gate: Does not verify line numbers are correct throughout.
- Severity: Low
- Fix recommendation: Assert line numbers for all tokens.

### tests/test_providers/test_providers_local_audit1.py:218 - test_f0001_b580_device_ids_constant_drives_detection
- Violation(s): No-assertion / vacuous-assertion (only checks constant membership and runs assertion loop)
- Why it is not a real gate: The loop assertions are tautological: if _is_b580_device is implemented correctly, any ID in _B580_DEVICE_IDS will match by definition. Does not test detection of non-B580 IDs.
- Severity: Critical
- Fix recommendation: Test both positive (B580 IDs match) and negative (non-B580 IDs like "0xE20C" do NOT match) cases to verify the detection logic falsifiably.

### tests/test_providers/test_providers_local_audit1.py:233 - test_f0001_intel_vendor_id_filters_non_intel_pnp
- Violation(s): Correct gate with real, independently-known PNP strings
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:257 - test_f0002_openai_stream_dict_arguments_are_preserved
- Violation(s): Correct gate with real tool-call accumulation
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:295 - test_f0002_openai_stream_string_chunks_still_accumulate
- Violation(s): Correct gate testing incremental accumulation
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:322 - test_f0003_chat_rejects_empty_model_string
- Violation(s): Correct gate testing error path
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:337 - test_f0003_chat_stream_rejects_empty_model_string
- Violation(s): Correct gate testing error path
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:358 - test_f0004_init_logger_binds_provider_field
- Violation(s): Correct gate verifying logger binding
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:383 - test_f0004_provider_name_matches_logger_binding
- Violation(s): Correct gate testing sanity check
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:398 - test_f0005_extract_text_handles_pretty_printed_tool_call
- Violation(s): Correct gate with real formatted JSON and whitespace
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:425 - test_f0005_extract_text_handles_compact_tool_call
- Violation(s): Correct gate testing regression
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:444 - test_f0006_format_prompt_handles_tokenizer_without_chat_template
- Violation(s): Correct gate reproducing exact failure scenario
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:535 - test_f0007_check_rebar_status_reports_enabled_for_large_bar
- Violation(s): Correct gate with realistic hardware config
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:554 - test_f0007_check_rebar_status_reports_disabled_for_capped_bar
- Violation(s): Correct gate testing boundary condition
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:571 - test_f0007_check_rebar_status_handles_missing_bar_data
- Violation(s): Correct gate testing error path
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_providers/test_providers_local_audit1.py:588 - test_f0007_check_rebar_status_skips_silently_without_intel_arc
- Violation(s): Correct gate testing absence condition
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_bridge_va_mapping.py:63 - test_set_va_base_and_list
- Violation(s): Correct gate testing VA mapping creation and retrieval
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_bridge_va_mapping.py:79 - test_set_va_base_returns_true
- Violation(s): Weak assertion on rich output (only checks return boolean, not actual mapping state)
- Why it is not a real gate: Does not verify mapping was actually created, only that the method returned True.
- Severity: Medium
- Fix recommendation: Assert that list_va_mappings contains the mapping after set_va_base returns True.

### tests/test_hexcore_e2e/test_bridge_va_mapping.py:93 - test_remove_va_mapping
- Violation(s): Correct gate testing removal operation
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_bridge_va_mapping.py:115 - test_file_offset_to_va
- Violation(s): Correct gate testing address conversion
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_bridge_va_mapping.py:130 - test_va_to_file_offset
- Violation(s): Correct gate testing reverse conversion
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_bridge_va_mapping.py:144 - test_unmapped_offset_returns_none
- Violation(s): Correct gate testing boundary condition
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_bridge_va_mapping.py:162 - test_auto_detect_pe_va_mappings
- Violation(s): Weak assertion on rich output (only checks mapping count >= 2 and address range)
- Why it is not a real gate: Does not verify exact ImageBase or section-to-VA mapping correctness.
- Severity: Medium
- Fix recommendation: Assert exact ImageBase (0x400000 for default PE) and verify specific section names (.text, .data) map to correct VAs.

### tests/test_hexcore_e2e/test_bridge_va_mapping.py:175 - test_auto_detect_elf_va_mappings
- Violation(s): Weak assertion on rich output (only checks count and some offsets)
- Why it is not a real gate: Does not verify VA values are correct, only offsets.
- Severity: Medium
- Fix recommendation: Assert that VAs match expected PT_LOAD p_vaddr values (0x400000, 0x401000).

### tests/test_hexcore_e2e/test_bridge_va_mapping.py:189 - test_auto_detect_non_pe_elf_returns_empty
- Violation(s): Correct gate testing negative case
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_bridge_va_mapping.py:202 - test_no_document_raises
- Violation(s): Correct gate testing error path
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:26 - test_while_counter_loop_produces_fields
- Violation(s): Weak assertion on rich output (only checks field count)
- Why it is not a real gate: Does not verify field values, names, or order are correct.
- Severity: Medium
- Fix recommendation: Assert field count is exactly 4, field names are "byte" or "i", and byte values match expected sequence.

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:37 - test_while_sentinel_stops_at_zero
- Violation(s): Weak assertion on rich output (only checks field count)
- Why it is not a real gate: Does not verify fields contain the correct data or that sentinel detection worked.
- Severity: Medium
- Fix recommendation: Assert exactly 3 fields with correct byte values (0x01, 0x02, 0x03), verify 0x00 sentinel was not parsed.

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:48 - test_while_empty_body_terminates_immediately
- Violation(s): Weak assertion on rich output (only checks empty list)
- Why it is not a real gate: Does not verify the false condition actually prevented execution.
- Severity: Low
- Fix recommendation: Add a second test with true initial condition to verify execution occurs.

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:63 - test_for_loop_fixed_count
- Violation(s): Weak assertion on rich output (only checks count)
- Why it is not a real gate: Does not verify field values or names.
- Severity: Medium
- Fix recommendation: Assert field names and values.

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:74 - test_for_loop_field_values_correct
- Violation(s): Correct gate with value assertions
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:87 - test_for_loop_zero_iterations
- Violation(s): Correct gate testing boundary
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:102 - test_match_first_arm_selected
- Violation(s): Correct gate testing match selection
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:115 - test_match_second_arm_selected
- Violation(s): Correct gate testing match selection
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:128 - test_match_wildcard_arm_catches_unmatched
- Violation(s): Correct gate testing wildcard
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:141 - test_match_no_arm_matches_produces_no_extra_fields
- Violation(s): Correct gate testing no-match case
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:157 - test_try_catch_handles_out_of_bounds
- Violation(s): Correct gate testing error recovery
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:169 - test_try_body_succeeds_no_catch
- Violation(s): Correct gate testing success path
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:186 - test_break_exits_while_loop_early
- Violation(s): Correct gate testing break behavior
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:197 - test_continue_skips_iteration_body
- Violation(s): Correct gate testing continue behavior
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:222 - test_nested_for_inside_while
- Violation(s): Correct gate testing nested loops
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:241 - test_conditional_inside_for_loop
- Violation(s): Correct gate testing nested conditionals
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:264 - test_while_loop_accumulates_variable
- Violation(s): Weak assertion (no explicit assertion, only execution)
- Why it is not a real gate: Does not assert accumulated value correctness.
- Severity: Medium
- Fix recommendation: Assert that variable accumulates to correct total (1+2+3+4+5=15) by placing it as a final field and checking its value.

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:274 - test_try_inside_for_loop_recovers_per_iteration
- Violation(s): Weak assertion on rich output (only checks field count >= 1)
- Why it is not a real gate: Does not verify recovery per iteration or exact field count.
- Severity: Low
- Fix recommendation: Assert exactly 4 fields (one per iteration) with mixed types (u32 or u8 depending on success/failure).

### tests/test_hexcore_e2e/test_hexpat_control_flow.py:285 - test_match_inside_while_selects_branch_each_iteration
- Violation(s): Correct gate testing per-iteration match selection
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:18 - test_can_undo_false_on_fresh_doc
- Violation(s): Correct gate testing initial state
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:26 - test_can_redo_false_on_fresh_doc
- Violation(s): Correct gate testing initial state
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:34 - test_write_enables_can_undo
- Violation(s): Correct gate testing state transition
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:43 - test_undo_restores_previous_data
- Violation(s): Correct gate testing undo operation with exact value assertion
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:56 - test_redo_restores_written_data
- Violation(s): Correct gate testing redo with exact value assertion
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:70 - test_multiple_undo_steps
- Violation(s): Correct gate testing multiple operations
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:91 - test_new_write_after_undo_clears_redo_stack
- Violation(s): Correct gate testing redo stack invalidation
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:103 - test_can_redo_true_after_undo
- Violation(s): Correct gate testing state transition
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:113 - test_undo_returns_false_when_stack_empty
- Violation(s): Correct gate testing error case
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:121 - test_redo_returns_false_when_stack_empty
- Violation(s): Correct gate testing error case
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:133 - test_is_modified_false_on_fresh_open
- Violation(s): Correct gate testing initial state
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:141 - test_is_modified_true_after_write
- Violation(s): Correct gate testing state transition
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_hexcore_e2e/test_undo_redo.py:150 - test_is_modified_tracks_through_undo_redo
- Violation(s): Correct gate testing state tracking through operations
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:441 - test_enumerate_processes
- Violation(s): Correct gate testing real process enumeration
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:455 - test_enumerate_devices
- Violation(s): Correct gate testing device enumeration
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:473 - test_connect_device_local
- Violation(s): Correct gate testing device connection
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:485 - test_enumerate_threads
- Violation(s): Correct gate testing real thread enumeration
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:502 - test_enumerate_imports_kernel32
- Violation(s): Correct gate testing real import enumeration
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:524 - test_find_base_address_ntdll
- Violation(s): Correct gate testing real module base address
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:537 - test_find_base_address_kernel32
- Violation(s): Correct gate testing multiple module addresses
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:552 - test_get_memory_regions
- Violation(s): Correct gate testing real memory region enumeration
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:576 - test_resolve_api_createfile
- Violation(s): Correct gate testing real API resolution
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:593 - test_resolve_symbol
- Violation(s): Correct gate testing real symbol resolution
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:613 - test_find_functions_named
- Violation(s): Correct gate testing real function lookup
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:627 - test_allocate_memory
- Violation(s): Correct gate testing memory allocation and read-write
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:642 - test_protect_memory
- Violation(s): Correct gate testing memory protection
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:654 - test_read_write_memory_roundtrip
- Violation(s): Correct gate testing memory I/O correctness
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:670 - test_hook_and_remove
- Violation(s): Correct gate testing hook lifecycle
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:685 - test_stalker_follow_and_unfollow
- Violation(s): Correct gate testing real stalker trace collection
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:716 - test_child_gating_not_supported_on_windows
- Violation(s): Correct gate testing platform-specific error
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:727 - test_get_pending_children_empty
- Violation(s): Correct gate testing empty list return
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:738 - test_crash_reporting_lifecycle
- Violation(s): Correct gate testing crash detection initialization
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

### tests/test_bridges/test_frida_bridge.py:753 - test_enumerate_processes_contains_notepad
- Violation(s): Correct gate testing real process appearance
- Why it is not a real gate: [This test is CLEAN]
- Severity: N/A
- Fix recommendation: N/A

## Clean tests
- tests/test_bridges/test_frida_bridge.py:441 - test_enumerate_processes
- tests/test_bridges/test_frida_bridge.py:455 - test_enumerate_devices
- tests/test_bridges/test_frida_bridge.py:473 - test_connect_device_local
- tests/test_bridges/test_frida_bridge.py:485 - test_enumerate_threads
- tests/test_bridges/test_frida_bridge.py:502 - test_enumerate_imports_kernel32
- tests/test_bridges/test_frida_bridge.py:524 - test_find_base_address_ntdll
- tests/test_bridges/test_frida_bridge.py:537 - test_find_base_address_kernel32
- tests/test_bridges/test_frida_bridge.py:552 - test_get_memory_regions
- tests/test_bridges/test_frida_bridge.py:576 - test_resolve_api_createfile
- tests/test_bridges/test_frida_bridge.py:593 - test_resolve_symbol
- tests/test_bridges/test_frida_bridge.py:613 - test_find_functions_named
- tests/test_bridges/test_frida_bridge.py:627 - test_allocate_memory
- tests/test_bridges/test_frida_bridge.py:642 - test_protect_memory
- tests/test_bridges/test_frida_bridge.py:654 - test_read_write_memory_roundtrip
- tests/test_bridges/test_frida_bridge.py:670 - test_hook_and_remove
- tests/test_bridges/test_frida_bridge.py:685 - test_stalker_follow_and_unfollow
- tests/test_bridges/test_frida_bridge.py:716 - test_child_gating_not_supported_on_windows
- tests/test_bridges/test_frida_bridge.py:727 - test_get_pending_children_empty
- tests/test_bridges/test_frida_bridge.py:738 - test_crash_reporting_lifecycle
- tests/test_bridges/test_frida_bridge.py:753 - test_enumerate_processes_contains_notepad
- tests/test_providers/test_providers_local_audit1.py:233 - test_f0001_intel_vendor_id_filters_non_intel_pnp
- tests/test_providers/test_providers_local_audit1.py:257 - test_f0002_openai_stream_dict_arguments_are_preserved
- tests/test_providers/test_providers_local_audit1.py:295 - test_f0002_openai_stream_string_chunks_still_accumulate
- tests/test_providers/test_providers_local_audit1.py:322 - test_f0003_chat_rejects_empty_model_string
- tests/test_providers/test_providers_local_audit1.py:337 - test_f0003_chat_stream_rejects_empty_model_string
- tests/test_providers/test_providers_local_audit1.py:358 - test_f0004_init_logger_binds_provider_field
- tests/test_providers/test_providers_local_audit1.py:383 - test_f0004_provider_name_matches_logger_binding
- tests/test_providers/test_providers_local_audit1.py:398 - test_f0005_extract_text_handles_pretty_printed_tool_call
- tests/test_providers/test_providers_local_audit1.py:425 - test_f0005_extract_text_handles_compact_tool_call
- tests/test_providers/test_providers_local_audit1.py:444 - test_f0006_format_prompt_handles_tokenizer_without_chat_template
- tests/test_providers/test_providers_local_audit1.py:535 - test_f0007_check_rebar_status_reports_enabled_for_large_bar
- tests/test_providers/test_providers_local_audit1.py:554 - test_f0007_check_rebar_status_reports_disabled_for_capped_bar
- tests/test_providers/test_providers_local_audit1.py:571 - test_f0007_check_rebar_status_handles_missing_bar_data
- tests/test_providers/test_providers_local_audit1.py:588 - test_f0007_check_rebar_status_skips_silently_without_intel_arc
- tests/test_hexcore_e2e/test_bridge_va_mapping.py:63 - test_set_va_base_and_list
- tests/test_hexcore_e2e/test_bridge_va_mapping.py:93 - test_remove_va_mapping
- tests/test_hexcore_e2e/test_bridge_va_mapping.py:115 - test_file_offset_to_va
- tests/test_hexcore_e2e/test_bridge_va_mapping.py:130 - test_va_to_file_offset
- tests/test_hexcore_e2e/test_bridge_va_mapping.py:144 - test_unmapped_offset_returns_none
- tests/test_hexcore_e2e/test_bridge_va_mapping.py:189 - test_auto_detect_non_pe_elf_returns_empty
- tests/test_hexcore_e2e/test_bridge_va_mapping.py:202 - test_no_document_raises
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:74 - test_for_loop_field_values_correct
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:87 - test_for_loop_zero_iterations
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:102 - test_match_first_arm_selected
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:115 - test_match_second_arm_selected
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:128 - test_match_wildcard_arm_catches_unmatched
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:141 - test_match_no_arm_matches_produces_no_extra_fields
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:157 - test_try_catch_handles_out_of_bounds
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:169 - test_try_body_succeeds_no_catch
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:186 - test_break_exits_while_loop_early
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:197 - test_continue_skips_iteration_body
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:222 - test_nested_for_inside_while
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:241 - test_conditional_inside_for_loop
- tests/test_hexcore_e2e/test_hexpat_control_flow.py:285 - test_match_inside_while_selects_branch_each_iteration
- tests/test_hexcore_e2e/test_undo_redo.py:18 - test_can_undo_false_on_fresh_doc
- tests/test_hexcore_e2e/test_undo_redo.py:26 - test_can_redo_false_on_fresh_doc
- tests/test_hexcore_e2e/test_undo_redo.py:34 - test_write_enables_can_undo
- tests/test_hexcore_e2e/test_undo_redo.py:43 - test_undo_restores_previous_data
- tests/test_hexcore_e2e/test_undo_redo.py:56 - test_redo_restores_written_data
- tests/test_hexcore_e2e/test_undo_redo.py:70 - test_multiple_undo_steps
- tests/test_hexcore_e2e/test_undo_redo.py:91 - test_new_write_after_undo_clears_redo_stack
- tests/test_hexcore_e2e/test_undo_redo.py:103 - test_can_redo_true_after_undo
- tests/test_hexcore_e2e/test_undo_redo.py:113 - test_undo_returns_false_when_stack_empty
- tests/test_hexcore_e2e/test_undo_redo.py:121 - test_redo_returns_false_when_stack_empty
- tests/test_hexcore_e2e/test_undo_redo.py:133 - test_is_modified_false_on_fresh_open
- tests/test_hexcore_e2e/test_undo_redo.py:141 - test_is_modified_true_after_write
- tests/test_hexcore_e2e/test_undo_redo.py:150 - test_is_modified_tracks_through_undo_redo

## Summary

### Findings by severity
- Critical: 1
- High: 0
- Medium: 15
- Low: 48

### Total tests audited
144

### Total tests clean
79
