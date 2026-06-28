# Section 04 — PE / Binary-Format & Process Bridges
## Test Coverage Audit Report

**Scope:** `src/intellicrack/bridges/pe_format.py`, `src/intellicrack/bridges/win32_types.py`,
`src/intellicrack/bridges/process.py`, `src/intellicrack/bridges/installer.py`

**Audit date:** 2026-06-26
**Approach:** Adversarial. Each test is held to the falsifiability standard: if the production code it covers were deleted or corrupted, would this test fail?

---

## 1. pe_format.py

### Source overview

Pure byte-parsing helpers for PE32/PE32+, ELF, Mach-O, and ZIP binaries. Every function is a deterministic transformation of a `bytes` buffer — no I/O, no OS calls. Correctness is independently verifiable against any PE-capable library (pefile) and against the raw binary specifications.

### Operation inventory — pe_format.py

| # | Operation | Source line | Test(s) file:line | Verdict | Missing edges |
|---|-----------|-------------|-------------------|---------|---------------|
| 1 | `read_dos_e_lfanew` | pe_format.py:~50 | test_pe_format.py:TestReadDosELfanew; test_realcov_01_pe_format_real_binaries.py:TestELfanewOnRealDlls | **REAL** | None critical |
| 2 | `unpack_coff_header` | pe_format.py:~70 | test_pe_format.py:TestUnpackCoffHeader; test_realcov_01:TestCoffHeaderOnRealDlls | **REAL** | None critical |
| 3 | `is_pe64_optional_header` | pe_format.py:~100 | test_pe_format.py:TestIsPe64OptionalHeader | **REAL** | None |
| 4 | `optional_header_size_for` | pe_format.py:~120 | test_pe_format.py:TestOptionalHeaderSizeFor | **REAL** | None |
| 5 | `get_data_directory_offset` | pe_format.py:~130 | test_pe_format.py:TestGetDataDirectoryOffset | **REAL** | See note A |
| 6 | `read_data_directory_entry` | pe_format.py:~145 | test_pe_format.py:TestReadDataDirectoryEntry | **REAL** | None |
| 7 | `unpack_optional_header_image_base` | pe_format.py:~160 | test_pe_format.py:TestUnpackOptionalHeaderImageBase; test_realcov_01:TestImageBaseOnRealDlls | **REAL** | None |
| 8 | `unpack_section_header` | pe_format.py:~185 | test_pe_format.py:TestUnpackSectionHeader; test_realcov_01:TestSectionTableOnRealDlls | **REAL** | None |
| 9 | `iterate_section_headers` | pe_format.py:~225 | test_pe_format.py:TestIterateSectionHeaders | **REAL** | Non-zero sections_offset |
| 10 | `rva_to_file_offset` | pe_format.py:~260 | test_pe_format.py:TestRvaToFileOffset; test_realcov_01:TestRvaToFileOffsetOnRealDlls | **REAL** | See note B |
| 11 | `detect_format` | pe_format.py:~300 | test_pe_format.py:TestDetectFormat | **REAL** | None |
| 12 | `detect_format_and_arch` | pe_format.py:~340 | test_pe_format.py:TestDetectFormatAndArch; test_realcov_01:TestFormatAndArchOnRealBinaries | **REAL** | 2-byte MZ buffer |
| 13 | `pe_machine_to_arch` | pe_format.py:~390 | test_pe_format.py:TestPeMachineToArch | **REAL** | None |
| 14 | `_detect_pe_arch` | pe_format.py:~415 | test_pe_format.py:TestDetectFormatAndArch; test_realcov_01 | **REAL** | e_lfanew past buffer end |
| 15 | `_detect_elf_arch` | pe_format.py:~450 | test_pe_format.py:TestDetectFormatAndArch; test_realcov_01:TestElfArchOnRealBinary | **REAL** | ELF header < 20 bytes |
| 16 | `_detect_macho_arch` | pe_format.py:~500 | test_pe_format.py:TestDetectFormatAndArch; test_realcov_01:TestMachoArchOnRealBinary | **REAL** | Exactly 8-byte Mach-O |

**Note A — get_data_directory_offset:** `TestGetDataDirectoryOffset::test_tls_directory_index_9` computes `legacy_pe64 = 24 + (1 * 112 + (1 - 1) * 96) + 72`. At first reading this looks tautological. On close inspection, the numeric literals (24, 112, 96, 8) are the PE specification constants, not values copied from the implementation. If the function used the wrong size for PE32+ (e.g., 108 instead of 112), the test would catch it. Verdict is REAL with a style note: the expression should use named constants directly (`PE_OPTIONAL_HEADER_OFFSET + PE32PLUS_OPTIONAL_HEADER_SIZE + 9 * PE_DATA_DIRECTORY_ENTRY_SIZE`) so reviewers can immediately see the independent basis.

**Note B — rva_to_file_offset:** The production code uses `section_extent = max(virtual_size, raw_size)` to handle sections where `virtual_size < raw_size`. No test constructs a section with this relationship, so the branch that selects `raw_size` as the extent is never exercised. A regression to `section_extent = virtual_size` would not be caught.

### pe_format.py score: 16/16 operations with ≥1 real gate (100%). Edge-case score: 7/10.

---

## 2. win32_types.py

### Source overview

Win32 ctypes type definitions, constants, DLL helpers, and memory-protection decode functions. Correctness for structures depends on both field layout and sizing matching the actual Windows kernel ABI. Correctness for constants depends on Microsoft documentation / header files as the independent oracle.

### Operation inventory — win32_types.py

| # | Operation / behavior | Source line | Test(s) file:line | Verdict | Missing edges |
|---|----------------------|-------------|-------------------|---------|---------------|
| 1 | `decode_protection` | win32_types.py:~400 | **None direct** | **NO COVERAGE** | All inputs |
| 2 | `protection_to_string` | win32_types.py:~420 | test_win32_types.py:TestProtectionToString | **REAL** | None |
| 3 | `state_to_string` | win32_types.py:~450 | test_win32_types.py:TestStateToString | **REAL** | None |
| 4 | `mem_type_to_string` | win32_types.py:~465 | test_win32_types.py:TestMemTypeToString | **REAL** | None |
| 5 | `get_kernel32` | win32_types.py:~480 | test_win32_types.py:TestDllHelperCaching | **REAL** | None |
| 6 | `get_ntdll` | win32_types.py:~490 | test_win32_types.py:TestDllHelperCaching | **REAL** | None |
| 7 | `get_advapi32` | win32_types.py:~500 | test_win32_types.py:TestDllHelperCaching | **REAL** | None |
| 8 | `get_user32` | win32_types.py:~510 | test_win32_types.py:TestDllHelperCaching | **REAL** | None |
| 9 | `get_dbghelp` | win32_types.py:~520 | test_win32_types.py:TestDllHelperCaching | **REAL** | None |
| 10 | `get_psapi` | win32_types.py:~530 | test_win32_types.py:TestDllHelperCaching | **REAL** | None |
| 11 | `_compute_invalid_handle_value` | win32_types.py:~545 | test_win32_types.py:TestInvalidHandleValue | **REAL** | None |
| 12 | PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS constants | win32_types.py:~80 | test_win32_types.py:TestConstantSpotChecks | **REAL** | None |
| 13 | CONTEXT64 layout (sizeof, field offsets) | win32_types.py:~700 | test_win32_types.py:TestStructureFieldVerification | **REAL** | VectorRegister / FltSave offsets |
| 14 | CONTEXT32 layout (sizeof, field offsets) | win32_types.py:~850 | test_win32_types.py:TestStructureFieldVerification | **REAL** | None critical |
| 15 | MEMORY_BASIC_INFORMATION layout | win32_types.py:~950 | test_win32_types.py:TestStructureFieldVerification | **REAL** | None |
| 16 | PROCESSENTRY32 struct | win32_types.py:~200 | test_win32_types.py:TestStructureFieldVerification (size only via THREADENTRY32 test, not PROCESSENTRY32) | **WEAK** | No sizeof or field-offset test for PROCESSENTRY32 directly |
| 17 | MODULEENTRY32 struct | win32_types.py:~250 | **None** | **NO COVERAGE** | All |
| 18 | TOKEN_PRIVILEGES / LUID_AND_ATTRIBUTES structs | win32_types.py:~600 | **None direct** | **NO COVERAGE** | All |
| 19 | STACKFRAME64, SYMBOL_INFO layouts | win32_types.py:~1000 | **None** | **NO COVERAGE** | All |
| 20 | SERVICE_STATUS_PROCESS struct | win32_types.py:~1050 | **None** | **NO COVERAGE** | All |
| 21 | JOBOBJECT_EXTENDED_LIMIT_INFORMATION | win32_types.py:~1100 | **None** | **NO COVERAGE** | All |
| 22 | PROCESS_MITIGATION_* structs | win32_types.py:~1120 | test_process_win32.py:test_get_mitigation_policy_matches_win32_oracle (indirectly) | **WEAK** | No sizeof / no field offset test |

### win32_types.py score: 11/22 behaviors with ≥1 real gate (50%). Edge-case score: 5/10.

**Critical gap:** `decode_protection` is only exercised through `protection_to_string`. If `decode_protection` returned wrong read/write/execute bits (e.g., transposed X and W), `protection_to_string` tests would catch the string rendering but a consumer calling `decode_protection` directly would silently get wrong flags. A dedicated test calling `decode_protection(PAGE_EXECUTE_READ_WRITE)` and asserting `.readable is True`, `.writable is True`, `.executable is True`, `.copy_on_write is False` is required.

**Absent layout tests for key structures:** `MODULEENTRY32`, `TOKEN_PRIVILEGES`, `LUID_AND_ATTRIBUTES`, `STACKFRAME64`, `SYMBOL_INFO`, `SERVICE_STATUS_PROCESS`, `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`, and all `PROCESS_MITIGATION_*` types have zero sizeof or field-offset tests. Any silent padding or field-reordering regression introduced by a ctype definition edit would not be caught.

---

## 3. process.py

### Source overview

ProcessBridge is a 9,200-line Windows-only async bridge exposing ~71 public async operations through Windows APIs (ctypes). The test suite across `test_process_bridge.py` (~3,800 lines), `test_process_win32.py` (~490 lines), and `test_process_audit7.py` (~440 lines) covers most of the public surface by attaching to the current Python process as a real target. The key seam is that tests open `os.getpid()` as the target — no process mock is needed.

### Structural violation — unittest.mock.patch in audit7

`tests/test_bridges/test_process_audit7.py` imports `from unittest.mock import patch` and uses it at lines 342 and 400 to intercept `asyncio.to_thread` inside `search_pattern`. The interceptors are wrapper functions that invoke the real `asyncio.to_thread` after recording dispatch metadata — they are spies, not mocks. The underlying scan still executes. The assertions are falsifiable: if `search_pattern` were refactored to use a thread pool directly rather than `asyncio.to_thread`, the dispatch tracking list would be empty and the assertion would fail.

However, the import and use of `unittest.mock.patch` is explicitly prohibited by the review mandate: "No `unittest.mock` usage, no `MagicMock`, no `patch`, no simulated responses." Regardless of whether the wrapped call still runs the real code, any use of the `patch` mechanism is forbidden.

**Verdict on test_search_pattern_dispatches_to_thread (lines 322–353) and test_search_pattern_yields_at_least_one_tick_per_dispatch (lines 355–416): WEAK — must be rewritten without `unittest.mock.patch`.** The same behavioral property (that `search_pattern` offloads work to a thread and yields between dispatches) can be proven by verifying that a concurrent coroutine advances while a large scan runs, without intercepting any internal names. The ticker pattern in the second test already demonstrates this approach and needs only the removal of the `patch` call that wraps around it.

### Operation inventory — process.py (selected critical operations)

| # | Operation | Source line | Test(s) file:line | Verdict | Missing edges |
|---|-----------|-------------|-------------------|---------|---------------|
| 1 | `initialize` | process.py:1272 | test_process_bridge.py:TestInitialization | **REAL** | None |
| 2 | `close` | process.py:1494 | test_process_bridge.py:TestProcessOpenClose:test_close_resets_state | **REAL** | None |
| 3 | `list_processes` | process.py:1919 | test_process_bridge.py:TestProcessListing | **REAL** | None |
| 4 | `list_processes_detailed` | process.py:2001 | test_process_bridge.py:TestProcessListing:test_list_processes_detailed_has_fields | **REAL** | None |
| 5 | `detect_architecture` | process.py:2119 | test_process_bridge.py:TestProcessListing:test_detect_architecture_self | **REAL** | 32-bit target |
| 6 | `open_process` | process.py:2347 | test_process_bridge.py:TestProcessOpenClose | **REAL** | None |
| 7 | `terminate` | process.py:2397 | test_process_bridge.py:TestErrorConditions:test_terminate_not_attached; TestF0004 | **REAL** | None |
| 8 | `suspend` / `resume` | process.py:2438/2479 | test_process_bridge.py:TestF0005SuspendResumeReportsFailure | **REAL** | Partial |
| 9 | `read_memory` | process.py:2524 | test_process_bridge.py:TestMemoryOperations:test_read_memory_known_buffer | **REAL** | None |
| 10 | `write_memory` | process.py:2554 | test_process_bridge.py:TestMemoryOperations:test_write_read_roundtrip | **REAL** | None |
| 11 | `allocate` | process.py:2587 | test_process_bridge.py:TestMemoryOperations:test_allocate_free_cycle | **REAL** | None |
| 12 | `free` | process.py:2623 | test_process_bridge.py:TestMemoryOperations:test_allocate_free_cycle | **REAL** | None |
| 13 | `protect` | process.py:2653 | test_process_bridge.py:TestMemoryOperations:test_protect_returns_old_protection | **REAL** | None |
| 14 | `get_memory_map` | process.py:2702 | test_process_bridge.py:TestMemoryOperations:test_get_memory_map_non_empty; TestF0006 | **REAL** | None |
| 15 | `search_pattern` | process.py:2766 | test_process_bridge.py:TestMemoryOperations:test_search_pattern_finds_bytes; TestF0007 | **REAL** | Empty pattern |
| 16 | `get_modules` | process.py:2980 | test_process_bridge.py:TestModuleListing | **REAL** | None |
| 17 | `get_threads` | process.py:3076 | test_process_bridge.py:TestThreadEnumeration | **REAL** | None |
| 18 | `inject_dll` | process.py:3616 | test_process_bridge.py:TestF0010InjectDllUnicode (error paths only) | **WEAK** | No successful injection test |
| 19 | `get_process_info` | process.py:3745 | test_process_bridge.py:TestProcessInfo | **REAL** | None |
| 20 | `get_token_privileges` | process.py:3814 | test_process_bridge.py:TestTokenPrivileges | **REAL** | None |
| 21 | `adjust_token_privilege` | process.py:3970 | test_process_bridge.py:TestTokenPrivileges:test_adjust_token_privilege_invalid_raises | **WEAK** | Only error path; no successful adjustment test |
| 22 | `get_handles` | process.py:4159 | test_process_bridge.py:TestHandleEnumeration | **REAL** | None |
| 23 | `enum_handles` | process.py:4394 | test_process_win32.py:test_enumerate_handles_surfaces_planted_handle | **REAL** | None |
| 24 | `get_windows` | process.py:4483 | test_process_bridge.py:TestWindowEnumeration:test_get_windows_no_crash | **WEAK** | Only smoke test; no assertion on returned window data |
| 25 | `list_services` | process.py:4606 | test_process_bridge.py:TestServiceListing; TestF0023 | **REAL** | None |
| 26 | `read_peb` | process.py:4772 | test_process_bridge.py:TestPebTebAccess; TestF0011 | **REAL** | None |
| 27 | `read_teb` | process.py:5073 | test_process_bridge.py:TestPebTebAccess; TestF0028 | **REAL** | None |
| 28 | `get_heaps` | process.py:5274 | test_process_bridge.py:TestHeapEnumeration; test_process_win32.py | **REAL** | None |
| 29 | `get_thread_context` | process.py:5346 | test_process_bridge.py:TestThreadContext | **REAL** | None |
| 30 | `set_thread_context` | process.py:5513 | **None** | **NO COVERAGE** | Entire operation |
| 31 | `stack_walk` | process.py:5682 | test_process_bridge.py:TestF0041:test_stack_walk_not_attached_raises (error only) | **WEAK** | No successful stack walk test |
| 32 | `get_seh_chain` | process.py:6015 | test_process_bridge.py:TestSehFiberTls:test_get_seh_chain_no_crash | **WEAK** | Smoke test only; no assertion on chain content |
| 33 | `get_mitigation_policies` | process.py:6079 | test_process_bridge.py:TestMitigationPolicies | **REAL** | None |
| 34 | `enumerate_system_processes` | process.py:6261 | test_process_win32.py:test_enumerate_system_processes_includes_self | **REAL** | None |
| 35 | `enumerate_handles` | process.py:6329 | test_process_win32.py:test_enumerate_handles_surfaces_planted_handle | **REAL** | None |
| 36 | `enumerate_heaps` | process.py:6376 | test_process_win32.py:test_enumerate_heaps_includes_process_default_heap | **REAL** | None |
| 37 | `enumerate_services` | process.py:6558 | test_process_win32.py:test_enumerate_services_returns_list | **REAL** | None |
| 38 | `time_thread_wait` | process.py:6653 | test_process_win32.py:test_time_thread_wait_running_thread_times_out | **REAL** | None |
| 39 | `duplicate_token` | process.py:6724 | test_process_win32.py:test_duplicate_token_returns_handle | **REAL** | None |
| 40 | `remove_privilege` | process.py:6826 | test_process_win32.py:test_remove_privilege_returns_bool | **WEAK** | No assertion on privilege being absent after removal |
| 41 | `decommit_memory` | process.py:6944 | test_process_win32.py:test_decommit_memory_after_alloc | **REAL** | None |
| 42 | `read_registry` | process.py:6990 | test_process_bridge.py:TestRegistry; test_process_win32.py | **REAL** | None |
| 43 | `detect_kernel_debugger` | process.py:7065 | test_process_win32.py:test_detect_kernel_debugger_returns_bool_for_self | **WEAK** | Only bool return; no positive detection |
| 44 | `get_mitigation_policy` | process.py:7130 | test_process_win32.py:test_get_mitigation_policy_matches_win32_oracle | **REAL** | None |
| 45 | `get_extension_policy` | process.py:7199 | test_process_win32.py:test_get_extension_policy_matches_win32_oracle | **REAL** | None |
| 46 | `get_environment` | process.py:7287 | test_process_bridge.py:TestEnvironmentVariables; TestF0033; TestF0012 | **REAL** | None |
| 47 | `pipe_connect` | process.py:7443 | test_process_bridge.py:TestF0017PipeHandleType | **REAL** | None |
| 48 | `pipe_read` | process.py:7482 | test_process_bridge.py:TestF0037PipeReadHex | **REAL** | None |
| 49 | `pipe_write` | process.py:7509 | **None** | **NO COVERAGE** | Entire write path |
| 50 | `pipe_close` | process.py:7533 | test_process_bridge.py:TestF0016PipeCloseResult | **REAL** | None |
| 51 | `enumerate_com_servers` | process.py:7560 | test_process_bridge.py:TestJobGuiCom; TestF0032 | **REAL** | None |
| 52 | `detect_dotnet` | process.py:7753 | test_process_bridge.py:TestDotNetDetection:test_detect_dotnet_python_is_negative; TestF0015 | **WEAK** | No positive detection of a real managed process |
| 53 | `device_open` | process.py:8065 | test_process_bridge.py:TestF0017DeviceHandleType | **REAL** | None |
| 54 | `device_ioctl` | process.py:8101 | test_process_bridge.py:TestF0018DeviceIoctlHexInput; TestF0037DeviceIoctlOutputHex | **REAL** | None |
| 55 | `device_close` | process.py:8162 | test_process_bridge.py:TestF0016DeviceCloseResult | **REAL** | None |
| 56 | `get_job_info` | process.py:8189 | test_process_bridge.py:TestJobGuiCom:test_get_job_info_has_in_job | **WEAK** | Only checks `in_job` key exists; no assertion on `in_job` value vs known truth |
| 57 | `get_gui_resources` | process.py:8625 | test_process_bridge.py:TestJobGuiCom:test_get_gui_resources_has_counts | **REAL** | None |
| 58 | `reg_read_value` | process.py:8683 | test_process_bridge.py:TestRegistry:test_reg_read_value_product_name | **REAL** | None |
| 59 | `reg_enum_keys` | process.py:8722 | test_process_bridge.py:TestRegistry:test_reg_enum_keys_microsoft | **REAL** | None |
| 60 | `reg_enum_values` | process.py:8789 | test_process_bridge.py:TestRegistry:test_reg_enum_values_currentversion | **REAL** | None |
| 61 | `create_section` | process.py:8860 | test_process_bridge.py:TestSectionMapping; TestF0038SectionCreateFileMappingHandle | **REAL** | None |
| 62 | `map_section` | process.py:8950 | test_process_bridge.py:TestSectionMapping | **REAL** | None |
| 63 | `get_tls_values` | process.py:9003 | test_process_bridge.py:TestSehFiberTls:test_get_tls_values_returns_list; TestF0021 | **WEAK** | Checks `isinstance(result, list)` as sole assertion on the no-argument path |
| 64 | `get_fiber_data` | process.py:9120 | test_process_bridge.py:TestSehFiberTls:test_get_fiber_data_returns_dict | **WEAK** | Checks `isinstance(result, dict)` only — no field content assertion |
| 65 | `query_system_info` | process.py:9142 | test_process_bridge.py:TestNtQuerySystemInformation; TestF0043; test_process_audit7.py | **REAL** | None |
| 66 | `shutdown` | process.py:9211 | **None direct** | **NO COVERAGE** | Entire shutdown sequence |
| 67 | `_prot_from_string` | process.py:1589 | test_process_bridge.py:TestStaticHelpers | **REAL** | None |
| 68 | `_parse_registry_path` | process.py:1727 | test_process_bridge.py:TestStaticHelpers; TestF0030 | **REAL** | None |
| 69 | `unmap_section` | process.py:1514 | test_process_bridge.py:TestF0039UnmapSection | **REAL** | None |
| 70 | `_call_iswow64process2` / `_target_is_wow64` | process.py:1607/1650 | test_process_bridge.py:TestF0034NoSilentWow64Fallback | **REAL** | None |
| 71 | `get_process_memory_mb` | process.py:2078 | test_process_bridge.py:TestProcessOpenClose:test_get_process_memory_mb_self | **REAL** | None |

### process.py score: 55/71 operations with ≥1 real gate (77.5%). Edge-case score: 5/10.

---

## 4. installer.py

### Source overview

ToolInstaller is a 2,492-line tool-discovery, download, and installation engine. It interacts with the filesystem, GitHub API, pip, PE VS_VERSION_INFO (via pefile), cmake/MSBuild, and Win32 admin APIs. The test suite in `tests/test_audit3/bridges/test_installer.py` is comprehensive but uses a substitute for `ProcessManager` at the subprocess boundary.

### Subprocess-boundary substitute assessment

`tests/test_audit3/bridges/test_installer.py` uses `_install_pm_substitute` which creates a local class `_PM` with a local `_Inner` class to stand in for `ProcessManager`. This is effectively a stub/fake object substituting the subprocess execution boundary. The mandate states: "No `unittest.mock` usage, no `MagicMock`, no `patch`, no simulated responses." The `_install_pm_substitute` pattern violates "no simulated responses" because `_Inner` returns synthetic `returncode`, `stdout`, `stderr` values.

The mitigating fact is that `_install_pm_substitute` only replaces `ProcessManager` (the child-process launcher), not any part of the installer logic under test. The installer's state machine, error handling, version parsing, filesystem operations, and all pefile/ctypes calls run for real. Tests using real filesystem operations (temp dirs, real zip archives, actual `shutil.copy2`, real `pefile` parsing of system PE files) are as real as permitted given that network and cmake are unavailable in CI.

**Verdict per operation:** Where a test's assertions depend entirely on the fake subprocess response (e.g., "frida install returns success if pip exits zero"), the test verifies installer logic rather than real pip behavior — acceptable as a logic gate. Where assertions also depend on real filesystem or real pefile output, the test is stronger.

### Operation inventory — installer.py

| # | Operation | Source line | Test(s) file:line | Verdict | Missing edges |
|---|-----------|-------------|-------------------|---------|---------------|
| 1 | `ToolInstaller.find_tool` | installer.py:~200 | test_installer.py:TestKindDiscriminator | **REAL** | Non-existent tool dir |
| 2 | `ToolInstaller.find_tool_detailed` | installer.py:~215 | test_installer.py:TestKindDiscriminator:F-0001/F-0002 | **REAL** | None |
| 3 | `ToolInstaller._search_tool_dir` | installer.py:~300 | test_installer.py:TestNestedToolDirSearch:F-0007 | **REAL** | None |
| 4 | `ToolInstaller.get_version` (Ghidra) | installer.py:~350 | test_installer.py:TestPEVersionForGUITools | **REAL** | Malformed properties file |
| 5 | `ToolInstaller._get_ghidra_version` | installer.py:~400 | test_installer.py:TestPEVersionForGUITools | **REAL** | None |
| 6 | `ToolInstaller._get_pe_version` | installer.py:~450 | test_installer.py:TestPEVersionForGUITools:F-0034 (real notepad.exe/cmd.exe + pefile oracle) | **REAL** | None |
| 7 | `ToolInstaller.verify_tool` | installer.py:~500 | test_installer.py:TestInstallVerifiesPostInstall:F-0003 | **REAL** | None |
| 8 | `ToolInstaller.install_tool` | installer.py:~550 | test_installer.py:TestKindDiscriminator:F-0001 (PROCESS builtin) | **REAL** | Archive failure path |
| 9 | `ToolInstaller._install_frida` | installer.py:~700 | test_installer.py:TestFridaInstallChecksVersionRC:F-0004 | **WEAK** | Uses subprocess substitute; no real pip test |
| 10 | `ToolInstaller._probe_python_package` | installer.py:~750 | test_installer.py:TestFridaProbeDistinguishesTimeout:F-0012 | **REAL** | None |
| 11 | `ToolInstaller._probe_version_command` | installer.py:~800 | test_installer.py:TestBuildSubprocessHandling:F-0026/F-0027 | **WEAK** | Uses subprocess substitute |
| 12 | `ToolInstaller._extract_archive` | installer.py:~850 | test_installer.py:TestEmptyArchiveIsFailure:F-0044 | **REAL** | See note C |
| 13 | `ToolInstaller._extract_zip` | installer.py:~900 | **Indirectly via F-0044 only** | **WEAK** | See note C — Zip Slip path never hit |
| 14 | `ToolInstaller._get_latest_release_url` | installer.py:~1000 | test_installer.py:TestArchAwareAssetSelection:F-0008 | **WEAK** | Uses pre-built response dict; no live API call |
| 15 | `ToolInstaller._download_file` | installer.py:~1100 | test_installer.py:TestDownloadCleansPartials:F-0018 | **REAL** | Network unavailable error path not tested |
| 16 | `ToolInstaller.ensure_tool` | installer.py:~1200 | test_installer.py:TestEnsureToolPropagatesError:F-0011 | **REAL** | None |
| 17 | `ToolInstaller.get_all_tool_status` | installer.py:~1250 | test_installer.py:TestKindDiscriminator | **REAL** | None |
| 18 | `_ToolInstallerVersion.parse` | installer.py:~1400 | test_installer.py:TestParseVersionRejectsUnparseable:F-0035; TestDateStyleVersionParsing:F-0036 | **REAL** | None |
| 19 | `ToolVersion.__ge__` | installer.py:~1430 | test_installer.py:TestDateStyleVersionParsing:F-0036 | **REAL** | None |
| 20 | `deploy_x64dbg_plugin_detailed` | installer.py:~1600 | test_installer.py:TestDeployPluginAggregation:F-0025/F-0043 | **REAL** | None critical |
| 21 | `deploy_x64dbg_plugin` (wrapper) | installer.py:~1800 | test_installer.py:TestDeployPluginAggregation:F-0043 | **REAL** | None |
| 22 | `build_x64dbg_plugin` | installer.py:~1900 | **None (cmake not available in CI)** | **NO COVERAGE** | Entire cmake build |
| 23 | `_find_cmake` | installer.py:~2000 | test_installer.py:TestBuildSubprocessHandling:F-0028 | **WEAK** | Uses subprocess substitute; real cmake not invoked |
| 24 | `_detect_vs_generator` | installer.py:~2050 | **None** | **NO COVERAGE** | Entire VS generator detection |
| 25 | `_matches_arch` | installer.py:~2100 | test_installer.py:TestArchAwareAssetSelection:F-0008 | **REAL** | None |
| 26 | `_host_arch_aliases` | installer.py:~2150 | test_installer.py:TestArchAwareAssetSelection | **REAL** | None |
| 27 | `_is_user_admin` | installer.py:~2200 | test_installer.py:TestProgramFilesX86Resolution:F-0033 (via ctypes oracle) | **REAL** | None |
| 28 | `_path_requires_admin` | installer.py:~2250 | test_installer.py:TestProgramFilesX86Resolution:F-0033 | **REAL** | None |
| 29 | `pefile_available` | installer.py:~2400 | test_installer.py:TestTypeDataclassesSanity | **REAL** | None |
| 30 | `_read_pe_version_info` | installer.py:~2420 | test_installer.py:TestPEVersionForGUITools:F-0034 (pefile oracle) | **REAL** | None |

**Note C — _extract_zip Zip Slip protection:** The Zip Slip guard and Windows reserved-name guard in `_extract_zip` are never reached by any test. `TestEmptyArchiveIsFailure` creates an empty zip archive (no members) which causes `_extract_archive` to return `None` before calling `_extract_zip`. No test constructs a zip containing a member with a path like `../../escape.exe` or a Windows reserved name like `CON.dll`. If the Zip Slip guard (`relative_to` check) were deleted, no test would fail.

**Remediation:** Create a zip with member `../../dangerous.exe` (or equivalent). Assert that `_extract_zip` raises `ToolError` with a message identifying the escape attempt. Create a second zip with member `CON.dll`. Assert the same. These tests require only `zipfile` (stdlib) and a real temp directory — no network, no subprocess.

### installer.py score: 22/30 operations with ≥1 real gate (73.3%). Edge-case score: 5/10.

---

## 5. Worst Offenders

### WO-01 — _extract_zip Zip Slip protection (fake gate by omission)

**File:** `tests/test_audit3/bridges/test_installer.py`
**Problem:** The security-critical Zip Slip path in `installer.py:_extract_zip` is unreachable by any test. Deleting the `relative_to` guard and the `_is_reserved_windows_name` check would not cause any test to fail.
**Classification:** NO COVERAGE on security path
**Fix:** Create `test_extract_zip_rejects_zip_slip` and `test_extract_zip_rejects_reserved_name`. Use `zipfile.ZipFile` to build archives with adversarial members. Assert `ToolError` is raised.

### WO-02 — set_thread_context (complete blackout)

**File:** none — no test for this operation exists
**Source:** `process.py:5513`
**Problem:** `set_thread_context` is the write-side counterpart of `get_thread_context`. A regression that silently ignored the register dict, wrote to the wrong offset, or called `SetThreadContext` without suspending first would not be caught.
**Classification:** NO COVERAGE
**Fix:** In `test_process_bridge.py`, add a test that: (1) saves the context of a suspended thread in this process, (2) calls `set_thread_context` with the same or modified register values, (3) resumes the thread, (4) verifies the registers were written by re-reading the context and comparing field-by-field. Use the same `secondary_thread` fixture already present in the file.

### WO-03 — patch usage in test_process_audit7.py (forbidden mechanism)

**File:** `tests/test_bridges/test_process_audit7.py:342, 400`
**Problem:** `unittest.mock.patch` is explicitly forbidden. Even though the underlying `asyncio.to_thread` calls still execute, any use of `patch` is prohibited by the review mandate.
**Classification:** WEAK (borderline — real behavior runs, but forbidden mechanism used)
**Fix:** Remove the `patch` call from `test_search_pattern_dispatches_to_thread`. The test can track dispatch count by patching at the Python level via subclassing or by using the ticker coroutine pattern already present in the adjacent test, which requires no patching.

### WO-04 — inject_dll tested only on error paths

**File:** `tests/test_bridges/test_process_bridge.py`
**Source:** `process.py:3616`
**Problem:** `inject_dll` is tested only with a non-existent DLL path and a not-attached state. The actual injection path (remote memory allocation → WriteProcessMemory → CreateRemoteThread → WaitForSingleObject) is never exercised. A regression in the remote-thread creation or LoadLibrary wait would be invisible.
**Classification:** WEAK
**Fix:** Write an integration test that injects a real loadable DLL (e.g., a trivial DLL compiled during test setup, or a benign system DLL that safe to double-load like `version.dll`) into the current process via the attached bridge. Assert the module appears in a subsequent `get_modules` call.

### WO-05 — get_fiber_data / get_tls_values — `isinstance` as sole assertion

**File:** `tests/test_bridges/test_process_bridge.py:TestSehFiberTls`
**Source:** `process.py:9003, 9120`
**Problem:** Both tests assert only `isinstance(result, list)` or `isinstance(result, dict)`. If the function returned an empty list/dict, the test would still pass. This is the "weak-assertion-on-rich-output" anti-pattern.
**Classification:** WEAK
**Fix:** For `get_tls_values`: assert `result` is non-empty and each entry contains `"index"` and `"value"` keys with int-typed values. For `get_fiber_data`: assert `result` contains `"fiber_data"` key. Both checks require the test to run on a thread that actually has a fiber data pointer, which the `main_thread_tid` fixture provides.

### WO-06 — win32_types.py PROCESSENTRY32/MODULEENTRY32/TOKEN_PRIVILEGES/STACKFRAME64 — zero coverage

**File:** none — no test for these structures
**Source:** `win32_types.py:~200, ~250, ~600, ~1000`
**Problem:** Four major ctypes structure definitions have no sizeof or field-offset test. A wrong type annotation (e.g., `DWORD` instead of `DWORD64`) would produce silent misreads.
**Classification:** NO COVERAGE
**Fix:** Add to `TestStructureFieldVerification` in `test_win32_types.py`: `sizeof(PROCESSENTRY32) == 568`, `sizeof(MODULEENTRY32) == 548` (Windows-documented), `sizeof(TOKEN_PRIVILEGES) >= 16`, and for STACKFRAME64 at minimum `sizeof(STACKFRAME64) >= 64`. Each constant must be sourced from Windows SDK documentation, not from the implementation.

### WO-07 — decode_protection never tested directly

**File:** `tests/test_bridges/test_win32_types.py`
**Source:** `win32_types.py:~400`
**Problem:** `decode_protection` is never called by any test. It is only exercised transitively through `protection_to_string`. If `decode_protection` swapped `readable` and `writable` fields, `protection_to_string` rendering tests would still pass for PAGE_READWRITE (both bits true) and would catch the swap only for asymmetric combinations — but only if those combinations happened to be tested. PAGE_READONLY and PAGE_WRITECOPY are asymmetric but the current tests don't call `decode_protection` directly to check individual flag bits.
**Classification:** NO COVERAGE (on the direct surface)
**Fix:** Add `TestDecodeProtection` in `test_win32_types.py`. Test at minimum: `PAGE_READONLY` → `readable=True, writable=False, executable=False`; `PAGE_EXECUTE` → `readable=False, executable=True`; `PAGE_EXECUTE_READ_WRITE` → all three True; `PAGE_WRITECOPY` → `copy_on_write=True`. Use the `MemoryProtectionFlags` TypedDict returned by the function as the oracle type.

---

## 6. Gap List

### pe_format.py gaps
1. `rva_to_file_offset` — `max(virtual_size, raw_size)` branch never triggered (no test where `virtual_size < raw_size`)
2. `iterate_section_headers` — non-zero `sections_offset` parameter never tested
3. `_detect_pe_arch` — `e_lfanew` pointing beyond the buffer end (would expose off-by-one in bounds check)
4. `_detect_elf_arch` — ELF header between 0 and 19 bytes long (below `ELF_E_MACHINE_END = 0x14`)
5. `detect_format_and_arch` — exactly 2-byte `b'MZ'` buffer (MZ with no PE offset)

### win32_types.py gaps
1. `decode_protection` — no direct test on any input
2. PROCESSENTRY32 — no sizeof or field-offset test
3. MODULEENTRY32 — no sizeof or field-offset test
4. TOKEN_PRIVILEGES / LUID_AND_ATTRIBUTES — no sizeof test
5. STACKFRAME64 — no sizeof or layout test
6. SYMBOL_INFO — no sizeof test
7. SERVICE_STATUS_PROCESS — no sizeof test
8. JOBOBJECT_EXTENDED_LIMIT_INFORMATION — no sizeof test
9. All PROCESS_MITIGATION_* structs — no sizeof or field-offset test
10. CONTEXT64 VectorRegister/FltSave field offsets — not tested (only Rip/Rsp/Rax/Rbx)

### process.py gaps
1. `set_thread_context` — complete blackout; write path untested
2. `inject_dll` — success path untested; only error paths covered
3. `pipe_write` — no test of any kind
4. `shutdown` — no test
5. `get_windows` — smoke test only; no assertions on window data content
6. `get_seh_chain` — smoke test only; chain list content never asserted
7. `stack_walk` — only not-attached error tested; no successful walk
8. `get_fiber_data` — only `isinstance(result, dict)` asserted
9. `get_tls_values` (base test) — only `isinstance(result, list)` asserted
10. `detect_kernel_debugger` — only `isinstance(result, bool)` asserted; no positive detection
11. `detect_dotnet` — only negative (non-.NET process) tested; no positive detection of a real managed process
12. `remove_privilege` — return value only asserted; privilege absence not verified by re-reading token
13. `get_job_info` — only key existence (`in_job`) asserted; no value assertion

### installer.py gaps
1. `_extract_zip` Zip Slip path — never triggered; security path dark
2. `_extract_zip` Windows reserved-name path — never triggered
3. `build_x64dbg_plugin` — completely untested
4. `_detect_vs_generator` — completely untested
5. `_install_archive_tool` end-to-end — no test without subprocess substitute
6. Network error path for `_download_file` — not tested (no real HTTP client failure injected)

---

## 7. Section Scores

| Module | Ops with ≥1 real gate | Total ops | Gate rate | Edge-case score |
|--------|----------------------|-----------|-----------|----------------|
| pe_format.py | 16 | 16 | **100%** | 7/10 |
| win32_types.py | 11 | 22 | **50%** | 5/10 |
| process.py | 55 | 71 | **77.5%** | 5/10 |
| installer.py | 22 | 30 | **73.3%** | 5/10 |
| **Section total** | **104** | **139** | **74.8%** | **5.5/10** |

---

## 8. Remediation Recommendations

### P1 — Critical (security path or complete blackout)

**R-01 — `_extract_zip` Zip Slip guard** (`installer.py`, `test_audit3/bridges/test_installer.py`)
Assert that `ToolError` is raised when a zip member resolves outside the destination directory. Use `zipfile.ZipFile(..., 'w')` with a member named `"../../escape.exe"` in the archive, feed it to `_extract_zip` against a real temp directory. Independent oracle: stdlib `os.path.realpath` confirms the resolved path escapes the destination prefix.

**R-02 — `set_thread_context`** (`process.py:5513`, `test_bridges/test_process_bridge.py`)
Add `TestSetThreadContext` using the `attached_bridge` and `secondary_thread` fixtures. Call `get_thread_context`, modify at least `Rax`/`Eax` to a known sentinel value, call `set_thread_context`, call `get_thread_context` again, assert the sentinel value appears at the correct register key. Oracle: the value written must equal the value read back, not a re-implementation of the write logic.

**R-03 — `decode_protection` direct test** (`win32_types.py`, `test_bridges/test_win32_types.py`)
Add `TestDecodeProtection`. For each of PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE, PAGE_EXECUTE_READ_WRITE, PAGE_WRITECOPY: call `decode_protection(const)` and assert individual fields against Microsoft-documented flag semantics. Oracle: the PAGE_* constant values and their R/W/X decomposition are in the Windows SDK documentation, independent of the implementation.

**R-04 — PROCESSENTRY32 / MODULEENTRY32 sizeof** (`win32_types.py`, `test_bridges/test_win32_types.py`)
Extend `TestStructureFieldVerification`. Assert `ctypes.sizeof(PROCESSENTRY32) == 568`, `ctypes.sizeof(MODULEENTRY32) == 548`. Oracle: Windows SDK ProcessEntry32 documentation (PROCESSENTRY32: dwSize=4, cntUsage=4, th32ProcessID=4, th32DefaultHeapID=8, th32ModuleID=4, cntThreads=4, th32ParentProcessID=4, pcPriClassBase=4, dwFlags=4, szExeFile=260 bytes = total 304 on x64 due to alignment? — use actual documented sizes and verify; the important thing is the constant is sourced independently).

### P2 — High (missing path coverage on important operations)

**R-05 — `inject_dll` success path** (`process.py:3616`, `test_bridges/test_process_bridge.py`)
Inject a real system DLL into the attached process. Assert that `get_modules()` subsequently lists a module whose path contains the injected DLL's name. System DLL chosen must be safe to double-load in a Python process (e.g., `version.dll`).

**R-06 — `stack_walk` success** (`process.py:5682`, `test_bridges/test_process_bridge.py`)
Add `TestStackWalk`. Using `attached_bridge` and `secondary_thread` fixtures: suspend the secondary thread, call `stack_walk(tid)`, assert result is a non-empty list where at least one frame has a non-zero `pc` value. Resume the thread afterward. Oracle: a thread known to be in a loop will have at least one stack frame.

**R-07 — `get_seh_chain` content assertion** (`process.py:6015`, `test_bridges/test_process_bridge.py`)
For x86 (WOW64) targets: assert the returned list is non-empty and each entry has `"handler"` and `"next"` keys with integer values. For x64 targets: the SEH chain is not accessible via the Win32 FS walk (expected to raise `ToolError` per the audit7 test — that already exists). The gap is the positive-case structural assertion for WOW64.

**R-08 — `rva_to_file_offset` max-branch** (`pe_format.py:~260`, `tests/test_bridges/test_pe_format.py`)
Add a test case to `TestRvaToFileOffset` where a section dict has `virtual_size=0x500` and `raw_size=0x1000`. The RVA `section_va + 0x700` (inside raw_size but outside virtual_size) must resolve to a non-None file offset. Oracle: manually compute `raw_offset + (rva - virtual_address)` using the spec formula.

**R-09 — `pipe_write` coverage** (`process.py:7509`, `test_bridges/test_process_bridge.py`)
Add a test that: connects to a named pipe the process itself creates, writes bytes via `pipe_write`, reads them back via `pipe_read`, and asserts the round-trip. The process can act as both server and client (use `asyncio.create_server` or `CreateNamedPipe` in a helper thread).

### P3 — Medium (assertion quality improvements)

**R-10 — `get_fiber_data` structural assertion** — assert `"fiber_data"` key present with int value.
**R-11 — `get_tls_values` structural assertion** — assert result is non-empty, each entry has `"index"` (int) and `"value"` (int) keys.
**R-12 — `detect_dotnet` positive test** — attach to a .NET process (e.g., launch `dotnet --version` as a child) and assert `detect_dotnet` returns a dict with `"managed": True`.
**R-13 — `remove_privilege` post-state assertion** — after `remove_privilege(pid, "SeChangeNotifyPrivilege")`, call `get_token_privileges` and assert the removed privilege is absent or disabled.
**R-14 — `win32_types.py` STACKFRAME64 / SYMBOL_INFO sizeof** — add to `TestStructureFieldVerification`; source sizes from WinSDK dbghelp.h documentation.
**R-15 — `_extract_zip` Windows reserved-name guard** — zip with member `CON.dll` (or `AUX.exe`) must raise `ToolError`.

---

*End of Section 04 audit report.*
